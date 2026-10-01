/**
 * 专用审批渠道解析与安全子 agent 的 LLM 调用（零第三方依赖）。
 * provider 是审批的唯一 LLM 来源；模型不可用时由上层交回客户端原生审批。
 * 作者: zhao
 * 创建日期: 2026年08月29日
 * 更新日期: 2026年10月01日
 */

import http from "node:http";
import https from "node:https";

import { REVIEW_PROVIDER_FILE, PROVIDER_CAPS_FILE, logWrite, readJsonFile, writeFileAtomic, withFileLock } from "./common.js";
import { redactSecrets } from "./redaction.js";

class ProviderError extends Error {}
class LlmError extends Error {}

const MAX_OUTPUT_TOKENS = 2048;
const HOOK_TIMEOUT_BUDGET_MS = 120000;
const HOOK_CLEANUP_MARGIN_MS = 5000;
const PROVIDER_REQUEST_BUDGET_MS = HOOK_TIMEOUT_BUDGET_MS - HOOK_CLEANUP_MARGIN_MS;
const PROVIDER_CAPS_STALE_MS = 7 * 24 * 60 * 60 * 1000;
const MAX_RESPONSE_BYTES = 1024 * 1024;
const MIN_REMAINING_MS = 100;

function effectiveProviderRetries(timeout_ms, configured_retries) {
  const t_timeout = Number.isFinite(timeout_ms) && timeout_ms > 0 ? timeout_ms : 30000;
  const t_configured = Number.isFinite(configured_retries)
    ? Math.min(3, Math.max(0, Math.round(configured_retries)))
    : 1;
  const t_budget_attempts = Math.max(1, Math.floor(PROVIDER_REQUEST_BUDGET_MS / t_timeout));
  return Math.max(0, Math.min(t_configured, t_budget_attempts - 1));
}

function providerWorstCaseMs(timeout_ms, configured_retries) {
  const t_timeout = Number.isFinite(timeout_ms) && timeout_ms > 0 ? timeout_ms : 30000;
  return t_timeout * (1 + effectiveProviderRetries(t_timeout, configured_retries));
}

function transientLlmError(message) {
  const t_error = new LlmError(message);
  t_error.retryable = true;
  return t_error;
}

function deadlineLlmError() {
  const t_error = new LlmError("审批请求超过总截止时间");
  t_error.deadline = true;
  t_error.retryable = false;
  return t_error;
}

function loadReviewProviderOverride() {
  const t_raw = readJsonFile(REVIEW_PROVIDER_FILE(), null, "provider");
  if (!t_raw || typeof t_raw !== "object" || Array.isArray(t_raw)) return null;

  const t_entry = {};
  for (const [t_key, t_value] of Object.entries(t_raw)) {
    if (!t_key.startsWith("_")) t_entry[t_key] = t_value;
  }
  const t_base_url = String(t_entry.base_url || "").trim();
  const t_api_key = String(t_entry.api_key || "").trim();
  if (!t_base_url && !t_api_key) return null;
  if (!t_base_url || !t_api_key) {
    throw new ProviderError("review_provider.json 只填了 base_url/api_key 之一（要么补全，要么两者都留空视为未配置）");
  }
  const t_kind = String(t_entry.api_kind || "").trim().toLowerCase();
  if (t_kind && t_kind !== "anthropic" && t_kind !== "openai") {
    throw new ProviderError("review_provider.json 的 api_kind 只接受 anthropic 或 openai");
  }
  return {
    kind: t_kind || (/anthropic/i.test(t_base_url) ? "anthropic" : "openai"),
    baseURL: t_base_url,
    apiKey: t_api_key,
    model: String(t_entry.model || "").trim(),
  };
}

function isLoopbackHost(hostname) {
  const t_host = String(hostname || "").toLowerCase().replace(/^\[|\]$/g, "");
  if (t_host === "localhost" || t_host === "::1") return true;
  const t_parts = t_host.split(".");
  return t_parts.length === 4 && t_parts[0] === "127" && t_parts.every((part) => /^\d+$/.test(part) && Number(part) <= 255);
}

function validateProviderTransport(base_url) {
  let t_url;
  try {
    t_url = new URL(base_url);
  } catch {
    throw new ProviderError("review_provider.json 的 base_url 不是合法 URL");
  }
  if (t_url.protocol !== "https:" && t_url.protocol !== "http:") {
    throw new ProviderError(`审批渠道不支持该协议: ${t_url.protocol}`);
  }
  if (t_url.protocol === "http:" && !isLoopbackHost(t_url.hostname)) {
    throw new ProviderError("非本机审批渠道必须使用 HTTPS，避免 API key、命令和脚本内容明文传输");
  }
  return t_url;
}

function capabilityKey(provider_info) {
  const t_base = String(provider_info && provider_info.baseURL || "").replace(/\/+$/, "");
  return `${String(provider_info.kind || "").toLowerCase()}|${t_base}|${provider_info.model}`;
}

function readJsonModeCapability(provider_info) {
  const t_raw = readJsonFile(PROVIDER_CAPS_FILE(), null, "provider");
  if (!t_raw || typeof t_raw !== "object" || t_raw.version !== 1 || !t_raw.entries || typeof t_raw.entries !== "object") {
    return "unknown";
  }
  const t_entry = t_raw.entries[capabilityKey(provider_info)];
  if (!t_entry || (t_entry.json_object !== "supported" && t_entry.json_object !== "unsupported")) return "unknown";
  if (!Number.isFinite(t_entry.checked_at) || Date.now() - t_entry.checked_at > PROVIDER_CAPS_STALE_MS) return "unknown";
  return t_entry.json_object;
}

function markJsonModeCapability(provider_info, state) {
  // Keep the old one-argument form harmless for external callers; it cannot
  // create a cross-provider capability conclusion.
  if (!provider_info || typeof provider_info !== "object" || !provider_info.baseURL) return false;
  if (state !== "supported" && state !== "unsupported") return false;
  const t_result = withFileLock(PROVIDER_CAPS_FILE() + ".lock", () => {
    const t_raw = readJsonFile(PROVIDER_CAPS_FILE(), null, "provider");
    const t_entries = t_raw && t_raw.version === 1 && t_raw.entries && typeof t_raw.entries === "object"
      ? { ...t_raw.entries }
      : {};
    t_entries[capabilityKey(provider_info)] = { json_object: state, checked_at: Date.now() };
    const t_keys = Object.keys(t_entries);
    if (t_keys.length > 64) {
      t_keys.sort((a, b) => Number(t_entries[a]?.checked_at || 0) - Number(t_entries[b]?.checked_at || 0));
      for (const t_key of t_keys.slice(0, t_keys.length - 64)) delete t_entries[t_key];
    }
    return writeFileAtomic(PROVIDER_CAPS_FILE(), JSON.stringify({ version: 1, entries: t_entries }));
  });
  return t_result === true;
}

function resolveProvider(settings) {
  const t_file_provider = loadReviewProviderOverride();
  if (!t_file_provider) {
    throw new ProviderError("专用审批渠道未配置：用 provider path 创建 ~/.zcode/auto-review/review_provider.json 并填写 base_url / api_key / model（未配置时 LLM 审查不可用，命令转人工审批）");
  }
  validateProviderTransport(t_file_provider.baseURL);
  if (!t_file_provider.model) throw new ProviderError("review_provider.json 未填 model，请补上审批使用的模型名");
  const t_timeout = Number(settings && settings.timeout_ms);
  const t_retries = Number(settings && settings.provider_retries);
  return {
    kind: t_file_provider.kind,
    baseURL: t_file_provider.baseURL,
    apiKey: t_file_provider.apiKey,
    model: t_file_provider.model,
    timeoutMs: Number.isFinite(t_timeout) && t_timeout > 0 ? t_timeout : 30000,
    retries: Number.isFinite(t_retries) ? Math.min(3, Math.max(0, Math.round(t_retries))) : 1,
    json_mode: ["auto", "on", "off"].includes(String(settings && settings.provider_json_mode))
      ? String(settings.provider_json_mode)
      : "auto",
  };
}

function joinEndpoint(base_url, endpoint) {
  const t_base = String(base_url).replace(/\/+$/, "");
  if (t_base.toLowerCase().endsWith(endpoint.toLowerCase())) return t_base;
  if (/\/v\d+$/.test(t_base)) return t_base + endpoint;
  return t_base + "/v1" + endpoint;
}

function shortResponseSummary(text) {
  return redactSecrets(String(text || "")).replace(/\s+/g, " ").slice(0, 180);
}

function requestText(url_str, headers, body_str, timeout_ms, { deadlineAt = Date.now() + PROVIDER_REQUEST_BUDGET_MS, maxBytes = MAX_RESPONSE_BYTES } = {}) {
  const t_remaining = Math.min(Number(timeout_ms) || 30000, deadlineAt - Date.now());
  if (t_remaining < MIN_REMAINING_MS) return Promise.reject(deadlineLlmError());

  let t_timer = null;
  return new Promise((resolve, reject) => {
    let t_settled = false;
    const finishResolve = (value) => { if (!t_settled) { t_settled = true; resolve(value); } };
    const finishReject = (error) => { if (!t_settled) { t_settled = true; reject(error); } };
    let t_url;
    try {
      t_url = new URL(url_str);
    } catch {
      finishReject(new LlmError("无效的请求地址"));
      return;
    }
    if (t_url.protocol !== "http:" && t_url.protocol !== "https:") {
      finishReject(new LlmError(`不支持的请求协议: ${t_url.protocol}`));
      return;
    }
    const t_transport = t_url.protocol === "https:" ? https : http;
    let t_req;
    try {
      t_req = t_transport.request({
        hostname: t_url.hostname.replace(/^\[|\]$/g, ""),
        port: t_url.port,
        path: t_url.pathname + t_url.search,
        method: "POST",
        headers: { ...headers, "content-length": Buffer.byteLength(body_str), connection: "close" },
        agent: false,
      }, (t_res) => {
        const t_chunks = [];
        let t_bytes = 0;
        t_res.on("data", (t_chunk) => {
          t_bytes += Buffer.byteLength(t_chunk);
          if (t_bytes > maxBytes) {
            const t_error = new LlmError(`provider 响应超过 ${maxBytes} 字节上限`);
            t_error.response_too_large = true;
            t_req.destroy(t_error);
            finishReject(t_error);
            return;
          }
          t_chunks.push(Buffer.isBuffer(t_chunk) ? t_chunk : Buffer.from(t_chunk));
        });
        t_res.on("error", (t_error) => finishReject(t_error instanceof LlmError ? t_error : transientLlmError(t_error.message)));
        t_res.on("end", () => finishResolve({ status: t_res.statusCode, text: Buffer.concat(t_chunks).toString("utf8") }));
      });
    } catch (t_error) {
      finishReject(new LlmError(`请求创建失败: ${t_error.message}`));
      return;
    }
    t_req.on("error", (t_error) => finishReject(t_error instanceof LlmError ? t_error : transientLlmError(t_error.message)));
    t_timer = setTimeout(() => {
      const t_error = deadlineAt - Date.now() <= Number(timeout_ms) ? deadlineLlmError() : transientLlmError(`请求超时（${Math.max(1, Math.floor(t_remaining))}ms）`);
      t_req.destroy(t_error);
      finishReject(t_error);
    }, Math.max(1, Math.floor(t_remaining)));
    t_req.end(body_str);
    const clear = () => clearTimeout(t_timer);
    t_req.once("close", clear);
  }).catch((error) => {
    if (error instanceof LlmError) throw error;
    throw transientLlmError(error && error.message ? error.message : "网络请求失败");
  });
}

function isJsonModeUnsupportedError(error) {
  if (!(error instanceof LlmError) || error.json_mode_attempted !== true) return false;
  if (![400, 422].includes(error.http_status)) return false;
  const t_summary = String(error.provider_summary || "");
  return /(?:response[_ -]?format|json[_ -]?object|structured\s+output|json\s+mode)[\s\S]{0,80}(?:unsupported|not\s+supported|invalid|unknown|unrecognized)|(?:unsupported|not\s+supported|invalid|unknown|unrecognized)[\s\S]{0,80}(?:response[_ -]?format|json[_ -]?object|structured\s+output|json\s+mode)/i.test(t_summary);
}

async function callLlm(provider_info, system_prompt, user_payload, { deadlineAt: suppliedDeadline } = {}) {
  const t_provider = provider_info || {};
  const t_deadline = Number.isFinite(suppliedDeadline)
    ? suppliedDeadline
    : (Number.isFinite(t_provider.deadlineAt) ? t_provider.deadlineAt : Date.now() + PROVIDER_REQUEST_BUDGET_MS);
  const t_is_anthropic = t_provider.kind === "anthropic";
  const t_url = t_is_anthropic ? joinEndpoint(t_provider.baseURL, "/messages") : joinEndpoint(t_provider.baseURL, "/chat/completions");
  const t_headers = { "content-type": "application/json" };
  let t_body;
  if (t_is_anthropic) {
    t_headers["x-api-key"] = t_provider.apiKey;
    t_headers.authorization = `Bearer ${t_provider.apiKey}`;
    t_headers["anthropic-version"] = "2023-06-01";
    t_body = {
      model: t_provider.model,
      max_tokens: MAX_OUTPUT_TOKENS,
      thinking: { type: "disabled" },
      system: system_prompt,
      messages: [{ role: "user", content: user_payload }],
    };
  } else {
    t_headers.authorization = `Bearer ${t_provider.apiKey}`;
    t_body = {
      model: t_provider.model,
      max_tokens: MAX_OUTPUT_TOKENS,
      messages: [{ role: "system", content: system_prompt }, { role: "user", content: user_payload }],
    };
  }

  const t_use_json = !t_is_anthropic && t_provider.json_mode && t_provider.json_mode !== "off"
    && (t_provider.json_mode === "on" || readJsonModeCapability(t_provider) !== "unsupported");
  if (t_use_json) t_body.response_format = { type: "json_object" };

  const t_max_attempts = 1 + effectiveProviderRetries(t_provider.timeoutMs, t_provider.retries);
  let t_res = null;
  for (let t_attempt = 1; t_attempt <= t_max_attempts; t_attempt++) {
    if (Date.now() + MIN_REMAINING_MS >= t_deadline) throw deadlineLlmError();
    const t_is_last = t_attempt === t_max_attempts;
    try {
      t_res = await requestText(t_url, t_headers, JSON.stringify(t_body), t_provider.timeoutMs, { deadlineAt: t_deadline });
      const t_status = Number(t_res.status) || 0;
      if (t_status >= 200 && t_status < 300) break;
      const t_error = new LlmError(`HTTP ${t_status}${shortResponseSummary(t_res.text) ? `（${shortResponseSummary(t_res.text)}）` : ""}`);
      t_error.http_status = t_status;
      t_error.json_mode_attempted = t_use_json;
      t_error.provider_summary = shortResponseSummary(t_res.text);
      t_error.retryable = t_status === 429 || t_status >= 500;
      if (!t_is_last && t_error.retryable && Date.now() + MIN_REMAINING_MS < t_deadline) {
        logWrite("WARN", "provider", `LLM 第 ${t_attempt} 次失败（HTTP ${t_status}），在总 deadline 内重试`);
        continue;
      }
      throw t_error;
    } catch (t_error) {
      if (!t_is_last && t_error instanceof LlmError && t_error.retryable === true && Date.now() + MIN_REMAINING_MS < t_deadline) {
        logWrite("WARN", "provider", `LLM 第 ${t_attempt} 次失败（${String(t_error.message).slice(0, 120)}），在总 deadline 内重试`);
        continue;
      }
      throw t_error;
    }
  }

  let t_data;
  try {
    t_data = JSON.parse(t_res.text);
  } catch {
    throw new LlmError("响应不是合法 JSON");
  }
  let t_text = "";
  if (t_is_anthropic) {
    const t_stop = t_data.stop_reason;
    if (!(["end_turn", "stop_sequence"].includes(t_stop))) {
      throw new LlmError(`Anthropic 响应未完整结束（stop_reason=${String(t_stop)})`);
    }
    t_text = Array.isArray(t_data.content)
      ? t_data.content.filter((block) => block && block.type === "text").map((block) => block.text).join("")
      : "";
  } else {
    const t_choice = Array.isArray(t_data.choices) ? t_data.choices[0] : null;
    const t_finish = t_choice && t_choice.finish_reason;
    if (t_finish !== "stop") throw new LlmError(`OpenAI 响应未完整结束（finish_reason=${String(t_finish)})`);
    const t_content = t_choice && t_choice.message && t_choice.message.content;
    t_text = typeof t_content === "string" ? t_content : "";
  }
  if (!t_text.trim()) throw new LlmError("响应中没有完整文本内容");
  if (t_use_json) markJsonModeCapability(t_provider, "supported");
  return t_text;
}

export {
  ProviderError,
  LlmError,
  resolveProvider,
  callLlm,
  effectiveProviderRetries,
  providerWorstCaseMs,
  PROVIDER_REQUEST_BUDGET_MS,
  markJsonModeCapability,
  readJsonModeCapability,
  isJsonModeUnsupportedError,
};
