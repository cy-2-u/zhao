/**
 * 模块功能: 专用审批渠道解析与安全子 agent 的 LLM 调用（零第三方依赖）
 * 作者: hh-zyb
 * 创建日期: 2026年08月29日
 * 描述: 审批只使用 review_provider.json（用户手填的专用渠道），不回落 ZCode provider 表——
 *       Coding Plan 渠道需客户端签名无法直连，混合回落只会造成"看似配好了实际不可用"的错觉；
 *       未配置/配置不完整时 LLM 审查直接不可用，由上层转人工审批（绝不自动许可）；
 *       按 kind 选择 Anthropic Messages 或 OpenAI Chat Completions 协议直连调用；
 *       超时/网络抖动/HTTP 5xx/429 自动重试 1 次——渠道"慢而不死"的尖峰（实测 9s 成功
 *       与 30s 超时交替出现）第二次尝试常能成功，最坏 2×timeout 后仍失败才上抛兜底，
 *       hook 预算 1h 内无压力；4xx 配置类错误与响应结构异常不重试（重试改变不了结局）；
 *       传输层用 node:http/https 而非 fetch——undici 的 keep-alive 连接池会在
 *       process.exit 时触发 libuv 断言崩溃（Windows 退出码 0xC0000409），客户端
 *       把非零退出码视为 hook 故障后丢弃已写出的协议 JSON，自动审批就失效了
 * 功能:
 *   - resolveProvider: 专用审批渠道解析（文件读取、完整性校验、协议推断）
 *   - requestText: node:http(s) 单次 POST（connection:close，响应读完 socket 即关）
 *   - callLlm: 通用单轮对话调用（总时长超时控制）
 * 依赖: node:http node:https ./common.js
 * 更新日期: 2026年09月17日
 */

import http from "node:http";
import https from "node:https";

import { REVIEW_PROVIDER_FILE, logWrite, readJsonFile } from "./common.js";

// provider 配置解析失败（未配置专用渠道 / 缺字段等），携带面向日志的原因
class ProviderError extends Error {}

// LLM 调用失败（网络 / 超时 / HTTP 非 2xx / 响应结构异常）
class LlmError extends Error {}

// 结论 JSON 很小，但必须给混合推理模型的正文留足额度（thinking 已显式关闭，此为双保险）
const MAX_OUTPUT_TOKENS = 2048;

/**
 * 函数功能: 构造可重试的网络层错误（请求超时/连接重置/拒连等瞬时故障）
 * @param {string} message - 错误消息
 * @returns {LlmError} 带 retryable=true 标记的错误
 */
function transientLlmError(message) {
  const t_error = new LlmError(message);
  t_error.retryable = true;
  return t_error;
}

/**
 * 函数功能: 读取专用审批渠道配置文件（review_provider.json，用户手填）——审批的唯一 LLM 来源。
 *           全空（未填写的模板）视为未配置；半填（只填一项）视为配置错误直接报出
 * @returns {{kind: string, baseURL: string, apiKey: string, model: string}|null}
 *          未填写返回 null；存在但填写不完整时抛 ProviderError
 */
function loadReviewProviderOverride() {
  const t_raw = readJsonFile(REVIEW_PROVIDER_FILE(), null, "provider");
  if (!t_raw || typeof t_raw !== "object") {
    return null;
  }

  // 下划线前缀键（如 _说明）是模板里的填写指引，参与校验前剥离
  const t_entry = {};
  for (const [t_key, t_value] of Object.entries(t_raw)) {
    if (!t_key.startsWith("_")) {
      t_entry[t_key] = t_value;
    }
  }

  const t_base_url = String(t_entry.base_url || "").trim();
  const t_api_key = String(t_entry.api_key || "").trim();
  // 全空 = 未填写的模板：视为未配置（LLM 审查不可用，命令交回客户端原生流程，无任何回落渠道）
  if (!t_base_url && !t_api_key) {
    return null;
  }
  // 半填 = 配置错误：报出来而不是静默当未配置
  if (!t_base_url || !t_api_key) {
    throw new ProviderError("review_provider.json 只填了 base_url/api_key 之一（要么补全，要么两者都留空视为未配置）");
  }

  const t_kind = String(t_entry.api_kind || "").trim().toLowerCase();
  if (t_kind && t_kind !== "anthropic" && t_kind !== "openai") {
    throw new ProviderError("review_provider.json 的 api_kind 只接受 anthropic 或 openai");
  }
  // 未填协议时按端点路径推断：含 anthropic 即 Anthropic Messages 协议，否则 OpenAI 兼容
  const t_effective_kind = t_kind || (/anthropic/i.test(t_base_url) ? "anthropic" : "openai");

  logWrite("INFO", "provider", `使用专用审批渠道 ${t_base_url}（kind=${t_effective_kind}）`);
  return {
    kind: t_effective_kind,
    baseURL: t_base_url,
    apiKey: t_api_key,
    model: String(t_entry.model || "").trim(),
  };
}

/**
 * 函数功能: 解析审批专用渠道连接信息。review_provider.json 是唯一 LLM 来源，
 *           未配置/配置不完整直接报错——不回落 ZCode provider 表（主 agent 渠道多为
 *           需客户端签名的 Coding Plan，直连必败，静默回落只会掩盖"审批没在工作"）
 * @param {object} settings - 运行时配置（timeout_ms）
 * @returns {{kind: string, baseURL: string, apiKey: string, model: string, timeoutMs: number, source: string}}
 * @throws {ProviderError} 专用渠道未配置或配置不完整时抛出，由上层兜底 pass
 */
function resolveProvider(settings) {
  const t_file_provider = loadReviewProviderOverride();
  if (!t_file_provider) {
    throw new ProviderError("专用审批渠道未配置：用 provider path 创建 ~/.zcode/auto-review/review_provider.json 并填写 base_url / api_key / model（未配置时 LLM 审查不可用，命令转人工审批）");
  }
  const t_model = t_file_provider.model;
  if (!t_model) {
    throw new ProviderError("review_provider.json 未填 model，请补上审批使用的模型名");
  }
  return {
    kind: t_file_provider.kind,
    baseURL: t_file_provider.baseURL,
    apiKey: t_file_provider.apiKey,
    model: t_model,
    timeoutMs: (settings && settings.timeout_ms) || 30000,
    source: "file",
  };
}

/**
 * 函数功能: 拼接 API 地址——baseURL 已带版本段（/v1、/v4 等）或完整端点时不再重复追加
 * @param {string} base_url - provider baseURL（末尾斜杠容忍）
 * @param {string} endpoint - 接口路径（如 "/messages"、"/chat/completions"）
 * @returns {string} 完整 URL
 */
function joinEndpoint(base_url, endpoint) {
  const t_base = base_url.replace(/\/+$/, "");
  if (t_base.toLowerCase().endsWith(endpoint.toLowerCase())) {
    return t_base;
  }
  // 已带 /v1 /v2 /v4 等版本段：只补接口名
  if (/\/v\d+$/.test(t_base)) {
    return t_base + endpoint;
  }
  // 无版本段：补标准 /v1 前缀（Anthropic Messages 与 OpenAI 兼容端点的主流约定）
  return t_base + "/v1" + endpoint;
}

/**
 * 函数功能: 底层 HTTP(S) 请求——node:http/https 直连，keep-alive 池是 hook 的隐形杀手：
 *           复用中的 socket 在 process.exit 时触发 libuv 断言崩溃（Windows 退出码
 *           0xC0000409），协议 JSON 已写出也会被客户端当 hook 故障丢弃。
 *           connection:close + 请求级一次性 Agent 保证响应读完 socket 即关，进程干净退出
 * @param {string} url_str - 完整请求 URL
 * @param {object} headers - 请求头
 * @param {string} body_str - 请求体（JSON 文本）
 * @param {number} timeout_ms - 总时长上限（毫秒）
 * @returns {Promise<{status: number, text: string}>} HTTP 状态码与响应全文
 * @throws {LlmError} URL 非法、协议不支持、网络错误、超时
 */
function requestText(url_str, headers, body_str, timeout_ms) {
  let t_timer = null;
  const t_promise = new Promise((t_resolve, t_reject) => {
    let t_url;
    try {
      t_url = new URL(url_str);
    } catch {
      t_reject(new LlmError(`无效的请求地址: ${url_str}`)); // 配置类错误，不可重试
      return;
    }
    if (t_url.protocol !== "http:" && t_url.protocol !== "https:") {
      t_reject(new LlmError(`不支持的请求协议: ${t_url.protocol}`)); // 配置类错误，不可重试
      return;
    }
    const t_transport = t_url.protocol === "https:" ? https : http;
    const t_req = t_transport.request(
      {
        hostname: t_url.hostname,
        port: t_url.port,
        path: t_url.pathname + t_url.search,
        method: "POST",
        headers: { ...headers, connection: "close" },
        // agent:false = 请求级一次性 Agent（keepAlive:false），不复用也不驻留连接
        agent: false,
      },
      (t_res) => {
        const t_chunks = [];
        t_res.on("data", (t_chunk) => t_chunks.push(t_chunk));
        t_res.on("error", (t_error) => t_reject(t_error instanceof LlmError ? t_error : transientLlmError(t_error.message)));
        t_res.on("end", () => {
          t_resolve({ status: t_res.statusCode, text: Buffer.concat(t_chunks).toString("utf8") });
        });
      },
    );
    t_req.on("error", (t_error) => t_reject(t_error instanceof LlmError ? t_error : transientLlmError(t_error.message)));
    // 总时长兜底：request 自带的 timeout 只监听 socket 空闲，防不住慢速滴流型服务端
    t_timer = setTimeout(() => t_req.destroy(transientLlmError(`请求超时（${timeout_ms}ms）`)), timeout_ms);
    t_req.end(body_str);
  });
  return t_promise.finally(() => clearTimeout(t_timer));
}

/**
 * 函数功能: 执行一次 LLM 单轮调用（系统提示 + 用户消息），带总时长超时控制。
 *           重试策略：请求超时/网络抖动/HTTP 5xx/429 最多重试 1 次；4xx 配置类错误
 *           与响应结构异常不重试
 * @param {object} provider_info - resolveProvider 的返回值
 * @param {string} system_prompt - 系统提示词（安全审查提示词）
 * @param {string} user_payload - 用户消息（审查载荷）
 * @returns {Promise<string>} 模型输出的文本
 * @throws {LlmError} 重试后仍超时/网络错误/HTTP 非 2xx，或响应结构异常
 */
async function callLlm(provider_info, system_prompt, user_payload) {
  const t_is_anthropic = provider_info.kind === "anthropic";
  const t_url = t_is_anthropic
    ? joinEndpoint(provider_info.baseURL, "/messages")
    : joinEndpoint(provider_info.baseURL, "/chat/completions");

  const t_headers = { "content-type": "application/json" };
  let t_body;
  if (t_is_anthropic) {
    // 双认证头同发：官方 Anthropic 端点认 x-api-key，各类中转/网关（如 Z.ai、bigmodel 的
    // Anthropic 兼容层）普遍认 Authorization Bearer；多发一个头对任一类端点都无害
    t_headers["x-api-key"] = provider_info.apiKey;
    t_headers["authorization"] = `Bearer ${provider_info.apiKey}`;
    t_headers["anthropic-version"] = "2023-06-01";
    t_body = {
      model: provider_info.model,
      max_tokens: MAX_OUTPUT_TOKENS,
      // GLM 系为混合推理模型：默认思考会吃掉大量时延与 token 额度，
      // 实测关闭后 16s→5s 且正文稳定存在（否则长思考可耗尽 max_tokens 导致正文为空）
      thinking: { type: "disabled" },
      system: system_prompt,
      messages: [{ role: "user", content: user_payload }],
    };
  } else {
    t_headers["authorization"] = `Bearer ${provider_info.apiKey}`;
    t_body = {
      model: provider_info.model,
      max_tokens: MAX_OUTPUT_TOKENS,
      messages: [
        { role: "system", content: system_prompt },
        { role: "user", content: user_payload },
      ],
    };
  }

  // 最多两次尝试：t_res 在成功 break 后必非空（末次失败一律走 throw）
  let t_res = null;
  for (let t_attempt = 1; t_attempt <= 2; t_attempt++) {
    const t_is_last = t_attempt === 2;
    try {
      t_res = await requestText(t_url, t_headers, JSON.stringify(t_body), provider_info.timeoutMs);
      const t_status = Number(t_res.status) || 0;
      if (t_status >= 200 && t_status < 300) {
        break;
      }
      if (!t_is_last && (t_status === 429 || t_status >= 500)) {
        logWrite("WARN", "provider", `LLM 调用第 ${t_attempt} 次失败（HTTP ${t_status}），重试 1 次`);
        continue;
      }
      throw new LlmError(`HTTP ${t_status}: ${t_res.text.slice(0, 300)}`);
    } catch (t_error) {
      if (!t_is_last && t_error instanceof LlmError && t_error.retryable === true) {
        logWrite("WARN", "provider", `LLM 调用第 ${t_attempt} 次失败（${t_error.message.slice(0, 100)}），重试 1 次`);
        continue;
      }
      throw t_error;
    }
  }
  const t_status = Number(t_res.status) || 0;
  let t_data;
  try {
    t_data = JSON.parse(t_res.text);
  } catch {
    throw new LlmError(`响应不是合法 JSON: ${t_res.text.slice(0, 120)}`);
  }
  const t_text = t_is_anthropic
    ? (t_data.content || []).filter((t_block) => t_block.type === "text").map((t_block) => t_block.text).join("")
    : (t_data.choices && t_data.choices[0] && t_data.choices[0].message && t_data.choices[0].message.content) || "";
  if (!t_text) {
    throw new LlmError("响应中没有文本内容");
  }
  return t_text;
}

export {
  ProviderError,
  LlmError,
  resolveProvider,
  callLlm,
};
