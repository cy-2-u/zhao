/**
 * 模块功能: 决策缓存——策略盐、缓存键与 allow/deny 结论的读写（锁内读改写）。
 *           缓存只承载模型的 allow/deny 结论，ask 是外层人工路径的产物，永不入缓存
 * 作者: zhao
 * 创建日期: 2026年10月01日
 * 描述: 从 reviewer.js 拆出（0.8.8 模块化）。策略盐覆盖策略版本、运行时设置、
 *       危险规则、快速通道、提示词与审批渠道（kind/baseURL/model，不纳入 api_key）；
 *       任一策略内容变化后旧结论立即失效。动态执行命令与不完整附件的缓存资格
 *       由调用方判定后经 cacheable 参数控制，本模块不做语义判断
 * 依赖: node:crypto ./common.js ./settings.js ./provider.js ./decision.js
 * 更新日期: 2026年10月01日
 */

import { createHash } from "node:crypto";
import path from "node:path";

import { CACHE_FILE, logWrite, readJsonFile, writeFileAtomic, withFileLock } from "./common.js";
import { loadSettings, loadRawDangerRules, loadRawFastAllow, loadSecurityPrompt } from "./settings.js";
import { resolveProvider } from "./provider.js";
import { ACTION_ALLOW, ACTION_DENY } from "./decision.js";

// 缓存的策略盐版本：决策语义或管线结构变化时递增，旧条目自然全部失效
// （0.8.7：fast/cd、动态脚本附件与 provider 输出合同收紧）
const POLICY_SALT_VERSION = "v6";

// 缓存条目上限：超限时丢弃过期项后按过期时间保留最新的一批，防止缓存文件无限增长
const MAX_CACHE_ENTRIES = 500;

/**
 * 函数功能: 递归按键排序的稳定序列化，保证等价输入命中同一缓存键
 * @param {*} value - 任意 JSON 值
 * @returns {string} 规范化 JSON 文本
 */
function stableStringify(value) {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map(stableStringify).join(",") + "]";
  }
  const t_keys = Object.keys(value).sort();
  return "{" + t_keys.map((t_key) => JSON.stringify(t_key) + ":" + stableStringify(value[t_key])).join(",") + "}";
}

/**
 * 函数功能: 计算当前安全策略的内容摘要（危险规则/快速通道/提示词/审批渠道），
 *           作为缓存键的盐——任一策略内容变化后旧结论立即失效。
 *           只保留渠道的 kind/baseURL/model，不纳入 api_key（避免密钥进入键运算）
 * @param {object} [settings] - 运行时配置
 * @param {{rulesRaw?: Array, fastRaw?: Array, prompt?: string}} [preloaded] - 同请求内
 *        已读取的原始策略内容（省去重复读盘；缺省现读）
 * @returns {string} 策略盐文本
 */
function buildPolicySalt(settings = loadSettings(), preloaded) {
  const t_parts = [POLICY_SALT_VERSION];
  const t_hash = (text) => createHash("sha256").update(String(text || "")).digest("hex").slice(0, 16);
  t_parts.push(`settings:${t_hash(stableStringify({
    enabled: settings.enabled,
    review_tools: settings.review_tools,
    timeout_ms: settings.timeout_ms,
    provider_retries: settings.provider_retries,
    provider_json_mode: settings.provider_json_mode,
    cache_ttl_seconds: settings.cache_ttl_seconds,
    max_payload_chars: settings.max_payload_chars,
    inspect_scripts: settings.inspect_scripts,
    script_max_bytes: settings.script_max_bytes,
    fast_allow_enabled: settings.fast_allow_enabled,
  }))}`);
  // 危险规则与快速通道：原始 JSON 逐条规范化，避免编译对象不可序列化
  t_parts.push(`rules:${t_hash(stableStringify(preloaded && preloaded.rulesRaw ? preloaded.rulesRaw : loadRawDangerRules()))}`);
  t_parts.push(`fast:${t_hash(stableStringify(preloaded && preloaded.fastRaw ? preloaded.fastRaw : loadRawFastAllow()))}`);
  t_parts.push(`prompt:${t_hash(preloaded && typeof preloaded.prompt === "string" ? preloaded.prompt : loadSecurityPrompt())}`);
  try {
    const t_provider = resolveProvider(settings);
    t_parts.push(`provider:${t_hash(`${t_provider.kind}|${t_provider.baseURL}|${t_provider.model}`)}`);
  } catch {
    // 渠道未配置/解析失败：以"未配置"参与盐，渠道补配后缓存自然失效
    t_parts.push("provider:none");
  }
  return t_parts.join("|");
}

/**
 * 函数功能: 计算缓存键
 * @param {string} tool_name - 标准工具名
 * @param {object} tool_input - 工具调用参数
 * @param {string} [extra_salt] - 附加加盐串（策略盐/cwd/脚本附件摘要）
 * @returns {string} sha256 十六进制摘要
 */
function computeCacheKey(tool_name, tool_input, extra_salt = "") {
  const t_base = `${tool_name}\n${stableStringify(tool_input)}`;
  return createHash("sha256").update(extra_salt ? `${t_base}\n${extra_salt}` : t_base).digest("hex");
}

/**
 * 函数功能: 审查缓存键——在 computeCacheKey 之上叠加策略盐、cwd 与脚本附件摘要。
 *           策略盐保证规则/提示词/渠道变化后旧结论不复用（旧 allow 不能跨策略存活）；
 *           cwd 必须参与键：同一命令文本在不同项目目录语义可能不同（如 node scripts/deploy.js）
 * @param {string} tool_name - 标准工具名
 * @param {object} tool_input - 工具调用参数
 * @param {string} cwd - hook 输入的工作目录
 * @param {object|null} attachments - 脚本附件（参与键）
 * @param {object} [settings] - 运行时配置
 * @param {string} [precomputed_salt] - 同请求内已算好的策略盐（省去重复哈希；缺省现算）
 * @returns {string} sha256 十六进制摘要
 */
function reviewCacheKey(tool_name, tool_input, cwd, attachments, settings = loadSettings(), precomputed_salt) {
  const t_parts = [precomputed_salt || buildPolicySalt(settings)];
  t_parts.push(`cwd:${path.resolve(String(cwd || "").trim() || process.cwd())}`);
  const t_attach_salt = hashAttachments(attachments);
  if (t_attach_salt) {
    t_parts.push(t_attach_salt);
  }
  return computeCacheKey(tool_name, tool_input, t_parts.join("|"));
}

/**
 * 函数功能: 计算附件的缓存加盐串（文件路径 + 内容摘要 + 附注），空附件返回空串
 * @param {object|null} attachments - collectScriptAttachments 的返回值
 * @returns {string} 加盐串
 */
function hashAttachments(attachments) {
  if (!attachments) {
    return "";
  }
  const t_parts = [];
  for (const t_file of attachments.files || []) {
    t_parts.push(JSON.stringify([t_file.path, t_file.truncated, t_file.total_bytes, createHash("sha256").update(t_file.content).digest("hex")]));
  }
  for (const t_note of attachments.notes || []) {
    t_parts.push(`note:${t_note}`);
  }
  return t_parts.join("|");
}

/**
 * 函数功能: 校验缓存条目结构——合法动作、字符串 reason、有限 expires
 * @param {*} entry - 待校验条目
 * @returns {boolean} 结构合法返回 true
 */
function validCacheEntry(entry) {
  return entry && typeof entry === "object" && !Array.isArray(entry)
    && (entry.action === ACTION_ALLOW || entry.action === ACTION_DENY)
    && typeof entry.reason === "string" && Number.isFinite(entry.expires);
}

/**
 * 函数功能: 读取缓存中未过期的决策
 * @param {string} key - 缓存键
 * @param {number} ttl_seconds - 有效期（秒），0 表示禁用缓存
 * @returns {object|null} {action, reason}，未命中或已过期返回 null
 */
function readCachedDecision(key, ttl_seconds) {
  if (!Number.isFinite(ttl_seconds) || ttl_seconds <= 0) {
    return null;
  }
  const t_cache = readJsonFile(CACHE_FILE(), {}, "cache");
  const t_entry = t_cache && !Array.isArray(t_cache) && Object.hasOwn(t_cache, key) ? t_cache[key] : null;
  if (!validCacheEntry(t_entry)) {
    return null;
  }
  if (Date.now() >= t_entry.expires || t_entry.expires - Date.now() > ttl_seconds * 1000) {
    return null;
  }
  return { action: t_entry.action, reason: t_entry.reason || "" };
}

/**
 * 函数功能: 写入缓存决策（惰性清理过期项并限制总量）
 * @param {string} key - 缓存键
 * @param {object} decision - {action, reason}
 * @param {number} ttl_seconds - 有效期（秒）
 * @returns {void}
 */
function writeCachedDecision(key, decision, ttl_seconds) {
  if (!Number.isFinite(ttl_seconds) || ttl_seconds <= 0 || !validCacheEntry({ ...decision, expires: Date.now() + ttl_seconds * 1000 })) {
    return;
  }
  // 读-改-写整体持锁：并发 hook 进程同时写缓存时避免"后写覆盖先写"丢条目
  withFileLock(CACHE_FILE() + ".lock", () => {
    const raw = readJsonFile(CACHE_FILE(), {}, "cache");
    const t_cache = Object.assign(Object.create(null), raw && typeof raw === "object" && !Array.isArray(raw) ? raw : {});
    const t_now = Date.now();
    for (const [t_k, t_v] of Object.entries(t_cache)) {
      if (!validCacheEntry(t_v) || t_v.expires <= t_now || t_v.expires - t_now > ttl_seconds * 1000) {
        delete t_cache[t_k];
      }
    }
    t_cache[key] = { ...decision, expires: t_now + ttl_seconds * 1000 };
    const t_entries = Object.entries(t_cache);
    if (t_entries.length > MAX_CACHE_ENTRIES) {
      t_entries.sort((a, b) => Number(a[1].expires) - Number(b[1].expires));
      for (let t_i = 0; t_i < t_entries.length - MAX_CACHE_ENTRIES; t_i++) {
        delete t_cache[t_entries[t_i][0]];
      }
    }
    writeFileAtomic(CACHE_FILE(), JSON.stringify(t_cache));
  });
}

export {
  stableStringify,
  buildPolicySalt,
  computeCacheKey,
  reviewCacheKey,
  hashAttachments,
  readCachedDecision,
  writeCachedDecision,
};
