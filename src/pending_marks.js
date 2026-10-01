/**
 * 模块功能: pending 转人工标记——PreToolUse ask 与 PermissionRequest 之间的
 *           短时效凭证，防止"模型不可用→人工"的既定路径被第二层翻转为自动放行
 * 作者: zhao
 * 创建日期: 2026年10月01日
 * 描述: 从 reviewer.js 拆出（0.8.8 模块化）。标记键含工具名、完整 tool_input、
 *       规则文本、cwd 与请求身份摘要，两层 hook 对同一条命令算出同一个键；
 *       读取用同一文件句柄 fstat + 64KB 上限（消除 stat/read TOCTOU）。
 *       三态合同：hit=第一层刚裁定人工（退避）、miss=无标记（照常审查）、
 *       error/corrupt=状态不可靠（第二层必须退避，不能继续自动裁决）
 * 依赖: node:crypto ./common.js ./tool_text.js ./decision_cache.js
 * 更新日期: 2026年10月01日
 */

import { createHash } from "node:crypto";

import { PENDING_ASKS_FILE, logWrite, readTextFileBounded, writeFileAtomic, withFileLock } from "./common.js";
import { normalizeToolName, buildRuleText } from "./tool_text.js";
import { stableStringify } from "./decision_cache.js";

// PreToolUse 转人工标记的有效期：PreToolUse ask 与 PermissionRequest 之间只隔毫秒级，
// 窗口放大到 15s 覆盖慢机器上的客户端排队；超窗标记视为陈旧，第二层照常审查
const PENDING_ASK_TTL_MS = 15 * 1000;
// 标记文件条目上限：防止异常风暴（反复不可用）把文件刷大，超限按时间淘汰最旧的
const MAX_PENDING_ASKS = 50;
const MAX_PENDING_FILE_BYTES = 64 * 1024;

/**
 * 函数功能: 计算 pending-ask 标记键——工具名 + 规则层匹配文本 + 完整输入 +
 *           cwd + 请求身份的摘要。两层 hook 的输入字段形态可能有差异，
 *           用归一化后的命令文本而非原始 JSON 做键，保证 PreToolUse 写入与
 *           PermissionRequest 查询对同一条命令算出同一个键
 * @param {object} hook_input - hook stdin 的 JSON
 * @returns {string} sha256 十六进制摘要
 */
function pendingAskKeyForInput(hook_input) {
  const t_name = normalizeToolName(hook_input && (hook_input.tool_name || hook_input.toolName));
  const t_input = hook_input && hook_input.tool_input && typeof hook_input.tool_input === "object" ? hook_input.tool_input : {};
  const t_rule_text = buildRuleText(t_name, t_input).ruleText;
  const t_identity = {
    session_id: hook_input && (hook_input.session_id || hook_input.sessionId || ""),
    request_id: hook_input && (hook_input.request_id || hook_input.requestId || ""),
    tool_use_id: hook_input && (hook_input.tool_use_id || hook_input.toolUseId || ""),
  };
  const t_cwd = String((hook_input && hook_input.cwd) || "").trim();
  return createHash("sha256")
    .update(stableStringify({ tool_name: t_name, tool_input: t_input, rule_text: t_rule_text, cwd: t_cwd, identity: t_identity }))
    .digest("hex");
}

/**
 * 函数功能: 读取 pending 标记文件并区分缺失、有效和损坏/不可读状态。
 *           readJsonFile 的 fallback 会把损坏文件伪装成空表，这里必须保留错误信号，
 *           否则 PermissionRequest 可能在第一层人工路径失败后继续自动放行。
 * @returns {{status: "missing"|"ok"|"corrupt"|"error", map?: object, error?: Error}}
 */
function readPendingAskMap() {
  try {
    // 同一句柄完成 fstat 与读取：stat 后文件被替换/增长不会绕过字节上限
    const t_raw = readTextFileBounded(PENDING_ASKS_FILE(), MAX_PENDING_FILE_BYTES);
    let t_parsed;
    try {
      t_parsed = JSON.parse(t_raw.replace(/^\uFEFF/, ""));
    } catch (t_error) {
      return { status: "corrupt", error: t_error };
    }
    if (!t_parsed || typeof t_parsed !== "object" || Array.isArray(t_parsed)) {
      return { status: "corrupt", error: new Error("pending 标记根节点不是对象") };
    }
    if (Object.keys(t_parsed).length > MAX_PENDING_ASKS) {
      return { status: "error", error: new Error("pending 标记条目超过上限") };
    }
    for (const t_value of Object.values(t_parsed)) {
      if (!Number.isFinite(t_value) || t_value > Date.now() + 1000 || t_value < 0) {
        return { status: "corrupt", error: new Error("pending 标记时间戳非法") };
      }
    }
    return { status: "ok", map: t_parsed };
  } catch (t_error) {
    if (t_error && t_error.code === "ENOENT") {
      return { status: "missing", map: {} };
    }
    return { status: "error", error: t_error };
  }
}

/**
 * 函数功能: 写入 pending-ask 标记（PreToolUse 层决定转人工时调用）。
 *           标记 + 短 TTL 是"这条命令已由第一层裁定人工"的凭证，PermissionRequest
 *           层据此退避；持锁读改写防并发 hook 互相覆盖，返回 false 表示未可靠写入。
 *           调用方应记录写失败日志——写失败时第二层将重新裁决（方向安全：多审一次）
 * @param {string} key - pendingAskKeyForInput 的返回值
 * @returns {boolean} 是否写入成功
 */
function writePendingAskMarker(key) {
  if (!key) return false;
  try {
    const t_result = withFileLock(PENDING_ASKS_FILE() + ".lock", () => {
      const t_loaded = readPendingAskMap();
      if (t_loaded.status === "error") {
        logWrite("WARN", "pending", "读取 pending 标记失败，放弃写入");
        return false;
      }
      // 损坏文件只在第一层准备写入新凭证时重建；PermissionRequest 读取损坏文件则退避。
      const t_map = t_loaded.status === "ok" || t_loaded.status === "corrupt" ? (t_loaded.map || {}) : {};
      const t_now = Date.now();
      for (const [t_k, t_ts] of Object.entries(t_map)) {
        if (!Number.isFinite(t_ts) || t_ts > t_now + 1000 || t_ts < 0 || t_now - t_ts > PENDING_ASK_TTL_MS) {
          delete t_map[t_k];
        }
      }
      t_map[key] = t_now;
      const t_entries = Object.entries(t_map);
      if (t_entries.length > MAX_PENDING_ASKS) {
        t_entries.sort((a, b) => a[1] - b[1]);
        for (let t_i = 0; t_i < t_entries.length - MAX_PENDING_ASKS; t_i++) {
          delete t_map[t_entries[t_i][0]];
        }
      }
      return writeFileAtomic(PENDING_ASKS_FILE(), JSON.stringify(t_map));
    });
    return t_result === true;
  } catch (t_error) {
    logWrite("WARN", "pending", `写入 pending 标记异常: ${t_error && t_error.message ? t_error.message : "未知错误"}`);
    return false;
  }
}

/**
 * 函数功能: 查询并消费 pending-ask 标记（PermissionRequest 层调用）。
 *           返回 hit/miss/error 三态；缺文件是正常 miss，锁/读取/消费失败必须 error。
 * @param {string} key - pendingAskKeyForInput 的返回值
 * @returns {{status: "hit"|"miss"|"error", hit: boolean, error?: Error}}
 */
function takePendingAskMarkerState(key) {
  try {
    const t_result = withFileLock(PENDING_ASKS_FILE() + ".lock", () => {
      const t_loaded = readPendingAskMap();
      if (t_loaded.status === "missing") {
        return { status: "miss", hit: false };
      }
      if (t_loaded.status !== "ok") {
        logWrite("WARN", "pending", "读取 pending 标记不可靠，PermissionRequest 保守退避");
        return { status: "error", hit: false, error: t_loaded.error };
      }
      const t_map = t_loaded.map;
      const t_now = Date.now();
      let t_fresh = false;
      let t_changed = false;
      for (const [t_k, t_ts] of Object.entries(t_map)) {
        if (!Number.isFinite(t_ts) || t_ts > t_now + 1000 || t_ts < 0 || t_now - t_ts > PENDING_ASK_TTL_MS) {
          delete t_map[t_k];
          t_changed = true;
          continue;
        }
        if (t_k === key) t_fresh = true;
      }
      if (Object.hasOwn(t_map, key)) {
        delete t_map[key];
        t_changed = true;
      }
      if (t_changed && !writeFileAtomic(PENDING_ASKS_FILE(), JSON.stringify(t_map))) {
        logWrite("WARN", "pending", "消费 pending 标记失败，PermissionRequest 保守退避");
        return { status: "error", hit: false };
      }
      return { status: t_fresh ? "hit" : "miss", hit: t_fresh };
    });
    if (!t_result || (t_result.status !== "hit" && t_result.status !== "miss" && t_result.status !== "error")) {
      return { status: "error", hit: false };
    }
    return t_result;
  } catch (t_error) {
    logWrite("WARN", "pending", `消费 pending 标记异常: ${t_error && t_error.message ? t_error.message : "未知错误"}`);
    return { status: "error", hit: false, error: t_error };
  }
}

export {
  pendingAskKeyForInput,
  writePendingAskMarker,
  takePendingAskMarkerState,
};
