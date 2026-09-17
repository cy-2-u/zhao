/**
 * 模块功能: PreToolUse hook 入口——stdin 读取 hook JSON，输出权限决策
 * 作者: hh-zyb
 * 创建日期: 2026年08月29日
 * 描述: hooks.json 以 process 方式启动本文件（node src/hook_main.js）；
 *       stdout 只允许协议 JSON 或空（决策协议见 decision.js）；
 *       最外层兜底：任何未知异常以 exit 2 阻断，绝不放行。
 *       ask 一律交回客户端原生审批——插件不再自建审批 UI，也不猜测远程/子智能体
 *       上下文（客户端未提供可信来源字段，字符串猜测只会造成误路由）
 * 功能:
 *   - stdin 全量读取与容错解析
 *   - 调用审查管线并输出决策
 *   - AUTO_REVIEW_DEBUG=1 时记录输入顶层字段名与标量值（不含载荷内容），用于适配客户端字段
 * 依赖: ./reviewer.js ./decision.js ./common.js
 * 更新日期: 2026年09月17日
 */

import { reviewToolUse } from "./reviewer.js";
import { emitDecision, emitCrash, ACTION_DENY } from "./decision.js";
import { logWrite } from "./common.js";

/**
 * 函数功能: 全量读取 stdin（hook 输入一次性传入，无流式交互）
 * @returns {Promise<string>} stdin 的完整文本
 */
function readStdinAll() {
  return new Promise((resolve, reject) => {
    const t_chunks = [];
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (t_chunk) => t_chunks.push(t_chunk));
    process.stdin.on("end", () => resolve(t_chunks.join("")));
    process.stdin.on("error", reject);
  });
}

/**
 * 函数功能: 主流程：stdin → JSON → 审查管线 → 决策输出
 * @returns {Promise<void>}
 */
async function main() {
  const t_raw = await readStdinAll();

  // 空输入或非 JSON：无法确认要审查什么。按 fail-closed 阻断——放行等于让一个
  // 未知调用绕过全部审查层；阻断会让协议漂移立刻显式暴露（日志可排查），而不是静默漏过
  if (!t_raw.trim()) {
    logWrite("WARN", "hook", "stdin 为空，无法确认审查对象，阻断");
    emitDecision({
      action: ACTION_DENY,
      reason: "[auto-review] hook 输入为空，无法确认审查对象，已阻断。如频繁出现请检查客户端版本或暂时禁用本插件。",
    });
    return;
  }
  let t_input;
  try {
    t_input = JSON.parse(t_raw);
  } catch {
    logWrite("WARN", "hook", `stdin 非合法 JSON（前 80 字符: ${t_raw.slice(0, 80).replace(/\s+/g, " ")}），阻断`);
    emitDecision({
      action: ACTION_DENY,
      reason: "[auto-review] hook 输入不是合法 JSON，无法确认审查对象，已阻断。",
    });
    return;
  }
  if (!t_input || typeof t_input !== "object" || Array.isArray(t_input)) {
    logWrite("WARN", "hook", "stdin JSON 不是对象，阻断");
    emitDecision({
      action: ACTION_DENY,
      reason: "[auto-review] hook 输入不是 JSON 对象，无法确认审查对象，已阻断。",
    });
    return;
  }

  // 调试开关：记录 hook 输入的顶层字段名与非敏感值形态，用于适配客户端实际
  // 下发的字段（如权限模式）；载荷本体（tool_input）只记长度不记内容
  if (process.env.AUTO_REVIEW_DEBUG) {
    const t_fields = {};
    for (const [t_key, t_value] of Object.entries(t_input)) {
      t_fields[t_key] = t_key === "tool_input" ? `<${typeof t_value}>` : String(t_value).slice(0, 120);
    }
    logWrite("INFO", "debug-input", JSON.stringify(t_fields));
  }

  // 审查管线保证不抛异常并返回最终决策；ask 交客户端原生审批，
  // 会话内重复指令的放行由客户端原生"会话内允许"语义承接
  const t_decision = await reviewToolUse(t_input);
  emitDecision(t_decision);
}

// 最外层兜底：未知异常阻断（exit 2），宁可打断工作流也不带病放行
main().catch((t_error) => {
  logWrite("ERROR", "hook", `未捕获异常: ${t_error && t_error.stack ? t_error.stack.split("\n")[0] : String(t_error)}`);
  emitCrash(t_error && t_error.message ? t_error.message : "未知异常");
});
