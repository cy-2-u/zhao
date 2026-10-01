/**
 * 模块功能: PreToolUse hook 入口——stdin 读取 hook JSON，输出权限决策
 * 作者: zhao
 * 创建日期: 2026年08月29日
 * 描述: hooks.json 以 process 方式启动本文件（node src/hook_main.js）；
 *       stdout 只允许协议 JSON 或空（决策协议见 decision.js）；
 *       最外层兜底：任何未知异常以 exit 2 阻断，绝不放行。
 *       ask 一律交回客户端原生审批——插件不再自建审批 UI，也不猜测远程/子智能体
 *       上下文（客户端未提供可信来源字段，字符串猜测只会造成误路由）
 * 功能:
 *   - stdin 全量读取与容错解析（共享实现见 common.js readHookJsonInput）
 *   - 调用审查管线并输出决策
 *   - AUTO_REVIEW_DEBUG=1 时记录输入顶层字段名与标量值（不含载荷内容），用于适配客户端字段
 * 依赖: ./reviewer.js ./decision.js ./common.js ./redaction.js
 * 更新日期: 2026年10月01日
 */

import { reviewToolUse, pendingAskKeyForInput, writePendingAskMarker } from "./reviewer.js";
import { emitDecision, emitCrash, ACTION_ASK, ACTION_DENY } from "./decision.js";
import { logWrite, readHookJsonInput, logHookInputFields } from "./common.js";
import { redactSecrets } from "./redaction.js";

// 输入形态异常到 fail-closed 文案的映射：放行等于让一个未知调用绕过全部审查层；
// 阻断会让协议漂移立刻显式暴露（日志可排查），而不是静默漏过
const INPUT_ERROR_REASONS = {
  tooLarge: "[auto-review] hook 输入超过 1MB 字节上限，无法安全确认审查对象，已阻断。",
  empty: "[auto-review] hook 输入为空，无法确认审查对象，已阻断。如频繁出现请检查客户端版本或暂时禁用本插件。",
  invalid: "[auto-review] hook 输入不是合法 JSON，无法确认审查对象，已阻断。",
  notObject: "[auto-review] hook 输入不是 JSON 对象，无法确认审查对象，已阻断。",
};

/**
 * 函数功能: 主流程：stdin → JSON → 审查管线 → 决策输出
 * @returns {Promise<void>}
 */
async function main() {
  const t_input_result = await readHookJsonInput("hook");
  if (t_input_result.status !== "ok") {
    emitDecision({
      action: ACTION_DENY,
      reason: INPUT_ERROR_REASONS[t_input_result.status],
    });
    return;
  }
  const t_input = t_input_result.input;

  // 调试开关：记录 hook 输入的顶层字段名与非敏感值形态，用于适配客户端实际
  // 下发的字段（如权限模式）；载荷本体（tool_input）只记长度不记内容
  logHookInputFields("debug-input", t_input);

  // 审查管线保证不抛异常并返回最终决策；ask 交客户端原生审批，
  // 会话内重复指令的放行由客户端原生"会话内允许"语义承接
  const t_decision = await reviewToolUse(t_input);
  if (t_decision && t_decision.action === ACTION_ASK) {
    // 转人工的命令留短时标记：PermissionRequest 层看到标记即退避，
    // "模型不可用→人工"的既定路径不被第二层 hook 翻转为自动放行。
    // 写失败只损失"省一轮重试"，方向安全（第二层会重新裁决），记日志供诊断
    const t_marker_ok = writePendingAskMarker(pendingAskKeyForInput(t_input));
    if (!t_marker_ok) {
      logWrite("WARN", "hook", "pending 标记写入失败，第二层将重新裁决本命令");
    }
  }
  emitDecision(t_decision);
}

// 最外层兜底：未知异常阻断（exit 2），宁可打断工作流也不带病放行
main().catch((t_error) => {
  logWrite("ERROR", "hook", `未捕获异常: ${redactSecrets(t_error && t_error.stack ? t_error.stack.split("\n")[0] : String(t_error))}`);
  emitCrash(redactSecrets(t_error && t_error.message ? t_error.message : "未知异常"));
});
