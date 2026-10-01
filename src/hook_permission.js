/**
 * 模块功能: PermissionRequest hook 入口——客户端即将弹原生权限框时介入审查。
 *           全自动审批语义：hooks.json 对本层不设 matcher（省略即匹配所有工具）——
 *           客户端实际触发 PermissionRequest 的请求（review_tools 名单外工具如
 *           默认配置下的 Write/Edit、MCP/扩展工具等）一律经 force_review 强制送
 *           安全子 agent 裁决：模型 allow 即自动放行（弹窗消失），deny 拦截并回传
 *           分析；只有模型不可用（兜底 ask）才退避交回原生弹窗。实测（0.8.4）当前
 *           客户端版本不把子智能体（Agent/Task）的创建与内部调用送入本层——Agent
 *           输入识别保留为休眠能力，这类请求由客户端权限系统裁决。plan 与 yolo/完全访问是例外——前者是客户端只读规划的硬
 *           边界，后者客户端本来就全放行，插件在这两种模式下隐身。
 *           客户端若不触发此 hook，则插件无法从本层接管该路径；退避方向始终是
 *           "交人工"而不是"放行"——本层故障只损失自动化，不损失安全性
 * 作者: zhao
 * 创建日期: 2026年09月18日
 * 描述: hooks.json 以 process 方式在 PermissionRequest 事件上启动本文件；
 *       输出契约使用客户端实际解析的 hookSpecificOutput.decision.behavior/message，
 *       与 PreToolUse 的 permissionDecision/permissionDecisionReason 结构不同；
 *       AUTO_REVIEW_DEBUG=1 时记录输入顶层字段名与标量值（不含载荷内容），用于适配客户端字段
 * 依赖: ./reviewer.js ./decision.js ./common.js
 * 更新日期: 2026年10月01日
 */

import {
  reviewToolUse,
  normalizeToolName,
  buildRuleText,
  pendingAskKeyForInput,
  takePendingAskMarkerState,
  isPassthroughMode,
} from "./reviewer.js";
import { emitPass, emitPermissionDecision, ACTION_ALLOW, ACTION_DENY } from "./decision.js";
import { logWrite, readHookJsonInput, logHookInputFields } from "./common.js";
import { redactSecrets } from "./redaction.js";

/**
 * 函数功能: 主流程：stdin → JSON → 退避判定 → 审查管线 → 决策输出。
 *           退避形态：输入读不懂、plan/完全访问（yolo）边界、第一层刚裁定人工
 *           （pending 标记命中；标记损坏/读取/消费失败同样退避）、模型不可用兜底 ask
 * @returns {Promise<void>}
 */
async function main() {
  const t_input_result = await readHookJsonInput("permission");
  // 输入读不懂就不干预：本层的失败形态是"保持原生弹窗"，不是阻断（阻断会
  // 让所有权限弹窗都被一个 schema 适配问题卡死）也不是放行
  if (t_input_result.status !== "ok") {
    return emitPass();
  }
  const t_input = t_input_result.input;

  // 调试开关：记录 hook 输入的顶层字段名与非敏感值形态，用于适配客户端实际字段
  logHookInputFields("debug-permission-input", t_input);

  // 模式闸门与 PreToolUse 同判定：plan（只读规划硬边界）与 yolo/完全访问（客户端
  // 原生全放行）退避；其余模式（含字段缺失）一律接管，人工弹窗只允许在模型不可用时出现
  if (isPassthroughMode(t_input)) {
    logWrite("INFO", "permission", "plan/完全访问模式退避，交回客户端原生流程");
    return emitPass();
  }

  // 识别不了审查对象的请求不裁决：缺工具名或提取不出命令文本，模型无从审查
  const t_name = normalizeToolName(t_input.tool_name || t_input.toolName);
  const t_tool_input = t_input.tool_input && typeof t_input.tool_input === "object" ? t_input.tool_input : {};
  if (!t_name || !buildRuleText(t_name, t_tool_input).ruleText) {
    logWrite("INFO", "permission", "无法从输入中识别审查对象，退避交客户端原生审批");
    return emitPass();
  }

  // 第一层（PreToolUse）刚把这条命令转人工（模型不可用兜底）：退避让人工路径
  // 生效，也避免第二层再烧一轮注定失败的重试
  const t_pending = takePendingAskMarkerState(pendingAskKeyForInput(t_input));
  if (t_pending.status === "hit") {
    logWrite("INFO", "permission", "命中第一层刚转人工的标记，退避交用户裁决");
    return emitPass();
  }
  // 标记缺失表示本层可能是独立进入的路径，照常审查；标记损坏、读取失败或消费失败
  // 则无法证明第一层是否已经交人工，必须退避而不是继续自动裁决。
  if (t_pending.status === "error") {
    logWrite("WARN", "permission", "pending 标记状态不可靠，退避交客户端原生审批");
    return emitPass();
  }

  // force_review：跳过 review_tools 名单强制裁决。凡走到本层的请求都是客户端
  // 真要弹窗的请求（名单外工具如 Write/Edit、子智能体调用、客户端未采信第一层
  // 决策的路径），全部送模型——不能因为"不在名单内"就把人交回弹窗
  const t_decision = await reviewToolUse(t_input, { force_review: true });
  if (t_decision.action === ACTION_ALLOW || t_decision.action === ACTION_DENY) {
    logWrite("INFO", "permission", `${t_decision.action}（${t_decision.source || "pipeline"}）`);
    return emitPermissionDecision(t_decision);
  }
  // ask（审批模型不可用兜底）/ pass（未启用、plan）等：不干预，弹窗照常——
  // 这是全自动语义下唯一的人工路径
  return emitPass();
}

// 最外层兜底：未知异常也只损失自动化（退避到原生弹窗），不阻断也不放行
main().catch((t_error) => {
  logWrite("ERROR", "permission", `未捕获异常: ${redactSecrets(t_error && t_error.message ? t_error.message : String(t_error))}`);
  emitPass();
});
