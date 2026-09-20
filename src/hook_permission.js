/**
 * 模块功能: PermissionRequest hook 入口——客户端即将弹原生权限框时介入审查。
 *           全自动审批语义：hooks.json 对本层不设 matcher（省略即匹配所有工具）——
 *           客户端实际触发 PermissionRequest 的请求，含子智能体创建（Agent/Task）、
 *           review_tools 名单外工具（如默认配置下的 Write/Edit）与 MCP/扩展工具，
 *           一律经 force_review 强制送安全子 agent 裁决：模型 allow 即自动放行
 *           （弹窗消失），deny 拦截并回传分析；只有模型不可用（兜底 ask）才退避
 *           交回原生弹窗。plan 与 yolo/完全访问是例外——前者是客户端只读规划的硬
 *           边界，后者客户端本来就全放行，插件在这两种模式下隐身。
 *           客户端若不触发此 hook，则插件无法从本层接管该路径；退避方向始终是
 *           "交人工"而不是"放行"——本层故障只损失自动化，不损失安全性
 * 作者: hh-zyb
 * 创建日期: 2026年09月18日
 * 描述: hooks.json 以 process 方式在 PermissionRequest 事件上启动本文件；
 *       输出契约使用客户端实际解析的 hookSpecificOutput.decision.behavior/message，
 *       与 PreToolUse 的 permissionDecision/permissionDecisionReason 结构不同；
 *       AUTO_REVIEW_DEBUG=1 时记录输入顶层字段名与标量值（不含载荷内容），用于适配客户端字段
 * 依赖: ./reviewer.js ./decision.js ./common.js
 * 更新日期: 2026年09月20日
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
 * 函数功能: 主流程：stdin → JSON → 退避判定 → 审查管线 → 决策输出。
 *           退避只剩三种形态：输入读不懂、plan 只读边界、第一层刚裁定的人工兜底
 * @returns {Promise<void>}
 */
async function main() {
  const t_raw = await readStdinAll();

  // 输入读不懂就不干预：本层的失败形态是"保持原生弹窗"，不是阻断（阻断会
  // 让所有权限弹窗都被一个 schema 适配问题卡死）也不是放行
  if (!t_raw.trim()) {
    logWrite("WARN", "permission", "stdin 为空，退避交客户端原生审批");
    return emitPass();
  }
  let t_input;
  try {
    t_input = JSON.parse(t_raw);
  } catch {
    logWrite("WARN", "permission", `stdin 非合法 JSON（前 80 字符: ${t_raw.slice(0, 80).replace(/\s+/g, " ")}），退避`);
    return emitPass();
  }
  if (!t_input || typeof t_input !== "object" || Array.isArray(t_input)) {
    logWrite("WARN", "permission", "stdin JSON 不是对象，退避");
    return emitPass();
  }

  // 调试开关：记录 hook 输入的顶层字段名与非敏感值形态，用于适配客户端实际字段
  if (process.env.AUTO_REVIEW_DEBUG) {
    const t_fields = {};
    for (const [t_key, t_value] of Object.entries(t_input)) {
      t_fields[t_key] = t_key === "tool_input" ? `<${typeof t_value}>` : String(t_value).slice(0, 120);
    }
    logWrite("INFO", "debug-permission-input", JSON.stringify(t_fields));
  }

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
  // miss（含子智能体等未过第一层的路径）与 error（标记读取不可靠）都照常裁决：
  // 模型在场即自动决策（error 只是少了"省一次重试"的捷径），模型不在场时管线
  // 自然兜底 ask 退回原生弹窗——人工仍只与模型可用性挂钩
  if (t_pending.status === "error") {
    logWrite("WARN", "permission", "pending 标记状态不可靠，照常送审（模型不可用时自然兜底转人工）");
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
  logWrite("ERROR", "permission", `未捕获异常: ${t_error && t_error.message ? t_error.message : String(t_error)}`);
  emitPass();
});
