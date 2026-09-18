/**
 * 模块功能: hook 输出协议封装——把内部决策映射为 PreToolUse 的 stdout JSON / exit code
 * 作者: hh-zyb
 * 创建日期: 2026年08月29日
 * 描述: 输出 schema 是唯一与客户端耦合的点，字段名如与严格校验不符只需改本文件；
 *       stdout 必须只有协议 JSON 或完全为空，任何杂散输出都会破坏协议；
 *       退出必须等管道写回调确认（Windows 下紧跟 process.exit 会截断输出，
 *       且非零退出码会被客户端当 hook 故障丢弃协议 JSON）
 * 功能:
 *   - 内部动作 pass/allow/ask/deny 到协议的映射
 * 依赖: 无
 * 更新日期: 2026年09月17日
 */

// 内部决策动作：pass 表示不干预（交回内置权限流程），其余三个为显式权限决策
const ACTION_PASS = "pass";
const ACTION_ALLOW = "allow";
const ACTION_ASK = "ask";
const ACTION_DENY = "deny";

// exit code 2 在 PreToolUse 语义下是阻断，作为内部崩溃时的最终防线
const EXIT_PASS = 0;
const EXIT_BLOCK = 2;

/**
 * 函数功能: 输出决策并结束进程
 * @param {{action: string, reason: string}} decision - 内部决策对象
 * @returns {void} 进程直接退出
 */
function emitDecision(decision) {
  // pass = 不干预：空输出 + exit 0，客户端按内置权限流程继续
  if (decision.action === ACTION_PASS) {
    process.exit(EXIT_PASS);
  }

  // 正式输出只有一种协议形态（hookSpecificOutput 包装）——曾有的 simple 旁路
  // 只在集成期排查用过，留着反而可能被误设导致客户端解析失败
  const t_payload = {
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: decision.action,
      permissionDecisionReason: decision.reason,
      // 客户端在"模式已 ask + hook ask"时不渲染 reason（fTr 合并丢弃），
      // additionalContext 是把审查分析送进主 agent 上下文的通道（事后转述用）
      ...(decision.additionalContext ? { additionalContext: decision.additionalContext } : {}),
    },
  };
  // Windows 管道写是异步的：紧跟 process.exit 可能截断输出，等写回调确认后再退出；
  // 回调极端情况不触发时由 unref 计时器兜底，不悬挂也不丢决策
  process.stdout.write(JSON.stringify(t_payload), () => process.exit(EXIT_PASS));
  setTimeout(() => process.exit(EXIT_PASS), 1000).unref();
}

/**
 * 函数功能: 空输出放行（exit 0）——PermissionRequest 层的退避形态：
 *           不输出决策即"不干预"，客户端照常弹原生审批框交用户
 * @returns {void} 进程直接退出
 */
function emitPass() {
  process.exit(EXIT_PASS);
}

/**
 * 函数功能: 输出 PermissionRequest 决策并结束进程。客户端对该事件使用 decision.behavior/message
 *           契约，而不是 PreToolUse 的 permissionDecision 字段；只接受 allow/deny，其他动作由调用方退避。
 * @param {{action: string, reason: string}} decision - 内部决策对象（只接受 allow/deny）
 * @returns {void} 进程直接退出
 */
function emitPermissionDecision(decision) {
  const t_payload = {
    hookSpecificOutput: {
      hookEventName: "PermissionRequest",
      decision: {
        behavior: decision.action,
        ...(decision.reason ? { message: decision.reason } : {}),
      },
    },
  };
  process.stdout.write(JSON.stringify(t_payload), () => process.exit(EXIT_PASS));
  setTimeout(() => process.exit(EXIT_PASS), 1000).unref();
}

/**
 * 函数功能: 内部崩溃时的最终防线——阻断而非放行
 * @param {string} message - 崩溃原因（写入 stderr 供诊断，不污染 stdout 协议）
 * @returns {void} 进程以 exit 2 退出
 */
function emitCrash(message) {
  process.stderr.write(`[auto-review] 内部错误: ${message}\n`, () => process.exit(EXIT_BLOCK));
  setTimeout(() => process.exit(EXIT_BLOCK), 1000).unref();
}

export {
  ACTION_PASS,
  ACTION_ALLOW,
  ACTION_ASK,
  ACTION_DENY,
  emitDecision,
  emitPass,
  emitPermissionDecision,
  emitCrash,
};
