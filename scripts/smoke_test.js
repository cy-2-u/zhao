/**
 * 模块功能: 端到端冒烟测试——以子进程方式运行 hook_main.js / hook_permission.js 与 ctl.js，模拟真实 hook 输入
 * 作者: hh-zyb
 * 创建日期: 2026年08月29日
 * 描述: 覆盖决策管线分支与 ctl 控制脚本全命令；
 *       不写 review_provider.json（审批渠道未配置），验证 LLM 审查不可用时兜底转人工（ask）；
 *       当前语义覆盖：组合命令快速通道（cd 段 + 2>&1 尾缀）、出厂关机 deny 规则提示送审、
 *       ctl 键 provider_retries / inspect_scripts、hook_permission.js 退避矩阵与双协议输出契约、
 *       PreToolUse ask 后 pending 标记写入 + PermissionRequest 层见标记或读取故障时退避、
 *       第二层不设 matcher 的子智能体创建（Agent/Task）与 MCP 工具弹窗强制送审（0.8.2 起）
 * 依赖: node:child_process node:assert node:crypto node:fs node:os node:path
 * 用法: node scripts/smoke_test.js
 * 更新日期: 2026年09月20日
 */

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const t_root = path.resolve(fileURLToPath(new URL(".", import.meta.url)), "..");
const t_hook = path.join(t_root, "src", "hook_main.js");
const t_permission_hook = path.join(t_root, "src", "hook_permission.js");
const t_ctl = path.join(t_root, "src", "ctl.js");

// 每次冒烟用独立临时数据目录，避免污染真实用户数据
const t_data_dir = fs.mkdtempSync(path.join(os.tmpdir(), "auto-review-smoke-"));

try {
// 通过配置文件把开关打开（enabled 默认 false，冒烟需要显式开启）；
// 刻意不写 review_provider.json：审批渠道未配置 → LLM 审查不可用 → 兜底转人工（ask）
fs.writeFileSync(path.join(t_data_dir, "settings.json"), JSON.stringify({
  enabled: true, review_tools: ["Bash"],
  timeout_ms: 5000, cache_ttl_seconds: 0, max_payload_chars: 8000,
}));

// 数据目录重定向即全部隔离：插件不再有任何审批 UI，无需其他开关
const t_env = { ...process.env, AUTO_REVIEW_DATA_DIR: t_data_dir };

let g_pass_count = 0;

/**
 * 函数功能: 执行一次 hook 冒烟并断言结果
 * @param {string} name - 用例名
 * @param {string} stdin_text - 模拟的 hook stdin
 * @param {object} expect - {stdout_json|null, exit_code, decision, reason_includes}
 * @returns {void}
 */
function runHookCase(name, stdin_text, expect) {
  const t_result = spawnSync("node", [t_hook], { input: stdin_text, env: t_env, encoding: "utf8", timeout: 30000 });
  const t_exit = t_result.status;
  const t_stdout = (t_result.stdout || "").trim();
  if (expect.stdout_json === null) {
    assert.equal(t_stdout, "", `${name}: 期望空输出`);
    assert.equal(t_exit, 0, `${name}: 期望 exit 0`);
  } else {
    assert.equal(t_exit, expect.exit_code ?? 0, `${name}: exit code`);
    const t_payload = JSON.parse(t_stdout);
    if (expect.decision) {
      assert.equal(t_payload.hookSpecificOutput.permissionDecision, expect.decision, `${name}: decision`);
      if (expect.reason_includes) {
        assert.ok(t_payload.hookSpecificOutput.permissionDecisionReason.includes(expect.reason_includes), `${name}: reason 内容`);
      }
    }
  }
  g_pass_count++;
  console.log(`  ok - ${name}`);
}

/**
 * 函数功能: 执行一次 ctl 冒烟并断言退出码与输出片段
 * @param {string[]} args - ctl 参数
 * @param {object} expect - {exit_code, stdout_includes?}
 * @returns {object} spawn 结果
 */
function runCtl(args, expect) {
  const t_result = spawnSync("node", [t_ctl, ...args], { env: t_env, encoding: "utf8", timeout: 30000 });
  assert.equal(t_result.status, expect.exit_code ?? 0, `ctl ${args.join(" ")}: exit code`);
  if (expect.stdout_includes) {
    assert.ok((t_result.stdout || "").includes(expect.stdout_includes), `ctl ${args.join(" ")}: 输出应包含 "${expect.stdout_includes}"`);
  }
  if (expect.stderr_includes) {
    assert.ok((t_result.stderr || "").includes(expect.stderr_includes), `ctl ${args.join(" ")}: 错误应包含 "${expect.stderr_includes}"`);
  }
  return t_result;
}

console.log("hook_main.js 决策管线分支:");

// ① 开关关闭 → 不干预（空输出，内置流程继续）
fs.writeFileSync(path.join(t_data_dir, "settings.json"), JSON.stringify({ enabled: false }));
runHookCase("开关关闭 → 空输出放行", JSON.stringify({
  tool_name: "Bash", tool_input: { command: "ls -la" },
}), { stdout_json: null });

// 重新开启，后续用例生效
fs.writeFileSync(path.join(t_data_dir, "settings.json"), JSON.stringify({
  enabled: true, review_tools: ["Bash"], timeout_ms: 5000, cache_ttl_seconds: 0,
}));

// ② 非审查工具（Read 不在 review_tools）→ 不干预
runHookCase("非审查工具 → 空输出放行", JSON.stringify({
  tool_name: "Read", tool_input: { file_path: "sandbox/a.txt" },
}), { stdout_json: null });

// ③ 危险命令命中出厂 deny 规则 → 提炼送审提示；审批渠道未配置 → 兜底转人工（不再本地拦截）
runHookCase("危险命令 rm -rf / → 送审提示+模型不可用转人工", JSON.stringify({
  tool_name: "Bash", tool_input: { command: "rm -rf /", description: "清理" },
}), { decision: "ask", reason_includes: "审批模型不可用" });

// ③' 电源操作不在出厂规则内（0.8.0）：按普通请求走模型审查；审批渠道未配置 → 兜底转人工。
runHookCase("关机命令走普通模型审查，模型不可用转人工", JSON.stringify({
  tool_name: "Bash", tool_input: { command: "shutdown /s /t 60" },
}), { decision: "ask", reason_includes: "审批模型不可用" });

// ⑥ 工具级安全白名单：搜索/抓取类只读工具 0 审查直通（不送模型、不弹窗）
runHookCase("WebSearch 只读工具 → 直接放行", JSON.stringify({
  tool_name: "WebSearch", tool_input: { query: "zcode hooks" },
}), { decision: "allow", reason_includes: "只读工具" });
runHookCase("WebFetch 只读工具 → 直接放行", JSON.stringify({
  tool_name: "WebFetch", tool_input: { url: "https://example.com" },
}), { decision: "allow", reason_includes: "只读工具" });

// ④ 白名单规则 → allow（跳过 LLM）
fs.writeFileSync(path.join(t_data_dir, "danger_rules.json"), JSON.stringify([
  { pattern: "^git\\s+status", action: "allow", description: "git status 白名单" },
]));
runHookCase("白名单命令 → 规则放行", JSON.stringify({
  tool_name: "Bash", tool_input: { command: "git status" },
}), { decision: "allow", reason_includes: "白名单" });
fs.rmSync(path.join(t_data_dir, "danger_rules.json"));

// ⑤ 普通命令 + 审批渠道未配置 → LLM 审查不可用，兜底转人工审批（不自动许可）
runHookCase("审批渠道未配置 → 兜底转人工审批", JSON.stringify({
  tool_name: "Bash", tool_input: { command: "node smoke-fallback-probe.js", description: "探测" },
}), { decision: "ask", reason_includes: "审批模型不可用" });

// ⑥ stdin 非法 → fail-closed 阻断（无法确认审查对象时不得放行）
runHookCase("stdin 非法 JSON → 阻断", "这不是JSON{{{", { decision: "deny", reason_includes: "不是合法 JSON" });

// ⑥' stdin 为空 → 同样阻断
runHookCase("stdin 为空 → 阻断", "", { decision: "deny", reason_includes: "输入为空" });

// ⑥'' 空命令/空白命令 → 无法解析出审查对象，统一 fail-closed 阻断（不再交回内置流程）
runHookCase("空命令 → 阻断", JSON.stringify({
  tool_name: "Bash", tool_input: { command: "" },
}), { decision: "deny", reason_includes: "无法从工具输入中解析出审查对象" });
runHookCase("空白命令 → 阻断", JSON.stringify({
  tool_name: "Bash", tool_input: { command: "   \t " },
}), { decision: "deny", reason_includes: "无法从工具输入中解析出审查对象" });

// ⑦ 快速通道：出门厂规则白名单（dir 为只读查询）→ 0 LLM 静默放行
runHookCase("快速通道只读命令 dir → 0 LLM 放行", JSON.stringify({
  tool_name: "Bash", tool_input: { command: "dir" },
}), { decision: "allow", reason_includes: "快速通道" });

// ⑦' 组合命令快速通道：cd 段 + 白名单段整条零 LLM 放行；段尾 2>&1 剥离后照常判定
runHookCase("组合命令 cd && dir → 组合快速通道放行", JSON.stringify({
  tool_name: "Bash", tool_input: { command: "cd /d D:\\work\\VPN && dir /b" },
}), { decision: "allow", reason_includes: "组合命令快速通道放行" });
runHookCase("白名单命令 + 2>&1 尾缀 → 快速通道放行", JSON.stringify({
  tool_name: "Bash", tool_input: { command: "git status 2>&1" },
}), { decision: "allow", reason_includes: "快速通道" });
runHookCase("组合命令含非白名单段 → 交模型审查（渠道未配置转人工）", JSON.stringify({
  tool_name: "Bash", tool_input: { command: "cd /d D:\\work && npm install" },
}), { decision: "ask", reason_includes: "审批模型不可用" });

// ⑧ toolName 兼容字段：字段兼容生效后进入审查管线（渠道未配置 → 兜底转人工）
runHookCase("toolName 兼容字段", JSON.stringify({
  toolName: "Bash", tool_input: { command: "del compat-test.tmp" },
}), { decision: "ask", reason_includes: "审批模型不可用" });

console.log("ctl.js 控制脚本命令:");

runCtl(["status"], { stdout_includes: "enabled: true" });
g_pass_count++;
console.log("  ok - status 展示当前状态");

runCtl(["set", "timeout_ms", "15000"], { stdout_includes: "已设置 timeout_ms" });
g_pass_count++;
console.log("  ok - set 修改配置");

runCtl(["set", "bad_key", "x"], { exit_code: 1, stderr_includes: "未知配置键" });
g_pass_count++;
console.log("  ok - set 拒绝未知键");

runCtl(["set", "ask_to_user", "true"], { exit_code: 1, stderr_includes: "未知配置键" });
g_pass_count++;
console.log("  ok - set 拒绝已移除的 ask_to_user 键");

runCtl(["rules", "add", "deny", "python\\s+-m\\s+http\\.server", "起本地HTTP服务"], { stdout_includes: "已追加规则" });
runCtl(["rules", "list"], { stdout_includes: "起本地HTTP服务" });
runCtl(["rules", "test", "python -m http.server 8080"], { stdout_includes: "命中 1 条" });
runCtl(["rules", "test", "echo hi"], { stdout_includes: "未命中" });
runCtl(["rules", "remove", "1"], { stdout_includes: "已删除" });
g_pass_count++;
console.log("  ok - rules add/list/test/remove 全链路");

runCtl(["rules", "add", "deny", "([bad", "x"], { exit_code: 1, stderr_includes: "正则编译失败" });
g_pass_count++;
console.log("  ok - rules add 拒绝非法正则");

const t_prompt_path_result = runCtl(["prompt", "path"], { stdout_includes: t_data_dir });
assert.ok(fs.existsSync(t_prompt_path_result.stdout.trim()), "prompt path 输出的文件应已物化");
g_pass_count++;
console.log("  ok - prompt path 物化并返回路径");

runCtl(["prompt", "reset"], { stdout_includes: "已恢复出厂默认提示词" });
g_pass_count++;
console.log("  ok - prompt reset");

// provider_retries 区间钳制 + 状态展示（含动态预算说明）
// （0.6.2 移除 ask_policy：规则层只有 deny/allow，无枚举键可设置）
runCtl(["set", "provider_retries", "99"], { stdout_includes: "已设置 provider_retries = 3" });
runCtl(["status"], { stdout_includes: "provider_retries: 3" });
runCtl(["set", "provider_retries", "0"], { stdout_includes: "已设置 provider_retries = 0" });
runCtl(["set", "provider_retries", "2"], { stdout_includes: "已设置 provider_retries = 2" });
runCtl(["set", "banana", "x"], { exit_code: 1, stderr_includes: "未知配置键" });
g_pass_count++;
console.log("  ok - set/status 覆盖 provider_retries 且拒绝未知枚举键");

// rules test 的语义说明为固定文案（deny=送审提示，不再随策略变化）
runCtl(["rules", "add", "deny", "^probe-gate", "冒烟门槛"], { stdout_includes: "已追加" });
runCtl(["rules", "test", "probe-gate now"], { stdout_includes: "deny=作为风险提示送审批模型裁决" });
runCtl(["rules", "remove", "1"], { stdout_includes: "已删除" });
g_pass_count++;
console.log("  ok - rules test 语义说明固定展示二动作语义");

console.log("hook_permission.js PermissionRequest 层:");

/**
 * 函数功能: 执行一次 PermissionRequest hook 冒烟并断言结果。
 *           expect.pass=true 断言空输出 + exit 0（不干预，客户端原生弹窗照常）；
 *           否则断言 PermissionRequest 决策 JSON 的完整契约形态
 * @param {string} name - 用例名
 * @param {string} stdin_text - 模拟的 hook stdin
 * @param {object} expect - {pass: true} 或 {decision, reason_includes?}
 * @returns {void}
 */
function runPermissionCase(name, stdin_text, expect) {
  const t_result = spawnSync("node", [t_permission_hook], { input: stdin_text, env: t_env, encoding: "utf8", timeout: 30000 });
  const t_stdout = (t_result.stdout || "").trim();
  if (expect.pass) {
    assert.equal(t_stdout, "", `${name}: 期望空输出（不干预，原生审批照常）`);
    assert.equal(t_result.status, 0, `${name}: 期望 exit 0`);
  } else {
    assert.equal(t_result.status, 0, `${name}: exit code`);
    const t_payload = JSON.parse(t_stdout);
    assert.equal(t_payload.hookSpecificOutput.hookEventName, "PermissionRequest", `${name}: 事件名`);
    assert.equal(t_payload.hookSpecificOutput.decision.behavior, expect.decision, `${name}: decision`);
    if (expect.reason_includes) {
      assert.ok(t_payload.hookSpecificOutput.decision.message.includes(expect.reason_includes), `${name}: reason 内容`);
    }
  }
  g_pass_count++;
  console.log(`  ok - ${name}`);
}

// PermissionRequest 层前置环境：启用审查、无渠道、无规则、无遗留标记
fs.writeFileSync(path.join(t_data_dir, "settings.json"), JSON.stringify({
  enabled: true, review_tools: ["Bash"], timeout_ms: 5000, cache_ttl_seconds: 0, fast_allow_enabled: true,
}));
fs.rmSync(path.join(t_data_dir, "danger_rules.json"), { force: true });
fs.rmSync(path.join(t_data_dir, "pending_asks.json"), { force: true });

// 退避矩阵：本层只剩"看不懂/plan 只读边界/第一层刚裁定人工"三种退避形态；
// 其余请求一律送审——全自动语义下人工弹窗只允许在模型不可用时出现
runPermissionCase("空 stdin → 退避", "", { pass: true });
runPermissionCase("非法 JSON → 退避", "这不是JSON{{{", { pass: true });
runPermissionCase("JSON 非对象（数组）→ 退避", "[1,2]", { pass: true });
runPermissionCase("plan 只读规划模式 → 退避", JSON.stringify({
  tool_name: "Bash", tool_input: { command: "dir /b" }, permission_mode: "plan",
}), { pass: true });
runPermissionCase("完全访问（yolo）模式 → 退避（客户端原生全放行，无需自动审批）", JSON.stringify({
  tool_name: "Bash", tool_input: { command: "dir /b" }, permission_mode: "yolo",
}), { pass: true });
runPermissionCase("无法识别审查对象（Read 无路径）→ 退避", JSON.stringify({
  tool_name: "Read", tool_input: {},
}), { pass: true });
// 模式字段不再是退避条件：default/其他模式一律接管（旧版仅 edit 接管，是
// "开了还要人审批"与子智能体弹窗泄漏的根因）
runPermissionCase("default 模式 → 照常接管（快速通道 allow）", JSON.stringify({
  tool_name: "Bash", tool_input: { command: "dir /b" }, permission_mode: "default",
}), { decision: "allow", reason_includes: "快速通道" });

// force_review：名单外工具（Write）走到第二层即强制送审——不再因"不在名单"退避。
// 无渠道 → 兜底 ask → 不干预；用日志证据区分"名单跳过"与"送审后兜底"
fs.rmSync(path.join(t_data_dir, "review.log"), { force: true });
runPermissionCase("名单外工具 Write → 强制送审（无渠道兜底 ask，不干预）", JSON.stringify({
  tool_name: "Write", tool_input: { file_path: "probe-force-review.txt", content: "x" },
}), { pass: true });
assert.ok(fs.readFileSync(path.join(t_data_dir, "review.log"), "utf8").includes("审查不可用"), "Write 请求应实际进入送审管线（fallback 日志），而非名单跳过");
g_pass_count++;
console.log("  ok - Write 请求确实进入送审管线（日志含 fallback 记录）");

// 0.8.2：第二层不设 matcher 全量接管——子智能体（Agent/Task）与 MCP/扩展工具的
// 弹窗请求同样强制送审；渠道未配置 → 兜底 ask 不干预，日志 fallback 记录证明进管线
fs.rmSync(path.join(t_data_dir, "review.log"), { force: true });
runPermissionCase("子智能体 Agent 创建请求 → 强制送审（无渠道兜底 ask，不干预）", JSON.stringify({
  tool_name: "Agent", tool_input: { subagent_type: "general-purpose", description: "搜索", prompt: "搜索项目 TODO 并汇总" },
}), { pass: true });
assert.ok(fs.readFileSync(path.join(t_data_dir, "review.log"), "utf8").includes("审查不可用"), "Agent 请求应实际进入送审管线（fallback 日志）");
g_pass_count++;
console.log("  ok - Agent 请求确实进入送审管线（日志含 fallback 记录）");
runPermissionCase("Task 别名创建请求 → 同样强制送审（不干预）", JSON.stringify({
  tool_name: "Task", tool_input: { description: "调研", prompt: "调研依赖升级影响" },
}), { pass: true });
runPermissionCase("MCP 工具入参 → 强制送审（不干预）", JSON.stringify({
  tool_name: "mcp__node_repl__js", tool_input: { code: "console.log(1)" },
}), { pass: true });
runPermissionCase("无任务内容的 Agent 请求 → 无法识别退避（原生弹窗照常）", JSON.stringify({
  tool_name: "Agent", tool_input: {},
}), { pass: true });

// 决策输出：快速通道命令在第二层 allow（子智能体路径的弹窗被模型侧决策替代）
runPermissionCase("白名单命令 dir /b → 第二层 allow 决策", JSON.stringify({
  tool_name: "Bash", tool_input: { command: "dir /b" },
}), { decision: "allow", reason_includes: "快速通道" });

// ask 结论（模型不可用兜底）不输出决策：照常原生弹窗
runPermissionCase("普通命令无渠道 → 兜底 ask 不干预，弹窗照常", JSON.stringify({
  tool_name: "Bash", tool_input: { command: "del probe-file.tmp" },
}), { pass: true });

// 防回环：PreToolUse 刚转人工的命令必须写 pending 标记，第二层见标记退避不自动放行
runHookCase("PreToolUse ask 后写入 pending 标记（hook_main）", JSON.stringify({
  tool_name: "Bash", tool_input: { command: "del marker-probe.tmp" },
}), { decision: "ask", reason_includes: "审批模型不可用" });
const t_marker_file = path.join(t_data_dir, "pending_asks.json");
const t_marker_key = createHash("sha256").update("Bash\ndel marker-probe.tmp").digest("hex");
const t_marker_map = JSON.parse(fs.readFileSync(t_marker_file, "utf8"));
assert.ok(typeof t_marker_map[t_marker_key] === "number", "hook_main ask 决策应写入对应命令的 pending 标记");
g_pass_count++;
console.log("  ok - PreToolUse ask 写入 pending 标记");

// 第二层见新鲜标记 → 即使命中快速通道也退避（"模型不可用→人工"不被第二层翻转为自动放行）
const t_fast_key = createHash("sha256").update("Bash\ndir /b").digest("hex");
fs.writeFileSync(t_marker_file, JSON.stringify({ [t_fast_key]: Date.now() }));
runPermissionCase("新鲜 pending 标记命中 → 第二层退避不自动放行", JSON.stringify({
  tool_name: "Bash", tool_input: { command: "dir /b" },
}), { pass: true });
fs.rmSync(t_marker_file, { force: true });
runPermissionCase("标记清除后同命令恢复第二层 allow", JSON.stringify({
  tool_name: "Bash", tool_input: { command: "dir /b" },
}), { decision: "allow", reason_includes: "快速通道" });

// 陈旧标记不退避：回写过期时间戳后第二层照常审查（标记窗口只有 15s）
fs.writeFileSync(t_marker_file, JSON.stringify({ [t_fast_key]: Date.now() - 60 * 1000 }));
runPermissionCase("陈旧标记不退避 → 第二层照常 allow", JSON.stringify({
  tool_name: "Bash", tool_input: { command: "dir /b" },
}), { decision: "allow", reason_includes: "快速通道" });
fs.rmSync(t_marker_file, { force: true });

// 旧 ask 条目命中第二层同样不干预：结论是兜底 ask（无渠道），原生弹窗照常。
// （0.6.2 移除 ask_policy：规则 ask 归一为 deny 送审，人工只与模型可用性挂钩）
fs.writeFileSync(path.join(t_data_dir, "danger_rules.json"), JSON.stringify([
  { pattern: "^dir /b$", action: "ask", description: "冒烟门槛（旧条目）" },
]));
runPermissionCase("旧 ask 条目命中 → 第二层兜底 ask 不干预，弹窗照常", JSON.stringify({
  tool_name: "Bash", tool_input: { command: "dir /b" },
}), { pass: true });

// 总开关关闭 → 第二层同样不干预
fs.writeFileSync(path.join(t_data_dir, "danger_rules.json"), JSON.stringify([]));
fs.writeFileSync(path.join(t_data_dir, "settings.json"), JSON.stringify({
  enabled: false, review_tools: ["Bash"],
}));
runPermissionCase("总开关关闭 → 第二层不干预", JSON.stringify({
  tool_name: "Bash", tool_input: { command: "dir /b" },
}), { pass: true });

// 还原环境，避免影响后续审计回归块
fs.writeFileSync(path.join(t_data_dir, "settings.json"), JSON.stringify({
  enabled: true, review_tools: ["Bash"], timeout_ms: 5000, cache_ttl_seconds: 0,
}));
fs.rmSync(path.join(t_data_dir, "danger_rules.json"), { force: true });
fs.rmSync(t_marker_file, { force: true });

// 审计回归：全部使用隔离文件，绝不调用真实 API。
function writeConfig(name, value) {
  fs.writeFileSync(path.join(t_data_dir, name), JSON.stringify(value));
}
for (const root of [null, [], "bad", 42, true]) {
  writeConfig("settings.json", root);
  runCtl(["status"], { stdout_includes: "review_tools:" });
  runCtl(["set", "enabled", "true"], { stdout_includes: "已设置" });
  g_pass_count++;
}
for (const tools of [[null], [1], [{}], [" "], ["Bash", false]]) {
  writeConfig("settings.json", { review_tools: tools });
  runCtl(["status"], { stdout_includes: "review_tools: Bash" });
  g_pass_count++;
}
for (const key of ["x", "tinykey", "eightkey", "long-secret-key-value", "", null, 123]) {
  writeConfig("review_provider.json", { api_key: key });
  const result = runCtl(["provider", "show"], { stdout_includes: "api_key: ***" });
  if (key) assert.ok(!result.stdout.includes(`api_key: ${key}`));
  g_pass_count++;
}
for (const root of [null, [], "bad", 42]) {
  writeConfig("review_provider.json", root);
  runCtl(["provider", "show"], { exit_code: 1, stderr_includes: "JSON 对象" });
  g_pass_count++;
}
writeConfig("danger_rules.json", [null, 42, {}, "bad"]);
runCtl(["rules", "list"], { stdout_includes: "无效" });
for (let i = 0; i < 4; i++) runCtl(["rules", "remove", "1"], { stdout_includes: "已删除" });
g_pass_count++;
for (const [pattern, description] of [["a".repeat(501), "x"], ["x", "d".repeat(201)]]) {
  const before = fs.readFileSync(path.join(t_data_dir, "danger_rules.json"), "utf8");
  runCtl(["rules", "add", "deny", pattern, description], { exit_code: 1, stderr_includes: "超长" });
  assert.equal(fs.readFileSync(path.join(t_data_dir, "danger_rules.json"), "utf8"), before);
  g_pass_count++;
}
runCtl(["rules", "add", "deny", "a".repeat(500), "d".repeat(200)], { stdout_includes: "已追加" });
g_pass_count++;
const validRule = { pattern: "^dir$", action: "allow", description: "test" };
writeConfig("danger_rules.json", Array.from({ length: 199 }, () => validRule));
runCtl(["rules", "add", "deny", "shutdown", "gate"], { stdout_includes: "已追加" });
runCtl(["rules", "add", "deny", "more", "gate"], { exit_code: 1, stderr_includes: "上限 200" });
g_pass_count++;
writeConfig("danger_rules.json", [...Array.from({ length: 200 }, () => validRule), { ...validRule, action: "deny" }]);
writeConfig("settings.json", { enabled: true, review_tools: ["Bash"] });
runHookCase("超限整表保守送审提示，前 allow 不得绕过（模型不可用兜底转人工）", JSON.stringify({ tool_name: "Bash", tool_input: { command: "dir" } }), { decision: "ask", reason_includes: "审批模型不可用" });
for (const oversized of [
  { pattern: "a".repeat(501), action: "deny", description: "gate" },
  { pattern: "^dir$", action: "deny", description: "d".repeat(201) },
]) {
  writeConfig("danger_rules.json", [validRule, oversized]);
  runHookCase("超长后置 deny 提示不得被前 allow 绕过（模型不可用兜底转人工）", JSON.stringify({ tool_name: "Bash", tool_input: { command: "dir" } }), { decision: "ask", reason_includes: "审批模型不可用" });
}
// CLI 同时遵守原始条目预算：无效条目不能让追加制造运行时整表 ask。
for (const rules of [
  [null, ...Array.from({ length: 199 }, () => validRule)],
  Array(200).fill(null),
  Array.from({ length: 201 }, (_, i) => [null, {}, { pattern: "[", description: "bad" }][i % 3]),
  Array(1000).fill(null),
]) {
  writeConfig("danger_rules.json", rules);
  const before = fs.readFileSync(path.join(t_data_dir, "danger_rules.json"), "utf8");
  const result = runCtl(["rules", "add", "deny", "more", "gate"], {
    exit_code: 1, stderr_includes: "请先清理无效或多余条目",
  });
  assert.ok(!result.stdout.includes("已追加"));
  assert.equal(fs.readFileSync(path.join(t_data_dir, "danger_rules.json"), "utf8"), before);
  g_pass_count++;
}
// 原始 199 条（全部无效）仍可追加至 200，之后必须拒绝且保留文件。
writeConfig("danger_rules.json", Array(199).fill(null));
runCtl(["rules", "add", "allow", "^dir$", "boundary"], { stdout_includes: "已追加规则 #200" });
const boundary = fs.readFileSync(path.join(t_data_dir, "danger_rules.json"), "utf8");
assert.equal(JSON.parse(boundary).length, 200);
runCtl(["rules", "add", "deny", "more", "gate"], { exit_code: 1, stderr_includes: "上限 200" });
assert.equal(fs.readFileSync(path.join(t_data_dir, "danger_rules.json"), "utf8"), boundary);
g_pass_count++;
runHookCase("199 无效条目追加至 200 不触发整表 ask", JSON.stringify({ tool_name: "Bash", tool_input: { command: "dir" } }), { decision: "allow", reason_includes: "白名单" });
for (const [name, args] of [
  ["settings.json", ["init"]],
  ["review_provider.json", ["provider", "path"]],
  ["security_prompt.md", ["prompt", "path"]],
  ["security_prompt.md", ["prompt", "reset"]],
]) {
  const target = path.join(t_data_dir, name);
  fs.rmSync(target, { recursive: true, force: true });
  fs.mkdirSync(target);
  try {
    const result = runCtl(args, { exit_code: 1 });
    assert.ok(!/已创建模板|已恢复出厂|已初始化/.test(result.stdout));
  } finally { fs.rmSync(target, { recursive: true, force: true }); }
  g_pass_count++;
}
// 数据目录本身是文件，覆盖实际 writeFileAtomic 返回 false 的路径。
const blocked = path.join(t_data_dir, "blocked");
fs.writeFileSync(blocked, "not a directory");
for (const args of [["init"], ["provider", "path"], ["prompt", "path"], ["prompt", "reset"]]) {
  const result = spawnSync(process.execPath, [t_ctl, ...args], {
    env: { ...t_env, AUTO_REVIEW_DATA_DIR: blocked }, encoding: "utf8", timeout: 30000,
  });
  assert.equal(result.status, 1);
  assert.ok(!/已创建模板|已恢复出厂|已初始化/.test(result.stdout));
  g_pass_count++;
}
console.log(`\n冒烟测试全部通过: ${g_pass_count} 项断言组`);
} finally {
  fs.rmSync(t_data_dir, { recursive: true, force: true });
}
