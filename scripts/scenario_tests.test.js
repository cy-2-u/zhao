/**
 * 模块功能: 场景固定测试——手工验收场景的自动化回归（放行/转审核/脚本/规则三态/复合命令/脚本送审）
 * 作者: hh-zyb
 * 创建日期: 2026年08月29日
 * 描述: 复现手工验收路径并固化为可重复执行的断言：
 *       场景1-3 走 LLM 审查层，由本地假审批渠道（review_provider.json 指向假服务，
 *       openai 协议）按命令关键字返回预置结论，离线固化"安全放行 / 危险转审核 /
 *       脚本转审核"的管线行为；
 *       场景4-8 走危险规则层：deny 提炼送审提示（不再本地拦截）、allow 快速放行，
 *       复合命令逐段拆分匹配（0.6.2：规则层无 ask 确认门槛——仅模型不可用/输入
 *       无法可靠判定时才转用户，规则不再直接弹给用户）；
 *       场景9 上下文字段不路由（source/querySource/session_id 不绕过规则与快速通道），
 *       10-11 专用审批渠道未配置/不可用的兜底转人工（ask）、
 *       12-15 脚本内容随命令送审（inspect_scripts 开关、附件块入载荷、脚本内容变化缓存失效）、
 *       16 渠道瞬时故障自动重试、17 出厂关机规则各包装形态命中后提炼提示送模型裁决
 *       （真实关机/重启由模型结合完整命令裁决）；
 *       18 旧 ask 规则/ask_policy 键兼容——归一为 deny 送审（ask_policy 仅被容忍不再改变行为）、
 *       19 规则命中但渠道不可用——兜底转人工与规则命中无关（人工是唯一的模型不在场路径）、
 *       20 provider_retries 次数精确生效（0 次不补发、N 次内恢复、4xx 不重试）、
 *       21 组合命令快速通道零 LLM 放行（cd 段 + 白名单段 + stderr 尾缀）、
 *       22 PermissionRequest 真实子进程协议输出（allow/deny）、
 *       23 预算收紧后的重试次数上限、24 force_review 强制裁决——名单外工具
 *       （Write，模拟子智能体/默认模式弹窗路径）经模型自动放行，plan 模式退避；
 *       另附两条防回归锚定：白名单开头的复合命令藏危险段必须降级 LLM、
 *       LLM 输出 deny 在自动二值语义下保留并回传分析。
 *       环境变量必须在 import 业务模块之前设置（common.js 在加载期固化路径）
 * 依赖: node:test node:assert node:fs node:http node:os node:path ../src/*
 * 更新日期: 2026年09月18日
 */

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

// 隔离环境：临时数据目录（审批渠道走 review_provider.json，指向本地假 LLM 服务）
const t_tmp_dir = fs.mkdtempSync(path.join(os.tmpdir(), "auto-review-scenario-"));
const t_old_data_dir = process.env.AUTO_REVIEW_DATA_DIR;
process.env.AUTO_REVIEW_DATA_DIR = t_tmp_dir;
test.after(() => {
  fs.rmSync(t_tmp_dir, { recursive: true, force: true });
  if (t_old_data_dir === undefined) delete process.env.AUTO_REVIEW_DATA_DIR;
  else process.env.AUTO_REVIEW_DATA_DIR = t_old_data_dir;
});

// LLM 幻觉 deny 专用结论：验证自动二值语义下 deny 被保留并回传分析（deny 是合法结论）
const LLM_HALLUCINATED_DENY = { decision: "deny", risk_level: "high", analysis: "（幻觉拦截）", risks: [], scope: "无" };

// 按审查载荷中的命令关键字分发预置结论：场景1 走默认 allow，场景2/3/锚定 各命中专属关键字
const LLM_VERDICT_BY_KEYWORD = [
  {
    keyword: "rm -rf",
    verdict: { decision: "ask", risk_level: "high", analysis: "递归强制删除整个目录，不可逆删除且目标为绝对路径", risks: ["rm -rf 无回收站可恢复", "绝对路径存在范围逃逸"], scope: "目标目录下全部文件与子目录" },
  },
  {
    keyword: ".sh",
    verdict: { decision: "ask", risk_level: "medium", analysis: "执行外部脚本，脚本内容未随调用提供无法确认行为", risks: ["脚本内容不可见", "文件名暗示删除操作"], scope: "脚本内部引用的文件与目录" },
  },
  {
    keyword: "format",
    verdict: LLM_HALLUCINATED_DENY,
  },
];
// 未命中任何关键字的命令（场景1 的安全指令）按安全放行处理
const DEFAULT_VERDICT = { decision: "allow", risk_level: "low", analysis: "命令为只读查询，无破坏性", risks: [], scope: "无" };

// 假 LLM 服务收到的请求计数：规则层场景必须为 0，锚定"规则层不经过 LLM"
let g_llm_request_count = 0;

// 最近一次收到的送审载荷全文：脚本送审用例据此断言附件块确实进入载荷
let g_last_payload = "";

// 可注入的连续故障：接下来 N 个请求返回该状态码（重试路径测试），N 耗尽或手动清零即恢复
let g_fail_next_status = 0;
let g_fail_next_count = 1;

// 假 LLM 服务（openai chat/completions 协议）：解析载荷中的命令，按关键字回预置结论
const t_fake_llm = http.createServer((t_req, t_res) => {
  const t_chunks = [];
  t_req.on("data", (t_chunk) => t_chunks.push(t_chunk));
  t_req.on("end", () => {
    g_llm_request_count++;
    if (g_fail_next_status && g_fail_next_count > 0) {
      const t_status = g_fail_next_status;
      if (--g_fail_next_count <= 0) {
        g_fail_next_status = 0;
        g_fail_next_count = 1;
      }
      t_res.writeHead(t_status, { "content-type": "application/json" });
      t_res.end(JSON.stringify({ error: { message: "fake transient failure" } }));
      return;
    }
    const t_body = JSON.parse(Buffer.concat(t_chunks).toString("utf8"));
    const t_user_msg = (t_body.messages || []).find((t_m) => t_m.role === "user");
    const t_payload = String((t_user_msg && t_user_msg.content) || "");
    g_last_payload = t_payload;
    const t_hit = LLM_VERDICT_BY_KEYWORD.find((t_item) => t_payload.includes(t_item.keyword));
    const t_verdict = t_hit ? t_hit.verdict : DEFAULT_VERDICT;
    t_res.writeHead(200, { "content-type": "application/json" });
    t_res.end(JSON.stringify({ choices: [{ message: { content: JSON.stringify(t_verdict) } }] }));
  });
});
test.after(async () => {
  t_fake_llm.closeAllConnections();
  await new Promise((resolve) => t_fake_llm.close(resolve));
});
await new Promise((t_resolve) => t_fake_llm.listen(0, "127.0.0.1", t_resolve));
const t_port = t_fake_llm.address().port;

/**
 * 函数功能: 写入专用审批渠道配置（review_provider.json 是审批的唯一 LLM 来源）
 * @param {string} base_url - 端点地址（默认指向本地假 LLM 服务）
 * @returns {void}
 */
function writeReviewProvider(base_url) {
  fs.writeFileSync(path.join(t_tmp_dir, "review_provider.json"), JSON.stringify({
    _说明: "测试专用审批渠道",
    base_url: base_url || `http://127.0.0.1:${t_port}/v1`,
    api_key: "test-key",
    api_kind: "",
    model: "fake-model",
  }));
}
writeReviewProvider();

// 环境就绪后再加载业务模块
const { loadSettings, saveSettings, saveDangerRules } = await import("../src/settings.js");
const { reviewToolUse } = await import("../src/reviewer.js");

const t_permission_hook = path.resolve(fileURLToPath(new URL("../src/hook_permission.js", import.meta.url)));
const t_hook_env = { ...process.env, AUTO_REVIEW_DATA_DIR: t_tmp_dir };

// 场景用例共享隔离数据目录、假服务计数器和 provider 配置，必须串行执行；
// 测试运行器可能并发调度 top-level 用例，显式队列化整个回调而不是只设置子测试选项。
let g_serial_tail = Promise.resolve();
const serialTest = (name, fn) => test(name, async (t_context) => {
  const t_previous = g_serial_tail;
  let t_release;
  g_serial_tail = new Promise((t_resolve) => { t_release = t_resolve; });
  await t_previous;
  try {
    return await fn(t_context);
  } finally {
    t_release();
  }
});

/**
 * 函数功能: 以真实 PermissionRequest 子进程运行 hook，验证客户端协议层输出。
 * @param {string} command - 测试命令文本（只作为字符串审查，不执行）
 * @param {object} [input_override] - 完整 hook 输入覆盖（force_review 名单外工具用例）；
 *        缺省按 Bash 命令构造
 * @returns {Promise<{status: number, stdout: string, stderr: string}>}
 */
function runPermissionHook(command, input_override) {
  return new Promise((resolve, reject) => {
    const t_child = spawn(process.execPath, [t_permission_hook], { env: t_hook_env });
    const t_stdout = [];
    const t_stderr = [];
    const t_timer = setTimeout(() => {
      t_child.kill();
      reject(new Error("PermissionRequest 测试子进程超时"));
    }, 30000);
    t_child.stdout.setEncoding("utf8");
    t_child.stderr.setEncoding("utf8");
    t_child.stdout.on("data", (t_chunk) => t_stdout.push(t_chunk));
    t_child.stderr.on("data", (t_chunk) => t_stderr.push(t_chunk));
    t_child.on("error", (t_error) => {
      clearTimeout(t_timer);
      reject(t_error);
    });
    t_child.on("close", (t_status) => {
      clearTimeout(t_timer);
      resolve({ status: t_status, stdout: t_stdout.join("").trim(), stderr: t_stderr.join("") });
    });
    t_child.stdin.end(JSON.stringify(input_override || { tool_name: "Bash", tool_input: { command } }));
  });
}

// 运行时配置：开启审查、只审 Bash、禁用缓存保证用例无状态串扰
// （0.6.2 移除 ask_policy：规则层只有 deny/allow，无策略可切换）
const t_settings = loadSettings();
t_settings.enabled = true;
t_settings.review_tools = ["Bash"];
t_settings.cache_ttl_seconds = 0;
saveSettings(t_settings);

/**
 * 函数功能: 写入本用例的危险规则表（数据目录规则优先生效，空数组即屏蔽出厂规则）
 * @param {Array<{pattern: string, action: string, description: string}>} rules - 原始规则数组
 * @returns {void}
 */
function writeRules(rules) {
  saveDangerRules(rules);
}

/**
 * 函数功能: 以 hook 输入形态执行一次审查，并重置 LLM 请求计数与载荷捕获便于逐用例断言
 * @param {string} command - 被审查的 Bash 命令
 * @param {string} [cwd] - hook 输入的工作目录（脚本送审用例必传，附件按它界定边界）
 * @returns {Promise<{action: string, reason: string, source: string}>} 决策对象
 */
async function reviewCommand(command, cwd) {
  g_llm_request_count = 0;
  g_last_payload = "";
  return reviewToolUse({ tool_name: "Bash", tool_input: { command }, ...(cwd ? { cwd } : {}) });
}

// 单条测试规则（场景4-6 换 action 复用同一正则，与手工验收一致）
const LS_RULE = (t_action) => ({ pattern: "^\\s*ls\\b", action: t_action, description: "测试规则-ls命令" });
const NODE_VERSION_RULE = (t_action) => ({ pattern: "^\\s*node\\s+--version\\b", action: t_action, description: "测试规则-node版本查询" });

serialTest("场景1: 安全普通指令——LLM 审查后放行", async () => {
  writeRules([]);
  const t_decision = await reviewCommand("npm run build");
  assert.equal(t_decision.action, "allow");
  assert.equal(t_decision.source, "llm");
  assert.match(t_decision.reason, /安全审查通过/);
  assert.equal(g_llm_request_count, 1);
});

serialTest("场景2: 危险删除指令——LLM 判高风险，自动模式收敛为 deny 并回传分析", async () => {
  writeRules([]);
  const t_decision = await reviewCommand("rm -rf D:/app/demo_dir");
  assert.equal(t_decision.action, "deny");
  assert.equal(t_decision.source, "llm");
  assert.match(t_decision.reason, /风险级别 high/);
  // deny 回传通道：风险分析与替代方案随 additionalContext 进入主 agent 上下文
  assert.match(t_decision.additionalContext, /风险级别 high/);
  assert.equal(g_llm_request_count, 1);
});

serialTest("场景3: 执行删除脚本——LLM 判中风险，自动模式收敛为 deny", async () => {
  writeRules([]);
  const t_decision = await reviewCommand("bash D:/app/delete_demo.sh");
  assert.equal(t_decision.action, "deny");
  assert.equal(t_decision.source, "llm");
  assert.match(t_decision.reason, /风险级别 medium/);
  assert.equal(g_llm_request_count, 1);
});

serialTest("场景4: deny 规则命中 ls——提炼风险提示送审，不再本地直接拦", async () => {
  writeRules([LS_RULE("deny")]);
  const t_decision = await reviewCommand("ls D:/app/demo_dir");
  assert.equal(t_decision.action, "allow");
  assert.equal(t_decision.source, "llm");
  assert.match(t_decision.reason, /安全审查通过/);
  assert.ok(g_last_payload.includes("危险规则 #1"), "规则提示应随载荷送审");
  assert.ok(g_last_payload.includes("本地规则仅作为风险提示"), "提示需注明只是线索非结论");
  assert.equal(g_llm_request_count, 1);
});

serialTest("场景5: 复合命令 deny 段——全文命中提炼出提示送审，模型裁决不直问用户", async () => {
  writeRules([LS_RULE("deny")]);
  const t_decision = await reviewCommand("ls D:/app/demo_dir && echo after");
  assert.equal(t_decision.action, "allow", "风险提示送模型终审（假模型默认放行），不再本地拦截也不直接弹用户");
  assert.equal(t_decision.source, "llm");
  assert.ok(g_last_payload.includes("危险规则 #1"), "复合命令的风险提示同样随载荷送审");
  assert.equal(g_llm_request_count, 1);
});

serialTest("场景6: allow 规则命中 ls——白名单直接放行，跳过 LLM", async () => {
  writeRules([LS_RULE("allow")]);
  const t_decision = await reviewCommand("ls D:/app/demo_dir");
  assert.equal(t_decision.action, "allow");
  assert.equal(t_decision.source, "rule");
  assert.match(t_decision.reason, /白名单放行/);
  assert.equal(g_llm_request_count, 0);
});

serialTest("场景7: 复合命令 ls(allow)+node --version(旧 ask 条目)拆段——归一 deny 提示压过 allow 段，径送审由模型裁决", async () => {
  writeRules([LS_RULE("allow"), NODE_VERSION_RULE("ask")]);
  const t_decision = await reviewCommand("ls D:/app/demo_dir && node --version");
  assert.equal(t_decision.action, "allow", "归一后的提示送模型终审（假模型默认放行）");
  assert.equal(t_decision.source, "llm");
  assert.ok(g_last_payload.includes("「node --version」命中"), "提示应指出命中的子命令");
  assert.equal(g_llm_request_count, 1);
});

serialTest("场景8: 复合命令两段全 allow——白名单整条放行", async () => {
  writeRules([LS_RULE("allow"), NODE_VERSION_RULE("allow")]);
  const t_decision = await reviewCommand("ls D:/app/demo_dir && node --version");
  assert.equal(t_decision.action, "allow");
  assert.equal(t_decision.source, "rule");
  assert.match(t_decision.reason, /2 段子命令全部命中白名单规则/);
  assert.equal(g_llm_request_count, 0);
});

serialTest("锚定A: allow 开头的复合命令藏危险段——不允许直接放行，降级 LLM 审查", async () => {
  // 仅 ls 在白名单：`ls && rm -rf` 的第二段未命中任何规则，allow 不能替它作保
  writeRules([LS_RULE("allow")]);
  const t_decision = await reviewCommand("ls D:/app/demo_dir && rm -rf D:/app/demo_dir");
  assert.equal(t_decision.action, "deny");
  assert.equal(t_decision.source, "llm");
  assert.equal(g_llm_request_count, 1);
});

serialTest("锚定B: LLM 输出 deny——自动二值语义下保留 deny 并回传分析", async () => {
  writeRules([]);
  const t_decision = await reviewCommand("format D:");
  assert.equal(t_decision.action, "deny");
  assert.equal(t_decision.source, "llm");
  assert.match(t_decision.additionalContext, /幻觉拦截/);
  assert.equal(g_llm_request_count, 1);
});

// ─── 场景9: 上下文字段不路由（客户端未提供可信 agent 来源字段，字符串猜测不参与决策）───

serialTest("场景9: source=remote/querySource/session_id 不影响路由——不绕过规则提示也不绕过快速通道", async () => {
  // 命中风险提示：送审由模型终审，上下文字段既不放行也不额外阻断
  writeRules([LS_RULE("deny")]);
  g_llm_request_count = 0;
  const t_route = await reviewToolUse({
    tool_name: "Bash", tool_input: { command: "ls D:/app/demo_dir" },
    source: "remote", querySource: "remote", session_id: "sess_ctx",
  });
  assert.equal(t_route.action, "allow", "送审提示由模型终审（假模型默认放行）");
  assert.equal(t_route.source, "llm", "remote 字段不得让规则命中凭空消失");
  assert.equal(g_llm_request_count, 1);

  // 普通命令带着同样字段照常走 LLM 审查：字段既不放行也不额外阻断
  writeRules([]);
  g_llm_request_count = 0;
  const t_llm = await reviewToolUse({
    tool_name: "Bash", tool_input: { command: "npm run build-ctx" },
    source: "remote", querySource: "subagent", session_id: "sess_ctx",
  });
  assert.equal(t_llm.action, "allow");
  assert.equal(t_llm.source, "llm", "无规则命中时正常送审，不因来源字段短路");
  assert.equal(g_llm_request_count, 1);
});

// ─── 场景10-11: 专用审批渠道不可用的兜底（审批只认 review_provider.json，不回落 provider 表）───

serialTest("场景10: 专用审批渠道未配置——兜底转人工审批，绝不自动许可", async () => {
  writeRules([]);
  fs.writeFileSync(path.join(t_tmp_dir, "review_provider.json"), JSON.stringify({
    _说明: "全空模板（provider path 刚创建的形态）", base_url: "", api_key: "", api_kind: "", model: "",
  }));
  const t_decision = await reviewCommand("npm run build");
  assert.equal(t_decision.action, "ask", "模型不在场时必须转人工");
  assert.equal(t_decision.source, "fallback");
  assert.match(t_decision.reason, /审批模型不可用/);
  assert.equal(g_llm_request_count, 0, "未配置渠道不应发出任何 LLM 请求");
});

serialTest("场景11: 专用审批渠道不可达——兜底转人工审批（重试后仍失败）", async () => {
  writeRules([]);
  writeReviewProvider("http://127.0.0.1:1/v1");
  try {
  const t_decision = await reviewCommand("npm run build");
  assert.equal(t_decision.action, "ask", "渠道不可达同样转人工，不静默放行");
  assert.equal(t_decision.source, "fallback");
  assert.match(t_decision.reason, /审批模型不可用/);
  } finally { writeReviewProvider(); }
});

// ─── 场景12-15: 脚本内容随命令送审（inspect_scripts，附件块 + cwd 边界 + 缓存加盐）───

// 真实脚本文件目录：safe.py 内容安全；danger.py 内容含 "rm -rf" 关键字（假 LLM 据载荷内文本判定）
const t_script_dir = fs.mkdtempSync(path.join(os.tmpdir(), "auto-review-scripts-"));
test.after(() => fs.rmSync(t_script_dir, { recursive: true, force: true }));
const SAFE_PY = "print('hello scenario')";
const DANGER_PY = "import os\nos.system('rm -rf D:/scenario-data')\n";
fs.writeFileSync(path.join(t_script_dir, "safe.py"), SAFE_PY);
fs.writeFileSync(path.join(t_script_dir, "danger.py"), DANGER_PY);

serialTest("场景12: 脚本送审开启——危险脚本内容进入载荷并按内容转审核", async () => {
  writeRules([]);
  const t_settings = loadSettings();
  t_settings.cache_ttl_seconds = 0;
  t_settings.inspect_scripts = true;
  saveSettings(t_settings);
  // cwd 必传：附件只读取工作目录内的文件（0.5.0 附件边界）
  const t_decision = await reviewCommand(`python ${t_script_dir}/danger.py`, t_script_dir);
  assert.equal(t_decision.action, "deny", "脚本内容含 rm -rf，假 LLM 按载荷内文本判 ask 后自动收敛为 deny");
  assert.equal(t_decision.source, "llm");
  assert.ok(g_last_payload.includes("命令引用的脚本文件内容"), "载荷含附件块标题");
  assert.ok(g_last_payload.includes(DANGER_PY.trim()), "脚本实际内容进入载荷");
  assert.equal(g_llm_request_count, 1);
});

serialTest("场景13: 脚本送审开启——相对路径按 hook 输入 cwd 解析，安全脚本放行", async () => {
  writeRules([]);
  g_llm_request_count = 0;
  g_last_payload = "";
  const t_decision = await reviewToolUse({ tool_name: "Bash", tool_input: { command: "python safe.py" }, cwd: t_script_dir });
  assert.equal(t_decision.action, "allow");
  assert.equal(t_decision.source, "llm");
  assert.ok(g_last_payload.includes(SAFE_PY), "相对路径解析正确且内容入载荷");
  assert.equal(g_llm_request_count, 1);
});

serialTest("场景14: 脚本送审关闭——载荷不含脚本内容，行为与旧版一致", async () => {
  writeRules([]);
  const t_settings = loadSettings();
  t_settings.inspect_scripts = false;
  saveSettings(t_settings);
  const t_decision = await reviewCommand(`python ${t_script_dir}/danger.py`, t_script_dir);
  assert.equal(t_decision.action, "allow", "命令文本本身无危险关键字，按命令判 allow");
  assert.equal(t_decision.source, "llm");
  assert.equal(g_last_payload.includes(DANGER_PY.trim()), false, "脚本内容不得进入载荷");
  assert.equal(g_last_payload.includes("命令引用的脚本文件内容"), false, "不得出现附件块");
  assert.equal(g_llm_request_count, 1);
});

serialTest("场景15: 缓存加盐——脚本内容变化后同命令重新送审，内容不变复用缓存", async () => {
  writeRules([]);
  const t_settings = loadSettings();
  t_settings.inspect_scripts = true;
  t_settings.cache_ttl_seconds = 3600;
  saveSettings(t_settings);

  try {
  const t_first = await reviewCommand(`python ${t_script_dir}/safe.py`, t_script_dir);
  assert.equal(t_first.action, "allow");
  assert.equal(g_llm_request_count, 1, "首次送审");

  // 同命令同内容：缓存命中，不再请求 LLM
  const t_second = await reviewCommand(`python ${t_script_dir}/safe.py`, t_script_dir);
  assert.equal(t_second.action, "allow");
  assert.equal(t_second.source, "cache");
  assert.equal(g_llm_request_count, 0, "内容未变应复用缓存");

  // 脚本内容改为危险：附件摘要变化 → 缓存键变化 → 重新送审并按新内容自动收敛为 deny
  fs.writeFileSync(path.join(t_script_dir, "safe.py"), DANGER_PY);
  const t_third = await reviewCommand(`python ${t_script_dir}/safe.py`, t_script_dir);
  assert.equal(t_third.action, "deny", "内容变化必须重新审查");
  assert.equal(g_llm_request_count, 1, "缓存应失效");

  // 新内容再次执行：重新入缓存后复用
  const t_fourth = await reviewCommand(`python ${t_script_dir}/safe.py`, t_script_dir);
  assert.equal(t_fourth.action, "deny");
  assert.equal(t_fourth.source, "cache");
  assert.equal(g_llm_request_count, 0);

  } finally {
  // 还原环境，避免影响后续用例
  fs.writeFileSync(path.join(t_script_dir, "safe.py"), SAFE_PY);
  const t_restore = loadSettings();
  t_restore.cache_ttl_seconds = 0;
  t_restore.inspect_scripts = false;
  saveSettings(t_restore);
  }
});

serialTest("场景16: LLM 首次 5xx——自动重试一次后成功放行（渠道瞬时故障不落人工）", async () => {
  writeRules([]);
  g_fail_next_status = 500;
  const t_decision = await reviewCommand("npm run build2");
  assert.equal(t_decision.action, "allow");
  assert.equal(t_decision.source, "llm");
  assert.equal(g_llm_request_count, 2, "首次 500 后应恰好重试一次");
});

serialTest("场景17: 电源操作不在出厂危险规则内——按普通请求走模型审查，由模型判定是否用户要求", async () => {
  // 删除数据目录规则表回落出厂规则（0.8.0 起不含关机/电源规则）
  fs.rmSync(path.join(t_tmp_dir, "danger_rules.json"), { force: true });
  for (const t_command of [
    "shutdown /s /t 60",
    "shutdown.exe /r /t 0",
    "cmd /c shutdown /s",
    "powershell -Command Stop-Computer",
    "Restart-Computer",
    "cd /d C:\\app && shutdown /s /t 60",
    "shutdown /a",
  ]) {
    const t_decision = await reviewCommand(t_command);
    assert.equal(t_decision.action, "allow", `「${t_command}」走普通模型审查（假模型默认放行）`);
    assert.equal(t_decision.source, "llm", `「${t_command}」不经规则层，直达模型`);
    assert.ok(!g_last_payload.includes("关机/重启/电源操作"), `「${t_command}」不应再带出厂关机规则提示`);
    assert.equal(g_llm_request_count, 1, `命令 ${t_command} 必须走模型审查路径`);
  }

  // deny 类出厂规则（rm -rf /）保持不变：提示送审 + 假模型 ask 收敛 deny
  const t_rm = await reviewCommand("rm -rf /");
  assert.equal(t_rm.action, "deny", "最终拒绝由模型裁决（rm -rf 关键字触发假模型 ask→deny）");
  assert.equal(t_rm.source, "llm");
  assert.ok(g_last_payload.includes("危险规则 #1"), "不可逆风险提示必须随载荷送审");
  assert.equal(g_llm_request_count, 1);
});

// ─── 场景18-19: 旧 ask 配置兼容 与 唯一转人工兜底（人工与规则命中无关）───

serialTest("场景18: 旧 ask 规则与 ask_policy 键——条目归一为 deny 送审，旧键被容忍不再改变行为", async () => {
  // ① 旧配置里的 ask 条目：加载时归一为 deny——只作为风险提示送审，不再转用户
  writeRules([LS_RULE("allow"), { pattern: "shutdown", action: "ask", description: "旧用户确认门槛" }]);
  let t_decision = await reviewCommand("shutdown /s /t 0");
  assert.equal(t_decision.action, "allow", "旧 ask 条目归一为 deny → 提示送审 → 模型裁决，不弹用户");
  assert.equal(t_decision.source, "llm");
  assert.ok(g_last_payload.includes("旧用户确认门槛"), "归一后的描述原文随载荷送审");
  assert.equal(g_llm_request_count, 1);

  // 复合命令中的旧 ask 段同样只是送审提示：其余段不被整条拖成人工确认
  t_decision = await reviewCommand("ls D:/app/demo_dir && shutdown now");
  assert.equal(t_decision.action, "allow", "旧 ask 段归一 deny → 提示送审 → 模型终审");
  assert.equal(t_decision.source, "llm");
  assert.equal(g_llm_request_count, 1);

  // ② 旧 ask_policy 键写进 settings：未知键被容忍移除，user 不再切人工——仍走模型
  const t_settings = loadSettings();
  t_settings.ask_policy = "user";
  saveSettings(t_settings);
  t_decision = await reviewCommand("shutdown /s /t 0");
  assert.equal(t_decision.action, "allow", "旧 user 策略不再翻转为转人工，仍由模型裁决");
  assert.equal(t_decision.source, "llm");

  // ③ 渠道断开后同命令兜底转人工：人工路径唯一且只由模型不可用触发
  const t_provider_file = path.join(t_tmp_dir, "review_provider.json");
  const t_saved_provider = fs.readFileSync(t_provider_file, "utf8");
  writeReviewProvider("http://127.0.0.1:1/v1");
  try {
    t_decision = await reviewCommand("shutdown /s /t 0");
    assert.equal(t_decision.action, "ask", "模型不可用时兜底转人工");
    assert.equal(t_decision.source, "fallback", "兜底与规则命中无关，只由模型链路触发");
    assert.equal(g_llm_request_count, 0);
  } finally {
    fs.writeFileSync(t_provider_file, t_saved_provider);
    fs.rmSync(path.join(t_tmp_dir, "danger_rules.json"), { force: true });
  }
});

serialTest("场景19: 规则命中但渠道不可用——兜底转人工与规则命中无关（规则层不直接转人工）", async () => {
  writeRules([LS_RULE("ask")]); // 旧 ask 条目仅验证归一 deny 后命中路径同样受兜底保护
  const t_provider_file = path.join(t_tmp_dir, "review_provider.json");
  const t_saved_provider = fs.readFileSync(t_provider_file, "utf8");
  try {
    fs.writeFileSync(t_provider_file, JSON.stringify({
      _说明: "全空模板（未配置形态）", base_url: "", api_key: "", api_kind: "", model: "",
    }));
    const t_decision = await reviewCommand("ls D:/app/demo_dir");
    assert.equal(t_decision.action, "ask", "模型不可用时兜底转人工，不静默放行");
    assert.equal(t_decision.source, "fallback");
    assert.match(t_decision.reason, /审批模型不可用/);
    assert.equal(g_llm_request_count, 0);
  } finally {
    fs.writeFileSync(t_provider_file, t_saved_provider);
    fs.rmSync(path.join(t_tmp_dir, "danger_rules.json"), { force: true });
  }
});

// ─── 场景20-23: 渠道重试、PermissionRequest 协议与组合命令快速通道 ───

serialTest("场景20: provider_retries 精确生效——0 次不补发、N 次内恢复、4xx 不重试", async () => {
  writeRules([]);
  const t_settings = loadSettings();
  try {
    // ① retries=0：一次 500 直接兜底转人工
    t_settings.provider_retries = 0;
    saveSettings(t_settings);
    g_fail_next_status = 500;
    g_fail_next_count = 5; // 即使服务持续 500，客户端也只允许发一次
    let t_decision = await reviewCommand("npm run build-retry0");
    assert.equal(t_decision.action, "ask");
    assert.equal(t_decision.source, "fallback");
    assert.equal(g_llm_request_count, 1, "retries=0 时 500 后不得补发请求");

    // ② retries=2：连续两次 500 后第三次成功放行
    t_settings.provider_retries = 2;
    saveSettings(t_settings);
    g_fail_next_status = 500;
    g_fail_next_count = 2;
    t_decision = await reviewCommand("npm run build-retry2");
    assert.equal(t_decision.action, "allow");
    assert.equal(t_decision.source, "llm");
    assert.equal(g_llm_request_count, 3, "2 次重试后第三次成功");

    // ③ 4xx 是永久错误：即使 retries=2 也不补发
    g_fail_next_status = 400;
    g_fail_next_count = 5;
    t_decision = await reviewCommand("npm run build-4xx");
    assert.equal(t_decision.action, "ask");
    assert.equal(t_decision.source, "fallback");
    assert.equal(g_llm_request_count, 1, "4xx 直接失败不重试");
  } finally {
    g_fail_next_status = 0;
    g_fail_next_count = 1;
    const t_restore = loadSettings();
    t_restore.provider_retries = 2;
    saveSettings(t_restore);
  }
});

serialTest("场景22: PermissionRequest 模型可用时真实子进程输出 allow/deny 协议", async () => {
  writeRules([]);
  const t_settings = loadSettings();
  t_settings.enabled = true;
  t_settings.review_tools = ["Bash"];
  t_settings.fast_allow_enabled = false;
  t_settings.cache_ttl_seconds = 0;
  t_settings.timeout_ms = 5000;
  t_settings.provider_retries = 0;
  saveSettings(t_settings);

  const t_allow = await runPermissionHook("npm run permission-probe");
  assert.equal(t_allow.status, 0, `PermissionRequest allow 子进程失败: ${t_allow.stderr}`);
  assert.notEqual(t_allow.stdout, "", `PermissionRequest allow 空输出，stderr=${t_allow.stderr}`);
  const t_allow_payload = JSON.parse(t_allow.stdout);
  assert.equal(t_allow_payload.hookSpecificOutput.hookEventName, "PermissionRequest");
  assert.equal(t_allow_payload.hookSpecificOutput.decision.behavior, "allow");
  assert.equal(Object.hasOwn(t_allow_payload.hookSpecificOutput, "permissionDecision"), false);

  const t_deny = await runPermissionHook("format D:");
  assert.equal(t_deny.status, 0);
  const t_deny_payload = JSON.parse(t_deny.stdout);
  assert.equal(t_deny_payload.hookSpecificOutput.hookEventName, "PermissionRequest");
  assert.equal(t_deny_payload.hookSpecificOutput.decision.behavior, "deny");
  assert.match(t_deny_payload.hookSpecificOutput.decision.message, /幻觉拦截/);
});

serialTest("场景23: 45s/3 最大预算不超过两次请求", async () => {
  writeRules([]);
  const t_settings = loadSettings();
  t_settings.enabled = true;
  t_settings.review_tools = ["Bash"];
  t_settings.fast_allow_enabled = false;
  t_settings.cache_ttl_seconds = 0;
  t_settings.timeout_ms = 45000;
  t_settings.provider_retries = 3;
  saveSettings(t_settings);
  g_fail_next_status = 500;
  g_fail_next_count = 10;
  const t_decision = await reviewCommand("npm run budget-probe");
  assert.equal(t_decision.action, "ask");
  assert.equal(t_decision.source, "fallback");
  assert.equal(g_llm_request_count, 2, "最大预算配置只能发起初次请求和一次重试");
  g_fail_next_status = 0;
  g_fail_next_count = 1;
  t_settings.timeout_ms = 5000;
  t_settings.provider_retries = 2;
  t_settings.fast_allow_enabled = true;
  saveSettings(t_settings);
});

serialTest("场景24: force_review 强制裁决——名单外工具 Write 经模型自动放行，plan 退避", async () => {
  writeRules([]);
  const t_settings = loadSettings();
  t_settings.enabled = true;
  // 名单刻意不含 Write：模拟默认配置下子智能体/默认模式触发的 Write 弹窗请求，
  // 请求已走到"客户端即将弹原生审批框"，force_review 必须仍送模型裁决
  t_settings.review_tools = ["Bash"];
  t_settings.fast_allow_enabled = false;
  t_settings.cache_ttl_seconds = 0;
  t_settings.timeout_ms = 5000;
  t_settings.provider_retries = 0;
  saveSettings(t_settings);

  const t_write = await runPermissionHook("", {
    tool_name: "Write",
    tool_input: { file_path: "src/permission-probe.js", content: "export const probe = 1;" },
  });
  assert.equal(t_write.status, 0, `force_review 子进程失败: ${t_write.stderr}`);
  const t_write_payload = JSON.parse(t_write.stdout);
  assert.equal(t_write_payload.hookSpecificOutput.hookEventName, "PermissionRequest");
  assert.equal(t_write_payload.hookSpecificOutput.decision.behavior, "allow", "名单外 Write 应强制送模型并自动放行（弹窗被决策替代）");

  // plan 模式仍是硬边界：空输出退避交回原生流程
  const t_plan = await runPermissionHook("", {
    tool_name: "Bash", tool_input: { command: "dir /b" }, permission_mode: "plan",
  });
  assert.equal(t_plan.status, 0);
  assert.equal(t_plan.stdout, "", "plan 模式必须退避，不得自动放行");

  // 还原共享配置，后续场景依赖快速通道开启
  t_settings.fast_allow_enabled = true;
  saveSettings(t_settings);
});

serialTest("场景21: 组合命令快速通道——cd 段 + 白名单段 + stderr 尾缀零 LLM 放行", async () => {
  writeRules([]);
  for (const t_command of [
    "cd /d D:\\work\\VPN && dir /b",
    "dir 2>&1",
    "chdir sub & git status 2>&1",
    "ls | wc -l",
  ]) {
    const t_decision = await reviewCommand(t_command);
    assert.equal(t_decision.action, "allow", `「${t_command}」应整条走快速通道放行`);
    assert.equal(t_decision.source, "fast");
    assert.equal(g_llm_request_count, 0, `「${t_command}」不得消耗 LLM`);
  }
  // 含危险段的组合不享受捷径：整条降级送审由模型终审
  const t_evil = await reviewCommand("cd /d D:\\work && rm -rf D:/work/tmp-clean");
  assert.equal(t_evil.action, "deny");
  assert.equal(t_evil.source, "llm");
  assert.equal(g_llm_request_count, 1, "危险段必须把整条拖进模型审查");
});


