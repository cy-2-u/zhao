/**
 * 模块功能: 场景固定测试——手工验收场景的自动化回归（放行/转审核/脚本/规则三态/复合命令/脚本送审）
 * 作者: hh-zyb
 * 创建日期: 2026年08月29日
 * 描述: 复现手工验收路径并固化为可重复执行的断言：
 *       场景1-3 走 LLM 审查层，由本地假审批渠道（review_provider.json 指向假服务，
 *       openai 协议）按命令关键字返回预置结论，离线固化"安全放行 / 危险转审核 /
 *       脚本转审核"的管线行为；
 *       场景4-8 走危险规则层：deny 提炼送审提示（不再本地拦截）、ask 恒转用户确认、
 *       allow 快速放行，复合命令逐段拆分匹配；
 *       场景9 上下文字段不路由（source/querySource/session_id 不影响 ask 门槛与常规送审），
 *       10-11 专用审批渠道未配置/不可用的兜底转人工（ask）、
 *       12-15 脚本内容随命令送审（inspect_scripts 开关、附件块入载荷、脚本内容变化缓存失效）、
 *       16 渠道瞬时故障自动重试、17 出厂关机规则各包装形态恒转用户确认；
 *       另附两条防回归锚定：白名单开头的复合命令藏危险段必须降级 LLM、
 *       LLM 输出 deny 在自动二值语义下保留并回传分析。
 *       环境变量必须在 import 业务模块之前设置（common.js 在加载期固化路径）
 * 依赖: node:test node:assert node:fs node:http node:os node:path ../src/*
 * 更新日期: 2026年09月17日
 */

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";

// 隔离环境：临时数据目录（审批渠道走 review_provider.json，指向本地假 LLM 服务）
const t_tmp_dir = fs.mkdtempSync(path.join(os.tmpdir(), "auto-review-scenario-"));
process.env.AUTO_REVIEW_DATA_DIR = t_tmp_dir;

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

// 可注入的一次性故障状态码：下一个请求返回它（重试路径测试），发完即清零
let g_fail_next_status = 0;

// 假 LLM 服务（openai chat/completions 协议）：解析载荷中的命令，按关键字回预置结论
const t_fake_llm = http.createServer((t_req, t_res) => {
  const t_chunks = [];
  t_req.on("data", (t_chunk) => t_chunks.push(t_chunk));
  t_req.on("end", () => {
    g_llm_request_count++;
    if (g_fail_next_status) {
      const t_status = g_fail_next_status;
      g_fail_next_status = 0;
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

// 运行时配置：开启审查、只审 Bash、禁用缓存保证用例无状态串扰
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

test("场景1: 安全普通指令——LLM 审查后放行", async () => {
  writeRules([]);
  const t_decision = await reviewCommand("npm run build");
  assert.equal(t_decision.action, "allow");
  assert.equal(t_decision.source, "llm");
  assert.match(t_decision.reason, /安全审查通过/);
  assert.equal(g_llm_request_count, 1);
});

test("场景2: 危险删除指令——LLM 判高风险，自动模式收敛为 deny 并回传分析", async () => {
  writeRules([]);
  const t_decision = await reviewCommand("rm -rf D:/app/demo_dir");
  assert.equal(t_decision.action, "deny");
  assert.equal(t_decision.source, "llm");
  assert.match(t_decision.reason, /风险级别 high/);
  // deny 回传通道：风险分析与替代方案随 additionalContext 进入主 agent 上下文
  assert.match(t_decision.additionalContext, /风险级别 high/);
  assert.equal(g_llm_request_count, 1);
});

test("场景3: 执行删除脚本——LLM 判中风险，自动模式收敛为 deny", async () => {
  writeRules([]);
  const t_decision = await reviewCommand("bash D:/app/delete_demo.sh");
  assert.equal(t_decision.action, "deny");
  assert.equal(t_decision.source, "llm");
  assert.match(t_decision.reason, /风险级别 medium/);
  assert.equal(g_llm_request_count, 1);
});

test("场景4: deny 规则命中 ls——提炼风险提示送审，不再本地直接拦", async () => {
  writeRules([LS_RULE("deny")]);
  const t_decision = await reviewCommand("ls D:/app/demo_dir");
  assert.equal(t_decision.action, "allow");
  assert.equal(t_decision.source, "llm");
  assert.match(t_decision.reason, /安全审查通过/);
  assert.ok(g_last_payload.includes("危险规则 #1"), "规则提示应随载荷送审");
  assert.ok(g_last_payload.includes("本地规则仅作为风险提示"), "提示需注明只是线索非结论");
  assert.equal(g_llm_request_count, 1);
});

test("场景5: ask 规则命中 ls——恒转用户确认（规则层 ask 不收敛）", async () => {
  writeRules([LS_RULE("ask")]);
  const t_decision = await reviewCommand("ls D:/app/demo_dir");
  assert.equal(t_decision.action, "ask");
  assert.equal(t_decision.source, "rule");
  assert.match(t_decision.reason, /危险规则 #1/);
  assert.match(t_decision.reason, /等待你裁决/);
  assert.match(t_decision.additionalContext, /等待你裁决/);
  assert.equal(g_llm_request_count, 0);
});

test("场景6: allow 规则命中 ls——白名单直接放行，跳过 LLM", async () => {
  writeRules([LS_RULE("allow")]);
  const t_decision = await reviewCommand("ls D:/app/demo_dir");
  assert.equal(t_decision.action, "allow");
  assert.equal(t_decision.source, "rule");
  assert.match(t_decision.reason, /白名单放行/);
  assert.equal(g_llm_request_count, 0);
});

test("场景7: 复合命令 ls(allow)+node --version(ask)——拆分匹配，整条转用户确认", async () => {
  writeRules([LS_RULE("allow"), NODE_VERSION_RULE("ask")]);
  const t_decision = await reviewCommand("ls D:/app/demo_dir && node --version");
  assert.equal(t_decision.action, "ask");
  assert.equal(t_decision.source, "rule");
  assert.match(t_decision.reason, /node --version/);
  assert.match(t_decision.reason, /转用户确认/);
  assert.equal(g_llm_request_count, 0);
});

test("场景8: 复合命令两段全 allow——白名单整条放行", async () => {
  writeRules([LS_RULE("allow"), NODE_VERSION_RULE("allow")]);
  const t_decision = await reviewCommand("ls D:/app/demo_dir && node --version");
  assert.equal(t_decision.action, "allow");
  assert.equal(t_decision.source, "rule");
  assert.match(t_decision.reason, /2 段子命令全部命中白名单规则/);
  assert.equal(g_llm_request_count, 0);
});

test("锚定A: allow 开头的复合命令藏危险段——不允许直接放行，降级 LLM 审查", async () => {
  // 仅 ls 在白名单：`ls && rm -rf` 的第二段未命中任何规则，allow 不能替它作保
  writeRules([LS_RULE("allow")]);
  const t_decision = await reviewCommand("ls D:/app/demo_dir && rm -rf D:/app/demo_dir");
  assert.equal(t_decision.action, "deny");
  assert.equal(t_decision.source, "llm");
  assert.equal(g_llm_request_count, 1);
});

test("锚定B: LLM 输出 deny——自动二值语义下保留 deny 并回传分析", async () => {
  writeRules([]);
  const t_decision = await reviewCommand("format D:");
  assert.equal(t_decision.action, "deny");
  assert.equal(t_decision.source, "llm");
  assert.match(t_decision.additionalContext, /幻觉拦截/);
  assert.equal(g_llm_request_count, 1);
});

// ─── 场景9: 上下文字段不路由（客户端未提供可信 agent 来源字段，字符串猜测不参与决策）───

test("场景9: source=remote/querySource/session_id 不影响路由——ask 门槛恒转用户，普通命令照常送审", async () => {
  // ask 规则恒转用户：任何上下文字段都不得绕过用户确认门槛
  writeRules([LS_RULE("ask")]);
  g_llm_request_count = 0;
  const t_ask = await reviewToolUse({
    tool_name: "Bash", tool_input: { command: "ls D:/app/demo_dir" },
    source: "remote", querySource: "remote", session_id: "sess_ctx",
  });
  assert.equal(t_ask.action, "ask", "remote 来源猜测不得隐式放行 ask 规则");
  assert.equal(t_ask.source, "rule");
  assert.equal(g_llm_request_count, 0);

  // 普通命令带着同样字段照常走 LLM 审查：字段既不放行也不额外阻断
  writeRules([]);
  g_llm_request_count = 0;
  const t_llm = await reviewToolUse({
    tool_name: "Bash", tool_input: { command: "npm run build-ctx" },
    source: "remote", querySource: "subagent", session_id: "sess_ctx",
  });
  assert.equal(t_llm.action, "allow");
  assert.equal(t_llm.source, "llm", "无 ask/deny 命中时正常送审，不因来源字段短路");
  assert.equal(g_llm_request_count, 1);
});

// ─── 场景10-11: 专用审批渠道不可用的兜底（审批只认 review_provider.json，不回落 provider 表）───

test("场景10: 专用审批渠道未配置——兜底转人工审批，绝不自动许可", async () => {
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

test("场景11: 专用审批渠道不可达——兜底转人工审批（重试后仍失败）", async () => {
  writeRules([]);
  writeReviewProvider("http://127.0.0.1:1/v1");
  const t_decision = await reviewCommand("npm run build");
  assert.equal(t_decision.action, "ask", "渠道不可达同样转人工，不静默放行");
  assert.equal(t_decision.source, "fallback");
  assert.match(t_decision.reason, /审批模型不可用/);
  // 还原可用渠道，供后续脚本送审用例使用
  writeReviewProvider();
});

// ─── 场景12-15: 脚本内容随命令送审（inspect_scripts，附件块 + cwd 边界 + 缓存加盐）───

// 真实脚本文件目录：safe.py 内容安全；danger.py 内容含 "rm -rf" 关键字（假 LLM 据载荷内文本判定）
const t_script_dir = fs.mkdtempSync(path.join(os.tmpdir(), "auto-review-scripts-"));
const SAFE_PY = "print('hello scenario')";
const DANGER_PY = "import os\nos.system('rm -rf D:/scenario-data')\n";
fs.writeFileSync(path.join(t_script_dir, "safe.py"), SAFE_PY);
fs.writeFileSync(path.join(t_script_dir, "danger.py"), DANGER_PY);

test("场景12: 脚本送审开启——危险脚本内容进入载荷并按内容转审核", async () => {
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

test("场景13: 脚本送审开启——相对路径按 hook 输入 cwd 解析，安全脚本放行", async () => {
  writeRules([]);
  g_llm_request_count = 0;
  g_last_payload = "";
  const t_decision = await reviewToolUse({ tool_name: "Bash", tool_input: { command: "python safe.py" }, cwd: t_script_dir });
  assert.equal(t_decision.action, "allow");
  assert.equal(t_decision.source, "llm");
  assert.ok(g_last_payload.includes(SAFE_PY), "相对路径解析正确且内容入载荷");
  assert.equal(g_llm_request_count, 1);
});

test("场景14: 脚本送审关闭——载荷不含脚本内容，行为与旧版一致", async () => {
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

test("场景15: 缓存加盐——脚本内容变化后同命令重新送审，内容不变复用缓存", async () => {
  writeRules([]);
  const t_settings = loadSettings();
  t_settings.inspect_scripts = true;
  t_settings.cache_ttl_seconds = 3600;
  saveSettings(t_settings);

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

  // 还原环境，避免影响后续用例
  fs.writeFileSync(path.join(t_script_dir, "safe.py"), SAFE_PY);
  const t_restore = loadSettings();
  t_restore.cache_ttl_seconds = 0;
  t_restore.inspect_scripts = false;
  saveSettings(t_restore);
});

test("场景16: LLM 首次 5xx——自动重试一次后成功放行（渠道瞬时故障不落人工）", async () => {
  writeRules([]);
  g_fail_next_status = 500;
  const t_decision = await reviewCommand("npm run build2");
  assert.equal(t_decision.action, "allow");
  assert.equal(t_decision.source, "llm");
  assert.equal(g_llm_request_count, 2, "首次 500 后应恰好重试一次");
});

test("场景17: 出厂关机规则——各包装形态恒转用户确认（ask 门槛不经 LLM）", async () => {
  // 删除数据目录规则表回落出厂规则（ask 关机门槛 + deny 不可逆提示）
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
    assert.equal(t_decision.action, "ask", `「${t_command}」应命中出厂 ask 门槛`);
    assert.equal(t_decision.source, "rule");
  }
  assert.equal(g_llm_request_count, 0, "ask 门槛直接转用户，不消耗 LLM");

  // deny 类出厂规则（rm -rf /）不再本地拦截：提炼提示送审，假模型按 "rm -rf" 关键字
  // 判 ask 后自动收敛为 deny——证明"拒绝"真正来自模型而非规则
  const t_rm = await reviewCommand("rm -rf /");
  assert.equal(t_rm.action, "deny", "最终拒绝由模型裁决（rm -rf 关键字触发假模型 ask→deny）");
  assert.equal(t_rm.source, "llm");
  assert.ok(g_last_payload.includes("危险规则 #1"), "不可逆风险提示必须随载荷送审");
  assert.equal(g_llm_request_count, 1);
});

test.after(() => {
  t_fake_llm.close();
  fs.rmSync(t_script_dir, { recursive: true, force: true });
  fs.rmSync(t_tmp_dir, { recursive: true, force: true });
});
