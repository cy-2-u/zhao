/**
 * 模块功能: 插件控制 CLI——斜杠命令操作插件的唯一入口（init/status/set/rules/prompt/provider）
 * 作者: hh-zyb
 * 创建日期: 2026年08月29日
 * 描述: 命令文档指导主 agent 调用本脚本完成配置变更，校验逻辑集中在代码而非提示词中，
 *       避免模型手改 JSON 出错；本脚本独立于 hook 协议，stdout 面向命令输出可读文本
 * 功能:
 *   - init: 把出厂默认配置物化到数据目录（不覆盖已有文件）
 *   - status / set: 运行时配置查看与修改（键与类型校验，含脚本送审开关）
 *   - rules list|add|remove|test: 危险规则表管理
 *   - prompt show|path|reset: 安全提示词查看/定位/恢复默认
 *   - provider path|show|test: 专用审批渠道模板定位/脱敏查看/真实连通性测试
 * 依赖: node:fs ./common.js ./settings.js ./provider.js
 * 更新日期: 2026年09月18日
 */

import fs from "node:fs";

import {
  getDataDir,
  SETTINGS_FILE,
  DANGER_RULES_FILE,
  SECURITY_PROMPT_FILE,
  FAST_ALLOW_FILE,
  REVIEW_PROVIDER_FILE,
  DEFAULT_SETTINGS_FILE,
  DEFAULT_DANGER_RULES_FILE,
  DEFAULT_SECURITY_PROMPT_FILE,
  DEFAULT_FAST_ALLOW_FILE,
  writeFileAtomic,
  readJsonFile,
} from "./common.js";
import { loadSettings, saveSettings, loadRawDangerRules, loadDangerRules, saveDangerRules, loadRawFastAllow, validateDangerRule, MAX_RULES } from "./settings.js";
import { resolveProvider, callLlm, providerWorstCaseMs, effectiveProviderRetries } from "./provider.js";

// set 命令允许修改的键及其解析方式；未列出的键一律拒绝，防止写入无效配置。
// 审批渠道与模型不在其中——只认 review_provider.json（provider 子命令管理）
const SETTABLE_KEYS = {
  enabled: "boolean",
  review_tools: "string_array",
  timeout_ms: "int",
  provider_retries: "int",
  cache_ttl_seconds: "int",
  max_payload_chars: "int",
  inspect_scripts: "boolean",
  script_max_bytes: "int",
  fast_allow_enabled: "boolean",
};

// 数值键的合法区间，与 settings.js 加载时的钳制保持一致
const NUMBER_RANGES = {
  timeout_ms: [5000, 45000],
  provider_retries: [0, 3],
  cache_ttl_seconds: [0, 86400],
  max_payload_chars: [500, 100000],
  script_max_bytes: [1000, 100000],
};

/**
 * 函数功能: 把出厂默认配置物化到数据目录（已存在的文件不覆盖）
 * @returns {void}
 */
function existingFile(file) {
  if (!fs.existsSync(file)) return false;
  if (!fs.statSync(file).isFile()) throw new Error(`目标不是普通文件: ${file}`);
  return true;
}

function requireWrite(file, content) {
  if (!writeFileAtomic(file, content)) throw new Error(`写入失败: ${file}`);
}

function cmdInit() {
  getDataDir();
  const t_pairs = [
    [DEFAULT_SETTINGS_FILE, SETTINGS_FILE()],
    [DEFAULT_DANGER_RULES_FILE, DANGER_RULES_FILE()],
    [DEFAULT_FAST_ALLOW_FILE, FAST_ALLOW_FILE()],
    [DEFAULT_SECURITY_PROMPT_FILE, SECURITY_PROMPT_FILE()],
  ];
  for (const [t_src, t_dst] of t_pairs) {
    if (existingFile(t_dst)) {
      console.log(`已存在，跳过: ${t_dst}`);
      continue;
    }
    requireWrite(t_dst, fs.readFileSync(t_src, "utf8"));
    console.log(`已初始化: ${t_dst}`);
  }
}

/**
 * 函数功能: 输出当前配置摘要（供 /auto-review 状态汇报）
 * @returns {void}
 */
function cmdStatus() {
  const t_settings = loadSettings();
  const t_rules = loadRawDangerRules();
  const t_fast = loadRawFastAllow();
  console.log(`数据目录: ${getDataDir()}`);
  console.log(`enabled: ${t_settings.enabled}`);
  console.log(`review_tools: ${t_settings.review_tools.join(", ")}`);
  // 审批只认 review_provider.json：如实展示填写状态，未配置即 LLM 审查不可用
  const t_review_raw = readJsonFile(REVIEW_PROVIDER_FILE(), null, "ctl");
  let t_channel_desc;
  if (!t_review_raw) {
    t_channel_desc = "未配置（LLM 审查不可用：allow 规则/快速通道照常放行，其余命令转人工审批；用 provider path 创建）";
  } else {
    const t_base = String(t_review_raw.base_url || "").trim();
    const t_key = String(t_review_raw.api_key || "").trim();
    const t_model = String(t_review_raw.model || "").trim();
    if (t_base && t_key && t_model) {
      t_channel_desc = `专用审批渠道 ${t_base}（模型 ${t_model}）`;
    } else if (t_base || t_key) {
      t_channel_desc = "填写不完整（补全 base_url/api_key/model 后生效，当前 LLM 审查不可用，命令转人工审批）";
    } else {
      t_channel_desc = "模板未填写（LLM 审查不可用，命令转人工审批）";
    }
  }
  console.log(`审批渠道: ${t_channel_desc}`);
  console.log(`timeout_ms: ${t_settings.timeout_ms}`);
  const t_effective_retries = effectiveProviderRetries(t_settings.timeout_ms, t_settings.provider_retries);
  const t_worst_case_ms = providerWorstCaseMs(t_settings.timeout_ms, t_settings.provider_retries);
  console.log(`provider_retries: ${t_settings.provider_retries}（配置值；实际最多重试 ${t_effective_retries} 次，最坏阻塞约 ${t_worst_case_ms}ms，含 120s hook 预算）`);
  console.log(`cache_ttl_seconds: ${t_settings.cache_ttl_seconds}`);
  console.log(`max_payload_chars: ${t_settings.max_payload_chars}`);
  console.log(`inspect_scripts: ${t_settings.inspect_scripts}${t_settings.inspect_scripts ? `（单文件上限 ${t_settings.script_max_bytes} 字节）` : "（脚本内容不随载荷送审）"}`);
  console.log(`fast_allow_enabled: ${t_settings.fast_allow_enabled}（快速通道白名单 ${t_fast.length} 条）`);
  console.log(`危险规则条数: ${t_rules.length}`);
  console.log(`提示词: ${fs.existsSync(SECURITY_PROMPT_FILE()) ? "已自定义" : "出厂默认"}`);
}

// 专用审批渠道模板：下划线键为填写指引，provider.js 加载时剥离
const REVIEW_PROVIDER_TEMPLATE = `{
  "_说明": "专用审批渠道配置——审批的唯一 LLM 来源，未配置时 LLM 审查不可用（allow 规则/快速通道照常放行，其余命令转人工审批）。base_url 填 OpenAI 兼容或 Anthropic 兼容端点（如 https://open.bigmodel.cn/api/paas/v4 或 https://api.z.ai/api/anthropic）；api_key 填该平台的 API Key；api_kind 填 openai 或 anthropic（留空按地址自动推断）；model 填模型名（推荐快模型）。",
  "base_url": "",
  "api_key": "",
  "api_kind": "",
  "model": ""
}
`;

/**
 * 函数功能: 专用审批渠道子命令——path 定位/物化模板、show 查看脱敏配置、test 连通性实测
 * @param {string} sub - path / show / test
 * @returns {Promise<void>}
 */
async function cmdProvider(sub) {
  if (sub === "path") {
    if (!existingFile(REVIEW_PROVIDER_FILE())) {
      requireWrite(REVIEW_PROVIDER_FILE(), REVIEW_PROVIDER_TEMPLATE);
      console.log(`已创建模板: ${REVIEW_PROVIDER_FILE()}`);
      console.log("填好 base_url / api_key / model 后用 provider test 验证连通。");
    } else {
      console.log(REVIEW_PROVIDER_FILE());
    }
    return;
  }
  if (sub === "show") {
    if (!existingFile(REVIEW_PROVIDER_FILE())) {
      console.log("(未配置专用审批渠道，LLM 审查不可用（规则层/快速通道照常）。用 provider path 创建模板。)");
      return;
    }
    const t_raw = JSON.parse(fs.readFileSync(REVIEW_PROVIDER_FILE(), "utf8").replace(/^\uFEFF/, ""));
    if (!t_raw || typeof t_raw !== "object" || Array.isArray(t_raw)) throw new Error("渠道配置必须为 JSON 对象");
    for (const [t_key, t_value] of Object.entries(t_raw)) {
      if (t_key === "api_key") {
        console.log(`${t_key}: ${"***"}…(已脱敏，长度 ${String(t_value ?? "").length})`);
      } else {
        console.log(`${t_key}: ${t_value}`);
      }
    }
    return;
  }
  if (sub === "test") {
    let t_info;
    try {
      t_info = resolveProvider(loadSettings());
    } catch (t_error) {
      console.log(`配置解析失败: ${t_error.message}`);
      process.exitCode = 1;
      return;
    }
    console.log(`渠道: ${t_info.baseURL}（kind=${t_info.kind}，专用审批渠道）`);
    console.log(`模型: ${t_info.model}`);
    console.log("发起真实连通性测试…");
    try {
      const t_start = Date.now();
      const t_text = await callLlm(t_info, "你是连通性测试助手。", '只输出 JSON: {"ok":true}');
      const t_ms = Date.now() - t_start;
      console.log(`调用成功（${t_ms}ms），模型输出: ${t_text.slice(0, 200)}`);
      console.log("审批链路可用。");
    } catch (t_error) {
      console.log(`调用失败: ${t_error.message}`);
      console.log("请检查 review_provider.json 的 base_url / api_key / model 是否正确（审批只认专用渠道，不回落 ZCode provider 表）。");
      process.exitCode = 1;
    }
    return;
  }
  throw new Error("子命令: path / show / test");
}

/**
 * 函数功能: 解析 set 命令的值字符串为目标类型
 * @param {string} key - 配置键
 * @param {string} raw_value - 命令行原始值
 * @returns {*} 类型正确的值
 * @throws {Error} 值非法时抛出（消息面向用户）
 */
function parseSetValue(key, raw_value) {
  const t_type = SETTABLE_KEYS[key];
  if (t_type === "boolean") {
    if (raw_value === "true") return true;
    if (raw_value === "false") return false;
    throw new Error(`${key} 只接受 true/false`);
  }
  if (t_type === "string_array") {
    let t_parsed;
    try {
      t_parsed = JSON.parse(raw_value);
    } catch {
      // 容忍裸写法：Bash,Write
      t_parsed = raw_value.split(",").map((s) => s.trim()).filter(Boolean);
    }
    if (!Array.isArray(t_parsed) || t_parsed.some((s) => typeof s !== "string" || !s.trim())) {
      throw new Error(`${key} 需要字符串数组，如 '["Bash"]' 或 "Bash,Write"`);
    }
    return t_parsed;
  }
  // 数值键
  const t_num = Number(raw_value);
  if (!Number.isFinite(t_num)) {
    throw new Error(`${key} 需要数字`);
  }
  const [t_min, t_max] = NUMBER_RANGES[key];
  return Math.min(t_max, Math.max(t_min, Math.round(t_num)));
}

/**
 * 函数功能: 修改并保存一个配置键
 * @param {string} key - 配置键
 * @param {string} raw_value - 原始值字符串
 * @returns {void}
 */
function cmdSet(key, raw_value) {
  if (!(key in SETTABLE_KEYS)) {
    throw new Error(`未知配置键 "${key}"，可用: ${Object.keys(SETTABLE_KEYS).join(", ")}`);
  }
  const t_settings = loadSettings();
  t_settings[key] = parseSetValue(key, raw_value);
  if (!saveSettings(t_settings)) {
    throw new Error("写入 settings.json 失败");
  }
  console.log(`已设置 ${key} = ${JSON.stringify(t_settings[key])}`);
  if (key === "enabled" && t_settings.enabled) {
    console.log("提示: 自动审查已开启，除 plan 与完全访问（yolo）外的所有权限模式均自动接管，无需切换模式；人工审批只在审批模型不可用时出现。");
  }
}

/**
 * 函数功能: 列出危险规则表
 * @returns {void}
 */
function cmdRulesList() {
  const t_rules = loadRawDangerRules();
  if (t_rules.length === 0) {
    console.log("(规则表为空，后续按快速通道、缓存与模型审查流程处理)");
    return;
  }
  t_rules.forEach((t_rule, t_index) => {
    console.log(`#${t_index + 1} [${t_rule?.action ?? "无效"}] ${t_rule?.description ?? "(无效规则)"}`);
    console.log(`    ${t_rule?.pattern ?? "(无正则)"}`);
  });
}

/**
 * 函数功能: 追加一条危险规则（正则先行自校验）
 * @param {string} action - deny/allow
 * @param {string} pattern - 正则源文本
 * @param {string} description - 规则描述
 * @returns {void}
 */
function cmdRulesAdd(action, pattern, description) {
  const t_new = { pattern, action, description: description || "(无描述)" };
  validateDangerRule(t_new, { strictAction: true });
  const t_rules = loadRawDangerRules();
  if (t_rules.length >= MAX_RULES) {
    throw new Error(`原始规则条目已达上限 ${MAX_RULES}，请先清理无效或多余条目再追加`);
  }
  t_rules.push(t_new);
  if (!saveDangerRules(t_rules)) {
    throw new Error("写入 danger_rules.json 失败");
  }
  console.log(`已追加规则 #${t_rules.length} [${action}] ${description}`);
}

/**
 * 函数功能: 按序号删除危险规则
 * @param {string} index_str - 1 起始的序号字符串
 * @returns {void}
 */
function cmdRulesRemove(index_str) {
  const t_index = Number(index_str);
  const t_rules = loadRawDangerRules();
  if (!Number.isInteger(t_index) || t_index < 1 || t_index > t_rules.length) {
    throw new Error(`序号必须是 1~${t_rules.length}`);
  }
  const t_removed = t_rules.splice(t_index - 1, 1)[0];
  if (!saveDangerRules(t_rules)) {
    throw new Error("写入 danger_rules.json 失败");
  }
  console.log(`已删除 #${t_index}: ${t_removed?.description ?? "(无效规则)"}`);
}

/**
 * 函数功能: 用给定文本跑一遍规则层（不调 LLM），报告全部命中
 * @param {string} text - 被测文本（命令或路径）
 * @returns {void}
 */
function cmdRulesTest(text) {
  if (!text) {
    throw new Error("缺少被测文本");
  }
  const t_hits = [];
  for (const t_rule of loadDangerRules()) {
    if (t_rule.regex.test(text)) {
      t_hits.push(`#${t_rule.index} [${t_rule.action}] ${t_rule.description}`);
    }
  }
  if (t_hits.length === 0) {
    console.log("未命中任何规则（后续仍会检查快速通道与缓存；需要模型审查但渠道不可用时转人工审批）");
  } else {
    console.log(`命中 ${t_hits.length} 条:`);
    for (const t_hit of t_hits) {
      console.log(`  ${t_hit}`);
    }
    console.log(`(语义: allow=单独/组合命令按段快速放行；deny=作为风险提示送审批模型裁决，模型不可用时才转人工审批；命中规则都不会直接弹给用户)`);
  }
}

/**
 * 函数功能: 输出当前安全提示词全文
 * @returns {void}
 */
function cmdPromptShow() {
  const t_source = fs.existsSync(SECURITY_PROMPT_FILE()) ? SECURITY_PROMPT_FILE() : DEFAULT_SECURITY_PROMPT_FILE;
  console.log(`(来源: ${t_source})`);
  console.log(fs.readFileSync(t_source, "utf8"));
}

/**
 * 函数功能: 输出提示词文件路径（供主 agent 直接编辑）
 * @returns {void}
 */
function cmdPromptPath() {
  getDataDir();
  // 不存在则先物化默认，保证 agent 拿到的路径一定可编辑
  if (!existingFile(SECURITY_PROMPT_FILE())) {
    requireWrite(SECURITY_PROMPT_FILE(), fs.readFileSync(DEFAULT_SECURITY_PROMPT_FILE, "utf8"));
  }
  console.log(SECURITY_PROMPT_FILE());
}

/**
 * 函数功能: 恢复出厂默认提示词
 * @returns {void}
 */
function cmdPromptReset() {
  requireWrite(SECURITY_PROMPT_FILE(), fs.readFileSync(DEFAULT_SECURITY_PROMPT_FILE, "utf8"));
  console.log("已恢复出厂默认提示词");
}

/**
 * 函数功能: 子命令分发表
 * @param {string[]} argv - 去掉 node 与脚本路径后的参数列表
 * @returns {void}
 */
function dispatch(argv) {
  const [t_cmd, t_sub, ...t_rest] = argv;
  if (t_cmd === "init") return cmdInit();
  if (t_cmd === "status") return cmdStatus();
  if (t_cmd === "set") {
    if (!t_sub || t_rest.length < 1) throw new Error("用法: set <key> <value>");
    return cmdSet(t_sub, t_rest.join(" "));
  }
  if (t_cmd === "rules") {
    if (t_sub === "list") return cmdRulesList();
    if (t_sub === "add") {
      if (t_rest.length < 3) throw new Error('用法: rules add <deny|allow> <正则> <描述>');
      return cmdRulesAdd(t_rest[0], t_rest[1], t_rest.slice(2).join(" "));
    }
    if (t_sub === "remove") {
      if (t_rest.length < 1) throw new Error("用法: rules remove <序号>");
      return cmdRulesRemove(t_rest[0]);
    }
    if (t_sub === "test") {
      if (t_rest.length < 1) throw new Error("用法: rules test <文本>");
      return cmdRulesTest(t_rest.join(" "));
    }
    throw new Error("子命令: list / add / remove / test");
  }
  if (t_cmd === "prompt") {
    if (t_sub === "show") return cmdPromptShow();
    if (t_sub === "path") return cmdPromptPath();
    if (t_sub === "reset") return cmdPromptReset();
    throw new Error("子命令: show / path / reset");
  }
  if (t_cmd === "provider") {
    return cmdProvider(t_sub);
  }
  throw new Error(`未知命令 "${t_cmd || ""}"。可用: init / status / set / rules / prompt / provider`);
}

// 入口：错误统一走 stderr + exit 1，成功输出全部在 stdout；provider test 为异步命令
try {
  const t_result = dispatch(process.argv.slice(2));
  if (t_result && typeof t_result.catch === "function") {
    t_result.catch((t_error) => {
      process.stderr.write(`[auto-review] ${t_error && t_error.message ? t_error.message : String(t_error)}\n`);
      process.exit(1);
    });
  }
} catch (t_error) {
  process.stderr.write(`[auto-review] ${t_error.message}\n`);
  process.exit(1);
}
