/**
 * 模块功能: 运行时配置的加载与保存——settings / 危险规则 / 安全提示词
 * 作者: hh-zyb
 * 创建日期: 2026年08月29日
 * 描述: 数据目录文件优先，缺失或损坏时回落插件包内出厂默认；
 *       所有写入走原子写；规则对象在加载时即编译正则，非法规则跳过并告警
 * 功能:
 *   - loadSettings/saveSettings: 运行时配置（开关、审查工具、脚本送审等）
 *   - loadDangerRules: 危险规则表（含正则编译与容错）
 *   - loadFastAllow/loadRawFastAllow: 快速通道白名单（低风险命令 0 LLM 放行，含正则编译）
 *   - loadSecurityPrompt: 安全子 agent 系统提示词
 * 依赖: ./common.js
 * 更新日期: 2026年09月16日
 */

import fs from "node:fs";

import {
  SETTINGS_FILE,
  DANGER_RULES_FILE,
  SECURITY_PROMPT_FILE,
  FAST_ALLOW_FILE,
  DEFAULT_SETTINGS_FILE,
  DEFAULT_DANGER_RULES_FILE,
  DEFAULT_SECURITY_PROMPT_FILE,
  DEFAULT_FAST_ALLOW_FILE,
  logWrite,
  readJsonFile,
  writeFileAtomic,
} from "./common.js";

// LLM 超时的合法区间：上限 45s 是体验预算（审批每条命令都要等，越久交互越卡；
// 低值快速失败让兜底转人工审批，不打断工作流）
const TIMEOUT_MS_MIN = 5000;
const TIMEOUT_MS_MAX = 45000;

// 脚本送审单文件读取上限的合法区间：过小无审查价值，过大撑爆载荷与 token 预算
const SCRIPT_BYTES_MIN = 1000;
const SCRIPT_BYTES_MAX = 100000;

// 数值键上限与 ctl.js 的 NUMBER_RANGES 保持一致：手改 settings.json 绕过 ctl 时同样受约束
// （超大 cache_ttl 会让缓存近乎永久生效，读取侧的 2 倍 TTL 防线依赖 TTL 本身有界）
const CACHE_TTL_MAX_SECONDS = 86400;
const MAX_PAYLOAD_MAX_CHARS = 100000;

// 规则表规模上限：防止超大/超长配置（误粘贴、生成器产物）拖垮每次 hook 的
// 正则编译与匹配，同时限制病态正则的回溯成本
const MAX_RULES = 200;
const MAX_PATTERN_LENGTH = 500;
const MAX_DESCRIPTION_LENGTH = 200;

// 合法动作集合，规则 action 超出此集合按 ask 处理（宁可多问不放过）
const VALID_RULE_ACTIONS = new Set(["deny", "ask", "allow"]);

// 规则正则编译标志：i 应对 Windows 命令大小写不定，m 保证行首锚点按行生效
const RULE_REGEX_FLAGS = "im";

/**
 * 函数功能: 加载运行时配置（出厂默认 + 数据目录覆盖，含类型校验与钳制）
 * @returns {object} 合并后的配置对象
 */
function loadSettings() {
  const t_defaults = readJsonFile(DEFAULT_SETTINGS_FILE, {}, "settings");
  const t_raw = readJsonFile(SETTINGS_FILE(), {}, "settings");
  const t_stored = t_raw && typeof t_raw === "object" && !Array.isArray(t_raw) ? t_raw : {};
  if (t_stored !== t_raw) logWrite("WARN", "settings", "配置根节点应为对象，已回落默认值");
  const t_merged = { ...t_defaults };

  // 只接受与默认值同类型的覆盖，防止手改配置文件引入脏值拖垮审查
  for (const t_key of Object.keys(t_defaults)) {
    const t_value = t_stored[t_key];
    if (t_value === undefined) {
      continue;
    }
    if (Array.isArray(t_defaults[t_key])) {
      if (Array.isArray(t_value) && (t_key !== "review_tools" || t_value.every((v) => typeof v === "string" && v.trim()))) {
        t_merged[t_key] = t_value;
      } else {
        logWrite("WARN", "settings", `字段 ${t_key} 应为数组，已回落默认值`);
      }
    } else if (typeof t_value === typeof t_defaults[t_key] && t_value !== null) {
      t_merged[t_key] = t_value;
    } else {
      logWrite("WARN", "settings", `字段 ${t_key} 类型不符，已回落默认值`);
    }
  }

  // 数值字段钳制到合法区间，越界值就近收敛而不是拒绝服务
  t_merged.timeout_ms = Math.min(TIMEOUT_MS_MAX, Math.max(TIMEOUT_MS_MIN, Number(t_merged.timeout_ms) || TIMEOUT_MS_MAX));
  t_merged.cache_ttl_seconds = Math.min(CACHE_TTL_MAX_SECONDS, Math.max(0, Number(t_merged.cache_ttl_seconds) || 0));
  t_merged.max_payload_chars = Math.min(MAX_PAYLOAD_MAX_CHARS, Math.max(500, Number(t_merged.max_payload_chars) || 8000));
  t_merged.script_max_bytes = Math.min(SCRIPT_BYTES_MAX, Math.max(SCRIPT_BYTES_MIN, Number(t_merged.script_max_bytes) || 16000));
  return t_merged;
}

/**
 * 函数功能: 保存运行时配置到数据目录（原子写）
 * @param {object} settings - 完整配置对象
 * @returns {boolean} 是否保存成功
 */
function saveSettings(settings) {
  return writeFileAtomic(SETTINGS_FILE(), JSON.stringify(settings, null, 2) + "\n");
}

/**
 * 函数功能: 加载危险规则并编译正则
 * @returns {Array<{regex: RegExp, action: string, description: string, index: number}>}
 *          可用规则列表，index 为用户在命令中看到的序号（含被跳过的非法规则）
 */
function validateDangerRule(rule, { strictAction = false } = {}) {
  if (!rule || typeof rule !== "object" || Array.isArray(rule) ||
      typeof rule.pattern !== "string" || typeof rule.description !== "string") {
    throw new Error("规则结构非法（缺 pattern/description）");
  }
  if (!rule.pattern.trim()) throw new Error("正则不能为空");
  if (rule.pattern.length > MAX_PATTERN_LENGTH) throw new Error(`正则超长（上限 ${MAX_PATTERN_LENGTH}）`);
  if (rule.description.length > MAX_DESCRIPTION_LENGTH) throw new Error(`描述超长（上限 ${MAX_DESCRIPTION_LENGTH}）`);
  if (strictAction && !VALID_RULE_ACTIONS.has(rule.action)) throw new Error("action 只能是 deny/ask/allow");
  try {
    return { regex: new RegExp(rule.pattern, RULE_REGEX_FLAGS),
      action: VALID_RULE_ACTIONS.has(rule.action) ? rule.action : "ask", description: rule.description };
  } catch (error) {
    throw new Error(`正则编译失败: ${error.message}`);
  }
}

function loadDangerRules() {
  const t_rules = loadRawDangerRules();
  // 原始条目也计入运行时预算：无效条目不能诱发无界编译。
  // 不截断规则，否则后置 ask 会丢失而让前置 allow 生效。
  if (t_rules.length > MAX_RULES) {
    const description = `规则表超限（${t_rules.length} > ${MAX_RULES}），为避免遗漏确认规则，整表保守转人工；请清理无效或多余规则`;
    logWrite("WARN", "rule", description);
    return [{ regex: /[\s\S]*/, action: "ask", description, index: 0 }];
  }
  const t_compiled = [];
  t_rules.forEach((t_rule, t_index) => {
    try {
      t_compiled.push({ ...validateDangerRule(t_rule), index: t_index + 1 });
    } catch (t_error) {
      if (t_rule && (typeof t_rule.pattern === "string" && t_rule.pattern.length > MAX_PATTERN_LENGTH ||
          typeof t_rule.description === "string" && t_rule.description.length > MAX_DESCRIPTION_LENGTH)) {
        const description = `规则 #${t_index + 1} 超限：${t_error.message}，保守转人工确认，请修正规则`;
        logWrite("WARN", "rule", description);
        t_compiled.push({ regex: /[\s\S]*/, action: "ask", description, index: t_index + 1 });
      } else {
        logWrite("WARN", "rule", `规则 #${t_index + 1} ${t_error.message}，已跳过`);
      }
    }
  });
  return t_compiled;
}

/**
 * 函数功能: 读取原始规则数组（供命令展示与修改用，不做编译）
 * @returns {Array<{pattern: string, action: string, description: string}>} 原始规则数组
 */
function loadRawDangerRules() {
  const t_rules = readJsonFile(DANGER_RULES_FILE(), null, "rule");
  if (Array.isArray(t_rules)) {
    return t_rules;
  }
  return readJsonFile(DEFAULT_DANGER_RULES_FILE, [], "rule");
}

/**
 * 函数功能: 保存原始规则数组到数据目录
 * @param {Array<object>} rules - 规则数组
 * @returns {boolean} 是否保存成功
 */
function saveDangerRules(rules) {
  return writeFileAtomic(DANGER_RULES_FILE(), JSON.stringify(rules, null, 2) + "\n");
}

/**
 * 函数功能: 加载安全子 agent 系统提示词（数据目录优先，回落出厂默认）
 * @returns {string} 提示词全文
 */
function loadSecurityPrompt() {
  try {
    return fs.readFileSync(SECURITY_PROMPT_FILE(), "utf8");
  } catch {
    try {
      return fs.readFileSync(DEFAULT_SECURITY_PROMPT_FILE, "utf8");
    } catch (t_error) {
      // 提示词彻底缺失时给最小可用兜底，保证审查仍按二值契约输出 JSON
      logWrite("ERROR", "settings", `出厂提示词缺失: ${t_error.message}`);
      return "你是安全审查员。默认放行，只拒绝明显不可逆的破坏性操作。只输出 JSON：{\"decision\":\"allow或deny\",\"risk_level\":\"low/medium/high\",\"analysis\":\"一句话分析\",\"risks\":[\"风险点\"],\"scope\":\"影响范围\",\"alternative\":\"deny 时给出更安全做法，allow 时空字符串\"}";
    }
  }
}

/**
 * 函数功能: 加载快速通道白名单（低风险命令，数据目录优先，回落出厂默认）并编译正则。
 *           命中即 0 LLM 放行；条目非法只跳过自身，不能让整个快速通道瘫痪
 * @returns {Array<{regex: RegExp, description: string}>} 可用白名单条目
 */
function loadFastAllow() {
  let t_entries = readJsonFile(FAST_ALLOW_FILE(), null, "fast");
  if (!Array.isArray(t_entries)) {
    t_entries = readJsonFile(DEFAULT_FAST_ALLOW_FILE, [], "fast");
  }

  if (t_entries.length > MAX_RULES) {
    logWrite("WARN", "fast", `快速通道表超限（上限 ${MAX_RULES}），停用快速通道`);
    return [];
  }
  const t_compiled = [];
  t_entries.forEach((t_entry, t_index) => {
    if (!t_entry || typeof t_entry.pattern !== "string" || !t_entry.pattern.trim()) {
      logWrite("WARN", "fast", `快速通道 #${t_index + 1} 结构非法（缺 pattern），已跳过`);
      return;
    }
    if (t_entry.pattern.length > MAX_PATTERN_LENGTH) {
      logWrite("WARN", "fast", `快速通道 #${t_index + 1} 正则超长（${t_entry.pattern.length} > ${MAX_PATTERN_LENGTH}），已跳过`);
      return;
    }
    try {
      const t_desc = String(t_entry.description || "低风险命令").slice(0, MAX_DESCRIPTION_LENGTH);
      t_compiled.push({ regex: new RegExp(t_entry.pattern, RULE_REGEX_FLAGS), description: t_desc });
    } catch (t_error) {
      logWrite("WARN", "fast", `快速通道 #${t_index + 1} 正则编译失败: ${t_error.message}，已跳过`);
    }
  });
  return t_compiled;
}

/**
 * 函数功能: 读取原始快速通道数组（供命令展示，不做编译）
 * @returns {Array<{pattern: string, description: string}>} 原始数组
 */
function loadRawFastAllow() {
  const t_entries = readJsonFile(FAST_ALLOW_FILE(), null, "fast");
  if (Array.isArray(t_entries)) {
    return t_entries;
  }
  return readJsonFile(DEFAULT_FAST_ALLOW_FILE, [], "fast");
}

export {
  validateDangerRule,
  MAX_RULES,
  MAX_PATTERN_LENGTH,
  MAX_DESCRIPTION_LENGTH,
  loadSettings,
  saveSettings,
  loadDangerRules,
  loadRawDangerRules,
  saveDangerRules,
  loadSecurityPrompt,
  loadFastAllow,
  loadRawFastAllow,
};
