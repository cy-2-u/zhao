/**
 * 模块功能: 运行时配置的加载与保存——settings / 危险规则 / 安全提示词
 * 作者: zhao
 * 创建日期: 2026年08月29日
 * 描述: 数据目录文件优先，缺失或损坏时回落插件包内出厂默认；
 *       所有写入走原子写；规则对象在加载时即编译正则，非法规则跳过并告警
 * 功能:
 *   - loadSettings/saveSettings: 运行时配置（开关、审查工具、脚本送审等）
 *   - loadDangerRules: 危险规则表（含正则编译与容错）
 *   - loadFastAllow/loadRawFastAllow: 快速通道白名单（低风险命令 0 LLM 放行，含正则编译）
 *   - loadSecurityPrompt: 安全子 agent 系统提示词
 *   - loadPolicySnapshot: 一次请求内把设置/规则/白名单/提示词各读一次的快照
 * 依赖: ./common.js
 * 更新日期: 2026年10月01日
 */

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
  readTextFileBounded,
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

// 审批渠道瞬时故障（超时/5xx/429）的额外重试次数：0=只试一次。配置上限仍为 3，
// provider.js 会按 120s hook 总预算动态收紧实际尝试次数并保留收尾余量
const PROVIDER_RETRIES_MIN = 0;
const PROVIDER_RETRIES_MAX = 3;

// 规则表规模上限：防止超大/超长配置（误粘贴、生成器产物）拖垮每次 hook 的
// 正则编译与匹配，同时限制病态正则的回溯成本
const MAX_RULES = 200;
const MAX_PATTERN_LENGTH = 500;
const MAX_DESCRIPTION_LENGTH = 200;
const MAX_PROMPT_BYTES = 256 * 1024;

function hasUnsafeRegexStructure(pattern) {
  const t_source = String(pattern || "");
  // User rules run in the hook process. Reject features whose runtime cost or
  // matching semantics cannot be bounded without a worker sandbox.
  if (/\\[1-9]/.test(t_source) || /\(\?[=!<]/.test(t_source)) return true;
  // Reject quantified groups that contain another quantifier, including bounded
  // outer quantifiers such as (a+){2}; V8 can still revisit the inner branch.
  if (/\((?:\\.|[^()\\])*[+*](?:\\.|[^()\\])*\)\s*(?:[+*]|\{\d+(?:,\d*)?\})/.test(t_source)) return true;
  // Alternation with overlapping quantified prefixes is another common
  // backtracking shape; it is not needed by the built-in policy grammar.
  if (/\((?:[^()|\\]|\\.)*\|(?:[^()|\\]|\\.)*\)\s*[+*]/.test(t_source)) return true;
  return false;
}

// 合法动作集合：deny=风险提示送审，allow=白名单候选。旧配置中的 ask 条目与未知动作
// 统一归一为 deny——规则层不再产生直接转人工的确认门槛，用户审批只在模型不可用或
// 输入无法可靠判定时由兜底层触发
const VALID_RULE_ACTIONS = new Set(["deny", "allow"]);

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

  // 数值字段钳制到合法区间。使用 finite 判断而不是 ||，让显式 0 的语义保持一致：
  // timeout/payload/script 归到最小值，cache TTL/retries 的 0 继续分别表示禁用/不重试。
  const t_number = (value, fallback, min, max) => {
    const t_num = Number(value);
    if (!Number.isFinite(t_num)) return fallback;
    return Math.min(max, Math.max(min, Math.round(t_num)));
  };
  t_merged.timeout_ms = t_number(t_merged.timeout_ms, TIMEOUT_MS_MAX, TIMEOUT_MS_MIN, TIMEOUT_MS_MAX);
  t_merged.cache_ttl_seconds = t_number(t_merged.cache_ttl_seconds, 0, 0, CACHE_TTL_MAX_SECONDS);
  t_merged.max_payload_chars = t_number(t_merged.max_payload_chars, 8000, 500, MAX_PAYLOAD_MAX_CHARS);
  t_merged.script_max_bytes = t_number(t_merged.script_max_bytes, 16000, SCRIPT_BYTES_MIN, SCRIPT_BYTES_MAX);
  t_merged.provider_retries = t_number(t_merged.provider_retries, 2, PROVIDER_RETRIES_MIN, PROVIDER_RETRIES_MAX);
  // json 输出模式枚举校验：非法值回落 auto 并告警（类型校验已在上方合并时完成）
  if (!["auto", "on", "off"].includes(t_merged.provider_json_mode)) {
    logWrite("WARN", "settings", `provider_json_mode 非法（${String(t_merged.provider_json_mode)}），回落 auto`);
    t_merged.provider_json_mode = "auto";
  }
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
 * 函数功能: 校验并编译单条危险规则——结构/长度检查、正则编译、非法 action 归一为 deny
 *           （strictAction=true 时非法 action 直接报错，供 rules add 入口强校验）
 * @param {object} rule - 原始规则 {pattern, action, description}
 * @param {{strictAction?: boolean}} [options] - 是否要求 action 必须是 deny/allow
 * @returns {{regex: RegExp, action: string, description: string}} 编译后的规则
 * @throws {Error} 结构非法、正则空/超长/编译失败，strictAction 下 action 非法
 */
function validateDangerRule(rule, { strictAction = false } = {}) {
  if (!rule || typeof rule !== "object" || Array.isArray(rule) ||
      typeof rule.pattern !== "string" || typeof rule.description !== "string") {
    throw new Error("规则结构非法（缺 pattern/description）");
  }
  if (!rule.pattern.trim()) throw new Error("正则不能为空");
  if (rule.pattern.length > MAX_PATTERN_LENGTH) throw new Error(`正则超长（上限 ${MAX_PATTERN_LENGTH}）`);
  if (rule.description.length > MAX_DESCRIPTION_LENGTH) throw new Error(`描述超长（上限 ${MAX_DESCRIPTION_LENGTH}）`);
  if (hasUnsafeRegexStructure(rule.pattern)) throw new Error("正则包含未允许的回溯/动态结构（不支持反向引用、lookaround 或嵌套量词）");
  if (strictAction && !VALID_RULE_ACTIONS.has(rule.action)) throw new Error("action 只能是 deny/allow");
  try {
    return { regex: new RegExp(rule.pattern, RULE_REGEX_FLAGS),
      action: VALID_RULE_ACTIONS.has(rule.action) ? rule.action : "deny", description: rule.description };
  } catch (error) {
    throw new Error(`正则编译失败: ${error.message}`);
  }
}

/**
 * 函数功能: 编译危险规则表（超限时整表降级为单条兜底 deny 提示，非法条目转为
 *           deny 哨兵保留并告警）——供 loadDangerRules 与 loadPolicySnapshot 复用
 * @param {Array<{pattern: string, action: string, description: string}>} rules - 原始规则数组
 * @returns {Array<{regex: RegExp, action: string, description: string, index: number}>}
 *          可用规则列表，index 为用户在命令中看到的序号（含哨兵保留的非法规则）
 */
function compileDangerRules(rules) {
  // 原始条目也计入运行时预算：无效条目不能诱发无界编译。
  // 不截断规则，否则后置 ask 会丢失而让前置 allow 生效。
  if (rules.length > MAX_RULES) {
    const description = `规则表超限（${rules.length} > ${MAX_RULES}），整表按风险提示送审（模型不可用时转人工）；请清理无效或多余规则`;
    logWrite("WARN", "rule", description);
    return [{ regex: /[\s\S]*/, action: "deny", description, index: 0 }];
  }
  const t_compiled = [];
  rules.forEach((t_rule, t_index) => {
    try {
      t_compiled.push({ ...validateDangerRule(t_rule), index: t_index + 1 });
    } catch (t_error) {
      const description = `规则 #${t_index + 1} 无法安全编译，按风险提示送审，请修正规则`;
      logWrite("WARN", "rule", `规则 #${t_index + 1} ${t_error.message}，以风险提示哨兵保留`);
      t_compiled.push({ regex: /[\s\S]*/, action: "deny", description, index: t_index + 1 });
    }
  });
  return t_compiled;
}

/**
 * 函数功能: 加载危险规则并编译正则
 * @returns {Array<{regex: RegExp, action: string, description: string, index: number}>} 可用规则列表
 */
function loadDangerRules() {
  return compileDangerRules(loadRawDangerRules());
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
  const t_read = (file_path) => readTextFileBounded(file_path, MAX_PROMPT_BYTES);
  try {
    return t_read(SECURITY_PROMPT_FILE());
  } catch {
    try {
      return t_read(DEFAULT_SECURITY_PROMPT_FILE);
    } catch (t_error) {
      // 提示词彻底缺失时给最小可用兜底，保证审查仍按二值契约输出 JSON
      logWrite("ERROR", "settings", `出厂提示词缺失: ${t_error.message}`);
      return "你是安全审查员。只在能够确认操作低风险且范围明确时输出 allow；无法确认、输入不完整或存在潜在不可逆影响时输出 deny。只输出 JSON：{\"decision\":\"allow或deny\",\"risk_level\":\"low/medium/high\",\"analysis\":\"一句话分析\",\"risks\":[\"风险点\"],\"scope\":\"影响范围\",\"alternative\":\"deny 时给出可执行的更安全做法，allow 时为空字符串\"}";
    }
  }
}

/**
 * 函数功能: 编译快速通道白名单条目（非法条目只跳过自身，不能让整个快速通道瘫痪）
 * @param {Array<{pattern: string, description: string}>} entries - 原始条目数组
 * @param {boolean} is_custom - 是否用户自定义（自定义条目执行危险结构检查，出厂规则受信）
 * @returns {Array<{regex: RegExp, description: string}>} 可用白名单条目
 */
function compileFastRules(entries, is_custom) {
  if (entries.length > MAX_RULES) {
    logWrite("WARN", "fast", `快速通道表超限（上限 ${MAX_RULES}），停用快速通道`);
    return [];
  }
  const t_compiled = [];
  entries.forEach((t_entry, t_index) => {
    if (!t_entry || typeof t_entry.pattern !== "string" || !t_entry.pattern.trim()) {
      logWrite("WARN", "fast", `快速通道 #${t_index + 1} 结构非法（缺 pattern），已跳过`);
      return;
    }
    if (t_entry.pattern.length > MAX_PATTERN_LENGTH) {
      logWrite("WARN", "fast", `快速通道 #${t_index + 1} 正则超长（${t_entry.pattern.length} > ${MAX_PATTERN_LENGTH}），已停用`);
      return;
    }
    if (is_custom && hasUnsafeRegexStructure(t_entry.pattern)) {
      logWrite("WARN", "fast", `快速通道 #${t_index + 1} 含未允许的回溯/动态结构，已停用`);
      return;
    }
    try {
      const t_desc = String(t_entry.description || "低风险命令").slice(0, MAX_DESCRIPTION_LENGTH);
      t_compiled.push({ regex: new RegExp(t_entry.pattern, RULE_REGEX_FLAGS), description: t_desc });
    } catch (t_error) {
      logWrite("WARN", "fast", `快速通道 #${t_index + 1} 正则编译失败: ${t_error.message}，已停用`);
    }
  });
  return t_compiled;
}

/**
 * 函数功能: 加载快速通道白名单（低风险命令，数据目录优先，回落出厂默认）并编译正则。
 *           命中即 0 LLM 放行
 * @returns {Array<{regex: RegExp, description: string}>} 可用白名单条目
 */
function loadFastAllow() {
  const t_loaded = readJsonFile(FAST_ALLOW_FILE(), null, "fast");
  const t_custom = Array.isArray(t_loaded);
  const t_entries = t_custom ? t_loaded : readJsonFile(DEFAULT_FAST_ALLOW_FILE, [], "fast");
  return compileFastRules(t_entries, t_custom);
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

/**
 * 函数功能: 一次请求内把策略内容各读一次的快照——设置、危险规则（原始+编译）、
 *           快速通道（原始+编译）、提示词。决策管线用同一份快照贯穿规则层、
 *           快速通道、缓存盐与送审载荷，消除同请求内 8 次以上的重复读盘与
 *           全表正则重编译
 * @param {object} [settings] - 运行时配置（缺省现读）
 * @returns {{settings: object, rulesRaw: Array, rulesCompiled: Array, fastRaw: Array, fastCompiled: Array, prompt: string}}
 */
function loadPolicySnapshot(settings = loadSettings()) {
  const t_rules_raw = loadRawDangerRules();
  const t_loaded_fast = readJsonFile(FAST_ALLOW_FILE(), null, "fast");
  const t_custom = Array.isArray(t_loaded_fast);
  const t_fast_raw = t_custom ? t_loaded_fast : readJsonFile(DEFAULT_FAST_ALLOW_FILE, [], "fast");
  return {
    settings,
    rulesRaw: t_rules_raw,
    rulesCompiled: compileDangerRules(t_rules_raw),
    fastRaw: t_fast_raw,
    fastCompiled: compileFastRules(t_fast_raw, t_custom),
    prompt: loadSecurityPrompt(),
  };
}

export {
  validateDangerRule,
  MAX_RULES,
  MAX_PROMPT_BYTES,
  loadSettings,
  saveSettings,
  loadDangerRules,
  loadRawDangerRules,
  saveDangerRules,
  loadSecurityPrompt,
  loadFastAllow,
  loadRawFastAllow,
  loadPolicySnapshot,
};
