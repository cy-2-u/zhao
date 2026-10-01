/**
 * 模块功能: 安全审查引擎——PreToolUse 决策管线的完整编排
 * 作者: zhao
 * 创建日期: 2026年08月29日
 * 描述: 管线顺序固定"先确定性后概率性"：总开关 → plan/完全访问（yolo）模式边界 →
 *       工具级安全白名单（WebSearch/WebFetch/web-reader 0 审查放行）→ 工具过滤 → 危险规则层
 *       （不经过 LLM）→ 复合命令逐段 → 快速通道（只读单命令 0 LLM 放行）
 *       → 脚本内容附加（可选）→ 缓存层 → 安全子 agent（LLM）→ 模型不可用时 ask（交回人工审批）。
 *       规则层只负责快速放行或向 LLM 提供风险提示，不替代模型做最终拒绝。
 *       0.8.8 模块化：命令词法（shell_lex）、送审文本（tool_text）、快速通道文法
 *       （fast_allow）、脚本附件（script_attach）、缓存（decision_cache）、结论解析
 *       （verdict）、pending 标记（pending_marks）各自成模块，本文件保留管线编排与
 *       规则匹配，并作为兼容门面再导出既有符号（hook 入口与测试的导入路径不变）。
 * 功能:
 *   - reviewToolUse: 主入口，输入 hook JSON，输出 {action, reason, source}（保证不抛异常）；
 *     force_review 供 PermissionRequest 层强制裁决——请求已走到"客户端即将弹原生审批框"，
 *     review_tools 范围外的工具同样送模型，人工弹窗只允许在模型不可用时出现
 *   - 危险规则/复合命令逐段匹配（正则优先级 deny 提示 > allow）
 *   - 全自动二值语义：审批模型只出 allow/deny，模型的 ask（存疑）收敛为 deny + additionalContext
 *     回传主 agent；用户审批唯一来源是模型不可用兜底（fallback）；附件不完整/载荷超限
 *     一律截断或带附注送模型裁决，不转人工
 *   - plan 与完全访问（yolo/bypass-permissions/full-access）是模式级退避：客户端只读规划
 *     或全放行的硬边界，插件自动许可不得越过
 * 依赖: ./common.js ./settings.js ./provider.js ./redaction.js ./decision.js
 *       ./tool_text.js ./shell_lex.js ./fast_allow.js ./script_attach.js ./decision_cache.js ./verdict.js ./pending_marks.js
 * 更新日期: 2026年10月01日
 */

import { LOG_PREVIEW_CHARS, logWrite } from "./common.js";
import { loadSettings, loadDangerRules, loadPolicySnapshot, loadSecurityPrompt } from "./settings.js";
import { resolveProvider, callLlm, ProviderError, LlmError, PROVIDER_REQUEST_BUDGET_MS, markJsonModeCapability, isJsonModeUnsupportedError } from "./provider.js";
import { redactObject, redactSecrets } from "./redaction.js";
import { ACTION_PASS, ACTION_ALLOW, ACTION_ASK, ACTION_DENY } from "./decision.js";
import { isPassthroughMode, normalizeToolName, buildRuleText } from "./tool_text.js";
import { splitTopLevelCommands } from "./shell_lex.js";
import { stripStderrRedirect, unquotedRedirectOrMalformed, userAllowSegmentSafe, matchFastSegment, matchFastAllow } from "./fast_allow.js";
import { collectScriptAttachments, isDynamicExecutionCommand } from "./script_attach.js";
import { stableStringify, buildPolicySalt, computeCacheKey, reviewCacheKey, readCachedDecision, writeCachedDecision, hashAttachments } from "./decision_cache.js";
import { parseVerdict, formatVerdictReason, extractJsonObject, extractJsonObjects } from "./verdict.js";
import { pendingAskKeyForInput, writePendingAskMarker, takePendingAskMarkerState } from "./pending_marks.js";

// 工具级安全白名单：天生只读、无本地写副作用的内建工具——网页搜索/抓取不产生
// 任何本地变更，送审批模型纯属浪费延迟（模型审不出比"只读"更多的信息），命中
// 即 0 LLM 直接放行。真正带风险的"上网"形态（curl 外发数据、POST、带凭据）走
// 的是 Bash 审查，不受此白名单影响
const SAFE_FAST_TOOLS = new Set(["WebSearch", "WebFetch", "mcp__web_reader__webReader"]);

// 规则层的中间态：命中 deny 规则时不产出最终动作，只携带 ruleHint 风险提示
// 随载荷送审——对外动作仍只有 pass/allow/ask/deny
const DECISION_ROUTE = "route";

// 规则扫描与 hook 输入均受资源预算约束；过长文本不执行用户正则，直接带风险提示送审
const MAX_RULE_INPUT_CHARS = 32768;

const PAYLOAD_TRUNCATION_MARKER = "载荷超出字符预算已截断";

/**
 * 函数功能: 对单段文本按数组顺序扫描规则。固定优先级：deny 提示优先于 allow 放行——
 *           用户把宽泛 allow 排在 deny 之前时，风险提示不能被遮蔽（allow 只是捷径，
 *           deny 才承载用户的真实风险意志）
 * @param {string} text - 被匹配文本
 * @param {Array<object>} [rules] - 已编译规则表（缺省现读；复合命令逐段复用同一份，避免每段重复读盘+编译）
 * @returns {object|null} 命中的规则定义（含编译好的 regex/action/description/index）
 */
function scanRules(text, rules = loadDangerRules()) {
  if (!text || String(text).length > MAX_RULE_INPUT_CHARS) {
    return null;
  }
  let t_match = null;
  const priority = { allow: 1, deny: 2 };
  for (const t_rule of rules) {
    if (t_rule.regex.test(text) && (!t_match || priority[t_rule.action] > priority[t_match.action])) t_match = t_rule;
  }
  return t_match;
}

/**
 * 函数功能: 危险规则层——两种动作各司其职：
 *           1) allow 命中单段命令 → 快速放行（低风险白名单）
 *           2) deny 不直接拦截 → 产出 ruleHint 风险提示随载荷送审，由审批模型裁决：
 *              模型 deny 才是真正的拒绝，模型不可用时由上层兜底转人工。
 *           规则层不存在确认门槛：用户审批只在模型不可用或输入无法可靠判定时发生，
 *           不因为"命中某条规则"而直接弹给用户
 * @param {string} rule_text - 被匹配文本（命令全文或目标路径）
 * @param {{rules?: Array<object>, segments?: string[]}} [precomputed] - 同请求内已加载的
 *        编译规则表与顶层分段（省去重复读盘/编译/分割；缺省现算）
 * @returns {object|null} allow 决策或 route 提示（含 ruleHint），未命中返回 null
 */
function matchDangerRules(rule_text, { rules, segments } = {}) {
  if (String(rule_text || "").length > MAX_RULE_INPUT_CHARS) {
    const t_hint = `工具输入超过规则扫描上限（${MAX_RULE_INPUT_CHARS} 字符），无法安全执行用户正则`;
    return { action: DECISION_ROUTE, reason: `[auto-review] ${t_hint}，交给审批模型结合完整命令判断。`, source: "rule", ruleHint: t_hint };
  }
  const t_rule = scanRules(rule_text, rules);
  if (!t_rule) {
    return null;
  }
  const t_desc = redactSecrets(`危险规则 #${t_rule.index}: ${t_rule.description}`);
  if (t_rule.action === ACTION_ALLOW) {
    // allow 只对单段命令快速放行；复合命令交 matchCompoundRules 逐段确认，
    // 防止 "ls; rm ..." 因第一段白名单而跳过审查。
    // 信任边界是用户写的正则本身，结构上只兜底命令替换/文件重定向/环境变量展开，
    // 引号括号等编程文本不再一刀切——否则 node -e "只读脚本" 永远配不了白名单
    const t_segments = segments || splitTopLevelCommands(rule_text);
    if (t_segments.length <= 1 && userAllowSegmentSafe(rule_text)) {
      return {
        action: ACTION_ALLOW,
        reason: `[auto-review] 白名单放行（${t_desc}）`,
        source: "rule",
      };
    }
    return null;
  }
  // deny 规则不再直接拦截：只作为风险提示送审——模型能看到完整命令与参数，
  // 比正则更适合判断"这条命令此刻是否合理"；模型不可用时由上层兜底转人工审批
  return {
    action: DECISION_ROUTE,
    reason: `[auto-review] 风险规则命中（${t_desc}），交给审批模型结合完整命令判断。`,
    source: "rule",
    ruleHint: t_desc,
  };
}

/**
 * 函数功能: 复合命令的逐段规则审查——每段独立匹配：
 *           任一段命中 deny 规则 → 只产出 ruleHint 风险提示（送审，不直接拦截）；
 *           全部段命中 allow 规则 → 整条白名单放行；其余情况返回 null 降级 LLM 审查。
 *           防止 allow 规则（如 ^ls\b）放行 "ls; rm -rf x" 这类以白名单命令开头的复合命令
 * @param {string} rule_text - 命令全文
 * @param {{rules?: Array<object>, segments?: string[]}} [precomputed] - 同请求内已加载的
 *        编译规则表与顶层分段（缺省现算）
 * @returns {object|null} allow 决策或 route 提示（含 ruleHint），需要 LLM 审查时返回 null
 */
function matchCompoundRules(rule_text, { rules, segments } = {}) {
  const t_subs = segments || splitTopLevelCommands(rule_text);
  if (t_subs.length <= 1) {
    return null;
  }
  // 规则表只读一次再逐段匹配：段数多时避免每段重复读盘与正则编译
  const t_rule_list = rules || loadDangerRules();
  const t_hits = t_subs.map((t_sub) => ({ sub: t_sub, rule: scanRules(t_sub, t_rule_list) }));
  const t_short = (t_sub) => redactSecrets(t_sub).replace(/\s+/g, " ").slice(0, 80);
  // deny 段提炼为整体风险提示：段级正则命中的上下文有限，交模型看完整命令裁决
  const t_deny_hit = t_hits.find((t_item) => t_item.rule && t_item.rule.action === ACTION_DENY);
  if (t_deny_hit) {
    const t_hint = redactSecrets(`复合命令的子命令「${t_short(t_deny_hit.sub)}」命中（危险规则 #${t_deny_hit.rule.index}: ${t_deny_hit.rule.description}）`);
    return {
      action: DECISION_ROUTE,
      reason: `[auto-review] ${t_hint}，交给审批模型结合完整命令判断。`,
      ruleHint: t_hint,
    };
  }
  const t_unmatched = t_hits.filter((t_item) => !t_item.rule);
  // 全段 allow 放行：每段都被用户 allow 规则显式覆盖 + 每段过轻量结构门禁
  //（命令替换/文件重定向/环境变量展开不参与放行）。旧的全文一刀切字符门禁
  // 会把 node -e "只读脚本" 这类用户明确信任的形态永远挡在白名单外
  if (t_unmatched.length === 0 && t_subs.every((sub) => userAllowSegmentSafe(sub))) {
    const t_ids = t_hits.map((t_item) => `#${t_item.rule.index}`).join("、");
    return {
      action: ACTION_ALLOW,
      reason: `[auto-review] 白名单放行：${t_hits.length} 段子命令全部命中白名单规则（${t_ids}）。`,
    };
  }
  // 存在未命中白名单的子命令：整体降级 LLM 审查（allow 不能替未覆盖的段作保）
  return null;
}

/**
 * 函数功能: 构造送审载荷（截断保护 + 可选脚本附件块 + 可选 cwd 上下文 + 敏感值脱敏）。
 *           工具输入与脚本内容同属不可信数据，常见的密钥/令牌值替换为占位符后再送审，
 *           保留命令结构供模型判断语义——附件通道不能成为把凭据外送审批渠道的途径
 * @param {string} tool_name - 标准工具名
 * @param {object} tool_input - 工具调用参数
 * @param {number} max_chars - 完整载荷总字符预算（含附件、cwd、规则提示和所有元数据）；超限截断
 * @param {object|null} [attachments] - collectScriptAttachments 的返回值
 * @param {string} [cwd] - hook 输入的工作目录（相对路径命令的语义依赖它，附上供模型结合判断）
 * @param {string} [rule_hint] - 规则层风险提示（作为线索附给模型，不构成最终结论）
 * @returns {string} 审查载荷文本
 */
function buildReviewPayload(tool_name, tool_input, max_chars, attachments, cwd, rule_hint = "") {
  if (!Number.isFinite(max_chars) || max_chars <= 0) throw new Error("无效载荷预算");
  const t_json = JSON.stringify(redactObject(cwd ? { tool_name, tool_input, cwd } : { tool_name, tool_input }));
  let t_payload = `审查以下工具调用，只输出结论 JSON：\n${t_json}`;
  if (rule_hint) {
    t_payload += `\n本地规则仅作为风险提示，不是最终结论：${redactSecrets(rule_hint)}`;
  }
  if (attachments && ((attachments.files && attachments.files.length > 0) || (attachments.notes && attachments.notes.length > 0))) {
    const t_sections = ["", "── 命令引用的脚本文件内容（auto-review 自动读取附上，结论必须结合脚本实际内容）──"];
    for (const [t_index, t_file] of attachments.files.entries()) {
      const t_size_note = t_file.truncated
        ? `已截断至前 ${t_file.content.length} 字符（原文 ${t_file.total_bytes} 字节）`
        : `${t_file.total_bytes} 字节`;
      t_sections.push(`[${t_index + 1}] ${redactSecrets(t_file.path)}（${t_size_note}）`);
      t_sections.push("```");
      t_sections.push(redactSecrets(t_file.content));
      t_sections.push("```");
    }
    for (const t_note of attachments.notes) {
      t_sections.push(`(附注) ${redactSecrets(t_note)}`);
    }
    t_payload += "\n" + t_sections.join("\n");
  }
  t_payload = redactSecrets(t_payload);
  // 超预算不转人工（全自动语义下人工只与模型可用性挂钩）：截断保留前缀并显式
  // 标注，模型知道内容不完整，按提示词契约无法判断时收敛到 deny（保守侧）
  if (t_payload.length > max_chars) {
    const t_marker = "\n(载荷超出字符预算已截断，以上仅为前缀；无法据此判断安全性时必须 deny)";
    t_payload = t_payload.slice(0, Math.max(1, max_chars - t_marker.length)) + t_marker;
  }
  return t_payload;
}

/**
 * 函数功能: 执行安全子 agent 审查（专用渠道解析 → LLM 调用 → 结论解析 → 缓存）。
 *           review_provider.json 是唯一 LLM 来源，任何失败直接上抛由总兜底转人工审批
 * @param {string} tool_name - 标准工具名
 * @param {object} tool_input - 工具调用参数
 * @param {object} settings - 运行时配置（timeout_ms、cache_ttl_seconds、max_payload_chars 等）
 * @param {object|null} [attachments] - 脚本附件（参与载荷与缓存键）
 * @param {string} [cwd] - 工作目录（参与载荷与缓存键，跨项目结论不串用）
 * @param {string} [rule_hint] - 规则层提炼的风险提示（随载荷送审，不参与最终裁决）
 * @param {string} cache_key - 调用方算好的缓存键（查/写缓存共用，避免策略盐重复计算）
 * @param {boolean} [cacheable] - 是否允许写缓存（动态执行/不完整附件为 false）
 * @param {string} [prompt] - 同请求内已读取的提示词（缺省现读）
 * @returns {Promise<{action: string, reason: string}>} 决策对象
 * @throws {ProviderError|LlmError} 渠道未配置、调用失败或输出不可解析
 */
async function runLlmReview(tool_name, tool_input, settings, attachments, cwd, rule_hint, cache_key, cacheable = true, prompt) {
  const t_prompt = typeof prompt === "string" ? prompt : loadSecurityPrompt();
  const t_payload = buildReviewPayload(tool_name, tool_input, settings.max_payload_chars, attachments, cwd, rule_hint);
  const t_script_note = attachments && attachments.files.length > 0 ? ` scripts=${attachments.files.length}` : "";

  // 专用审批渠道是唯一 LLM 来源：未配置/不可达不回落任何其他渠道，
  // 错误上抛由总兜底转人工审批——模型不在场时绝不自动许可。
  const t_provider = resolveProvider(settings);
  const t_deadline_at = Date.now() + PROVIDER_REQUEST_BUDGET_MS;
  const t_start_ms = Date.now();
  let t_active_provider = t_provider;
  let t_raw;
  try {
    t_raw = await callLlm(t_active_provider, t_prompt, t_payload, { deadlineAt: t_deadline_at });
  } catch (t_call_error) {
    // 只有错误明确表示 response_format/json_object 不支持时才回落；普通 400、
    // 认证失败、模型不存在等错误必须原样上抛，避免把真正的配置故障伪装成能力探测。
    if (t_provider.json_mode && t_provider.json_mode !== "off" && isJsonModeUnsupportedError(t_call_error)) {
      if (t_provider.json_mode === "auto") markJsonModeCapability(t_provider, "unsupported");
      t_active_provider = { ...t_provider, json_mode: "off" };
      logWrite("WARN", "provider", `渠道不接受 response_format json_object（HTTP ${t_call_error.http_status}），已在本次 deadline 内回落明文请求${t_provider.json_mode === "auto" ? "，后续不再尝试" : ""}`);
      t_raw = await callLlm(t_active_provider, t_prompt, t_payload, { deadlineAt: t_deadline_at });
    } else {
      throw t_call_error;
    }
  }
  let t_verdict;
  try {
    t_verdict = parseVerdict(t_raw);
  } catch (t_parse_error) {
    // 结论解析失败不等于渠道故障：仅在同一个绝对 deadline 尚有余量时原样重问一次。
    // 已确认 JSON mode 不支持后，解析重问保持明文，不能把 response_format 带回来。
    if (Date.now() + 2000 >= t_deadline_at) throw t_parse_error;
    logWrite("WARN", "llm", `结论解析失败（${String(t_parse_error.message).slice(0, 100)}），在总 deadline 内重问一次`);
    t_raw = await callLlm({ ...t_active_provider, retries: 0 }, t_prompt, t_payload, { deadlineAt: t_deadline_at });
    t_verdict = parseVerdict(t_raw);
  }
  const t_duration_s = ((Date.now() - t_start_ms) / 1000).toFixed(1);

  // 载荷被截断意味着模型没有看到完整审查对象。即使模型给出 allow，也不能把
  // 不完整事实当作安全证明；收敛为 deny，避免截断前缀意外形成自动授权。
  if (t_payload.includes(PAYLOAD_TRUNCATION_MARKER) && t_verdict.decision === ACTION_ALLOW) {
    t_verdict.decision = ACTION_DENY;
    t_verdict.risk_level = t_verdict.risk_level === "low" ? "medium" : t_verdict.risk_level;
    t_verdict.risks = ["审查载荷已截断，未覆盖完整工具输入"];
    t_verdict.alternative = "缩小工具输入或提高 max_payload_chars 后重新审查";
    t_verdict.analysis = "审查载荷不完整，不能据此自动放行";
  }

  // 自动二值收敛：模型输出 ask（存疑）按 deny 处理并回传分析——审批契约只允许
  // allow/deny，存疑本身不是安全证明，收敛到保守侧由主 agent 按分析改写后重试
  if (t_verdict.decision === ACTION_ASK) {
    t_verdict.decision = ACTION_DENY;
    t_verdict.risks = t_verdict.risks.length > 0 ? t_verdict.risks : ["模型对该操作存疑"];
    t_verdict.alternative = t_verdict.alternative || "请拆分命令、缩小影响范围或改用只读等价做法后重试";
  }

  let t_reason;
  if (t_verdict.decision === ACTION_ALLOW) {
    t_reason = `[auto-review] 安全审查通过（${t_verdict.risk_level}风险，${t_duration_s}s）: ${redactSecrets(t_verdict.analysis).slice(0, 240)}`;
  } else {
    t_reason = formatVerdictReason(t_verdict);
  }
  logWrite("INFO", "llm", `${t_verdict.decision} risk=${t_verdict.risk_level} ${t_duration_s}s${t_script_note}（专用审批渠道）`);
  // 动态执行、解释器、shell wrapper、cd 语义或不完整附件都不具备稳定的
  // 可复用授权证明；这类请求只允许本次送审，不读也不写普通决策缓存。
  if (cacheable) {
    writeCachedDecision(cache_key, { action: t_verdict.decision, reason: t_reason }, settings.cache_ttl_seconds);
  }
  const t_extra = t_verdict.decision !== ACTION_ALLOW ? { additionalContext: t_reason } : {};
  return { action: t_verdict.decision, reason: t_reason, ...t_extra };
}

/**
 * 函数功能: 决策管线主入口（对两层 hook 暴露的唯一函数，保证不抛异常）
 * @param {object} hook_input - hook stdin 的 JSON（tool_name/tool_input，字段防御式读取）
 * @param {{force_review?: boolean}} [options] - force_review: PermissionRequest 层强制裁决，
 *        跳过 review_tools 过滤（请求已到弹窗前一步，范围外工具同样送模型，不退回人工）
 * @returns {Promise<{action: string, reason: string, source: string}>} 决策对象
 */
async function reviewToolUse(hook_input, { force_review = false } = {}) {
  try {
    const t_settings = loadSettings();
    if (!t_settings.enabled) {
      return { action: ACTION_PASS, reason: "", source: "off" };
    }

    // 防御式读取：tool_name 与 toolName 双兼容。第一层 matcher 限 Bash/Write/Edit/
    // ApplyPatch 与网页只读工具，第二层不设 matcher 全量接管；正常输入必有工具名，
    // 缺失属协议异常——无法确认审查对象时阻断，不放行未知调用
    const t_tool_name = normalizeToolName(hook_input && (hook_input.tool_name || hook_input.toolName));
    if (!t_tool_name) {
      logWrite("WARN", "review", "hook 输入缺少工具名，无法确认审查对象，阻断");
      return {
        action: ACTION_DENY,
        reason: "[auto-review] hook 输入缺少工具名，无法确认审查对象，已阻断。如频繁出现请检查客户端版本或暂时禁用本插件。",
        source: "malformed",
      };
    }
    // 权限模式闸门：plan（只读规划硬边界）与 yolo/完全访问（客户端原生全放行，
    // 接管只是徒增延迟）退避交回客户端流程；其余模式（default/edit 及字段缺失）
    // 一律接管，人工弹窗只允许在模型不可用时出现
    if (isPassthroughMode(hook_input)) {
      logWrite("INFO", "mode", "plan/完全访问模式退避，交回客户端原生流程");
      return { action: ACTION_PASS, reason: "", source: "mode" };
    }

    // 工具级安全放行：搜索/抓取类只读工具 0 审查直通（两层 hook 同样生效，
    // force_review 也不越过——白名单在名单过滤与模型之前）
    if (SAFE_FAST_TOOLS.has(t_tool_name)) {
      logWrite("INFO", "safe", `allow ${t_tool_name}: 只读工具直通`);
      return {
        action: ACTION_ALLOW,
        reason: `[auto-review] 只读工具直接放行（${t_tool_name} 不产生本地变更，无需审查）`,
        source: "safeTool",
      };
    }

    // 工具过滤：PreToolUse 层只审 review_tools 名单；PermissionRequest 层
    // force_review 跳过名单——请求已走到"客户端即将弹原生审批框"，名单外工具
    // （如默认配置下的 Write/Edit）同样送模型裁决，把最后一处人工弹窗收编
    if (!force_review && !t_settings.review_tools.includes(t_tool_name)) {
      return { action: ACTION_PASS, reason: "", source: "skip" };
    }

    // 请求级策略快照：设置/规则/白名单/提示词各只读一次，贯穿规则层、快速通道、
    // 缓存盐与送审载荷（0.8.8 前 same request 内最多重复读盘 10+ 次）
    const t_snapshot = loadPolicySnapshot(t_settings);

    const t_tool_input = hook_input && hook_input.tool_input && typeof hook_input.tool_input === "object"
      ? hook_input.tool_input
      : {};
    const t_cwd = String((hook_input && hook_input.cwd) || "").trim() || process.cwd();
    const { ruleText: t_rule_text, preview: t_preview } = buildRuleText(t_tool_name, t_tool_input);
    const t_short = redactSecrets(t_preview).replace(/\s+/g, " ").slice(0, LOG_PREVIEW_CHARS);
    const t_segments = splitTopLevelCommands(t_rule_text);
    const t_rule_deps = { rules: t_snapshot.rulesCompiled, segments: t_segments };

    // ③ 规则层：allow 单段命令快速放行（最终决策）；deny 不直接拦截——
    //     提炼 ruleHint 风险提示随载荷送审，由审批模型裁决（旧的 ask 确认门槛
    //     已并入 deny 送审，规则层不再产生直接转人工的决策）
    let t_rule_hint = "";
    const t_rule_decision = matchDangerRules(t_rule_text, t_rule_deps);
    if (t_rule_decision && t_rule_decision.action !== DECISION_ROUTE) {
      logWrite("INFO", "rule", `${t_rule_decision.action} ${t_tool_name}: ${t_short} (${t_rule_decision.reason.split("\n")[0]})`);
      return t_rule_decision;
    }
    if (t_rule_decision && t_rule_decision.ruleHint) {
      t_rule_hint = t_rule_decision.ruleHint;
      logWrite("INFO", "rule", `hint ${t_tool_name}: ${t_short} (${t_rule_hint})`);
    }
    // ③' 复合命令逐段：全 allow 整条放行；deny 段并入送审提示
    if (t_tool_name === "Bash") {
      const t_compound_decision = matchCompoundRules(t_rule_text, t_rule_deps);
      if (t_compound_decision && t_compound_decision.action !== DECISION_ROUTE
          && !(t_rule_hint && t_compound_decision.action === ACTION_ALLOW)) {
        logWrite("INFO", "rule", `${t_compound_decision.action} ${t_tool_name}: ${t_short} (复合命令逐段: ${t_compound_decision.reason.split("\n")[0]})`);
        return { ...t_compound_decision, source: "rule" };
      }
      if (t_compound_decision && t_compound_decision.ruleHint) {
        t_rule_hint = t_rule_hint ? `${t_rule_hint}；${t_compound_decision.ruleHint}` : t_compound_decision.ruleHint;
        logWrite("INFO", "rule", `hint ${t_tool_name}: ${t_short} (${t_compound_decision.ruleHint})`);
      }
    }
    if (!t_rule_text) {
      // 送审文本为空说明输入形态异常：与缺工具名同属协议异常，统一 fail-closed 阻断，
      // 不再交回内置流程——"无法确认审查对象"不能因为字段齐全度不同而有两种结局
      logWrite("WARN", "review", "无法解析工具输入（空命令/无路径/未识别工具），阻断");
      return {
        action: ACTION_DENY,
        reason: "[auto-review] 无法从工具输入中解析出审查对象（空命令或缺少路径），已阻断。如频繁出现请检查客户端版本或暂时禁用本插件。",
        source: "malformed",
      };
    }

    // ③'' 快速通道：只读单命令命中白名单即静默放行（0 LLM、0 等待）。
    //     带风险提示（deny 规则命中）的命令不走捷径——必须让模型看过再放行
    if (t_tool_name === "Bash" && !t_rule_hint) {
      const t_fast_decision = matchFastAllow(t_rule_text, t_settings, { segments: t_segments, fast_rules: t_snapshot.fastCompiled });
      if (t_fast_decision) {
        logWrite("INFO", "fast", `allow ${t_tool_name}: ${t_short}`);
        return t_fast_decision;
      }
    }

    // ③.5 脚本内容附加：读取命令引用的脚本文件随载荷送审（相对路径按 hook 输入的 cwd 解析）。
    //     放在缓存之前：附件摘要参与缓存键，脚本内容变化后旧结论自动失效
    let t_attachments = null;
    if (t_tool_name === "Bash" && t_settings.inspect_scripts) {
      t_attachments = collectScriptAttachments(t_rule_text, t_cwd, t_settings);
    }

    // 完整附件、不确定附件和动态执行形态都不能复用普通决策缓存。
    // 解释器、shell wrapper、cd、npm run 等命令的实际效果依赖运行时状态，
    // 即使文本相同也不能把上一次的 allow 当作稳定授权证明。
    const t_command_cacheable = t_tool_name !== "Bash"
      || !isDynamicExecutionCommand(t_rule_text);
    const t_attachment_cacheable = !t_attachments || t_attachments.cacheable !== false;
    const t_cacheable = t_command_cacheable && t_attachment_cacheable;

    // ④ 缓存层：只有静态、完整且可复用的请求才读缓存；动态请求仍可使用键做
    // 诊断关联，但不把模型结论持久化为后续自动放行依据。
    const t_cache_key = reviewCacheKey(t_tool_name, t_tool_input, t_cwd, t_attachments, t_settings, buildPolicySalt(t_settings, t_snapshot));
    const t_cached = t_cacheable
      ? readCachedDecision(t_cache_key, t_settings.cache_ttl_seconds)
      : null;
    if (t_cached) {
      logWrite("INFO", "cache", `${t_cached.action} ${t_tool_name}: ${t_short}`);
      // deny/ask 结论同样双发 additionalContext（兼容不含该字段的旧缓存条目），
      // 保证缓存命中的拒绝也把分析+替代方案送回主模型，闭环不因缓存而断
      const t_extra = t_cached.action !== ACTION_ALLOW ? { additionalContext: t_cached.reason } : {};
      return { ...t_cached, source: "cache", ...t_extra };
    }

    // ⑤ 安全子 agent（LLM）审查（缓存键复用上方已算好的 t_cache_key，不重复计算策略盐）
    const t_llm_decision = await runLlmReview(
      t_tool_name,
      t_tool_input,
      t_settings,
      t_attachments,
      t_cwd,
      t_rule_hint,
      t_cache_key,
      t_cacheable,
      t_snapshot.prompt,
    );
    return { ...t_llm_decision, source: "llm" };
  } catch (t_error) {
    // ⑥ 总兜底：审批模型不可用时不猜测、不自动放行，转客户端人工审批。
    // 规则命中本身不会触发人工；只有模型链路失败才进入这里。
    const t_cause = redactSecrets((t_error instanceof ProviderError || t_error instanceof LlmError)
      ? t_error.message
      : (t_error && t_error.message ? t_error.message : "未知错误")).slice(0, 240);
    logWrite("WARN", "fallback", `审查不可用: ${t_cause}`);
    const t_reason = `[auto-review] 审批模型不可用（${t_cause}），未自动批准该操作，已转人工审批。`;
    return {
      action: ACTION_ASK,
      reason: t_reason,
      source: "fallback",
      additionalContext: `${t_reason}\n请由用户确认后再执行；模型恢复后该命令将重新进入自动审查。`,
    };
  }
}

export {
  reviewToolUse,
  isPassthroughMode,
  normalizeToolName,
  buildRuleText,
  matchDangerRules,
  matchCompoundRules,
  matchFastAllow,
  matchFastSegment,
  stripStderrRedirect,
  userAllowSegmentSafe,
  unquotedRedirectOrMalformed,
  splitTopLevelCommands,
  collectScriptAttachments,
  isDynamicExecutionCommand,
  hashAttachments,
  stableStringify,
  buildPolicySalt,
  computeCacheKey,
  reviewCacheKey,
  readCachedDecision,
  writeCachedDecision,
  pendingAskKeyForInput,
  writePendingAskMarker,
  takePendingAskMarkerState,
  extractJsonObject,
  extractJsonObjects,
  parseVerdict,
  formatVerdictReason,
  buildReviewPayload,
  redactSecrets,
};
