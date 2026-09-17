/**
 * 模块功能: 安全审查引擎——PreToolUse 决策管线的完整编排
 * 作者: hh-zyb
 * 创建日期: 2026年08月29日
 * 描述: 管线顺序固定"先确定性后概率性"：总开关 → 工具过滤 → 非自动模式探测 → 危险规则层
 *       （不经过 LLM）→ 复合命令逐段 → 快速通道（只读单命令 0 LLM 放行）
 *       → 脚本内容附加（可选）→ 缓存层 → 安全子 agent（LLM）→ 模型不可用时 ask（交回人工审批）。
 *       规则层只负责快速放行或向 LLM 提供风险提示，不替代模型做最终拒绝。
 * 功能:
 *   - reviewToolUse: 主入口，输入 hook JSON，输出 {action, reason, source}（保证不抛异常）
 *   - 危险规则/复合命令逐段/快速通道/缓存读写、LLM 载荷构造、结论解析与 reason 拼装
 *   - 自动二值语义：审批模型只出 allow/deny，模型的 ask（存疑）收敛为 deny + additionalContext
 *     回传主 agent；规则的 deny 不再直接拦截（只作 ruleHint 风险提示送审，模型 deny 才是
 *     真正的拒绝），ask 是用户显式确认门槛（如关机），恒转用户裁决；模型不可用时转人工
 *   - 脚本内容附加：提取 Bash 命令引用的脚本文件并读取内容随载荷送审（inspect_scripts）
 * 依赖: node:crypto node:fs node:os node:path ./common.js ./settings.js ./provider.js
 * 更新日期: 2026年09月16日
 */

import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { CACHE_FILE, logWrite, readJsonFile, writeFileAtomic, withFileLock } from "./common.js";
import { loadSettings, loadDangerRules, loadRawDangerRules, loadRawFastAllow, loadSecurityPrompt, loadFastAllow } from "./settings.js";
import { resolveProvider, callLlm, ProviderError, LlmError } from "./provider.js";
import { ACTION_PASS, ACTION_ALLOW, ACTION_ASK, ACTION_DENY } from "./decision.js";

// matcher 别名在内部过滤时归一到标准工具名（ApplyPatch 即 Write/Edit 的别名）
const TOOL_ALIASES = { ApplyPatch: "Write" };

// 规则层的中间态：命中 deny 规则时不产出最终动作，只携带 ruleHint 风险提示
// 随载荷送审——对外动作仍只有 pass/allow/ask/deny
const DECISION_ROUTE = "route";

// 缓存的策略盐版本：决策语义或管线结构变化时递增，旧条目自然全部失效
const POLICY_SALT_VERSION = "v3";

// 缓存条目上限：超限时丢弃过期项后按过期时间保留最新的一批，防止缓存文件无限增长
const MAX_CACHE_ENTRIES = 500;

// 日志中命令预览长度，避免单行日志过长
const LOG_PREVIEW_CHARS = 120;

// 脚本送审的单次命令最多附加文件数：控制载荷规模，超出部分以附注说明
const MAX_SCRIPT_FILES = 3;

// 视为"脚本文件"的扩展名集合：解释器调用与裸路径执行都要求命中，防止误读普通数据文件
const SCRIPT_EXTENSIONS = new Set(["sh", "bash", "py", "pyw", "js", "mjs", "cjs", "ts", "rb", "pl", "ps1", "bat", "cmd"]);

// 命中即放弃该命令段的脚本提取：-c/-e 的代码已内联在命令文本里，-m 引用的是模块而非文件路径
const SCRIPT_INLINE_FLAGS = new Set(["-c", "-e", "-m", "--command", "--eval", "--module"]);

// 可带脚本文件参数的解释器名单（powershell 走 -File 特判，cmd 走 /c、/k 特判）
const SCRIPT_INTERPRETERS = new Set(["python", "python3", "py", "node", "deno", "bun", "bash", "sh", "zsh", "dash", "ruby", "perl", "pwsh"]);

// 快速通道的结构化拦截：包装器/动态执行形态全拦——真实命令藏在参数里，
// 白名单正则按首词匹配会放行任意内层命令
const FAST_WRAPPER_HEADS = new Set([
  "cmd", "powershell", "pwsh", "start", "start-process", "invoke-expression", "iex", "call",
  "invoke-command", "bash", "sh", "zsh", "dash", "wscript", "cscript", "mshta", "rundll32", "regsvr32",
]);

// 脚本解释器：真实命令同样在参数里，只放行纯版本查询（无代码/脚本/任意参数）
const FAST_INTERPRETER_HEADS = new Set(["python", "python3", "py", "node", "deno", "bun", "ruby", "perl"]);
const FAST_VERSION_ARGS = new Set(["-v", "-V", "--version", "version"]);

// 敏感文件名/扩展名：脚本附件不得读取凭据类文件（防止把 .env、私钥随载荷外送审批渠道）
const SENSITIVE_FILE_PATTERN = /(^|[/\\])(\.env|\.npmrc|\.netrc|\.pypirc|\.aws|\.ssh|\.gnupg|id_rsa|id_ed25519|id_ecdsa)(\.|[/\\]|$)|\.(pem|key|pfx|p12|crt|keystore)([/\\]|$)/i;

/**
 * 函数功能: 归一化工具名（处理 matcher 别名）
 * @param {string} tool_name - hook 输入中的工具名
 * @returns {string} 标准工具名，无法识别返回空串
 */
function normalizeToolName(tool_name) {
  const t_name = String(tool_name || "").trim();
  return TOOL_ALIASES[t_name] || t_name;
}

/**
 * 函数功能: 构造某工具的"送审文本"——规则层与日志使用的核心内容
 * @param {string} tool_name - 标准工具名
 * @param {object} tool_input - 工具调用参数
 * @returns {{ruleText: string, preview: string}} 规则匹配文本与短预览；无法识别时 ruleText 为空
 */
function buildRuleText(tool_name, tool_input) {
  const t_input = tool_input && typeof tool_input === "object" ? tool_input : {};
  if (tool_name === "Bash") {
    const t_command = typeof t_input.command === "string" ? t_input.command : "";
    // 空命令无实际效果，交回内置流程即可，不值得占用一次审查
    if (!t_command.trim()) {
      return { ruleText: "", preview: "(空命令)" };
    }
    return { ruleText: t_command, preview: t_command };
  }
  if (tool_name === "Write" || tool_name === "Edit") {
    const t_path = typeof t_input.file_path === "string" ? t_input.file_path : "";
    if (!t_path) {
      return { ruleText: "", preview: "(无路径)" };
    }
    return { ruleText: t_path, preview: `${t_path} 写入` };
  }
  return { ruleText: "", preview: "(未识别工具)" };
}

/**
 * 函数功能: 快速通道——只读单段命令命中白名单即 0 LLM 静默放行。
 *           复合命令、重定向、命令替换、shell 包装器、解释器执行、脚本路径
 *           一律不走快速通道（只放行纯只读形态）
 * @param {string} rule_text - 命令全文
 * @param {object} settings - 运行时配置（fast_allow_enabled）
 * @returns {object|null} 放行决策，未命中返回 null
 */
// Cross-shell conservative grammar: no expansion, escaping, expressions or operators,
// even inside quotes (cmd does not share POSIX quoting/escaping rules).
function simpleCommandTokens(text) {
  if (/[\\\r\n;&|<>`$%!?(){}\[\]^\x00-\x1f]/.test(text)) return null;
  const parts = String(text).match(/"[^"\r\n]*"|'[^'\r\n]*'|[^\s"']+/g) || [];
  if (parts.join(" ") !== String(text).trim().replace(/\s+/g, " ")) return null;
  if (parts.some((p) => /["']/.test(p) && !/^("[^"]*"|'[^']*')$/.test(p))) return null;
  return parts.map((p) => p.replace(/^("|')|("|')$/g, ""));
}

function safeFastArguments(tokens) {
  const [head, ...args] = tokens;
  const h = head.toLowerCase();
  const literal = (x) => /^[A-Za-z0-9_./:@,+*=-]+$/.test(x) && !x.startsWith("-");
  const options = (allowed, positional = true) => args.every((x) => allowed.test(x) || (positional && literal(x)));
  if (/^(node|python|python3|py|deno|bun|ruby|perl|git|npm|pnpm|yarn|pip|pip3|java|go|cargo|rustc|dotnet|uv|docker)$/.test(h)
      && args.length === 1 && /^(--version|-v|-V)$/.test(args[0])) return true;
  if (h === "git") {
    const [sub, ...rest] = args;
    const flags = {
      status: /^(--short|--branch|--porcelain(?:=v[12])?|-s|-b|--untracked-files(?:=(?:no|normal|all))?)$/,
      log: /^(--oneline|--graph|--all|--decorate|--no-decorate|--stat|--name-only|--name-status|--no-ext-diff|--no-textconv|-\d+|--max-count=\d+)$/,
      diff: /^(--stat|--name-only|--name-status|--cached|--staged|--no-ext-diff|--no-textconv|--check|--quiet|--exit-code)$/,
      'ls-files': /^(--cached|--deleted|--modified|--others|--exclude-standard|-c|-d|-m|-o)$/,
      'rev-parse': /^(--show-toplevel|--show-prefix|--is-inside-work-tree|--abbrev-ref|--verify|--short)$/,
      describe: /^(--tags|--always|--long|--abbrev=\d+)$/,
      branch: /^(--list|--all|--remotes|-a|-r|-v|-vv)$/,
      tag: /^(--list|-l)$/,
    };
    // diff/log may invoke configured external diff/textconv when showing patches.
    // Only summary diff forms are eligible, and log deliberately has no patch/show flags.
    if (sub === "diff" && !rest.some((x) => /^(--stat|--name-only|--name-status|--check|--quiet|--exit-code)$/.test(x))) return false;
    if (sub === "remote") return rest.length === 0 || (rest.length === 1 && /^(--verbose|-v)$/.test(rest[0]));
    if (sub === "stash") return rest.length === 1 && rest[0] === "list";
    if (!flags[sub]) return false;
    if ((sub === "branch" || sub === "tag") && rest.length && !rest.every((x) => flags[sub].test(x))) return false;
    return rest.every((x) => flags[sub].test(x) || literal(x));
  }
  if (/^(pwd|whoami|hostname|ver|date|get-date|get-location)$/.test(h)) return args.length === 0;
  if (h === "mkdir") return args.length > 0 && args.every((x) => /^[A-Za-z0-9_][A-Za-z0-9._-]*$/.test(x));
  if (/^(echo|write-host|write-output)$/.test(h)) return args.every((x) => !x.startsWith("-"));
  if (h === "ls") return options(/^-[alhtrSdF1]+$/);
  if (h === "dir") return options(/^\/(?:b|a|s|w|p|o|n)$/i);
  if (/^(cat|type|wc|stat|file|where|which|df|du)$/.test(h)) return options(/^-(?:[blnshakm]+|L)$/);
  if (/^(head|tail)$/.test(h)) return options(/^-(?:[ncbqv]|\d+)$/);
  if (/^(get-childitem|get-content|get-item|get-process|get-service)$/.test(h)) return options(/^-(?:Name|Path|LiteralPath|Force|Recurse|File|Directory|TotalCount|Tail)$/i);
  if (h === "ipconfig") return args.length === 0 || (args.length === 1 && args[0].toLowerCase() === "/all");
  return false;
}

function matchFastAllow(rule_text, settings) {
  if (!settings || settings.fast_allow_enabled === false) {
    return null;
  }
  const safeTokens = simpleCommandTokens(rule_text || "");
  if (!safeTokens || !safeTokens.length || !safeFastArguments(safeTokens)) return null;
  if (!rule_text || splitTopLevelCommands(rule_text).length > 1) {
    return null;
  }
  // 重定向（> < >>）与命令替换（$( 、`）会引入写入或任意执行，快速通道只认纯只读
  if (/[><]|\$\(|`/.test(rule_text)) {
    return null;
  }
  // 环境变量间接执行（Windows %VAR% 展开 / shell $VAR 调用）不参与确定性放行
  if (/%[^%\s]+%/.test(rule_text)) {
    return null;
  }
  const t_cmd = rule_text.trim();
  // 结构化前置检查：包装器/解释器形态的真实命令藏在参数里，
  // 白名单正则按首词匹配会放行任意内层命令
  const t_tokens = tokenizeSegment(t_cmd);
  const t_head = String(t_tokens[0] || "").toLowerCase().replace(/\.exe$/, "");
  if (!t_head || t_head.startsWith("$") || t_head.startsWith("%")) {
    return null;
  }
  if (FAST_WRAPPER_HEADS.has(t_head)) {
    return null;
  }
  if (FAST_INTERPRETER_HEADS.has(t_head)) {
    // 解释器只放行纯版本查询：任何代码/脚本/任意参数形态都交模型审查
    const t_arg = String(t_tokens[1] || "").toLowerCase();
    if (t_tokens.length !== 2 || !FAST_VERSION_ARGS.has(t_arg)) {
      return null;
    }
  }
  for (const t_entry of loadFastAllow()) {
    if (t_entry.regex.test(t_cmd)) {
      return { action: ACTION_ALLOW, reason: `[auto-review] 快速通道放行（${t_entry.description}）`, source: "fast" };
    }
  }
  return null;
}

/**
 * 函数功能: 危险规则层——规则不再自动拒绝，三种动作各司其职：
 *           1) allow 命中单段命令 → 快速放行（低风险白名单）
 *           2) ask 是用户显式设置的确认门槛（如关机）→ 恒转用户裁决：模型看不到
 *              对话历史，无法替用户判断"这是不是我要求的"，这类规则必须由人拍板
 *           3) deny 不再直接拦截 → 产出 ruleHint 风险提示随载荷送审，由审批模型
 *              结合完整命令裁决（模型的 deny 才是真正的拒绝）
 * @param {string} rule_text - 被匹配文本（命令全文或目标路径）
 * @returns {object|null} allow/ask 决策或 route 提示（含 ruleHint），未命中返回 null
 */
function matchDangerRules(rule_text) {
  const t_rule = scanRules(rule_text);
  if (!t_rule) {
    return null;
  }
  const t_desc = redactSecrets(`危险规则 #${t_rule.index}: ${t_rule.description}`);
  if (t_rule.action === ACTION_ALLOW) {
    // allow 只对单段命令快速放行；复合命令交 matchCompoundRules 逐段确认，
    // 防止 "ls; rm ..." 因第一段白名单而跳过审查
    if (splitTopLevelCommands(rule_text).length <= 1 && simpleCommandTokens(rule_text)) {
      return {
        action: ACTION_ALLOW,
        reason: `[auto-review] 白名单放行（${t_desc}）`,
        source: "rule",
      };
    }
    return null;
  }
  if (t_rule.action === ACTION_ASK) {
    const t_reason = `[auto-review] ${t_desc}\n该操作命中你设置的确认（ask）规则，等待你裁决：确属你的要求点允许，否则点拒绝。`;
    return { action: ACTION_ASK, reason: t_reason, source: "rule", additionalContext: t_reason };
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
 * 函数功能: 对单段文本按数组顺序扫描规则。固定优先级：deny/ask 提示优先于 allow 放行——
 *           用户把宽泛 allow 排在 deny 之前时，风险提示不能被遮蔽（allow 只是捷径，
 *           deny/ask 才承载用户的真实风险意志）
 * @param {string} text - 被匹配文本
 * @param {Array<object>} [rules] - 已编译规则表（缺省现读；复合命令逐段复用同一份，避免每段重复读盘+编译）
 * @returns {object|null} 命中的规则定义（含编译好的 regex/action/description/index）
 */
function scanRules(text, rules = loadDangerRules()) {
  if (!text) {
    return null;
  }
  let t_match = null;
  const priority = { allow: 1, deny: 2, ask: 3 };
  for (const t_rule of rules) {
    t_rule.regex.lastIndex = 0;
    if (t_rule.regex.test(text) && (!t_match || priority[t_rule.action] > priority[t_match.action])) t_match = t_rule;
  }
  return t_match;
}

/**
 * 函数功能: 顶层命令分割——按 ; && || | 换行 切分复合命令
 * @param {string} text - 命令全文
 * @returns {string[]} 非空子命令列表；引号内与 $() / 反引号命令替换内的分隔符不参与切分
 */
function splitTopLevelCommands(text) {
  const t_subs = [];
  let t_cur = "";
  let t_single = false;
  let t_double = false;
  let t_backtick = false;
  let t_dollar_depth = 0;
  let t_escaped = false;
  for (let t_i = 0; t_i < text.length; t_i++) {
    const t_ch = text[t_i];
    // 转义态：前一字符为反斜杠，当前字符原样保留（即使是分隔符/引号/另一个反斜杠）。
    // 不能用"前一字符是反斜杠"的朴素判断：\\ 后跟 ; 在 bash 里是真分隔符，
    // 漏切分会把 "echo \\; 危险命令" 当成 echo 开头的单段命令，被快速通道 0 审查放行
    if (t_escaped) {
      t_escaped = false;
      t_cur += t_ch;
      continue;
    }
    if (t_single) {
      // 单引号内反斜杠是字面量，不存在转义
      if (t_ch === "'") t_single = false;
      t_cur += t_ch;
      continue;
    }
    // 反斜杠转义下一字符（引号外与双引号内均是；单引号内已在上方按字面量处理）
    if (t_ch === "\\") {
      t_escaped = true;
      t_cur += t_ch;
      continue;
    }
    if (t_double) {
      if (t_ch === '"') t_double = false;
      t_cur += t_ch;
      continue;
    }
    if (t_backtick) {
      if (t_ch === "`") t_backtick = false;
      t_cur += t_ch;
      continue;
    }
    if (t_ch === "'") { t_single = true; t_cur += t_ch; continue; }
    if (t_ch === '"') { t_double = true; t_cur += t_ch; continue; }
    if (t_ch === "`") { t_backtick = true; t_cur += t_ch; continue; }
    if (t_ch === "$" && text[t_i + 1] === "(") {
      // 一次消费 "$(" 两个字符并把深度置 1，保证闭合 ")" 恰好归零
      t_dollar_depth = 1;
      t_cur += "$(";
      t_i++;
      continue;
    }
    if (t_dollar_depth > 0) {
      if (t_ch === "(") t_dollar_depth++;
      if (t_ch === ")") t_dollar_depth--;
      t_cur += t_ch;
      continue;
    }
    if (t_ch === ";" || t_ch === "\n" || t_ch === "|") {
      t_subs.push(t_cur);
      t_cur = "";
      continue;
    }
    if (t_ch === "&") {
      // && 与单个 &（后台执行）均为命令边界
      t_subs.push(t_cur);
      t_cur = "";
      if (text[t_i + 1] === "&") t_i++;
      continue;
    }
    t_cur += t_ch;
  }
  t_subs.push(t_cur);
  return t_subs.map((t_sub) => t_sub.trim()).filter(Boolean);
}

/**
 * 函数功能: 把单段命令按空白切分为 token（引号内的空白不切分，引号本身剥离）
 * @param {string} segment - 单段命令文本
 * @returns {string[]} token 列表
 */
function tokenizeSegment(segment) {
  const t_tokens = [];
  let t_cur = "";
  let t_quote = "";
  for (const t_ch of String(segment || "")) {
    if (t_quote) {
      if (t_ch === t_quote) {
        t_quote = "";
      } else {
        t_cur += t_ch;
      }
      continue;
    }
    if (t_ch === "'" || t_ch === '"') {
      t_quote = t_ch;
      continue;
    }
    if (/\s/.test(t_ch)) {
      if (t_cur) {
        t_tokens.push(t_cur);
        t_cur = "";
      }
      continue;
    }
    t_cur += t_ch;
  }
  if (t_cur) {
    t_tokens.push(t_cur);
  }
  return t_tokens;
}

/**
 * 函数功能: 判断 token 是否为已知扩展名的脚本文件路径
 * @param {string} token - 命令中的单个 token
 * @returns {boolean} 是否脚本路径
 */
function isScriptPath(token) {
  const t_clean = String(token || "").trim();
  const t_dot = t_clean.lastIndexOf(".");
  if (t_dot <= 0) {
    return false;
  }
  return SCRIPT_EXTENSIONS.has(t_clean.slice(t_dot + 1).toLowerCase());
}

/**
 * 函数功能: 从单段命令的 token 序列中提取脚本文件引用
 * @param {string[]} tokens - tokenizeSegment 的输出
 * @returns {string|null} 脚本路径引用（原始文本），无匹配返回 null
 */
function extractRefFromSegment(tokens) {
  const t_head = String(tokens[0] || "").replace(/\\/g, "/").split("/").pop().toLowerCase().replace(/\.exe$/, "");
  // powershell/pwsh 的 -File <path>：显式脚本入口
  if (t_head === "powershell" || t_head === "pwsh") {
    for (let t_i = 1; t_i < tokens.length - 1; t_i++) {
      if (tokens[t_i].toLowerCase() === "-file" && isScriptPath(tokens[t_i + 1])) {
        return tokens[t_i + 1];
      }
    }
    return null;
  }
  // cmd 的 /c、/k <path>：批处理入口
  if (t_head === "cmd") {
    for (let t_i = 1; t_i < tokens.length - 1; t_i++) {
      const t_flag = tokens[t_i].toLowerCase();
      if ((t_flag === "/c" || t_flag === "/k") && isScriptPath(tokens[t_i + 1])) {
        return tokens[t_i + 1];
      }
    }
    return null;
  }
  // 裸脚本路径执行（./x.sh、x.py 直接作为段首命令）
  if (isScriptPath(tokens[0])) {
    return tokens[0];
  }
  // 解释器调用：跳过选项，取第一个非选项 token；内联/模块标志出现则整段放弃
  if (SCRIPT_INTERPRETERS.has(t_head)) {
    for (let t_i = 1; t_i < tokens.length; t_i++) {
      const t_token = tokens[t_i];
      const t_lower = t_token.toLowerCase();
      if (t_token.startsWith("-")) {
        if (SCRIPT_INLINE_FLAGS.has(t_lower) || SCRIPT_INLINE_FLAGS.has(t_lower.split("=")[0])) {
          return null;
        }
        continue;
      }
      return isScriptPath(t_token) ? t_token : null;
    }
  }
  return null;
}

/**
 * 函数功能: 从 Bash 命令全文中提取全部脚本文件引用（复合命令逐段提取、去重、保持顺序）
 * @param {string} command - 命令全文
 * @returns {string[]} 脚本路径引用列表（原始文本）
 */
function extractScriptRefs(command) {
  const t_refs = [];
  const t_seen = new Set();
  for (const t_segment of splitTopLevelCommands(String(command || ""))) {
    const t_tokens = tokenizeSegment(t_segment);
    if (t_tokens.length === 0) {
      continue;
    }
    const t_ref = extractRefFromSegment(t_tokens);
    if (t_ref && !t_seen.has(t_ref)) {
      t_seen.add(t_ref);
      t_refs.push(t_ref);
    }
  }
  return t_refs;
}

/**
 * 函数功能: 展开 ~ 前缀为用户主目录（跨平台），其余路径原样返回
 * @param {string} ref - 命令中的路径引用
 * @returns {string} 展开后的路径
 */
function expandTilde(ref) {
  if (ref === "~") {
    return os.homedir();
  }
  if (ref.startsWith("~/") || ref.startsWith("~\\")) {
    return path.join(os.homedir(), ref.slice(2));
  }
  return ref;
}

/**
 * 函数功能: 读取命令引用的脚本文件内容，构造送审附件（任何失败只降级为"不附加该文件"）。
 *           边界约束：realpath 必须位于 cwd 内（无 cwd 时只接受进程 cwd 内）、拒绝 symlink
 *           与敏感凭据文件——附件通道不能被用来读取项目外文件或把密钥外送审批渠道；
 *           附件总预算与工具调用 JSON 共用 max_payload_chars，防止大脚本撑爆单次请求
 * @param {string} command - Bash 命令全文
 * @param {string} cwd - 相对路径的解析基准目录（hook 输入的 cwd 回落进程 cwd）
 * @param {object} settings - 运行时配置（script_max_bytes 单文件上限；max_payload_chars 附件总预算）
 * @returns {{files: Array<{ref: string, path: string, content: string, truncated: boolean, total_bytes: number}>, notes: string[]}|null}
 *          附件对象；无任何引用或整体异常返回 null
 */
function collectScriptAttachments(command, cwd, settings) {
  try {
    const t_refs = extractScriptRefs(command);
    if (t_refs.length === 0) {
      return null;
    }
    const t_max_bytes = Math.max(1, Number(settings && settings.script_max_bytes) || 16000);
    const t_total_budget = Math.max(500, Number(settings && settings.max_payload_chars) || 8000);
    let t_used_chars = 0;
    const t_base_dir = String(cwd || "").trim() || process.cwd();
    // 基准目录自身先规范化，之后所有附件必须落在它下面
    const t_base_real = fs.realpathSync(t_base_dir);
    const t_files = [];
    const t_notes = [];
    let attempted = 0;
    for (const t_ref of t_refs) {
      if (attempted++ >= MAX_SCRIPT_FILES) {
        t_notes.push(`引用脚本超过 ${MAX_SCRIPT_FILES} 个，其余未附加`);
        break;
      }
      if (SENSITIVE_FILE_PATTERN.test(t_ref.replace(/\\/g, "/"))) {
        t_notes.push(`${t_ref}: 凭据类敏感文件，未附加`);
        continue;
      }
      // lstat 拒绝 symlink（含中间目录由 realpath 兜底）；realpath 解析最终落点
      const t_full = path.resolve(t_base_real, expandTilde(t_ref));
      try {
        if (SENSITIVE_FILE_PATTERN.test(t_full)) {
          t_notes.push(`${t_ref}: 凭据类敏感文件，未附加`);
          continue;
        }
        if (!isInsideDir(t_full, t_base_real)) {
          t_notes.push(`${t_ref}: 路径越出工作目录，未附加`);
          continue;
        }
        const t_lstat = fs.lstatSync(t_full);
        if (t_lstat.isSymbolicLink()) {
          t_notes.push(`${t_ref}: 符号链接，未附加`);
          continue;
        }
        const t_real = fs.realpathSync(t_full);
        if (!isInsideDir(t_real, t_base_real)) {
          t_notes.push(`${t_ref}: 解析后越出工作目录，未附加`);
          continue;
        }
        if (SENSITIVE_FILE_PATTERN.test(t_full) || SENSITIVE_FILE_PATTERN.test(t_real)) {
          t_notes.push(`${t_ref}: 凭据类敏感文件，未附加`);
          continue;
        }
        const t_stat = fs.statSync(t_real);
        if (!t_stat.isFile()) {
          t_notes.push(`${t_ref}: 非普通文件，未附加`);
          continue;
        }
        // 实际读取上限 = 单文件上限 与 剩余总预算 的较小值；预算耗尽即停止附加
        const t_read_cap = Math.min(t_max_bytes, t_total_budget - t_used_chars);
        if (t_read_cap <= 0) {
          t_notes.push("附件总大小已达载荷预算（max_payload_chars），其余未附加");
          break;
        }
        let t_content;
        let t_truncated;
        const t_fd = fs.openSync(t_real, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
        try {
          const before = fs.fstatSync(t_fd);
          if (!before.isFile() || before.dev !== t_stat.dev || before.ino !== t_stat.ino) throw new Error("文件已变化");
          const t_buf = Buffer.alloc(Math.floor(t_read_cap));
          let read = 0;
          while (read < t_buf.length) {
            const n = fs.readSync(t_fd, t_buf, read, t_buf.length - read, read);
            if (!n) break;
            read += n;
          }
          const after = fs.fstatSync(t_fd);
          t_content = t_buf.subarray(0, read).toString("utf8");
          t_truncated = read !== before.size || after.size !== before.size || after.mtimeMs !== before.mtimeMs;
        } finally {
          fs.closeSync(t_fd);
        }
        t_used_chars += t_content.length;
        // 二进制内容对审查无意义且浪费载荷：NUL 字节在前 8K 出现即跳过
        if (t_content.slice(0, 8192).includes("\0")) {
          t_notes.push(`${t_ref}: 二进制文件，未附加`);
          continue;
        }
        t_files.push({ ref: t_ref, path: t_real, content: t_content, truncated: t_truncated, total_bytes: t_stat.size });
      } catch (t_error) {
        // 详细原因进日志即可，给 LLM 的附注不携带本机错误细节
        logWrite("WARN", "script", `读取脚本失败 ${t_ref}: ${t_error.message}`);
        t_notes.push(`${t_ref}: 无法读取，未附加`);
      }
    }
    if (t_files.length === 0 && t_notes.length === 0) {
      return null;
    }
    logWrite("INFO", "script", `脚本送审 ${t_files.length} 个文件: ${t_files.map((t_f) => t_f.ref).join("、").slice(0, LOG_PREVIEW_CHARS) || "(全部失败)"}`);
    return { files: t_files, notes: t_notes };
  } catch (t_error) {
    // 附加功能自身故障绝不影响决策：按无附件继续走原管线
    logWrite("WARN", "script", `脚本附加异常: ${redactSecrets(t_error.message)}`);
    return { files: [], notes: ["脚本附加失败，内容不完整"] };
  }
}

/**
 * 函数功能: 判断 target 路径是否位于 base 目录之内（均需为已规范化的绝对路径）
 * @param {string} target - 待判断的绝对路径
 * @param {string} base - 边界目录的绝对路径
 * @returns {boolean} 是否在边界内（target === base 视为在内）
 */
function isInsideDir(target, base) {
  if (target === base) {
    return true;
  }
  const t_prefix = base.endsWith(path.sep) ? base : base + path.sep;
  return target.startsWith(t_prefix);
}

/**
 * 函数功能: 计算附件的缓存加盐串（文件路径 + 内容摘要 + 附注），空附件返回空串
 * @param {object|null} attachments - collectScriptAttachments 的返回值
 * @returns {string} 加盐串
 */
function hashAttachments(attachments) {
  if (!attachments) {
    return "";
  }
  const t_parts = [];
  for (const t_file of attachments.files || []) {
    t_parts.push(JSON.stringify([t_file.path, t_file.truncated, t_file.total_bytes, createHash("sha256").update(t_file.content).digest("hex")]));
  }
  for (const t_note of attachments.notes || []) {
    t_parts.push(`note:${t_note}`);
  }
  return t_parts.join("|");
}

/**
 * 函数功能: 复合命令的逐段规则审查——每段独立匹配：
 *           任一段命中 ask 规则 → 整条转用户裁决（确认门槛不能被其余段稀释）；
 *           任一段命中 deny 规则 → 只产出 ruleHint 风险提示（送审，不直接拦截）；
 *           全部段命中 allow 规则 → 整条白名单放行；其余情况返回 null 降级 LLM 审查。
 *           防止 allow 规则（如 ^ls\b）放行 "ls; rm -rf x" 这类以白名单命令开头的复合命令
 * @param {string} rule_text - 命令全文
 * @returns {object|null} allow/ask 决策或 route 提示（含 ruleHint），需要 LLM 审查时返回 null
 */
function matchCompoundRules(rule_text) {
  const t_subs = splitTopLevelCommands(rule_text);
  if (t_subs.length <= 1) {
    return null;
  }
  // 规则表只读一次再逐段匹配：段数多时避免每段重复读盘与正则编译
  const t_rules = loadDangerRules();
  const t_hits = t_subs.map((t_sub) => ({ sub: t_sub, rule: scanRules(t_sub, t_rules) }));
  const t_short = (t_sub) => redactSecrets(t_sub).replace(/\s+/g, " ").slice(0, 80);

  // ask 段：复合命令中任一段是用户确认门槛，整条转用户裁决
  const t_ask_hit = t_hits.find((t_item) => t_item.rule && t_item.rule.action === ACTION_ASK);
  if (t_ask_hit) {
    const t_desc = `危险规则 #${t_ask_hit.rule.index}: ${t_ask_hit.rule.description}`;
    const t_reason = `[auto-review] 复合命令的子命令「${t_short(t_ask_hit.sub)}」命中（${t_desc}），整条命令转用户确认。`;
    return { action: ACTION_ASK, reason: t_reason, ruleHint: t_desc, additionalContext: t_reason };
  }
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
  if (t_unmatched.length === 0 && t_subs.every((sub) => simpleCommandTokens(sub))
      && !/[\\`$%!?(){}\[\]^<>\r\x00]/.test(rule_text)) {
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
 * 函数功能: 递归按键排序的稳定序列化，保证等价输入命中同一缓存键
 * @param {*} value - 任意 JSON 值
 * @returns {string} 规范化 JSON 文本
 */
function stableStringify(value) {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map(stableStringify).join(",") + "]";
  }
  const t_keys = Object.keys(value).sort();
  return "{" + t_keys.map((t_key) => JSON.stringify(t_key) + ":" + stableStringify(value[t_key])).join(",") + "}";
}

/**
 * 函数功能: 计算当前安全策略的内容摘要（危险规则/快速通道/提示词/审批渠道），
 *           作为缓存键的盐——任一策略内容变化后旧结论立即失效。
 *           只保留渠道的 kind/baseURL/model，不纳入 api_key（避免密钥进入键运算）
 * @returns {string} 策略盐文本
 */
function buildPolicySalt() {
  const t_parts = [POLICY_SALT_VERSION];
  const t_hash = (text) => createHash("sha256").update(String(text || "")).digest("hex").slice(0, 16);
  // 危险规则与快速通道：原始 JSON 逐条规范化，避免编译对象不可序列化
  t_parts.push(`rules:${t_hash(stableStringify(loadRawDangerRules()))}`);
  t_parts.push(`fast:${t_hash(stableStringify(loadRawFastAllow()))}`);
  t_parts.push(`prompt:${t_hash(loadSecurityPrompt())}`);
  try {
    const t_provider = resolveProvider(loadSettings());
    t_parts.push(`provider:${t_hash(`${t_provider.kind}|${t_provider.baseURL}|${t_provider.model}`)}`);
  } catch {
    // 渠道未配置/解析失败：以"未配置"参与盐，渠道补配后缓存自然失效
    t_parts.push("provider:none");
  }
  return t_parts.join("|");
}

/**
 * 函数功能: 计算缓存键
 * @param {string} tool_name - 标准工具名
 * @param {object} tool_input - 工具调用参数
 * @param {string} [extra_salt] - 附加加盐串（策略盐/cwd/脚本附件摘要）
 * @returns {string} sha256 十六进制摘要
 */
function computeCacheKey(tool_name, tool_input, extra_salt = "") {
  const t_base = `${tool_name}\n${stableStringify(tool_input)}`;
  return createHash("sha256").update(extra_salt ? `${t_base}\n${extra_salt}` : t_base).digest("hex");
}

/**
 * 函数功能: 审查缓存键——在 computeCacheKey 之上叠加策略盐、cwd 与脚本附件摘要。
 *           策略盐保证规则/提示词/渠道变化后旧结论不复用（旧 allow 不能跨策略存活）；
 *           cwd 必须参与键：同一命令文本在不同项目目录语义可能不同（如 node scripts/deploy.js）
 * @param {string} tool_name - 标准工具名
 * @param {object} tool_input - 工具调用参数
 * @param {string} cwd - hook 输入的工作目录
 * @param {object|null} attachments - 脚本附件（参与键）
 * @returns {string} sha256 十六进制摘要
 */
function reviewCacheKey(tool_name, tool_input, cwd, attachments) {
  const t_parts = [buildPolicySalt()];
  t_parts.push(`cwd:${path.resolve(String(cwd || "").trim() || process.cwd())}`);
  const t_attach_salt = hashAttachments(attachments);
  if (t_attach_salt) {
    t_parts.push(t_attach_salt);
  }
  return computeCacheKey(tool_name, tool_input, t_parts.join("|"));
}

/**
 * 函数功能: 读取缓存中未过期的决策
 * @param {string} key - 缓存键
 * @param {number} ttl_seconds - 有效期（秒），0 表示禁用缓存
 * @returns {object|null} {action, reason}，未命中或已过期返回 null
 */
function validCacheEntry(entry) {
  return entry && typeof entry === "object" && !Array.isArray(entry)
    && (entry.action === ACTION_ALLOW || entry.action === ACTION_DENY)
    && typeof entry.reason === "string" && Number.isFinite(entry.expires);
}

function readCachedDecision(key, ttl_seconds) {
  if (!Number.isFinite(ttl_seconds) || ttl_seconds <= 0) {
    return null;
  }
  const t_cache = readJsonFile(CACHE_FILE(), {}, "cache");
  const t_entry = t_cache && !Array.isArray(t_cache) && Object.hasOwn(t_cache, key) ? t_cache[key] : null;
  if (!validCacheEntry(t_entry)) {
    return null;
  }
  if (Date.now() >= t_entry.expires || t_entry.expires - Date.now() > ttl_seconds * 1000) {
    return null;
  }
  // 缓存只承载模型的 allow/deny 结论；ask 是外层人工路径的产物，永不入缓存
  if (t_entry.action !== ACTION_ALLOW && t_entry.action !== ACTION_DENY) {
    return null;
  }
  return { action: t_entry.action, reason: t_entry.reason || "" };
}

/**
 * 函数功能: 写入缓存决策（惰性清理过期项并限制总量）
 * @param {string} key - 缓存键
 * @param {object} decision - {action, reason}
 * @param {number} ttl_seconds - 有效期（秒）
 * @returns {void}
 */
function writeCachedDecision(key, decision, ttl_seconds) {
  if (!Number.isFinite(ttl_seconds) || ttl_seconds <= 0 || !validCacheEntry({ ...decision, expires: Date.now() + ttl_seconds * 1000 })) {
    return;
  }
  // 读-改-写整体持锁：并发 hook 进程同时写缓存时避免"后写覆盖先写"丢条目
  withFileLock(CACHE_FILE() + ".lock", () => {
    const raw = readJsonFile(CACHE_FILE(), {}, "cache");
    const t_cache = Object.assign(Object.create(null), raw && typeof raw === "object" && !Array.isArray(raw) ? raw : {});
    const t_now = Date.now();
    for (const [t_k, t_v] of Object.entries(t_cache)) {
      if (!validCacheEntry(t_v) || t_v.expires <= t_now || t_v.expires - t_now > ttl_seconds * 1000) {
        delete t_cache[t_k];
      }
    }
    t_cache[key] = { ...decision, expires: t_now + ttl_seconds * 1000 };
    const t_entries = Object.entries(t_cache);
    if (t_entries.length > MAX_CACHE_ENTRIES) {
      t_entries.sort((a, b) => Number(a[1].expires) - Number(b[1].expires));
      for (let t_i = 0; t_i < t_entries.length - MAX_CACHE_ENTRIES; t_i++) {
        delete t_cache[t_entries[t_i][0]];
      }
    }
    writeFileAtomic(CACHE_FILE(), JSON.stringify(t_cache));
  });
}

/**
 * 函数功能: 从模型输出中提取平衡的第一个 JSON 对象文本（容忍围栏与前后杂文）
 * @param {string} text - 模型原始输出
 * @returns {string|null} JSON 对象文本，找不到返回 null
 */
function extractJsonObject(text) {
  const t_start = text.indexOf("{");
  if (t_start < 0) {
    return null;
  }
  let t_depth = 0;
  let t_in_string = false;
  let t_escaped = false;
  for (let t_i = t_start; t_i < text.length; t_i++) {
    const t_char = text[t_i];
    if (t_in_string) {
      if (t_escaped) {
        t_escaped = false;
      } else if (t_char === "\\") {
        t_escaped = true;
      } else if (t_char === '"') {
        t_in_string = false;
      }
      continue;
    }
    if (t_char === '"') {
      t_in_string = true;
    } else if (t_char === "{") {
      t_depth++;
    } else if (t_char === "}") {
      t_depth--;
      if (t_depth === 0) {
        return text.slice(t_start, t_i + 1);
      }
    }
  }
  return null;
}

/**
 * 函数功能: 解析并归一化安全子 agent 的审查结论
 *           自动二值语义：deny 是合法结论（拦截并回传分析），ask 仅作兼容保留
 * @param {string} llm_text - 模型原始输出
 * @returns {{decision: string, risk_level: string, analysis: string, risks: string[], scope: string, alternative: string}}
 * @throws {Error} 输出不可解析或缺少必需字段
 */
function parseVerdict(llm_text) {
  const t_json_text = extractJsonObject(llm_text) || "";
  let t_parsed;
  try {
    t_parsed = JSON.parse(t_json_text);
  } catch {
    throw new Error("模型输出不是合法 JSON");
  }
  if (!t_parsed || typeof t_parsed !== "object") {
    throw new Error("模型输出不是 JSON 对象");
  }
  if (t_parsed.decision !== ACTION_ALLOW && t_parsed.decision !== ACTION_ASK && t_parsed.decision !== ACTION_DENY) {
    throw new Error(`decision 字段非法: ${String(t_parsed.decision)}`);
  }
  return {
    decision: t_parsed.decision,
    risk_level: String(t_parsed.risk_level || "medium"),
    analysis: String(t_parsed.analysis || "（模型未给出分析）"),
    risks: Array.isArray(t_parsed.risks) ? t_parsed.risks.map(String).slice(0, 8) : [],
    scope: String(t_parsed.scope || "（模型未给出影响范围）"),
    alternative: String(t_parsed.alternative || ""),
  };
}

/**
 * 函数功能: 拼装展示用/回传主 agent 的 reason（分析 + 风险点 + 影响范围 + 替代方案）
 * @param {object} verdict - parseVerdict 的返回值
 * @returns {string} 多行 reason 文本
 */
function formatVerdictReason(verdict) {
  const t_lines = [
    `[auto-review] 风险级别 ${verdict.risk_level}: ${verdict.analysis}`,
  ];
  if (verdict.risks.length > 0) {
    t_lines.push("风险点:");
    for (const t_risk of verdict.risks) {
      t_lines.push(`- ${t_risk}`);
    }
  }
  t_lines.push(`影响范围: ${verdict.scope}`);
  if (verdict.alternative) {
    t_lines.push(`替代方案: ${verdict.alternative}`);
  }
  return t_lines.join("\n");
}

/**
 * 函数功能: 构造送审载荷（截断保护 + 可选脚本附件块 + 可选 cwd 上下文 + 敏感值脱敏）。
 *           工具输入与脚本内容同属不可信数据，常见的密钥/令牌值替换为占位符后再送审，
 *           保留命令结构供模型判断语义——附件通道不能成为把凭据外送审批渠道的途径
 * @param {string} tool_name - 标准工具名
 * @param {object} tool_input - 工具调用参数
 * @param {number} max_chars - 完整载荷总字符预算（含附件、cwd、规则提示和所有元数据）；超限抛错转人工
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
  if (t_payload.length > max_chars) throw new Error("完整审查载荷超出 max_payload_chars，必须人工确认");
  return t_payload;
}

// 原始对象先递归脱敏，避免 JSON 转义隐藏赋值及嵌套敏感键。
const SENSITIVE_KEY = /(?:api[_-]?key|token|secret|password|passwd|pwd|authorization|credential|private[_-]?key)/i;
function redactObject(value) {
  if (typeof value === "string") return redactSecrets(value);
  if (Array.isArray(value)) return value.map(redactObject);
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, SENSITIVE_KEY.test(k) ? "<REDACTED>" : redactObject(v)]));
  return value;
}

// 常见凭据形态：赋值/参数/头字段（含 JSON 键值与 Bearer 头）中的长随机串值替换为占位符，保留键名供模型识别意图
const SECRET_VALUE_PATTERN = /((?:[\w-]*(?:api[_-]?key|token|secret|password|passwd|pwd|authorization|credential)[\w-]*)\s*["']?\s*(?:[=:]\s*|\s+)(?:bearer\s+)?)("(?:\\.|[^"\\\r\n])*"|'(?:\\.|[^'\\\r\n])*'|[^\s,;}"']+)/gi;

/**
 * 函数功能: 对文本中的常见密钥/令牌值做占位脱敏（键名保留，值替换为 <REDACTED>）
 * @param {string} text - 待脱敏文本
 * @returns {string} 脱敏后文本
 */
function redactSecrets(text) {
  const input = String(text || "");
  try {
    const parsed = JSON.parse(input);
    if (parsed && typeof parsed === "object") return JSON.stringify(redactObject(parsed));
  } catch { /* Not standalone JSON; redact shell assignments and CLI arguments. */ }
  return input.replace(SECRET_VALUE_PATTERN, (_, prefix, value) => {
    const quote = /^["']/.test(value) ? value[0] : "";
    return `${prefix}${quote}<REDACTED>${quote}`;
  }).replace(/(\bbearer\s+)([^\s"',;}]+)/gi, "$1<REDACTED>");
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
 * @returns {Promise<{action: string, reason: string}>} 决策对象
 * @throws {ProviderError|LlmError} 渠道未配置、调用失败或输出不可解析
 */
async function runLlmReview(tool_name, tool_input, settings, attachments, cwd, rule_hint, cache_key) {
  const t_prompt = loadSecurityPrompt();
  const t_payload = buildReviewPayload(tool_name, tool_input, settings.max_payload_chars, attachments, cwd, rule_hint);
  const t_script_note = attachments && attachments.files.length > 0 ? ` scripts=${attachments.files.length}` : "";

  // 专用审批渠道是唯一 LLM 来源：未配置/不可达不回落任何其他渠道，
  // 错误上抛由总兜底转人工审批——模型不在场时绝不自动许可
  const t_provider = resolveProvider(settings);
  const t_start_ms = Date.now();
  const t_raw = await callLlm(t_provider, t_prompt, t_payload);
  const t_verdict = parseVerdict(t_raw);
  const t_duration_s = ((Date.now() - t_start_ms) / 1000).toFixed(1);

  // 自动二值收敛：模型输出 ask（存疑）按 deny 处理并回传分析——审批契约只允许
  // allow/deny，存疑本身不是安全证明，收敛到保守侧由主 agent 按分析改写后重试
  if (t_verdict.decision === ACTION_ASK) {
    t_verdict.decision = ACTION_DENY;
    t_verdict.risks = t_verdict.risks.length > 0 ? t_verdict.risks : ["模型对该操作存疑"];
    t_verdict.alternative = t_verdict.alternative || "请拆分命令、缩小影响范围或改用只读等价做法后重试";
  }

  let t_reason;
  if (t_verdict.decision === ACTION_ALLOW) {
    t_reason = `[auto-review] 安全审查通过（${t_verdict.risk_level}风险，${t_duration_s}s）: ${t_verdict.analysis}`;
  } else {
    t_reason = formatVerdictReason(t_verdict);
  }
  logWrite("INFO", "llm", `${t_verdict.decision} risk=${t_verdict.risk_level} ${t_duration_s}s${t_script_note}（专用审批渠道）`);
  // 只有 LLM 结论入缓存（规则层是即时的，且规则变更后旧缓存可能失效）；
  // 缓存键含脚本附件摘要——脚本内容变更后旧结论自动失效重新审查
  writeCachedDecision(cache_key, { action: t_verdict.decision, reason: t_reason }, settings.cache_ttl_seconds);
  // 非 allow 结论双发 additionalContext：deny 的风险分析与替代方案同样要回传主 agent，
  // 主 agent 据此修改命令后重试（子模型 → 主模型的反馈闭环）
  const t_extra = t_verdict.decision !== ACTION_ALLOW ? { additionalContext: t_reason } : {};
  return { action: t_verdict.decision, reason: t_reason, ...t_extra };
}

/**
 * 函数功能: 决策管线主入口（对 hook_main 暴露的唯一函数，保证不抛异常）
 * @param {object} hook_input - hook stdin 的 JSON（tool_name/tool_input，字段防御式读取）
 * @returns {Promise<{action: string, reason: string, source: string}>} 决策对象
 */
async function reviewToolUse(hook_input) {
  try {
    const t_settings = loadSettings();
    if (!t_settings.enabled) {
      return { action: ACTION_PASS, reason: "", source: "off" };
    }

    // 防御式读取：tool_name 与 toolName 双兼容。hooks matcher 只对 Bash/Write/Edit
    // 触发，正常输入必有工具名；缺失属协议异常——无法确认审查对象时阻断，不放行未知调用
    const t_tool_name = normalizeToolName(hook_input && (hook_input.tool_name || hook_input.toolName));
    if (!t_tool_name) {
      logWrite("WARN", "review", "hook 输入缺少工具名，无法确认审查对象，阻断");
      return {
        action: ACTION_DENY,
        reason: "[auto-review] hook 输入缺少工具名，无法确认审查对象，已阻断。如频繁出现请检查客户端版本或暂时禁用本插件。",
        source: "malformed",
      };
    }
    if (!t_settings.review_tools.includes(t_tool_name)) {
      return { action: ACTION_PASS, reason: "", source: "skip" };
    }

    // 权限模式闸门：仅在"自动编辑"模式下接管，其他模式一律交回客户端原生审批，
    // 避免双重打扰。正向判定（只认 edit）而非关键词黑名单：客户端新增任何模式值
    // 都自动隐身，不会因名字里没有 plan/confirm 字样被误接管；
    // 字段缺失（无法判定）时维持接管行为，兼容未提供该字段的客户端。
    const t_mode_hint = String((hook_input && (hook_input.permission_mode || hook_input.permissionMode || hook_input.mode)) || "");
    if (t_mode_hint && t_mode_hint.toLowerCase() !== "edit") {
      logWrite("INFO", "mode", `检测到非自动编辑模式（${t_mode_hint}），交回客户端原生审批`);
      return { action: ACTION_PASS, reason: "", source: "mode" };
    }

    const t_tool_input = hook_input && hook_input.tool_input && typeof hook_input.tool_input === "object"
      ? hook_input.tool_input
      : {};
    const t_cwd = String((hook_input && hook_input.cwd) || "").trim() || process.cwd();
    const { ruleText: t_rule_text, preview: t_preview } = buildRuleText(t_tool_name, t_tool_input);
    const t_short = redactSecrets(t_preview).replace(/\s+/g, " ").slice(0, LOG_PREVIEW_CHARS);

    // ③ 规则层：allow 快速放行、ask 转用户裁决（都是最终决策）；
    //     deny 不再直接拦截——只提炼 ruleHint 风险提示随载荷送审，由审批模型裁决
    let t_rule_hint = "";
    const t_rule_decision = matchDangerRules(t_rule_text);
    if (t_rule_decision && t_rule_decision.action !== DECISION_ROUTE) {
      logWrite("INFO", "rule", `${t_rule_decision.action} ${t_tool_name}: ${t_short} (${t_rule_decision.reason.split("\n")[0]})`);
      return t_rule_decision;
    }
    if (t_rule_decision && t_rule_decision.ruleHint) {
      t_rule_hint = t_rule_decision.ruleHint;
      logWrite("INFO", "rule", `hint ${t_tool_name}: ${t_short} (${t_rule_hint})`);
    }
    // ③' 复合命令逐段：任一 ask 段整条转用户、全 allow 整条放行；deny 段并入送审提示
    if (t_tool_name === "Bash") {
      const t_compound_decision = matchCompoundRules(t_rule_text);
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
      const t_fast_decision = matchFastAllow(t_rule_text, t_settings);
      if (t_fast_decision) {
        logWrite("INFO", "fast", `allow ${t_tool_name}: ${t_short}`);
        return t_fast_decision;
      }
    }

    // 会话白名单已随插件审批对话框移除：重复指令的"会话内允许"由客户端原生
    // 权限流程承接，插件侧不再维护任何跨请求的会话放行状态

    // ③.5 脚本内容附加：读取命令引用的脚本文件随载荷送审（相对路径按 hook 输入的 cwd 解析）。
    //     放在缓存之前：附件摘要参与缓存键，脚本内容变化后旧结论自动失效
    let t_attachments = null;
    if (t_tool_name === "Bash" && t_settings.inspect_scripts) {
      t_attachments = collectScriptAttachments(t_rule_text, t_cwd, t_settings);
    }

    // 完整性检查先于缓存：旧 allow 不能为缺失/截断脚本或不完整载荷背书。
    if (t_attachments && (t_attachments.notes.length || t_attachments.files.some((f) => f.truncated))) {
      return { action: ACTION_ASK, source: "incomplete", reason: "[auto-review] 脚本内容未完整读取，必须人工确认。" };
    }
    buildReviewPayload(t_tool_name, t_tool_input, t_settings.max_payload_chars, t_attachments, t_cwd, t_rule_hint);

    // ④ 缓存层：相同调用+相同工作目录短期内复用结论，降低延迟与 token 消耗
    const t_cache_key = reviewCacheKey(t_tool_name, t_tool_input, t_cwd, t_attachments);
    const t_cached = readCachedDecision(t_cache_key, t_settings.cache_ttl_seconds);
    if (t_cached) {
      logWrite("INFO", "cache", `${t_cached.action} ${t_tool_name}: ${t_short}`);
      // deny/ask 结论同样双发 additionalContext（兼容不含该字段的旧缓存条目），
      // 保证缓存命中的拒绝也把分析+替代方案送回主模型，闭环不因缓存而断
      const t_extra = t_cached.action !== ACTION_ALLOW ? { additionalContext: t_cached.reason } : {};
      return { ...t_cached, source: "cache", ...t_extra };
    }

    // ⑤ 安全子 agent（LLM）审查（缓存键复用上方已算好的 t_cache_key，不重复计算策略盐）
    const t_llm_decision = await runLlmReview(t_tool_name, t_tool_input, t_settings, t_attachments, t_cwd, t_rule_hint, t_cache_key);
    return { ...t_llm_decision, source: "llm" };
  } catch (t_error) {
    // ⑥ 总兜底：审批模型不可用时不猜测、不自动放行，转客户端人工审批。
    // 规则命中本身不会触发人工；只有模型链路失败才进入这里。
    const t_cause = t_error instanceof ProviderError || t_error instanceof LlmError
      ? t_error.message
      : t_error && t_error.message ? t_error.message : "未知错误";
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
  normalizeToolName,
  buildRuleText,
  matchDangerRules,
  matchCompoundRules,
  matchFastAllow,
  splitTopLevelCommands,
  extractScriptRefs,
  collectScriptAttachments,
  hashAttachments,
  stableStringify,
  buildPolicySalt,
  computeCacheKey,
  reviewCacheKey,
  readCachedDecision,
  writeCachedDecision,
  extractJsonObject,
  parseVerdict,
  formatVerdictReason,
  buildReviewPayload,
  redactSecrets,
};
