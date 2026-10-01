/**
 * 模块功能: 快速通道——纯只读命令的有限参数白名单与保守结构门禁（0 LLM 放行）。
 *           只放行可证明只读的形态；cd/chdir、包装器、解释器、重定向、命令替换、
 *           变量展开等跨 shell 语义不确定形态一律交模型审查
 * 作者: zhao
 * 创建日期: 2026年10月01日
 * 描述: 从 reviewer.js 拆出（0.8.8 模块化）。两层门禁：结构层（simpleCommandTokens
 *       的跨 shell 保守文法 + safeFastArguments 的按命令参数白名单）+ 策略层
 *       （loadFastAllow 白名单正则）。用户自定义白名单正则由 settings.js 的
 *       危险结构检查兜底；本模块的参数白名单是第二道独立防线
 * 依赖: ./shell_lex.js ./settings.js ./decision.js
 * 更新日期: 2026年10月01日
 */

import { ACTION_ALLOW } from "./decision.js";
import { SENSITIVE_FILE_PATTERN, SENSITIVE_RUNTIME_FILE_PATTERN, splitTopLevelCommands, tokenizeSegment, isCdSegment } from "./shell_lex.js";
import { loadFastAllow } from "./settings.js";

// 快速通道的结构化拦截：包装器/动态执行形态全拦——真实命令藏在参数里，
// 白名单正则按首词匹配会放行任意内层命令
const FAST_WRAPPER_HEADS = new Set([
  "cmd", "powershell", "pwsh", "start", "start-process", "invoke-expression", "iex", "call",
  "invoke-command", "bash", "sh", "zsh", "dash", "wscript", "cscript", "mshta", "rundll32", "regsvr32",
]);

// 脚本解释器：真实命令同样在参数里，只放行纯版本查询（无代码/脚本/任意参数）
const FAST_INTERPRETER_HEADS = new Set(["python", "python3", "py", "node", "deno", "bun", "ruby", "perl"]);
const FAST_VERSION_ARGS = new Set(["-v", "-V", "--version", "version"]);

// 只读命令的首词集合。目标路径需要额外经过范围和敏感文件门禁。
// find 不在集合内：其 -exec/-delete 族参数有真实副作用，跨 shell 语义无法用参数白名单收敛
const FAST_READ_HEADS = new Set([
  "cat", "type", "head", "tail", "wc", "stat", "file", "where", "which", "df", "du", "ls", "dir",
  "grep", "egrep", "fgrep", "rg", "findstr",
  "get-childitem", "get-content", "get-item",
]);

/**
 * 函数功能: 判断快速读取目标是否能仅凭命令文本证明为当前目录内的普通文件。
 *           快速通道没有可靠 cwd/realpath 上下文，因此绝对路径、父目录穿越、变量展开和
 *           凭据/插件运行时文件统一交模型审查；普通相对文件名继续保留零延迟能力。
 * @param {string} token - 已去除引号的非选项 token
 * @returns {boolean} 可进入快速通道返回 true
 */
function isSafeFastReadTarget(token) {
  const t_path = String(token || "");
  if (!t_path || /[$%`]/.test(t_path)) return false;
  // Globs, drive-relative paths and shell-specific separators are not a stable
  // proof of the actual read target; leave them for model review.
  if (/[?*\[\]]/.test(t_path)) return false;
  if (/^[A-Za-z]:[^\\/]/.test(t_path)) return false;
  if (/^(?:[A-Za-z]:[\\/]|[\\/]{1,2}|~(?:[\\/]|$))/.test(t_path)) return false;
  if (/(^|[\\/])\.\.(?:[\\/]|$)/.test(t_path)) return false;
  if (SENSITIVE_FILE_PATTERN.test(t_path) || SENSITIVE_RUNTIME_FILE_PATTERN.test(t_path)) return false;
  return true;
}

/**
 * 函数功能: 对只读命令的非选项参数应用目标文件门禁。
 *           数字/选项值即使被视为目标也只能收紧判定，不会扩大放行范围。
 * @param {string} head - 归一化命令首词
 * @param {string[]} args - 命令参数
 * @returns {boolean} 所有可疑目标均通过返回 true
 */
function safeFastReadTargets(head, args) {
  if (!FAST_READ_HEADS.has(head)) return true;
  // findstr 的旗标是斜杠形态（/i /n），与 dir 同类——不能让旗标被目标门禁当绝对路径拦下
  const t_options = (head === "dir" || head === "findstr") ? /^\// : /^-/;
  return args.every((t_arg) => t_options.test(t_arg) || isSafeFastReadTarget(t_arg));
}

// Cross-shell conservative grammar: no expansion, escaping, expressions or operators,
// even inside quotes (cmd does not share POSIX quoting/escaping rules).
function simpleCommandTokens(text) {
  if (/[\\\r\n;&|<>`$%!?(){}\[\]^\x00-\x1f]/.test(text)) return null;
  const parts = String(text).match(/"[^"\r\n]*"|'[^'\r\n]*'|[^\s"']+/g) || [];
  if (parts.join(" ") !== String(text).trim().replace(/\s+/g, " ")) return null;
  if (parts.some((p) => /["']/.test(p) && !/^("[^"]*"|'[^']*')$/.test(p))) return null;
  return parts.map((p) => p.replace(/^("|')|("|')$/g, ""));
}

function safeFastSearchArguments(head, args) {
  const t_head = String(head || "").toLowerCase();
  const t_allowedShort = {
    grep: new Set(["r", "R", "n", "i", "v", "c", "l", "L", "H", "h", "q", "s", "o", "w", "F"]),
    egrep: new Set(["r", "R", "n", "i", "v", "c", "l", "L", "H", "h", "q", "s", "o", "w", "F"]),
    fgrep: new Set(["r", "R", "n", "i", "v", "c", "l", "L", "H", "h", "q", "s", "o", "w", "F"]),
    rg: new Set(["i", "n", "v", "w", "F", "S", "H", "h", "c", "l", "L", "r", "j", "T"]),
    findstr: new Set(["i", "n", "m", "x", "b", "e", "l", "r"]),
  }[t_head];
  const t_allowedLong = {
    grep: new Set(["--recursive", "--line-number", "--ignore-case", "--invert-match", "--count", "--files-with-matches", "--files-without-match", "--with-filename", "--no-filename", "--quiet", "--silent", "--only-matching", "--word-regexp", "--fixed-strings"]),
    egrep: new Set(["--recursive", "--line-number", "--ignore-case", "--invert-match", "--count", "--files-with-matches", "--files-without-match", "--with-filename", "--no-filename", "--quiet", "--silent", "--only-matching", "--word-regexp", "--fixed-strings"]),
    fgrep: new Set(["--recursive", "--line-number", "--ignore-case", "--invert-match", "--count", "--files-with-matches", "--files-without-match", "--with-filename", "--no-filename", "--quiet", "--silent", "--only-matching", "--word-regexp", "--fixed-strings"]),
    rg: new Set(["--files", "--ignore-case", "--line-number", "--invert-match", "--word-regexp", "--fixed-strings", "--no-heading", "--heading", "--color=never", "--json", "--stats", "--count", "--count-matches", "--files-with-matches", "--files-without-match", "--max-count=1"]),
    findstr: new Set(),
  }[t_head];
  let positional = 0;
  let filesMode = false;
  for (const token of args) {
    if (token === "--") return false;
    if (token.startsWith("--")) {
      if (!t_allowedLong.has(token)) return false;
      if (token === "--files") filesMode = true;
      continue;
    }
    if (t_head === "findstr" && /^\/[A-Za-z]$/.test(token)) {
      if (!t_allowedShort.has(token.slice(1))) return false;
      continue;
    }
    if (token.startsWith("-")) {
      const cluster = token.slice(1);
      if (!cluster || [...cluster].some((flag) => !t_allowedShort.has(flag))) return false;
      continue;
    }
    if (t_head === "findstr" && token.startsWith("/")) return false;
    if (!isSafeFastReadTarget(token)) return false;
    positional++;
  }
  // rg --files is a file listing mode and intentionally has no pattern.
  if (t_head === "rg" && filesMode) return positional <= 1;
  return positional >= 1;
}

function safeFastArguments(tokens) {
  const [head, ...args] = tokens;
  const h = head.toLowerCase();
  if (/^(grep|egrep|fgrep|rg|findstr)$/.test(h)) {
    return safeFastSearchArguments(h, args);
  }
  if (!safeFastReadTargets(h, args)) return false;
  const literal = (x) => /^[A-Za-z0-9_./:@,+=>-]+$/.test(x) && !x.startsWith("-") && !/[?*\[\]]/.test(x);
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
  // 包管理器只读查询（社区白名单共识：只放确定性无害的查询形态，install/run 交模型）
  if (/^(npm|pnpm|yarn)$/.test(h)) {
    const t_sub = args[0];
    if (!t_sub || !/^(ls|list|outdated)$/.test(t_sub)) return false;
    return args.slice(1).every((x) => literal(x) || /^(--long|--json|-g|--global|--depth=\d+)$/.test(x));
  }
  if (/^pip3?$/.test(h)) {
    const t_sub = args[0];
    if (!t_sub || !/^(list|show)$/.test(t_sub)) return false;
    return args.slice(1).every((x) => literal(x) || /^(--format=(?:columns|json|freeze)|--outdated|-v)$/.test(x));
  }
  if (h === "docker") {
    if (!args[0] || !/^(ps|images)$/.test(args[0])) return false;
    return args.slice(1).every((x) => /^(-a|--all|-q|--quiet)$/.test(x));
  }
  if (h === "tree") {
    return args.every((x) => /^(-L|-[aAfF]|\d+|\/[fa]|--filesfirst|--filelimit=\d+)$/.test(x));
  }
  if (h === "mkdir") return args.length > 0 && args.every((x) => /^[A-Za-z0-9_][A-Za-z0-9._-]*$/.test(x));
  if (/^(echo|write-host|write-output)$/.test(h)) return args.every((x) => !x.startsWith("-"));
  if (h === "ls") return options(/^-[alhtrSdF1]+$/);
  if (h === "dir") return options(/^\/(?:b|a|s|w|p|o|n)$/i);
  if (/^(cat|type|wc|stat|file|where|which|df|du)$/.test(h)) return options(/^-(?:[blnshakm]+|L)$/);
  if (/^(head|tail)$/.test(h)) return options(/^(?:-n|-c|-b|-q|-v|-[0-9]+)$/);
  if (/^(get-childitem|get-content|get-item|get-process|get-service)$/.test(h)) {
    return options(/^-(?:Name|Path|LiteralPath|Force|Recurse|File|Directory|TotalCount|Tail)$/i);
  }
  if (h === "ipconfig") return args.length === 0 || (args.length === 1 && args[0].toLowerCase() === "/all");
  return false;
}

/**
 * 函数功能: 剥离段尾纯 stderr 重定向（2>&1 / 2>/dev/null）。
 *           这两种形态只把错误流并入标准流或丢弃，不落盘不外发；剥离后段落
 *           交由各层原有的门禁判断。`2>nul` 在 POSIX shell 会写成普通文件、
 *           写文件的 `2>x` 与 `>`、`<` 一律不在剥离范围
 * @param {string} segment - 单段命令文本
 * @returns {string} 剥离后的文本（未命中返回原文）
 */
function stripStderrRedirect(segment) {
  // Only fd duplication and POSIX null sink are shell-independent enough here.
  return String(segment || "").replace(/\s+2>(&1|\/dev\/null)\s*$/i, "");
}

/**
 * 函数功能: 检测段文本中引号外的 < > 重定向字符与未闭合引号。重定向只在本层
 *           意味写文件/覆写；引号内的 < > 是编程文本（如 node -e "x=>y" 的箭头函数），
 *           一刀切拒绝会把用户明确信任的内联代码形态挡在白名单外。未闭合引号
 *           视为畸形：跨 shell 解析分歧太大，保守不放行
 * @param {string} text - 单段命令文本（已剥离段尾 stderr 重定向）
 * @returns {boolean} 检出问题返回 true
 */
function unquotedRedirectOrMalformed(text) {
  let t_quote = "";
  for (const t_ch of String(text || "")) {
    if (t_quote) {
      if (t_ch === t_quote) t_quote = "";
      continue;
    }
    if (t_ch === "'" || t_ch === '"') {
      t_quote = t_ch;
      continue;
    }
    if (t_ch === "<" || t_ch === ">") {
      return true;
    }
  }
  return t_quote !== "";
}

/**
 * 函数功能: 用户自写 allow 规则匹配段落的轻量结构门禁——正则本身是用户的信任边界
 *           （用户写什么放行什么是显式决策），这里只兜底确定性逃逸形态：
 *           命令替换 $( 与反引号（内层命令未经任何审查）、引号外文件重定向 < >、
 *           反斜杠紧跟分隔符（\& \; \| —— bash 转义为字面量但 cmd 是真命令边界，
 *           同一文本跨 shell 语义分歧，用户的单一正则无法表达两种语义）、
 *           Windows %VAR% 展开间接执行。引号内的编程文本（括号/箭头函数/分号等）
 *           不再一刀切，否则 node -e "只读脚本" 这类形态永远进不了白名单
 * @param {string} segment - 单段命令文本（剥离 stderr 后缀之前的原文亦可）
 * @returns {boolean} 通过返回 true
 */
function userAllowSegmentSafe(segment) {
  const t_stripped = stripStderrRedirect(segment);
  if (!t_stripped.trim()) return false;
  // Directory changes depend on shell state and cannot be proven from one regex.
  if (/^\s*(?:cd|chdir)(?:\s|$)/i.test(t_stripped)) return false;
  if (/`|\$\(/.test(t_stripped)) return false;
  if (/\\[&;|<>]/.test(t_stripped)) return false;
  if (unquotedRedirectOrMalformed(t_stripped)) return false;
  if (/%[^%\s]{1,64}%/.test(t_stripped)) return false;
  return true;
}

/**
 * 函数功能: 判断单个命令段是否可确定性放行（0 LLM），通过则返回该段的白名单描述。
 *           段尾纯 stderr 重定向（2>&1/2>/dev/null）先剥离再判断；
 *           cd/chdir 段与其他跨 shell 语义不确定形态默认交模型审查；其余段保持严格双门禁：
 *           包装器/解释器结构检查 + 保守 token 文法 + 参数白名单 + 白名单正则全过才放行
 * @param {string} segment - 段文本
 * @param {Array<{regex: RegExp, description: string}>} [fast_rules] - 预载的白名单条目
 *        （组合命令多段时预载一次，避免逐段重复读盘与正则编译；缺省现读）
 * @returns {string|null} 白名单描述，未命中返回 null
 */
function matchFastSegment(segment, fast_rules) {
  const t_seg = stripStderrRedirect(segment);
  if (!t_seg.trim()) {
    return null;
  }
  // 剥离后仍含文件重定向（>x、<x）或命令替换：快速通道只认纯只读形态
  if (/[<>]|\$\(|`/.test(t_seg)) {
    return null;
  }
  // 环境变量间接执行（Windows %VAR% 展开）不参与确定性放行
  if (/%[^%\s]{1,64}%/.test(t_seg)) {
    return null;
  }
  const t_tokens = tokenizeSegment(t_seg);
  if (!t_tokens || t_tokens.length === 0) {
    return null;
  }
  const t_head = String(t_tokens[0] || "").toLowerCase().replace(/\.exe$/, "");
  if (!t_head || t_head.startsWith("$") || t_head.startsWith("%")) {
    return null;
  }
  // cd/chdir changes the shell working directory and has cross-shell semantics.
  // It is always reviewed by the model, including as a compound-command segment.
  if (isCdSegment(t_tokens, "fast")) {
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
  const t_cmd = t_seg.trim();
  const t_safe_tokens = simpleCommandTokens(t_cmd);
  if (!t_safe_tokens || !t_safe_tokens.length || !safeFastArguments(t_safe_tokens)) {
    return null;
  }
  for (const t_entry of fast_rules || loadFastAllow()) {
    if (t_entry.regex.test(t_cmd)) {
      return t_entry.description;
    }
  }
  return null;
}

/**
 * 函数功能: 快速通道——纯只读命令命中白名单即 0 LLM 静默放行；组合命令在
 *           "每段都单独可放行"的前提下整条放行。cd/chdir 段与包装器、解释器、
 *           重定向、展开形态一样不参与确定性放行——任一段不可证明只读即整条
 *           降级模型审查
 * @param {string} rule_text - 命令全文
 * @param {object} settings - 运行时配置（fast_allow_enabled）
 * @param {{segments?: string[], fast_rules?: Array<{regex: RegExp, description: string}>}} [precomputed]
 *        - 同请求内已算好的分段与白名单（省去重复分割与读盘编译；缺省现算）
 * @returns {object|null} 放行决策，未命中返回 null
 */
function matchFastAllow(rule_text, settings, { segments, fast_rules } = {}) {
  if (!settings || settings.fast_allow_enabled === false) {
    return null;
  }
  const t_segments = segments || splitTopLevelCommands(rule_text || "");
  if (!t_segments.length) {
    return null;
  }
  // 白名单预载一次供全部段复用（0.8.5）：多段复合命令不再逐段读盘与编译正则
  const t_fast_rules = fast_rules || loadFastAllow();
  const t_descs = t_segments.map((t_seg) => matchFastSegment(t_seg, t_fast_rules));
  if (t_descs.some((t_desc) => !t_desc)) {
    return null;
  }
  if (t_segments.length === 1) {
    return { action: ACTION_ALLOW, reason: `[auto-review] 快速通道放行（${t_descs[0]}）`, source: "fast" };
  }
  return {
    action: ACTION_ALLOW,
    reason: `[auto-review] 组合命令快速通道放行（${t_segments.length} 段全部只读安全：${t_descs.join("、")}）`,
    source: "fast",
  };
}

export {
  FAST_WRAPPER_HEADS,
  FAST_VERSION_ARGS,
  stripStderrRedirect,
  unquotedRedirectOrMalformed,
  userAllowSegmentSafe,
  matchFastSegment,
  matchFastAllow,
};
