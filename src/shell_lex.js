/**
 * 模块功能: shell 命令词法层——顶层命令分割、token 切分、脚本路径识别与
 *           统一的 cd/chdir 段判定；同时收口跨模块共享的敏感文件模式。
 *           本层只做词法，不做安全裁决；调用方（规则层/快速通道/脚本附件）
 *           在词法结果之上叠加各自门禁。
 * 作者: zhao
 * 创建日期: 2026年10月01日
 * 描述: 从 reviewer.js 拆出（0.8.8 模块化）。splitTopLevelCommands 的转义态
 *       处理是防快速通道绕过的关键（\\ 后跟分隔符是真分隔符），tokenizeSegment
 *       对未闭合引号返回 null 要求调用方降级；isCdSegment 用 mode 参数收敛
 *       原先两套语义漂移的 cd 校验器（fast=快速通道拒绝引号、resolve=附件
 *       解析拒绝通配符但容忍引号）
 * 依赖: 无
 * 更新日期: 2026年10月01日
 */

// 视为"脚本文件"的扩展名集合：解释器调用与裸路径执行都要求命中，防止误读普通数据文件
const SCRIPT_EXTENSIONS = new Set(["sh", "bash", "py", "pyw", "js", "mjs", "cjs", "ts", "rb", "pl", "ps1", "bat", "cmd"]);

// 敏感文件名/扩展名：脚本附件不得读取凭据类文件（防止把 .env、私钥随载荷外送审批渠道）
const SENSITIVE_FILE_PATTERN = /(^|[/\\])(\.env|\.npmrc|\.netrc|\.pypirc|\.aws|\.ssh|\.gnupg|id_rsa|id_ed25519|id_ecdsa)(\.|[/\\]|$)|\.(pem|key|pfx|p12|crt|keystore)([/\\]|$)/i;

// 快速读取不得绕过模型的插件配置、状态与日志文件；这些文件可能包含凭据、端点或审查记录。
const SENSITIVE_RUNTIME_FILE_PATTERN = /(^|[/\\])(?:review_provider|provider_caps|settings|danger_rules|fast_allow|cache|pending_asks)\.json(?:\.old)?$|(^|[/\\])review\.log(?:\.old)?$/i;

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
  const t_text = String(text || "");
  for (let t_i = 0; t_i < t_text.length; t_i++) {
    const t_ch = t_text[t_i];
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
    if (t_ch === "$" && t_text[t_i + 1] === "(") {
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
      // fd 复制后缀（2>&1）里的 & 不是命令边界：前一个字符是 > 说明在重定向目标内，
      // 切走会让 "node x.js 2>&1" 被拆成残段，快速通道与规则逐段全都误判
      if (t_text[t_i - 1] === ">") {
        t_cur += t_ch;
        continue;
      }
      // && 与单个 &（后台执行）均为命令边界
      t_subs.push(t_cur);
      t_cur = "";
      if (t_text[t_i + 1] === "&") t_i++;
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
 * @returns {string[]|null} token 列表；未闭合引号返回 null（调用方必须降级）
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
  // 未闭合引号意味着不同 shell 可能产生不同语义；调用方必须降级，不能把残缺文本当 token。
  if (t_quote) return null;
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
 * 函数功能: 统一的 cd/chdir 段判定（0.8.8 合并原先语义漂移的两套实现）。
 *           mode="resolve"（脚本附件解析）：拒绝通配符/括号等展开形态但容忍引号——
 *           路径还要交给 stat/realpath 验证；mode="fast"（快速通道）：额外拒绝引号
 *           ——快速通道没有 cwd/realpath 上下文，判定只依赖文本本身。
 *           两种模式命中均表示"这是 cd/chdir 段"，由调用方决定拒绝或跟随
 * @param {string[]} tokens - tokenizeSegment 的输出
 * @param {"fast"|"resolve"} [mode] - 判定模式，缺省 resolve
 * @returns {boolean} 是 cd/chdir 段返回 true
 */
function isCdSegment(tokens, mode = "resolve") {
  const t_head = String(tokens[0] || "").toLowerCase();
  if (t_head !== "cd" && t_head !== "chdir") return false;
  const t_args = tokens.slice(1);
  if (t_args.length === 0) return true;
  const t_path_args = String(t_args[0]).toLowerCase() === "/d" ? t_args.slice(1) : t_args;
  if (t_path_args.length !== 1) return false;
  const t_path = String(t_path_args[0]);
  if (!t_path) return false;
  return mode === "fast"
    ? !/[<>|&%$`!"']/.test(t_path)
    : !/[<>|&%$`!?*\[\]{}]/.test(t_path);
}

export {
  SCRIPT_EXTENSIONS,
  SENSITIVE_FILE_PATTERN,
  SENSITIVE_RUNTIME_FILE_PATTERN,
  splitTopLevelCommands,
  tokenizeSegment,
  isScriptPath,
  isCdSegment,
};
