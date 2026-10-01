/**
 * 模块功能: 脚本附件——从 Bash 命令中提取脚本文件引用并按安全边界读取内容，
 *           构造随载荷送审的附件；同时提供动态执行命令判定（缓存资格依据）
 * 作者: zhao
 * 创建日期: 2026年10月01日
 * 描述: 从 reviewer.js 拆出（0.8.8 模块化）。边界约束：realpath 必须位于 cwd 内
 *       （无 cwd 时只接受进程 cwd 内）、拒绝 symlink 与敏感凭据文件——附件通道
 *       不能被用来读取项目外文件或把密钥外送审批渠道；附件总预算与工具调用
 *       JSON 共用 max_payload_chars。读取用同一文件句柄 fstat 复核（O_NOFOLLOW
 *       + dev/ino 比对），stat 后文件被替换/增长不会绕过单文件上限
 * 依赖: node:fs node:os node:path ./shell_lex.js ./fast_allow.js ./common.js ./redaction.js
 * 更新日期: 2026年10月01日
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { LOG_PREVIEW_CHARS, logWrite } from "./common.js";
import { redactSecrets } from "./redaction.js";
import { SENSITIVE_FILE_PATTERN, tokenizeSegment, isScriptPath, isCdSegment, splitTopLevelCommands } from "./shell_lex.js";
import { FAST_WRAPPER_HEADS, FAST_VERSION_ARGS } from "./fast_allow.js";

// 脚本送审的单次命令最多附加文件数：控制载荷规模，超出部分以附注说明
const MAX_SCRIPT_FILES = 3;

// 命中即放弃该命令段的脚本提取：-c/-e 的代码已内联在命令文本里，-m 引用的是模块而非文件路径
const SCRIPT_INLINE_FLAGS = new Set(["-c", "-e", "-m", "--command", "--eval", "--module"]);

// 可带脚本文件参数的解释器名单（powershell 走 -File 特判，cmd 走 /c、/k 特判）
const SCRIPT_INTERPRETERS = new Set(["python", "python3", "py", "node", "deno", "bun", "bash", "sh", "zsh", "dash", "ruby", "perl", "pwsh"]);

// 解释器选项表：值区分大小写（python -W/-X/-B 与小写形态语义不同）；arity=1 表示
// 选项后跟一个参数。未知拼写一律按动态处理交模型，不能靠小写化"猜中"白名单
const SCRIPT_OPTION_ARITY = new Map([
  ["--require", 1], ["-r", 1], ["--loader", 1], ["--experimental-loader", 1], ["--import", 1],
  ["--eval", 1], ["-e", 1], ["--print", 1], ["-p", 1], ["-c", 1], ["--command", 1],
  ["-m", 1], ["--module", 1], ["-W", 1], ["-X", 1], ["--check-hash-based-pycs", 1],
  ["--input-type", 1], ["--conditions", 1], ["--inspect", 0], ["--inspect-brk", 0], ["--watch", 0],
  ["--watch-path", 1], ["--trace-warnings", 0], ["--no-warnings", 0], ["--version", 0], ["-u", 0],
  ["-3", 0], ["-B", 0], ["-E", 0], ["-I", 0], ["-O", 0], ["-OO", 0], ["-q", 0], ["-s", 0],
  ["-S", 0], ["-v", 0], ["-V", 0], ["--debug", 0], ["--help", 0],
]);

function extractRefsFromSegment(tokens) {
  const t_head = String(tokens[0] || "").replace(/\\/g, "/").split("/").pop().toLowerCase().replace(/\.exe$/, "");
  if (t_head === "powershell" || t_head === "pwsh") {
    for (let t_i = 1; t_i < tokens.length; t_i++) {
      if (tokens[t_i].toLowerCase() === "-file") {
        const t_ref = tokens[t_i + 1];
        return t_ref && isScriptPath(t_ref)
          ? { refs: [t_ref], complete: true }
          : { refs: [], complete: false };
      }
      if (/^-command$/i.test(tokens[t_i]) || /^-encodedcommand$/i.test(tokens[t_i])) {
        return { refs: [], complete: false, dynamic: true };
      }
    }
    return { refs: [], complete: true };
  }
  if (t_head === "cmd") {
    for (let t_i = 1; t_i < tokens.length; t_i++) {
      const t_flag = tokens[t_i].toLowerCase();
      if (t_flag === "/c" || t_flag === "/k") {
        const t_ref = tokens[t_i + 1];
        return t_ref && isScriptPath(t_ref)
          ? { refs: [t_ref], complete: true }
          : { refs: [], complete: false, dynamic: true };
      }
    }
    return { refs: [], complete: true };
  }
  if (isScriptPath(tokens[0])) return { refs: [tokens[0]], complete: true };
  if (!SCRIPT_INTERPRETERS.has(t_head)) return { refs: [], complete: true };

  const t_refs = [];
  let t_script_seen = false;
  for (let t_i = 1; t_i < tokens.length; t_i++) {
    const t_token = tokens[t_i];
    if (t_script_seen) continue;
    const t_lower = t_token.toLowerCase();
    if (t_token.startsWith("-")) {
      // 解释器选项区分大小写（python -W/-X/-B 与小写形态语义不同）；
      // 未知拼写一律按动态处理交模型，不能靠小写化"猜中"白名单。
      const t_option = t_token.split("=", 1)[0];
      if (SCRIPT_INLINE_FLAGS.has(t_lower) || SCRIPT_INLINE_FLAGS.has(t_option.toLowerCase())) {
        return { refs: [], complete: false, dynamic: true };
      }
      const t_arity = SCRIPT_OPTION_ARITY.has(t_option) ? SCRIPT_OPTION_ARITY.get(t_option) : undefined;
      if (t_arity === undefined) return { refs: [], complete: false, dynamic: true };
      if (t_arity === 1) {
        if (t_lower.includes("=")) {
          const t_value = t_token.slice(t_token.indexOf("=") + 1);
          if (isScriptPath(t_value)) t_refs.push(t_value);
        } else {
          const t_value = tokens[++t_i];
          if (!t_value) return { refs: [], complete: false, dynamic: true };
          if (isScriptPath(t_value) && (t_option === "--require" || t_option === "-r" || t_option === "--loader" || t_option === "--import" || t_option === "--experimental-loader")) {
            t_refs.push(t_value);
          }
        }
      }
      continue;
    }
    if (isScriptPath(t_token)) {
      t_refs.push(t_token);
      t_script_seen = true;
      continue;
    }
    if (t_refs.length > 0) {
      // Arguments after a proven script entry point do not change which file
      // is inspected; keep the entry point and stop parsing positional args.
      t_script_seen = true;
      continue;
    }
    // A non-script positional token before an entry point is a module/name or
    // an interpreter-specific mode we cannot safely resolve.
    return { refs: [], complete: false, dynamic: true };
  }
  return { refs: t_refs, complete: true };
}

function extractScriptRefsDetailed(command, cwd) {
  const t_base = path.resolve(String(cwd || "").trim() || process.cwd());
  let t_current = t_base;
  let t_complete = true;
  let t_dynamic = false;
  const t_refs = [];
  const t_seen = new Set();
  const t_segments = splitTopLevelCommands(String(command || ""));
  for (const t_segment of t_segments) {
    const t_tokens = tokenizeSegment(t_segment);
    if (!t_tokens || t_tokens.length === 0) {
      t_complete = false;
      continue;
    }
    const t_head = String(t_tokens[0] || "").toLowerCase();
    if (t_head === "cd" || t_head === "chdir") {
      if (!isCdSegment(t_tokens, "resolve")) {
        t_complete = false;
        t_dynamic = true;
        continue;
      }
      const t_args = t_tokens.slice(1);
      const t_ref = t_args[0] && t_args[0].toLowerCase() === "/d" ? t_args[1] : t_args[0];
      const t_next = t_ref ? path.resolve(t_current, expandTilde(t_ref)) : t_current;
      try {
        const t_stat = fs.statSync(t_next);
        if (!t_stat.isDirectory()) throw new Error("cd 目标不是目录");
        t_current = fs.realpathSync(t_next);
      } catch {
        t_complete = false;
        t_dynamic = true;
      }
      continue;
    }
    const t_result = extractRefsFromSegment(t_tokens);
    if (!t_result.complete) {
      t_complete = false;
      t_dynamic = t_dynamic || Boolean(t_result.dynamic);
    }
    for (const t_ref of t_result.refs) {
      const t_key = `${t_current}\n${t_ref}`;
      if (!t_seen.has(t_key)) {
        t_seen.add(t_key);
        t_refs.push({ ref: t_ref, base_dir: t_current });
      }
    }
  }
  // A directory change followed by a conditional alternative has shell-state
  // dependent results; do not claim attachment completeness for that shape.
  if (/\b(?:cd|chdir)\b[^;&|]*(?:\|\||\||;|&)/i.test(command) && !/\b(?:cd|chdir)\b[^;&|]*&&/i.test(command)) {
    t_complete = false;
    t_dynamic = true;
  }
  return { refs: t_refs, complete: t_complete, dynamic: t_dynamic };
}

function isDynamicExecutionCommand(command) {
  for (const t_segment of splitTopLevelCommands(String(command || ""))) {
    const t_tokens = tokenizeSegment(t_segment);
    if (!t_tokens || t_tokens.length === 0) return true;
    const t_raw_head = String(t_tokens[0] || "").toLowerCase();
    const t_head = t_raw_head.replace(/\.exe$/, "");
    if (t_head === "cd" || t_head === "chdir" || FAST_WRAPPER_HEADS.has(t_head)) return true;
    if (SCRIPT_INTERPRETERS.has(t_head) || /(?:^|[\\/])(?:python(?:3)?|py|node|deno|bun|bash|sh|zsh|dash|ruby|perl|pwsh)(?:\.exe)?$/i.test(t_tokens[0])) {
      const t_arg = String(t_tokens[1] || "").toLowerCase();
      if (!(t_tokens.length === 2 && FAST_VERSION_ARGS.has(t_arg))) return true;
    }
    if (/^(npm|pnpm|yarn)$/.test(t_head) && /^(run|exec|dlx|node|test|start|build)$/.test(String(t_tokens[1] || "").toLowerCase())) return true;
    if (t_tokens.some((t_token) => isScriptPath(t_token))) return true;
  }
  return false;
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
 * @returns {{files: Array<{ref: string, path: string, content: string, truncated: boolean, total_bytes: number}>, notes: string[], complete: boolean, cacheable: boolean}|null}
 *          附件对象；无任何引用或整体异常返回 null
 */
function collectScriptAttachments(command, cwd, settings) {
  try {
    const t_ref_info = extractScriptRefsDetailed(command, cwd);
    const t_refs = t_ref_info.refs;
    if (t_refs.length === 0 && t_ref_info.complete) {
      return null;
    }
    const t_max_bytes = Math.max(1, Number(settings && settings.script_max_bytes) || 16000);
    const t_total_budget = Math.max(500, Number(settings && settings.max_payload_chars) || 8000);
    let t_used_chars = 0;
    const t_base_dir = String(cwd || "").trim() || process.cwd();
    const t_base_real = fs.realpathSync(t_base_dir);
    const t_files = [];
    const t_notes = [];
    let t_complete = t_ref_info.complete;
    if (!t_ref_info.complete) {
      t_notes.push("脚本入口或工作目录无法完整解析，未猜测其余附件");
    }
    let attempted = 0;
    for (const t_ref_info_item of t_refs) {
      if (attempted++ >= MAX_SCRIPT_FILES) {
        t_notes.push(`引用脚本超过 ${MAX_SCRIPT_FILES} 个，其余未附加`);
        t_complete = false;
        break;
      }
      const t_ref = t_ref_info_item.ref;
      const t_ref_base = path.resolve(t_ref_info_item.base_dir || t_base_real);
      if (!isInsideDir(t_ref_base, t_base_real)) {
        t_notes.push(`${t_ref}: 解析后的工作目录越出原始工作目录，未附加`);
        t_complete = false;
        continue;
      }
      if (SENSITIVE_FILE_PATTERN.test(t_ref.replace(/\\/g, "/"))) {
        t_notes.push(`${t_ref}: 凭据类敏感文件，未附加`);
        t_complete = false;
        continue;
      }
      const t_full = path.resolve(t_ref_base, expandTilde(t_ref));
      try {
        const t_lstat = fs.lstatSync(t_full);
        if (t_lstat.isSymbolicLink()) {
          t_notes.push(`${t_ref}: 符号链接，未附加`);
          t_complete = false;
          continue;
        }
        const t_real = fs.realpathSync(t_full);
        if (!isInsideDir(t_real, t_base_real)) {
          t_notes.push(`${t_ref}: 解析后越出工作目录，未附加`);
          t_complete = false;
          continue;
        }
        if (SENSITIVE_FILE_PATTERN.test(t_full) || SENSITIVE_FILE_PATTERN.test(t_real)) {
          t_notes.push(`${t_ref}: 凭据类敏感文件，未附加`);
          t_complete = false;
          continue;
        }
        const t_stat = fs.statSync(t_real);
        if (!t_stat.isFile()) {
          t_notes.push(`${t_ref}: 非普通文件，未附加`);
          t_complete = false;
          continue;
        }
        const t_read_cap = Math.min(t_max_bytes, t_total_budget - t_used_chars);
        if (t_read_cap <= 0) {
          t_notes.push("附件总大小已达载荷预算（max_payload_chars），其余未附加");
          t_complete = false;
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
        if (t_content.slice(0, 8192).includes("\0")) {
          t_notes.push(`${t_ref}: 二进制文件，未附加`);
          t_complete = false;
          continue;
        }
        if (t_truncated) t_complete = false;
        t_files.push({ ref: t_ref, path: t_real, content: t_content, truncated: t_truncated, total_bytes: t_stat.size });
      } catch (t_error) {
        logWrite("WARN", "script", `读取脚本失败 ${t_ref}: ${t_error.message}`);
        t_notes.push(`${t_ref}: 无法读取，未附加`);
        t_complete = false;
      }
    }
    if (t_files.length === 0 && t_notes.length === 0) {
      return null;
    }
    logWrite("INFO", "script", `脚本送审 ${t_files.length} 个文件: ${t_files.map((t_f) => t_f.ref).join("、").slice(0, LOG_PREVIEW_CHARS) || "(全部失败)"}`);
    return { files: t_files, notes: t_notes, complete: t_complete, cacheable: t_complete };
  } catch (t_error) {
    logWrite("WARN", "script", `脚本附加异常: ${redactSecrets(t_error.message)}`);
    return { files: [], notes: ["脚本附加失败，内容不完整"], complete: false, cacheable: false };
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

export {
  extractScriptRefsDetailed,
  collectScriptAttachments,
  isDynamicExecutionCommand,
};
