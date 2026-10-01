/**
 * 模块功能: 全局配置中心——数据目录、路径常量、统一日志与原子写工具
 * 作者: zhao
 * 创建日期: 2026年08月29日
 * 描述: 集中管理插件全部路径常量与跨模块共用的工具函数；
 *       测试可通过 AUTO_REVIEW_DATA_DIR 环境变量重定向数据目录，避免污染真实用户数据
 * 功能:
 *   - 数据目录定位与按需创建
 *   - 审查日志（带轮转）写入
 *   - JSON 文件防御式读取与原子写（临时文件 + rename，避免半截文件）
 *   - 两层 hook 共享的 stdin 读取/JSON 解析/调试日志（0.8.8 从入口下沉）
 * 依赖: node:os node:path node:fs node:url
 * 更新日期: 2026年10月01日
 */

import os from "node:os";
import path from "node:path";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import { redactSecrets } from "./redaction.js";

// 插件名，用于目录与日志标识
const PLUGIN_NAME = "auto-review";

// 源码目录向上即插件根目录（marketplace 缓存运行时同样成立）
const SRC_DIR = fileURLToPath(new URL(".", import.meta.url));
const PLUGIN_ROOT = path.resolve(SRC_DIR, "..");

// 统一数据目录：hook 进程与主 agent 侧命令都能确定性推出该路径
const g_data_dir = process.env.AUTO_REVIEW_DATA_DIR
  ? path.resolve(process.env.AUTO_REVIEW_DATA_DIR)
  : path.join(os.homedir(), ".zcode", PLUGIN_NAME);

// 数据目录内各文件路径
const SETTINGS_FILE = () => path.join(g_data_dir, "settings.json");
const DANGER_RULES_FILE = () => path.join(g_data_dir, "danger_rules.json");
const SECURITY_PROMPT_FILE = () => path.join(g_data_dir, "security_prompt.md");
const CACHE_FILE = () => path.join(g_data_dir, "cache.json");
const LOG_FILE = () => path.join(g_data_dir, "review.log");
// 专用审批渠道配置（用户手填：base_url/api_key/api_kind/model），审批的唯一 LLM 来源
const REVIEW_PROVIDER_FILE = () => path.join(g_data_dir, "review_provider.json");
// 快速通道白名单（只读命令，命中即 0 LLM 放行）
const FAST_ALLOW_FILE = () => path.join(g_data_dir, "fast_allow.json");
// PreToolUse 转人工(ask)时留下的短时标记：PermissionRequest hook 看到新鲜标记即退避，
// 防"模型不可用→人工"的既定路径被第二层 hook 翻转为自动放行
const PENDING_ASKS_FILE = () => path.join(g_data_dir, "pending_asks.json");
// 渠道能力探测状态（0.8.5：response_format json_object 是否被审批渠道接受；
// auto 模式自动维护，7 天过期重新探测）
const PROVIDER_CAPS_FILE = () => path.join(g_data_dir, "provider_caps.json");

// 出厂默认配置（只读回落源，位于插件包内）
const DEFAULT_SETTINGS_FILE = path.join(PLUGIN_ROOT, "config", "default_settings.json");
const DEFAULT_DANGER_RULES_FILE = path.join(PLUGIN_ROOT, "config", "default_danger_rules.json");
const DEFAULT_SECURITY_PROMPT_FILE = path.join(PLUGIN_ROOT, "config", "default_security_prompt.md");
const DEFAULT_FAST_ALLOW_FILE = path.join(PLUGIN_ROOT, "config", "default_fast_allow.json");

// 日志轮转阈值：超过则把旧日志改名为 .old 重新起笔，防止日志无限增长
const MAX_LOG_BYTES = 512 * 1024;
// 配置/状态 JSON 文件硬上限：避免异常大文件进入 JSON.parse、规则编译或脱敏路径
const MAX_JSON_FILE_BYTES = 2 * 1024 * 1024;
const MAX_STDIN_BYTES = 1024 * 1024;

// 日志/展示中的预览长度上限：避免单条日志或载荷元数据过长
const LOG_PREVIEW_CHARS = 120;

// 日志级别到标识的映射，统一"时间戳[级别][模块] 内容"格式
const LOG_LEVEL_TAGS = { INFO: "INFO", WARN: "WARN", ERROR: "ERROR" };

/**
 * 函数功能: 获取数据目录（不存在则创建）
 * @returns {string} 数据目录绝对路径
 */
function getDataDir() {
  fs.mkdirSync(g_data_dir, { recursive: true });
  return g_data_dir;
}

/**
 * 函数功能: 追加一条审查日志，超限时轮转
 * @param {string} level - 日志级别 INFO/WARN/ERROR
 * @param {string} moduleName - 模块标识（rule/cache/llm/settings/fallback 等）
 * @param {string} message - 日志内容（不得包含密钥等敏感信息）
 * @returns {void}
 */
function logWrite(level, moduleName, message) {
  const t_log_file = LOG_FILE();
  const t_tag = LOG_LEVEL_TAGS[level] || "INFO";
  // 预算与 appendLogLine 的单行 4096 字节上限对齐（留出时间戳/级别前缀余量），
  // 超长内容在整行截断时只会截到消息尾部
  const t_message = redactSecrets(String(message || "").slice(0, 3600));
  const t_line = `[${new Date().toISOString()}][${t_tag}][${moduleName}] ${t_message}\n`;
  try {
    appendLogLine(t_log_file, t_line);
  } catch {
    // 目录尚不存在（首次运行）时补建目录再试一次；仍失败则静默——日志不能拖垮审查决策
    try {
      fs.mkdirSync(path.dirname(t_log_file), { recursive: true });
      appendLogLine(t_log_file, t_line);
    } catch { /* 放弃本条日志 */ }
  }
}

/**
 * 函数功能: 追加一行日志并在超过阈值时轮转（rename 失败如被占用则继续追加）
 * @param {string} log_file - 日志文件路径
 * @param {string} line - 已格式化的整行文本
 * @returns {void}
 */
function appendLogLine(log_file, line) {
  const t_line = Buffer.from(String(line || "").slice(0, 4096), "utf8");
  let t_size = 0;
  try {
    if (fs.existsSync(log_file)) t_size = fs.statSync(log_file).size;
  } catch {
    t_size = MAX_LOG_BYTES;
  }
  if (t_size + t_line.byteLength > MAX_LOG_BYTES) {
    try {
      fs.renameSync(log_file, log_file + ".old");
      t_size = 0;
    } catch {
      try {
        fs.unlinkSync(log_file + ".old");
        fs.renameSync(log_file, log_file + ".old");
        t_size = 0;
      } catch {
        return;
      }
    }
  }
  fs.appendFileSync(log_file, t_line);
}

/**
 * 函数功能: 从同一文件句柄读取有字节上限的普通文本文件。
 * @param {string} file_path - 文件路径
 * @param {number} max_bytes - 最大字节数
 * @returns {string} UTF-8 文本
 */
function readTextFileBounded(file_path, max_bytes = MAX_JSON_FILE_BYTES) {
  if (!Number.isSafeInteger(max_bytes) || max_bytes < 1) throw new Error("无效文件读取上限");
  const t_fd = fs.openSync(file_path, "r");
  try {
    const t_stat = fs.fstatSync(t_fd);
    if (!t_stat.isFile()) throw new Error("不是普通文件");
    if (t_stat.size > max_bytes) throw new Error(`文件超过 ${max_bytes} 字节上限`);
    const t_buffer = Buffer.alloc(Math.min(max_bytes + 1, 65536));
    const t_chunks = [];
    let t_bytes = 0;
    while (true) {
      const t_count = fs.readSync(t_fd, t_buffer, 0, Math.min(t_buffer.length, max_bytes + 1 - t_bytes), null);
      if (t_count === 0) break;
      t_bytes += t_count;
      if (t_bytes > max_bytes) throw new Error(`文件超过 ${max_bytes} 字节上限`);
      t_chunks.push(Buffer.from(t_buffer.subarray(0, t_count)));
    }
    return Buffer.concat(t_chunks, t_bytes).toString("utf8");
  } finally {
    fs.closeSync(t_fd);
  }
}

function readStdinBounded(input = process.stdin) {
  return new Promise((resolve, reject) => {
    const t_chunks = [];
    let t_bytes = 0;
    let t_done = false;
    const t_data = (chunk) => {
      if (t_done) return;
      const t_buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
      t_bytes += t_buffer.byteLength;
      if (t_bytes > MAX_STDIN_BYTES) {
        t_done = true;
        input.removeListener("data", t_data);
        input.removeListener("end", t_end);
        input.removeListener("error", t_error);
        input.pause();
        resolve({ text: "", tooLarge: true, bytes: t_bytes });
        return;
      }
      t_chunks.push(t_buffer);
    };
    const t_end = () => {
      if (t_done) return;
      t_done = true;
      input.removeListener("data", t_data);
      input.removeListener("error", t_error);
      resolve({ text: Buffer.concat(t_chunks).toString("utf8"), tooLarge: false, bytes: t_bytes });
    };
    const t_error = (error) => {
      if (t_done) return;
      t_done = true;
      input.removeListener("data", t_data);
      input.removeListener("end", t_end);
      reject(error);
    };
    input.on("data", t_data);
    input.once("end", t_end);
    input.once("error", t_error);
  });
}

/**
 * 函数功能: 两层 hook 共享的 stdin 读取与 JSON 解析（0.8.8 从两个入口下沉）。
 *           只做形态判定不做决策：超限/为空/非法 JSON/非对象由调用方按各自
 *           协议处置（PreToolUse 阻断，PermissionRequest 退避）
 * @param {string} tag - 日志模块标识（"hook" / "permission"）
 * @returns {Promise<{status: "ok"|"tooLarge"|"empty"|"invalid"|"notObject", input?: object}>}
 */
async function readHookJsonInput(tag) {
  const t_stdin = await readStdinBounded();
  if (t_stdin.tooLarge) {
    logWrite("WARN", tag, `stdin 超过 ${MAX_STDIN_BYTES} 字节上限`);
    return { status: "tooLarge" };
  }
  if (!t_stdin.text.trim()) {
    logWrite("WARN", tag, "stdin 为空");
    return { status: "empty" };
  }
  let t_input;
  try {
    t_input = JSON.parse(t_stdin.text);
  } catch {
    logWrite("WARN", tag, "stdin 非合法 JSON");
    return { status: "invalid" };
  }
  if (!t_input || typeof t_input !== "object" || Array.isArray(t_input)) {
    logWrite("WARN", tag, "stdin JSON 不是对象");
    return { status: "notObject" };
  }
  return { status: "ok", input: t_input };
}

/**
 * 函数功能: 调试开关下的 hook 输入字段摘要（AUTO_REVIEW_DEBUG=1 时调用）。
 *           记录顶层字段名与非敏感值形态，用于适配客户端实际下发的字段；
 *           载荷本体（tool_input）只记类型不记内容
 * @param {string} tag - 日志模块标识（"debug-input" / "debug-permission-input"）
 * @param {object} input - hook stdin 解析出的对象
 * @returns {void}
 */
function logHookInputFields(tag, input) {
  if (!process.env.AUTO_REVIEW_DEBUG) {
    return;
  }
  const t_fields = {};
  for (const [t_key, t_value] of Object.entries(input)) {
    t_fields[t_key] = t_key === "tool_input"
      ? `<${typeof t_value}>`
      : typeof t_value === "string" ? redactSecrets(t_value).slice(0, 120) : `<${typeof t_value}>`;
  }
  logWrite("INFO", tag, JSON.stringify(t_fields));
}

function readJsonFile(file_path, fallback, moduleName) {
  try {
    const t_raw = readTextFileBounded(file_path);
    // PowerShell 写入的 UTF-8 BOM 不属于 JSON 数据。
    return JSON.parse(t_raw.replace(/^\uFEFF/, ""));
  } catch (t_error) {
    if (t_error.code !== "ENOENT" && moduleName) {
      logWrite("WARN", moduleName, `读取 ${path.basename(file_path)} 失败: ${t_error.message}，使用回落值`);
    }
    return fallback;
  }
}

// 原子写临时文件的进程内序号：并发写同一目标时（多 hook 进程/同进程多次写）
// 固定临时名会让两个写者互相覆盖 .tmp 甚至 rename 到半截内容
let g_tmp_seq = 0;

/**
 * 函数功能: 原子写文件（先写本进程专属临时文件再 rename），保证读者不会看到半截内容
 * @param {string} file_path - 目标文件路径
 * @param {string} content - 写入内容
 * @returns {boolean} 是否写入成功
 */
function writeFileAtomic(file_path, content) {
  const t_tmp_path = `${file_path}.${process.pid}.${g_tmp_seq++}.tmp`;
  try {
    fs.mkdirSync(path.dirname(file_path), { recursive: true });
    fs.writeFileSync(t_tmp_path, content, "utf8");
    fs.renameSync(t_tmp_path, file_path);
    return true;
  } catch (t_error) {
    logWrite("WARN", "common", `原子写 ${path.basename(file_path)} 失败: ${t_error.message}`);
    try { fs.unlinkSync(t_tmp_path); } catch { /* 临时文件本就不存在，无需处理 */ }
    return false;
  }
}

// 持锁超过该时长视为持有者已死（进程被杀/崩溃），强行接管锁文件
const FILE_LOCK_STALE_MS = 10 * 1000;

/**
 * 函数功能: 同步休眠（Atomics.wait 阻塞当前线程，供锁自旋等待使用）
 * @param {number} ms - 休眠毫秒数
 * @returns {void}
 */
function syncSleep(ms) {
  try {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
  } catch { /* 环境不支持时跳过休眠，由超时上限兜底 */ }
}

/**
 * 函数功能: 进程间文件锁——并发 hook 进程同时读改写同一 JSON（缓存文件）时，
 *           避免各自的"读-改-写"互相覆盖丢条目。独占创建 lock 文件（wx）+ 短自旋等待；
 *           锁无法创建或等待超时直接放弃本次持久化，不降级为无锁写入——
 *           无锁写会让并发读改写互相覆盖，损坏缓存状态后影响后续放行判断；
 *           持锁过久按持有者已死强行接管
 * @param {string} lock_path - 锁文件路径（通常为 目标文件 + ".lock"）
 * @param {Function} fn - 持锁期间执行的临界区函数（同步）
 * @param {number} [timeout_ms] - 等待获取锁的上限，默认 1500ms
 * @returns {*} fn 的返回值；无法获得锁时返回 undefined
 */
function withFileLock(lock_path, fn, timeout_ms = 1500) {
  const t_start = Date.now();
  let t_fd = null;
  while (true) {
    try {
      t_fd = fs.openSync(lock_path, "wx");
      break;
    } catch (t_error) {
      if (t_error.code !== "EEXIST") {
        logWrite("WARN", "lock", `无法创建锁文件 ${path.basename(lock_path)}: ${t_error.message}，放弃本次持久化`);
        return undefined;
      }
      try {
        if (Date.now() - fs.statSync(lock_path).mtimeMs > FILE_LOCK_STALE_MS) {
          fs.unlinkSync(lock_path); // 过期锁强行接管；unlink 失败则继续等待
          continue;
        }
      } catch { /* stat 失败说明锁刚好被释放，下一轮直接尝试创建 */ }
      if (Date.now() - t_start > timeout_ms) {
        logWrite("WARN", "lock", `等待锁文件 ${path.basename(lock_path)} 超时，放弃本次持久化`);
        return undefined;
      }
      syncSleep(15);
    }
  }
  try {
    return fn();
  } finally {
    try { fs.closeSync(t_fd); } catch { /* 句柄已关闭 */ }
    try { fs.unlinkSync(lock_path); } catch { /* 删除失败留给过期接管兜底 */ }
  }
}

export {
  getDataDir,
  SETTINGS_FILE,
  DANGER_RULES_FILE,
  SECURITY_PROMPT_FILE,
  CACHE_FILE,
  REVIEW_PROVIDER_FILE,
  FAST_ALLOW_FILE,
  PENDING_ASKS_FILE,
  PROVIDER_CAPS_FILE,
  DEFAULT_SETTINGS_FILE,
  DEFAULT_DANGER_RULES_FILE,
  DEFAULT_SECURITY_PROMPT_FILE,
  DEFAULT_FAST_ALLOW_FILE,
  LOG_PREVIEW_CHARS,
  MAX_JSON_FILE_BYTES,
  logWrite,
  readJsonFile,
  readTextFileBounded,
  readHookJsonInput,
  logHookInputFields,
  writeFileAtomic,
  withFileLock,
};
