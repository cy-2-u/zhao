/**
 * 模块功能: 全局配置中心——数据目录、路径常量、统一日志与原子写工具
 * 作者: hh-zyb
 * 创建日期: 2026年08月29日
 * 描述: 集中管理插件全部路径常量与跨模块共用的工具函数；
 *       测试可通过 AUTO_REVIEW_DATA_DIR 环境变量重定向数据目录，避免污染真实用户数据
 * 功能:
 *   - 数据目录定位与按需创建
 *   - 审查日志（带轮转）写入
 *   - JSON 文件防御式读取与原子写（临时文件 + rename，避免半截文件）
 * 依赖: node:os node:path node:fs node:url
 * 更新日期: 2026年09月16日
 */

import os from "node:os";
import path from "node:path";
import fs from "node:fs";
import { fileURLToPath } from "node:url";

// 插件名，用于目录与日志标识
const PLUGIN_NAME = "auto-review";

// 源码目录向上即插件根目录（marketplace 缓存运行时同样成立）
const SRC_DIR = fileURLToPath(new URL(".", import.meta.url));
const PLUGIN_ROOT = path.resolve(SRC_DIR, "..");

// 统一数据目录：hook 进程与主 agent 侧命令都能确定性推出该路径（方案见 docs/project_plan/04）
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

// 出厂默认配置（只读回落源，位于插件包内）
const DEFAULT_SETTINGS_FILE = path.join(PLUGIN_ROOT, "config", "default_settings.json");
const DEFAULT_DANGER_RULES_FILE = path.join(PLUGIN_ROOT, "config", "default_danger_rules.json");
const DEFAULT_SECURITY_PROMPT_FILE = path.join(PLUGIN_ROOT, "config", "default_security_prompt.md");
const DEFAULT_FAST_ALLOW_FILE = path.join(PLUGIN_ROOT, "config", "default_fast_allow.json");

// 日志轮转阈值：超过则把旧日志改名为 .old 重新起笔，防止日志无限增长
const MAX_LOG_BYTES = 512 * 1024;

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
  const t_line = `[${new Date().toISOString()}][${t_tag}][${moduleName}] ${message}\n`;
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
  if (fs.existsSync(log_file) && fs.statSync(log_file).size > MAX_LOG_BYTES) {
    try {
      fs.renameSync(log_file, log_file + ".old");
    } catch {
      // 旧 .old 被占用等导致改名失败：删掉旧轮转文件再试一次；
      // 仍失败则保留原文件继续追加——轮转失败不能变成后续日志全部丢失
      try {
        fs.unlinkSync(log_file + ".old");
        fs.renameSync(log_file, log_file + ".old");
      } catch { /* 继续向原文件追加 */ }
    }
  }
  fs.appendFileSync(log_file, line, "utf8");
}

/**
 * 函数功能: 防御式读取 JSON 文件
 * @param {string} file_path - 文件路径
 * @param {*} fallback - 读取失败或解析失败时的返回值
 * @param {string} moduleName - 记日志用的模块标识
 * @returns {*} 解析后的 JSON 值或 fallback
 */
function readJsonFile(file_path, fallback, moduleName) {
  try {
    const t_raw = fs.readFileSync(file_path, "utf8");
    // 剥 UTF-8 BOM：PowerShell Set-Content -Encoding UTF8 恒写 BOM，不剥会导致 JSON.parse 失败静默回落默认值
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
  DEFAULT_SETTINGS_FILE,
  DEFAULT_DANGER_RULES_FILE,
  DEFAULT_SECURITY_PROMPT_FILE,
  DEFAULT_FAST_ALLOW_FILE,
  logWrite,
  readJsonFile,
  writeFileAtomic,
  withFileLock,
};
