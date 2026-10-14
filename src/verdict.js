/**
 * 模块功能: 审批模型输出合同——从模型原始输出中提取并校验结论 JSON。
 *           独立成小模块供 ctl.js（provider test）复用，避免 CLI 为一个函数
 *           拉入整个决策引擎（0.8.8 模块化）
 * 作者: zhao
 * 创建日期: 2026年10月01日
 * 描述: 自动二值语义：deny 是合法结论（拦截并回传分析），ask 仅作兼容保留。
 *       0.9.0 新增 modified_input：deny 时模型可给"改写后可放行的工具输入"（客户端
 *       3.15.x PreToolUse 支持 updatedInput 改写执行），校验为与原 tool_input 同形态
 *       的平面对象、含脱敏占位符或非字符串值一律拒绝。
 *       校验覆盖：总输出长度、decision 枚举（思考对象带非法 decision 立即失败，
 *       无 decision 的思考对象跳过）、多个合法结论冲突即失败、字段类型与
 *       4096 字符长度上限、risks 数组上限 8 条
 * 依赖: node:无 ./redaction.js ./decision.js
 * 更新日期: 2026年10月14日
 */

import { redactSecrets, MAX_REDACTION_CHARS } from "./redaction.js";
import { ACTION_ALLOW, ACTION_ASK, ACTION_DENY } from "./decision.js";

const MAX_VERDICT_FIELD_CHARS = 4096;
// 客户端把 hook 回传的 updatedInput 直接当作工具执行输入：含脱敏占位符的"改写"
// 意味着模型把 <REDACTED> 占位当成了真实值（真实值从未送审），执行即数据外发——
// 0.7.1 提示词已把该占位符列为必须 deny 的数据外发形态，这里在代码层兜底
const REDACTED_PLACEHOLDER = "<REDACTED>";

/**
 * 函数功能: 从模型输出中提取全部平衡的 JSON 对象文本（容忍围栏与前后杂文）。
 *           只收集顶层对象——一个对象闭合后跳过其内部继续扫描，嵌套对象不单列；
 *           0.8.4 起按序返回全部候选，供 parseVerdict 择优：模型偶发先吐一段
 *           非结论 JSON（缺 decision）再吐结论时，不能让前者顶掉后者
 * @param {string} text - 模型原始输出
 * @returns {string[]} JSON 对象文本列表（可能为空）
 */
function extractJsonObjects(text) {
  const t_results = [];
  let t_from = 0;
  while (true) {
    const t_start = String(text || "").indexOf("{", t_from);
    if (t_start < 0) {
      break;
    }
    let t_depth = 0;
    let t_in_string = false;
    let t_escaped = false;
    let t_end = -1;
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
          t_end = t_i;
          break;
        }
      }
    }
    if (t_end < 0) {
      break;
    }
    t_results.push(text.slice(t_start, t_end + 1));
    t_from = t_end + 1;
  }
  return t_results;
}

/**
 * 函数功能: 从模型输出中提取平衡的第一个 JSON 对象文本（兼容保留，供测试与诊断）
 * @param {string} text - 模型原始输出
 * @returns {string|null} JSON 对象文本，找不到返回 null
 */
function extractJsonObject(text) {
  const t_all = extractJsonObjects(text);
  return t_all.length > 0 ? t_all[0] : null;
}

/**
 * 函数功能: 校验模型回传的 modified_input——改写输入会被客户端直接执行，比普通
 *           结论字段承担更高的信任责任：必须是平面对象、全部值为有界字符串、
 *           不含脱敏占位符（防止把占位符当真值执行）且总大小有界
 * @param {unknown} value - 结论中的 modified_input 字段
 * @returns {object|null} 合法返回浅拷贝对象；模型未提供或非法返回 null（非法时由调用方记日志）
 */
function sanitizeModifiedInput(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const t_entries = Object.entries(value);
  if (t_entries.length === 0 || t_entries.length > 16) return null;
  const t_out = {};
  for (const [t_key, t_val] of t_entries) {
    if (!t_key || t_key.length > 128) return null;
    if (typeof t_val !== "string" || t_val.length === 0 || t_val.length > MAX_VERDICT_FIELD_CHARS) return null;
    if (t_val.includes(REDACTED_PLACEHOLDER)) return null;
    t_out[t_key] = t_val;
  }
  return t_out;
}

/**
 * 函数功能: 解析并归一化安全子 agent 的审查结论
 * @param {string} llm_text - 模型原始输出
 * @returns {{decision: string, risk_level: string, analysis: string, risks: string[], scope: string, alternative: string, modified_input: object|null}}
 * @throws {Error} 输出不可解析或缺少必需字段
 */
function parseVerdict(llm_text) {
  const t_source = String(llm_text || "");
  if (t_source.length > MAX_REDACTION_CHARS) {
    throw new Error("模型输出超过字符上限");
  }
  const t_candidates = extractJsonObjects(t_source);
  const t_valid = [];
  let t_first_parsed = null;
  for (const t_json_text of t_candidates) {
    let t_obj;
    try {
      t_obj = JSON.parse(t_json_text);
    } catch {
      continue;
    }
    if (!t_obj || typeof t_obj !== "object" || Array.isArray(t_obj)) continue;
    if (!t_first_parsed) t_first_parsed = t_obj;
    if (Object.hasOwn(t_obj, "decision") && ![ACTION_ALLOW, ACTION_ASK, ACTION_DENY].includes(t_obj.decision)) {
      throw new Error("模型输出包含非法 decision 字段");
    }
    if (!Object.hasOwn(t_obj, "decision")) continue;
    t_valid.push(t_obj);
  }
  if (t_valid.length === 0) {
    if (!t_first_parsed) throw new Error("模型输出不是合法 JSON");
    throw new Error(`decision 字段非法: ${redactSecrets(String(t_first_parsed.decision)).slice(0, 80)}`);
  }
  const t_decisions = new Set(t_valid.map((t_obj) => t_obj.decision));
  if (t_decisions.size !== 1) {
    throw new Error("模型输出包含相互冲突的多个合法 decision");
  }
  const t_parsed = t_valid[t_valid.length - 1];
  const t_risk = t_parsed.risk_level;
  if (typeof t_risk !== "string" || !["low", "medium", "high"].includes(t_risk)) {
    throw new Error("risk_level 字段非法");
  }
  if (typeof t_parsed.analysis !== "string" || !t_parsed.analysis.trim() || t_parsed.analysis.length > MAX_VERDICT_FIELD_CHARS) {
    throw new Error("analysis 字段非法");
  }
  if (!Array.isArray(t_parsed.risks) || t_parsed.risks.length > 8 || !t_parsed.risks.every((value) => typeof value === "string" && value.length <= MAX_VERDICT_FIELD_CHARS)) {
    throw new Error("risks 字段非法");
  }
  if (typeof t_parsed.scope !== "string" || !t_parsed.scope.trim() || t_parsed.scope.length > MAX_VERDICT_FIELD_CHARS) {
    throw new Error("scope 字段非法");
  }
  if (typeof t_parsed.alternative !== "string" || t_parsed.alternative.length > MAX_VERDICT_FIELD_CHARS) {
    throw new Error("alternative 字段非法");
  }
  return {
    decision: t_parsed.decision,
    risk_level: t_risk,
    analysis: t_parsed.analysis,
    risks: t_parsed.risks,
    scope: t_parsed.scope,
    alternative: t_parsed.alternative,
    // deny 时的改写放行候选：非法形态归 null，由调用方决定是否回传分析要求人工改写
    modified_input: Object.hasOwn(t_parsed, "modified_input") ? sanitizeModifiedInput(t_parsed.modified_input) : null,
  };
}

/**
 * 函数功能: 拼装展示用/回传主 agent 的 reason（分析 + 风险点 + 影响范围 + 替代方案）
 * @param {object} verdict - parseVerdict 的返回值
 * @returns {string} 多行 reason 文本
 */
function formatVerdictReason(verdict) {
  const t_lines = [
    `[auto-review] 风险级别 ${verdict.risk_level}: ${redactSecrets(verdict.analysis).slice(0, 200)}`,
  ];
  if (verdict.risks.length > 0) {
    t_lines.push("风险点:");
    for (const t_risk of verdict.risks) {
      t_lines.push(`- ${redactSecrets(t_risk).slice(0, 200)}`);
    }
  }
  t_lines.push(`影响范围: ${redactSecrets(verdict.scope).slice(0, 240)}`);
  if (verdict.alternative) {
    t_lines.push(`替代方案: ${redactSecrets(verdict.alternative).slice(0, 240)}`);
  }
  return t_lines.join("\n");
}

export {
  MAX_VERDICT_FIELD_CHARS,
  extractJsonObjects,
  extractJsonObject,
  parseVerdict,
  formatVerdictReason,
  sanitizeModifiedInput,
};
