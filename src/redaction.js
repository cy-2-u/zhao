/**
 * 模块功能: 有界脱敏——不可信文本与 JSON 值中的常见凭据形态替换为占位符。
 * 作者: zhao
 * 创建日期: 2026年09月30日
 * 描述: 逐字符线性扫描 key/value，不依赖可能造成 ReDoS 的复杂回溯正则；
 *       总预算 200000 字符，超限带显式截断标记。redactSecrets 只在输入看起来
 *       是完整 JSON 且不超预算时先走结构化路径（对象键脱敏），否则回落文本扫描
 * 依赖: 无
 * 更新日期: 2026年10月01日
 */

const MAX_REDACTION_CHARS = 200000;
const REDACTED = "<REDACTED>";
const TRUNCATED = "\n<REDACTED_INPUT_TRUNCATED>";
const SENSITIVE_KEY_PATTERN = /api[_-]?key|token|secret|password|passwd|pwd|authorization|credential|private[_-]?key/i;

function isKeyChar(char) {
  if (!char) return false;
  const code = char.charCodeAt(0);
  return (code >= 65 && code <= 90) || (code >= 97 && code <= 122)
    || (code >= 48 && code <= 57) || char === "_" || char === "-";
}

function redactText(text) {
  const original = String(text ?? "");
  const input = original.slice(0, MAX_REDACTION_CHARS);
  const parts = [];
  let cursor = 0;
  let index = 0;
  while (index < input.length) {
    if (!isKeyChar(input[index])) { index++; continue; }
    const keyStart = index;
    while (index < input.length && isKeyChar(input[index])) index++;
    const keyEnd = index;
    if (!SENSITIVE_KEY_PATTERN.test(input.slice(keyStart, keyEnd))) continue;

    let valueStart = keyEnd;
    if (input[valueStart] === '"' || input[valueStart] === "'") valueStart++;
    const separatorStart = valueStart;
    while (input[valueStart] === " " || input[valueStart] === "\t") valueStart++;
    const whitespace = valueStart > separatorStart;
    if (input[valueStart] === "=" || input[valueStart] === ":") {
      valueStart++;
      while (input[valueStart] === " " || input[valueStart] === "\t") valueStart++;
    } else if (!whitespace) {
      continue;
    }
    if (input.slice(valueStart, valueStart + 6).toLowerCase() === "bearer"
        && /[ \t]/.test(input[valueStart + 6] || "")) {
      valueStart += 6;
      while (input[valueStart] === " " || input[valueStart] === "\t") valueStart++;
    }
    if (valueStart >= input.length) continue;

    const quote = input[valueStart] === '"' || input[valueStart] === "'" ? input[valueStart] : "";
    let valueEnd = valueStart;
    let closed = false;
    if (quote) {
      valueEnd++;
      let escaped = false;
      while (valueEnd < input.length) {
        const char = input[valueEnd++];
        if (escaped) escaped = false;
        else if (char === "\\") escaped = true;
        else if (char === quote) { closed = true; break; }
      }
    } else {
      while (valueEnd < input.length && !/[\s,;}"']/.test(input[valueEnd])) valueEnd++;
    }
    if (valueEnd <= valueStart) continue;
    parts.push(input.slice(cursor, valueStart), quote ? `${quote}${REDACTED}${closed ? quote : ""}` : REDACTED);
    cursor = valueEnd;
    index = valueEnd;
  }
  parts.push(input.slice(cursor));
  if (original.length > MAX_REDACTION_CHARS) parts.push(TRUNCATED);
  return parts.join("");
}

function redactObject(value, depth = 0, budget = { remaining: MAX_REDACTION_CHARS }) {
  if (depth > 32 || budget.remaining <= 0) return REDACTED;
  budget.remaining--;
  if (typeof value === "string") {
    const limit = Math.min(value.length, budget.remaining);
    budget.remaining -= limit;
    return redactText(value.slice(0, limit)) + (limit < value.length ? TRUNCATED : "");
  }
  if (Array.isArray(value)) {
    const result = [];
    for (const item of value) {
      if (budget.remaining <= 0) { result.push(TRUNCATED); break; }
      result.push(redactObject(item, depth + 1, budget));
    }
    return result;
  }
  if (value && typeof value === "object") {
    const entries = [];
    for (const [key, item] of Object.entries(value)) {
      if (budget.remaining <= 0) { entries.push(["_truncated", TRUNCATED]); break; }
      budget.remaining -= key.length;
      entries.push([key, SENSITIVE_KEY_PATTERN.test(key) ? REDACTED : redactObject(item, depth + 1, budget)]);
    }
    return Object.fromEntries(entries);
  }
  return value;
}

function redactSecrets(text) {
  const input = String(text ?? "");
  if (input.length <= MAX_REDACTION_CHARS && /^\s*[\[{]/.test(input)) {
    try {
      const parsed = JSON.parse(input);
      if (parsed && typeof parsed === "object") return JSON.stringify(redactObject(parsed));
    } catch {
      // Embedded or incomplete JSON is handled by the bounded text scanner.
    }
  }
  return redactText(input);
}

export { MAX_REDACTION_CHARS, redactObject, redactSecrets };
