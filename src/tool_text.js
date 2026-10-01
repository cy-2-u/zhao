/**
 * 模块功能: 工具输入文本层——工具名归一化、权限模式闸门与"送审文本"提炼。
 *           供决策管线（规则层/日志）与两层 hook 入口、pending 标记键共用
 * 作者: zhao
 * 创建日期: 2026年10月01日
 * 描述: 从 reviewer.js 拆出（0.8.8 模块化）。0.8.2 起第二层不设 matcher：
 *       凡客户端送入的弹窗请求（名单外工具、MCP/扩展工具等）都要能提炼出审查对象。
 *       Agent/Task 的输入识别已内置——实测当前客户端版本不把子智能体请求送入
 *       hook 通道，此分支为休眠能力（客户端将来接入通道即可直接生效）
 * 依赖: 无
 * 更新日期: 2026年10月01日
 */

// matcher 别名在内部过滤时归一到标准工具名（ApplyPatch 即 Write/Edit 的别名；
// Task 是子智能体创建工具在部分客户端版本里的名字，归一到 Agent 统一审查与缓存）
const TOOL_ALIASES = { ApplyPatch: "Write", Task: "Agent" };

// 退避模式集合（归一化后精确匹配）：
// - plan：客户端只读规划硬边界，插件的自动许可不得越过它去执行变更；
// - yolo / bypasspermissions / fullaccess（客户端"完全访问"）：该模式下客户端本身
//   对所有操作原生放行、永不弹窗（同 Codex full-access），插件接管只会给每条命令
//   白白加一次审查延迟。其余模式（default/edit 及字段缺失）全部接管
const PASSTHROUGH_MODES = new Set(["plan", "yolo", "bypasspermissions", "fullaccess"]);

/**
 * 函数功能: 归一化 hook 输入中的权限模式字段并判断是否为插件退避模式。
 *           归一化去除了大小写、连字符、空格等书写差异（bypass-permissions、
 *           Full Access 均可命中），未知模式值一律返回 false（继续接管，不漏审）
 * @param {object} hook_input - hook stdin 的 JSON
 * @returns {boolean} 属于退避模式返回 true
 */
function isPassthroughMode(hook_input) {
  const t_mode = String((hook_input && (hook_input.permission_mode || hook_input.permissionMode || hook_input.mode)) || "")
    .toLowerCase()
    .replace(/[^a-z0-9]/g, "");
  return PASSTHROUGH_MODES.has(t_mode);
}

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
  if (tool_name === "Agent") {
    const t_type = typeof t_input.subagent_type === "string" ? t_input.subagent_type.trim() : "";
    const t_desc = typeof t_input.description === "string" ? t_input.description.trim() : "";
    const t_prompt = typeof t_input.prompt === "string" ? t_input.prompt.trim() : "";
    if (!t_type && !t_desc && !t_prompt) {
      return { ruleText: "", preview: "(无任务内容)" };
    }
    // 完整任务文本进规则匹配文本（deny 规则可命中任务描述里的风险意图）；
    // 送审载荷另走 tool_input 序列化，由 max_payload_chars 预算统一截断
    return {
      ruleText: `Agent subagent_type=${t_type}\ndescription=${t_desc}\nprompt=${t_prompt}`,
      preview: `子代理 ${t_type || "(未指定类型)"}: ${t_desc || t_prompt.slice(0, 60)}`,
    };
  }
  // 其他工具（MCP/扩展等）：入参 JSON 即审查对象；空入参提炼不出审查对象，
  // 保持空 ruleText 语义（第一层 fail-closed，第二层退避原生弹窗）
  const t_generic = JSON.stringify(t_input);
  if (!t_generic || t_generic === "{}") {
    return { ruleText: "", preview: "(无参数)" };
  }
  return { ruleText: t_generic, preview: t_generic };
}

export {
  isPassthroughMode,
  normalizeToolName,
  buildRuleText,
};
