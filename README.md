# auto-review — ZCode 全自动审批权限插件

模拟 Codex 全自动审批：开启后除 `plan` 外的所有权限模式均自动接管，通过客户端实际触发的 PreToolUse 与 PermissionRequest 两层 hook 审查工具调用。符合保守校验的低风险命令（含安全组合命令）可直接放行；其他请求（含 PermissionRequest 层实际触发的子智能体调用与名单外工具）交专用审批模型自动二值裁决，拒绝时把风险分析与替代方案回传主 agent。人工审批是唯一兜底，且只由审批模型不可用触发——附件不完整或载荷超限一律截断/带附注送模型裁决，不再单独弹原生审批框。

作者：hh-zyb ｜ 版本：0.7.1 ｜ Node.js ≥ 18 ｜ 零第三方依赖 ｜ MIT

## 快速开始

1. ZCode 设置 → 插件管理 → 添加本地 marketplace，选择含 `marketplace.json` 的项目根目录并安装启用。
2. `/auto-review provider path` 定位专用渠道配置 `~/.zcode/auto-review/review_provider.json`。
3. 填写 `base_url`、`api_key`、`api_kind`、`model`。`api_kind` 支持 openai/anthropic，留空按端点推断。审批不回落客户端 provider 表。
4. `/auto-review on`。无需切换权限模式：除 `plan` 外的所有模式自动接管。`/auto-review` 查看状态。

插件默认关闭。当前版本不提供插件 GUI、插件审查对话框或插件会话白名单；人工确认统一交客户端且只在模型不可用时出现。项目目录仍可保留 `auto-review-0.5.0`，不必随版本重命名。

## 0.7.1 决策与安全边界

| 情况 | 行为 |
|------|------|
| 插件关闭、plan 只读规划、完全访问（yolo） | pass，交回客户端权限流程；其余模式（default/edit 及字段缺失）全接管 |
| 命中 deny 规则 | 提炼风险提示送审，不是本地终审拒绝；不得被 allow 或快速通道遮蔽 |
| 命中 allow 规则（单段命令） | 白名单快速放行（仍须通过结构门禁）；复合命令须每个分段有自己的 allow |
| allow 规则或快速通道候选 | 仍须通过命令结构和参数保守校验；匹配正则不等于安全 |
| 安全组合命令（cd 段 + 全部白名单段） | 每段独立过严格双门禁后整条 0 LLM 放行；段尾 `2>&1` 等纯 stderr 重定向先剥离再判定 |
| 普通请求 | 审批模型 allow/deny；模型存疑 ask 收敛为 deny |
| provider 未配置、故障或输出无效 | 瞬时故障按 `provider_retries` 配置重试，但实际尝试次数受 120 秒 hook 总预算限制；仍失败则转 ask——这是唯一的人工审批入口 |
| 载荷超限或脚本附件不完整 | 截断/带附注照常送模型裁决（截断标记要求模型无法判断时必须 deny），不再单独转人工 |
| hook 协议异常 | 阻断；进程崩溃 exit 2 |
| PermissionRequest 层（第二层） | 对客户端实际送入该事件的请求（含子智能体调用、名单外工具如 Write/Edit）强制送审：allow/deny 输出决策；只有模型不可用兜底 ask、plan 模式、输入读不懂或第一层刚裁定的人工路径退避到原生弹窗；客户端未触发该事件或不接受决策时，插件无法强行接管 |

- **全自动审批管线**：确定性安全快速通道 → 专用审批模型自动 allow/deny → 仅模型不可用时交客户端原生人工审批。该承诺只覆盖客户端实际触发对应 hook 的调用。
- **规则层只有 deny/allow 两种动作**：deny 只作风险提示送审（模型 deny 才是真正的拒绝），allow 是仍需过结构门禁的白名单候选。规则层不存在直接转人工的确认门槛——用户审批唯一来源是模型不可用的兜底路径。
- **关机/重启等出厂规则**：命中后作为风险提示送审批模型，由模型结合完整命令裁决；出厂安全提示词对真实电源中断默认倾向 deny，`shutdown /a` 等取消动作可按实际语义 allow。只有审批模型不可用时才进入人工流程。
- **PermissionRequest 协议**：PreToolUse 使用 `permissionDecision/permissionDecisionReason`；PermissionRequest 使用客户端实际解析的 `decision.behavior/message`。两层协议不同，不能混用。
- **防回环设计**：第一层决定转人工时写入短时效标记（15s）；第二层看到新鲜标记即退避（也省掉一轮注定失败的重试）。标记读取不可靠时第二层照常送审——模型在场即自动决策，不在场自然兜底转人工。
- **规则优先级固定为 `deny（提示送审）> allow`**，不依赖数组排列。规则仅在管线接管后生效。
- **快速通道采用保守参数校验**。不是按命令名称全面放行，不保证所有 Git 参数安全。包装器、解释器执行、重定向、替换、未知参数或无法可靠解析的语法不应获得捷径许可。任意内联代码（如 `node -e`）零配置不放行——但可为各分段自写 allow 规则整条放行（规则是信任边界，插件只兜底命令替换、引号外重定向、`%VAR%` 展开与 `\&` 类跨 shell 歧义形态）。解析器不是所有 shell 的完整语法实现。
- **上下文隔离而非注入免疫**。审批模型只接收本次工具调用、必要上下文与可选脚本附件，不接收对话历史；工具描述与附件仍是不可信数据，不能保证完全免疫提示注入。
- **脚本送审默认关闭**。开启后仅尝试读取工作目录内的普通文件，检查目录边界、符号链接、敏感路径组件及文件类型。工具输入、上下文、规则提示、附件与序列化开销共享单一 `max_payload_chars` 预算。不完整附件以附注随载荷送模型裁决；附件摘要参与缓存键，完整读取的旧 allow 不可能为不完整读取背书。
- **先脱敏原始字段，再序列化**。工具字段及附件中的常见凭据形态替换为 `<REDACTED>`，渠道展示也保护短 API key；这不是覆盖所有 secret 的保证。启用附件前确认审批渠道可信。
- **缓存不是授权记录**。仅复用 schema 合法、`expires` 为有限数值且尚未过期的模型 allow/deny；无效、损坏或不符合当前结构的条目不使用。键包含策略摘要、工具输入、cwd 与附件摘要，策略或附件变化后不复用旧结论；TTL 以配置为准，0 禁用。
- **配置校验一致**。CLI 与加载端遵循同一校验约束，超限规则不能悄悄写入成功却不生效。控制 CLI 写入失败返回 exit 1，不应报告保存成功。

## 命令

- `/auto-review`：status、on、off、set、provider path/show/test。可设置键含 `provider_retries`（0-3）。
- `/danger-rules`：列出、添加、删除、测试规则。`test` 只匹配已保存规则，不执行待测命令，也不模拟全部决策管线。
- `/security-prompt`：查看、按要求修改、重置审查提示词。

`provider test` 会真实联网；它不是离线测试的一部分。

## 仓库结构

```text
marketplace.json             本地市场入口
.zcode-plugin/plugin.json    插件清单
hooks/hooks.json             PreToolUse + PermissionRequest 注册（预算各 2 分钟）
src/common.js                路径、日志、原子写、文件锁
src/settings.js              配置与规则加载/校验
src/provider.js              专用渠道与双协议请求（可配置重试）
src/reviewer.js              规则、参数校验、附件、脱敏、缓存、模型审查、pending 标记
src/decision.js              hookSpecificOutput 输出协议（PreToolUse / PermissionRequest）
src/hook_main.js             PreToolUse 入口与协议检查
src/hook_permission.js       PermissionRequest 入口（客户端触发范围内的审查与安全退避）
src/ctl.js                   控制 CLI
commands/                   三个斜杠命令
config/                     出厂默认
scripts/                    离线单元、场景、冒烟测试
docs/                       现行 wiki 与历史资料
```

## 离线验证

在项目根目录运行以下命令，无需安装第三方依赖。测试使用隔离数据目录与本地模拟审批渠道，不要求真实 API 凭据。

```bash
npm test
```

不要通过实际执行破坏性命令验证拦截。测试数量和通过结果以当次输出为准。

## 文档导航

- [现行项目 Wiki](docs/project_wiki/README.md)
- [用户指南](docs/project_wiki/01_用户指南/使用指南.md)
- [开发设计](docs/project_wiki/02_开发文档/模块设计_决策管线.md)
- [变更记录](docs/project_wiki/99_附录/变更记录.md)

客户端是否触发 PermissionRequest、是否把内置子智能体请求送入父级 hook runner，以及是否显示 hook reason，均取决于客户端实现；脚本级协议测试不能替代真实客户端验证。ask/deny 的 additionalContext 用于向主 agent 补充说明，不代表插件提供自己的审批界面。
