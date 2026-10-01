# auto-review — ZCode 全自动审批权限插件

模拟 Codex 全自动审批：开启后除 `plan` 与完全访问（yolo）外的所有权限模式均自动接管，通过客户端实际触发的 PreToolUse 与 PermissionRequest 两层 hook 审查工具调用。可证明低风险的命令按有限白名单快速放行（含 `cd` 在内的复合命令一律交模型审查）；其他请求（第二层全量接管的名单外工具与 MCP/扩展工具弹窗）交专用审批模型自动二值裁决，拒绝时把风险分析与替代方案回传主 agent；子智能体（Agent/Task）的创建与内部调用客户端当前不送入 hook 通道，由客户端权限系统裁决（见下方第二层边界）。人工审批是唯一兜底，只由审批模型不可用或两层审批状态不可靠触发——附件不完整或载荷超限一律截断/带附注送模型裁决，不单独弹原生审批框。

作者：zhao ｜ 版本：0.8.8 ｜ Node.js ≥ 18 ｜ 零第三方依赖 ｜ MIT

## 快速开始

1. ZCode 设置 → 插件管理 → 添加本地 marketplace，选择含 `marketplace.json` 的项目根目录并安装启用。
2. `/auto-review provider path` 定位专用渠道配置 `~/.zcode/auto-review/review_provider.json`。
3. 填写 `base_url`、`api_key`、`api_kind`、`model`。`api_kind` 支持 openai/anthropic，留空按端点推断。审批不回落客户端 provider 表。
4. `/auto-review on`。无需切换权限模式：除 `plan` 与完全访问（yolo）外的所有模式自动接管。`/auto-review` 查看状态。

插件默认关闭。当前版本不提供插件 GUI、插件审查对话框或插件会话白名单；人工确认统一交客户端，只在审批模型不可用、两层审批状态不可靠或识别不出审查对象时出现。项目目录仍可保留 `auto-review-0.5.0`，不必随版本重命名。

## 0.8.8 决策与安全边界

| 情况 | 行为 |
|------|------|
| 插件关闭、plan 只读规划、完全访问（yolo） | pass，交回客户端权限流程；其余模式（default/edit 及字段缺失）全接管 |
| 网页搜索/抓取等只读工具（WebSearch/WebFetch/web-reader） | 0 审查直接放行：不产生本地变更，送模型纯属浪费延迟；带风险的上网形态（curl 外发数据等）仍走 Bash 审查 |
| 命中 deny 规则 | 提炼风险提示送审，不是本地终审拒绝；不得被 allow 或快速通道遮蔽 |
| 命中 allow 规则（单段命令） | 白名单快速放行（仍须通过结构门禁）；复合命令须每个分段有自己的 allow |
| allow 规则或快速通道候选 | 仍须通过命令结构和参数保守校验；匹配正则不等于安全 |
| 含 `cd`/`chdir` 的复合命令 | 一律交审批模型审查：目录切换依赖 shell 进程状态且跨 shell 语义分歧，不作为快速放行证明；段尾仅剥离 `2>&1` 与 `2>/dev/null`（`2>nul` 在 POSIX shell 会写成普通文件，不剥离） |
| 普通请求 | 审批模型 allow/deny；模型存疑 ask 收敛为 deny |
| provider 未配置、故障或输出无效 | 瞬时故障按 `provider_retries` 配置重试，但实际尝试次数受 120 秒 hook 总预算限制；仍失败则转 ask——这是唯一的人工审批入口 |
| 动态执行与脚本命令 | 解释器、shell 包装器、`npm run/test` 等生命周期命令及引用脚本的命令不复用普通决策缓存：每次送模型重新裁决，静态只读查询仍可短 TTL 缓存 |
| 载荷超限或脚本附件不完整 | 截断/带附注照常送模型裁决（截断标记要求模型无法判断时必须 deny），不再单独转人工 |
| hook 协议异常 | 阻断；进程崩溃 exit 2 |
| PermissionRequest 层（第二层） | hooks.json 不设 matcher（匹配所有工具）：客户端实际送入该事件的弹窗请求——名单外工具（Write/Edit）、MCP/扩展工具——一律强制送审，allow/deny 输出决策；只有模型不可用兜底 ask、plan 模式、输入读不懂或第一层刚裁定的人工路径退避到原生弹窗。**实测（0.8.7）当前客户端版本不把子智能体（Agent/Task）的创建与内部工具调用送入该通道**——这类请求由客户端权限系统直接裁决（弹窗与否随会话权限模式），插件无法接管 |

- **全自动审批管线**：确定性安全快速通道 → 专用审批模型自动 allow/deny → 仅模型不可用时交客户端原生人工审批。该承诺只覆盖客户端实际触发对应 hook 的调用。
- **规则层只有 deny/allow 两种动作**：deny 只作风险提示送审（模型 deny 才是真正的拒绝），allow 是仍需过结构门禁的白名单候选。规则层不存在直接转人工的确认门槛——用户审批唯一来源是模型不可用的兜底路径。
- **电源操作（关机/重启/注销/休眠）**：0.8.0 起不再列入出厂危险规则，按普通请求走审批模型；提示词要求模型判定**是否用户明确要求的**——命令 description 等字段写明用户要求 → 自动执行，没有明确依据或疑似代理自作主张 → 自动拒绝并要求补充授权依据；`shutdown /a` 等取消动作直接放行。只有审批模型不可用时才进入人工流程。
- **PermissionRequest 协议**：PreToolUse 使用 `permissionDecision/permissionDecisionReason`；PermissionRequest 使用客户端实际解析的 `decision.behavior/message`。两层协议不同，不能混用。
- **防回环设计**：第一层决定转人工时写入短时效标记（15s）；第二层看到新鲜标记即退避（也省掉一轮注定失败的重试）。标记损坏、读取失败或消费失败时第二层同样退避到原生弹窗——无法证明第一层是否已交人工时，不继续自动裁决。
- **规则优先级固定为 `deny（提示送审）> allow`**，不依赖数组排列。规则仅在管线接管后生效。
- **快速通道采用保守参数校验**。不是按命令名称全面放行，不保证所有 Git 参数安全。`cd`/`chdir`、包装器、解释器执行、重定向、替换、未知参数或无法可靠解析的语法不获得捷径许可。任意内联代码（如 `node -e`）零配置不放行——但可为各分段自写 allow 规则整条放行（规则是信任边界，插件只兜底命令替换、引号外重定向、`%VAR%` 展开与 `\&` 类跨 shell 歧义形态）。解析器不是所有 shell 的完整语法实现。
- **上下文隔离而非注入免疫**。审批模型只接收本次工具调用、必要上下文与可选脚本附件，不接收对话历史；工具描述与附件仍是不可信数据，不能保证完全免疫提示注入。
- **脚本送审默认关闭**。开启后仅尝试读取工作目录内的普通文件，检查目录边界、符号链接、敏感路径组件及文件类型。工具输入、上下文、规则提示、附件与序列化开销共享单一 `max_payload_chars` 预算。不完整附件以附注随载荷送模型裁决；附件摘要参与缓存键，完整读取的旧 allow 不可能为不完整读取背书。
- **先脱敏原始字段，再序列化**。工具字段及附件中的常见凭据形态替换为 `<REDACTED>`，渠道展示也保护短 API key；这不是覆盖所有 secret 的保证。启用附件前确认审批渠道可信。
- **缓存不是授权记录**。仅复用 schema 合法、`expires` 为有限数值且尚未过期的模型 allow/deny；无效、损坏或不符合当前结构的条目不使用。键包含策略摘要、工具输入、cwd 与附件摘要，策略或附件变化后不复用旧结论；TTL 以配置为准，0 禁用。
- **配置校验一致**。CLI 与加载端遵循同一校验约束，超限规则不能悄悄写入成功却不生效。控制 CLI 写入失败返回 exit 1，不应报告保存成功。

## 命令

- `/auto-review`：status、on、off、set、provider path/show/test。可设置键含 `provider_retries`（0-3）与 `provider_json_mode`（auto/on/off，json_object 强制输出）。
- `/danger-rules`：列出、添加、删除、测试规则。`test` 只匹配已保存规则，不执行待测命令，也不模拟全部决策管线。
- `/security-prompt`：查看、按要求修改、重置审查提示词。

`provider test` 会真实联网；它不是离线测试的一部分。

## 仓库结构

```text
marketplace.json             本地市场入口
.zcode-plugin/plugin.json    插件清单
hooks/hooks.json             PreToolUse（名单 matcher）+ PermissionRequest（不设 matcher，全量接管）注册（预算各 2 分钟）
src/common.js                路径、日志、原子写、文件锁、hook 共享输入读取
src/shell_lex.js             命令词法（分割/tokenize/cd 判定/敏感模式）
src/tool_text.js             工具名归一、模式闸门、送审文本提炼
src/verdict.js               模型输出合同（parseVerdict，独立供 CLI 复用）
src/fast_allow.js            快速通道（结构门禁 + 参数白名单）
src/script_attach.js         脚本附件与动态执行判定
src/decision_cache.js        策略盐与决策缓存
src/pending_marks.js         pending 转人工标记
src/settings.js              配置与规则加载/校验、请求级策略快照
src/provider.js              专用渠道与双协议请求（共享 deadline）
src/reviewer.js              决策管线编排（兼容门面再导出）
src/decision.js              hookSpecificOutput 输出协议（PreToolUse / PermissionRequest）
src/hook_main.js             PreToolUse 入口与协议检查
src/hook_permission.js       PermissionRequest 入口（客户端触发范围内的审查与安全退避）
src/ctl.js                   控制 CLI
commands/                    三个斜杠命令
config/                      出厂默认
scripts/                     离线单元、场景、冒烟测试
docs/                        现行 wiki（含变更记录档案）
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

实测（0.8.7）：当前客户端版本会为父会话触发两层 hook（主会话调用全覆盖），但**不把内置子智能体（Agent/Task）的创建与内部工具调用送入父级 hook runner**——这类请求的弹窗与放行完全由客户端权限系统决定，插件无法接管；是否显示 hook reason 同样取决于客户端实现。脚本级协议测试不能替代真实客户端验证。ask/deny 的 additionalContext 用于向主 agent 补充说明，不代表插件提供自己的审批界面。
