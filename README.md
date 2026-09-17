# auto-review — ZCode 自动审批权限插件

在 ZCode 自动编辑模式下，通过 PreToolUse hook 审查工具调用。符合保守校验的低风险命令可直接放行；其他请求交专用审批模型裁决，拒绝时把风险分析与替代方案回传主 agent。规则确认门槛、审查故障或审查输入不完整时转客户端原生人工审批。

作者：hh-zyb ｜ 版本：0.5.1 ｜ Node.js ≥ 18 ｜ 零第三方依赖 ｜ MIT

## 快速开始

1. ZCode 设置 → 插件管理 → 添加本地 marketplace，选择含 `marketplace.json` 的项目根目录并安装启用。
2. `/auto-review provider path` 定位专用渠道配置 `~/.zcode/auto-review/review_provider.json`。
3. 填写 `base_url`、`api_key`、`api_kind`、`model`。`api_kind` 支持 openai/anthropic，留空按端点推断。审批不回落客户端 provider 表。
4. `/auto-review on`，将客户端权限模式切到自动编辑。`/auto-review` 查看状态。

插件默认关闭。当前版本不提供插件 GUI、插件审查对话框或插件会话白名单；人工确认统一交客户端。项目目录仍可保留 `auto-review-0.5.0`，不必随版本重命名。

## 0.5.1 决策与安全边界

| 情况 | 行为 |
|------|------|
| 插件关闭、工具范围外、非接管模式 | pass，交回客户端权限流程 |
| 接管后命中 ask 规则 | 转用户确认，优先于 deny 提示和 allow |
| 命中 deny 规则 | 提炼风险提示送审，不是本地终审拒绝；不得被 allow 或快速通道遮蔽 |
| allow 规则或快速通道候选 | 仍须通过命令结构和参数保守校验；匹配正则不等于安全 |
| 普通请求 | 审批模型 allow/deny；模型存疑 ask 收敛为 deny |
| provider 未配置、故障或输出无效 | 需要模型审查的请求转 ask，不自动许可 |
| 载荷超限或缺少完整审查输入 | ask；不得用截断内容取得自动 allow |
| hook 协议异常 | 阻断；进程崩溃 exit 2 |

- **规则优先级固定为 `ask > deny（提示送审）> allow`**，不依赖数组排列。ask 仅在管线接管后生效，不是跨所有权限模式的全局拦截器。
- **快速通道采用保守参数校验**。不是按命令名称全面放行，不保证所有 Git 参数安全。包装器、解释器执行、重定向、替换、未知参数或无法可靠解析的语法不应获得捷径许可。解析器不是所有 shell 的完整语法实现。
- **上下文隔离而非注入免疫**。审批模型只接收本次工具调用、必要上下文与可选脚本附件，不接收对话历史；工具描述与附件仍是不可信数据，不能保证完全免疫提示注入。
- **脚本送审默认关闭**。开启后仅尝试读取工作目录内的普通文件，检查目录边界、符号链接、敏感路径组件及文件类型。工具输入、上下文、规则提示、附件与序列化开销共享单一 `max_payload_chars` 预算。`truncated` 脚本或缺失必要内容不得获得自动 allow。
- **先脱敏原始字段，再序列化**。工具字段及附件中的常见凭据形态替换为 `<REDACTED>`，渠道展示也保护短 API key；这不是覆盖所有 secret 的保证。启用附件前确认审批渠道可信。
- **缓存不是授权记录**。仅复用 schema 合法、`expires` 为有限数值且尚未过期的模型 allow/deny；无效、损坏或不符合当前结构的条目不使用。键包含策略摘要、工具输入、cwd 与附件摘要，策略或附件变化后不复用旧结论；TTL 以配置为准，0 禁用。
- **配置校验一致**。CLI 与加载端遵循同一校验约束，超限规则不能悄悄写入成功却不生效。控制 CLI 写入失败返回 exit 1，不应报告保存成功。

## 命令

- `/auto-review`：status、on、off、set、provider path/show/test。
- `/danger-rules`：列出、添加、删除、测试规则。`test` 只匹配已保存规则，不执行待测命令，也不模拟全部决策管线。
- `/security-prompt`：查看、按要求修改、重置审查提示词。

`provider test` 会真实联网；它不是离线测试的一部分。

## 仓库结构

```text
marketplace.json             本地市场入口
.zcode-plugin/plugin.json    插件清单
hooks/hooks.json             PreToolUse 注册（预算 2 分钟）
src/common.js                路径、日志、原子写、文件锁
src/settings.js              配置与规则加载/校验
src/provider.js              专用渠道与双协议请求
src/reviewer.js              规则、参数校验、附件、脱敏、缓存、模型审查
src/decision.js              hookSpecificOutput 输出协议
src/hook_main.js             hook 入口与协议检查
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

`docs/project_demand.md`、`docs/project_plan/`、`docs/project_process/` 与 `docs/project_log.md` 为历史资料，不作为当前行为契约。客户端是否显示 hook reason 取决于其权限合并逻辑；ask/deny 的 additionalContext 用于向主 agent 补充说明，不代表插件提供自己的审批界面。
