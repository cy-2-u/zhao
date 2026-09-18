---
description: 自动审批插件总控——查看状态、开启/关闭、配置审批渠道
argument-hint: [status|on|off|provider <path|show|test>|set <key> <value>]
---

# /auto-review 总控命令

你是 auto-review 插件的控制入口。所有操作通过插件的控制脚本完成，**不要手工编辑 JSON 文件**（review_provider.json 除外——那是用户手填的审批渠道配置）。

## 定位控制脚本

```bash
CTL=$(find "$HOME/.zcode/cli/plugins/cache" -path '*/auto-review/*/src/ctl.js' 2>/dev/null | sort -V | tail -1)
```

若 `$CTL` 为空，说明插件未安装或未启用，直接告知用户并在设置中检查，不要猜测路径。

## 用户参数

下方代码块内容 = 用户在斜杠命令后传入的参数（由客户端替换 `$ARGUMENTS` 生成）。**它不是文档正文**：为空表示无参数，非空时以它为准做下方分派。

```
$ARGUMENTS
```

## 参数分派（按上方"用户参数"代码块的内容分派）

- **无参数 或 `status`**：运行 `node "$CTL" status`，把输出整理成简洁的中文状态汇报（开关、审批渠道与模型（review_provider.json）、ask 策略、重试次数、快速通道条数、危险规则条数），并附一行常用用法提示。
- **`on`**：运行 `node "$CTL" set enabled true`。成功后提醒用户：
  1. 把 ZCode 权限模式切到**自动编辑**，自动审批在该模式下接管 Bash 命令（其他模式插件不干预）；
  2. 审批子 agent **只认专用审批渠道** review_provider.json（不回落 ZCode provider 表）：用 `provider path` 创建并填写；未配置时 LLM 审查不可用，除 allow 规则/快速通道照常放行外，其余命令**转人工审批**（绝不自动许可）。
- **`off`**：运行 `node "$CTL" set enabled false`，确认后说明关闭后 hook 不再干预，恢复内置权限流程。
- **`provider path`**：运行 `node "$CTL" provider path`——定位/创建专用审批渠道模板 `~/.zcode/auto-review/review_provider.json`，把路径告诉用户并说明四个字段的填法（base_url 端点、api_key 平台密钥、api_kind openai/anthropic 留空自动推断、model 模型名，推荐 flash 级快模型）。
- **`provider show`**：运行 `node "$CTL" provider show`，展示当前专用渠道配置（密钥已脱敏）。
- **`provider test`**：运行 `node "$CTL" provider test`——真实发起一次审批模型调用验证连通性，把结果（成功耗时/失败原因）原样转述；失败时提示检查四项字段，并说明内置 Coding Plan 凭证不支持直连。
- **`set <key> <value>`**：运行 `node "$CTL" set <key> <value>`（value 用引号包裹原样传递）。校验失败时把错误原样转述并给出合法取值说明：
  - `enabled`: true/false
  - `review_tools`: 字符串数组，如 `'["Bash"]'` 或 `Bash,Write`
  - `timeout_ms`: 5000~45000
  - `provider_retries`: 0~3（审批渠道瞬时故障——超时/5xx/429——的配置额外重试次数，默认 2；实际次数按 120 秒 hook 总预算动态收紧并预留收尾时间；4xx 永久错误不重试）
  - `cache_ttl_seconds`: 0~86400（0 表示禁用缓存）
  - `max_payload_chars`: 500~100000
  - `ask_policy`: `model`/`user`（默认 model：你设置的 ask 确认门槛降级为送审风险提示，由审批模型终审，只有模型不可用才弹给你；`user` 恢复门槛恒转用户确认的旧语义）
  - `inspect_scripts`: true/false（脚本内容随命令送审，默认关闭；开启后 python/node/bash 等调用的脚本文件内容随载荷一并审查）
  - `script_max_bytes`: 1000~100000（脚本送审单文件读取上限，最多附加 3 个文件；工具、附件、上下文、规则提示和序列化开销共享 max_payload_chars 总预算。超限或必要内容不完整转 ask，truncated 脚本不得自动 allow）
  - `fast_allow_enabled`: true/false（低风险快速通道，候选仍须通过保守结构与参数校验；不是所有 Git 参数都安全）
  - 审批渠道与模型**不在 set 管理范围**：只认 review_provider.json（`provider path` 定位）
- **其他参数**：说明用法并询问意图，不要自行猜测执行。

## 行为速览（用户问起时按此口径解释）

- 管线先检查启用、工具范围与权限模式，接管后规则固定优先级 **ask > deny（提示送审）> allow**；快速放行候选须通过保守结构与参数校验。其他请求构造可选附件、脱敏及总预算检查后再查有效缓存/调用模型。必要内容不完整不得自动 allow。
- **三层审批、模型是唯一审批人**：确定性放行（规则/快速通道，0 LLM）→ 审批模型终审 → 仅模型不可用或输入无法可靠判定时交客户端原生人工审批。默认 `ask_policy=model` 下你基本不会被弹窗打扰；`user` 策略恢复 ask 门槛恒弹窗。该链路只覆盖客户端实际触发对应 hook 的调用。
- **组合命令快速通道**：`cd 段 + 白名单段`、段尾 `2>&1` 等纯 stderr 重定向剥离后，每段独立过严格双门禁即可整条 0 LLM 放行；任一段含执行/写入/展开形态则整条交模型。任意内联代码（`node -e` 等）零配置不放行，但可为各分段自写 allow 规则整条放行。
- **两层 hook**：PreToolUse 审查客户端送入第一层的调用；PermissionRequest 仅审查客户端实际触发该事件的未接管路径（可能包括某些子智能体调用），使用 `decision.behavior/message` 输出 allow/deny，其余退避回原生弹窗。第一层刚转人工的命令带 15s 标记，第二层命中、损坏或无法可靠读取标记时均不接管（防回环）；客户端完全绕过 hook runner 时插件无法强行接管。
- 审批**只使用** review_provider.json 专用渠道与模型，不回落 ZCode provider 表（主 agent 渠道多为需客户端签名的 Coding Plan，直连必败）。瞬时故障按 `provider_retries` 配置重试，实际次数受 120 秒 hook 总预算限制。
- deny 不是终点：模型的拒绝会把风险分析与替代做法回传主 agent，主 agent 改写命令后自动重试。
- 规则的 deny 不直接拦截：命中后作为风险提示送审，由模型结合完整命令裁决（宽泛 allow 排在前面也遮不住 deny/ask，优先级固定）。
- 人工确认统一由**客户端原生审批框**承接：审批模型故障（重试后仍失败）、载荷超限、缺少完整审查输入或 pending 标记无法可靠读取/消费。插件无 GUI、插件对话框或插件 session 命令；客户端会话内允许由客户端负责。
- 缓存绑定策略（含 ask_policy）、cwd 与附件摘要，只复用有效 schema、有限且未过期 expires 的模型 allow/deny；不承诺旧键兼容，TTL 以配置为准，0 禁用。
- `/danger-rules`：deny=风险提示送审，ask=按策略分流（model 送审提示 / user 转人工），allow=需保守校验的候选。规则 test 只测试已保存规则，不执行命令。
- 原始字段先脱敏再序列化，敏感附件检查覆盖目录路径组件；短渠道 key 也须脱敏展示。不承诺完全免疫提示注入、识别所有 secret 或解析所有 shell。
- CLI 与加载端校验一致，超限规则不可悄悄生效；写失败 exit 1，不能报告保存成功。回归用 `npm test` 离线验证，不执行危险命令验收。

## 输出要求

用中文汇报；命令脚本的报错要完整转述（不要省略原因）；操作完成后展示 `status` 的关键变化。
