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

- **无参数 或 `status`**：运行 `node "$CTL" status`，把输出整理成简洁的中文状态汇报（开关、审批渠道与模型（review_provider.json）、快速通道条数、危险规则条数），并附一行常用用法提示。
- **`on`**：运行 `node "$CTL" set enabled true`。成功后提醒用户：
  1. 把 ZCode 权限模式切到**自动编辑**，自动审批在该模式下接管 Bash 命令（其他模式插件不干预）；
  2. 审批子 agent **只认专用审批渠道** review_provider.json（不回落 ZCode provider 表）：用 `provider path` 创建并填写；未配置时 LLM 审查不可用，除 allow 规则/快速通道照常放行外，其余命令**转人工审批**（绝不自动许可）。
- **`off`**：运行 `node "$CTL" set enabled false`，确认后说明关闭后 hook 不再干预，恢复内置权限流程。
- **`provider path`**：运行 `node "$CTL" provider path`——定位/创建专用审批渠道模板 `~/.zcode/auto-review/review_provider.json`，把路径告诉用户并说明四个字段的填法（base_url 端点、api_key 平台密钥、api_kind openai/anthropic 留空自动推断、model 模型名，推荐 flash 级快模型）。
- **`provider show`**：运行 `node "$CTL" provider show`，展示当前专用渠道配置（密钥已脱敏）。
- **`provider test`**：运行 `node "$CTL" provider test`——真实发起一次审批模型调用验证连通性，把结果（成功耗时/失败原因）原样转述；失败时提示检查三项字段，并说明内置 Coding Plan 凭证不支持直连。
- **`set <key> <value>`**：运行 `node "$CTL" set <key> <value>`（value 用引号包裹原样传递）。校验失败时把错误原样转述并给出合法取值说明：
  - `enabled`: true/false
  - `review_tools`: 字符串数组，如 `'["Bash"]'` 或 `Bash,Write`
  - `timeout_ms`: 5000~45000
  - `cache_ttl_seconds`: 0~86400（0 表示禁用缓存）
  - `max_payload_chars`: 500~100000
  - `inspect_scripts`: true/false（脚本内容随命令送审，默认关闭；开启后 python/node/bash 等调用的脚本文件内容随载荷一并审查）
  - `script_max_bytes`: 1000~100000（脚本送审单文件读取上限；附件总预算与工具调用共享 max_payload_chars，超限截断并附注，最多附加 3 个文件）
  - `fast_allow_enabled`: true/false（低风险命令快速通道，命中白名单 0 LLM 直接放行）
  - 审批渠道与模型**不在 set 管理范围**：只认 review_provider.json（`provider path` 定位）
- **其他参数**：说明用法并询问意图，不要自行猜测执行。

## 行为速览（用户问起时按此口径解释）

- 管线顺序：危险规则（allow 快速放行 / ask 恒转用户 / deny 提炼风险提示送审）→ 快速通道（低风险命令直接放行）→ 脚本附件（可选）→ 缓存 → 审批子 agent（LLM 全自动二值）。
- 审批**只使用** review_provider.json 专用渠道与模型，不回落 ZCode provider 表（主 agent 渠道多为需客户端签名的 Coding Plan，直连必败）。
- deny 不是终点：模型的拒绝会把风险分析与替代做法回传主 agent，主 agent 改写命令后自动重试。
- 规则的 deny 不直接拦截：命中后作为风险提示送审，由模型结合完整命令裁决（宽泛 allow 排在前面也遮不住 deny/ask，优先级固定）。
- 需要人工确认的情况一律由**客户端原生审批框**承接：用户显式设置的 ask 规则（如关机）、审批模型不可用时的兜底转人工。插件自身不弹任何审批窗口；会话内重复指令的放行由客户端原生"会话内允许"承接。
- 缓存绑定策略盐：修改规则、快速通道、提示词或审批渠道后，旧缓存结论自动失效重新审查。
- 危险规则用户可完全自定义：`/danger-rules`（deny=风险提示送审 / ask=恒转用户确认 / allow=白名单快速放行）。

## 输出要求

用中文汇报；命令脚本的报错要完整转述（不要省略原因）；操作完成后展示 `status` 的关键变化。
