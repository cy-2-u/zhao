# auto-review — ZCode 自动审批权限插件

> 在 ZCode 现有权限模式之上模拟"自动审批"：主 agent 保持自动编辑模式，由一个**上下文干净的安全子 agent**（PreToolUse hook + LLM）全自动二值裁决——**allow 立即执行，deny 拦截并把风险分析与更安全做法回传主 agent 修改重试**。日常无人值守；仅两类情况转人工：用户显式设置的 ask 确认门槛（如关机）、审批模型不可用时的兜底。

作者: hh-zyb ｜ 版本: 0.5.0 ｜ 技术栈: Node.js ≥ 18（零第三方依赖）｜ License: MIT

## 功能特性

- 🔎 **自动审批模式**——自动编辑基座 + hook 门卫，安全的命令自动放行（实测 1~5 秒/次）；deny 的分析经 additionalContext 回传主 agent，自动形成"拒绝→修改→重试"闭环
- ⚡ **低风险命令快速通道**——dir/ls/cat/git status/git add/git commit/mkdir 等 26 条高频低风险模式单段命中即静默放行，0 次 LLM 调用、0 延迟；包装器（cmd/powershell/Start-Process…）、解释器执行、`%VAR%` 间接调用、重定向/管道/命令替换、date 带参数、越界 mkdir 一律不走捷径
- 🧼 **上下文干净**——安全子 agent 只看本次工具调用的 JSON（+ 可选的脚本附件），不接触对话历史，免疫对话内提示注入
- 🔌 **专用审批渠道**——审批只认 `~/.zcode/auto-review/review_provider.json`（base_url/api_key/model，OpenAI 与 Anthropic 双协议，超时/5xx/429 自动重试 1 次）；未配置或不可用时 LLM 审查不可用，命令**转人工审批**（绝不自动许可），不打断工作流
- 🧭 **规则只做路由，不做终审**——`deny` 规则命中后提炼风险提示（ruleHint）随载荷送审，由审批模型结合完整命令裁决（模型的 deny 才是真正的拒绝）；`allow` 单段命令快速放行；`ask` 规则是用户显式设置的确认门槛，恒转用户裁决；宽泛 allow 排在前面也遮不住 deny/ask（固定优先级）
- 🚧 **出厂规则**——5 条不可逆高危提示（删除根/家目录、格式化（不误伤 Format-Table）、dd 写块设备、fork 炸弹、chmod -R 777 根）+ 1 条关机确认门槛（覆盖裸命令、shutdown.exe、cmd /c、PowerShell cmdlet、wmic 等包装形态；用户主动要求关机时点允许即可执行）；复合命令逐段审查，白名单无法被"白名单命令; 危险命令"绕过
- 📜 **脚本内容随命令送审**（默认关闭）——开启后 python/node/bash 等调用的脚本文件内容自动读取并随载荷送审，审查基于脚本实际内容而非文件名猜测；附件边界严格：只读工作目录内的普通文件（拒绝 `..` 穿越、cwd 外绝对路径、symlink、凭据类敏感文件名、二进制），附件总预算与工具调用共享 max_payload_chars，脚本内容变化后缓存自动失效重审
- 🧮 **缓存绑定策略盐**——缓存键由危险规则/快速通道/提示词/审批渠道的摘要共同加盐，任一策略或 cwd、脚本内容变化后旧结论立即失效重新审查；缓存只承载模型的 allow/deny 结论
- 🛡️ **送审载荷脱敏**——工具输入与脚本附件中的常见密钥/令牌/密码值（含 JSON 键值与 Bearer 头形态）在送审前替换为 `<REDACTED>` 占位符，附件通道不能成为把凭据外送审批渠道的途径
- 🛡️ **失败必保守**——审批模型超时/报错兜底转人工审批（不自动许可）；hook 输入为空/非法 JSON/缺失工具名/空命令属协议异常，直接阻断；插件崩溃时阻断而非放行；默认关闭，显式开启才介入

三个命令：`/auto-review`（总控）、`/danger-rules`（危险规则）、`/security-prompt`（审查策略）。

## 快速开始

```bash
# 1. 安装：ZCode 设置 → 插件管理 → 发现 → + 添加本地 marketplace（选本项目根目录，含市场清单）→ 安装 auto-review
# 2. 配置专用审批渠道：/auto-review provider path 定位 review_provider.json，填写 base_url / api_key / model
# 3. 开启：/auto-review on，然后把权限模式切到「自动编辑模式」
```

## 仓库结构

```
├── marketplace.json             # 市场清单（本地市场源入口）
├── .zcode-plugin/plugin.json     # 插件清单（hooks + commands）
├── hooks/hooks.json              # PreToolUse 注册（预算 2 分钟）
├── src/                         # 核心模块（零第三方依赖）
│   ├── common.js                # 路径常量/日志轮转/原子写/文件锁
│   ├── settings.js              # 配置与规则加载（回落默认+类型钳制+规模上限）
│   ├── provider.js              # 专用审批渠道解析 + 双协议 LLM 调用（node:http 直连，thinking 关闭，瞬时故障重试 1 次）
│   ├── reviewer.js              # 决策管线（规则路由/快速通道/脚本附件/缓存/LLM 审查/脱敏）
│   ├── decision.js              # hook 输出协议封装
│   ├── hook_main.js             # PreToolUse 入口 + 协议异常阻断
│   └── ctl.js                   # 控制 CLI（命令的唯一操作入口）
├── commands/                    # 3 个斜杠命令
├── config/                      # 出厂默认（6 条危险规则 + 26 条低风险快速通道 + 审查提示词 + 默认配置）
├── scripts/                     # 3 份测试（单元 / 场景 / 冒烟）
└── docs/                        # 需求、方案、wiki、开发日志
```

## 测试

```bash
npm test                                   # 单元 + 场景 + 冒烟一键全跑（56 项 + 20 组）
node --test scripts/unit_tests.test.js     # 单元测试（37 项，离线）
node --test scripts/scenario_tests.test.js # 场景固定测试（19 项：本地假审批渠道离线复现全管线）
node scripts/smoke_test.js                 # 端到端冒烟（20 项断言组，子进程运行 hook 与 ctl，不触网）
```

## 文档导航

| 内容 | 位置 |
|------|------|
| 需求（只读） | [docs/project_demand.md](docs/project_demand.md) |
| 技术方案 | [docs/project_plan/](docs/project_plan/) |
| 使用指南 / 常见问题 | [docs/project_wiki/01_用户指南/](docs/project_wiki/01_用户指南/) |
| 开发文档 / 流程图 | [docs/project_wiki/02_开发文档/](docs/project_wiki/02_开发文档/) |
| 二次开发 | [docs/project_wiki/03_二次开发指南/](docs/project_wiki/03_二次开发指南/) |
| 开发日志 | [docs/project_log.md](docs/project_log.md) |

## 设计边界说明

插件无法修改客户端内置的权限模式枚举，"自动审查"通过 **内置自动编辑模式 + PreToolUse hook 返回 allow/ask/deny 决策** 实现，入口是 `/auto-review on` 而非模式下拉框。插件自身**不弹任何审批 UI**：需要人工确认的情况（ask 规则、模型不可用兜底）一律交回**客户端原生审批框**，会话内重复指令的放行也由客户端原生"会话内允许"承接；客户端未提供可信的 agent 来源字段，插件不做远程/子智能体字符串猜测，任何上下文字段都不影响路由。客户端原生审批框仅在"升级路径"渲染 hook 文本（合并函数在同向叠加时丢弃 reason），插件侧以 additionalContext 转述补全决策时信息。

## 0.5.0 决策语义速览

| 情况 | 行为 |
|------|------|
| 命中 allow 规则（单段命令） | 快速放行，0 LLM |
| 复合命令全段 allow | 整条放行，0 LLM |
| 命中 deny 规则 | 提炼风险提示送审，由审批模型裁决（模型 deny 才拒绝） |
| 命中 ask 规则（如关机） | 恒转用户确认（客户端原生审批框），不经 LLM |
| 普通复杂命令 | 审批模型按提示词二值裁决 |
| 模型输出存疑（ask） | 收敛为 deny 并回传分析 |
| 审批模型不可用/超时（重试后） | 兜底转人工审批，绝不自动许可 |
| hook 输入为空/非法 JSON/缺工具名/空命令 | 直接阻断（协议异常 fail-closed） |
| 修改规则/快速通道/提示词/审批渠道 | 缓存策略盐变化，旧结论自动失效重审 |
