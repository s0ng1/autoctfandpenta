# YuPentestPilot

YuPentestPilot 是一个面向 CTF 与 Web 安全测试场景的轻量运行时。

它的核心思路不是让 Agent 在“读工具文档 -> 调一个工具 -> 解析结果 -> 再调下一个工具”的循环里消耗上下文，而是给 Agent 一个受控沙箱，再提供一套可编排的 Python 执行环境，让它直接通过代码组织浏览器、终端、流量分析、笔记和报告能力。

这个仓库是从实际比赛与实验环境中抽离出的精简版本，重点是把核心链路开源出来，方便复现、学习和继续改造。

## Project Origin

这个项目并不是凭空产生的独立想法，而是基于笑神在 AI for 攻防方向上的公开探索所做的一次复刻、整理与工程化实现。

如果你读过笑神关于 Intent Engineering、APG、Meta-Tooling、Python Executor MCP 等方向的分享，会很容易看出 YuPentestPilot 在问题意识和设计取向上与这些思路一脉相承。当前仓库更像是其中一条实践路线的轻量化开源版本，而不是对原始设想的完整一比一实现。

## Why YuPentestPilot

传统 Agent Tool Use 往往会遇到几个问题：

- 工具调用链很长，上下文容易被中间结果污染
- 多工具协同时，推理过程会被大量机械步骤打断
- 安全测试任务天然需要浏览器、终端、流量、笔记、报告多种能力联动
- 一旦任务变复杂，单轮单工具式调用会越来越笨重

YuPentestPilot 试图换一种方式：

**Agent 负责表达意图，Python 代码负责组织执行。**

也就是说，Agent 不再只是一段“逐步调用工具的对话”，而是可以在沙箱里写小段 Python，把多种能力串起来完成实际任务。

## Core Idea

整体链路如下：

1. 宿主机启动 `YuPentestPilot.py`
2. Python 脚本拉起 Docker 沙箱
3. 容器内运行 Claude Code
4. Claude 通过 MCP 调用 Python Executor
5. Python Executor 在状态化会话中执行代码
6. 代码通过 `toolset` 调用浏览器、终端、代理、笔记、报告等能力

对应到仓库结构，大致分成三层：

- **调度层**
  - `YuPentestPilot.py`
  - 负责启动容器、注入任务、挂载工作目录
- **执行层**
  - `meta-tooling/service/python_executor_mcp.py`
  - 提供状态化 Python 执行能力
- **能力层**
  - `meta-tooling/toolset/src/toolset`
  - 提供 browser / terminal / proxy / note / report 等工具集

## Features

当前版本已经具备以下能力：

- 支持 `ctf` 与 `pentest` 两种模式
- 基于 Docker 的隔离沙箱运行
- 通过 Claude Code 驱动任务执行
- 通过 MCP 暴露状态化 Python 执行环境
- 支持浏览器自动化与页面交互
- 支持终端会话管理与安全工具调用
- 支持 HTTP 流量查看
- 支持持久化笔记记录
- 支持基于模板生成 Word 渗透测试报告
- 支持 intent-native metadata / artifact 持久化
- 支持 VNC 观察执行过程

## Modes

### CTF Mode

适用于 Web CTF 或类似夺旗场景。

Agent 会围绕目标 URL 进行侦察、测试和利用，目标是尽快获取 flag。拿到 flag 后即可结束，不要求继续做完整评估。

### Pentest Mode

适用于授权的 Web 渗透测试场景。

Agent 会在受控环境中完成从侦察、漏洞发现、漏洞验证到报告输出的完整流程，最终在工作目录中生成中文 Word 渗透测试报告。

## Repository Layout

```text
.
├─ YuPentestPilot.py
├─ tinyctfer.py                  # 兼容旧入口
├─ claude_code/
│  ├─ .mcp.json
│  └─ .claude/
├─ meta-tooling/
│  ├─ service/
│  └─ toolset/
├─ README/
├─ .env.example
├─ pyproject.toml
└─ README.md
```

关键目录说明：

- `YuPentestPilot.py`
  - 项目主入口
- `claude_code/`
  - Claude Code 配置、MCP 配置、Agent Prompt
- `meta-tooling/service/`
  - MCP 服务和浏览器服务
- `meta-tooling/toolset/`
  - 浏览器、终端、流量、笔记、报告等工具实现

## Quick Start

### 1. 拉取沙箱镜像

```bash
docker pull ghcr.io/l3yx/sandbox:latest
docker tag ghcr.io/l3yx/sandbox:latest l3yx/sandbox:latest
```

### 2. 安装依赖

推荐使用 `uv`：

```bash
uv sync
```

### 3. 配置环境变量

复制示例配置：

```bash
cp .env.example .env
```

填写你可用的 Anthropic 兼容接口配置：

- `ANTHROPIC_BASE_URL`
- `ANTHROPIC_AUTH_TOKEN`
- `ANTHROPIC_MODEL`

### 4. 启动任务

CTF 模式：

```bash
uv run --env-file .env YuPentestPilot.py \
  --ctf http://target.example.com \
  --workspace workspace \
  --mode ctf
```

Pentest 模式：

```bash
uv run --env-file .env YuPentestPilot.py \
  --ctf http://target.example.com \
  --workspace workspace \
  --mode pentest
```

## Arguments

- `--ctf`
  - 目标 URL
- `--workspace`
  - 本地工作目录，会挂载到容器内 `/home/ubuntu/Workspace`
- `--mode`
  - 运行模式，可选 `ctf` 或 `pentest`
- `--vnc-port`
  - VNC 端口，默认 `5901`

## Output

在不同模式下，输出内容略有区别：

- `ctf`
  - 重点是获得 flag
  - 终端会打印最终执行结果
- `pentest`
  - 重点是完成测试并输出报告
  - 报告会写入工作目录
  - 最终报告强制输出为 `.docx`
  - `intentlang/artifacts/final_report_reference.json` 会记录最终报告路径

## Tooling

当前 `toolset` 提供以下核心能力：

- `toolset.browser`
  - 获取 Playwright 浏览器上下文
  - 适合页面访问、交互、源码查看、控制台监听
- `toolset.terminal`
  - 基于 tmux 管理终端会话
  - 可用于执行 httpx、katana、ffuf、sqlmap 等工具
- `toolset.proxy`
  - 查看浏览器相关 HTTP 流量
- `toolset.note`
  - 保存与读取持久化笔记
- `toolset.intentlang`
  - 读取 runtime metadata
  - 维护 `recon_summary` / `surface_map` / `verified_findings` 等 artifacts
  - 提供 `append_verified_finding()`、`upsert_verified_finding()`、`deduplicate_verified_findings()` 等高层写接口
- `toolset.report`
  - 仅保留基于 `verified_findings` artifact 的模板化 Word 报告主路径
  - 自动写回 `final_report_reference`

## IntentLang Workflow

当前主流程已经不是单纯依赖 prompt 的临时输出，而是围绕 workspace 中的 `intentlang/` 目录运行：

- `intentlang/metadata/`
  - 保存 `run`、`strategy`、`intents`、`runtime_objects`、`artifact_schemas`
  - `pentest` 模式下会自动复制 Word 报告模板到 `pentest_report_template.docx`
- `intentlang/artifacts/`
  - 保存 `recon_summary`、`surface_map`、`hypotheses`
  - 保存 `candidate_findings`、`candidate_evidence`、`verified_findings`
  - 保存 `final_report_reference`

推荐的 pentest 报告链路：

1. 侦察阶段将结构化结果写入 `surface_map`、`recon_summary`
2. 验证阶段将候选结果提升到 `verified_findings`
3. 优先使用 `toolset.intentlang.append_verified_finding()` 或 `upsert_verified_finding()` 写模板友好的字段
4. 对重复漏洞调用 `toolset.intentlang.deduplicate_verified_findings()` 做归并
5. 使用 `toolset.report.generate_word_report_from_artifacts()` 直接从 artifact 生成最终 Word 报告

## Testing

当前仓库已补上最小的 repo 内 intent-native 端到端测试，覆盖：

- `YuPentestPilot.main()` 在 `ctf` / `pentest` 下的 bootstrap 与任务注入
- `verified_findings` 的 upsert / dedup 行为
- `append_verified_finding -> generate_word_report_from_artifacts -> final_report_reference`
- `record_ctf_flag -> save_ctf_report -> final_report_reference`

运行方式：

```bash
./.venv/bin/python -m unittest -v tests.test_intentlang_e2e
```

补充文档：

- 最新开发记忆见 [docs/latest-memory.md](docs/latest-memory.md)
- GitHub 更新摘要见 [docs/github-summary.md](docs/github-summary.md)

## VNC

当前版本默认启用 VNC，便于观察浏览器与终端中的执行过程。

示例地址：

```text
vnc://127.0.0.1:5901
```

默认密码：

```text
123456
```

## Project Status

这个仓库目前更接近：

- 一个可运行的原型
- 一个面向安全测试场景的 Agent Runtime 示例
- 一个展示 “Intent Engineering + Meta-Tooling” 思路的开源版本

它还不是一个已经充分工程化、稳定性完善、接口完全收敛的正式产品。

换句话说，这个版本更适合：

- 学习整体设计
- 复现运行链路
- 在此基础上继续二次开发

## Known Limitations

当前仓库仍然存在一些明显的工程化不足，例如：

- 某些 Agent Prompt 中引用的方法尚未完全落地
- 报告模块还有进一步加强转义与安全性的空间
- 启动与异常处理逻辑比较轻量
- 工具模块之间的边界还可以进一步收敛

如果你希望把它长期维护成一个正式项目，这些部分都值得继续重构。

## Safety Notice

请仅在**明确授权**的范围内使用本项目。

尤其在 `pentest` 模式下，应避免：

- DoS / DDoS
- 高并发扫描或爆破
- 破坏性数据修改
- 超出授权范围的端口与网络探测

这个项目的目标是服务于受控研究、学习和授权测试，而不是绕过授权边界。

## Future Work

后续比较值得继续推进的方向包括：

- 更稳定的运行时管理
- 更清晰的工具接口设计
- 更低耦合的 Agent Prompt
- 更完整的截图与报告链路
- 更好的错误处理与日志体系
- 更完善的自动化测试

## Acknowledgement

YuPentestPilot 的整体方向、核心工程理念以及其中关于 AI for 攻防的一些关键判断，主要参考和借鉴了笑神公开分享的探索与实践。更准确地说，这个仓库并不是试图把这些思路包装成一套“完全原创”的新概念，而是基于相关公开经验所做的一次复刻、整理与开源化落地。

这份借鉴主要体现在几个层面：

- 对 AI Agent 本质的理解：强调 LLM 仍然要回到 token prediction、Prompt、Tool Calling 这些基本事实来审视
- 对安全 Agent 设计瓶颈的判断：关注上下文污染、工具过载、流程约束力弱、专家经验难以沉淀等问题
- 对意图工程方向的重视：强调 Prompt Engineering、Context Engineering 之后，应该进一步思考面向意图的表达与执行
- 对 Meta-Tooling 思路的吸收：让 Agent 通过代码而不是多轮自然语言对话去编排工具，把 LLM 从繁琐的原子调用中解放出来
- 对攻防场景工程化路径的启发：把专家经验、运行时、工具封装和可追溯执行记录结合起来，而不仅仅是“给 Agent 塞更多工具”

相关参考链接：

- 笑神相关文章：[微信文章链接](https://mp.weixin.qq.com/s/jT4poWZ4Gfu3faXvul07HA)

感谢笑神公开分享这些关于 AI for 攻防、Intent Engineering、APG、Meta-Tooling 等方向的思考与实践成果。这个仓库在很多地方都直接受到了这些内容的启发。

同时也需要说明，YuPentestPilot 目前并不是对原始设想的完整复现。像 APG 这样的能力并没有在当前仓库中完整落地；现在真正实现并开源出来的核心部分，更多是围绕 Docker 沙箱、Claude Code、Python Executor MCP 和一套可编排的安全工具运行时，用一个更轻量、可复现的方式去承接这条思路。

因此，这个项目更适合被理解为：**对笑神相关方法论的一次工程化复刻与个人化整理版本**。它的目标不是替代原始思考，而是把其中一条很有价值的实践路线变成一个更容易复现、阅读和继续改造的开源仓库。

它的价值不只在于“自动化解题”或“自动化测试”，更在于它尝试展示一种更适合复杂任务的 Agent Runtime 设计方式：

**让 Agent 更少地陷入工具调用细节，让代码承担更多执行编排。**

如果你对这条路线感兴趣，建议也去阅读原始分享，再结合这个仓库的实现一起看，会更容易理解它背后的出发点与演化方向。


