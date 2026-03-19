# IntentLang Plan Memory

## Current Goal

YuPentestPilot 的中长期目标不是单纯做一个 “Agent + 一堆工具” 的自动化脚本，而是做一个 **CTF / Pentest 双用的高智能攻防运行时**。

当前优先目标：

- 同时支持 CTF 与授权 Web 渗透测试
- 尽量保持对 `intentlang` 初衷的忠实
- 在高智能渗透 / CTF 执行能力上，尽量和普通真人选手或传统 Agent 方案拉开差距
- 外部使用方式尽量保持稳定，不轻易破坏现有 CLI 和工作流

## Current Implementation Status

截至目前，Phase 1 的 intent-native 骨架已经不是纯计划，而是已经有一套可运行实现。

已经落地的关键点：

- 新增内部 `intentlang` 运行层
  - 在运行前生成 `Intent` / `Strategy` / `Runtime Object`
  - 在 workspace 下初始化 `intentlang/metadata` 与 `intentlang/artifacts`
- 主入口 `YuPentestPilot.py` 已切到 intent-native 初始化路径
  - 不再直接手写两段模式 prompt 作为唯一控制面
  - 运行前会先 bootstrap runtime metadata / artifacts
- 已落地的 runtime metadata
  - `run`
  - `strategy`
  - `intents`
  - `runtime_objects`
  - `artifact_schemas`
- 已落地的 artifacts
  - `recon_summary`
  - `surface_map`
  - `hypotheses`
  - `candidate_findings`
  - `candidate_evidence`
  - `verified_findings`
  - `final_report_reference`
- 已落地的 strategy
  - `PentestStrategy`
  - `CTFStrategy`
- 已落地的 intent
  - `WebReconIntent`
  - `WebVerificationIntent`
  - `CTFGoalIntent`
- 已将 `toolset.intentlang` 接入容器内能力层
  - 支持读取 metadata / artifact
  - 支持 append / replace / promote
  - 支持 CTF flag 记录与 CTF 报告输出
  - 支持模板友好的 `append_verified_finding()`
- 已将 agent prompt 调整为 artifact-first
  - 先读 metadata / schema
  - 优先写 artifact，而不是只写 note 或只靠上下文记忆
- 已将 pentest 报告主路径切到 Word 输出
  - 最终报告强制为 `.docx`
  - 报告由代码直接生成，不依赖仓库内私有模板
  - 最终通过 `final_report_reference` 回写报告路径

## Current Workflow

当前真实的 pentest 主链路已经演进为：

1. 宿主机启动 `YuPentestPilot.py`
2. 运行前 bootstrap `intentlang/metadata`、`intentlang/artifacts`
3. 容器内 agent 先读取：
   - `run`
   - `strategy`
   - `intents`
   - `runtime_objects`
   - `artifact_schemas`
4. 侦察阶段写入：
   - `recon_summary`
   - `surface_map`
   - `hypotheses`
5. 验证阶段写入：
   - `candidate_findings`
   - `candidate_evidence`
   - `verified_findings`
6. 报告阶段优先从 `verified_findings` 直接生成 Word 报告
7. 最终将报告路径写入 `final_report_reference`

当前真实的 CTF 主链路为：

1. 仍然走 intent-native runtime 初始化
2. 围绕 `CTFGoalIntent` 执行
3. flag 获取后写入 `verified_findings`
4. 输出 flag，必要时保存简化 CTF 报告

## What Has Been Resolved

本轮开发实际上已经解决了几个关键偏差：

1. 不再只靠模式 prompt 驱动
   - Prompt 仍存在，但已经退居为 runtime contract 的解释层
   - 真正的结构化控制面已经落在 runtime metadata / artifact / strategy

2. Artifact 不再是口头约定
   - 已有真实落盘目录
   - 已有 schema
   - 已有校验、默认值、枚举约束
   - 已有 promote 和 append_verified_finding 等高层入口

3. Pentest 输出已经不再是“随便生成一个报告”
   - 已强制收敛到 Word
   - 已能直接从 `verified_findings` artifact 生成报告

4. 外部兼容性基本保持
   - CLI 未破坏
   - `YuPentestPilot.py` 仍是主入口
   - `tinyctfer.py` 仍兼容
   - workspace 输出位置未改变

## Phase 1 Closure Status

第一阶段原先剩余的几项收尾项，当前已经完成：

- 已补上正式 repo 内端到端测试
  - 测试文件：`tests/test_intentlang_e2e.py`
  - 已覆盖 `YuPentestPilot.main()` 在 `ctf` / `pentest` 下的 bootstrap
  - 已覆盖 `append_verified_finding -> generate_word_report_from_artifacts -> final_report_reference`
  - 已覆盖 `record_ctf_flag -> save_ctf_report -> final_report_reference`
- `verified_findings` 已补上更强的去重 / 更新机制
  - `append_artifact_item("verified_findings", ...)` 会按身份自动 merge
  - 已新增 `upsert_verified_finding()`
  - 已新增 `deduplicate_verified_findings()`
- report 模块已收紧到 Word 主路径
  - HTML 报告分支已从 Phase 1 主实现中移除
  - `generate_report()` 仅接受 `docx`
- 模板字段默认补齐已前移到 artifact 写入层
  - `control_point` / `evaluation_unit` / `risk_analysis` / `test_process` 等字段在写入 `verified_findings` 时就会补齐最小值
  - report 阶段不再承担主要的“猜测映射”职责
- artifact-first 工作流文档已同步
  - README 已补充 upsert / dedup / Word-only 报告链路
  - README 已补充当前测试入口

## Agreed Design Principles

目前已确认的核心原则：

1. **IntentLang 优先**
   - 第一阶段不以传统 workflow engine 为中心
   - 第一阶段以 `Intent`、`Runtime Object`、`Capability`、`Artifact` 为中心

2. **不要回退到大 Prompt 驱动**
   - 不能继续把主要控制流塞进超长 prompt
   - Agent 不应只是“解释 prompt”，而应执行结构化意图

3. **不要先做通用 DAG / APG Runtime**
   - APG 很重要，但不进入第一阶段
   - 第一阶段先把 intent-native runtime 做稳，再考虑更高层编排

4. **不要先做多 agent**
   - 第一阶段不以 subagent orchestration 为重点
   - 先把单 runtime + 高价值 intent 跑通

5. **共享 runtime，分离策略**
   - CTF 与 Pentest 共用底层 runtime / capability / artifact 体系
   - 通过 strategy 区分行为、优先级、退出条件和输出形态

## Phase 1 Direction

第一阶段不是先做一个通用阶段机，而是先建立最小的 intent-native 系统。

第一阶段的最小核心抽象：

- `Intent`
- `Runtime Object`
- `Capability`
- `Artifact`
- `Strategy`

当前判断：

- 这组最小抽象已经落地
- 当前剩余工作不再是“是否要做 intent-native runtime”
- 而是继续把这条 runtime 做稳、做严、做可复盘

### 必须先实现的 Intent

第一阶段只做 3 个高价值 intent：

- `WebReconIntent`
- `WebVerificationIntent`
- `CTFGoalIntent`

说明：

- `WebReconIntent`
  - 用于目标访问、技术栈识别、认证方式识别、入口点与参数面探索
- `WebVerificationIntent`
  - 用于把候选攻击面转化为已验证 finding 和 evidence
- `CTFGoalIntent`
  - 用于围绕 flag 获取进行高收益探索、利用和证据保留

### Runtime 形态

第一阶段 runtime 应该支持：

- 接收结构化 intent，而不是只接收长 prompt
- 将 browser / terminal / proxy / report 作为 embedded runtime objects 提供给 Agent
- 在执行过程中持续写入 artifact
- 允许后续 intent 消费已有 artifact，而不是重新靠上下文回忆

## Artifact Strategy

要想让系统比普通 Agent 更强，必须优先补齐 artifact 和记忆能力。

第一阶段应至少落盘这些 artifact：

- recon summary
- surface map
- hypotheses
- candidate findings
- candidate evidence
- verified findings
- final report reference

重要原则：

- **宽进严出**
- 不要求 Agent 在写入时就精确判断“高价值”
- 只要它认为值得记录，就先写入 candidate 层
- 在 reporting 前再过滤、归并和收敛

当前实现补充：

- artifact 已经不是自由 JSON
- 每类 artifact 已有最小 schema
- 已有默认值与枚举约束
- `verified_findings` 已支持正式报告需要的字段：
  - `control_point`
  - `evaluation_unit`
  - `risk_analysis`
  - `vuln_url`
  - `test_process`
  - `vuln_code`

## Strategy Layer

第一阶段就要显式区分 CTF 与 Pentest 的策略，而不是只靠 prompt 文本隐式区分。

建议至少有两类策略：

- `PentestStrategy`
- `CTFStrategy`

策略决定的内容包括：

- 优先测试类型
- 允许的激进程度
- 是否允许早停
- 证据完整性要求
- hypothesis 排序方式
- 报告输出要求

## What Phase 1 Should Not Do

第一阶段明确不做：

- 不先做通用 DAG / graph orchestration
- 不先做完整 APG runtime
- 不先做多 agent 协作系统
- 不先扩展到太多安全领域
- 不先重写现有全部 toolset
- 不把 `intentlang` 退化成“以后可能接”的装饰层

## Compatibility Expectations

即使内部架构开始 intent-native 化，外部使用方式最好尽量保持稳定：

- CLI 尽量不变
- `YuPentestPilot.py` 继续保留主入口
- `tinyctfer.py` 继续兼容旧入口
- workspace 输出位置尽量不变
- VNC 观察方式尽量不变

变化应尽量限制在内部执行层，而不是优先改变用户的使用习惯。

当前兼容性结果：

- 这一原则基本满足
- 目前最大的外部行为变化只有：
  - pentest 最终报告已强制变为 Word 输出
  - 内部 workspace 多了 `intentlang/` 目录

## Future Phases

只有在第一阶段满足下面条件后，才进入下一阶段：

- intent 执行链稳定
- artifact 持续落盘可复盘
- WebReconIntent 跑通
- CTFGoalIntent 跑通
- WebVerificationIntent 能稳定输出 verified findings / evidence

第二阶段再决定是否引入：

- 更强的 intentlang 表达方式
- 更高层 graph / APG 风格编排
- 更复杂的 strategy 组合
- 更多目标域与能力扩展

## Suggested Next Actions

第一阶段建议动作已经完成，下一步不再是“把 phase 1 补齐”，而是二选一：

1. 进入 Phase 2 设计
   - 评估是否要引入更强的 intent 表达、graph / APG 风格编排、或更复杂 strategy 组合
2. 做工程化增强
   - 强化异常处理、日志、提示词与 capability 文档一致性，以及更完整的 CI / 回归测试

## Important Notes

我们已经明确达成的一个共识：

- 如果只是先做传统阶段机，再把 `intentlang` 放到后面，这会在工程上更稳，但会偏离 `intentlang` 最激进的初衷
- 所以当前选定的方向是：**第一阶段就以 intent-native runtime 为中心**
- 同时，渗透 / CTF 能力增强不是后加项，而要在第一阶段就通过高价值 intent 和 artifact / strategy 体系一起落地

补充结论：

- 当前代码状态已经证明这条方向可以在不破坏现有入口的前提下逐步落地
- 也就是说，第一阶段已经不再是“方向假设”，而是已经形成可运行实现
