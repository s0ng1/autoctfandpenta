# IntentLang Plan Memory

## Current Goal

YuPentestPilot 的中长期目标不是单纯做一个 “Agent + 一堆工具” 的自动化脚本，而是做一个 **CTF / Pentest 双用的高智能攻防运行时**。

当前优先目标：

- 同时支持 CTF 与授权 Web 渗透测试
- 尽量保持对 `intentlang` 初衷的忠实
- 在高智能渗透 / CTF 执行能力上，尽量和普通真人选手或传统 Agent 方案拉开差距
- 外部使用方式尽量保持稳定，不轻易破坏现有 CLI 和工作流

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

## Important Notes

我们已经明确达成的一个共识：

- 如果只是先做传统阶段机，再把 `intentlang` 放到后面，这会在工程上更稳，但会偏离 `intentlang` 最激进的初衷
- 所以当前选定的方向是：**第一阶段就以 intent-native runtime 为中心**
- 同时，渗透 / CTF 能力增强不是后加项，而要在第一阶段就通过高价值 intent 和 artifact / strategy 体系一起落地
