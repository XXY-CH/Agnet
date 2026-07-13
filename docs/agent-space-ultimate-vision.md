# Agent Space 终极构想

状态：Vision Draft 0  
关系：本文描述长期终局，不作为第一版实现范围。可落地版本见 `docs/agent-space-architecture.md`。

## Current status (2026-07-13)

The 30-unit local foundation slice is complete: U1-U30 now provide a local proof kernel spanning signed transport/task/receipt/artifact/reachability evidence and the Phase C Go-local durable Swarm. The durable Swarm uses a same-host filesystem journal under OS process locks, replayable views, deterministic parallel ready waves, a byte-stable close, output verification, and irreversible signed disband. Workers remain at-least-once; only the fenced signed receipt commitment is exactly-once. Node is a pure verifier of fixed offline U29 vectors for this durable format.

The current proof boundary is intentionally narrower than the vision: live public proof covers transport/task/receipt/artifact/reachability, not durable Swarm completion. The completed slice does not claim globally distributed operation, public durable-Swarm completion, real Docker smoke, hardware attestation, cross-host operation, remote artifact handling, or exactly-once worker execution.

[INFERENCE] full Ultimate is ~55-65% complete. This is an architectural-coverage estimate, not a production-readiness metric: the proof kernel spans much of the narrow waist, while every distributed, economic, human-facing, and operational layer below remains incomplete.

### Remaining programs, in dependency order

| # | Program | Why it follows | Exit criterion |
| --- | --- | --- | --- |
| 1 | Public overlay and reachability | Extends the scoped local transport proof before workloads can leave one host/Zone. | Independent, globally routable multi-zone reachability evidence; relay/NAT policy; observable routing failure semantics. |
| 2 | Distributed discovery and reputation | Needs public topology before capability and reputation information can be safely propagated. | Interoperable distributed capability discovery, freshness/revocation propagation, reputation provenance, and abuse/Sybil controls. |
| 3 | Remote task fabric and artifact plane | Needs discovered peers and routable Zones before remote work can be recovered and audited. | Multi-host task/event recovery, durable remote artifact references and retrieval, and end-to-end receipt/artifact verification. |
| 4 | Cross-host Swarm coordination | Builds on a remote fabric; the completed Phase C journal remains explicitly same-host. | Membership, leases/fencing, recovery, deterministic scheduling, and close/disband evidence across independent hosts. |
| 5 | Hardware-backed trust and isolation | Cross-host execution needs stronger evidence than local sandbox claims. | Hardware-backed attestation or equivalent verifiable isolation evidence, distributed revocation, and production key lifecycle. |
| 6 | Knowledge network | Requires trusted remote work and artifacts before knowledge can be attributed and reused. | Ingestion, citation/conflict graph, semantic index, source reputation, freshness, and license-policy enforcement. |
| 7 | Semantic OS and human governance | Requires task, trust, and knowledge evidence that people and organizations can inspect and control. | Intent workspace, explainability, approvals, revocation, organizational policy, and accountable human-facing workflow. |
| 8 | Economy, governance, and production operations | Depends on measurable work, trust, human controls, and a stable distributed fabric. | Metering, quotas, settlement, disputes, governance controls, observability, incident response, and production SLOs. |

## 1. 终极目标

Agent Space 的终局不是一个 Agent 聊天平台，也不是一个更复杂的 API 网关。

它的终极目标是：在现有 Internet 之上，形成一个面向 Agent 的独立逻辑网络，让 Agent 能够以身份、能力、任务、信任和经济约束为基础，自主发现、协商、协作、验证和结算。

如果传统 Internet 连接的是主机、网页和人类应用，那么终局 Agent Space 连接的是：

- Agent 身份
- Agent 能力
- Agent 任务
- Agent 组织
- Agent 记忆
- Agent 信任
- Agent 劳动

它不是替代 Internet，而是在 Internet 之上长出一层 Agent 社会的基础设施。

## 2. 终局形态

终局 Agent Space 是一个多层 overlay civilization：

```text
Human Society
  人类目标、审批、治理、法律责任

Semantic OS
  个人主理 Agent、组织入口、任务看板、意图界面

Agent Economy
  服务市场、信誉、保险、配额、结算、责任边界

Agent Swarm Layer
  动态组队、角色分配、协作拓扑、任务 DAG

Trust & Verification Layer
  身份、凭证、沙箱、远程证明、审计、共识验证

Agent Task Fabric
  signed task、event stream、artifact、receipt、checkpoint

Agent Discovery Layer
  Agent ID、能力寻址、语义召回、信誉排序、局部路由

Agent Overlay Network
  Zone、Federation、P2P relay、DHT、edge gateway

Internet Underlay
  TCP/IP、QUIC、TLS、WebSocket、HTTP、云、边缘网络
```

## 3. 从 Web 到 Agent Space 的范式变化

传统 Web：

```text
人类打开浏览器
输入 URL
访问网页
阅读信息
手动比较
手动决策
手动操作
```

终局 Agent Space：

```text
人类表达意图
个人 Agent 理解目标
Agent Space 发现能力
动态组建 Swarm
签署任务契约
异步执行任务
持续验证结果
请求人类审批关键节点
交付可审计产物
沉淀经验和信誉
```

人类不再逐页访问信息，而是委托 Agent 在 Agent Space 中完成任务。

浏览器的中心地位会下降，个人主理 Agent、语义操作系统和任务工作台会成为新入口。

## 4. 独立性的终局含义

终局 Agent Space 仍然复用 Internet 的物理和传输能力，但在以下方面独立：

### 4.1 身份独立

Agent 不依附于域名、IP、云厂商账号或某个应用平台。

Agent 拥有长期 Agent ID、公钥、能力档案、历史 receipt、信誉轨迹和可撤销凭证。

### 4.2 寻址独立

人类和 Agent 不再主要通过 URL 找服务，而是通过：

- Agent ID
- capability query
- intent query
- trust requirement
- policy constraint

寻找合适执行者。

`agent://` 是身份入口，`capability://` 是能力入口，向量语义是发现信号，不是最终身份。

### 4.3 协作独立

Agent 不再依赖同步 HTTP 请求链条，而是通过任务、事件、产物和审计凭证协作。

长任务、失败恢复、人类审批、状态流、断点续传、产物引用成为协议原生能力。

### 4.4 信任独立

信任不再只依赖 HTTPS 证书、平台账号或云厂商边界。

终局信任来自：

- 密码学身份
- 可验证凭证
- 任务级权限
- 沙箱隔离
- 远程证明
- 动态信誉
- 多方验证
- 审计 receipt
- 可撤销授权

### 4.5 经济独立

Agent 之间可以进行机器级资源交换：算力、工具、数据、推理、验证、存储、出口代理、专家能力。

但终局经济不是一上来就上链。它应从组织账单、配额、服务等级、保险池和责任边界演化，再进入跨组织自动结算。

## 5. 语义寻址的终局

终局 Agent Space 需要语义寻址，但不能把语义向量当成唯一地址。

最终模型应是多信号路由：

```text
identity match
capability match
credential match
semantic match
policy match
cost match
latency match
reputation match
risk match
availability match
```

向量寻址的价值是召回候选 Agent，尤其是在未知网络中找到潜在能力。

但最终选择必须经过：

- 身份验证
- 能力证明
- 策略检查
- 历史表现
- 成本预算
- 风险评估

终局路由不是“最近向量获胜”，而是“在约束下最可信、最合适、最可追责的执行者获胜”。

## 6. Swarm 的终局

Swarm 不是固定团队，而是被任务召唤出来的临时协作拓扑。

一次 Swarm 生命周期：

```text
1. 人类或上游 Agent 发起意图
2. 主理 Agent 拆解目标和约束
3. Agent Space 召回候选能力
4. 候选 Agent 提供微契约
5. 策略引擎筛选风险
6. 形成任务 DAG
7. Agent 加入加密任务空间
8. 事件驱动执行
9. 关键节点请求审批
10. 输出被验证和合并
11. 产物交付
12. receipt 固化
13. Swarm 解散
14. 信誉和经验沉淀
```

Swarm 的关键不是“多个 Agent 聊天”，而是：

- 任务分解
- 角色分配
- 权限隔离
- 状态同步
- 并行执行
- 冲突解决
- 输出验证
- 失败迁移
- 审计闭环

## 7. 人类在终局中的位置

终局 Agent Space 不能把人类降级成按钮。

人类应保留四种权力：

### 7.1 意图权

人类定义目标、偏好、边界和不可接受结果。

### 7.2 审批权

涉及支付、删除、发布、外部通信、法律风险、隐私数据时，Agent 必须请求人类或组织策略授权。

### 7.3 解释权

Agent 必须能解释关键决策路径、数据来源、风险权衡和替代方案。

### 7.4 撤销权

人类和组织必须能撤销 Agent 权限、终止任务、隔离节点、回滚某些动作。

终局的目标不是让 Agent 取代人类意志，而是把人类从网页点击和重复操作中解放出来，同时保留责任链上的最终控制权。

## 8. Agent 访问人类 Web 的终局

人类 Web 对 Agent 不友好：广告、SEO、验证码、动态渲染、假信息、重复内容、版权边界、反爬限制。

终局 Agent Space 不应让每个 Agent 都直接爬网页。

更合理的结构：

```text
Human Web
  ↓
Agent-native Interface
  MCP server / API / structured feed / signed content package / llms.txt-like index
  ↓
Knowledge Gateway
  parsing / dedup / source reputation / citation / freshness / license
  ↓
Agent Knowledge Layer
  semantic cache / domain index / evidence graph / conflict graph
  ↓
Agent Task Fabric
```

爬虫只应是兜底能力。长期目标是推动网站和数据服务提供 Agent 原生接口。

## 9. 信任的终局

Agent Space 的信任不是二元状态，不是“可信/不可信”。

它是上下文相关的动态概率。

同一个 Agent 可能：

- 在代码审计任务中可信
- 在医疗诊断任务中不可信
- 在低风险任务中可直接调用
- 在高风险任务中必须经过人类审批
- 在跨 Zone 任务中只能访问脱敏数据

终局信任系统由多层组成：

```text
Identity       你是谁
Credential     你被谁证明过
Policy         你现在被允许做什么
Sandbox        你能破坏到什么程度
Receipt        你实际做了什么
Reputation     你过去表现如何
Verification   这次结果是否可信
Insurance      出错后谁承担损失
Revocation     出问题后如何撤销
```

## 10. 机器经济的终局

终局 Agent Space 中，Agent 劳动会成为可组合资源。

可交易对象可能包括：

- 推理服务
- 代码执行
- 数据查询
- 文档解析
- 专业判断
- 仿真计算
- 事实核查
- 安全审计
- 出口网关
- 存储和缓存
- 人类专家审批

但机器经济必须先解决责任问题：

- Agent 失败谁负责
- 算力超支谁负责
- 数据泄露谁负责
- 错误建议谁负责
- 恶意调用如何赔偿
- 新 Agent 如何冷启动
- 高信誉 Agent 如何防垄断

因此终局经济层不应只是微支付，而应包括：

- 配额
- 服务等级协议
- 押金
- 保险池
- 争议仲裁
- 责任上限
- 信誉衰减
- 反 Sybil 机制

## 11. 终局协议族

长期可以形成一组 Agent Space RFC：

```text
ASP-001 Agent Identity
ASP-002 Agent Manifest
ASP-003 Signed Task Envelope
ASP-004 Event Stream
ASP-005 Artifact Reference
ASP-006 Policy Scope
ASP-007 Audit Receipt
ASP-008 Federation Gateway
ASP-009 Transport Binding
ASP-010 MCP / A2A Compatibility

ASP-101 Semantic Discovery
ASP-102 Capability Credential
ASP-103 Reputation Graph
ASP-104 Swarm Contract
ASP-105 Checkpoint & Migration
ASP-106 Knowledge Gateway
ASP-107 Verification Protocol
ASP-108 Agent Economy
ASP-109 Dispute Resolution
ASP-110 Human Governance
```

第一组是可落地内核。第二组是终局演化方向。

## 12. 终局风险

Agent Space 的风险不是传统网络风险的简单延伸。

必须长期处理：

- 幻觉级联
- 语义漂移
- Swarm 目标偏移
- Prompt 注入
- 工具越权
- 数据外泄
- 模型逆向
- 声誉刷分
- Agent 垄断
- 算力耗尽攻击
- 跨 Zone 责任不清
- 人类意图被操纵

这些风险决定了 Agent Space 不能只设计通信协议，还必须设计治理协议。

## 13. 终局判断标准

Agent Space 终局是否成立，不看它是否使用 HTTP，也不看它是否完全 P2P。

它成立的标志是：

1. Agent 有独立身份，而不是附属于某个 URL。
2. Agent 可以基于能力和信任被发现。
3. Agent 之间通过任务和事件协作，而不是普通请求响应。
4. 长任务可以暂停、恢复、迁移、审计。
5. 产物可以被引用、验证、复用。
6. 权限是任务级、上下文级、可撤销的。
7. Zone 可以联邦，而不是依赖单一平台。
8. 人类可以表达意图、审批风险、追责结果。
9. Agent 劳动可以被度量、验证和治理。
10. 错误、欺骗和失控有隔离与补救机制。

## 14. 北极星

传统 Internet 的窄腰是 IP。

Agent Space 的窄腰应是：

```text
Agent identity
+ Signed task
+ Event stream
+ Scoped policy
+ Artifact reference
+ Audit receipt
+ Federation
```

终局 Agent Space 不是“所有 Agent 都连在一起聊天”。

它是一个让机器劳动可以被发现、授权、执行、验证、追责和治理的网络空间。

这是 Agent 时代真正需要的基础设施。
