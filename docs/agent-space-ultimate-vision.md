# Agnet Agent Internet — Ultimate Vision

状态：Vision Draft 1 — Web3-native repositioning
关系：本文描述长期终局和 AFP 方向；当前可验证实现边界见 `docs/implementation-status.md`，AFP v1 design gate 见 `docs/afp-v1-design.md`。

## Current status (2026-07-22)

U1–U30 provide a completed local proof kernel: signed task/event/Artifact/checkpoint semantics, a same-host durable Swarm, replayable views, deterministic parallel ready waves, byte-stable close, output verification, and irreversible signed disband. Worker execution remains at least once; the fenced signed Receipt commitment is the sole exactly-once authority. Node independently verifies fixed offline U29 vectors.

The implementation does **not** yet prove AFP v1, public delivery, remote task recovery, cross-host Swarm, relay custody, DHT/P2P discovery, hardware attestation, or settlement. ASP v14 remains the implemented local-first wire surface; AFP is the future transport-neutral protocol family.

The 30-unit local foundation slice is complete. [INFERENCE] full Ultimate is ~55-65% complete; the revised estimate remains architectural coverage rather than production readiness.

[INFERENCE] Architectural coverage remains ~55–65% of the Ultimate vision. This is not a production-readiness estimate: the evidence narrow waist is mature locally, while the sovereign delivery, distributed, economic, governance, and operational programs remain incomplete.

### Remaining programs, in dependency order

| # | Program | Why it follows | Exit criterion |
| --- | --- | --- | --- |
| AF0 | AFP protocol freeze | A public system cannot safely emerge from implicit ASP-to-Direct reinterpretation. | Schemas, domain separation, capability/custody/settlement invariants, threat model, and vectors are ratified. |
| AF1 | Sovereign Core | Establishes a Zone-free Agent principal before public infrastructure. | Two independent operators complete one invited Direct task with a verifiable Artifact and Receipt. |
| AF2 | Async mailbox and custody | Remote work needs offline delivery and cancellation/expiry ordering. | Relay custody cannot forge delivery, acceptance, execution, or Receipt. |
| AF3–AF4 | P2P reachability, discovery, and offers | Delivery must work before unknown peers can safely meet. | Direct/relayed routes, provenance-labelled discovery, abuse controls, and bounded offer negotiation work. |
| AF5 | Direct Swarm | Reuses remote task, fence, receipt, close, and disband semantics without mandatory Zones. | A chartered multi-host Direct Swarm preserves one terminal lineage under its declared failure model. |
| U31–U68 | Governed/Private profile | Organizations still need zero-egress, consensus, private knowledge, governance, and operations. | Hardened private multi-host deployment consumes AFP common semantics without becoming the identity root. |
| AF6–AF7 | Settlement and product convergence | Economy depends on verifiable resource facts; UX depends on explicit assurance. | Pluggable settlement binds commitments without changing task semantics; users see every edge's assurance profile. |

The prior dependency framing remains historically valid inside the reordered AFP program: Public overlay and reachability; Distributed discovery and reputation; Remote task fabric and artifact plane; Cross-host Swarm coordination; Hardware-backed trust and isolation; Knowledge network; Semantic OS and human governance; Economy, governance, and production operations.

## 1. 终极目标

Agnet 的终局不是 Agent 聊天平台、API gateway、单一链上的市场，或“带签名的 HTTP”。

它是在现有 Internet 之上形成一层 **Agent Internet**：独立 Agent 以主权身份、能力授权、可验证任务、内容绑定 Artifact、可替换交付基础设施和可编程结算为基础，自主发现、协商、协作、验证和结算。

传统 Internet 连接主机、网页和人类应用；Agent Internet 连接：

- Agent identity
- Agent capability and bounded authority
- intent, offer, task, and event lineage
- Artifact and checkpoint evidence
- relay/mailbox custody
- trust, governance, and human control
- measured machine labour and settlement facts

它不是替代 Internet，而是在其上构建可独立验证、可替换基础设施承载的 Agent 社会基础设施。

## 2. 终局形态

```text
Human Society
  intent · approval · governance · legal responsibility

Semantic OS
  principal Agent · workspaces · explanation · assurance UX

Settlement and Economy
  offers · budgets · metering · escrow/credit · disputes · liability

Agent Swarm Layer
  temporary charters · roles · DAGs · fencing · close/disband

AFP Trust & Evidence Fabric
  aid · grants · tasks · events · Artifacts · Receipts · verification

Discovery and Delivery
  capability queries · signed offers · encrypted mailboxes · relays · DHT hints

Reusable Peer Substrate
  local IPC · HTTPS/QUIC · libp2p discovery/relay/pubsub

Internet Underlay
  TCP/IP · QUIC · TLS · WebSocket · HTTP · cloud and edge networks
```

AFP is not a new IP layer. It is the authority and evidence narrow waist above a replaceable peer substrate.

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

### 4.1 身份独立

Agent 不依附于域名、IP、云厂商账号、平台账户、Zone 或链账户。`aid:` 是 canonical identity；Zone、域名、relay、wallet 与 marketplace 都只是可增减绑定。

### 4.2 寻址独立

身份、内容、mailbox、intent 与 route 必须分离。内容以 digest/manifest 独立验证；mailbox 可随 endpoint 或 relay 迁移；intent query 只暴露策略允许的需求约束；发现结果不产生授权。

### 4.3 协作独立

Agent 不依赖同步 HTTP request chain。它们通过持久的 Task、causal Event、Artifact、checkpoint、encrypted mailbox handoff、Receipt 和 close/disband 证据协作。离线、重启、路由迁移、失败重试与取消必须有可验证的顺序语义。

### 4.4 信任独立

信任不是 TLS 登录后开放端口，也不是单一 reputation score。它组合 cryptographic identity、selected trust profile、attenuated capability grant、local policy、sandbox/attestation、Receipt、revocation 和 independent verification。身份提供责任连续性；能力提供可衰减的每次操作授权。

### 4.5 经济独立

机器劳动的预算和结算不应依赖某个平台账本。AFP 将 delivery custody、storage epoch、execution、verification 等资源事实绑定到 Receipt/commitment，再由可替换的企业账本、credit、payment channel、stablecoin 或其他 adapter 结算。区块链、Token、staking 和 marketplace 是可选实现，不是身份或执行前提。

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

AFP 不是对当前 ASP 文件、向量和 frame 的即时重命名。ASP v14 是已实现的 local-first proof compatibility surface；AF0 之后才冻结 AFP 规范族。

```text
AFP-001 Sovereign Agent Identity and Descriptor
AFP-002 Capability Advertisement, Intent Query, and Signed Offer
AFP-003 Attenuated Capability Grant
AFP-004 Task, Event, Checkpoint, and Causal Replay
AFP-005 Context-bound Artifact Manifest and Access Grant
AFP-006 Mailbox Envelope, Custody, Cancellation, and Expiry
AFP-007 Receipt, Fence, Close, and Independent Verification
AFP-008 Direct, Governed, and A2A Assurance Profiles
AFP-009 Peer-Substrate and Transport Bindings

AFP-101 Distributed Discovery and Anti-abuse
AFP-102 Direct Swarm Charter and Authority
AFP-103 Metering and Settlement Commitments
AFP-104 Dispute, Recovery, and Reputation Provenance
AFP-105 Knowledge and Human Governance
```

每个规范都必须声明 domain separation、版本协商、downgrade behavior、privacy disclosure、failure semantics 与跨语言 vectors。没有这些证据，概念名称不是协议。

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

Agent Internet 是否成立，不由是否使用 HTTP、是否完全 P2P、是否有 Token 或是否运行在某条链上决定。

它成立的标志是：

1. Agent 拥有不依附 URL、Zone、relay、平台或链账户的主权身份。
2. identity、content、mailbox、intent 与 route 相互独立且可验证。
3. discovery 只提供候选和证据，不成为信任、授权或身份权威。
4. capability grant 可衰减、可撤销、受资源/成本/时间约束；连接本身不授予执行权限。
5. 异步 delivery、relay custody、acceptance、cancellation 与 expiry 有可验证的单调顺序。
6. Task、Artifact、Receipt、close 和 settlement facts 可独立验证、重放和争议处理。
7. Zone 可以增加治理，但不拥有 Agent 的 global identity；Direct 与 governed profile 不可静默降级。
8. 人类可以表达 intent、审批风险、理解 assurance、撤销权限并处理争议。
9. Agent 劳动可度量、可约束、可结算，且结算 rail 可以替换。
10. 失败、欺骗、Sybil、资源耗尽、隐私泄露和 authority fork 有明确拒绝或 contested 行为。

## 14. 北极星

传统 Internet 的窄腰是 IP；Agent Internet 的逻辑窄腰是 AFP evidence and authority fabric：

```text
aid
+ capability grant
+ signed task and causal events
+ context-bound Artifact
+ fence-selected Receipt
+ optional mailbox custody and settlement commitment
```

终局不是“所有 Agent 都连在一起聊天”。它是一个让机器劳动能在可替换基础设施上被发现、受限授权、执行、验证、结算、追责和治理的网络空间。
