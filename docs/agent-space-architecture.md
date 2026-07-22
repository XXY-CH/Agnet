# Agent Internet Architecture

状态：Repositioned Draft 1
目标：定义 Agnet 的 Web3-native Agent Internet architecture，同时保留已证明的 ASP v14 local-first core 与可审计迁移边界。

## 1. 一句话定位

Agnet 是 **Agent Internet 的主权、可验证协调与可编程结算 Fabric**。其目标协议族名为 **AFP — Agnet Fabric Protocol**。

AFP 运行在现有 Internet 之上，但不等于“带签名的 HTTP”：它提供自证明 `aid:` 身份、端点无关的交付命名、能力授权、异步工作事件、内容绑定 Artifact、Receipt finality 与可选结算承诺。

它不重建 TCP/IP、QUIC、TLS、libp2p 或云和物理链路；这些机制负责搬运字节和建立路径。AFP 负责定义谁能做什么、在哪个受限上下文中做、谁拥有提交权、哪些结果与成本可验证。

## 2. 与 Octo 的区别

Octo 更接近 Agent-native workplace：人类、Agent、工具在 Space、Channel、Thread 里协作。它的核心价值是组织协作界面、IM 式消息流和私有化工作台。

Agent Space 不应直接竞争这个方向。我们的定位应当更底层：

| 维度 | Octo | Agent Space |
| --- | --- | --- |
| 第一用户 | 人类团队 | Agent runtime、开发者、组织系统 |
| 核心对象 | Space、Channel、Thread、Message | Agent ID、Task、Event、Artifact、Receipt、Policy |
| 产品形态 | 协作工作台 | Agent task fabric / control plane |
| 协作方式 | 人和 Agent 在频道中协作 | Agent 通过签名任务和事件流协作 |
| 信任重点 | 组织内权限和工作台治理 | 跨 Agent 身份、权限、审计、撤销和联邦 |
| 协议位置 | 应用层产品 | 可被 Octo、IDE、CLI、企业系统调用的底层网络层 |

理想关系：Octo 可以作为 Agent Space 的一个人类入口或组织协作前端；Agent Space 提供其下方的任务网络、身份、权限、审计和联邦能力。

## 3. 从 Web2 工作流到 Agent Internet

旧式 Web2 Agent integration 以固定 endpoint、平台账号、同步 request/response 和平台数据库为中心。AFP 迁移到下列可验证边界：

| Web2 默认 | AFP / Agent Internet 原则 |
| --- | --- |
| URL 或平台账号是入口 | `aid:` 是自证明主权身份；Zone、域名、relay、registry 是可选绑定 |
| Endpoint 是服务地址 | 内容、mailbox、identity、intent query 和 route hint 分离 |
| API 调用即工作事实 | Task、event、Artifact、receipt、custody 与 settlement 是可重放证据 |
| TLS 登录后开放端口 | 身份认证 + 衰减型 capability grant + 本地 policy + sandbox evidence |
| 长连接是唯一状态通道 | 异步 mailbox、relay custody、重连、checkpoint 与 monotonic handoff |
| 应用层事后结算 | 预算与结算授权绑定经过验证的 delivery/storage/execution/verification commitment |

这不是把所有语义塞进网络包，也不是把区块链或 Token 设为身份根。语义模型只可用于候选召回；协议接受、工具授权、Receipt 和结算必须来自确定性、可验证、可撤销的对象。

## 4. 独立性的边界

Agent Space “部分独立于 Internet”，不是物理独立。

复用现有 Internet：

- TCP/IP
- QUIC
- TLS
- WebSocket
- WebTransport
- HTTP/2 或 HTTP/3
- 云、边缘节点、NAT、CDN

独立于现有 Internet：

- Agent 身份
- Agent 命名和寻址
- 能力声明
- 任务生命周期
- 事件流
- 产物引用
- 权限和策略
- 审计凭证
- Zone 间联邦

简化理解：

```text
Internet 负责搬运字节。
Agent Space 负责定义谁在做什么任务、凭什么权限、产生什么结果、谁负责。
```

## 5. 核心架构

```text
┌──────────────────────────────────────────────┐
│ Product / Semantic OS                         │
│ Principal Agent · intent · approval · UX      │
└──────────────────────┬───────────────────────┘
                       │
┌──────────────────────▼───────────────────────┐
│ Economy & Settlement Adapters                 │
│ offer · budget · meter · escrow · dispute     │
└──────────────────────┬───────────────────────┘
                       │
┌──────────────────────▼───────────────────────┐
│ AFP Evidence & Authority Fabric               │
│ aid · grant · task · event · Artifact · receipt│
│ fence · mailbox custody · replay · settlement │
└──────────────────────┬───────────────────────┘
                       │
┌──────────────────────▼───────────────────────┐
│ Discovery & Delivery                          │
│ capability query · signed offer · relay · DHT │
└──────────────────────┬───────────────────────┘
                       │
┌──────────────────────▼───────────────────────┐
│ Replaceable Peer Substrate                    │
│ local IPC · HTTPS/QUIC · libp2p · relay       │
└──────────────────────┬───────────────────────┘
                       │
┌──────────────────────▼───────────────────────┐
│ Internet Underlay                             │
│ IP · TCP/UDP · QUIC · TLS · NAT · edge        │
└──────────────────────────────────────────────┘
```

U1–U30 already prove the narrow evidence core inside AFP: signed task/event/Artifact/checkpoint semantics, fenced Receipt commitment, replay, output verification, close, disband, and independent verification. ASP v14 remains that implemented compatibility surface; AFP v1 is the next protocol-design and implementation program.

## 6. Agent Zone

Agent Zone 是一个可治理的 Agent 专属空间。

一个 Zone 可以对应：

- 一个公司
- 一个团队
- 一个个人
- 一个高校实验室
- 一个云环境
- 一个设备集群

Zone 内部可以中心化治理。Zone 之间通过 Federation Gateway 互联。

```text
Company A Zone  ── Federation Gateway ── Company B Zone
      │                                      │
   Agents                                 Agents
      │                                      │
   Tools / Data                           Tools / Data
```

设计原则：

- Zone 内强调控制、审计、权限和效率。
- Zone 间强调签名、最小披露、策略协商和可撤销信任。
- 不要求所有 Agent 暴露公网地址。
- 不要求所有 Agent 加入全球 P2P 网络。

## 7. Identity, content, mailbox, and intent addressing

AFP deliberately separates four questions:

| Question | Canonical object | What it must not become |
| --- | --- | --- |
| Who is the Agent? | `aid:` plus a signed descriptor | A DNS name, Zone alias, endpoint, or marketplace account |
| Which immutable bytes? | Content digest plus context-bound manifest | An authorization grant merely because a digest is known |
| Where can encrypted work arrive? | Recipient-controlled mailbox namespace and epoch | Global permanent topology disclosure |
| What bounded work is sought? | Expiring policy-filtered `IntentQuery` | Public unrestricted natural-language broadcast |

`agent://` remains a governed alias/namespace that resolves to an `aid:`. Direct participation works from a pinned `aid:` descriptor without a global name service.

## 8. AFP and implemented ASP v14

AFP is the future Agent Fabric protocol family; ASP v14 is the current local-first implementation. AFP is not HTTP's replacement or a new TCP. Its initial bindings may use local IPC, HTTPS/QUIC, or a reusable libp2p substrate.

AFP object families are:

```text
AgentDescriptor      identity, capability, transport hints, freshness
CapabilityAdvertisement / IntentQuery / Offer
CapabilityGrant      attenuable action/resource/byte/cost/time authority
TaskOpen / TaskClaim / TaskEvent
ArtifactManifest     immutable bytes plus producer/recipient/policy context
MailboxEnvelope / CustodyReceipt
ReceiptCommit / SettlementCommit
```

The corresponding ASP v14 `FED_*` frames remain governed federation objects. AFP must not silently downgrade a rejected federated frame into Direct traffic, and no AFP object becomes wire-compatible until schemas, domain separation, vectors, and migration rules are frozen in AF0.

## 9. AFP narrow-waist invariants

1. **Identity and capability are complementary.** Identity supplies accountability and continuity; a grant supplies bounded authority.
2. **Content address does not grant access.** Every Artifact manifest binds context, recipient, policy, and encryption/access authority.
3. **Discovery is not trust.** A query returns labelled candidates; acceptance remains a local policy decision.
4. **Relay custody is not task acceptance.** Encrypted storage/forwarding cannot forge recipient acceptance, execution, or a Receipt.
5. **Execution is at least once; commitment is selected by fence.** Conflicts remain contested unless the declared lineage selects one authority.
6. **Settlement commits facts, not network folklore.** Payment adapters consume verified delivery, storage, execution, or verification commitments—not raw unreliable packet counts.

## 10. Capability discovery, offers, and routing

```text
1. Principal creates an expiry-bounded, policy-filtered IntentQuery.
2. Discovery returns provenance-labelled capability candidates without granting authority.
3. Candidates return signed Offers with capability proof, limits, price terms, and assurance.
4. Principal chooses under policy, budget, risk, and privacy constraints.
5. Receiver validates identity, trust profile, local policy, and CapabilityGrant.
6. TaskOpen then creates the durable work lineage.
```

Semantic/vector systems may rank candidates locally. They cannot determine identity, authorization, Receipt validity, or settlement.

## 11. Governed federation and sovereign Direct work

Zones remain useful for organizations: aliases, credentials, revocation, policy, private topology, and federation. They are optional governance layers above a canonical `aid:`.

The implemented `FED_*` flow is a governed profile. AFP Direct work is a separate profile with peer pins or selected bootstrap, capability grants, mailbox/delivery evidence, and no implicit Zone creation. Mixed workflows bind the profile of every edge and never auto-downgrade a failed stronger profile.

## 12. Human entry

Human entry points can be an IDE, CLI, browser, workbench, personal principal Agent, or organization system. They must expose the chosen assurance profile—local, Direct, relayed, Zone-governed, or A2A-bridged—rather than displaying a generic “verified” badge.

## 13. Security boundary

External objects are untrusted. Before execution, a receiver must verify the selected identity/trust profile, bounded CapabilityGrant, local policy, resource limits, Artifact access context, and required approval. High-risk actions also need sandbox evidence and immediate authority revalidation before irreversible side effects, Receipt commitment, close, or charge.

## 14. MCP, A2A, ANP, and peer substrates

```text
MCP     = tools, resources, and prompt/context servers
A2A     = interoperable Agent application tasks and messages
ANP     = Web-native Agent identity/discovery/messaging suite
libp2p  = reusable peer transport, relay, discovery, and PubSub substrate
AFP     = sovereign work authority, evidence, custody, and settlement fabric
```

AFP can adapt to these systems but cannot let any of them replace its local policy, authority, Artifact, Receipt, or downgrade semantics.


## 15. Current non-goals

The current repository does not yet ship:

- AFP v1 wire schemas or bindings;
- public DHT/P2P routing, relay custody, NAT traversal, or public discovery;
- token, blockchain, stablecoin, Lightning, or marketplace integration;
- a global shared memory, reputation truth score, or semantic routing authority;
- anonymous unrestricted remote execution;
- a replacement for MCP, A2A, ANP, libp2p, browsers, or the Internet underlay.

These are explicit scope boundaries. AFP allows settlement and peer substrates later without making any specific chain, asset, or provider mandatory.

## 16. Historical ASP MVP baseline

This section records the original local/governed MVP boundary. It describes ASP v14-compatible prototype work, not AFP v1 transport semantics.

最小可用版本应包含：

1. Agent Zone Controller
   - registry
   - policy engine
   - audit log
   - event broker

2. Agent Runtime
   - 接收 Signed Task
   - 发出 Task Event
   - 生成 Artifact Ref
   - 产生 Receipt
   - 通过 MCP 或本地 adapter 调用工具

3. ASP v14 over WebSocket (historical prototype binding)
   - HELLO
   - AUTH
   - TASK_OPEN
   - TASK_EVENT
   - ARTIFACT_REF
   - RECEIPT
   - TASK_CLOSE

4. Human Gateway
   - 查看任务
   - 审批高风险操作
   - 查看产物
   - 查看审计

5. Federation Gateway 雏形
   - 两个 Zone 间转发 signed task
   - 策略拒绝
   - receipt 返回

## 17. Protocol-family roadmap

```text
ASP v14    Implemented local-first proof and governed federation compatibility

AFP-0xx    Core identity, descriptor, capability grant, task/event/Artifact,
           mailbox custody, receipt, settlement, and transport bindings

AFP-1xx    Discovery query/offers, Direct Swarm, verifier profiles, A2A mapping

AFP-2xx    Settlement adapters, disputes, governance, and product assurance UX
```

AFP numbering is reserved until AF0 freezes schemas, domain separation, compatibility, and vector requirements. Existing ASP identifiers remain historical/implemented identifiers until an explicit migration contract exists.

## 18. 第一阶段验证目标

第一阶段不证明“下一代互联网成立”。

只证明：

```text
两个不同 Agent runtime
在同一个 Zone 内
通过 agent:// 被发现
通过 ASP 建立会话
执行一个签名任务
流式返回事件
产生一个 artifact
留下 receipt
并在高风险操作时触发人类审批
```

第二阶段再证明：

```text
两个 Zone
通过 Federation Gateway
完成跨 Zone signed task
且双方策略、事件、产物、审计都可验证
```

## 19. Core judgment

Agent Internet is not proven by abandoning HTTP, by adopting a blockchain, or by broadcasting every Intent through a DHT.

It is proven when:

- an Agent owns an identity independent of URL, Zone, relay, and platform;
- a bounded capability grant—not ambient connection authority—authorizes work;
- work survives transport change through durable, encrypted, causal delivery semantics;
- Artifacts, Receipts, and settlement facts can be independently verified;
- discovery, relays, and payment providers remain replaceable infrastructure;
- organizations can add governance without owning an Agent's global identity; and
- humans retain intent, approval, explanation, revocation, and dispute authority.

```text
aid + capability grant + signed task/event + context-bound Artifact
+ fence-selected Receipt + optional custody/settlement commitment
```

This is the minimal Web3-native Agent Fabric. U1–U30 provide its local evidence base; AFP v1 makes it portable across independent Agents and transports.
