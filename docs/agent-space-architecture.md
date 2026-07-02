# Agent Space 架构构想草案

状态：Draft 0  
目标：把 Agent 专属网络空间的核心构想固化为可讨论、可拆分、可实现的架构文档。

## 1. 一句话定位

Agent Space 是建立在现有 Internet 之上的 Agent 专属 overlay space。

它不重建 TCP/IP、DNS、TLS、云和物理链路，而是在这些基础设施之上，建立一套独立的 Agent 身份、寻址、任务、事件、权限、审计和联邦规则。

核心目标不是让 Agent “访问更多 HTTP API”，而是让 Agent 进入一个可发现、可授权、可执行、可恢复、可追责的任务网络。

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

## 3. 与原始构想的区别

原始构想更像终局版 IoA：全球去中心化、语义向量寻址、P2P/DHT、微支付、全局声誉、共享记忆和机器经济。

本草案把目标压缩为可落地内核：

| 原始构想 | 本草案 |
| --- | --- |
| 全球去中心化 Agent 网络 | 先做可治理的 Agent Zone，Zone 间再联邦 |
| 向量语义寻址是核心 | Agent ID 是核心，语义向量只做发现和排序 |
| P2P/DHT 是底层依赖 | P2P 是可选 transport，不作为 v1 前提 |
| 微支付、声誉、智能合约 | 先用权限、审计、配额、组织账单和服务等级 |
| 共享黑板/全局记忆 | scoped workspace / task context |
| 类似新 Internet | Internet 上的 Agent overlay |
| 重点是找到最合适 Agent | 重点是安全地把任务交给 Agent 并追责 |

这不是否定终局构想，而是把终局拆成可以先活下来的最小协议层。

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
│ Human / App Entry                             │
│ Octo / IDE / CLI / Browser / API              │
└──────────────────────┬───────────────────────┘
                       │
┌──────────────────────▼───────────────────────┐
│ Gateway Layer                                  │
│ 人类审批、组织边界、会话映射、UI 能力协商       │
└──────────────────────┬───────────────────────┘
                       │
┌──────────────────────▼───────────────────────┐
│ Agent Space Protocol Narrow Waist             │
│ SignedTask / Event / Artifact / Receipt        │
└──────────────────────┬───────────────────────┘
                       │
┌──────────────────────▼───────────────────────┐
│ Control Plane                                  │
│ Registry / Capability / Policy / Scheduler     │
│ Audit / Revocation / Federation                │
└──────────────────────┬───────────────────────┘
                       │
┌──────────────────────▼───────────────────────┐
│ Data Plane                                     │
│ Event stream / Object store / Stream relay     │
│ Checkpoint / Artifact cache                    │
└──────────────────────┬───────────────────────┘
                       │
┌──────────────────────▼───────────────────────┐
│ Agent Runtime Nodes                            │
│ Sandbox / MCP tools / A2A adapter / Web API    │
└──────────────────────────────────────────────┘
```

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

## 7. Agent ID 与 agent://

HTTP URL 表示某台服务器上的某个资源：

```text
https://example.com/api/run
```

Agent ID 表示一个 Agent 身份、能力或逻辑位置：

```text
agent://acme/security.audit.v1
agent://personal.xxyu/codex.builder
agent://lab-a/research.paper-reviewer
capability://code.review.security
```

`agent://` 是命名和寻址层，不是底层传输层。

它需要经过解析，得到 Agent Descriptor。

示例：

```json
{
  "agent_id": "agent://acme/security.audit.v1",
  "zone": "acme",
  "public_key": "ed25519:...",
  "capabilities": [
    "code.audit",
    "security.review",
    "dependency.risk"
  ],
  "transports": [
    "asp+wss://gateway.acme.com/agent",
    "asp+quic://gateway.acme.com:7443"
  ],
  "policy": {
    "requires_signed_task": true,
    "external_network": "deny_by_default",
    "human_approval": [
      "write",
      "payment",
      "external_network"
    ]
  },
  "attestation": [
    "sandboxed-runtime",
    "signed-build"
  ]
}
```

## 8. ASP：Agent Space Protocol

ASP 是 Agent Space 的连接和任务协议。

它不是 HTTP 的替代底层，也不是新 TCP。ASP 是跑在现有传输之上的应用协议。

推荐 transport binding：

```text
asp+wss://      v1 必须支持，方便穿透企业网络
asp+quic://     v1 推荐支持，用于低延迟、多路复用和长连接
asp+local://    本机 Agent 通信
asp+a2a://      兼容 A2A 生态
asp+libp2p://   后续支持 P2P 节点
```

连接流程：

```text
1. Resolve agent://
2. 获取 Agent Descriptor
3. 建立 asp+wss 或 asp+quic 连接
4. 双方用 Agent ID 和公钥签名握手
5. 协商能力、权限、预算、事件通道
6. 打开 task channel
7. 流式传输 event、artifact ref、receipt
8. 任务完成、失败、取消或 checkpoint
```

最小帧类型：

```text
HELLO           身份握手
AUTH            签名认证
CAPABILITY      能力声明
TASK_OPEN       创建任务
TASK_EVENT      任务事件
ARTIFACT_REF    产物引用
APPROVAL_REQ    人类审批请求
POLICY_DENY     权限拒绝
RECEIPT         审计凭证
TASK_CLOSE      关闭任务
PING/PONG       心跳
```

HTTP 是 request/response。

ASP 是：

```text
signed session -> task -> event stream -> artifact -> receipt
```

## 9. 窄腰协议对象

Agent Space 的窄腰应该尽量小。第一版只定义五个核心对象。

### 9.1 Signed Task

任务是 Agent Space 的核心单位。

```json
{
  "task_id": "task_123",
  "from": "agent://personal.xxyu/main",
  "to": "capability://code.review.security",
  "intent": "Review this repository for security issues",
  "scope": {
    "files": ["src/**"],
    "network": false,
    "write": false
  },
  "budget": {
    "tokens": 200000,
    "time_seconds": 1800
  },
  "deadline": "2026-07-02T12:00:00Z",
  "requires_human_approval": true,
  "signature": "ed25519:..."
}
```

### 9.2 Event

事件描述任务状态变化。

```text
task.accepted
task.started
task.progress
artifact.created
approval.required
task.blocked
task.failed
task.completed
task.cancelled
```

### 9.3 Artifact

产物不直接塞进消息体，而是用引用。

```text
artifact://acme/task_123/report.md
artifact://acme/task_123/patch.diff
artifact://acme/task_123/audit.json
```

### 9.4 Receipt

Receipt 是审计凭证。

它回答：

```text
谁
在什么时候
以什么权限
调用了什么工具
访问了什么数据
产生了什么产物
由谁签名
```

### 9.5 Policy

Policy 描述任务可做什么，不可做什么。

重点约束：

- 文件访问
- 网络访问
- 工具调用
- 数据域
- 写入权限
- 支付权限
- 人类审批
- 权限过期时间

## 10. 能力发现与路由

Agent Space 不应把语义向量当成最终地址。

推荐分层：

```text
Agent ID       稳定身份
Capability    能力声明
Credential    能力证明
Vector        发现和排序信号
Policy        是否允许调用
Receipt       调用后可追责
```

一次能力寻址流程：

```text
1. 用户或 Agent 产生 intent
2. Router 生成 capability query
3. Registry 返回候选 Agent
4. 按能力、凭证、成本、延迟、策略、历史表现排序
5. 创建 Signed Task
6. 被选 Agent 接受或拒绝
7. 任务开始执行
```

向量用于召回候选，不用于定义身份。

## 11. Federation Gateway

Federation Gateway 负责 Zone 间互联。

它不暴露内部所有 Agent 拓扑，只暴露本 Zone 愿意公开的能力、策略和入口。

职责：

- 验证外部 Zone 身份
- 映射外部任务到本地策略
- 拒绝不合规任务
- 转发已签名任务
- 记录跨 Zone receipt
- 隐藏内部 Agent 地址
- 支持撤销和熔断

跨 Zone 任务流：

```text
Local Agent
  -> Local Zone Gateway
  -> Remote Zone Gateway
  -> Remote Policy Engine
  -> Remote Agent Runtime
  -> Signed Events / Artifacts / Receipts
  -> Local Zone
```

## 12. 人类入口

人类不应直接面对海量 Agent。

人类入口可以是：

- Octo 这类协作工作台
- IDE
- CLI
- 浏览器扩展
- 个人主理 Agent
- 企业内部系统

Human Gateway 负责：

- 展示任务状态
- 发起审批
- 管理授权
- 查看产物
- 查询审计
- 中止任务

关键设计：人类入口可以很多，但它们都调用同一个 Agent Space 任务协议。

## 13. 安全边界

默认不信任任何外部 Agent。

安全基线：

- 所有任务必须签名。
- 所有跨 Zone 调用必须经过 Gateway。
- 所有工具调用必须经过 policy 检查。
- 外部输入默认不可信。
- 写操作、支付、外部网络访问默认需要显式授权。
- 高风险任务必须支持人类审批。
- 任务必须产生 receipt。
- Agent 异常时可以熔断、撤销、隔离。

沙箱建议：

- 本地普通任务：进程级或容器级隔离。
- 执行外部代码：容器、gVisor、Firecracker 或 WASM。
- 高敏感数据：后续考虑 TEE 和远程证明。

## 14. 与 MCP 和 A2A 的关系

Agent Space 不应替代 MCP 或 A2A。

推荐定位：

```text
MCP = Agent 如何使用工具和数据源
A2A = Agent 如何与 Agent 通信和交换任务状态
Agent Space = Agent 如何被发现、授权、执行、审计和联邦治理
```

实现上应当：

- 支持 MCP tool server 作为 Agent Runtime 的工具层。
- 支持 A2A Agent Card / task / artifact 概念的兼容映射。
- 在 A2A 之上补 Zone、Policy、Audit、Federation 和 runtime governance。

## 15. 非目标

第一版明确不做：

- 全球 P2P 路由
- 区块链结算
- Token 经济
- 全局共享记忆
- 通用搜索引擎
- 新 DNS
- 完整 IM 产品
- 取代浏览器
- 取代 MCP
- 取代 A2A

这些不是永远不做，而是不作为协议内核。

## 16. MVP 范围

详细边界见 `docs/mvp-boundary.md`。Agent ID 计算规则见 `docs/asp-001-agent-identity.md`。

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

3. ASP over WebSocket
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

## 17. 规范拆分

建议后续拆成以下规范：

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
```

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

## 19. 核心判断

Agent Space 是否成立，不取决于它是否完全摆脱 HTTP。

它取决于：

- Agent 是否拥有独立于 URL 的身份。
- Agent 是否通过任务而非普通请求协作。
- 任务是否有权限边界。
- 长任务状态是否存在于 Agent Space。
- 产物是否可引用、可验证。
- 执行过程是否可审计。
- Zone 之间是否可以联邦。

HTTP、WebSocket、QUIC 只是运输车。

真正的新东西是：

```text
Agent identity + signed task + event stream + scoped policy + artifact + receipt + federation
```

这就是 Agent 专属空间的最小内核。
