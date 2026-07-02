# Agent Space MVP 边界

状态：Draft 0  
原则：先证明最小闭环，不做终局系统。

## 1. MVP 目标

MVP 只证明一件事：

```text
一个 Agent Zone 内的两个 Agent
可以用独立 Agent ID 互相识别，
通过签名任务建立会话，
流式返回事件，
产生产物引用，
留下审计 receipt。
```

这足够证明 Agent Space 的核心，不需要先做全球网络。

## 2. 必须包含

### 2.1 Agent ID

- Agent 拥有自证明身份 `aid:`。
- `aid:` 由 Agent 公钥计算，不依赖 DNS、IP、HTTP URL、云账号或注册中心。
- `agent://` 只是人类可读和 Zone 可路由的别名。

### 2.2 单 Zone Registry

- 本地文件或轻量服务都可以。
- 保存 Agent Descriptor。
- 支持通过 `agent://` 查到 `aid:` 和 transport。
- 不做全球 DHT。

### 2.3 ASP over WebSocket

- MVP 先做本机 `asp+tcp`，详见 `docs/asp-009-local-transport.md`。
- WebSocket 推迟到下一阶段。
- 不做 QUIC。
- 不做 libp2p。

### 2.4 Signed Task

- 任务必须包含 `task_id`、`from`、`to`、`intent`、`scope`、`budget`、`signature`。
- 接收方必须验证发送方签名。

### 2.5 Event Stream

最少事件：

```text
task.accepted
task.started
task.progress
artifact.created
task.completed
task.failed
```

### 2.6 Artifact Reference

- 产物不塞进 event。
- event 只返回 `artifact://...` 引用。
- MVP 可以把 artifact 存在本地目录。

### 2.7 Receipt

最小 receipt：

```text
task_id
from aid
to aid
accepted_at
completed_at
artifact refs
agent signature
```

### 2.8 Minimal Policy Gate

- Worker 必须在执行前检查 task scope。
- MVP 只检查 `network` 和 `write`。
- `network: true` 默认拒绝。
- `write` 只能写入 worker descriptor 允许的 artifact 前缀。

### 2.9 Approval Event

- 高风险但允许的操作不直接执行。
- MVP 中 `write` 需要生成 `approval.required`。
- 本地 operator 可以生成 `approval.granted`。
- 真实人类 UI 延后实现。

### 2.10 Audit Log

- MVP 用 JSON Lines 写入 `state/audit.log`。
- 记录 task event 和 receipt。
- 暂不做防篡改存储。

## 3. 明确不做

- 全球 P2P
- DHT
- 区块链
- Token
- 声誉系统
- 复杂语义路由
- 多 Zone 联邦
- QUIC
- 沙箱集群
- 远程证明
- 通用搜索
- 完整 UI 工作台
- MCP/A2A 全兼容

跳过这些不是否定它们，而是避免 MVP 死在基础设施欲望里。

## 4. MVP 拓扑

```text
┌──────────────────┐
│ Zone Registry     │
│ agent:// -> aid   │
└────────┬─────────┘
         │
┌────────▼─────────┐       asp+ws       ┌──────────────────┐
│ Agent A Runtime   │ ─────────────────▶ │ Agent B Runtime   │
│ aid:...           │                    │ aid:...           │
└────────┬─────────┘                    └────────┬─────────┘
         │                                       │
         ▼                                       ▼
  local artifacts                         local receipts
```

## 5. 第一条演示任务

```text
Agent A:
  intent = "请审阅这段文本并生成一个摘要 artifact"

Agent B:
  验证 Agent A 签名
  接受任务
  发送 progress event
  生成 artifact://local/task_001/summary.md
  返回 receipt
```

这个任务很小，但覆盖身份、寻址、任务、事件、产物和审计。

## 6. 成功标准

MVP 成功必须满足：

- 不知道对方 IP 也能通过 `agent://` 找到 descriptor。
- descriptor 能绑定到自证明 `aid:`。
- 任务签名能被验证。
- 事件能按顺序到达。
- artifact ref 能被解析到本地产物。
- receipt 能证明哪个 Agent 完成了哪个 task。
- policy gate 能拒绝一个请求网络访问的 task。
- write task 能产生 approval event。
- audit log 能记录 event 和 receipt。

## 7. 延后到第二阶段

第二阶段再做：

- Federation Gateway
- `asp+quic`
- capability query
- policy engine
- approval event
- MCP adapter
- A2A compatibility
- 多 Agent DAG

先有一条能跑通的线，再扩网。
