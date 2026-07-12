# Agent Space v0 Boundary

状态：v0 candidate  
目标：冻结第一个可运行、可验证的 Agent Space MVP 边界。

## v0 包含什么

v0 证明的是单机、单 Zone、双进程 Agent 协作闭环。

```text
requester process
  -> registry resolve agent://
  -> asp+tcp newline JSON frames
  -> worker process
  -> policy gate
  -> approval events
  -> artifact
  -> signed receipt
  -> audit log
```

具体能力：

- `aid:` 自证明 Agent ID。
- `agent://` 本地 registry alias。
- `state/registry.json` 解析 descriptor。
- Ed25519 task signing。
- Descriptor public key verification。
- `TASK_OPEN` / `TASK_EVENT` / `RECEIPT` / `TASK_CLOSE` / `TASK_ERROR` frames。
- Minimal policy gate：拒绝 `network: true`，限制 artifact 写入前缀。
- Minimal approval：`write` 触发 `approval.required` 和 `approval.granted`。
- Artifact reference：`artifact://local/...`。
- Signed receipt。
- JSON Lines audit log。
- 单进程 demo。
- 双进程 runtime。
- 自动化测试。

## v0 不包含什么

- WebSocket
- QUIC
- TLS
- libp2p
- DHT
- DID resolver
- Zone federation
- Global registry
- Reputation
- Token economy
- Sandbox
- Real human UI
- MCP adapter
- A2A adapter
- Multi-agent DAG
- Tamper-proof audit storage

这些不是否定项，只是不进入第一个 v0。

## v0 验收命令

```bash
node --test --test-concurrency=1 test/*.test.mjs
```

必须通过：

```text
tests 2
pass 2
fail 0
```

## v0 手动运行

终端 1：

```bash
node agent-runtime.mjs worker 8787
```

终端 2：

```bash
node agent-runtime.mjs request agent://local/summarizer
```

期望结果：

- requester 输出 `aid:ed25519:...`
- worker 输出 `aid:ed25519:...`
- events 最后一个是 `task.completed`
- receipt 含 worker 签名
- artifact 写入 `artifacts/`
- audit 追加到 `state/audit.log`

## v0 判断

v0 不是 Agent Internet。

v0 是 Agent Space 的最小活体样本：两个独立进程，不通过 HTTP API 语义，而通过 Agent ID、Signed Task、ASP frame、Policy、Approval、Artifact 和 Receipt 完成一次可审计协作。

后续跨语言协议向量见 `docs/v0.1-boundary.md`。
