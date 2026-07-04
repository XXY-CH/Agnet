# Agent Net Gap

状态：v8.14 assessment

## 一句话

当前项目是 Agent Net 的 protocol seed，不是 Agent Net 产品。

它已经抓住了真正 Agent Net 的底层骨架：identity、signed task、policy、artifact、receipt、audit、federation。

它还缺产品面、运行面、部署面、多人协作面和真实工具执行面。

## 离真正 Agent Net 还有多远

### Protocol core

进度：约 89%。

已有：

- Ed25519 Agent/Zone identity。
- `agent://` alias -> `aid:` descriptor。
- signed task。
- policy scope。
- event stream。
- artifact ref。
- signed receipt。
- hash-chained audit。
- Zone federation。
- capability credential。
- Go discovery/trust path through v2.4。
- Go minimal execution path in v3。
- Go audit path in v3.1。
- Go multi-worker registry in v3.2。
- WebSocket binding in v3.3。
- Thin Human Gateway in v3.4。
- Built-in pure-text tool adapter in v3.5。
- External stdio tool adapter in v3.6。
- Minimal MCP stdio tools/call in v3.7。
- Simulated external/MCP tool approval gate in v3.8。
- Signed local approval evidence and sandbox evidence in v3.9。
- Protocol-native checkpoint evidence in v4。
- Artifact manifest digest evidence in v4.1。
- Canonical policy scope evidence in v4.2。
- Zone-signed credential status evidence in v4.3。
- Authenticated session handshake in v4.4。
- Remote audit proof query in v4.5。
- Signed sandbox proof evidence in v5.0。
- Minimal checkpoint resume parent link in v5.1。
- Signed cancellation receipt evidence in v5.2。
- Retry lineage evidence in v5.3。
- Sandbox claim binding in v5.4。
- Tool command provenance digest in v5.5。
- Tool output digest alignment in v5.6。
- MCP initialize metadata evidence in v5.7。
- MCP resources/prompts metadata evidence in v5.8。
- MCP tools/list metadata evidence in v5.9。
- MCP selected tool binding in v5.10。
- MCP selected tool schema digest in v5.11。
- MCP tools/call argument digest in v5.12。
- MCP required argument gate in v5.13。
- Sandbox isolation level evidence in v5.14。

主要缺：

- credential revocation feed / renewal。
- richer routing beyond exact matches。

### Runtime core

进度：约 78%。

已有：

- Node prototype runtime。
- Node federation execution path。
- Go discovery gateway with minimal deterministic execution。
- Go audit verifier for execution evidence。
- Go exact-match multi-worker routing。
- Go built-in pure-text tool execution。
- Go external stdio tool execution envelope。
- Go minimal MCP stdio tools/call execution。
- Simulated tool approval gate。
- Minimal `FED_TASK_RESUME` execution that links a new receipt to a parent checkpoint。
- Signed `FED_TASK_CANCEL` evidence with worker cancellation receipts。
- `FED_TASK_RETRY` lineage evidence with normal task execution。
- Sandbox claim binding prevents overclaiming local-temp-dir as stronger isolation。
- External/MCP sandbox evidence records tool command digest。
- Tool output digest aligns signed receipt with artifact manifest。
- MCP sandbox evidence records protocol/server initialize metadata。
- MCP resources/prompts surfaces are recorded as count+digest evidence。
- MCP tools surface is recorded as count+digest evidence。
- Selected MCP tool is bound to a `tools/list` descriptor digest。
- Selected MCP tool input schema is recorded as digest evidence。
- MCP tool arguments are recorded as digest evidence。
- MCP tool arguments are rejected when selected schema required fields are missing。
- External/MCP sandbox evidence records explicit `local-process` isolation level。
- Completed/cancelled Go tasks persist minimal state files linked to receipt digests。
- Failed Go task execution persists error state before a receipt exists。
- Signed task cancellation interrupts a running external tool through the in-memory runtime registry。
- Running Go tasks persist state before external/MCP execution completes。
- Failed Go queue items can be explicitly retried with durable retry/backoff state。
- Human Gateway exposes durable queue state and explicit local claim/drain actions。
- Human Gateway can enqueue already signed tasks through the local queue action API。
- Checkpoint resume can be queued durably before explicit drain。
- Queued checkpoint resume records restored parent checkpoint state digest evidence。
- Human/local queue actions are recorded as hash-chained audit evidence。
- Human/local queue actions require signed action grants。
- Human/local queue action grants bind a local actor string。
- Human/local queue actions pass a minimal local actor allowlist。
- Human/local queue action audit records include actor evidence and local policy result evidence when the policy gate is reached。
- Human/local queue action grants carry action scope and expiry。
- Human/local queue action grants are rejected on replay after successful use。
- Human Gateway can draft, locally sign, and enqueue queued tasks through the existing queue action path。
- Human Gateway can accept externally signed requester tasks through the draft endpoint without holding the requester private key。
- Human Gateway write actions can require a bearer token before mutation。
- Human Gateway exposes its local deployment security posture through `/api/security`。
- Human Gateway page can generate, export, import, rotate, bind the alias for, and use a browser-held requester key to submit signed queue drafts。
- Human Gateway can issue a Zone-signed requester alias rebinding proof after verifying browser requester rotation proof。
- Human Gateway persists rebound requester aliases in a multi-alias local registry JSON file。
- Human Gateway exposes the local requester registry as a read-only API and table。
- Human Gateway exposes a local requester alias rebinding history API and table。
- Direct Go tool tasks wait for explicit Human Gateway approval before execution。
- Queued Go drains wait for explicit Human Gateway approval before tool execution。
- Human Gateway approvals can deny or expire before tool execution。

主要缺：

- richer MCP sessions/resources/prompts。
- configurable actor authorization policy。
- container-grade sandbox。
- concurrency model。
- encrypted browser-side private-key storage。
- browser multi-key manager。
- Human Gateway requester selector UI。
- server-side rotation registry。
- passphrase-protected requester key export。
- login-backed approval identity。
- token storage / rotation。
- durable queue action nonce index。
- model KV/cache checkpoint restore。
- automatic retry / backoff scanning。
- binary/package provenance。
- streamed output transcript evidence。
- long-running MCP session reuse。
- full MCP resource/prompt catalog storage。
- full MCP schema verification。
- artifact store beyond local files。

### Network layer

进度：约 30%。

已有：

- newline JSON over local TCP。
- WebSocket text-frame binding。
- authenticated session handshake。
- local process proof。

主要缺：

- TLS/QUIC binding。
- public gateway deployment。
- NAT/proxy story。
- service discovery beyond static trusted stores。
- observability and ops。

### Product layer

进度：约 16%。

已有：

- CLI/test flows。
- read-only Human Gateway。
- simulated approval events。
- direct Human Gateway approval API。
- queued drain Human Gateway approval gate。
- approval denial/expiry gate。
- signed approval receipts visible through Human Gateway。
- local deployment security posture API。
- browser-held requester key, rotation proof, rebinding proof API, local requester registry, requester registry table, alias rebinding UI, rebinding history table, and signed draft UI。
- checkpoint evidence receipts。
- docs and protocol proofs。

主要缺：

- login-backed approval identity。
- artifact browser。
- audit viewer。
- admin / tenant model。
- installation and deployment story。

## 与 Octo 的差距

参考对象：

- [Mininglamp-OSS/OCTO](https://github.com/Mininglamp-OSS/OCTO)
- [octo-server](https://github.com/Mininglamp-OSS/octo-server)

Octo 当前更像 AI-native team collaboration product。

它的强项是人类和 Agent 的协作界面：

- Space / Category / Channel / Thread。
- web / desktop / mobile / admin clients。
- Go server。
- REST + WebSocket。
- Lobster agent orchestration。
- WuKongIM messaging/control plane。
- MySQL / Redis / MinIO deployment stack。

Agent Space 当前更像 lower-level task fabric。

它的强项是协议可信边界：

- Agent/Zone cryptographic identity。
- signed descriptor。
- signed task。
- Zone binding。
- capability credential。
- signed receipt。
- audit hash chain。
- cross-Zone federation proof。

## 对比矩阵

| Area | Octo | Agent Space |
| --- | --- | --- |
| Primary shape | collaboration product | protocol/runtime proof |
| Human workspace | strong | missing |
| Multi-client app | strong | missing |
| Messaging substrate | strong | local proof only |
| Agent orchestration | product-level | protocol-level |
| Cryptographic task identity | unclear from top-level docs | strong |
| Signed receipt/audit | unclear from top-level docs | strong prototype |
| Federation trust model | not the main visible layer | core focus |
| Deployment | Docker Compose stack | test/local only |
| Best next move | deepen trust/runtime layer | add execution + thin UI later |

## Practical Read

Octo is ahead as an app.

Agent Space is ahead as a signed task / federation protocol seed.

Trying to clone Octo now would pull this project sideways into chat/product surface before the protocol spine is strong enough.

The right path is:

```text
v4.4 authenticated session handshake
```

After v5.1, comparing with Octo is useful mainly for the Human Gateway/product layer, not for replacing Agent Space's protocol spine.

Octo should be treated as a possible Human Gateway layer above Agent Space, not as the thing to copy line by line.
