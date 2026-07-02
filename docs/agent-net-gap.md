# Agent Net Gap

状态：v3.7 assessment

## 一句话

当前项目是 Agent Net 的 protocol seed，不是 Agent Net 产品。

它已经抓住了真正 Agent Net 的底层骨架：identity、signed task、policy、artifact、receipt、audit、federation。

它还缺产品面、运行面、部署面、多人协作面和真实工具执行面。

## 离真正 Agent Net 还有多远

### Protocol core

进度：约 64%。

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

主要缺：

- richer policy schema。
- cancellation / checkpoint / retry。
- credential status / revocation feed。
- richer routing beyond exact matches。

### Runtime core

进度：约 50%。

已有：

- Node prototype runtime。
- Node federation execution path。
- Go discovery gateway with minimal deterministic execution。
- Go audit verifier for execution evidence。
- Go exact-match multi-worker routing。
- Go built-in pure-text tool execution。
- Go external stdio tool execution envelope。
- Go minimal MCP stdio tools/call execution。

主要缺：

- richer MCP sessions/resources/prompts。
- stronger sandbox / approvals。
- concurrency model。
- durable task state。
- artifact store beyond local files。

### Network layer

进度：约 22%。

已有：

- newline JSON over local TCP。
- WebSocket text-frame binding。
- local process proof。

主要缺：

- authenticated session handshake。
- TLS/QUIC binding。
- auth handshake。
- public gateway deployment。
- NAT/proxy story。
- service discovery beyond static trusted stores。
- observability and ops。

### Product layer

进度：约 12%。

已有：

- CLI/test flows。
- read-only Human Gateway。
- docs and protocol proofs。

主要缺：

- task list / status view。
- approval flow。
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
v3.8 tool approval + stronger sandbox
```

After v3.3 or v3.4, comparing directly with Octo becomes useful.

Before that, Octo should be treated as the possible Human Gateway layer above Agent Space, not as the thing to copy line by line.
