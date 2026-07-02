# Agent Space v2 Boundary

状态：v2 candidate  
目标：把 Federation discovery gateway 的可信发现面迁到 Go。

## v2 新增

- `cmd/go-fed-discovery`
- Go gateway supports:
  - `FED_RESOLVE`
  - `FED_QUERY`
- Go gateway verifies:
  - trusted origin Zone descriptor
  - local fixture Zone descriptor
  - local worker descriptor
- Go gateway serves:
  - Zone descriptor
  - worker descriptor
  - Zone binding
  - signed capability credential
- Node federation client verifies Go gateway responses.
- Integration test: Node client talks to Go gateway.

## 为什么这是 v2

v1.x 的 Federation Gateway 运行在 Node。

v2 的目标不是一次性重写全部 runtime，而是先让 Go 接管最适合 Go 的部分：可信发现面。

```text
Go discovery gateway
  -> returns signed descriptors and credentials
Node requester
  -> verifies and uses them
```

这证明协议开始脱离 Node prototype runtime。

## v2 不新增

- 不做 Go task execution。
- 不做 Go worker。
- 不做 Go audit writer。
- 不做 Go policy engine。
- 不做 public transport。
- 不做 WebSocket/QUIC。

Task execution 仍由 Node Federation Gateway 路径证明。

后续 Go dynamic signing 边界见 `docs/v2.1-boundary.md`。

## 验收

```bash
node --test --test-concurrency=1 *.test.mjs
go test ./...
```

必须通过：

```text
Go discovery gateway serves FED_RESOLVE and FED_QUERY to Node client
```

## v2.1 候选

下一步可以选择：

- Go `FED_TASK_OPEN` verification only, no worker execution。
- Go audit verifier CLI。
- Credential status / revocation feed。
