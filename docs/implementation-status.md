# Agent Space Implementation Status

状态：v3.2 complete
当前代码基线：`v3.2`

## 一句话

当前实现已经证明了 Agent identity、signed task、local runtime、Node federation execution、Go federation discovery、Go dynamic signing、Go key files、Go `FED_TASK_OPEN` verification、Go 最小 task execution path、Go audit/receipt verification，以及 Go multi-worker registry。

还不是可产品化的 Agent Net。

## 能力矩阵

| Capability | Node | Go | Evidence | Missing |
| --- | --- | --- | --- | --- |
| Agent identity | done | verify/generate subset | `asp-core.mjs`, `cmd/go-fed-discovery` | Go shared library/package shape |
| Zone identity | done | verify/generate subset | `trusted-zones.test.mjs`, Go descriptor verification | Zone lifecycle tooling |
| Local registry | done | multi-worker profile registry | `zone-registry.test.mjs`, `go-fed-discovery.test.mjs` | worker lifecycle API |
| Local task execution | done | minimal deterministic worker | `agent-runtime.test.mjs`, `go-fed-discovery.test.mjs` | real tool execution |
| Events | done | minimal federation events | `agent-runtime.test.mjs`, `federation-gateway.test.mjs`, `go-fed-discovery.test.mjs` | richer event lifecycle |
| Artifact write | done | deterministic local artifact | `mvp-demo.test.mjs`, `go-fed-discovery.test.mjs` | artifact store |
| Receipt signing | done | done for minimal Go execution | `test-vectors.test.mjs`, `go-fed-discovery.test.mjs` | receipt verification CLI |
| Audit hash chain | done | done for Go execution | `audit-chain.test.mjs`, `go-fed-discovery.test.mjs` | remote audit query |
| Federation resolve | done | done | `federation-gateway.test.mjs`, `go-fed-discovery.test.mjs` | public transport |
| Capability query | done | done | `federation-gateway.test.mjs`, `go-fed-discovery.test.mjs` | ranking / scheduling |
| Capability credential | done | done | `capability-credential.test.mjs`, Go dynamic signing | credential status feed |
| Key persistence | PKCS8 files | seed key files | `state/keys`, `--authority-key`, `--worker-key` | rotation, encryption, permissions |
| `FED_TASK_OPEN` | execute | execute minimal path | `federation-gateway.mjs`, `go-fed-discovery.test.mjs` | real worker/tools |
| Policy checks | done | network/write subset | `agent-runtime.test.mjs`, `go-fed-discovery.test.mjs` | richer scope schema |
| Human approval | simulated | no | Node events | real Human Gateway |
| Transport | local TCP / local process | local TCP | README commands | TLS, WebSocket, QUIC, auth handshake |
| Product surface | CLI/tests only | CLI/tests only | README | workspace UI, admin, deployment |

## Current Boundary

```text
Node
  -> full prototype execution path
  -> local/federated events, artifact, receipt, audit

Go
  -> trusted federation discovery
  -> dynamic worker descriptor, binding, credential signing
  -> key files
  -> FED_TASK_OPEN verification
  -> minimal task events, artifact, signed receipt
  -> audit JSONL hash chain and verifier
  -> multi-worker profile registry
```

## Next Boundary

Next natural boundary:

```text
WebSocket transport binding
  -> keep same federation frames over a less toy transport
```

Skipped until later: multi-worker registry, encrypted key store, public transport, real approval UI, sandbox/tool execution, scheduling, semantic routing.
