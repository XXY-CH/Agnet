# Agent Space Implementation Status

状态：v3.9 complete
当前代码基线：`v3.9`

## 一句话

当前实现已经证明了 Agent identity、signed task、local runtime、Node federation execution、Go federation discovery、Go dynamic signing、Go key files、Go `FED_TASK_OPEN` verification、Go 最小 task execution path、Go audit/receipt verification、Go multi-worker registry、Go WebSocket transport binding、thin Human Gateway、Go 内置 tool adapter、external stdio tool adapter、最小 MCP stdio `tools/call`、外部/MCP tool approval gate、signed approval evidence，以及本地临时目录 sandbox evidence。

还不是可产品化的 Agent Net。

## 能力矩阵

| Capability | Node | Go | Evidence | Missing |
| --- | --- | --- | --- | --- |
| Agent identity | done | verify/generate subset | `asp-core.mjs`, `cmd/go-fed-discovery` | Go shared library/package shape |
| Zone identity | done | verify/generate subset | `trusted-zones.test.mjs`, Go descriptor verification | Zone lifecycle tooling |
| Local registry | done | multi-worker profile registry | `zone-registry.test.mjs`, `go-fed-discovery.test.mjs` | worker lifecycle API |
| Local task execution | done | built-in + external stdio + MCP stdio tools/call + local temp-dir sandbox evidence | `agent-runtime.test.mjs`, `go-fed-discovery.test.mjs` | container sandbox / long-running MCP sessions |
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
| Human approval | simulated | signed local tool approval evidence visible in Human Gateway | Node events, `go-fed-discovery.test.mjs` | interactive approval queue / login-state UI |
| Transport | local TCP / local process | local TCP + minimal WebSocket | README commands, `go-fed-discovery.test.mjs` | TLS, auth handshake, QUIC |
| Product surface | CLI/tests only | thin read-only Human Gateway | README, `go-fed-discovery.test.mjs` | approvals, task creation, admin, deployment |

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
  -> WebSocket transport binding
  -> read-only Human Gateway
  -> built-in pure-text tool adapter
  -> external stdio tool adapter with process envelope
  -> minimal MCP stdio tools/call adapter
  -> signed local approval grants for external/MCP tools
  -> local temporary sandbox directory evidence for external/MCP tools
```

## Next Boundary

Next natural boundary:

```text
Interactive approval queue + container sandbox
  -> pending/reject path and stronger OS isolation
```

Skipped until later: encrypted key store, public transport, interactive approval queue, container sandbox, scheduling, semantic routing.
