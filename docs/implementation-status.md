# Agent Space Implementation Status

状态：v5.3 complete
当前代码基线：`v5.3-protocol`

## 一句话

当前实现已经证明了 Agent identity、signed task、local runtime、Node federation execution、Go federation discovery、Go dynamic signing、Go key files、Go `FED_TASK_OPEN` verification、Go `FED_TASK_RESUME` checkpoint link、Go signed `FED_TASK_CANCEL` evidence、Go `FED_TASK_RETRY` lineage evidence、Go 最小 task execution path、Go audit/receipt verification、Go multi-worker registry、Go WebSocket transport binding、thin Human Gateway、Go 内置 tool adapter、external stdio tool adapter、最小 MCP stdio `tools/call`、外部/MCP tool approval gate、signed approval evidence、本地临时目录 sandbox evidence、signed sandbox proof、protocol-native checkpoint evidence、artifact manifest digest evidence、canonical policy scope evidence、credential status evidence、authenticated session handshake，以及 remote audit query。

还不是可产品化的 Agent Net。

## 能力矩阵

| Capability | Node | Go | Evidence | Missing |
| --- | --- | --- | --- | --- |
| Agent identity | done | verify/generate subset | `asp-core.mjs`, `cmd/go-fed-discovery` | Go shared library/package shape |
| Zone identity | done | verify/generate subset | `trusted-zones.test.mjs`, Go descriptor verification | Zone lifecycle tooling |
| Local registry | done | multi-worker profile registry | `zone-registry.test.mjs`, `go-fed-discovery.test.mjs` | worker lifecycle API |
| Local task execution | done | built-in + external stdio + MCP stdio tools/call + signed local sandbox proof | `agent-runtime.test.mjs`, `go-fed-discovery.test.mjs` | container sandbox / long-running MCP sessions |
| Events | done | minimal federation events + Go checkpoint event | `agent-runtime.test.mjs`, `federation-gateway.test.mjs`, `go-fed-discovery.test.mjs` | richer event lifecycle |
| Artifact write | done | deterministic local artifact + Go artifact manifest digest evidence | `mvp-demo.test.mjs`, `go-fed-discovery.test.mjs` | artifact store |
| Receipt signing | done | done for minimal Go execution | `test-vectors.test.mjs`, `go-fed-discovery.test.mjs` | receipt verification CLI |
| Audit hash chain | done | done for Go execution + remote receipt proof query | `audit-chain.test.mjs`, `go-fed-discovery.test.mjs` | full log sync / remote search |
| Federation resolve | done | done | `federation-gateway.test.mjs`, `go-fed-discovery.test.mjs` | public transport |
| Capability query | done | done | `federation-gateway.test.mjs`, `go-fed-discovery.test.mjs` | ranking / scheduling |
| Capability credential | done | done + Go signed status evidence | `capability-credential.test.mjs`, `go-fed-discovery.test.mjs` | revocation feed / renewal |
| Key persistence | PKCS8 files | seed key files | `state/keys`, `--authority-key`, `--worker-key` | rotation, encryption, permissions |
| `FED_TASK_OPEN` | execute | execute minimal path | `federation-gateway.mjs`, `go-fed-discovery.test.mjs` | real worker/tools |
| `FED_TASK_CANCEL` | not yet | signed cancellation receipt evidence | `go-fed-discovery.test.mjs` | live process interruption / scheduler state |
| `FED_TASK_RETRY` | not yet | signed retry lineage evidence | `go-fed-discovery.test.mjs` | automatic retry / backoff / scheduler state |
| Policy checks | done | network/write subset + Go canonical policy scope digest + stable deny codes | `agent-runtime.test.mjs`, `go-fed-discovery.test.mjs` | policy negotiation / dynamic policy service |
| Human approval | simulated | signed local tool approval evidence visible in Human Gateway | Node events, `go-fed-discovery.test.mjs` | interactive approval queue / login-state UI |
| Checkpoint evidence | not yet | signed protocol-native checkpoint evidence + minimal resume parent link | `go-fed-discovery.test.mjs` | durable task state / real state restore |
| Transport | local TCP / local process + authenticated session handshake | local TCP + minimal WebSocket + authenticated session handshake | README commands, `federation-gateway.test.mjs`, `go-fed-discovery.test.mjs` | TLS, QUIC |
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
  -> FED_TASK_CANCEL signed cancellation evidence
  -> FED_TASK_RETRY retry lineage evidence
  -> minimal task events, artifact, signed receipt
  -> audit JSONL hash chain and verifier
  -> multi-worker profile registry
  -> WebSocket transport binding
  -> read-only Human Gateway
  -> built-in pure-text tool adapter
  -> external stdio tool adapter with process envelope
  -> minimal MCP stdio tools/call adapter
  -> signed local approval grants for external/MCP tools
  -> signed local sandbox proof for external/MCP tools
  -> signed protocol-native checkpoint evidence
  -> minimal FED_TASK_RESUME parent-checkpoint link
  -> artifact manifest digest evidence
  -> canonical policy scope digest and stable deny codes
  -> Zone-signed credential status evidence
  -> authenticated session handshake
  -> remote audit query by task id
```

## Next Boundary

Next natural boundary:

```text
v5.4 container sandbox claim boundary
  -> stronger sandbox evidence without hardware attestation
```

Route detail: `docs/v5-roadmap.md`。

Skipped until later: encrypted key store, public transport, interactive approval queue, container sandbox, Git/worktree/merge operations, scheduling, semantic routing.
