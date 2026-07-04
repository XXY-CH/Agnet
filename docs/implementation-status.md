# Agent Space Implementation Status

状态：v7.11 complete
当前代码基线：`v7.11-queue-grant-replay`

## 一句话

当前实现已经证明了 Agent identity、signed task、local runtime、Node federation execution、Go federation discovery、Go dynamic signing、Go key files、Go `FED_TASK_OPEN` verification、Go `FED_TASK_ENQUEUE` durable local queue entry、Go `FED_QUEUE_CLAIM` lease ownership/expiry/backoff gate、Go `FED_QUEUE_RECLAIM` expired lease ownership transfer、Go `FED_QUEUE_RETRY` failed queue retry/backoff state、Go `FED_QUEUE_RESUME` queued checkpoint resume binding、Go `FED_QUEUE_DRAIN` explicit queued execution、Go Human Gateway queue state/action/creation surface、Go Human Gateway scoped signed queue action grants、Go Human Gateway queue action grant replay rejection、Go Human Gateway queue action audit evidence、Go `FED_TASK_RESUME` audit-backed checkpoint link、Go signed `FED_TASK_CANCEL` evidence、Go live external task cancellation、Go `FED_TASK_RETRY` lineage evidence、Go 最小 task execution path、Go durable running/completed/cancelled/failed task state files、Go Human Gateway task state view、Go audit/receipt verification、Go multi-worker registry、Go WebSocket transport binding、thin Human Gateway、Go 内置 tool adapter、external stdio tool adapter、最小 MCP stdio `tools/call`、MCP initialize metadata evidence、MCP resources/prompts/tools metadata evidence、MCP selected tool binding、MCP selected schema digest evidence、MCP argument digest evidence、MCP required argument gate、外部/MCP tool approval gate、signed approval evidence、本地临时目录 sandbox evidence、sandbox isolation level evidence、signed sandbox proof、sandbox claim binding、tool command provenance digest、tool output digest alignment、protocol-native checkpoint evidence、artifact manifest digest evidence、canonical policy scope evidence、credential status evidence、authenticated session handshake，以及 remote audit query。

还不是可产品化的 Agent Net。

## 能力矩阵

| Capability | Node | Go | Evidence | Missing |
| --- | --- | --- | --- | --- |
| Agent identity | done | verify/generate subset | `asp-core.mjs`, `cmd/go-fed-discovery` | Go shared library/package shape |
| Zone identity | done | verify/generate subset | `trusted-zones.test.mjs`, Go descriptor verification | Zone lifecycle tooling |
| Local registry | done | multi-worker profile registry | `zone-registry.test.mjs`, `go-fed-discovery.test.mjs` | worker lifecycle API |
| Local task execution | done | built-in + external stdio + MCP stdio tools/call + MCP initialize/resources/prompts/tools metadata + selected tool/schema/argument evidence + MCP required argument gate + explicit local-process isolation evidence + signed local sandbox proof + sandbox claim binding + tool command digest | `agent-runtime.test.mjs`, `go-fed-discovery.test.mjs` | container sandbox / long-running MCP sessions |
| Events | done | minimal federation events + Go checkpoint event | `agent-runtime.test.mjs`, `federation-gateway.test.mjs`, `go-fed-discovery.test.mjs` | richer event lifecycle |
| Artifact write | done | deterministic local artifact + Go artifact manifest digest evidence + tool output digest alignment | `mvp-demo.test.mjs`, `go-fed-discovery.test.mjs` | artifact store |
| Receipt signing | done | done for minimal Go execution | `test-vectors.test.mjs`, `go-fed-discovery.test.mjs` | receipt verification CLI |
| Audit hash chain | done | done for Go execution, queue actions, and remote receipt proof query | `audit-chain.test.mjs`, `go-fed-discovery.test.mjs` | full log sync / remote search |
| Federation resolve | done | done | `federation-gateway.test.mjs`, `go-fed-discovery.test.mjs` | public transport |
| Capability query | done | done | `federation-gateway.test.mjs`, `go-fed-discovery.test.mjs` | ranking / scheduling |
| Capability credential | done | done + Go signed status evidence | `capability-credential.test.mjs`, `go-fed-discovery.test.mjs` | revocation feed / renewal |
| Key persistence | PKCS8 files | seed key files | `state/keys`, `--authority-key`, `--worker-key` | rotation, encryption, permissions |
| `FED_TASK_OPEN` | execute | execute minimal path + durable running/completed/failed task state files | `federation-gateway.mjs`, `go-fed-discovery.test.mjs` | scheduler / real restore |
| `FED_TASK_ENQUEUE` | not yet | durable local queue file + claim/lease expiry + reclaim + retry/backoff state + explicit drain path | `go-fed-discovery.test.mjs` | automatic drain |
| `FED_TASK_CANCEL` | not yet | signed cancellation receipt evidence + durable cancelled state file + live external process interruption | `go-fed-discovery.test.mjs` | persisted running registry / multi-node cancel |
| `FED_TASK_RETRY` | not yet | signed retry lineage evidence | `go-fed-discovery.test.mjs` | automatic retry / backoff / scheduler state |
| Policy checks | done | network/write subset + Go canonical policy scope digest + stable deny codes | `agent-runtime.test.mjs`, `go-fed-discovery.test.mjs` | policy negotiation / dynamic policy service |
| Human approval | simulated | signed local tool approval evidence visible in Human Gateway | Node events, `go-fed-discovery.test.mjs` | interactive approval queue / login-state UI |
| Checkpoint evidence | not yet | signed protocol-native checkpoint evidence + audit-backed immediate and queued resume parent links + receipt-linked task state file | `go-fed-discovery.test.mjs` | real state restore |
| Transport | local TCP / local process + authenticated session handshake | local TCP + minimal WebSocket + authenticated session handshake | README commands, `federation-gateway.test.mjs`, `go-fed-discovery.test.mjs` | TLS, QUIC |
| Product surface | CLI/tests only | thin Human Gateway with task table, queue table, and scoped signed explicit local enqueue/claim/drain actions with replay rejection | README, `go-fed-discovery.test.mjs` | approvals, task drafting/signing, admin, deployment |

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
  -> live external task cancellation through in-memory runtime registry
  -> FED_TASK_RETRY retry lineage evidence
  -> durable running/completed/cancelled/failed task state files
  -> minimal task events, artifact, signed receipt
  -> audit JSONL hash chain and verifier
  -> multi-worker profile registry
  -> WebSocket transport binding
  -> thin Human Gateway
  -> built-in pure-text tool adapter
  -> external stdio tool adapter with process envelope
  -> minimal MCP stdio tools/call adapter
  -> signed local approval grants for external/MCP tools
  -> signed local sandbox proof for external/MCP tools
  -> sandbox claim binding in receipt/proof
  -> explicit local-process isolation level in sandbox evidence
  -> tool command digest in sandbox evidence
  -> tool output digest aligned with artifact manifest
  -> MCP initialize metadata in sandbox evidence
  -> MCP resources/prompts count+digest evidence
  -> MCP tools count+digest evidence
  -> MCP selected tool digest evidence
  -> MCP selected tool schema digest evidence
  -> MCP tools/call argument digest evidence
  -> MCP required-field argument gate
  -> signed protocol-native checkpoint evidence
  -> FED_TASK_RESUME parent-checkpoint link verified against audit
  -> artifact manifest digest evidence
  -> canonical policy scope digest and stable deny codes
  -> Zone-signed credential status evidence
  -> authenticated session handshake
  -> remote audit query by task id
  -> Human Gateway /api/tasks and task table
  -> Human Gateway /api/queue and scoped signed explicit queue enqueue/claim/drain actions with replay rejection
  -> go_queue_action audit evidence for Human Gateway queue actions
  -> FED_TASK_ENQUEUE durable local queue file
  -> FED_QUEUE_CLAIM lease ownership and expiry
  -> FED_QUEUE_RECLAIM expired lease ownership transfer
  -> FED_QUEUE_RETRY failed queue retry/backoff state
  -> FED_QUEUE_RESUME queued checkpoint resume binding
  -> FED_QUEUE_DRAIN explicit queued execution
```

## Next Boundary

Next natural boundary:

```text
v7.12 Queue Action Grant Identity Boundary
  -> bind queue action grants to a local actor identity before richer product UI
```

Route detail: `docs/v5-roadmap.md`。

Skipped until later: encrypted key store, public transport, interactive approval queue, container sandbox, Git/worktree/merge operations, scheduler queues, semantic routing.
