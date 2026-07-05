# Agent Space Implementation Status

状态：v9.2 complete
当前代码基线：`v9.2-node-audit-append-serialization`

## 一句话

当前实现已经证明了 Agent identity、signed task、local runtime、Node federation execution、Node in-process serialized audit append、Go federation discovery、Go dynamic signing、Go key files、Go `FED_TASK_OPEN` verification、Go direct task Human Gateway explicit approval/denial/expiry/named actor evidence/local actor policy/local approval session actor evidence/session actor mismatch rejection/session state API/session state UI、Go `FED_TASK_ENQUEUE` durable local queue entry、Go `FED_QUEUE_CLAIM` lease ownership/expiry/backoff gate、Go `FED_QUEUE_RECLAIM` expired lease ownership transfer、Go `FED_QUEUE_RETRY` failed queue retry/backoff state、Go `FED_QUEUE_RESUME` queued checkpoint resume binding、Go queued checkpoint state digest restore evidence、Go `FED_QUEUE_DRAIN` explicit queued execution with Human Gateway approval、Go Human Gateway queue state/action/creation/drafting/external signed draft/approval/security posture/browser requester key surface with import/export/rotation proof/rebinding proof API/multi-alias local requester registry persistence/requester registry view/browser alias rebinding UI/local rebinding history table、Go Human Gateway transcript artifact link UI/task-scoped artifact manifest proof link/UI、task-scoped artifact manifest HEAD proof headers、task-scoped transcript stream API、Human Gateway transcript stream viewer、running external tool transcript snapshot API、Human Gateway running transcript snapshot viewer action、Human Gateway live transcript polling UI、MCP stdio live transcript snapshot API、filesystem artifact mirror object index/verifier coverage/GC plan、task-scoped audit proof API/link with audit hash、receipt-scoped artifact verify/read API/link、receipt-scoped artifact verify receipt digest and audit hash fields、receipt-scoped read digest headers、receipt-scoped HEAD proof headers、receipt digest and audit hash headers on artifact reads、Go Human Gateway write bearer-token gate、Go Human Gateway actor-bound scoped signed queue action grants、Go Human Gateway configurable local actor policy gate、Go Human Gateway queue action grant durable nonce replay rejection、Go Human Gateway queue action audit actor evidence、Go `FED_TASK_RESUME` audit-backed checkpoint link、Go signed `FED_TASK_CANCEL` evidence、Go live external task cancellation、Go `FED_TASK_RETRY` lineage evidence、Go 最小 task execution path、Go durable running/completed/cancelled/failed task state files、Go Human Gateway task state view、Go audit/receipt verification、Go multi-worker registry、Go WebSocket transport binding、thin Human Gateway、Go 内置 tool adapter、external stdio tool adapter、最小 MCP stdio `tools/call`、MCP initialize metadata evidence、MCP resources/prompts/tools metadata evidence、MCP selected tool binding、MCP selected schema digest evidence、MCP argument digest evidence、MCP required argument gate、外部/MCP tool approval gate、signed approval evidence、本地临时目录 sandbox evidence、sandbox isolation level evidence、sandbox environment binding evidence、signed sandbox proof、sandbox claim binding、tool command/executable binary/result transcript provenance digest、tool result transcript artifact evidence、tool output digest alignment、protocol-native checkpoint evidence、artifact manifest digest evidence、artifact manifest sidecar/API evidence、content-addressed local artifact evidence、filesystem artifact mirror evidence、artifact byte verification evidence、artifact named sidecar/digest sidecar/mirror verification evidence、canonical policy scope evidence、credential status evidence、authenticated session handshake，以及 remote audit query。

还不是可产品化的 Agent Net。

## 能力矩阵

| Capability | Node | Go | Evidence | Missing |
| --- | --- | --- | --- | --- |
| Agent identity | done | verify/generate subset | `asp-core.mjs`, `cmd/go-fed-discovery` | Go shared library/package shape |
| Zone identity | done | verify/generate subset | `trusted-zones.test.mjs`, Go descriptor verification | Zone lifecycle tooling |
| Local registry | done | multi-worker profile registry | `zone-registry.test.mjs`, `go-fed-discovery.test.mjs` | worker lifecycle API |
| Local task execution | done | built-in + external stdio + MCP stdio tools/call + MCP initialize/resources/prompts/tools metadata + selected tool/schema/argument evidence + MCP required argument gate + explicit local-process isolation evidence + sandbox-bound HOME/TMPDIR/XDG_CACHE_HOME + signed local sandbox proof + sandbox claim binding + tool command, binary, transcript digests, and transcript artifacts | `agent-runtime.test.mjs`, `go-fed-discovery.test.mjs` | container namespace sandbox / long-running MCP sessions |
| Events | done | minimal federation events + Go checkpoint event | `agent-runtime.test.mjs`, `federation-gateway.test.mjs`, `go-fed-discovery.test.mjs` | richer event lifecycle |
| Artifact write | done | deterministic local artifact + Go artifact manifest digest evidence + tool output/transcript digest alignment + local manifest sidecar/API + content-addressed local path + optional filesystem artifact mirror + mirror object index + audit verifier byte/named sidecar/digest sidecar/mirror/index checks + GC plan | `mvp-demo.test.mjs`, `go-fed-discovery.test.mjs` | object-store backend / GC apply |
| Receipt signing | done | done for minimal Go execution | `test-vectors.test.mjs`, `go-fed-discovery.test.mjs` | receipt verification CLI |
| Audit hash chain | done + in-process append serialization | done for Go execution, queue actions, remote receipt proof query, and Human Gateway task-scoped receipt proof query | `audit-chain.test.mjs`, `go-fed-discovery.test.mjs` | cross-process locking / full log sync / remote search |
| Federation resolve | done | done | `federation-gateway.test.mjs`, `go-fed-discovery.test.mjs` | public transport |
| Capability query | done | done | `federation-gateway.test.mjs`, `go-fed-discovery.test.mjs` | ranking / scheduling |
| Capability credential | done | done + Go signed status evidence | `capability-credential.test.mjs`, `go-fed-discovery.test.mjs` | revocation feed / renewal |
| Key persistence | PKCS8 files | seed key files | `state/keys`, `--authority-key`, `--worker-key` | rotation, encryption, permissions |
| `FED_TASK_OPEN` | execute | execute minimal path + durable running/completed/failed task state files | `federation-gateway.mjs`, `go-fed-discovery.test.mjs` | scheduler / real restore |
| `FED_TASK_ENQUEUE` | not yet | durable local queue file + claim/lease expiry + reclaim + retry/backoff state + explicit drain path | `go-fed-discovery.test.mjs` | automatic drain |
| `FED_TASK_CANCEL` | not yet | signed cancellation receipt evidence + durable cancelled state file + live external process interruption | `go-fed-discovery.test.mjs` | persisted running registry / multi-node cancel |
| `FED_TASK_RETRY` | not yet | signed retry lineage evidence | `go-fed-discovery.test.mjs` | automatic retry / backoff / scheduler state |
| Policy checks | done | network/write subset + Go canonical policy scope digest + stable deny codes | `agent-runtime.test.mjs`, `go-fed-discovery.test.mjs` | policy negotiation / dynamic policy service |
| Human approval | simulated | direct Go task execution and queued drain write pending approval state; approve continues, deny/expiry stops before tools; direct approvals preserve named `human://...` actors in signed grants; approval actors pass configurable local allowlists; local bearer approval sessions can supply the approval actor; mismatched body/session actors are rejected; `/api/session` exposes local session actor/actions state; Human Gateway page displays that local session state | Node events, `go-fed-discovery.test.mjs` | roles |
| Checkpoint evidence | not yet | signed protocol-native checkpoint evidence + audit-backed immediate and queued resume parent links + restored state digest evidence + receipt-linked task state file | `go-fed-discovery.test.mjs` | model KV/cache restore |
| Transport | local TCP / local process + authenticated session handshake | local TCP + minimal WebSocket + authenticated session handshake | README commands, `federation-gateway.test.mjs`, `go-fed-discovery.test.mjs` | TLS, QUIC |
| Product surface | CLI/tests only | thin Human Gateway with task table, queue table, approval table/API, task-scoped audit proof links/API with audit hash, receipt artifact links including transcript artifacts, task-scoped manifest links and HEAD proof headers, transcript stream API, transcript stream viewer, running transcript snapshot API, running transcript snapshot viewer action, live transcript polling UI, MCP stdio live transcript snapshot API, filesystem artifact mirror object index, verify links with receipt/audit proof fields, read links, signed digest headers on read responses, HEAD proof headers, receipt digest headers, and audit hash headers, local session state panel, security posture API, browser-held requester key panel with import/export/rotation proof/alias rebinding submission, requester alias rebinding proof API, multi-alias local requester registry persistence, requester registry table, local rebinding history table, optional bearer-token write gate, actor-bound scoped signed explicit local enqueue/claim/drain actions, configurable local actor policy, durable grant nonce index, local draft/sign/enqueue endpoint, and external signed draft enqueue endpoint | README, `go-fed-discovery.test.mjs` | encrypted key store, admin, deployment |

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
  -> direct task and queued drain Human Gateway pending approval state with approve/deny/expiry outcomes
  -> direct Human Gateway approvals preserve named human:// actors in signed approval grants
  -> Human Gateway --human-actor-policy local JSON policy for direct approval actor/action allowlists
  -> Human Gateway --human-actor-policy local approval_sessions bearer-to-actor mapping for direct approvals
  -> Human Gateway direct approval actor/session mismatch rejection
  -> Human Gateway /api/session read-only local approval session state
  -> Human Gateway page local approval session state panel
  -> signed local approval grants for external/MCP tools
  -> signed local sandbox proof for external/MCP tools
  -> sandbox claim binding in receipt/proof
  -> explicit local-process isolation level in sandbox evidence
  -> sandbox-bound HOME, TMPDIR, and XDG_CACHE_HOME for external/MCP tools
  -> tool command, executable binary, and result transcript digests in sandbox evidence
  -> external/MCP result transcript artifacts linked from sandbox evidence and receipt artifact manifests
  -> Human Gateway /api/transcripts/stream?task_id=<id> streams the signed transcript artifact as NDJSON
  -> Human Gateway receipt rows can load task-scoped transcript streams into a local viewer
  -> Human Gateway /api/transcripts/live?task_id=<id> reads running external tool stdout snapshots as NDJSON
  -> Human Gateway running task rows can load live transcript snapshots into the local transcript viewer
  -> Human Gateway live transcript loading polls the running snapshot until another transcript is selected
  -> MCP stdio responses are copied into the live transcript snapshot as NDJSON
  -> filesystem artifact mirrors maintain and verify an objects.ndjson content-addressed object index
  -> artifact-store GC plan lists unreferenced mirror index entries
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
  -> queued checkpoint resume restored state digest evidence
  -> artifact manifest digest evidence
  -> artifact manifest sidecar and read-only Human Gateway manifest API
  -> local content-addressed artifact copy under artifacts/by-sha256/<digest>
  -> optional filesystem artifact mirror under --artifact-store by-sha256/<digest>
  -> audit verifier checks local artifact bytes against manifests
  -> audit verifier checks named artifact manifest sidecars against manifests
  -> audit verifier checks digest-addressed artifact manifest sidecars against manifests
  -> audit verifier checks optional filesystem artifact mirror bytes, sidecars, and object index when --artifact-store is configured
  -> canonical policy scope digest and stable deny codes
  -> Zone-signed credential status evidence
  -> authenticated session handshake
  -> remote audit query by task id
  -> Human Gateway /api/audit?task_id task-scoped receipt proof query
  -> Human Gateway /api/tasks and task table
  -> Human Gateway /api/approvals and Approvals table
  -> Human Gateway optional bearer-token gate for write endpoints
  -> Human Gateway /api/security local deployment posture
  -> Human Gateway /api/queue and actor-bound scoped signed explicit queue enqueue/claim/drain actions with configurable local actor policy and durable nonce replay rejection
  -> Human Gateway --human-actor-policy local JSON policy for queue action actor/action allowlists
  -> Human Gateway queue action grant nonce index at audit-derived *-queue-grants directory
  -> Human Gateway /api/queue/drafts local draft/sign/enqueue endpoint and external signed draft enqueue endpoint
  -> Human Gateway /api/requester/rebindings Zone-signed requester alias rebinding proof endpoint
  -> Human Gateway multi-alias local requester registry persistence at state/go-fed-discovery-requester-registry.json
  -> Human Gateway /api/requester/registry and Requester Registry table
  -> Human Gateway local requester alias rebinding history at state/go-fed-discovery-requester-rebindings.json
  -> Human Gateway page browser-held requester key generation, import/export, rotation proof, alias rebinding submission, and signed draft submission
  -> Human Gateway receipt table links all receipt artifact refs, including tool-transcript.json
  -> Human Gateway receipt table links artifact refs to task-scoped /api/artifacts/manifest
  -> Human Gateway /api/artifacts/manifest?task_id=<id>&uri=<artifact-uri> returns signed manifest proof fields
  -> Human Gateway HEAD /api/artifacts/manifest?task_id=<id>&uri=<artifact-uri> exposes signed proof headers without bytes
  -> Human Gateway /api/artifacts/verify?task_id=<id>&uri=<artifact-uri> receipt-scoped artifact verification
  -> Human Gateway artifact verify responses expose signed receipt digest and audit hash fields
  -> Human Gateway receipt table links artifact refs to /api/artifacts/verify
  -> Human Gateway /api/audit?task_id=<id> returns the selected receipt audit hash
  -> Human Gateway /api/artifacts/read?task_id=<id>&uri=<artifact-uri> receipt-scoped artifact byte reads
  -> Human Gateway receipt-scoped artifact reads expose signed sha256 and manifest_hash headers
  -> Human Gateway HEAD /api/artifacts/read exposes signed proof headers without bytes
  -> Human Gateway artifact read responses expose signed receipt digest headers
  -> Human Gateway artifact read responses expose audit hash-chain entry headers
  -> Human Gateway receipt table links artifact refs to /api/artifacts/read
  -> Human Gateway receipt table links receipt tasks to /api/audit?task_id proof
  -> go_queue_action audit evidence for Human Gateway queue actions
  -> record actor policy inputs and reached policy results in queue action audit evidence
  -> FED_TASK_ENQUEUE durable local queue file
  -> FED_QUEUE_CLAIM lease ownership and expiry
  -> FED_QUEUE_RECLAIM expired lease ownership transfer
  -> FED_QUEUE_RETRY failed queue retry/backoff state
  -> FED_QUEUE_RESUME queued checkpoint resume binding
  -> FED_QUEUE_DRAIN explicit queued execution gated by Human Gateway approval
```

## Next Boundary

v9.2 serializes Node audit appends inside one process. The next natural boundary is Go audit scanner buffer hardening, Go approval action locking, artifact GC apply/delete over the plan, or another small Ultimate-aligned runtime/governance slice.

Route detail: `docs/v9-roadmap.md`。

Skipped until later: browser multi-key manager, requester selector UI, alias delete/disable, server-side rotation registry, encrypted key store, passphrase-protected export, public transport, TLS/QUIC, full login/session system, token rotation/storage, dynamic policy service, policy UI, distributed nonce service, package signature verification, SBOM, long-running MCP sessions, container namespace sandbox, artifact GC, object-store artifact backend, Git/worktree/merge operations, scheduler queues, semantic routing, A2A/ARD compatibility.
