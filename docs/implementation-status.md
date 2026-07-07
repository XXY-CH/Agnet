# Agent Space Implementation Status

状态：v12.25 active
当前代码基线：`v12.25-package-proof-relative-tarball`

## 一句话

当前实现已经证明了 Agent identity with Ed25519 `did:key` bridge input presence validation、Node local artifact URI boundary validation、Node local artifact path boundary validation、Node receipt artifact URI/ref shape validation、Go public-listen signed receipt transport proof、Go artifact manifest AFP validation、Go artifact manifest URI validation、Go artifact mirror index AFP type validation、Go artifact mirror index URI validation、Go artifact mirror index media type validation、Go artifact mirror index size validation、Go artifact mirror index AFP validation、Go artifact mirror index manifest hash validation、Go artifact mirror index SHA-256 presence validation、Go artifact mirror index SHA-256 path validation、Go artifact mirror index entry object validation、Go artifact mirror index exact field matching validation、Go artifact list entry shape validation、Go artifact manifest hash shape validation、Go artifact manifest media type shape validation、Go artifact manifest SHA-256 path boundary validation、receipt artifact manifest SHA-256 shape validation、receipt artifact manifest size shape validation、Node proof verifier malformed descriptor fail-closed validation、Node descriptor body object presence validation、Node registry file shape validation、Node resolveAgent registry context validation、Node Zone descriptor object presence validation、Node trusted Zone file shape validation、Node Zone binding object presence validation、Node Zone revocation object presence validation、Node descriptor public key presence validation、Node shared object signature fail-closed validation、Node rotation proof object presence validation、Node capability credential object presence validation、Node artifact manifest object presence validation、Node artifact manifest sidecar/receipt evidence, minimal AFP `afp:sha256:<sha256>` strings, receipt-side manifest metadata verification, receipt `task_digest` binding requirement, optional supplied-task `task_digest` verification across Node receipt/artifact CLIs and the Go receipt CLI, bidirectional Node/Go interop receipt `task_digest` verification against the signed task sent by the client, Node `FED_TASK_OPEN` and `FED_RECEIPT` frame object/type, Zone descriptor presence, payload object presence, and trusted Zone store presence validation, plus Node `FED_TASK_OPEN` worker descriptor context presence validation and worker descriptor identity validation, Node `FED_RECEIPT` worker descriptor identity validation, Node signed task/receipt signature presence validation, and Node unsafe signed receipt `task_id` rejection, Go `FED_TASK_OPEN` and `FED_RECEIPT` frame type validation, local artifact byte/sidecar verification, minimal artifact verifier CLI, minimal Node `FED_RECEIPT` verifier CLI with trusted-Zone descriptor validation, signed receipt origin-Zone trust validation, and stable `receipt_digest` output, one-receipt local artifact closure verifier CLI with trusted-Zone descriptor validation, stable `receipt_digest` output, verified artifact URI output, verified artifact SHA-256 output, and verified artifact manifest hash output, proof summary JSON receipt digest, artifact count, artifact URI, artifact SHA-256, verified artifact manifest hash, and signed transport proof forwarding, narrow Node `FED_SWARM_CLOSE` signature/digest verifier CLI with trusted-Zone descriptor validation and fail-closed structural close-frame/close-zone/close-proof/close-signature/step-receipt object/identity/task-id/uniqueness/NUL checks, local npm-facing verifier package contract, a narrow implementation-backed ASP Core draft, a reusable Go `FED_RECEIPT` frame verifier package with origin-Zone trust validation and optional supplied-task `task_digest` validation, shared `FED_TASK_OPEN` / `FED_RECEIPT` / `FED_SWARM_CLOSE` conformance fixtures, `FED_TASK_OPEN` frame type and requester Zone binding validation, `task_id` token validation, a one-command local proof demo with verifier-ready receipt/trust closure files, verified Docker proof demo outputs with overrideable base images, and a verifier-ready local public-listen authenticated resolve/query/task/audit/artifact/swarm proof with signed receipt transport proof, a portable Swarm close frame plus trusted Zone file, reproducible Swarm close digest, Node CLI close-frame verification, and out-of-receipt/post-receipt-tampered artifact-read rejection coverage that now runs in Docker、signed task、local runtime、Node federation execution、Node in-process serialized audit append、Go same-host audit append locking、Go federation discovery、Go federation TLS/mTLS listener with certificate-to-Zone binding、Go explicit federation listen host、bidirectional Node/Go `FED_TASK_OPEN` interop、Go explicit two-step `FED_SWARM_OPEN` DAG seed with signed downstream artifact dependency evidence、Go Swarm dependency list shape validation、Go FED_SWARM_OPEN after list shape validation、Go Swarm close step receipt list shape validation、Go delimiter-safe Swarm ids、Go single ordered complete audit-backed Zone-signed `FED_SWARM_CLOSE` close proof with ordered same-audit step receipt digests、Go audit verification for Swarm declared dependency steps, unique step ids even without artifacts, artifact manifests, upstream receipt digests, complete and ordered close proof step receipt sets, malformed close step receipt list rejection, duplicate close proof rejection, unknown close proof rejection, NUL-bearing Swarm identity rejection, and close proof step digests、Go dynamic signing、Go key files、Go receipt approval evidence list shape validation、Go receipt checkpoint evidence list shape validation、Go runtime checkpoint lookup list shape validation、Go receipt artifact lookup list shape validation、Go `FED_TASK_OPEN` requester Zone binding verification、Go unsafe `task_id` rejection、Go direct task Human Gateway explicit approval/denial/expiry/named actor evidence/local actor policy/local approval session actor evidence/session actor mismatch rejection/session state API/session state UI、Go `FED_TASK_ENQUEUE` durable local queue entry、Go `FED_QUEUE_CLAIM` lease ownership/expiry/backoff gate、Go `FED_QUEUE_RECLAIM` expired lease ownership transfer、Go `FED_QUEUE_RETRY` failed queue retry/backoff state、Go `FED_QUEUE_RESUME` queued checkpoint resume binding、Go queued checkpoint state digest restore evidence、Go `FED_QUEUE_DRAIN` explicit queued execution with Human Gateway approval、Go Human Gateway queue state/action/creation/drafting/external signed draft/approval/security posture/browser requester key surface with import/export/rotation proof/rebinding proof API/multi-alias local requester registry persistence/requester registry view/browser alias rebinding UI/local rebinding history table、Go Human Gateway transcript artifact link UI/task-scoped artifact manifest proof link/UI、task-scoped artifact manifest HEAD proof headers、task-scoped transcript stream API、Human Gateway transcript stream viewer、running external tool transcript snapshot API、Human Gateway running task rows can load live transcript snapshots into the local transcript viewer、Human Gateway live transcript loading polls the running snapshot until another transcript is selected、MCP stdio live transcript snapshot API、filesystem artifact mirror object index/verifier coverage/GC plan、task-scoped audit proof API/link with audit hash、receipt-scoped artifact verify/read API/link、receipt-scoped artifact verify receipt digest and audit hash fields、receipt-scoped read digest headers、receipt-scoped HEAD proof headers、receipt digest and audit hash headers on artifact reads、Go Human Gateway write bearer-token gate、Go Human Gateway actor-bound scoped signed queue action grants、Go signed queue action grant scope list shape validation、Go Human Gateway configurable local actor policy gate、Go queue action grant nonce replay rejection、Go queue action unsafe `task_id` rejection、Go `FED_TASK_RESUME` audit-backed checkpoint link、Go signed `FED_TASK_CANCEL` evidence、Go live external task cancellation、Go `FED_TASK_RETRY` lineage evidence、Go 最小 task execution path、Go durable running/completed/cancelled/failed task state files、Go Human Gateway task state view、Go audit/receipt verification、Go multi-worker registry、Go WebSocket transport binding、thin Human Gateway、Go 内置 tool adapter、external stdio tool adapter、最小 MCP stdio `tools/call`、MCP initialize metadata evidence、MCP resources/prompts/tools metadata evidence、MCP selected tool binding、MCP selected tool schema digest evidence、MCP argument digest evidence、MCP required argument gate、外部/MCP tool approval gate、signed approval evidence、本地临时目录 sandbox evidence、sandbox isolation level evidence、signed sandbox proof、sandbox claim binding、unsupported sandbox pre-approval gate、unsupported sandbox runtime probe evidence、sandbox probe CLI、sandbox require CLI、container runtime candidate probe evidence、container runtime binary digest evidence、tool command/executable binary/result transcript provenance digest、tool result transcript artifact evidence、tool output digest alignment、protocol-native checkpoint evidence、artifact manifest digest evidence、artifact manifest sidecar/API evidence、content-addressed local artifact evidence、filesystem artifact mirror evidence、artifact byte/AFP verification evidence、artifact named sidecar/digest sidecar/mirror verification evidence、canonical policy scope evidence、credential status evidence、authenticated session handshake，以及 remote audit query。

还不是可产品化的 Agent Net。

## 能力矩阵

| Capability | Node | Go | Evidence | Missing |
| --- | --- | --- | --- | --- |
| Agent identity | done + Ed25519 `did:key` bridge | verify/generate subset + Ed25519 `did:key` bridge | `asp-core.mjs`, `test-vectors.test.mjs`, `cmd/go-fed-discovery`, `cmd/go-fed-discovery/main_test.go` | Go shared library/package shape / DID document resolver |
| Zone identity | done | verify/generate subset + Go trusted Zone local revocation feed + load-time revocation signature verification | `trusted-zones.test.mjs`, `cmd/go-fed-discovery/main_test.go`, Go descriptor verification | Zone lifecycle tooling / remote revocation sync |
| Local registry | done | multi-worker profile registry | `zone-registry.test.mjs`, `go-fed-discovery.test.mjs` | worker lifecycle API |
| Local task execution | done | built-in + external stdio + MCP stdio tools/call + MCP initialize/resources/prompts/tools metadata + selected tool/schema/argument evidence + MCP required argument gate + explicit local-process isolation evidence + sandbox-bound HOME/TMPDIR/XDG_CACHE_HOME + signed local sandbox proof + sandbox claim binding + unsupported sandbox claim preflight before approval + failed sandbox runtime probe state + sandbox probe/require CLI + optional `AGNET_CONTAINER_RUNTIME` candidate and `runtime_sha256` probe evidence + tool command, binary, transcript digests, and transcript artifacts | `agent-runtime.test.mjs`, `go-fed-discovery.test.mjs` | container namespace sandbox / long-running MCP sessions |
| Events | done | minimal federation events + Go checkpoint event | `agent-runtime.test.mjs`, `federation-gateway.test.mjs`, `go-fed-discovery.test.mjs` | richer event lifecycle |
| Artifact write | local artifact + manifest sidecar + minimal AFP string + receipt manifest URI/ref shape validation + receipt manifest evidence + receipt/local manifest and byte verification + artifact verifier CLI | deterministic local artifact + Go artifact manifest digest evidence + minimal AFP string + tool output/transcript digest alignment + local manifest sidecar/API + content-addressed local path + optional filesystem artifact mirror + mirror object index + audit verifier byte/AFP/named sidecar/digest sidecar/mirror/index checks + GC plan/apply | `mvp-demo.test.mjs`, `test-vectors.test.mjs`, `go-fed-discovery.test.mjs`, `cmd/go-fed-discovery/main_test.go`, `verifier/receipt_test.go` | Node artifact verify/read API / object-store backend / retention policy |
| Receipt signing | done + generated receipts carry `task_digest` + receipt verifier rejects unsafe signed receipt task ids + single FED_RECEIPT frame verification CLI with optional task evidence + one-receipt local artifact closure CLI with optional task evidence | done for minimal Go execution and cancellation receipts + generated receipts carry `task_digest` + single receipt record verification CLI with optional task evidence + receipt verifier rejects unsafe signed receipt task ids | `test-vectors.test.mjs`, `go-fed-discovery.test.mjs`, `cmd/go-fed-discovery/main_test.go` | receipt store/search / batch receipt verification |
| Reusable verifier | Node exports verifier functions + local npm-facing `asp-verify` bin contract, including `FED_RECEIPT` frame type validation, worker descriptor identity validation, stable receipt digest output, origin-Zone trust validation, `task_digest` presence and optional supplied-task match validation, artifact URI/SHA-256/manifest-hash output, proof summary receipt digest/count/URI/SHA-256/manifest-hash forwarding, narrow `FED_SWARM_CLOSE` signature/digest verification with structural close-frame/close-zone/close-proof/close-signature/step-receipt object/identity/task-id/uniqueness/NUL checks, trusted-Zone descriptor validation in CLI paths, and local npm tarball artifact proof manifest metadata including SHA-256, canonical package proof digest, package proof verifier command, package proof manifest object validation, package proof tarball path safety, and manifest-relative package tarball verification | `agnet/verifier.VerifyFederatedReceipt` package function for one `FED_RECEIPT` frame, including frame type validation, origin-Zone trust validation, and optional supplied-task `task_digest` match validation | `test-vectors.test.mjs`, `package-contract.test.mjs`, `proof-demo.test.mjs`, `public-node-proof.test.mjs`, `verifier/receipt_test.go`, `cmd/go-fed-discovery/main_test.go` | package publish/signing / Go module split / batch verifier |
| ASP Core draft | implementation-backed Draft 0 | implementation-backed Draft 0 | `docs/asp-core-draft.md`, `docs-contract.test.mjs` | full standard / public interoperability process |
| Reproducible demo | `scripts/proof-demo.sh` local proof demo emits verifier-ready receipt/trust files, forwards `receipt_digest`, and verifies local artifact closure + `scripts/docker-proof-demo.sh` verified on Docker Server `29.0.1` and accepts `AGNET_NODE_BASE_IMAGE` + `scripts/public-node-proof.sh` verifies local public-listen status and authenticated `FED_RESOLVE` / `FED_QUERY` / `FED_TASK_OPEN` / `FED_AUDIT_QUERY` / `FED_ARTIFACT_READ` / `FED_SWARM_OPEN` round trips, emits verifier-ready receipt/trust files, forwards `receipt_digest`, confirms signed receipt transport proof fields, writes `state/public-node-proof-swarm-close.json` and `state/public-node-proof-swarm-close-trusted-zones.json`, verifies fetched artifact bytes, proves out-of-receipt plus post-receipt-tampered artifact reads are rejected, and verifies a two-step Swarm close proof with `swarm_close_digest` and summary `swarm_close_verify` via `asp-verify.mjs swarm-close` + `scripts/docker-public-node-proof.sh` verifies the same public-listen proof inside Docker and accepts `AGNET_GO_BASE_IMAGE` / `AGNET_NODE_BASE_IMAGE` | not yet | `proof-demo.test.mjs`, `docker-demo.test.mjs`, `public-node-proof.test.mjs`, `bash scripts/docker-proof-demo.sh`, `bash scripts/docker-public-node-proof.sh` | public reachability / hosted demo |
| Audit hash chain | done + in-process append serialization | done for Go execution, same-host append lock + head refresh, queue actions, remote receipt proof query, Human Gateway task-scoped receipt proof query, and large-line audit reads | `audit-chain.test.mjs`, `cmd/go-fed-discovery/main_test.go`, `go-fed-discovery.test.mjs` | Node cross-process locking / full log sync / remote search |
| Federation resolve | done | done | `federation-gateway.test.mjs`, `go-fed-discovery.test.mjs` | public transport |
| Capability query | done | done | `federation-gateway.test.mjs`, `go-fed-discovery.test.mjs` | ranking / scheduling |
| Capability credential | done | done + Go signed status evidence | `capability-credential.test.mjs`, `go-fed-discovery.test.mjs` | revocation feed / renewal |
| Key persistence | PKCS8 files | seed key files | `state/keys`, `--authority-key`, `--worker-key` | rotation, encryption, permissions |
| `FED_TASK_OPEN` / `FED_RECEIPT` / `FED_SWARM_CLOSE` vectors | execute + requester Zone binding + task id token validation including Node receipt task id validation + verifier context presence validation + receipt `task_digest` validation + Node client to Go task interop with receipt/task digest binding + shared task/receipt/Swarm-close conformance fixture verification | execute + requester Zone binding + task id token validation including Go receipt task id validation + receipt `task_digest` validation + Go client to Node task interop with receipt/task digest binding + durable running/completed/failed task state files + shared task/receipt conformance fixture verification | `test-vectors/asp-v9.24-fed-task-open.json`, `test-vectors/asp-v9.25-fed-receipt.json`, `test-vectors/asp-v10.38-fed-swarm-close.json`, `test-vectors.test.mjs`, `cmd/go-fed-discovery/main_test.go`, `federation-gateway.mjs`, `federation-gateway.test.mjs`, `go-fed-discovery.test.mjs` | scheduler / real restore / broader conformance suite |
| `FED_SWARM_OPEN` | not yet | explicit ordered two-step DAG seed; each step reuses signed task execution; receipts bind delimiter-safe dependency step ids, artifact manifests, and upstream receipt digest; `FED_SWARM_CLOSE` carries one complete audit-backed Zone-signed ordered close proof over same-audit receipts; audit verifier rejects duplicate step receipts, including artifactless duplicates, NUL-bearing Swarm identities, false signed dependency steps/manifests/receipt digests, incomplete/duplicate/reordered close summaries, duplicate close records, close proofs for audit-absent Swarms, and false close step digests | `go-fed-discovery.test.mjs`, `cmd/go-fed-discovery/main_test.go` | dynamic decomposition / scheduler / parallel execution / conflict resolution / cross-Zone Swarm |
| `FED_TASK_ENQUEUE` | not yet | durable local queue file + claim/lease expiry + reclaim + retry/backoff state + explicit drain path | `go-fed-discovery.test.mjs` | automatic drain |
| `FED_TASK_CANCEL` | not yet | signed cancellation receipt evidence + durable cancelled state file + live external process interruption | `go-fed-discovery.test.mjs` | persisted running registry / multi-node cancel |
| `FED_TASK_RETRY` | not yet | signed retry lineage evidence | `go-fed-discovery.test.mjs` | automatic retry / backoff / scheduler state |
| Policy checks | done | network/write subset + Go signed task write/data-domain list shape validation + Go receipt policy scope list shape validation and scalar shape validation + Go canonical policy scope digest + stable deny codes | `agent-runtime.test.mjs`, `go-fed-discovery.test.mjs`, `cmd/go-fed-discovery/main_test.go` | policy negotiation / dynamic policy service |
| Human approval | simulated | direct Go task execution and queued drain write pending approval state; in-process approval state writes are serialized; approve continues, deny/expiry stops before tools; worker policy approval-required list shape validation; direct approvals preserve named `human://...` actors in signed grants; approval actors pass configurable local allowlists; local bearer approval sessions can supply the approval actor; mismatched body/session actors are rejected; `/api/session` exposes local session actor/actions state; Human Gateway page displays that local session state | Node events, `cmd/go-fed-discovery/main_test.go`, `go-fed-discovery.test.mjs` | roles / cross-process locking |
| Checkpoint evidence | not yet | signed protocol-native checkpoint evidence + audit-backed immediate and queued resume parent links + restored state digest evidence + receipt-linked task state file | `go-fed-discovery.test.mjs` | model KV/cache restore |
| Transport | local TCP / local process + authenticated session handshake | local TCP + configurable main federation listen host + verifier-ready local public-listen authenticated resolve/query/task/audit/artifact/swarm proof with out-of-receipt and post-receipt-tamper rejection evidence + optional TLS/mTLS federation listener with certificate-to-Zone binding + minimal WebSocket + authenticated session handshake | README commands, `public-node-proof.test.mjs`, `cmd/go-fed-discovery/main_test.go`, `federation-gateway.test.mjs`, `go-fed-discovery.test.mjs` | public reachability / deployment / QUIC |
| Product surface | CLI/tests only | thin Human Gateway with task table, queue table, approval table/API, task-scoped audit proof links/API with audit hash, receipt artifact links including transcript artifacts, task-scoped manifest links and HEAD proof headers, transcript stream API, transcript stream viewer, running transcript snapshot API, running transcript snapshot viewer action, live transcript polling UI, MCP stdio live transcript snapshot API, filesystem artifact mirror object index, verify links with receipt/audit proof fields, read links, signed digest headers on read responses, HEAD proof headers, receipt digest headers, and audit hash headers, local session state panel, security posture API, browser-held requester key panel with import/export/rotation proof/alias rebinding submission, requester alias rebinding proof API, multi-alias local requester registry persistence, requester registry table, local rebinding history table, optional bearer-token write gate, actor-bound scoped signed explicit local enqueue/claim/drain actions, configurable local actor policy, durable grant nonce index, local draft/sign/enqueue endpoint, and external signed draft enqueue endpoint | README, `go-fed-discovery.test.mjs` | encrypted key store, admin, deployment |

## Current Boundary

```text
Node
  -> full prototype execution path
  -> local/federated events, artifact, receipt, audit
  -> Ed25519 descriptor did:key bridge generation and validation
  -> proof verifiers return false for malformed descriptor inputs instead of leaking parser errors
  -> local artifact verifier rejects non-local artifact URIs and escaping local paths before filesystem reads
  -> descriptor body helpers reject missing descriptor objects before removing signature fields
  -> registry files reject missing agent lists, missing entries, and missing descriptors before field reads
  -> resolveAgent rejects missing registry context before entry lookup
  -> trusted Zone files reject missing Zone lists before entry iteration and load raw descriptor arrays
  -> Zone binding verifier rejects missing binding context and descriptor objects before field reads
  -> Zone revocation verifiers reject missing revocation context, descriptor, and revocation-list objects before field reads
  -> descriptor public key presence validation before Node crypto parsing
  -> shared object signature fail-closed validation before Node crypto parsing
  -> artifact manifest sidecar and receipt artifact_manifests evidence
  -> FED_RECEIPT artifact manifest URI/ref shape validation
  -> FED_RECEIPT verifier checks signed artifact manifest metadata
  -> FED_RECEIPT verifier requires frame object/type FED_RECEIPT
  -> FED_RECEIPT verifier validates worker descriptor identity before receipt identity/signature checks
  -> FED_TASK_OPEN verifier requires local worker descriptor context before reading worker alias/policy
  -> FED_TASK_OPEN verifier validates local worker descriptor identity before target/policy checks
  -> FED_TASK_OPEN and FED_RECEIPT verifiers require signatures before crypto verification
  -> FED_RECEIPT verifier requires receipt task_digest and can compare supplied signed task evidence
  -> FED_RECEIPT verifier rejects unsafe signed receipt task ids
  -> Node-to-Go interop receipt verification compares receipt task_digest against the sent signed task
  -> local artifact byte and sidecar verification against receipt manifest
  -> asp-verify.mjs artifact <manifest.json> exact-arity CLI
  -> asp-verify.mjs fed-receipt <frame.json> <trusted-zones.json> [task.json] exact-arity CLI with receipt origin-Zone trust validation and optional task evidence check
  -> asp-verify.mjs fed-receipt-artifacts <frame.json> <trusted-zones.json> [task.json] exact-arity CLI with receipt origin-Zone trust validation and optional task evidence check
  -> asp-verify.mjs swarm-close <frame.json> <trusted-zones.json> exact-arity CLI for one FED_SWARM_CLOSE signature, digest, and structural close-frame/close-zone/close-proof/close-signature/step-receipt object/identity/task-id/uniqueness/NUL check
  -> asp-verify.mjs package-proof <manifest.json> verifies package proof_digest, manifest-relative tarball sha256, and manifest-relative tarball size, rejects non-object package proof manifests, and rejects unsafe package proof tarball paths
  -> package.json exposes local npm-facing asp-verify bin and asp-core.mjs exports
  -> scripts/package-proof.mjs creates a local npm tarball artifact and package-proof.json manifest with npm shasum, integrity, SHA-256, canonical package proof digest, size, and file-list metadata
  -> scripts/proof-demo.sh one-command local proof demo with verifier-ready FED_RECEIPT/trusted-zone files and summary receipt_digest
  -> Dockerfile + scripts/docker-proof-demo.sh Docker proof demo contract with AGNET_NODE_BASE_IMAGE override
  -> Dockerfile.public-node-proof + scripts/docker-public-node-proof.sh Docker public-listen proof contract with AGNET_GO_BASE_IMAGE and AGNET_NODE_BASE_IMAGE overrides

Go
  -> trusted federation discovery
  -> Ed25519 descriptor did:key bridge generation and validation
  -> Go trusted Zone store applies local Zone revocations
  -> Go trusted Zone store rejects tampered local Zone revocations at load time
  -> dynamic worker descriptor, binding, credential signing
  -> key files
  -> FED_TASK_OPEN verification
  -> FED_TASK_OPEN verifier requires frame.type FED_TASK_OPEN
  -> FED_TASK_OPEN task_id token validation
  -> shared FED_TASK_OPEN conformance fixture verification
  -> shared FED_RECEIPT conformance fixture verification
  -> FED_RECEIPT verifier requires frame.type FED_RECEIPT
  -> FED_RECEIPT verifier requires receipt task_digest and can compare supplied signed task evidence
  -> agnet/verifier.VerifyFederatedReceipt reusable package path for FED_RECEIPT frames with receipt origin-Zone trust validation
  -> go run ./cmd/go-fed-discovery --verify-receipt <receipt.json> --verify-task <task.json> optional task evidence check
  -> Go-to-Node interop receipt verification compares receipt task_digest against the sent signed task
  -> FED_TASK_OPEN requester Zone binding verification
  -> FED_TASK_OPEN task_id token validation
  -> FED_TASK_CANCEL signed cancellation evidence
  -> live external task cancellation through in-memory runtime registry
  -> FED_TASK_RETRY retry lineage evidence
  -> durable running/completed/cancelled/failed task state files
  -> Go JSON state files for task/approval/queue/requester registry/history are replaced through temp-file + rename
  -> minimal task events, artifact, signed receipt
  -> audit JSONL hash chain and verifier
  -> Go audit append uses same-host lock file and verifies the shared head before writing
  -> single receipt record verification CLI
  -> multi-worker profile registry
  -> explicit main federation listen host while defaulting to 127.0.0.1
  -> local public-listen proof for authenticated resolve, query, task execution, audit receipt query, artifact byte fetch, out-of-receipt artifact read rejection, post-receipt artifact byte tamper rejection, summary receipt_digest, two-step Swarm close proof verification, summary swarm_close_verify, reproducible close digest, verifier-ready receipt/trust/Swarm-close/trusted-Zone files, Node CLI close-frame verification, and fetched artifact byte verification
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
  -> unsupported sandbox claims fail before Human Gateway approval and before external/MCP tool start
  -> unsupported container namespace sandbox claims persist runtime probe evidence in failed task state
  -> --sandbox-probe exposes sandbox runtime support as JSON
  -> --sandbox-require exits non-zero when required sandbox support is unavailable
  -> AGNET_CONTAINER_RUNTIME lets container namespace probes report configured runtime candidates while keeping supported=false
  -> readable AGNET_CONTAINER_RUNTIME candidates include runtime_sha256 binary digest evidence
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
  -> filesystem artifact mirrors maintain and verify an objects.ndjson content-addressed object index with required SHA-256 path validation, present URI validation, present media-type validation, present size validation, present AFP alignment validation, present manifest-hash digest validation, object-entry validation, and exact manifest field matching
  -> artifact-store GC plan lists unreferenced mirror index entries
  -> artifact-store GC apply deletes unreferenced mirror bytes and sidecars
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
  -> audit artifact verifier rejects malformed manifest sha256 values before digest-addressed sidecar or mirror path reads
  -> audit verifier checks local artifact bytes against manifests
  -> audit verifier checks named artifact manifest sidecars against manifests
  -> audit verifier checks digest-addressed artifact manifest sidecars against manifests
  -> audit verifier checks optional filesystem artifact mirror bytes, sidecars, required safe SHA-256 index paths, present URI index validation, present media-type index validation, present size index validation, present AFP index alignment, present manifest-hash index digests, object-shaped index entries, and exact-type object index matches when --artifact-store is configured
  -> canonical policy scope digest, receipt policy scope list shape validation and scalar shape validation, and stable deny codes
  -> Zone-signed credential status evidence
  -> authenticated session handshake
  -> optional TLS on the main Go federation TCP listener with --tls-cert/--tls-key
  -> optional mTLS client certificate verification on the main Go federation TCP listener with --tls-client-ca
  -> mTLS client certificate URI SAN binding to HELLO origin_zone.zid
  -> remote audit query by task id
  -> Human Gateway /api/audit?task_id task-scoped receipt proof query
  -> Human Gateway /api/tasks and task table
  -> Human Gateway /api/approvals and Approvals table
  -> Human Gateway optional bearer-token gate for write endpoints
  -> Human Gateway /api/security local deployment posture
  -> Human Gateway /api/queue and actor-bound scoped signed explicit queue enqueue/claim/drain actions with configurable local actor policy, signed grant scope action list shape validation, and durable nonce replay rejection
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
  -> FED_SWARM_OPEN explicit two-step DAG seed with signed artifact dependency proof
  -> FED_SWARM_CLOSE single ordered complete audit-backed Zone-signed close proof with ordered same-audit step receipt digests
  -> verify-audit checks Swarm input_artifacts against declared after steps, unique upstream step ids even when artifactless, upstream step artifact manifests, and receipt digest in the same audit
  -> FED_QUEUE_CLAIM lease ownership and expiry
  -> FED_QUEUE_RECLAIM expired lease ownership transfer
  -> FED_QUEUE_RETRY failed queue retry/backoff state
  -> FED_QUEUE_RESUME queued checkpoint resume binding
  -> FED_QUEUE_DRAIN explicit queued execution gated by Human Gateway approval
```

## Next Boundary

v12.25 makes `asp-verify.mjs package-proof <manifest.json>` resolve safe tarball paths relative to the package proof manifest, and makes `scripts/package-proof.mjs` emit package-directory-relative `tarball` and `manifest` names. This keeps the proof boundary narrow: it does not claim remote-host reachability, JSON Schema, hosted public reachability, package signing, SBOM, scheduler ownership, batch verification, or A2A/ARD compatibility.

Route detail: `docs/v12-roadmap.md`。

Skipped until later: DID-native resolver/document/service routing, browser multi-key manager, requester selector UI, alias delete/disable, server-side rotation registry, encrypted key store, passphrase-protected export, public transport/QUIC, full login/session system, token rotation/storage, dynamic policy service, policy UI, distributed nonce service, package signature verification, SBOM, long-running MCP sessions, container namespace sandbox, object-store artifact backend, Git/worktree/merge operations, scheduler queues, dynamic Swarm decomposition, parallel Swarm execution, semantic routing, A2A/ARD compatibility.
