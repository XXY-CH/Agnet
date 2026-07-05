# Agent Space v9 Roadmap

状态：v9.27 complete; v9.28+ planned
目标：把 v8 形成的 Human Gateway / artifact proof 面继续推进到更真实的 runtime hardening，不扩大到产品化平台。

## v9.0: Artifact Store Index Verification

状态：complete
目标：`--verify-audit --artifact-store <dir>` verifies the mirror `objects.ndjson` index covers receipt artifacts.

新增：

- Audit verification reads `<artifact-store>/objects.ndjson` when `--artifact-store` is configured.
- Verification rejects a missing mirror index.
- Verification rejects a mirror index that lacks a receipt artifact manifest entry.
- Existing mirror byte and sidecar verification still runs.

不做：

- 不做 artifact GC。
- 不做 index compaction/dedup。
- 不做 remote object-store API。
- 不做 S3/MinIO backend。
- 不做 artifact browser。
- 不做 auth model for mirrored artifacts。
- 不做 container namespace sandbox。
- 不做 public deployment。
- 不做 A2A/ARD compatibility。

## v9.1: Artifact Store GC Plan

状态：complete
目标：artifact-store can produce a GC plan from the verified mirror index and audit receipts.

新增：

- `--artifact-store-gc-plan --artifact-store <dir> --audit <file>` prints a JSON plan.
- The command verifies the audit and mirror index before computing the plan.
- Entries in `objects.ndjson` not referenced by any receipt artifact manifest are returned as `orphans`.
- The integration test appends an orphan index entry and checks the plan.

不做：

- 不删除 artifact bytes。
- 不删除 sidecars。
- 不重写 or compact `objects.ndjson`。
- 不做 retention policy。
- 不做 remote object-store API。
- 不做 S3/MinIO backend。
- 不做 artifact browser。
- 不做 auth model for mirrored artifacts。
- 不做 container namespace sandbox。
- 不做 public deployment。
- 不做 A2A/ARD compatibility。

## v9.2: Node Audit Append Serialization

状态：complete
目标：Node `appendAudit` serializes concurrent audit writes.

新增：

- `appendAudit` uses a module-level Promise queue.
- Concurrent Node audit writes no longer read the same `audit.head`.
- The audit-chain test writes 32 entries concurrently and verifies the chain.

不做：

- 不做 lockfile。
- 不做 database。
- 不做 cross-process locking。
- 不做 audit log compaction。
- 不做 Go approval locking。
- 不做 scanner buffer changes。
- 不做 state-file atomic writes。
- 不做 A2A/ARD compatibility。

## v9.3: Go Audit Scanner Buffer

状态：complete
目标：Go audit readers accept larger valid JSONL audit entries.

新增：

- `readAuditEntries` sets a 1 MiB scanner token limit.
- Go package test writes a valid audit entry larger than the default 64 KiB limit.
- The test verifies the shared audit reader accepts the large line.

不做：

- 不做 streaming JSON decoder。
- 不做 audit compaction。
- 不做 audit pagination。
- 不做 state-file atomic writes。
- 不做 Go approval locking。
- 不做 queue grant replay index。
- 不做 A2A/ARD compatibility。

## v9.4: Go Approval Action Serialization

状态：complete
目标：Go approval state modifications are serialized inside one process.

新增：

- `applyApprovalAction` serializes approval read/check/write with a shared mutex.
- The `waitForApproval` expired-state write path uses the same mutex.
- Go package test races concurrent approve calls and verifies only one succeeds.

不做：

- 不做 cross-process locking。
- 不做 lockfile。
- 不做 channel/sync.Cond approval notification。
- 不做 approval polling rewrite。
- 不做 state-file atomic writes。
- 不做 role/login model。
- 不做 A2A/ARD compatibility。

## v9.5: Artifact Store GC Apply

状态：complete
目标：artifact-store can apply the GC plan to delete orphaned mirror objects.

新增：

- `--artifact-store-gc-apply --artifact-store <dir> --audit <file>` applies the verified GC plan.
- The command deletes orphaned mirror bytes under `by-sha256/<sha256>`.
- The command deletes orphaned mirror sidecars under `by-sha256/<sha256>.manifest.json`.
- The integration test verifies referenced mirror artifacts remain after apply.

不做：

- 不 compact or rewrite `objects.ndjson`。
- 不做 retention policy。
- 不删除 local `artifacts/` named outputs。
- 不做 remote object-store API。
- 不做 S3/MinIO backend。
- 不做 artifact browser。
- 不做 auth model for mirrored artifacts。
- 不做 container namespace sandbox。
- 不做 A2A/ARD compatibility。

## v9.6: Go JSON State Atomic Replace

状态：complete
目标：Go task/approval/queue/requester JSON state files are replaced through same-directory temp files and rename.

新增：

- `writeJSONStateFile` marshals JSON state and delegates to an atomic file replacement helper.
- `atomicWriteFile` writes in the target directory, syncs the temp file, renames over the final path, and best-effort syncs the directory.
- Task state, approval state, queue state, requester registry, and requester rebinding history writes use the shared helper.
- Go package test verifies repeated replacement leaves complete JSON and no `.tmp-` file.

不做：

- 不做 cross-process locking。
- 不做 database。
- 不做 lockfile protocol。
- 不做 audit append atomic rewrite。
- 不做 artifact byte atomic write。
- 不做 artifact-store `objects.ndjson` compaction or atomic rewrite。
- 不做 queue scheduler or automatic drain。
- 不做 container namespace sandbox。
- 不做 A2A/ARD compatibility。

## v9.7: Sandbox Claim Preflight

状态：complete
目标：unsupported sandbox claims fail before external/MCP tools start.

新增：

- `sandbox_claim` is checked before `task.started` and before tool execution.
- `external.stdio` and `mcp.stdio` can claim only `local-temp-dir` in the current runtime.
- Built-in/mock tools can claim only `in-process` in the current runtime.
- Unsupported claims persist failed task state and return `unsupported sandbox claim: <claim>`.
- Integration test proves a `container-namespace` claimed worker does not start its marker tool.

不做：

- 不实现 container namespace sandbox。
- 不做 Docker/OCI runtime。
- 不做 seccomp/AppArmor/profile enforcement。
- 不做 network namespace。
- 不做 filesystem mount namespace。
- 不做 cgroup limits。
- 不做 remote attestation。
- 不做 scheduler or automatic drain。
- 不做 A2A/ARD compatibility。

## v9.8: Receipt Verify CLI

状态：complete
目标：one Go receipt record can be verified directly from a JSON file.

新增：

- `--verify-receipt <file>` verifies a single receipt record and exits.
- The command reuses the same `verifyReceiptRecord` path used by audit verification.
- It checks Zone descriptor, worker descriptor, Zone binding, receipt signature, approval grants, checkpoints, artifact manifests, policy scope, and sandbox proof.
- Success output includes `go_receipt_verify: ok` and the verified `task_id`.
- Integration test writes the live `FED_RECEIPT` record to a JSON file and verifies it through the CLI.

不做：

- 不做 receipt store。
- 不做 receipt search。
- 不做 new receipt export format。
- 不做 revocation feed or renewal checking。
- 不做 remote verifier service。
- 不做 batch receipt verification。
- 不做 A2A/ARD compatibility。

## v9.9: Go Trusted Zone Revocation Feed

状态：complete
目标：Go trusted Zone store applies a local Zone revocation feed.

新增：

- Trusted Zone JSON can include top-level `revocations`.
- `loadTrustedZones` attaches revocations to the matching trusted Zone entry.
- `verifyTrustedZone` verifies Zone revocation signatures.
- A trusted origin Zone is rejected when a valid revocation targets its `zid`.
- Go package test covers a trusted store that contains a self-revoked Zone.

不做：

- 不做 remote revocation feed sync。
- 不做 credential renewal。
- 不做 agent-level Go registry revocation。
- 不做 distributed trust graph。
- 不做 CRL/OCSP protocol。
- 不做 UI。
- 不做 A2A/ARD compatibility。

## v9.10: Trusted Zone Revocation Load-Time Verification

状态：complete
目标：Go trusted Zone store rejects tampered local Zone revocations at load time.

新增：

- `loadTrustedZones` verifies matching local Zone revocations before returning the trusted store.
- Tampered revocation signatures fail with `zone revocation signature verification failed`.
- Go package test covers a signed revocation whose `reason` is edited after signing.

不做：

- 不做 remote revocation feed sync。
- 不做 credential renewal。
- 不做 agent-level Go registry revocation。
- 不做 revocation freshness policy。
- 不做 CRL/OCSP protocol。
- 不做 UI。
- 不做 A2A/ARD compatibility。

## v9.11: Sandbox Runtime Probe Evidence

状态：complete
目标：unsupported container sandbox claims persist runtime probe evidence before tool execution.

新增：

- Sandbox claim preflight returns a structured sandbox claim error.
- Failed task state records `sandbox_probe` for unsupported `container-namespace` claims.
- The probe records `claim`, `supported: false`, and the reason that the container namespace runtime is not implemented.
- Integration coverage proves the claimed container worker still does not start its marker tool.

不做：

- 不实现 container namespace sandbox。
- 不做 Docker/OCI runtime。
- 不做 Linux namespace setup。
- 不做 seccomp/AppArmor/profile enforcement。
- 不做 network namespace。
- 不做 filesystem mount namespace。
- 不做 cgroup limits。
- 不做 remote attestation。
- 不做 scheduler or automatic drain。
- 不做 A2A/ARD compatibility。

## v9.12: Sandbox Probe CLI

状态：complete
目标：Go exposes a sandbox runtime probe CLI before real container execution exists.

新增：

- `--sandbox-probe <claim>` prints JSON runtime support for a sandbox claim and exits.
- `container-namespace` returns `supported: false` with the same reason used in failed task state.
- Existing `in-process` and `local-temp-dir` claims report available local runtime modes.
- Integration coverage runs the CLI directly through `go run ./cmd/go-fed-discovery`.

不做：

- 不实现 container namespace sandbox。
- 不做 Docker/OCI runtime。
- 不做 Linux namespace setup。
- 不做 seccomp/AppArmor/profile enforcement。
- 不做 network namespace。
- 不做 filesystem mount namespace。
- 不做 cgroup limits。
- 不做 remote attestation。
- 不做 scheduler or automatic drain。
- 不做 A2A/ARD compatibility。

## v9.13: Sandbox Claim Pre-Approval Gate

状态：complete
目标：unsupported sandbox claims fail before Human Gateway approval.

新增：

- `executeTask` validates `sandbox_claim` immediately after `task.accepted`.
- Unsupported `container-namespace` claims no longer emit `approval.required`.
- Unsupported sandbox claims no longer create Human Gateway approval state.
- Failed task state still records `sandbox_probe`.

不做：

- 不实现 container namespace sandbox。
- 不做 Docker/OCI runtime。
- 不做 Linux namespace setup。
- 不做 seccomp/AppArmor/profile enforcement。
- 不做 network namespace。
- 不做 filesystem mount namespace。
- 不做 cgroup limits。
- 不做 remote attestation。
- 不做 scheduler or automatic drain。
- 不做 A2A/ARD compatibility。

## v9.14: Sandbox Require CLI

状态：complete
目标：Go exposes a fail-closed sandbox requirement preflight CLI.

新增：

- `--sandbox-require <claim>` prints the same JSON probe as `--sandbox-probe`.
- Supported claims exit 0.
- Unsupported claims exit non-zero after printing the probe JSON.
- Integration coverage proves `container-namespace` fails closed and `local-temp-dir` succeeds.

不做：

- 不实现 container namespace sandbox。
- 不做 Docker/OCI runtime。
- 不做 Linux namespace setup。
- 不做 seccomp/AppArmor/profile enforcement。
- 不做 network namespace。
- 不做 filesystem mount namespace。
- 不做 cgroup limits。
- 不做 remote attestation。
- 不做 scheduler or automatic drain。
- 不做 A2A/ARD compatibility。

## v9.15: Container Runtime Candidate Probe

状态：complete
目标：Go reports configured container runtime candidates without claiming container namespace support.

新增：

- `--sandbox-probe container-namespace` reads optional `AGNET_CONTAINER_RUNTIME`.
- Unconfigured probes report `runtime_configured: false` and `runtime_available: false`.
- Configured probes report `runtime_command` and `runtime_path` when the command is discoverable.
- `container-namespace` remains `supported: false` even when a runtime candidate exists.
- Failed unsupported container-claim task state persists the same structured probe evidence.

不做：

- 不实现 container namespace sandbox。
- 不执行 Docker/OCI container tasks。
- 不做 Linux namespace setup。
- 不做 seccomp/AppArmor/profile enforcement。
- 不做 network namespace。
- 不做 filesystem mount namespace。
- 不做 cgroup limits。
- 不做 remote attestation。
- 不做 scheduler or automatic drain。
- 不做 A2A/ARD compatibility。

## v9.16: Container Runtime Binary Digest Probe

状态：complete
目标：Go fingerprints configured container runtime candidates without claiming container namespace support.

新增：

- `--sandbox-probe container-namespace` records `runtime_sha256` when `AGNET_CONTAINER_RUNTIME` resolves to a readable command.
- `runtime_sha256` binds the probe to the discovered runtime binary at `runtime_path`.
- `container-namespace` remains `supported: false` even when the runtime binary is fingerprinted.

不做：

- 不实现 container namespace sandbox。
- 不执行 Docker/OCI container tasks。
- 不做 Linux namespace setup。
- 不做 seccomp/AppArmor/profile enforcement。
- 不做 network namespace。
- 不做 filesystem mount namespace。
- 不做 cgroup limits。
- 不做 remote attestation。
- 不做 scheduler or automatic drain。
- 不做 A2A/ARD compatibility。

## v9.17: Go Audit Cross-Process Append Lock

状态：complete
目标：Go audit append serializes same-host writers and refreshes the hash-chain head under lock.

新增：

- `AuditLog.Append` uses an exclusive `<audit>.lock` file lock.
- Append re-reads and verifies the existing audit log under the lock before selecting `prev_hash`.
- Multiple Go `AuditLog` instances pointing at the same file append to the current shared head.
- Corrupt shared audit logs are rejected before append.

不做：

- 不做 Node cross-process audit locking。
- 不做 distributed audit log sync。
- 不做 remote audit consensus。
- 不做 multi-host locking。
- 不做 database-backed audit store。
- 不做 scheduler or automatic drain。
- 不做 A2A/ARD compatibility。

## v9.18: Go Federation TLS Listener

状态：complete
目标：Go federation TCP listener can run over TLS with operator-provided certificate and key files.

新增：

- `--tls-cert <path>` and `--tls-key <path>` enable TLS on the main Go federation listener.
- The listener status reports `transport: "fed+tls"` when TLS is enabled and `transport: "fed+tcp"` otherwise.
- Partial TLS config is rejected at startup.
- Go package coverage proves a TLS client can complete a handshake.

不做：

- 不做 mTLS client certificate verification。
- 不做 public bind address。
- 不做 WebSocket TLS。
- 不做 Human Gateway HTTPS。
- 不做 QUIC。
- 不做 DHT / relay / edge gateway。
- 不做 A2A/ARD compatibility。

## v9.19: Go Federation mTLS Client CA

状态：complete
目标：Go federation TLS listener can require client certificates signed by an operator-provided CA.

新增：

- `--tls-client-ca <path>` enables client certificate verification on the main Go federation TLS listener.
- `--tls-client-ca` requires `--tls-cert` and `--tls-key`.
- The listener status reports `transport: "fed+mtls"` when client certificate verification is enabled.
- Go package coverage proves missing client certificates are rejected and CA-signed client certificates are accepted.

不做：

- 不把 client certificate 映射为 Zone identity。
- 不替代 `HELLO` / `AUTH` authenticated session handshake。
- 不做 public bind address。
- 不做 WebSocket TLS。
- 不做 Human Gateway HTTPS。
- 不做 QUIC。
- 不做 DHT / relay / edge gateway。
- 不做 A2A/ARD compatibility。

## v9.20: Go Federation mTLS Zone Binding

状态：complete
目标：Go federation mTLS client certificates are bound to the claimed `HELLO.origin_zone`.

新增：

- TLS client certificate URI SANs are checked against `HELLO.origin_zone.zid`.
- A CA-signed client certificate for one Zone cannot claim another trusted Zone during session setup.
- The check lives in the shared `HELLO` path before `AUTH`, so all federation frame types share it.
- Go package coverage proves mismatched certificate Zone claims are rejected.

不做：

- 不设计完整 PKI policy。
- 不做 certificate revocation / OCSP。
- 不替代 `HELLO` / `AUTH` signatures。
- 不做 public bind address。
- 不做 WebSocket TLS。
- 不做 Human Gateway HTTPS。
- 不做 QUIC。
- 不做 DHT / relay / edge gateway。
- 不做 A2A/ARD compatibility。

## v9.21: Node Client to Go Task Interop

状态：complete
目标：Node federation client can execute `FED_TASK_OPEN` against the Go federation gateway and verify the Go receipt.

新增：

- `federation-gateway.mjs request` defaults to no remote write scope, so it can interoperate with Go workers that do not grant artifact write prefixes.
- The Node client sends `FED_TASK_OPEN` to the Go summarizer worker.
- The Node client verifies the Go `FED_RECEIPT` signature via the returned worker descriptor and zone binding.
- The Go integration test proves the task creates a Go receipt audit entry.

不做：

- 不做 Node server receiving Go client tasks。
- 不做 full conformance suite。
- 不做 public bind address。
- 不做 WebSocket TLS。
- 不做 Human Gateway HTTPS。
- 不做 QUIC。
- 不做 DHT / relay / edge gateway。
- 不做 A2A/ARD compatibility。

## v9.22: Go Client to Node Task Interop

状态：complete
目标：Go client can execute `FED_TASK_OPEN` against the Node federation gateway and verify the Node receipt.

新增：

- `cmd/go-fed-discovery --print-zone` prints the Go authority Zone descriptor for Node trust setup.
- `cmd/go-fed-discovery --interop-request <port>` performs one Go client task request to a Node federation gateway.
- The Go client performs `HELLO` / `AUTH`, verifies the Node Zone and zone binding, and verifies the Node `FED_RECEIPT` signature.
- The Node federation test proves the Go request completes with `task.completed`.

不做：

- 不做 full Go client SDK。
- 不做 full conformance suite。
- 不做 scheduler-driven cross-implementation dispatch。
- 不做 public bind address。
- 不做 WebSocket TLS。
- 不做 Human Gateway HTTPS。
- 不做 QUIC。
- 不做 DHT / relay / edge gateway。
- 不做 A2A/ARD compatibility。

## v9.23: Explicit Go Federation Bind Host

状态：complete
目标：Go federation TCP listener can bind an explicitly configured host while preserving the default local-only bind.

新增：

- `cmd/go-fed-discovery --listen-host <host>` configures only the main federation TCP listener.
- Default remains `127.0.0.1`.
- Startup status and Human Gateway `/api/security` expose `listen_host` and a derived `public_transport` boolean.
- Go package coverage proves configured loopback binding and public-host classification.

不做：

- 不改 WebSocket listener bind host。
- 不改 Human Gateway listener bind host。
- 不做 public gateway deployment。
- 不做 NAT / proxy / relay。
- 不做 QUIC。
- 不做 DHT / edge gateway。
- 不做 container namespace sandbox。
- 不做 A2A/ARD compatibility。

## v9.24: FED_TASK_OPEN Conformance Fixture

状态：complete
目标：Node and Go verify the same static `FED_TASK_OPEN` conformance fixture.

新增：

- `test-vectors/asp-v9.24-fed-task-open.json` captures deterministic Zone/requester/worker descriptors and one signed task frame.
- Node exports `verifyFederatedTaskOpen(...)` and the federation gateway reuses it for live task handling.
- Go package coverage verifies the same fixture through `verifyTrustedZone` and `Fixture.verifyTaskOpen`.
- Node vector coverage verifies the same fixture through `verifyFederatedTaskOpen`.

不做：

- 不做 full conformance suite。
- 不做 fixture generator CLI。
- 不做 scheduler-driven cross-implementation dispatch。
- 不做 public gateway deployment。
- 不做 NAT / proxy / relay。
- 不做 QUIC。
- 不做 DHT / edge gateway。
- 不做 container namespace sandbox。
- 不做 A2A/ARD compatibility。

## v9.25: FED_RECEIPT Conformance Fixture

状态：complete
目标：Node and Go verify the same static `FED_RECEIPT` conformance fixture.

新增：

- `test-vectors/asp-v9.25-fed-receipt.json` captures deterministic Zone/worker descriptors, zone binding, and one signed receipt frame.
- Node exports `verifyFederatedReceipt(...)`.
- Node federation client/audit receipt verification reuses the shared verifier.
- Go package coverage verifies the same fixture through `verifyInteropReceipt`.
- Node vector coverage verifies the same fixture through `verifyFederatedReceipt`.

不做：

- 不做 full conformance suite。
- 不做 fixture generator CLI。
- 不做 receipt store/search。
- 不做 remote audit log sync。
- 不做 scheduler-driven cross-implementation dispatch。
- 不做 public gateway deployment。
- 不做 NAT / proxy / relay。
- 不做 QUIC。
- 不做 DHT / edge gateway。
- 不做 container namespace sandbox。
- 不做 A2A/ARD compatibility。

## v9.26: Explicit Swarm DAG Seed

状态：complete
目标：Go federation gateway accepts one explicit two-step Swarm DAG and binds downstream receipt evidence to upstream artifact manifests.

新增：

- `FED_SWARM_OPEN` is accepted after the existing authenticated federation handshake.
- The frame carries a caller-supplied `swarm_id` and ordered `steps`.
- Each step reuses the existing signed task verifier and task execution path.
- A step can declare `after: [...]`; dependencies must already have completed in the same frame.
- Swarm receipts include a signed `swarm` object with `swarm_id`, `step_id`, `after`, and `input_artifacts`.
- Dependent receipts bind upstream artifacts by `step_id`, `uri`, `sha256`, and `manifest_hash`.
- Integration coverage proves two different Go workers execute a summary step followed by a translation step.

不做：

- 不做 dynamic decomposition。
- 不做 candidate discovery / selection。
- 不做 scheduler。
- 不做 automatic drain。
- 不做 parallel execution。
- 不做 conflict resolution。
- 不做 Swarm UI。
- 不做 cross-Zone Swarm。
- 不做 Node Swarm server。
- 不做 container namespace sandbox。
- 不做 A2A/ARD compatibility。

## v9.27: Swarm Dependency Audit Verification

状态：complete
目标：Go audit verification rejects signed Swarm receipts whose declared input artifacts do not match upstream Swarm step receipts in the same audit log.

新增：

- `--verify-audit` records completed Swarm step artifact manifests while scanning the audit chain.
- Dependent Swarm receipts must reference an already completed step in the same `swarm_id`.
- `input_artifacts` must match the upstream step's first artifact manifest by `step_id`, `uri`, `sha256`, and `manifest_hash`.
- Go package coverage proves a worker-signed false dependency digest is rejected.
- The same coverage proves the clean Swarm dependency graph still verifies.

不做：

- 不做 cross-audit dependency lookup。
- 不做 remote audit sync。
- 不做 scheduler。
- 不做 dynamic decomposition。
- 不做 parallel execution。
- 不做 conflict resolution。
- 不做 Swarm UI。
- 不做 Node Swarm server。
- 不做 A2A/ARD compatibility。

## 后续方向

- real container namespace sandboxing。
- public federation deployment / QUIC binding。
- Node artifact manifest parity。
- richer Swarm orchestration: scheduler-owned DAG execution, cross-Zone workers, and conflict/merge receipts。
- more cross-implementation conformance fixtures。
