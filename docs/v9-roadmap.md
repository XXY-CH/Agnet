# Agent Space v9 Roadmap

状态：v9.10 complete; v9.11+ planned
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

## 后续方向

- real container namespace sandboxing。
