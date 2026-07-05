# Agent Space v9 Roadmap

状态：v9.5 complete; v9.6+ planned
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

## 后续方向

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

## 后续方向

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

## 后续方向

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

## 后续方向

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

## 后续方向

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

## 后续方向

- container namespace sandboxing。
