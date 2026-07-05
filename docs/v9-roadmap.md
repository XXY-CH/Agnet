# Agent Space v9 Roadmap

状态：v9.1 complete; v9.2+ planned
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

- artifact GC delete/apply over the plan。
- container namespace sandboxing。
- long-running MCP sessions。
- object-store-backed artifacts。
