# Agent Space v11 Roadmap

状态：active
目标：v11 从 Ultimate 的 Trust & Verification 缺口继续推进，但只补能被当前 verifier/test vectors 证明的窄边界。

## v11.0: Receipt Origin Zone Trust Validation

状态：complete
目标：Make `FED_RECEIPT` provenance fail closed when a signed receipt names an untrusted origin Zone.

新增：

- Node `verifyFederatedReceipt` rejects signed receipts whose `origin_zone` is absent from the trusted Zone store.
- Go `agnet/verifier.VerifyFederatedReceipt` rejects the same untrusted signed receipt origin.
- The shared `FED_RECEIPT` conformance vector includes both the origin Zone and executing Zone as trusted descriptors.
- `scripts/public-node-proof.mjs` writes verifier-ready receipt trusted-Zone files that include the proof origin Zone and executing Zone.
- Node and Go tests prove removing the signed `origin_zone` from trust makes verification fail.

不做：

- 不改变 `FED_RECEIPT` frame schema。
- 不要求 receipt frame 携带 requester descriptor。
- 不实现 requester-to-origin Zone binding。
- 不实现 DID document/resolver。
- 不实现 remote trust-store sync。
- 不实现 public reachability proof。
- 不实现 receipt store/search。
- 不实现 batch verifier。
- 不实现 HTTP verifier service。
- 不实现 A2A/ARD compatibility。

## v11.1: FED_TASK_OPEN Requester Zone Binding

状态：complete
目标：Make federated task entry fail closed unless the origin Zone signs the requester identity it forwards.

新增：

- `FED_TASK_OPEN` frames carry `requester_zone_binding`.
- Node `verifyFederatedTaskOpen` rejects missing or mismatched requester Zone bindings.
- Go `Fixture.verifyTaskOpen` rejects missing or mismatched requester Zone bindings whenever `origin_zone` is present.
- Node and Go federation clients emit requester Zone bindings.
- Go queued/drained task state carries the requester Zone binding forward for later verification.
- The shared `FED_TASK_OPEN` conformance vector includes the requester Zone binding.

不做：

- 不实现 DID document/resolver。
- 不实现 remote trust-store sync。
- 不改变 receipt frame requester proof。
- 不实现 public reachability proof。
- 不实现 scheduler-owned routing。
- 不实现 dynamic Swarm decomposition。
- 不实现 A2A/ARD compatibility。

## v11.2: FED_SWARM_CLOSE Structural Close Proof Validation

状态：complete
目标：Make the Node `FED_SWARM_CLOSE` verifier reject signed but structurally empty close proofs.

新增：

- Node `verifySwarmClose` rejects missing or empty `step_receipts`.
- Node `verifySwarmClose` requires each close step to include `step_id`, `task_id`, and a 64-hex `receipt_digest`.
- The Node test proves a trusted Zone signature alone cannot turn an empty close body into a valid close proof.

不做：

- 不实现 Node audit-backed Swarm completeness verification。
- 不验证 step receipts against an audit log。
- 不实现 dynamic Swarm decomposition。
- 不实现 scheduler-owned routing。
- 不实现 parallel or cross-Zone Swarm execution。
- 不实现 public reachability proof。
- 不实现 A2A/ARD compatibility。

## v11.3: Task ID Token Validation

状态：complete
目标：Make unsafe task ids fail closed before execution, queue state, artifact paths, or audit lookups.

新增：

- Node `verifyFederatedTaskOpen` rejects task ids outside `^[A-Za-z0-9._:-]{1,128}$`.
- Go `Fixture.verifyTaskOpen` rejects the same unsafe task ids before execution and queue enqueue/resume/retry/Swarm step execution.
- Go queue claim/reclaim/drain paths reject unsafe task ids before reading or writing queue state.
- Node and Go tests prove path-like task ids such as `../bad/task` are rejected.

不做：

- 不实现 global task-id registry。
- 不实现 UUID migration。
- 不改变 existing valid task ids。
- 不实现 scheduler-owned task namespace。
- 不实现 public reachability proof。
- 不实现 A2A/ARD compatibility。

## v11.4: Receipt Task Digest Binding

状态：complete
目标：Make `FED_RECEIPT` fail closed unless the receipt names the digest of the signed task object it claims to complete.

新增：

- Node local runtime and federation receipts carry `task_digest`.
- Go execution and cancellation receipts carry `task_digest`.
- Node `verifyFederatedReceipt` rejects missing or malformed `task_digest`.
- Go CLI receipt verification and `agnet/verifier.VerifyFederatedReceipt` reject missing or malformed `task_digest`.
- The shared `FED_RECEIPT` conformance vector includes `task_digest`.
- Node and Go tests prove a signed receipt without `task_digest` is rejected.

不做：

- 不存 raw task in every receipt。
- 不实现 receipt store/search。
- 不实现 external task-store lookup against `task_digest`。
- 不验证 `task_digest` against a separately supplied task frame。
- 不实现 scheduler-owned routing。
- 不实现 dynamic Swarm decomposition。
- 不实现 A2A/ARD compatibility。

## v11.5: Optional Receipt Task Evidence Verification

状态：complete
目标：Allow external verifiers to check receipt `task_digest` against a supplied signed task object.

新增：

- Node `verifyFederatedReceipt` accepts optional signed task evidence and rejects digest mismatches.
- `asp-verify.mjs fed-receipt` accepts an optional task JSON file and rejects digest mismatches.
- Go `agnet/verifier.VerifyFederatedReceipt` accepts optional signed task evidence and rejects digest mismatches.
- Node and Go tests prove mismatched supplied task evidence fails closed.

不做：

- 不实现 task store/search。
- 不要求 receipt permanently embed raw task bodies。
- 不改变 existing receipt verification when no task evidence is supplied。
- 不实现 batch verifier。
- 不实现 scheduler-owned routing。
- 不实现 dynamic Swarm decomposition。
- 不实现 A2A/ARD compatibility。

## v11.6: Artifact Closure Task Evidence Parity

状态：complete
目标：Make the Node receipt-plus-artifact verifier enforce the same optional task evidence check as the receipt-only verifier.

新增：

- `asp-verify.mjs fed-receipt-artifacts` accepts an optional task JSON file.
- The artifact-closure verifier rejects supplied task evidence whose digest does not match `receipt.task_digest`.
- The existing local artifact byte and manifest checks remain unchanged.

不做：

- 不实现 task store/search。
- 不实现 batch verifier。
- 不改变 no-task-evidence verification behavior。
- 不改变 artifact byte or manifest verification semantics。
- 不实现 scheduler-owned routing。
- 不实现 dynamic Swarm decomposition。
- 不实现 A2A/ARD compatibility。

## v11.7: Go Receipt CLI Task Evidence

状态：complete
目标：Expose optional supplied-task `task_digest` verification through the Go receipt verifier CLI.

新增：

- `--verify-receipt <receipt.json>` accepts optional `--verify-task <task.json>`.
- Go receipt file verification rejects supplied task evidence whose digest does not match `receipt.task_digest`.
- Existing receipt-only CLI verification remains unchanged when `--verify-task` is absent.

不做：

- 不实现 task store/search。
- 不实现 remote task evidence retrieval。
- 不改变 audit verifier semantics。
- 不实现 batch verifier。
- 不实现 scheduler-owned routing。
- 不实现 dynamic Swarm decomposition。
- 不实现 A2A/ARD compatibility。

## v11.8: Go-to-Node Interop Receipt Task Binding

状态：complete
目标：Make the Go interop client verify Node receipts against the signed task it sent.

新增：

- Go `--interop-request` keeps the signed task object sent to the Node gateway.
- Go interop receipt verification passes that signed task to `agnet/verifier.VerifyFederatedReceipt`.
- Go tests prove mismatched interop task evidence fails closed.

不做：

- 不改变 `FED_TASK_OPEN` frame shape。
- 不实现 task store/search。
- 不实现 remote task evidence retrieval。
- 不实现 new interop protocol objects。
- 不实现 scheduler-owned routing。
- 不实现 dynamic Swarm decomposition。
- 不实现 A2A/ARD compatibility。

## v11.9: Node-to-Go Interop Receipt Task Binding

状态：complete
目标：Make the Node interop client verify Go receipts against the signed task it sent.

新增：

- Node `federation-gateway.mjs request` keeps the signed task object sent to the Go gateway.
- Node interop receipt verification passes that signed task to `verifyFederatedReceipt`.
- Node integration tests prove mismatched interop task evidence fails closed.

不做：

- 不改变 `FED_TASK_OPEN` frame shape。
- 不实现 task store/search。
- 不实现 remote task evidence retrieval。
- 不改变 audit query verification。
- 不实现 scheduler-owned routing。
- 不实现 dynamic Swarm decomposition。
- 不实现 A2A/ARD compatibility。

## v11.10: FED_RECEIPT Frame Type Validation

状态：complete
目标：Make receipt verifiers reject receipt-shaped frames with the wrong protocol type.

新增：

- Node `verifyFederatedReceipt` rejects frames whose `type` is not `FED_RECEIPT`.
- Go `agnet/verifier.VerifyFederatedReceipt` rejects frames whose `type` is not `FED_RECEIPT`.
- Node and Go tests prove a `FED_TASK_OPEN` frame carrying otherwise valid receipt fields fails closed.

不做：

- 不改变 `FED_RECEIPT` frame schema。
- 不实现 receipt store/search。
- 不实现 batch verifier。
- 不改变 interop request semantics。
- 不实现 scheduler-owned routing。
- 不实现 dynamic Swarm decomposition。
- 不实现 A2A/ARD compatibility。

## v11.11: FED_TASK_OPEN Frame Type Validation

状态：complete
目标：Make task-open verifiers reject task-shaped frames with the wrong protocol type.

新增：

- Node `verifyFederatedTaskOpen` rejects frames whose `type` is not `FED_TASK_OPEN`.
- Go `Fixture.verifyTaskOpen` rejects frames whose `type` is not `FED_TASK_OPEN`.
- Go internal queue/resume/retry and Swarm replay callers pass explicit `FED_TASK_OPEN` type when re-validating embedded or stored signed tasks.
- Node and Go tests prove a `FED_RECEIPT` frame carrying otherwise valid task-open fields fails closed.

不做：

- 不改变 `FED_TASK_OPEN` frame schema。
- 不实现 task store/search。
- 不实现 scheduler-owned routing。
- 不实现 dynamic Swarm decomposition。
- 不改变 requester Zone binding semantics。
- 不实现 A2A/ARD compatibility。

## v11.12: FED_SWARM_CLOSE Duplicate Step Validation

状态：complete
目标：Make the Node `FED_SWARM_CLOSE` verifier reject duplicate step receipts.

新增：

- Node `verifySwarmClose` rejects repeated `step_id` values inside one signed close proof.
- The Node test proves a trusted Zone signature cannot make a duplicate-step close proof valid.

不做：

- 不实现 Node audit-backed Swarm completeness verification。
- 不验证 step receipts against an audit log。
- 不实现 dynamic Swarm decomposition。
- 不实现 scheduler-owned routing。
- 不实现 parallel or cross-Zone Swarm execution。
- 不实现 public reachability proof。
- 不实现 A2A/ARD compatibility。

## v11.13: FED_SWARM_CLOSE Swarm Identity Presence

状态：complete
目标：Make the Node `FED_SWARM_CLOSE` verifier reject close proofs without a signed Swarm id.

新增：

- Node `verifySwarmClose` requires the signed close body to include a non-empty `swarm_id`.
- The Node test proves a trusted Zone signature cannot make a close proof valid when Swarm identity is omitted.

不做：

- 不实现 Node audit-backed Swarm completeness verification。
- 不验证 step receipts against an audit log。
- 不实现 dynamic Swarm decomposition。
- 不实现 scheduler-owned routing。
- 不实现 parallel or cross-Zone Swarm execution。
- 不实现 public reachability proof。
- 不实现 A2A/ARD compatibility。

## v11.14: FED_SWARM_CLOSE NUL Identity Validation

状态：complete
目标：Make the Node `FED_SWARM_CLOSE` verifier reject NUL-bearing Swarm identities.

新增：

- Node `verifySwarmClose` rejects signed close `swarm_id` values containing NUL.
- Node `verifySwarmClose` rejects close step `step_id` values containing NUL.
- The Node test proves trusted signed close proofs fail closed for both NUL-bearing identity fields.

不做：

- 不实现 Node audit-backed Swarm completeness verification。
- 不验证 step receipts against an audit log。
- 不实现 dynamic Swarm decomposition。
- 不实现 scheduler-owned routing。
- 不实现 parallel or cross-Zone Swarm execution。
- 不实现 public reachability proof。
- 不实现 A2A/ARD compatibility。

## Next Candidates

1. Add real public reachability proof only with external network evidence, not same-host `0.0.0.0` proof.
2. Continue Phase A trust-boundary bug closure only where the current code still contradicts verified claims.
3. Continue Swarm proof work only where it adds verifiable accountability without dynamic decomposition, scheduler ownership, parallel execution, cross-Zone Swarm, or a Node audit verifier.
4. Keep compatibility work parked until the proof layer has an externally consumable release surface.
