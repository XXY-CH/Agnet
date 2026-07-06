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

## Next Candidates

1. Add real public reachability proof only with external network evidence, not same-host `0.0.0.0` proof.
2. Continue Swarm proof work only where it adds verifiable accountability without dynamic decomposition, scheduler ownership, parallel execution, cross-Zone Swarm, or a Node audit verifier.
3. Keep compatibility work parked until the proof layer has an externally consumable release surface.
