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

## v11.15: FED_SWARM_CLOSE Step Task ID Validation

状态：complete
目标：Make the Node `FED_SWARM_CLOSE` verifier reject unsafe close step task ids.

新增：

- Node `verifySwarmClose` applies the implemented `task_id` token boundary to each close step `task_id`.
- The Node test proves a trusted signed close proof cannot make a path-like step task id valid.
- The portable Swarm close verifier aligns step task identity with the `FED_TASK_OPEN` task id boundary.

不做：

- 不实现 Node audit-backed Swarm completeness verification。
- 不验证 step receipts against an audit log。
- 不实现 dynamic Swarm decomposition。
- 不实现 scheduler-owned routing。
- 不实现 parallel or cross-Zone Swarm execution。
- 不实现 public reachability proof。
- 不实现 A2A/ARD compatibility。

## v11.16: FED_SWARM_CLOSE Close Signature Presence

状态：complete
目标：Make the Node `FED_SWARM_CLOSE` verifier reject missing close signatures with a protocol error.

新增：

- Node `verifySwarmClose` rejects missing or empty `close_signature` before calling the crypto verifier.
- The Node test proves a structurally valid close body without `close_signature` fails with `swarm close signature missing`.
- The portable Swarm close verifier keeps the boundary structural.

不做：

- 不实现 Node audit-backed Swarm completeness verification。
- 不验证 step receipts against an audit log。
- 不实现 dynamic Swarm decomposition。
- 不实现 scheduler-owned routing。
- 不实现 parallel or cross-Zone Swarm execution。
- 不实现 public reachability proof。
- 不实现 A2A/ARD compatibility。

## v11.17: FED_SWARM_CLOSE Close Proof Presence

状态：complete
目标：Make the Node `FED_SWARM_CLOSE` verifier reject missing close proof objects with a protocol error.

新增：

- Node `verifySwarmClose` rejects missing or non-object `close` proof bodies before destructuring verifier fields.
- The Node test proves a trusted `FED_SWARM_CLOSE` frame without `close` fails with `swarm close proof missing`.
- The portable Swarm close verifier keeps the boundary structural.

不做：

- 不实现 JSON Schema validation。
- 不实现 Node audit-backed Swarm completeness verification。
- 不验证 step receipts against an audit log。
- 不实现 dynamic Swarm decomposition。
- 不实现 scheduler-owned routing。
- 不实现 parallel or cross-Zone Swarm execution。
- 不实现 public reachability proof。
- 不实现 A2A/ARD compatibility。

## v11.18: FED_SWARM_CLOSE Signing Zone Presence

状态：complete
目标：Make the Node `FED_SWARM_CLOSE` verifier reject missing signing Zones with a protocol error.

新增：

- Node `verifySwarmClose` rejects missing or non-object `zone` descriptors before calling Zone descriptor verification.
- The Node test proves a trusted `FED_SWARM_CLOSE` body without `zone` fails with `swarm close zone missing`.
- The portable Swarm close verifier keeps the boundary structural.

不做：

- 不实现 generic Zone schema validation。
- 不实现 Node audit-backed Swarm completeness verification。
- 不验证 step receipts against an audit log。
- 不实现 dynamic Swarm decomposition。
- 不实现 scheduler-owned routing。
- 不实现 parallel or cross-Zone Swarm execution。
- 不实现 public reachability proof。
- 不实现 A2A/ARD compatibility。

## v11.19: FED_SWARM_CLOSE Step Receipt Object Presence

状态：complete
目标：Make the Node `FED_SWARM_CLOSE` verifier reject malformed step receipt entries with a protocol error.

新增：

- Node `verifySwarmClose` rejects non-object entries inside signed `step_receipts` before reading step fields.
- The Node test proves a signed close body with `step_receipts: [null]` fails with `swarm close step receipt missing`.
- The portable Swarm close verifier keeps the boundary structural.

不做：

- 不实现 generic Swarm close schema validation。
- 不实现 Node audit-backed Swarm completeness verification。
- 不验证 step receipts against an audit log。
- 不实现 dynamic Swarm decomposition。
- 不实现 scheduler-owned routing。
- 不实现 parallel or cross-Zone Swarm execution。
- 不实现 public reachability proof。
- 不实现 A2A/ARD compatibility。

## v11.20: FED_SWARM_CLOSE Frame Object Presence

状态：complete
目标：Make the Node `FED_SWARM_CLOSE` verifier reject missing frame objects with a protocol error.

新增：

- Node `verifySwarmClose` rejects missing, non-object, or array frame inputs before reading `frame.type`.
- The Node test proves `verifySwarmClose(null, trustedZones)` fails with `expected FED_SWARM_CLOSE frame`.
- The portable Swarm close verifier keeps the boundary structural.

不做：

- 不实现 generic Swarm close schema validation。
- 不实现 Node audit-backed Swarm completeness verification。
- 不验证 step receipts against an audit log。
- 不实现 dynamic Swarm decomposition。
- 不实现 scheduler-owned routing。
- 不实现 parallel or cross-Zone Swarm execution。
- 不实现 public reachability proof。
- 不实现 A2A/ARD compatibility。

## v11.21: FED_TASK_OPEN and FED_RECEIPT Frame Object Presence

状态：complete
目标：Make the Node `FED_TASK_OPEN` and `FED_RECEIPT` verifiers reject missing frame objects with protocol errors.

新增：

- Node `verifyFederatedTaskOpen` rejects missing, non-object, or array frame inputs before reading `frame.type`.
- Node `verifyFederatedReceipt` rejects missing, non-object, or array frame inputs before reading `frame.type`.
- The Node tests prove `null` frame inputs fail with `expected FED_TASK_OPEN frame` or `expected FED_RECEIPT frame`.

不做：

- 不改变 `FED_TASK_OPEN` frame shape。
- 不改变 `FED_RECEIPT` frame shape。
- 不实现 generic frame schema validation。
- 不改变 Go verifier behavior。
- 不实现 task or receipt store/search。
- 不实现 batch verifier。
- 不实现 scheduler-owned routing。
- 不实现 dynamic Swarm decomposition。
- 不实现 A2A/ARD compatibility。

## v11.22: FED_TASK_OPEN and FED_RECEIPT Zone Descriptor Presence

状态：complete
目标：Make the Node `FED_TASK_OPEN` and `FED_RECEIPT` verifiers reject missing Zone descriptor objects with protocol errors.

新增：

- Node `verifyFederatedTaskOpen` rejects missing, non-object, or array `origin_zone` values before calling Zone descriptor verification.
- Node `verifyFederatedReceipt` rejects missing, non-object, or array signing `zone` values before calling Zone descriptor verification.
- The Node tests prove missing Zone descriptor objects fail with `task open origin zone missing` or `receipt zone missing`.

不做：

- 不实现 generic Zone schema validation。
- 不改变 `FED_TASK_OPEN` frame shape。
- 不改变 `FED_RECEIPT` frame shape。
- 不改变 Go verifier behavior。
- 不实现 remote Zone resolution。
- 不实现 task or receipt store/search。
- 不实现 scheduler-owned routing。
- 不实现 dynamic Swarm decomposition。
- 不实现 A2A/ARD compatibility。

## v11.23: FED_TASK_OPEN and FED_RECEIPT Payload Object Presence

状态：complete
目标：Make the Node `FED_TASK_OPEN` and `FED_RECEIPT` verifiers reject missing payload objects with protocol errors.

新增：

- Node `verifyFederatedTaskOpen` rejects missing, non-object, or array `requester` values before reading requester descriptor fields.
- Node `verifyFederatedTaskOpen` rejects missing, non-object, or array `task` values before reading the signed task body.
- Node `verifyFederatedReceipt` rejects missing, non-object, or array `worker` values before reading worker descriptor fields.
- Node `verifyFederatedReceipt` rejects missing, non-object, or array `receipt` values before reading the signed receipt body.
- The Node tests prove missing payload objects fail with `task open requester missing`, `task open task missing`, `receipt worker missing`, or `receipt body missing`.

不做：

- 不实现 generic payload schema validation。
- 不改变 `FED_TASK_OPEN` frame shape。
- 不改变 `FED_RECEIPT` frame shape。
- 不改变 Go verifier behavior。
- 不实现 task or receipt store/search。
- 不实现 scheduler-owned routing。
- 不实现 dynamic Swarm decomposition。
- 不实现 A2A/ARD compatibility。

## v11.24: Node Trusted Zone Store Presence

状态：complete
目标：Make Node task, receipt, and Swarm close verifiers reject missing trusted Zone stores with protocol-shaped errors.

新增：

- Node `verifyFederatedTaskOpen` rejects missing or non-Map-like trusted Zone stores before reading origin trust entries.
- Node `verifyFederatedReceipt` rejects missing or non-Map-like trusted Zone stores before reading signing or origin trust entries.
- Node `verifySwarmClose` rejects missing or non-Map-like trusted Zone stores before reading signing trust entries.
- The Node tests prove missing trusted Zone stores fail with `trusted zones missing`, not JavaScript `TypeError`.

不做：

- 不实现 generic trust-store schema validation。
- 不实现 remote trust-store sync。
- 不改变 trusted Zone file format。
- 不改变 Go verifier behavior。
- 不实现 DID document/resolver。
- 不实现 scheduler-owned routing。
- 不实现 dynamic Swarm decomposition。
- 不实现 A2A/ARD compatibility。

## v11.25: FED_TASK_OPEN Worker Context Presence

状态：complete
目标：Make Node `FED_TASK_OPEN` verification reject missing local worker descriptor context with a protocol-shaped error.

新增：

- Node `verifyFederatedTaskOpen` rejects missing, non-object, or array local worker descriptor context before reading `workerDescriptor.alias`.
- The Node tests prove missing worker descriptor context fails with `task open worker missing`, not JavaScript `TypeError` or a misleading target-alias mismatch.

不做：

- 不实现 generic worker descriptor schema validation。
- 不改变 `FED_TASK_OPEN` frame shape。
- 不改变 Go verifier behavior。
- 不实现 worker registry/store。
- 不实现 scheduler-owned routing。
- 不实现 dynamic Swarm decomposition。
- 不实现 A2A/ARD compatibility。

## v11.26: FED_TASK_OPEN and FED_RECEIPT Signature Presence

状态：complete
目标：Make Node task and receipt verification reject missing signed task/receipt signatures with protocol-shaped errors.

新增：

- Node `verifyFederatedTaskOpen` rejects missing, empty, or non-string task signatures before calling crypto verification.
- Node `verifyFederatedReceipt` rejects missing, empty, or non-string receipt signatures before calling crypto verification.
- The Node tests prove missing signed task/receipt signatures fail with `task signature missing` or `receipt signature missing`, not JavaScript `TypeError`.

不做：

- 不实现 generic task or receipt schema validation。
- 不改变 `FED_TASK_OPEN` frame shape。
- 不改变 `FED_RECEIPT` frame shape。
- 不改变 Go verifier behavior。
- 不实现 task or receipt store/search。
- 不实现 scheduler-owned routing。
- 不实现 dynamic Swarm decomposition。
- 不实现 A2A/ARD compatibility。

## v11.27: FED_TASK_OPEN Worker Descriptor Identity

状态：complete
目标：Make Node `FED_TASK_OPEN` verification validate local worker descriptor identity before target and policy checks.

新增：

- Node `verifyFederatedTaskOpen` resolves the local worker descriptor through the existing descriptor verifier before using worker alias or policy.
- Node `verifyFederatedTaskOpen` rejects malformed local worker descriptors with `task open worker invalid`.
- The Node tests prove missing worker public-key material or tampered worker Agent IDs no longer pass merely because the alias matches.

不做：

- 不实现 generic worker descriptor schema validation。
- 不实现 worker registry/store。
- 不改变 `FED_TASK_OPEN` frame shape。
- 不改变 Go verifier behavior。
- 不实现 scheduler-owned routing。
- 不实现 dynamic Swarm decomposition。
- 不实现 A2A/ARD compatibility。

## v11.28: FED_RECEIPT Worker Descriptor Identity

状态：complete
目标：Make Node `FED_RECEIPT` verification validate worker descriptor identity before receipt identity and signature checks.

新增：

- Node `verifyFederatedReceipt` resolves the receipt worker descriptor through the existing descriptor verifier before using the worker Agent ID or public key.
- Node `verifyFederatedReceipt` rejects malformed worker descriptors with `receipt worker invalid`.
- The Node conformance tests prove missing worker public-key material or tampered worker Agent IDs no longer leak low-level descriptor errors or JavaScript `TypeError` failures.

不做：

- 不实现 generic receipt schema validation。
- 不实现 worker registry/store。
- 不改变 `FED_RECEIPT` frame shape。
- 不改变 Go verifier behavior。
- 不实现 scheduler-owned routing。
- 不实现 dynamic Swarm decomposition。
- 不实现 A2A/ARD compatibility。

## v11.29: Node Descriptor Public Key Presence

状态：complete
目标：Make Node descriptor public key parsing reject missing `public_key_spki` before Node crypto parsing.

新增：

- Node `publicKeyFromDescriptor` rejects missing, empty, or non-string `public_key_spki` with `descriptor public key missing`.
- The shared descriptor parser test proves missing descriptor public keys no longer leak JavaScript `TypeError` failures.
- Because task-open, receipt, Zone, and Swarm verification route through the same helper, malformed descriptor public keys now fail closed at the shared root.

不做：

- 不实现 generic descriptor schema validation。
- 不改变 descriptor shape。
- 不改变 Go verifier behavior。
- 不实现 registry ownership changes。
- 不实现 scheduler-owned routing。
- 不实现 dynamic Swarm decomposition。
- 不实现 A2A/ARD compatibility。

## v11.30: Node Object Signature Fail-Closed Verification

状态：complete
目标：Make Node shared object signature verification reject missing, empty, or non-string signatures before Node crypto parsing.

新增：

- Node `verifyObject` returns `false` for missing, empty, or non-string signatures before calling Node crypto.
- The shared verifier test proves missing object signatures no longer leak JavaScript `TypeError` failures.
- Because Zone descriptors, Zone bindings, rotation proofs, capability credentials, credential status records, task receipts, and Swarm close proofs route through the same helper, malformed signatures now fail closed at the shared root.

不做：

- 不实现 generic signature schema validation。
- 不改变 signed object shapes。
- 不改变 Go verifier behavior。
- 不新增 per-verifier guards。
- 不实现 registry ownership changes。
- 不实现 scheduler-owned routing。
- 不实现 dynamic Swarm decomposition。
- 不实现 A2A/ARD compatibility。

## v11.31: Node Zone Descriptor Object Presence

状态：complete
目标：Make Node Zone descriptor verification reject missing or non-object descriptors before descriptor field reads.

新增：

- Node `verifyZoneDescriptor` rejects missing, array, or otherwise non-object Zone descriptor values with `zone descriptor missing`.
- `loadTrustedZones` inherits the same fail-closed behavior because it verifies every stored Zone descriptor through `verifyZoneDescriptor`.
- The trusted Zone test proves malformed trusted-Zone entries no longer leak JavaScript `TypeError` failures.

不做：

- 不实现 generic Zone schema validation。
- 不改变 Zone descriptor shape。
- 不改变 trust-store file shape。
- 不改变 Go verifier behavior。
- 不新增 per-caller guards。
- 不实现 registry ownership changes。
- 不实现 scheduler-owned routing。
- 不实现 dynamic Swarm decomposition。
- 不实现 A2A/ARD compatibility。

## v11.32: Node did:key Input Presence

状态：complete
目标：Make Node `did:key` bridge helpers reject missing descriptor/public-key and DID string inputs before field reads or parsing.

新增：

- Node `didKeyFromPublicKeySPKI` rejects missing, empty, or non-string public key values with `expected ed25519 public_key_spki`.
- Node `didKeyFromDescriptor` routes missing descriptor/public key values through the same public-key bridge guard.
- Node `publicKeySPKIFromDidKey` rejects missing or non-string DID values with `expected did:key z-base58btc value`.
- The test vector suite proves malformed bridge inputs no longer leak JavaScript or Node `TypeError` failures.

不做：

- 不实现 DID-native resolver。
- 不改变 descriptor shape。
- 不改变 `aid:` identity semantics。
- 不实现 generic descriptor schema validation。
- 不改变 Go verifier behavior。
- 不实现 registry ownership changes。
- 不实现 scheduler-owned routing。
- 不实现 dynamic Swarm decomposition。
- 不实现 A2A/ARD compatibility。

## v11.33: Node Artifact Manifest Object Presence

状态：complete
目标：Make Node artifact manifest verification reject missing receipt or manifest objects before field reads.

新增：

- Node `verifyReceiptArtifactManifests` rejects missing or non-object receipt wrappers before reading `artifact_manifests`.
- Node `verifyReceiptArtifactManifests` rejects missing, array, or otherwise non-object manifest entries with `artifact manifest missing`.
- Node `verifyLocalArtifact` rejects missing, array, or otherwise non-object manifest inputs before reading `uri`.
- The focused tests prove malformed artifact manifest inputs no longer leak JavaScript `TypeError` failures.

不做：

- 不改变 artifact manifest schema。
- 不实现 generic artifact schema validation。
- 不改变 receipt frame shape。
- 不改变 Go verifier behavior。
- 不实现 object-store artifact backend。
- 不实现 retention policy。
- 不实现 scheduler-owned routing。
- 不实现 dynamic Swarm decomposition。
- 不实现 A2A/ARD compatibility。

## v11.34: Node Credential Object Presence

状态：complete
目标：Make Node capability credential and credential status helpers reject missing proof objects before field reads.

新增：

- Node `verifyCapabilityCredential` returns `false` for missing, array, or otherwise non-object credential inputs before reading `capability`.
- Node `capabilityCredentialId` rejects missing, array, or otherwise non-object credential inputs with `credential missing`.
- Node `verifyCredentialStatus` returns `false` for missing, array, or otherwise non-object status or credential inputs before reading proof fields.
- The focused credential tests prove malformed credential/status inputs no longer leak JavaScript `TypeError` failures.

不做：

- 不改变 capability credential schema。
- 不实现 generic credential schema validation。
- 不改变 credential status shape。
- 不改变 Go verifier behavior。
- 不实现 revocation feed sync。
- 不实现 credential renewal。
- 不实现 scheduler-owned routing。
- 不实现 dynamic Swarm decomposition。
- 不实现 A2A/ARD compatibility。

## v11.35: Node Rotation Proof Object Presence

状态：complete
目标：Make Node rotation and alias rebinding proof verifiers reject missing proof and descriptor objects before field reads.

新增：

- Node `verifyRotationProof` returns `false` for missing, array, or otherwise non-object proof, previous descriptor, or next descriptor inputs.
- Node `verifyAliasRebindingProof` returns `false` for missing, array, or otherwise non-object proof, previous descriptor, or next descriptor inputs.
- The focused identity proof tests prove malformed rotation/rebinding inputs no longer leak JavaScript `TypeError` failures.

不做：

- 不改变 rotation proof schema。
- 不改变 alias rebinding proof schema。
- 不实现 generic identity proof schema validation。
- 不改变 Go verifier behavior。
- 不实现 registry ownership changes。
- 不实现 alias lifecycle API。
- 不实现 scheduler-owned routing。
- 不实现 dynamic Swarm decomposition。
- 不实现 A2A/ARD compatibility。

## v11.36: Node Zone Binding Object Presence

状态：complete
目标：Make Node Zone binding verification reject missing binding context and descriptor objects before field reads.

新增：

- Node `verifyZoneBinding` rejects missing, array, or otherwise non-object entry/context inputs with `zone binding context missing`.
- Node `verifyZoneBinding` rejects missing, array, or otherwise non-object descriptor inputs with `zone binding descriptor missing`.
- The focused Zone tests prove malformed binding context inputs no longer leak JavaScript `TypeError` failures.

不做：

- 不改变 Zone binding schema。
- 不改变 registry ownership behavior。
- 不改变 revocation verification semantics。
- 不实现 generic registry schema validation。
- 不改变 Go verifier behavior。
- 不实现 Zone lifecycle API。
- 不实现 scheduler-owned routing。
- 不实现 dynamic Swarm decomposition。
- 不实现 A2A/ARD compatibility。

## v11.37: Node Zone Revocation Object Presence

状态：complete
目标：Make Node Zone revocation verification reject missing revocation context and descriptor objects before field reads.

新增：

- Node `verifyZoneRevocation` returns `false` for missing, array, or otherwise non-object revocation inputs.
- Node `verifyNotRevoked` rejects missing, array, or otherwise non-object entry/context inputs with `zone revocation context missing`.
- Node `verifyNotRevoked` rejects missing, array, or otherwise non-object descriptor inputs with `zone revocation descriptor missing`.
- Node `verifyNotRevoked` rejects missing revocation-list inputs with `zone revocations missing`.
- The focused revocation tests prove malformed revocation context inputs no longer leak JavaScript `TypeError` failures.

不做：

- 不改变 Zone revocation schema。
- 不改变 revocation verification semantics。
- 不实现 revocation feed sync。
- 不实现 Zone lifecycle API。
- 不实现 generic registry schema validation。
- 不改变 Go verifier behavior。
- 不实现 scheduler-owned routing。
- 不实现 dynamic Swarm decomposition。
- 不实现 A2A/ARD compatibility。

## v11.38: Node Trusted Zone File Shape

状态：complete
目标：Make Node trusted Zone file loading reject missing Zone lists before entry iteration while preserving raw descriptor-array inputs.

新增：

- Node `loadTrustedZones` accepts the documented raw descriptor-array trusted Zone file shape.
- Node `loadTrustedZones` rejects missing or non-array trusted Zone lists with `trusted zone list missing`.
- The focused trusted Zone tests prove missing lists no longer leak JavaScript `TypeError` failures.

不做：

- 不实现 generic trusted Zone file schema validation。
- 不改变 trusted Zone descriptor verification。
- 不实现 remote trust-store sync。
- 不改变 Go verifier behavior。
- 不实现 DID document/resolver。
- 不实现 scheduler-owned routing。
- 不实现 dynamic Swarm decomposition。
- 不实现 A2A/ARD compatibility。

## v11.39: Node Registry File Shape

状态：complete
目标：Make Node registry file loading reject missing agent lists, entries, and descriptors before registry field reads.

新增：

- Node `loadRegistry` rejects missing non-array `agents` lists with `registry agents missing`.
- Node `loadRegistry` rejects missing, array, or otherwise non-object registry entries with `registry entry missing`.
- Node `loadRegistry` rejects missing, array, or otherwise non-object descriptors in both object-shaped and raw-array registries with `registry descriptor missing`.
- The focused registry tests prove malformed registry files no longer leak JavaScript `TypeError` failures.

不做：

- 不实现 generic registry schema validation。
- 不改变 registry ownership behavior。
- 不实现 registry lifecycle APIs。
- 不改变 alias resolution semantics。
- 不改变 Go verifier behavior。
- 不实现 scheduler-owned routing。
- 不实现 dynamic Swarm decomposition。
- 不实现 A2A/ARD compatibility。

## v11.40: Node resolveAgent Registry Context

状态：complete
目标：Make Node agent resolution reject missing registry context before entry lookup.

新增：

- Node `resolveAgent` rejects missing or non-Map-like registry contexts with `registry missing`.
- The focused registry tests prove missing registry context no longer leaks JavaScript `TypeError` failures.

不做：

- 不改变 alias resolution semantics。
- 不改变 registry file shape。
- 不实现 registry ownership behavior。
- 不实现 registry lifecycle APIs。
- 不实现 generic registry schema validation。
- 不改变 Go verifier behavior。
- 不实现 scheduler-owned routing。
- 不实现 dynamic Swarm decomposition。
- 不实现 A2A/ARD compatibility。

## v11.41: Node Descriptor Body Object Presence

状态：complete
目标：Make Node descriptor body helpers reject missing descriptor objects before removing signature fields.

新增：

- Node `descriptorBody` rejects missing, array, or otherwise non-object descriptors with `descriptor missing`.
- Node `zoneDescriptorBody` rejects missing, array, or otherwise non-object Zone descriptors with `zone descriptor missing`.
- The focused descriptor tests prove missing descriptor body inputs no longer leak JavaScript `TypeError` failures or silently canonicalize arrays as empty objects.

不做：

- 不实现 generic descriptor schema validation。
- 不改变 descriptor signature semantics。
- 不改变 Zone descriptor signature semantics。
- 不改变 identity resolution semantics。
- 不改变 registry ownership behavior。
- 不实现 registry lifecycle APIs。
- 不改变 Go verifier behavior。
- 不实现 scheduler-owned routing。
- 不实现 dynamic Swarm decomposition。
- 不实现 A2A/ARD compatibility。

## v11.42: Node Proof Verifier Malformed Descriptor Fail-Closed

状态：complete
目标：Make Node boolean proof verifiers return false for malformed descriptor inputs instead of leaking parser errors.

新增：

- Node `verifyRotationProof` returns `false` when previous or next descriptor objects are malformed enough to fail public-key parsing or descriptor-body checks.
- Node `verifyAliasRebindingProof` returns `false` when previous or next descriptor objects cannot form a valid alias rebinding body.
- Node `verifyCapabilityCredential` returns `false` for malformed authority or subject descriptor inputs.
- Node `verifyCredentialStatus` returns `false` for malformed authority descriptor inputs.
- Focused proof tests prove these boolean verifiers fail closed instead of throwing `descriptor public key missing`, `zone descriptor missing`, or alias-body parser errors.

不做：

- 不实现 generic descriptor schema validation。
- 不改变 descriptor signature semantics。
- 不改变 Zone descriptor signature semantics。
- 不改变 rotation, alias rebinding, credential, or credential-status proof schemas。
- 不改变 identity resolution semantics。
- 不改变 registry ownership behavior。
- 不实现 registry lifecycle APIs。
- 不改变 Go verifier behavior。
- 不实现 scheduler-owned routing。
- 不实现 dynamic Swarm decomposition。
- 不实现 A2A/ARD compatibility。

## v11.43: Node Local Artifact URI Boundary

状态：complete
目标：Make Node local artifact verification reject missing or non-local artifact URIs before filesystem reads.

新增：

- Node `verifyLocalArtifact` rejects missing manifest `uri` values with `artifact uri invalid`.
- Node `verifyLocalArtifact` rejects manifest URIs outside the implemented `artifact://local/` namespace before sidecar or byte reads.
- The focused MVP artifact verifier test proves malformed local artifact URIs no longer leak JavaScript `TypeError` failures or drift into arbitrary filesystem paths before local URI validation.

不做：

- 不改变 artifact manifest metadata schema。
- 不改变 receipt artifact manifest comparison semantics。
- 不实现 remote artifact fetch。
- 不实现 object-store artifact backend。
- 不实现 artifact retention policy。
- 不改变 Go verifier behavior。
- 不实现 scheduler-owned routing。
- 不实现 dynamic Swarm decomposition。
- 不实现 A2A/ARD compatibility。

## v11.44: Node Local Artifact Path Boundary

状态：complete
目标：Make Node local artifact URI-to-path mapping reject escaping or malformed local path segments before filesystem reads or writes.

新增：

- Node local artifact path mapping rejects `artifact://local/` URIs with empty, `.`, `..`, empty-segment, or backslash path segments with `artifact uri invalid`.
- Node `writeArtifact` and `verifyLocalArtifact` share the same local URI-to-path validation.
- The focused MVP artifact verifier test proves `artifact://local/../evil.md` fails before sidecar or byte reads.

不做：

- 不改变 artifact manifest metadata schema。
- 不改变 receipt artifact manifest comparison semantics。
- 不实现 remote artifact fetch。
- 不实现 object-store artifact backend。
- 不实现 artifact retention policy。
- 不改变 Go verifier behavior。
- 不实现 scheduler-owned routing。
- 不实现 dynamic Swarm decomposition。
- 不实现 A2A/ARD compatibility。

## v11.45: Go Artifact Digest Path Boundary

状态：complete
目标：Make Go audit artifact verification reject malformed manifest SHA-256 values before constructing digest-addressed sidecar or mirror paths.

新增：

- Go `verifyArtifactManifests` rejects non-64-hex manifest `sha256` values with `artifact manifest sha256 invalid`.
- The check runs before reading `artifacts/by-sha256/<sha>.manifest.json` or optional mirror paths under `--artifact-store`.
- The focused Go test proves `sha256: "../evil"` no longer reaches a digest-addressed filesystem path.

不做：

- 不改变 artifact manifest metadata schema。
- 不改变 receipt artifact manifest comparison semantics。
- 不实现 remote artifact fetch。
- 不实现 object-store artifact backend。
- 不实现 artifact retention policy。
- 不改变 Node verifier behavior。
- 不改变 Go reusable receipt verifier package behavior。
- 不实现 scheduler-owned routing。
- 不实现 dynamic Swarm decomposition。
- 不实现 A2A/ARD compatibility。

## v11.46: Receipt Artifact Digest Shape Boundary

状态：complete
目标：Make Node and Go reusable receipt verifiers reject malformed artifact manifest SHA-256 values before accepting signed artifact metadata.

新增：

- Node `verifyReceiptArtifactManifests` rejects non-64-hex manifest `sha256` values with `artifact manifest sha256 invalid`.
- Go `verifier.verifyReceiptArtifactManifests` rejects the same malformed manifest `sha256` values.
- Focused Node and Go tests prove signed receipt metadata using `sha256: "../evil"` is rejected even when `afp` and `manifest_hash` are recomputed around the malformed value.

不做：

- 不改变 artifact manifest metadata schema。
- 不实现 generic JSON Schema validation。
- 不改变 receipt artifact manifest comparison semantics。
- 不实现 remote artifact fetch。
- 不实现 object-store artifact backend。
- 不实现 artifact retention policy。
- 不改变 Go audit digest path behavior beyond v11.45。
- 不实现 scheduler-owned routing。
- 不实现 dynamic Swarm decomposition。
- 不实现 A2A/ARD compatibility。

## v11.47: Receipt Artifact Size Shape Boundary

状态：complete
目标：Make Node and Go receipt/audit artifact verifiers reject negative or fractional artifact manifest sizes before accepting signed artifact metadata.

新增：

- Node `verifyReceiptArtifactManifests` rejects negative or non-integer manifest `size` values with `artifact manifest size invalid`.
- Go `verifier.verifyReceiptArtifactManifests` rejects the same malformed manifest `size` values.
- Go `verifyArtifactManifests` rejects malformed manifest `size` values before local byte and sidecar comparison.
- Focused Node and Go tests prove signed receipt metadata using `size: -1` or `size: 1.5` is rejected even when `manifest_hash` is recomputed around the malformed value.

不做：

- 不改变 artifact manifest metadata schema。
- 不实现 generic JSON Schema validation。
- 不改变 receipt artifact manifest comparison semantics。
- 不实现 remote artifact fetch。
- 不实现 object-store artifact backend。
- 不实现 artifact retention policy。
- 不实现 scheduler-owned routing。
- 不实现 dynamic Swarm decomposition。
- 不实现 A2A/ARD compatibility。

## v11.48: Go Receipt Artifact Media Type Shape Boundary

状态：complete
目标：Make Go receipt/audit artifact verifiers reject non-string artifact manifest media types before accepting signed artifact metadata.

新增：

- Go `verifier.verifyReceiptArtifactManifests` rejects non-string manifest `media_type` values with `artifact manifest media_type invalid`.
- Go `verifyArtifactManifests` rejects non-string manifest `media_type` values before local byte and sidecar comparison.
- Focused Go tests prove signed receipt metadata using `media_type: {"type":"text/plain"}` is rejected even when `manifest_hash` is recomputed around the malformed value.
- Node already had the equivalent string-field guard in `verifyReceiptArtifactManifests`, so no Node behavior change was needed.

不做：

- 不改变 artifact manifest metadata schema。
- 不实现 generic JSON Schema validation。
- 不改变 receipt artifact manifest comparison semantics。
- 不实现 remote artifact fetch。
- 不实现 object-store artifact backend。
- 不实现 artifact retention policy。
- 不实现 scheduler-owned routing。
- 不实现 dynamic Swarm decomposition。
- 不实现 A2A/ARD compatibility。

## v11.49: Go Receipt Artifact Manifest Hash Shape Boundary

状态：complete
目标：Make Go receipt/audit artifact verifiers reject non-string artifact manifest hashes before accepting signed artifact metadata.

新增：

- Go `verifier.verifyReceiptArtifactManifests` rejects non-string manifest `manifest_hash` values with `artifact manifest manifest_hash invalid`.
- Go `verifyArtifactManifests` rejects non-string manifest `manifest_hash` values before local byte and sidecar comparison.
- Focused Go tests prove signed receipt metadata using `manifest_hash: {"hash":"..."}` is rejected before it falls through to generic hash or sidecar mismatch errors.
- Node already had the equivalent string-field guard in `verifyReceiptArtifactManifests`, so no Node behavior change was needed.

不做：

- 不改变 artifact manifest metadata schema。
- 不实现 generic JSON Schema validation。
- 不改变 receipt artifact manifest comparison semantics。
- 不实现 remote artifact fetch。
- 不实现 object-store artifact backend。
- 不实现 artifact retention policy。
- 不实现 scheduler-owned routing。
- 不实现 dynamic Swarm decomposition。
- 不实现 A2A/ARD compatibility。

## v11.50: Go Artifact List Shape Boundary

状态：complete
目标：Make Go receipt/audit artifact verifiers reject malformed artifact ref and manifest list entries instead of filtering them.

新增：

- Go reusable receipt verification rejects non-string `artifact_refs` entries with `artifact refs invalid`.
- Go audit artifact verification rejects non-object `artifact_manifests` entries with `artifact manifest missing`.
- Focused Go tests prove malformed extra list entries are no longer silently filtered out before artifact manifest verification.
- The fix is scoped to artifact verifier parsing; broad `stringsFromAny` / `mapsFromAny` helper behavior remains unchanged for UI and policy read paths.

不做：

- 不改变 artifact manifest metadata schema。
- 不实现 generic JSON Schema validation。
- 不改变 receipt artifact manifest comparison semantics。
- 不实现 remote artifact fetch。
- 不实现 object-store artifact backend。
- 不实现 artifact retention policy。
- 不实现 scheduler-owned routing。
- 不实现 dynamic Swarm decomposition。
- 不实现 A2A/ARD compatibility。

## v11.51: Go Artifact Mirror Index Shape Boundary

状态：complete
目标：Make Go filesystem artifact mirror index matching require exact manifest field values and types instead of string-coerced equality.

新增：

- Go mirror index matching now compares `objects.ndjson` entries to receipt artifact manifests without `fmt.Sprint` coercion.
- Focused Go test proves a mirror index entry with `size: "7"` no longer matches a manifest with numeric `size: 7`.
- The fix is scoped to artifact-store index proof matching; artifact manifest metadata, local byte checks, mirror bytes, and sidecar verification stay unchanged.

不做：

- 不改变 artifact manifest metadata schema。
- 不实现 generic JSON Schema validation。
- 不改变 receipt artifact manifest comparison semantics。
- 不实现 remote artifact fetch。
- 不实现 object-store artifact backend。
- 不实现 artifact retention policy。
- 不实现 scheduler-owned routing。
- 不实现 dynamic Swarm decomposition。
- 不实现 A2A/ARD compatibility。

## v11.52: Go Artifact Mirror Index Entry Boundary

状态：complete
目标：Make Go filesystem artifact mirror index readers reject non-object `objects.ndjson` entries instead of preserving malformed rows.

新增：

- Go `readArtifactStoreIndex` rejects `null` index rows with `artifact mirror index invalid`.
- Focused Go test proves `objects.ndjson` containing `null` no longer reads as a valid nil map entry.
- The fix is scoped to index row object presence; exact field matching remains owned by v11.51.

不做：

- 不改变 artifact manifest metadata schema。
- 不实现 generic JSON Schema validation。
- 不改变 receipt artifact manifest comparison semantics。
- 不实现 remote artifact fetch。
- 不实现 object-store artifact backend。
- 不实现 artifact retention policy。
- 不实现 scheduler-owned routing。
- 不实现 dynamic Swarm decomposition。
- 不实现 A2A/ARD compatibility。

## v11.53: Go Artifact Mirror Index Digest Boundary

状态：complete
目标：Make Go filesystem artifact mirror index readers reject unsafe `sha256` values before they can feed mirror or GC paths.

新增：

- Go `readArtifactStoreIndex` rejects present-but-malformed `sha256` fields with `artifact mirror index invalid`.
- Focused Go test proves an index row with `sha256: "../evil"` no longer reads as a valid orphan/index row.
- The fix is scoped to the path-bearing digest field; it does not add full mirror index schema validation.

不做：

- 不改变 artifact manifest metadata schema。
- 不实现 generic JSON Schema validation。
- 不改变 receipt artifact manifest comparison semantics。
- 不实现 remote artifact fetch。
- 不实现 object-store artifact backend。
- 不实现 artifact retention policy。
- 不实现 scheduler-owned routing。
- 不实现 dynamic Swarm decomposition。
- 不实现 A2A/ARD compatibility。

## v11.54: Go Artifact Mirror Index Digest Presence Boundary

状态：complete
目标：Make Go filesystem artifact mirror index readers reject rows that omit the path-bearing `sha256` field.

新增：

- Go `readArtifactStoreIndex` rejects missing `sha256` fields with `artifact mirror index invalid`.
- Focused Go test proves an index row without `sha256` no longer reads as a valid orphan/index row.
- The fix completes the mirror index digest input boundary without adding full mirror index schema validation.

不做：

- 不改变 artifact manifest metadata schema。
- 不实现 generic JSON Schema validation。
- 不改变 receipt artifact manifest comparison semantics。
- 不实现 remote artifact fetch。
- 不实现 object-store artifact backend。
- 不实现 artifact retention policy。
- 不实现 scheduler-owned routing。
- 不实现 dynamic Swarm decomposition。
- 不实现 A2A/ARD compatibility。

## v11.55: Go Artifact Mirror Index Manifest Hash Boundary

状态：complete
目标：Make Go filesystem artifact mirror index readers reject present malformed `manifest_hash` proof metadata.

新增：

- Go `readArtifactStoreIndex` rejects present-but-malformed `manifest_hash` fields with `artifact mirror index invalid`.
- Focused Go test proves an index row with `manifest_hash: "../evil"` no longer reads as a valid orphan/index row.
- The fix is scoped to digest-shaped proof metadata already present in mirror index rows; it does not make `manifest_hash` required and does not add full mirror index schema validation.

不做：

- 不改变 artifact manifest metadata schema。
- 不实现 generic JSON Schema validation。
- 不改变 receipt artifact manifest comparison semantics。
- 不实现 remote artifact fetch。
- 不实现 object-store artifact backend。
- 不实现 artifact retention policy。
- 不实现 scheduler-owned routing。
- 不实现 dynamic Swarm decomposition。
- 不实现 A2A/ARD compatibility。

## v11.56: Go Artifact Mirror Index AFP Boundary

状态：complete
目标：Make Go filesystem artifact mirror index readers reject present AFP strings that do not match the row SHA-256.

新增：

- Go `readArtifactStoreIndex` rejects present `afp` fields that are not exactly `afp:sha256:<sha256>` for the same row.
- Focused Go test proves an index row with a valid `sha256` but mismatched AFP no longer reads as a valid orphan/index row.
- The fix is scoped to proof metadata consistency already present in mirror index rows; it does not make `afp` required and does not add full mirror index schema validation.

不做：

- 不改变 artifact manifest metadata schema。
- 不实现 generic JSON Schema validation。
- 不改变 receipt artifact manifest comparison semantics。
- 不实现 remote artifact fetch。
- 不实现 object-store artifact backend。
- 不实现 artifact retention policy。
- 不实现 scheduler-owned routing。
- 不实现 dynamic Swarm decomposition。
- 不实现 A2A/ARD compatibility。

## v11.57: Go Artifact Mirror Index Size Boundary

状态：complete
目标：Make Go filesystem artifact mirror index readers reject present sizes that are not non-negative integers.

新增：

- Go `readArtifactStoreIndex` rejects present `size` fields that are strings, negative numbers, or fractional numbers with `artifact mirror index invalid`.
- Focused Go test proves index rows with `size: "7"`, `size: -1`, or `size: 1.5` no longer read as valid orphan/index rows.
- The fix is scoped to proof metadata shape already present in mirror index rows; it does not make `size` required and does not add full mirror index schema validation.

不做：

- 不改变 artifact manifest metadata schema。
- 不实现 generic JSON Schema validation。
- 不改变 receipt artifact manifest comparison semantics。
- 不实现 remote artifact fetch。
- 不实现 object-store artifact backend。
- 不实现 artifact retention policy。
- 不实现 scheduler-owned routing。
- 不实现 dynamic Swarm decomposition。
- 不实现 A2A/ARD compatibility。

## v11.58: Go Artifact Mirror Index Media Type Boundary

状态：complete
目标：Make Go filesystem artifact mirror index readers reject present media types that are not strings.

新增：

- Go `readArtifactStoreIndex` rejects present `media_type` fields that are not strings with `artifact mirror index invalid`.
- Focused Go test proves an index row with `media_type: {"type":"text/plain"}` no longer reads as a valid orphan/index row.
- The fix is scoped to proof metadata shape already present in mirror index rows; it does not make `media_type` required and does not add full mirror index schema validation.

不做：

- 不改变 artifact manifest metadata schema。
- 不实现 generic JSON Schema validation。
- 不改变 receipt artifact manifest comparison semantics。
- 不实现 remote artifact fetch。
- 不实现 object-store artifact backend。
- 不实现 artifact retention policy。
- 不实现 scheduler-owned routing。
- 不实现 dynamic Swarm decomposition。
- 不实现 A2A/ARD compatibility。

## v11.59: Go Artifact Mirror Index URI Boundary

状态：complete
目标：Make Go filesystem artifact mirror index readers reject present URIs that are not strings.

新增：

- Go `readArtifactStoreIndex` rejects present `uri` fields that are not strings with `artifact mirror index invalid`.
- Focused Go test proves an index row with `uri: {"path":"artifact://local/out.md"}` no longer reads as a valid orphan/index row.
- The fix is scoped to proof metadata shape already present in mirror index rows; it does not make `uri` required and does not add URI namespace/path validation or full mirror index schema validation.

不做：

- 不改变 artifact manifest metadata schema。
- 不实现 generic JSON Schema validation。
- 不改变 receipt artifact manifest comparison semantics。
- 不实现 remote artifact fetch。
- 不实现 object-store artifact backend。
- 不实现 artifact retention policy。
- 不实现 scheduler-owned routing。
- 不实现 dynamic Swarm decomposition。
- 不实现 A2A/ARD compatibility。

## v11.60: Go Artifact Manifest URI Boundary

状态：complete
目标：Make Go receipt and audit artifact manifest verification reject non-string manifest URIs.

新增：

- Go reusable receipt verification rejects non-string artifact manifest `uri` values with `artifact manifest uri invalid`.
- Go audit artifact verification rejects non-string artifact manifest `uri` values with `artifact manifest uri invalid` before comparing artifact refs or reading local bytes.
- The fix is scoped to artifact manifest proof metadata shape; it does not change local URI/path validation or full artifact manifest schema validation.

不做：

- 不改变 artifact manifest metadata schema。
- 不实现 generic JSON Schema validation。
- 不改变 receipt artifact manifest comparison semantics。
- 不实现 remote artifact fetch。
- 不实现 object-store artifact backend。
- 不实现 artifact retention policy。
- 不实现 scheduler-owned routing。
- 不实现 dynamic Swarm decomposition。
- 不实现 A2A/ARD compatibility。

## v11.61: Go Artifact Manifest AFP Boundary

状态：complete
目标：Make Go receipt and audit artifact manifest verification reject present non-string AFP values.

新增：

- Go reusable receipt verification rejects present non-string artifact manifest `afp` values with `artifact manifest afp invalid`.
- Go audit artifact verification rejects present non-string artifact manifest `afp` values with `artifact manifest afp invalid` before comparing AFP strings or reading local bytes.
- Existing string AFP mismatch behavior remains `artifact manifest afp mismatch`.
- The fix is scoped to optional artifact manifest proof metadata shape; it does not make `afp` required and does not add full artifact manifest schema validation.

不做：

- 不改变 artifact manifest metadata schema。
- 不实现 generic JSON Schema validation。
- 不改变 receipt artifact manifest comparison semantics。
- 不实现 remote artifact fetch。
- 不实现 object-store artifact backend。
- 不实现 artifact retention policy。
- 不实现 scheduler-owned routing。
- 不实现 dynamic Swarm decomposition。
- 不实现 A2A/ARD compatibility。

## v11.62: Go Artifact Mirror Index AFP Type Boundary

状态：complete
目标：Make Go filesystem artifact mirror index verification reject present non-string AFP values before comparing AFP strings.

新增：

- Go `readArtifactStoreIndex` rejects present non-string mirror index `afp` values with `artifact mirror index afp invalid`.
- Existing string AFP mismatch behavior remains `artifact mirror index invalid`.
- The fix is scoped to optional mirror index proof metadata shape; it does not make `afp` required and does not add full mirror index schema validation.

不做：

- 不改变 artifact manifest metadata schema。
- 不实现 generic JSON Schema validation。
- 不改变 receipt artifact manifest comparison semantics。
- 不实现 remote artifact fetch。
- 不实现 object-store artifact backend。
- 不实现 artifact retention policy。
- 不实现 scheduler-owned routing。
- 不实现 dynamic Swarm decomposition。
- 不实现 A2A/ARD compatibility。

## Next Candidates

1. Add real public reachability proof only with external network evidence, not same-host `0.0.0.0` proof.
2. Continue Phase A trust-boundary bug closure only where the current code still contradicts verified claims.
3. Continue Swarm proof work only where it adds verifiable accountability without dynamic decomposition, scheduler ownership, parallel execution, cross-Zone Swarm, or a Node audit verifier.
4. Keep compatibility work parked until the proof layer has an externally consumable release surface.
