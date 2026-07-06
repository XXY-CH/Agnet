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

## Next Candidates

1. Bind requester identity to origin Zone only if the frame carries enough requester evidence to verify that claim without adding a broad identity system.
2. Add real public reachability proof only with external network evidence, not same-host `0.0.0.0` proof.
3. Continue Swarm proof work only where it adds verifiable accountability without dynamic decomposition, scheduler ownership, parallel execution, or cross-Zone Swarm.
