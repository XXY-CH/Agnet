# Agent Space v12 Roadmap

状态：active
目标：把 v11 已闭合的 proof/accountability core 推向外部可消费的 proof surface，同时继续避免 A2A/ARD compatibility、scheduler、经济层和产品平台漂移。

## v12.0: Public Proof Bundle Manifest

状态：complete
目标：Make the local public-listen proof write one verifier-facing bundle manifest that points to the receipt, trust, artifact, transport, and Swarm close evidence it already proves.

新增：

- `scripts/public-node-proof.mjs` writes `state/public-node-proof-bundle.json`.
- The bundle records `receipt_frame`, `trusted_zones`, `receipt_digest`, artifact URI/SHA-256/manifest-hash lists, signed `transport_proof`, Swarm close proof paths, and `swarm_close_digest`.
- The public proof summary returns `bundle_manifest`.
- `public-node-proof.test.mjs` verifies the bundle exactly matches the receipt verifier output and Swarm close proof output.

不做：

- 不实现 hosted public node。
- 不实现 external public reachability proof。
- 不实现 package publish/signing。
- 不实现 SBOM。
- 不实现 batch verifier。
- 不实现 A2A/ARD compatibility。
- 不实现 scheduler-owned routing。

## Next Candidates

1. Add real external public reachability proof only with external network evidence.
2. Add package signing or SBOM only when a package/release artifact exists.
3. Add a small verifier command for proof bundles only if consumers need one; the current bundle is just a manifest over existing verifier-ready files.
