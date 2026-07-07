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

## v12.1: Proof Bundle Verifier Command

状态：complete
目标：Make one public proof bundle verifiable through the existing Node verifier CLI.

新增：

- `asp-verify.mjs proof-bundle <bundle.json>` verifies the receipt, artifact bytes, signed transport proof fields, and Swarm close digest named by the bundle.
- The command rejects manifest fields that do not match the existing verifier-owned receipt/artifact/Swarm close outputs.
- `public-node-proof.test.mjs` covers a successful bundle verification and a tampered `receipt_digest` rejection.

不做：

- 不实现 hosted public node。
- 不实现 external public reachability proof。
- 不实现 package publish/signing。
- 不实现 SBOM。
- 不实现 batch verifier。
- 不实现 A2A/ARD compatibility。
- 不实现 scheduler-owned routing。

## v12.2: Public Proof Summary Bundle Verification

状态：complete
目标：Make the one-command public proof summary report that its bundle was verified by the proof-bundle CLI.

新增：

- `scripts/public-node-proof.mjs` runs `asp-verify.mjs proof-bundle state/public-node-proof-bundle.json` after writing the bundle.
- The public proof summary returns `proof_bundle_verify: "ok"`.
- `public-node-proof.test.mjs` asserts the summary exposes that result.

不做：

- 不实现 hosted public node。
- 不实现 external public reachability proof。
- 不实现 package publish/signing。
- 不实现 SBOM。
- 不实现 batch verifier。
- 不实现 A2A/ARD compatibility。
- 不实现 scheduler-owned routing。

## v12.3: Bundle-Relative Proof File Paths

状态：complete
目标：Make the proof bundle's proof file paths resolve relative to the bundle manifest file.

新增：

- `scripts/public-node-proof.mjs` writes proof file references like `public-node-proof-fed-receipt.json` inside the bundle instead of `state/...`.
- `asp-verify.mjs proof-bundle <bundle.json>` resolves relative proof file paths from the bundle directory.
- `public-node-proof.test.mjs` asserts the bundle contains self-relative proof file paths.

不做：

- 不实现 artifact byte relocation。
- 不实现 hosted public node。
- 不实现 external public reachability proof。
- 不实现 package publish/signing。
- 不实现 SBOM。
- 不实现 batch verifier。
- 不实现 A2A/ARD compatibility。
- 不实现 scheduler-owned routing。

## v12.4: Proof Bundle Path Safety

状态：complete
目标：Make proof bundle proof-file paths fail closed before reading paths outside the bundle directory.

新增：

- `asp-verify.mjs proof-bundle <bundle.json>` rejects empty, absolute, backslash-bearing, `.` segment, and `..` segment proof-file paths before file reads.
- Rejections name the unsafe bundle field, such as `bundle receipt_frame path invalid`.
- `public-node-proof.test.mjs` covers parent traversal and absolute-path tampering.

不做：

- 不实现 artifact byte relocation。
- 不实现 hosted public node。
- 不实现 external public reachability proof。
- 不实现 package publish/signing。
- 不实现 SBOM。
- 不实现 batch verifier。
- 不实现 A2A/ARD compatibility。
- 不实现 scheduler-owned routing。

## v12.5: Proof Bundle Type Gate

状态：complete
目标：Make proof bundle type validation fail closed before following bundle proof-file paths.

新增：

- `asp-verify.mjs proof-bundle <bundle.json>` checks `proof === "public-node-proof"` immediately after parsing the bundle manifest.
- Wrong proof types are rejected before receipt, trusted-Zone, or Swarm proof-file path reads.
- `public-node-proof.test.mjs` covers wrong proof type plus escaping path tampering.

不做：

- 不实现 generic proof bundle schema。
- 不实现 artifact byte relocation。
- 不实现 hosted public node。
- 不实现 external public reachability proof。
- 不实现 package publish/signing。
- 不实现 SBOM。
- 不实现 batch verifier。
- 不实现 A2A/ARD compatibility。
- 不实现 scheduler-owned routing。

## v12.6: Proof Bundle Manifest Object

状态：complete
目标：Make proof bundle verification reject non-object bundle manifests before reading proof fields.

新增：

- `asp-verify.mjs proof-bundle <bundle.json>` rejects `null` or array bundle manifests with `bundle manifest invalid`.
- The manifest object check runs before the proof type check and before proof-file path reads.
- `public-node-proof.test.mjs` covers `null` and `[]` bundle files.

不做：

- 不实现 JSON Schema。
- 不实现 generic proof bundle schema。
- 不实现 artifact byte relocation。
- 不实现 hosted public node。
- 不实现 external public reachability proof。
- 不实现 package publish/signing。
- 不实现 SBOM。
- 不实现 batch verifier。
- 不实现 A2A/ARD compatibility。
- 不实现 scheduler-owned routing。

## v12.7: Proof Bundle Path Preflight

状态：complete
目标：Make proof bundle verification validate every proof-file path before opening any proof files.

新增：

- `asp-verify.mjs proof-bundle <bundle.json>` resolves and validates `receipt_frame`, `trusted_zones`, `swarm_close_frame`, and `swarm_close_trusted_zones` before reading any of them.
- Unsafe later path fields fail with their own field-specific error even if an earlier path is safe but missing.
- `public-node-proof.test.mjs` covers an escaping `swarm_close_frame` masked by a missing `receipt_frame`.

不做：

- 不实现 JSON Schema。
- 不实现 generic proof bundle schema。
- 不实现 artifact byte relocation。
- 不实现 hosted public node。
- 不实现 external public reachability proof。
- 不实现 package publish/signing。
- 不实现 SBOM。
- 不实现 batch verifier。
- 不实现 A2A/ARD compatibility。
- 不实现 scheduler-owned routing。

## v12.8: Proof Bundle CLI Arity

状态：complete
目标：Make the proof bundle verifier reject extra positional CLI arguments.

新增：

- `asp-verify.mjs proof-bundle <bundle.json>` accepts exactly one bundle path argument.
- Extra positional arguments fall through to the existing usage error instead of being ignored.
- `public-node-proof.test.mjs` covers `proof-bundle <bundle.json> extra.json`.

不做：

- 不改变其他 verifier CLI commands。
- 不实现 JSON Schema。
- 不实现 generic proof bundle schema。
- 不实现 artifact byte relocation。
- 不实现 hosted public node。
- 不实现 external public reachability proof。
- 不实现 package publish/signing。
- 不实现 SBOM。
- 不实现 batch verifier。
- 不实现 A2A/ARD compatibility。
- 不实现 scheduler-owned routing。

## v12.9: Proof Bundle Exact CLI Arity

状态：complete
目标：Make proof bundle CLI arity count positional arguments exactly.

新增：

- `asp-verify.mjs proof-bundle <bundle.json>` requires exactly two CLI tokens after the script name: `proof-bundle` and one bundle path.
- Empty-string extra positional arguments are rejected by the same usage path as non-empty extras.
- `public-node-proof.test.mjs` covers `proof-bundle <bundle.json> ""`.

不做：

- 不改变其他 verifier CLI commands。
- 不实现 batch verifier。
- 不实现 JSON Schema。
- 不实现 generic proof bundle schema。
- 不实现 artifact byte relocation。
- 不实现 hosted public node。
- 不实现 external public reachability proof。
- 不实现 A2A/ARD compatibility。
- 不实现 scheduler-owned routing。

## Next Candidates

1. Add real external public reachability proof only with external network evidence.
2. Add package signing or SBOM only when a package/release artifact exists.
3. Add hosted/public reachability only when the proof includes evidence from outside the same host.
