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

## v12.10: Verifier CLI Exact Arity

状态：complete
目标：Make every implemented verifier CLI command reject extra positional arguments.

新增：

- `asp-verify.mjs artifact <manifest.json>` requires exactly one manifest path.
- `asp-verify.mjs fed-receipt <frame.json> <trusted-zones.json> [task.json]` and `fed-receipt-artifacts` accept only their no-task and one-task forms.
- `asp-verify.mjs swarm-close <frame.json> <trusted-zones.json>` rejects extra positional arguments.
- `mvp-demo.test.mjs` and `test-vectors.test.mjs` cover extra positional argument rejection across the sibling verifier commands.

不做：

- 不增加 option parsing。
- 不改变 verifier JSON output。
- 不改变 command names or valid arities。
- 不实现 batch verifier。
- 不实现 JSON Schema。
- 不实现 generic proof bundle schema。
- 不实现 artifact byte relocation。
- 不实现 hosted public node。
- 不实现 external public reachability proof。
- 不实现 package signing or SBOM。
- 不实现 A2A/ARD compatibility。
- 不实现 scheduler-owned routing。

## v12.11: Proof Bundle Public Transport Gate

状态：complete
目标：Make public proof bundles reject signed receipts whose transport proof is not public.

新增：

- `asp-verify.mjs proof-bundle <bundle.json>` requires verified receipt `transport_proof.public_transport === true`.
- A bundle that matches a signed receipt with `public_transport: false` is rejected with `bundle public_transport proof missing`.
- `public-node-proof.test.mjs` covers a re-signed non-public transport receipt and matching bundle.

不做：

- 不实现 external public reachability proof。
- 不实现 hosted public node。
- 不实现 DNS, TLS, QUIC, NAT traversal, or remote probe infrastructure。
- 不改变 normal `fed-receipt` verification。
- 不改变 verifier JSON output。
- 不实现 batch verifier。
- 不实现 JSON Schema。
- 不实现 generic proof bundle schema。
- 不实现 package signing or SBOM。
- 不实现 A2A/ARD compatibility。
- 不实现 scheduler-owned routing。

## v12.12: Proof Bundle Transport Proof Shape

状态：complete
目标：Make public proof bundles reject incomplete signed transport proofs.

新增：

- `asp-verify.mjs proof-bundle <bundle.json>` requires verified receipt `transport_proof` to include non-empty `transport`, non-empty `listen_host`, decimal-string `port`, and `public_transport: true`.
- A bundle that matches a signed receipt with only `public_transport: true` is rejected with `bundle transport_proof invalid`.
- `public-node-proof.test.mjs` covers a re-signed incomplete transport proof receipt and matching bundle.

不做：

- 不实现 external public reachability proof。
- 不实现 hosted public node。
- 不改变 normal `fed-receipt` verification。
- 不改变 verifier JSON output。
- 不改变 Go receipt transport proof field shape。
- 不实现 DNS, TLS, QUIC, NAT traversal, or remote probe infrastructure。
- 不实现 batch verifier。
- 不实现 JSON Schema。
- 不实现 generic proof bundle schema。
- 不实现 package signing or SBOM。
- 不实现 A2A/ARD compatibility。
- 不实现 scheduler-owned routing。

## v12.13: Proof Bundle Federation Transport Gate

状态：complete
目标：Make public proof bundles reject non-federation transport proofs.

新增：

- `asp-verify.mjs proof-bundle <bundle.json>` requires verified receipt `transport_proof.transport === "fed+tcp"`.
- A bundle that matches a signed receipt with `transport: "asp+local"` and `public_transport: true` is rejected with `bundle transport_proof invalid`.
- `public-node-proof.test.mjs` covers a re-signed local-transport receipt and matching bundle.

不做：

- 不实现 external public reachability proof。
- 不实现 hosted public node。
- 不增加 QUIC, TLS, DNS, NAT traversal, or remote probe infrastructure。
- 不改变 normal `fed-receipt` verification。
- 不改变 verifier JSON output。
- 不实现 transport negotiation。
- 不实现 batch verifier。
- 不实现 JSON Schema。
- 不实现 generic proof bundle schema。
- 不实现 package signing or SBOM。
- 不实现 A2A/ARD compatibility。
- 不实现 scheduler-owned routing。

## v12.14: Proof Bundle Listen Host Gate

状态：complete
目标：Make public proof bundles reject loopback transport proofs.

新增：

- `asp-verify.mjs proof-bundle <bundle.json>` rejects verified receipt transport proofs whose `listen_host` is `localhost`, `::1`, or IPv4 `127.*`.
- A bundle that matches a signed receipt with `listen_host: "127.0.0.1"` and `public_transport: true` is rejected with `bundle transport_proof invalid`.
- `public-node-proof.test.mjs` covers a re-signed loopback-listen receipt and matching bundle.

不做：

- 不实现 external public reachability proof。
- 不实现 hosted public node。
- 不增加 DNS, TLS, QUIC, NAT traversal, or remote probe infrastructure。
- 不改变 Go receipt transport proof field shape。
- 不改变 normal `fed-receipt` verification。
- 不改变 verifier JSON output。
- 不实现 transport negotiation。
- 不实现 batch verifier。
- 不实现 JSON Schema。
- 不实现 generic proof bundle schema。
- 不实现 package signing or SBOM。
- 不实现 A2A/ARD compatibility。
- 不实现 scheduler-owned routing。

## v12.15: Proof Bundle Unspecified Host Gate

状态：complete
目标：Make public proof bundles and Go public transport status reject unspecified listener hosts.

新增：

- Go `isPublicListenHost` rejects `0.0.0.0` and `::` instead of treating unspecified bind addresses as public.
- `scripts/public-node-proof.mjs` binds the proof gateway to the first non-loopback IPv4 address instead of `0.0.0.0`.
- `asp-verify.mjs proof-bundle <bundle.json>` rejects signed receipt transport proofs whose `listen_host` is `0.0.0.0` or `::`.
- `public-node-proof.test.mjs` covers a re-signed unspecified-listen receipt and matching bundle.

不做：

- 不实现 external public reachability proof。
- 不实现 hosted public node。
- 不增加 DNS, TLS, QUIC, NAT traversal, or remote probe infrastructure。
- 不改变 normal `fed-receipt` verification。
- 不改变 verifier JSON output。
- 不实现 transport negotiation。
- 不实现 batch verifier。
- 不实现 JSON Schema。
- 不实现 generic proof bundle schema。
- 不实现 package signing or SBOM。
- 不实现 A2A/ARD compatibility。
- 不实现 scheduler-owned routing。

## v12.16: Proof Bundle Reachability Scope

状态：complete
目标：Make public proof bundle verification label its current reachability scope.

新增：

- `asp-verify.mjs proof-bundle <bundle.json>` returns `reachability_scope: "local-interface"`.
- `scripts/public-node-proof.mjs` forwards the verifier-owned `reachability_scope` into the public proof summary.
- `public-node-proof.test.mjs` covers both the public proof summary and direct `proof-bundle` verifier output.

不做：

- 不实现 external public reachability proof。
- 不实现 hosted public node。
- 不增加 DNS, TLS, QUIC, NAT traversal, or remote probe infrastructure。
- 不改变 normal `fed-receipt` verification。
- 不改变 verifier JSON output beyond `reachability_scope` on `proof-bundle`。
- 不实现 transport negotiation。
- 不实现 batch verifier。
- 不实现 JSON Schema。
- 不实现 generic proof bundle schema。
- 不实现 package signing or SBOM。
- 不实现 A2A/ARD compatibility。
- 不实现 scheduler-owned routing。

## v12.17: Proof Bundle Reachability Scope Ownership

状态：complete
目标：Make public proof bundle verification reject manifest-supplied reachability scope claims.

新增：

- `asp-verify.mjs proof-bundle <bundle.json>` rejects bundle manifests that include `reachability_scope`.
- `public-node-proof.test.mjs` covers a manifest trying to self-claim `reachability_scope: "external-host"`.
- `docs/asp-core-draft.md` documents `reachability_scope` as verifier-owned output.

不做：

- 不实现 external public reachability proof。
- 不实现 hosted public node。
- 不增加 DNS, TLS, QUIC, NAT traversal, or remote probe infrastructure。
- 不改变 normal `fed-receipt` verification。
- 不改变 successful `proof-bundle` verifier JSON output。
- 不实现 transport negotiation。
- 不实现 batch verifier。
- 不实现 JSON Schema。
- 不实现 generic proof bundle schema。
- 不实现 package signing or SBOM。
- 不实现 A2A/ARD compatibility。
- 不实现 scheduler-owned routing。

## v12.18: Package Artifact Proof

状态：complete
目标：Make the npm-facing verifier surface produce a real local package artifact with npm-owned digest metadata.

新增：

- `scripts/package-proof.mjs` runs `npm pack --json --pack-destination state/package-proof`.
- The script returns `package_proof: "ok"`, package name/version, tarball path, size, unpacked size, SHA-1 shasum, SHA-512 integrity, and packaged file list.
- `package-contract.test.mjs` covers tarball creation and the expected package file list.

不做：

- 不实现 package signing。
- 不实现 SBOM。
- 不发布 npm package。
- 不改变 `package.json` exports/bin/files。
- 不实现 external public reachability proof。
- 不实现 hosted public node。
- 不增加 DNS, TLS, QUIC, NAT traversal, or remote probe infrastructure。
- 不改变 normal `fed-receipt` verification。
- 不改变 `proof-bundle` verifier JSON output。
- 不实现 transport negotiation。
- 不实现 batch verifier。
- 不实现 JSON Schema。
- 不实现 generic proof bundle schema。
- 不实现 A2A/ARD compatibility。
- 不实现 scheduler-owned routing。

## v12.19: Package Artifact SHA-256

状态：complete
目标：Bind the local npm package artifact to the same SHA-256 digest shape used by ASP artifacts and receipts.

新增：

- `scripts/package-proof.mjs` computes `sha256` over the produced npm tarball.
- `package-contract.test.mjs` verifies `sha256` is 64 lowercase hex and matches the tarball bytes.

不做：

- 不实现 package signing。
- 不实现 SBOM。
- 不发布 npm package。
- 不改变 `package.json` exports/bin/files。
- 不改变 npm `shasum` or `integrity` handling。
- 不实现 external public reachability proof。
- 不实现 hosted public node。
- 不增加 DNS, TLS, QUIC, NAT traversal, or remote probe infrastructure。
- 不改变 normal `fed-receipt` verification。
- 不改变 `proof-bundle` verifier JSON output。
- 不实现 transport negotiation。
- 不实现 batch verifier。
- 不实现 JSON Schema。
- 不实现 generic proof bundle schema。
- 不实现 A2A/ARD compatibility。
- 不实现 scheduler-owned routing。

## v12.20: Package Proof Manifest

状态：complete
目标：Persist the local package proof JSON so future package signing or SBOM work has a stable file input.

新增：

- `scripts/package-proof.mjs` writes `state/package-proof/package-proof.json`.
- The script returns `manifest: "state/package-proof/package-proof.json"` in stdout.
- `package-contract.test.mjs` verifies the manifest JSON exactly matches the stdout proof object.

不做：

- 不实现 package signing。
- 不实现 SBOM。
- 不发布 npm package。
- 不改变 `package.json` exports/bin/files。
- 不改变 npm `shasum` or `integrity` handling。
- 不改变 tarball SHA-256 calculation。
- 不实现 external public reachability proof。
- 不实现 hosted public node。
- 不增加 DNS, TLS, QUIC, NAT traversal, or remote probe infrastructure。
- 不改变 normal `fed-receipt` verification。
- 不改变 `proof-bundle` verifier JSON output。
- 不实现 transport negotiation。
- 不实现 batch verifier。
- 不实现 JSON Schema。
- 不实现 generic proof bundle schema。
- 不实现 A2A/ARD compatibility。
- 不实现 scheduler-owned routing。

## v12.21: Package Proof Digest

状态：complete
目标：Bind the package proof manifest body to a stable ASP-style canonical digest before any future signing or SBOM format is chosen.

新增：

- `scripts/package-proof.mjs` computes `proof_digest` as `sha256(canonical(proof without proof_digest))`.
- The persisted `state/package-proof/package-proof.json` and stdout proof include the same `proof_digest`.
- `package-contract.test.mjs` recomputes the digest from the proof body.

不做：

- 不实现 package signing。
- 不实现 SBOM。
- 不发布 npm package。
- 不改变 `package.json` exports/bin/files。
- 不改变 npm `shasum` or `integrity` handling。
- 不改变 tarball SHA-256 calculation。
- 不实现 external public reachability proof。
- 不实现 hosted public node。
- 不增加 DNS, TLS, QUIC, NAT traversal, or remote probe infrastructure。
- 不改变 normal `fed-receipt` verification。
- 不改变 `proof-bundle` verifier JSON output。
- 不实现 transport negotiation。
- 不实现 batch verifier。
- 不实现 JSON Schema。
- 不实现 generic proof bundle schema。
- 不实现 A2A/ARD compatibility。
- 不实现 scheduler-owned routing。

## Next Candidates

1. Add real external public reachability proof only with external network evidence.
2. Add package signing or SBOM against the produced package artifact only when that signature/SBOM format is explicitly scoped.
3. Add hosted/public reachability only when the proof includes evidence from outside the same host.
