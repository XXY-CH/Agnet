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

## v12.22: Package Proof Verifier Command

状态：complete
目标：Let a third party verify the generated package proof manifest and tarball with the existing Node verifier CLI.

新增：

- `asp-verify.mjs package-proof <manifest.json>` verifies `proof_digest`, tarball `sha256`, and tarball size.
- The command returns `package_proof_verify: "ok"` plus package name, version, filename, tarball, SHA-256, and proof digest.
- `package-contract.test.mjs` runs the verifier against the real `state/package-proof/package-proof.json` output.

不做：

- 不实现 package signing。
- 不实现 SBOM。
- 不发布 npm package。
- 不改变 `package.json` exports/bin/files。
- 不改变 npm `shasum` or `integrity` handling。
- 不改变 tarball SHA-256 calculation。
- 不实现 relocatable package proof format。
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

## v12.23: Package Proof Manifest Object Gate

状态：complete
目标：Make the package proof verifier fail closed before reading fields from non-object manifests.

新增：

- `asp-verify.mjs package-proof <manifest.json>` rejects `null` and array package proof manifests with `package proof manifest invalid`.
- `package-contract.test.mjs` covers both non-object manifest shapes.

不做：

- 不实现 package signing。
- 不实现 SBOM。
- 不发布 npm package。
- 不改变 `package.json` exports/bin/files。
- 不改变 npm `shasum` or `integrity` handling。
- 不改变 tarball SHA-256 calculation。
- 不实现 relocatable package proof format。
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

## v12.24: Package Proof Tarball Path Safety

状态：complete
目标：Make the package proof verifier reject unsafe tarball paths before reading package bytes.

新增：

- `asp-verify.mjs package-proof <manifest.json>` rejects absolute and parent-directory tarball paths with `package proof tarball path invalid`.
- The package proof tarball path gate reuses the same non-empty, no-backslash, no-dot-segment path shape used by proof bundle file paths.
- `package-contract.test.mjs` covers absolute and `..` tarball paths.

不做：

- 不实现 package signing。
- 不实现 SBOM。
- 不发布 npm package。
- 不改变 `package.json` exports/bin/files。
- 不改变 npm `shasum` or `integrity` handling。
- 不改变 tarball SHA-256 calculation。
- 不实现 relocatable package proof format。
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

## v12.25: Package Proof Manifest-Relative Tarball

状态：complete
目标：Make the generated package proof directory copyable by resolving safe tarball paths relative to the package proof manifest.

新增：

- `asp-verify.mjs package-proof <manifest.json>` resolves safe tarball paths relative to the manifest file before checking tarball SHA-256 and size.
- `scripts/package-proof.mjs` writes `tarball` and `manifest` as package-directory-relative file names.
- `package-contract.test.mjs` covers a manifest in a nested proof directory with a sibling tarball.

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

## v12.26: Package Proof npm Digest Verification

状态：complete
目标：Make the package proof verifier reject npm `shasum` and `integrity` values that do not match the tarball bytes.

新增：

- `asp-verify.mjs package-proof <manifest.json>` checks `shasum` as SHA-1 over the manifest-relative tarball bytes.
- `asp-verify.mjs package-proof <manifest.json>` checks `integrity` as the npm `sha512-<base64>` string over the manifest-relative tarball bytes.
- `package-contract.test.mjs` covers mismatched `shasum` and `integrity` fields while keeping `proof_digest` self-consistent.

不做：

- 不实现 package signing。
- 不实现 SBOM。
- 不发布 npm package。
- 不改变 `package.json` exports/bin/files。
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

## v12.27: Package Proof Verified Metadata Output

状态：complete
目标：Make successful package proof verification return the verified npm digest and size metadata it already checked.

新增：

- `asp-verify.mjs package-proof <manifest.json>` returns verified `size`, `shasum`, and `integrity` fields in its JSON output.
- `package-contract.test.mjs` asserts successful package proof verification returns the same verified metadata as the proof manifest.

不做：

- 不实现 package signing。
- 不实现 SBOM。
- 不发布 npm package。
- 不改变 `package.json` exports/bin/files。
- 不改变 tarball SHA-256 calculation。
- 不改变 package proof verification inputs。
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

## v12.28: Package Proof Filename Binding

状态：complete
目标：Make the package proof verifier reject manifests whose displayed filename does not match the tarball path basename.

新增：

- `asp-verify.mjs package-proof <manifest.json>` requires `filename` to equal the final path segment of `tarball`.
- `package-contract.test.mjs` covers a self-consistent proof digest whose `filename` lies about the tarball being verified.

不做：

- 不实现 package signing。
- 不实现 SBOM。
- 不发布 npm package。
- 不改变 `package.json` exports/bin/files。
- 不改变 tarball SHA-256 calculation。
- 不改变 package proof verification inputs。
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

## v12.29: Package Proof File List Shape

状态：complete
目标：Make the package proof verifier reject malformed packaged file lists before accepting package proof metadata.

新增：

- `asp-verify.mjs package-proof <manifest.json>` requires `files` to be a non-empty array of unique safe relative paths.
- File entries with absolute paths, backslashes, empty path segments, `.` segments, or `..` segments are rejected with `package proof files invalid`.
- `package-contract.test.mjs` covers a self-consistent proof digest whose `files` field is not an array and whose file list escapes the package root.

不做：

- 不实现 package signing。
- 不实现 SBOM。
- 不实现 tarball member proof。
- 不发布 npm package。
- 不改变 `package.json` exports/bin/files。
- 不改变 tarball SHA-256 calculation。
- 不改变 package proof verification inputs。
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

## v12.30: Package Proof Manifest Filename Binding

状态：complete
目标：Make the package proof verifier reject manifests whose `manifest` field does not match the verifier input filename.

新增：

- `asp-verify.mjs package-proof <manifest.json>` requires `manifest` to equal the final path segment of the verifier input path.
- `package-contract.test.mjs` covers a self-consistent proof digest whose `manifest` field names a different manifest file.

不做：

- 不实现 package signing。
- 不实现 SBOM。
- 不实现 tarball member proof。
- 不发布 npm package。
- 不改变 `package.json` exports/bin/files。
- 不改变 tarball SHA-256 calculation。
- 不改变 package proof verification inputs。
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

## v12.31: Package Proof Identity Filename Binding

状态：complete
目标：Make the package proof verifier reject manifests whose package `name` and `version` metadata do not match the local npm tarball filename.

新增：

- `asp-verify.mjs package-proof <manifest.json>` requires `filename` to equal `<name>-<version>.tgz` for the current local npm package proof.
- `package-contract.test.mjs` covers a self-consistent proof digest whose package `name` no longer matches the tarball filename.

不做：

- 不实现 package signing。
- 不实现 SBOM。
- 不实现 tarball member proof。
- 不实现 scoped package filename generality。
- 不发布 npm package。
- 不改变 `package.json` exports/bin/files。
- 不改变 tarball SHA-256 calculation。
- 不改变 package proof verification inputs。
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

## v12.32: Go Protocol Canonical JSON HTML-Escape Parity

状态：complete
目标：Make Go protocol signing, signature verification, and digest paths match Node canonical JSON for signed and digested values containing `<`, `>`, and `&`.

新增：

- `agnet/verifier.VerifyFederatedReceipt` verifies a receipt and supplied signed task evidence containing `<>&` when signed/digested with Node canonical bytes.
- `cmd/go-fed-discovery` protocol `signBodyWithKey`, `verifyMapSignature`, and `digestHex` use `json.Encoder.SetEscapeHTML(false)` and trim the encoder newline.
- Focused Go tests cover reusable verifier acceptance and Go runtime signing/digest no-HTML-escape behavior.

不做：

- 不改变 JSON key ordering beyond Go's existing deterministic encoding.
- 不实现 full RFC/JCS canonicalization。
- 不改变 verifier CLI command shapes。
- 不实现 external public reachability proof。
- 不实现 hosted public node。
- 不实现 package signing。
- 不实现 SBOM。
- 不实现 scheduler-owned routing。
- 不实现 A2A/ARD compatibility。

## v12.33: External Reachability Evidence Gate

状态：complete
目标：Let the proof-bundle verifier upgrade `reachability_scope` to `external-host` only when it receives caller-supplied trusted observer evidence.

新增：

- `asp-verify.mjs proof-bundle <bundle.json> [external-trusted-zones.json]` accepts an optional external observer trusted-Zone file.
- `bundle.external_reachability` must be signed by a trusted observer Zone and bind `proof: "external-reachability"`, `observer_zid`, the verified `transport_proof`, the verified `receipt_digest`, and `reached: true`.
- Bundles that include external reachability evidence without the extra trust input fail closed.
- `public-node-proof.test.mjs` covers local default scope, trusted external-host upgrade, missing external trust rejection, and invalid external signature rejection.

不做：

- 不实现 hosted public node。
- 不运行真实 outside-host probe。
- 不增加 DNS, tunnel, NAT traversal, TLS, QUIC, or remote probe infrastructure。
- 不让 bundle 自己声明 `reachability_scope`。
- 不改变 normal `fed-receipt` verification。
- 不实现 package signing。
- 不实现 SBOM。
- 不实现 scheduler-owned routing。
- 不实现 A2A/ARD compatibility。

## v12.34: External Reachability Observer Script

状态：complete
目标：Provide a runnable observer that can create the signed external reachability evidence consumed by the v12.33 proof-bundle gate.

新增：

- `scripts/external-reachability-observer.mjs <bundle.json> <observed-bundle.json> <observer-trusted-zones.json>` reads a proof bundle and its receipt frame.
- The script verifies the bundle receipt digest and transport proof against the signed receipt before observing.
- The script TCP-connects to `transport_proof.listen_host:port`, then writes an observed bundle containing signed `external_reachability` evidence.
- The script writes the observer trusted-Zone file separately from the bundle.
- `public-node-proof.test.mjs` covers observer-written evidence that is accepted by `asp-verify.mjs proof-bundle <observed-bundle.json> <observer-trusted-zones.json>`.

不做：

- 不实现 hosted public node。
- 不证明 observer 运行在另一台物理主机。
- 不增加 DNS, tunnel, NAT traversal, TLS, QUIC, or remote probe infrastructure。
- 不让 bundle 自己声明 `reachability_scope`。
- 不把 observer trusted-Zone descriptor 嵌进 bundle。
- 不实现 package signing。
- 不实现 SBOM。
- 不实现 scheduler-owned routing。
- 不实现 A2A/ARD compatibility。

## v12.35: Docker External Reachability Observer Wrapper

状态：complete
目标：Run the external reachability observer from a Docker container without claiming real outside-host reachability.

新增：

- `scripts/docker-external-reachability-observer.sh <bundle.json> <observed-bundle.json> <observer-trusted-zones.json>` runs the existing observer script inside Docker.
- The wrapper uses `${AGNET_NODE_BASE_IMAGE:-node:22-bookworm-slim}` for constrained Docker environments.
- The wrapper mounts the repo at `/app`, adds `host.docker.internal` through Docker's host gateway, and delegates directly to `node scripts/external-reachability-observer.mjs "$@"`.
- `docker-demo.test.mjs` covers the wrapper contract without making Docker a required full-suite dependency.

不做：

- 不实现 hosted public node。
- 不证明 observer 运行在另一台物理主机。
- 不把 Docker bridge 证明描述成公网可达证明。
- 不增加 DNS, tunnel, NAT traversal, TLS, QUIC, or remote probe infrastructure。
- 不让 bundle 自己声明 `reachability_scope`。
- 不把 observer trusted-Zone descriptor 嵌进 bundle。
- 不实现 package signing。
- 不实现 SBOM。
- 不实现 scheduler-owned routing。
- 不实现 A2A/ARD compatibility。

## v12.37: Core Substrate Recenter

状态：complete
目标：Remove the upper-layer demo detour from the core proof-substrate line.

新增：

- `upper-layer-demo.mjs` is removed from the core repository surface.
- `upper-layer-demo.test.mjs` is removed from the core verification suite.
- `docs/v12.36-boundary.md` is removed because the v12.36 upper-layer demo plan is no longer part of the core v12 line.
- Public docs now present v12 as a proof-substrate/release-surface line again.

不做：

- 不实现 upper-layer demo, master-agent orchestration, or specialist-agent assignment execution。
- 不实现 automatic scheduler, semantic routing, ranking, or economy。
- 不实现 dynamic Swarm decomposition。
- 不实现 hosted public node。
- 不实现 real outside-host reachability。
- 不实现 package signing。
- 不实现 SBOM。
- 不实现 A2A/ARD compatibility。

## v12.38: Package Proof ASP Signature

状态：complete
目标：Sign the local package proof manifest with an ASP agent identity.

新增：

- `scripts/package-proof.mjs` creates or reuses `state/keys/package-proof-signer.pkcs8`.
- `state/package-proof/package-proof.json` includes a signer Agent descriptor and package proof signature.
- `asp-verify.mjs package-proof <manifest.json>` verifies the signer descriptor and package proof signature.
- The verifier returns `signer_aid` in its JSON output.
- `package-contract.test.mjs` covers valid signed package proofs plus missing and invalid package proof signatures.

不做：

- 不实现 npm registry signing。
- 不实现 external signer trust pin or release transparency。
- 不实现 SBOM。
- 不实现 package publish。
- 不实现 hosted public node。
- 不实现 real outside-host reachability。
- 不实现 scheduler-owned routing。
- 不实现 A2A/ARD compatibility。

## v12.39: Package Proof Trusted Signer Pin

状态：complete
目标：Let package proof verification pin the signer to a caller-supplied trusted signer file.

新增：

- `asp-verify.mjs package-proof <manifest.json> [trusted-signers.json]` accepts an optional trusted signer file.
- Trusted signer files may be `{ "signers": [...] }` or raw descriptor arrays.
- Trusted signer descriptors are validated through the existing Agent descriptor path.
- When supplied, the trusted signer set must include the package proof signer `aid`.
- Successful trusted verification returns `signer_trusted: true`.
- `package-contract.test.mjs` covers trusted signer acceptance and untrusted signer rejection.

不做：

- 不实现 npm registry signing。
- 不实现 release transparency。
- 不实现 SBOM。
- 不实现 package publish。
- 不实现 hosted public node。
- 不实现 real outside-host reachability。
- 不实现 scheduler-owned routing。
- 不实现 A2A/ARD compatibility。

## v12.40: Trusted Signer List Shape

状态：complete
目标：Make trusted package signer files reject missing signer lists without leaking JavaScript type errors.

新增：

- `asp-verify.mjs package-proof <manifest.json> <trusted-signers.json>` rejects `null` trusted signer files with `trusted package signer list missing`.
- The trusted signer loader checks the parsed trust file is an object or array before reading `signers`.
- `package-contract.test.mjs` covers null trusted signer list rejection.

不做：

- 不实现 JSON Schema。
- 不实现 npm registry signing。
- 不实现 release transparency。
- 不实现 SBOM。
- 不实现 package publish。
- 不实现 hosted public node。
- 不实现 real outside-host reachability。
- 不实现 scheduler-owned routing。
- 不实现 A2A/ARD compatibility。

## v12.41: Package Proof Metadata Preflight

状态：complete
目标：Validate package proof metadata before reading tarball bytes.

新增：

- `asp-verify.mjs package-proof <manifest.json>` checks package proof type, proof digest, signer signature, trusted signer pin, manifest filename, tarball filename, package identity, and packaged file list shape before reading the tarball.
- Malformed packaged file lists fail with `package proof files invalid` even when the referenced tarball is missing.
- `package-contract.test.mjs` covers malformed file-list rejection before tarball reads.

不做：

- 不实现 JSON Schema。
- 不实现 tarball member proof。
- 不实现 npm registry signing。
- 不实现 release transparency。
- 不实现 SBOM。
- 不实现 package publish。
- 不实现 hosted public node。
- 不实现 real outside-host reachability。
- 不实现 scheduler-owned routing。
- 不实现 A2A/ARD compatibility。

## v12.42: Package Proof Identity Shape

状态：complete
目标：Reject non-string package identity metadata before string interpolation.

新增：

- `asp-verify.mjs package-proof <manifest.json>` rejects empty or non-string `name`, `version`, and `filename` values with `package proof identity invalid`.
- Package identity binding now happens only after those identity fields are scalar strings.
- `package-contract.test.mjs` covers an array-valued package `name` that previously passed through JavaScript string coercion.

不做：

- 不实现 JSON Schema。
- 不实现 tarball member proof。
- 不实现 npm registry signing。
- 不实现 release transparency。
- 不实现 SBOM。
- 不实现 package publish。
- 不实现 hosted public node。
- 不实现 real outside-host reachability。
- 不实现 scheduler-owned routing。
- 不实现 A2A/ARD compatibility。

## v12.43: Package Proof Byte Metadata Shape

状态：complete
目标：Reject malformed package byte metadata before tarball reads.

新增：

- `asp-verify.mjs package-proof <manifest.json>` rejects empty or non-string `shasum`, `integrity`, and `sha256` values with `package proof byte metadata invalid`.
- It also rejects missing, negative, or non-integer `size` values with the same error.
- Byte metadata shape validation runs before reading tarball bytes.
- `package-contract.test.mjs` covers malformed byte metadata rejection before tarball reads.

不做：

- 不实现 JSON Schema。
- 不实现 digest regex preflight。
- 不实现 tarball member proof。
- 不实现 npm registry signing。
- 不实现 release transparency。
- 不实现 SBOM。
- 不实现 package publish。
- 不实现 hosted public node。
- 不实现 real outside-host reachability。
- 不实现 scheduler-owned routing。
- 不实现 A2A/ARD compatibility。

## Next Candidates

1. Run `scripts/external-reachability-observer.mjs` or the Docker wrapper from a real outside host against a hosted/public node using the v12.35 evidence shape.
2. Add release transparency or SBOM against the produced package artifact only when that trust/SBOM format is explicitly scoped.
3. Keep upper-layer demo/orchestration work parked outside this repository until the core proof substrate has externally consumable hosted-node evidence.
4. Keep compatibility work parked until the proof layer has externally consumable hosted-node evidence.
