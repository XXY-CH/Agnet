# `asp-verify.mjs` CLI reference

`asp-verify.mjs` is the Node verifier CLI. It reads JSON evidence from disk, exits non-zero on invalid evidence, and prints one JSON object on success.

## Usage

```text
node asp-verify.mjs artifact <manifest.json> |
  fed-receipt <frame.json> <trusted-zones.json> [task.json] |
  fed-receipt-artifacts <frame.json> <trusted-zones.json> [task.json] |
  swarm-close <frame.json> <trusted-zones.json> |
  sandbox-proof <frame.json> <trusted-zones.json> [required-sandbox-class] |
  sandbox-attestation <frame.json> <trusted-zones.json> <attestation.json> <trusted-attestors.json> |
  package-proof <manifest.json> [trusted-signers.json] |
  release-trust <release-trust.json> [trusted-release-signers.json] |
  proof-bundle <bundle.json> [external-trusted-zones.json]
```

Unsupported extra positional arguments fail closed.

## Commands

### `artifact <manifest.json>`

Verifies one local artifact manifest and its bytes.

```bash
node asp-verify.mjs artifact artifacts/task_001/summary.md.manifest.json
```

Success includes `artifact_verify` and `uri`.

### `fed-receipt <frame.json> <trusted-zones.json> [task.json]`

Verifies a `FED_RECEIPT` frame, Zone trust, worker identity, Zone binding, receipt signature, `task_digest`, optional supplied task evidence, and optional checkpoint evidence.

```bash
node asp-verify.mjs fed-receipt state/proof-demo-fed-receipt.json state/proof-demo-trusted-zones.json
```

Success includes `fed_receipt_verify`, `task_id`, and `receipt_digest`.

### `fed-receipt-artifacts <frame.json> <trusted-zones.json> [task.json]`

Runs `fed-receipt`, then verifies every local artifact manifest referenced by the receipt.

```bash
node asp-verify.mjs fed-receipt-artifacts state/proof-demo-fed-receipt.json state/proof-demo-trusted-zones.json
```

Success includes `artifact_count`, `artifact_uris`, `artifact_sha256s`, `artifact_manifest_hashes`, and `receipt_digest`.

### `swarm-close <frame.json> <trusted-zones.json>`

Verifies a `FED_SWARM_CLOSE` frame, signing Zone trust, close signature, close digest, step receipt shape, duplicate/NUL identity checks, micro-contracts, and migration log structure.

```bash
node asp-verify.mjs swarm-close state/public-node-proof-swarm-close.json state/public-node-proof-swarm-close-trusted-zones.json
```

Success includes `swarm_close_verify`, `swarm_id`, and `swarm_close_digest`.

### `sandbox-proof <frame.json> <trusted-zones.json> [required-sandbox-class]`

Verifies a trusted receipt and embedded signed `local.sandbox.v1` proof. The current verifier reports `sandbox_class: "local-process"`; requiring `remote-attestation` fails closed unless future matching evidence exists.

```bash
node asp-verify.mjs sandbox-proof state/proof-demo-fed-receipt.json state/proof-demo-trusted-zones.json local-process
```

Success includes sandbox claim, class, runtime identity, network, and receipt digest.

### `sandbox-attestation <frame.json> <trusted-zones.json> <attestation.json> <trusted-attestors.json>`

Verifies the trusted receipt and sandbox proof first, then verifies signed `asp-sandbox-attestation/v1` evidence from a trusted descriptor with `sandbox.attest` capability.

```bash
node asp-verify.mjs sandbox-attestation state/proof-demo-fed-receipt.json state/proof-demo-trusted-zones.json attestation.json trusted-attestors.json
```

Success includes `attestation_digest`, `attestor_aid`, `sandbox_class`, and `hardware_attestation: false`.

### `package-proof <manifest.json> [trusted-signers.json]`

Verifies local npm tarball proof metadata, tarball bytes, npm SHA-1 shasum, npm SHA-512 integrity, ASP SHA-256, canonical `proof_digest`, signer descriptor, `package.proof.sign` capability, package proof signature, optional trusted signer pin, and packaged file list.

```bash
node scripts/package-proof.mjs
node asp-verify.mjs package-proof state/package-proof/package-proof.json
node asp-verify.mjs package-proof state/package-proof/package-proof.json state/package-proof/trusted-package-signers.json
npm exec --package . -- asp-verify package-proof state/package-proof/package-proof.json
```

### `release-trust <release-trust.json> [trusted-release-signers.json]`

Verifies `asp-release-trust/v1` evidence against the referenced package proof and tarball bytes. It checks package proof freshness, package metadata binding, release signer capability, release trust digest, signature, timestamp, and optional trusted release signer pin.

```bash
node scripts/release-trust.mjs
node asp-verify.mjs release-trust state/package-proof/release-trust.json
node asp-verify.mjs release-trust state/package-proof/release-trust.json state/package-proof/trusted-release-signers.json
```

### `proof-bundle <bundle.json> [external-trusted-zones.json]`

Verifies the public-listen proof bundle: receipt frame, trusted Zones, local artifacts, signed transport proof, Swarm close proof, and optional external reachability observer evidence.

```bash
node asp-verify.mjs proof-bundle state/public-node-proof-bundle.json
node asp-verify.mjs proof-bundle state/public-node-proof-observed-bundle.json state/public-node-proof-observer-trusted-zones.json
```

Without observer evidence, success reports `reachability_scope: "local-interface"`. Trusted container observer evidence upgrades to `container-observer`; trusted external-host evidence upgrades to `external-host` only when the signed listen host is a globally routable literal IP.

## Trusted signer files

Trusted package, release, and sandbox attestation signer files may be raw descriptor arrays or objects with a `signers` array. Each descriptor must declare the required capability for that verifier command.
