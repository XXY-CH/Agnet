# Agent Space v10 Roadmap

状态：active
目标：把 v9 已经闭合的 proof/accountability core 推向更容易被外部生态验证和复用的形态，同时继续避免过早做调度器、产品平台或兼容性宣称。

## v10.0: Ed25519 did:key Identity Bridge

状态：complete
目标：Agent Descriptor can expose a W3C-visible `did:key` bridge for the same Ed25519 public key that already defines the canonical `aid:`.

新增：

- Node descriptors include `did_key` derived from `public_key_spki`.
- Go descriptors include `did_key` derived from the same Ed25519 key material.
- Node exports helpers to derive `did:key` from descriptors/SPKI and to round-trip `did:key` back to SPKI.
- Go exports local helpers to derive and round-trip the same bridge.
- Descriptor verification rejects a mismatched optional `did_key`.
- Shared test vectors prove Node and Go agree on the stable requester DID.

不做：

- 不把 `did:key` 变成 canonical identity。
- 不替换 `aid:`。
- 不实现 DID document。
- 不实现 DID resolver。
- 不实现 DID service endpoints。
- 不做 ANP/A2A/AGNTCY compatibility。
- 不做 public identity registry。

## v10.1: Node Artifact Manifest Parity

状态：complete
目标：Node artifact writes produce the same minimal manifest evidence shape already used by Go.

新增：

- Node `writeArtifact` persists `<artifact>.manifest.json`.
- Node artifact manifests include `uri`, `sha256`, `size`, `media_type`, and `manifest_hash`.
- Node MVP, local runtime, and federation gateway receipts bind `artifact_manifests`.
- Node `artifact.created` events carry the produced manifest.

不做：

- 不做 Node content-addressed mirror。
- 不做 Node artifact verify/read API。
- 不做 Node artifact-store GC。
- 不做 object-store backend。
- 不做 Node receipt verifier CLI。

## v10.2: Node Receipt Artifact Manifest Verification

状态：complete
目标：Node `FED_RECEIPT` verification rejects signed-but-invalid artifact manifest metadata.

新增：

- `verifyFederatedReceipt` validates optional `artifact_manifests`.
- Manifest count must match `artifact_refs`.
- Manifest `uri`, required fields, `size`, and `manifest_hash` are checked.
- A signed bad manifest hash is rejected by the vector test.

不做：

- 不读取 artifact bytes。
- 不验证 Node sidecar files。
- 不做 Node artifact verify/read API。
- 不做 receipt store/search。
- 不做 Go verifier package extraction。

## v10.3: Node Local Artifact Verification

状态：complete
目标：Node can verify local artifact bytes and sidecar files against a receipt artifact manifest.

新增：

- `verifyLocalArtifact(manifest)` verifies one local artifact.
- It reuses receipt manifest metadata checks.
- It rejects mismatched sidecar JSON.
- It rejects local artifact size or SHA-256 mismatches.

不做：

- 不做 Node artifact verify/read API。
- 不做 content-addressed mirror。
- 不做 artifact-store GC。
- 不做 remote artifact fetch。
- 不做 batch verifier。

## v10.4: Node Artifact Verify CLI

状态：complete
目标：Expose local Node artifact verification through one command.

新增：

- `node asp-verify.mjs artifact <manifest.json>` verifies one local artifact manifest file.
- The command prints JSON on success.
- The command exits non-zero and prints the verifier error on failure.

不做：

- 不做 npm package。
- 不做 receipt verifier CLI。
- 不做 HTTP artifact verify/read API。
- 不做 batch verification。
- 不做 remote artifact fetch。

## Next Candidates

1. Extract receipt verification into a small Go package and/or npm-facing verifier.
2. Publish an English ASP Core draft focused on receipts, artifacts, audit, and identity bridge fields.
3. Provide a first public-node or Docker demo that proves the existing local-first flow is reproducible.
4. Continue Swarm proof work only where it adds verifiable accountability, not scheduler breadth.
