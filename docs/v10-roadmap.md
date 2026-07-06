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

## Next Candidates

1. Extract receipt verification into a small Go package and/or npm-facing verifier.
2. Publish an English ASP Core draft focused on receipts, artifacts, audit, and identity bridge fields.
3. Provide a first public-node or Docker demo that proves the existing local-first flow is reproducible.
4. Continue Swarm proof work only where it adds verifiable accountability, not scheduler breadth.
