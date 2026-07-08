# Trust model

Agnet trust is local-first and evidence-backed. A verifier trusts explicit Zone descriptors, validates object signatures, checks revocation and credential state where supplied, and rejects malformed evidence before accepting claims.

## Identity

`aid:` is the canonical Agent identifier. It is derived from an Ed25519 public key and bound by the agent descriptor signature. `did:key` is an optional Ed25519 bridge field; verifiers check that it derives from the same public key and never replace `aid:` with `did:key` for task or receipt identity.

Zones use `zid:` identifiers with signed Zone descriptors. A trusted Zone store is required before federated task, receipt, or Swarm close verification reads trust entries.

## Credentials

Capability credentials are signed by an authority Zone and bind a subject descriptor to a capability plus optional claims. Discovery treats credentials as inspectable evidence, not opaque reputation.

Credentials may carry `valid_until` as an ISO UTC timestamp. Expired, malformed, non-string, or unparseable values fail closed as inactive for discovery ranking. Credentials without `valid_until` keep the prior active behavior.

## Revocation

Authority Zone revocations are signed local evidence. In `FED_QUERY`, a revoked worker still exposes trusted credential history when a signature exists, but `discovery_evidence.credential.active` becomes `false` and credential contribution is removed from `agent_score`.

There is no network revocation sync, distributed registry, or third-party revocation service in this prototype.

## Sandbox proof

`sandbox-proof` verifies a trusted `FED_RECEIPT`, then a signed `local.sandbox.v1` proof inside the receipt. The proof binds task id, authority Zone, worker, policy digest, sandbox claim, and sandbox evidence. Evidence must include mode, isolation level, network surface, command digest, binary digest, and transcript digest.

The current verifier-owned class is `local-process`. Stronger required classes such as `remote-attestation` fail closed unless matching signed evidence exists.

## Sandbox attestation

`sandbox-attestation` verifies `asp-sandbox-attestation/v1` evidence from a trusted descriptor with `sandbox.attest` capability. Evidence binds receipt digest, task id, sandbox digest, sandbox claim, policy digest, sandbox class, runtime identity, timestamp, attestor descriptor, attestation digest, and attestor signature.

It proves signed attestation evidence only. It is not hardware remote attestation, container namespace execution, VM isolation, or a TEE quote.

## Package and release trust

Package proof signs local npm tarball evidence: file list, tarball path, size, npm shasum, npm integrity, ASP SHA-256, proof digest, signer identity, and `package.proof.sign` capability.

Release trust signs an ASP-native `asp-release-trust/v1` manifest over the existing package proof artifact. It binds package name, version, filename, tarball, SHA-256, size, package proof digest, release signer identity, release timestamp, and file list. It is not CycloneDX, SPDX, SLSA provenance, npm registry signing, package publish, release transparency, or a generic supply-chain platform.

## Verification boundary

Trust is established only by verifier inputs and signed evidence. Missing stores, missing descriptors, unsafe task ids, malformed lists, bad signatures, stale evidence, unsupported sandbox classes, and mismatched digests reject before a capability is accepted.
