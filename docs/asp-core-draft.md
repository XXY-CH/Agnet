# ASP Core Draft

Status: Draft 0, implementation-backed.

ASP Core is the narrow proof layer of Agent Space Protocol. It defines the minimum objects a third party needs to verify an agent task: identity, signed task, receipt, artifacts, and audit evidence.

This draft describes the local-first prototype at `v13.13-protocol`. It is not a full Agent Space product spec.
Previous public draft baseline: local-first prototype at `v12.45-protocol`.

## Scope

ASP Core covers:

- Agent and Zone identifiers.
- Ed25519 descriptor signatures.
- `FED_TASK_OPEN` frames.
- `FED_RECEIPT` frames.
- Artifact references and `artifact_manifests`.
- Receipt verification.
- Local artifact byte verification.
- Audit hash chain evidence.

The implementation-backed rotation and alias rebinding proof verifiers reject missing proof and descriptor objects before field reads.

The implementation-backed boolean proof verifiers return false for malformed descriptor inputs instead of leaking parser errors.

The implementation-backed Zone binding verifier rejects missing binding context and descriptor objects before field reads.

The implementation-backed Zone revocation verifiers reject missing revocation context, descriptor, and revocation-list objects before field reads.

The implementation-backed capability credential helpers reject missing credential and status proof objects before field reads.

The implementation-backed artifact manifest helpers reject missing receipt and manifest objects before field reads.

The implementation-backed `did:key` bridge helpers reject missing descriptor/public-key and DID string inputs before field reads or buffer parsing.

The implementation-backed verifier checks Zone descriptor object presence before reading descriptor fields. This is a fail-closed trust-boundary guard, not a generic schema validation layer.

Trusted Zone files MUST contain a Zone descriptor list, either as `{ "zones": [...] }` or as a raw descriptor array. Missing lists fail before entry iteration.

Registry files MUST contain agent descriptor entries, either as an `agents` list of entries with descriptors or as a raw descriptor array. Missing lists, entries, or descriptors fail before registry field reads.

Agent resolution requires registry context with a lookup surface before reading registry entries.

ASP Core does not cover:

- Automatic scheduling and decomposition.
- Opaque semantic routing.
- Global reputation.
- Payments.
- Public discovery.
- DID document resolution.
- Remote artifact fetch.
- Receipt stores.
- Batch verification.
- Product UI.
- A2A compatibility is out of scope for this draft.

## Identity

aid: is the canonical Agent identifier.

An Agent Descriptor binds:

- `aid`
- `alias`
- `public_key_spki`
- `capabilities`
- `transports`
- `policy`
- `signature`

The descriptor signature is made by the Agent key over the descriptor body.

Descriptor body helpers MUST receive descriptor objects before removing signature fields.

Verifiers reject descriptors whose `public_key_spki` is missing before handing the descriptor to Node crypto parsing.

Shared object signature verification returns false for missing, empty, or non-string signatures before handing them to Node crypto parsing.

did:key is an Ed25519 bridge field, not canonical identity.

If a descriptor includes `did_key`, verifiers MUST check that it derives from the same Ed25519 `public_key_spki`. Verifiers MUST NOT replace `aid:` with `did:key` when checking task or receipt identity.

## Zone

A Zone Descriptor binds:

- `zid`
- `name`
- `public_key_spki`
- `signature`

Federated verification starts by checking that the sender Zone is trusted. A trusted Zone entry is matched by `zid` and public key.

Zone binding links an agent alias to an Agent ID inside a Zone:

```json
{
  "zone": "zid:ed25519:...",
  "alias": "agent://zone/summarizer",
  "aid": "aid:ed25519:...",
  "signature": "..."
}
```

Verifiers MUST reject a binding if the Zone, alias, Agent ID, or signature does not match the resolved descriptor.

## Signed Task

A task is the unit of work.

Minimum implemented fields:

- `task_id`
- `from`
- `to`
- `intent`
- `scope`
- `budget`
- `signature`

The requester signs the task body without `signature`.

`task_id` is currently constrained to the implemented token format `^[A-Za-z0-9._:-]{1,128}$`.

Verifiers MUST check:

- `task_id` matches the implemented token format.
- `from` matches the requester Agent ID.
- The requester signature is valid.
- The target worker descriptor resolves from `to`.
- Worker policy allows the requested scope.
- Go `FED_TASK_OPEN` policy enforcement rejects malformed signed task `scope.write` list entries before execution.
- Go `FED_TASK_OPEN` policy enforcement rejects malformed signed task `scope.data_domains` list entries before recording policy evidence.
- Go `FED_TASK_OPEN` policy enforcement rejects malformed worker policy `approval_required` list entries before tool approval gates can be skipped.
- Go receipt verification rejects malformed `policy_scope` `write`, `tools`, `data_domains`, and `approval_required` list entries before accepting signed policy evidence.
- Go receipt verification rejects malformed `policy_scope.network` and `policy_scope.expires_at` scalar fields before accepting signed policy evidence.
- Node and Go receipt verification reject unsafe signed receipt `task_id` values before accepting receipt evidence.

## FED_TASK_OPEN

`FED_TASK_OPEN` carries a signed task across a federation boundary.

Implemented frame shape:

```json
{
  "type": "FED_TASK_OPEN",
  "origin_zone": {},
  "requester": {},
  "requester_zone_binding": {},
  "task": {}
}
```

Receivers MUST verify:

- The frame is an object whose `frame.type` is `FED_TASK_OPEN`.
- The origin Zone descriptor is present as an object and verifies.
- A trusted Zone store is present for origin Zone lookup.
- The requester descriptor is present as an object.
- The signed task object is present as an object.
- The local worker descriptor context is present as an object.
- The local worker descriptor identity verifies before task target and policy checks.
- The task signature is present as a string.
- `requester_zone_binding` binds `requester.alias` and `requester.aid` to `origin_zone`.
- The requester task signature.
- The worker selected by `task.to`.
- The worker policy.

## FED_RECEIPT

`FED_RECEIPT` returns signed execution evidence.

Implemented frame shape:

```json
{
  "type": "FED_RECEIPT",
  "zone": {},
  "worker": {},
  "zone_binding": {},
  "receipt": {}
}
```

Minimum implemented receipt fields:

- `task_id`
- `task_digest`
- `from`
- `to`
- `origin_zone`
- `executing_zone`
- `artifact_refs`
- `artifact_manifests`
- `event_count`
- `signature`

The worker signs the receipt body without `signature`.

`task_digest` is the SHA-256 digest of the canonical signed task object, encoded as 64 lowercase hex characters. Current verifiers require this field to be present and well formed. When signed task evidence is supplied, verifiers compare its canonical digest to `receipt.task_digest`. They do not yet look up the original task from an external task store.

Verifiers MUST check:

- The frame is an object whose `frame.type` is `FED_RECEIPT`.
- The signing Zone descriptor is present as an object and trusted.
- A trusted Zone store is present for signing and origin Zone lookup.
- The worker descriptor is present as an object.
- The worker descriptor identity verifies before receipt identity and signature checks.
- The receipt body is present as an object.
- The receipt signature is present as a string.
- The Zone binding resolves the worker alias and Agent ID.
- `receipt.executing_zone` matches the signing Zone.
- `receipt.task_id` matches the implemented token format.
- `receipt.task_digest` is a 64-hex digest and matches supplied signed task evidence when present.
- `receipt.to` matches the worker Agent ID.
- The worker receipt signature is valid.
- Go receipt verification rejects malformed `approvals` and `approval_grants` list entries before approval grant count and signature checks.
- Go Human Gateway queue action grants reject malformed signed `scope.actions` list entries before accepting queue action authorization scope.
- Go receipt verification rejects malformed `checkpoint_refs` and `checkpoints` list entries before checkpoint count, parent, and signature checks.
- Go checkpoint lookup for resume rejects malformed receipt `checkpoint_refs` and `checkpoints` list entries before accepting a receipt-carried checkpoint.
- Go receipt artifact lookup rejects malformed `artifact_refs` and `artifact_manifests` list entries before returning a receipt-carried artifact manifest.
- `artifact_refs` and `artifact_manifests` match when manifests are present.

## Artifacts

Artifacts are referenced by URI. The implemented local URI form is:

```text
artifact://local/<task-id>/<name>
```

Local artifact byte verification MUST reject missing, non-`artifact://local/`, or path-escaping manifest URIs before filesystem reads.

Filesystem audit artifact verification MUST reject malformed manifest `sha256` values before constructing digest-addressed sidecar or mirror paths.

Receipt artifact manifest verification MUST reject malformed manifest `uri` and `sha256` values before accepting signed artifact metadata.

Receipt and audit artifact manifest verification MUST reject negative or non-integer manifest `size` values before accepting signed artifact metadata or comparing local bytes.

Node and Go receipt artifact manifest verification MUST reject non-string manifest `uri` values before accepting signed artifact metadata. Go audit artifact verification applies the same URI shape check before reading local bytes.

Go receipt and audit artifact manifest verification MUST reject present non-string manifest `afp` values before comparing AFP strings. When present, `afp` MUST equal `afp:sha256:<sha256>`.

Go receipt and audit artifact manifest verification MUST reject non-string manifest `media_type` values before accepting signed artifact metadata or comparing local bytes. Node already enforces string manifest fields in the shared artifact manifest helper.

Go receipt and audit artifact manifest verification MUST reject non-string manifest `manifest_hash` values before accepting signed artifact metadata or comparing local bytes. Node already enforces string manifest fields in the shared artifact manifest helper.

Node and Go receipt artifact manifest verification MUST reject malformed `artifact_refs` and `artifact_manifests` list entries instead of silently accepting non-string refs or non-object manifests. Go audit artifact verification applies the same list-shape checks before reading local bytes. This is an artifact verifier boundary, not a generic list parsing rule for every helper.

Go filesystem artifact mirror index verification MUST match index fields against receipt artifact manifest fields without string coercion. A mirror `objects.ndjson` entry with `"size":"7"` MUST NOT satisfy a manifest with numeric `size: 7`.

Go filesystem artifact mirror index readers MUST reject non-object `objects.ndjson` entries such as `null` instead of silently treating them as unmatched index rows.

Go filesystem artifact mirror index readers MUST reject index entries whose `sha256` field is missing or not a 64-hex digest before the value can be used for mirror or GC paths.

Go filesystem artifact mirror index readers MUST reject present `uri` values that are not strings.

Go filesystem artifact mirror index readers MUST reject present non-string `afp` values before comparing AFP strings. Present string `afp` values MUST equal `afp:sha256:<sha256>` for that row.

Go filesystem artifact mirror index readers MUST reject present `size` values that are not non-negative integers.

Go filesystem artifact mirror index readers MUST reject present `media_type` values that are not strings.

Go filesystem artifact mirror index readers MUST reject present `manifest_hash` values that are not 64-hex digests before those rows can be preserved as mirror or GC proof metadata.

An artifact manifest binds:

- `uri`
- `sha256`
- `size`
- `media_type`
- `afp`
- `manifest_hash`

`afp` is currently the interoperable artifact fingerprint string `afp:sha256:<sha256>`.

`manifest_hash` is the SHA-256 digest of the canonical manifest body without `manifest_hash`.

Verifiers MUST reject:

- Missing required manifest fields.
- Malformed manifest URI fields.
- Manifest URI mismatch.
- Manifest count mismatch.
- AFP mismatch when `afp` is present.
- Manifest hash mismatch.
- Local sidecar mismatch.
- Local byte size mismatch.
- Local byte digest mismatch.

## Transport Proof

Go server-mode task receipts MAY include `transport_proof` when the receipt was produced by a configured federation listener.

The implemented public-listen proof binds the following fields into the worker-signed receipt body:

- `transport`
- `listen_host`
- `port`
- `public_transport`

This is local accountability evidence for the configured listener used by the proof. It is not an external public reachability proof, endpoint discovery protocol, DID service endpoint, TLS/QUIC upgrade, or hosted-node guarantee.

## Audit

The audit log is JSONL plus an audit hash chain.

Each append links to the previous audit head. Verifiers check that entries preserve the chain and that receipt or artifact evidence can be tied back to the audited task.

The audit hash chain is accountability evidence, not a global consensus layer.

## Swarm Close

`FED_SWARM_CLOSE` binds a Swarm id to a signed list of completed step receipts.

The implemented Node verifier checks the close frame object and type, trusted Zone store presence, signing Zone object and descriptor, close proof object, close signature presence and verification, the signed Swarm id, the frame/body Swarm id match, and the structure of `step_receipts`. It requires at least one step receipt, requires each step receipt to be an object with `step_id`, a safe `task_id` token, and a 64-hex `receipt_digest`, and rejects duplicate or NUL-bearing Swarm identities.

This Node verifier is not an audit-backed completeness verifier. The audit-backed same-log Swarm completeness checks are implemented on the Go verifier path.

Go audit-backed Swarm dependency verification MUST reject malformed `after` and `input_artifacts` list entries instead of silently filtering them before dependency count and digest checks.

Go `FED_SWARM_OPEN` execution MUST reject malformed step `after` list entries before executing dependent steps.

Go audit-backed Swarm close proof verification MUST reject malformed `step_receipts` list entries instead of silently filtering them before close step count, order, task, and digest checks.

`FED_SWARM_SCHEDULE` accepts a signed Swarm DAG and executes steps in deterministic ready order. Each scheduled step reuses `FED_TASK_OPEN` task verification and the existing Swarm receipt dependency evidence. The close proof may include signed scheduler evidence with `mode: "ready-dag"` and the executed `step_order`. This is scheduler-owned DAG execution only, not automatic task decomposition, not parallel execution, not upper-layer master-agent orchestration, and not economic settlement.

## Verification Commands

Implemented Node checks:

```bash
bash scripts/proof-demo.sh
bash scripts/docker-proof-demo.sh
bash scripts/public-node-proof.sh
node scripts/package-proof.mjs
node asp-verify.mjs artifact <manifest.json>
node asp-verify.mjs fed-receipt <frame.json> <trusted-zones.json> [task.json]
node asp-verify.mjs fed-receipt-artifacts <frame.json> <trusted-zones.json> [task.json]
node asp-verify.mjs swarm-close <frame.json> <trusted-zones.json>
node asp-verify.mjs package-proof <manifest.json>
node asp-verify.mjs release-trust <release-trust.json> [trusted-release-signers.json]
node asp-verify.mjs proof-bundle <bundle.json> [external-trusted-zones.json]
node scripts/external-reachability-observer.mjs <bundle.json> <observed-bundle.json> <observer-trusted-zones.json> <container|external-host>
bash scripts/docker-external-reachability-observer.sh <bundle.json> <observed-bundle.json> <observer-trusted-zones.json>
```

The verifier CLI commands reject unsupported extra positional arguments. The optional task evidence commands accept only the no-task and one-task forms.

Go protocol signing, signature verification, and digest paths MUST use canonical JSON without HTML escaping for `<`, `>`, and `&`, matching the Node `canonical()` behavior for signed and digested protocol objects. The Go verifier MUST accept receipts and supplied signed task evidence containing these characters when the evidence was signed with the Node canonical byte string.

For `proof-bundle`, the signed receipt transport proof MUST be an object and MUST carry `transport: "fed+tcp"`, non-loopback non-unspecified `listen_host`, decimal-string `port`, and `public_transport: true`. This is local federation-listener evidence until trusted observer evidence upgrades the verifier-owned reachability scope.

The `proof-bundle` verifier reports `reachability_scope: "local-interface"` when no external reachability evidence is supplied and rejects bundle manifests that supply their own `reachability_scope`. With trusted observer evidence, it reports `reachability_scope: "container-observer"` for `vantage: "container"`, or `reachability_scope: "external-host"` for `vantage: "external-host"` only when the signed receipt `listen_host` is a globally routable literal IP. Hostname listen hosts are out of scope for `external-host` in this slice. Observer-backed scopes return `reachability_observer_zid`.

When `proof-bundle` receives an additional caller-supplied trusted-Zone file, it MAY accept `bundle.external_reachability` evidence signed by a trusted observer Zone. The evidence MUST bind `proof: "external-reachability"`, `observer_zid`, `vantage`, `observed_host`, `observed_port`, `observed_at`, `transport_proof`, `receipt_digest`, and `reached: true`; the verifier rejects stale, future, wrong-endpoint, wrong-digest, invalid-vantage, untrusted-observer, unsigned, and non-routable external-host evidence. A bundle that carries external reachability evidence without the extra trust input MUST fail closed. This is a verifier-owned evidence gate, not hosted-node deployment, NAT traversal, or completion of the real hosted external-host observer run.

`scripts/external-reachability-observer.mjs` is the minimal implemented observer writer for that evidence shape. It reads a proof bundle, verifies the bundle's signed receipt digest and transport proof match, TCP-connects to `transport_proof.listen_host:port`, records the requested vantage plus observed endpoint and freshness, and writes an observed bundle plus observer trusted-Zone file. `scripts/docker-external-reachability-observer.sh` runs the same observer from a Docker container using Docker's host gateway and `${AGNET_NODE_BASE_IMAGE:-node:22-bookworm-slim}` with container vantage. These scripts prove a TCP connection from wherever they are run; the Docker wrapper proves a container boundary, not hosted deployment, and specifically not hosted external-host reachability.

`scripts/public-node-proof.sh` can pass `AGNET_PUBLIC_LISTEN_HOST` through to the public-listen proof so a caller can bind an explicit globally routable literal IP, and `AGNET_PUBLIC_PROOF_KEEPALIVE_MS` can keep the listener alive after local proof generation while a hosted observer attempts the TCP connection. The `.github/workflows/hosted-reachability-observer.yml` Hosted Reachability Observer workflow decodes caller-supplied verifier-ready bundle files, runs the observer with `external-host`, and verifies the observed bundle. A recorded GitHub-hosted attempt, workflow run `28916288568`, failed with `ENETUNREACH` against the current IPv6 listener; the real hosted external-host observer run is still pending.

`FED_QUERY` may carry an `intent` string for semantic discovery. Ranking is deterministic and evidence-first: exact capability match, trusted capability credential, signed credential claims, receipt-count evidence, and semantic token overlap are exposed as inspectable evidence. The Go federation gateway FED_QUERY now accepts `intent` and returns ranked matches with `discovery_evidence` and `ranking` fields, mirroring the Node surface. For receipt-count reputation, receipt counts come from the persisted audit log; this is not a hardcoded demo value, not cross-session ML, not a global reputation oracle. The current implementation is token-overlap semantic discovery, not a vector database, not global reputation, not a public marketplace, and not scheduler integration.

Capability credentials may carry a `valid_until` ISO UTC expiry in claims; expired credentials lower discovery score and report `active: false` in discovery evidence. Credentials without `valid_until` keep the previous active behavior; malformed, unparseable, non-string, or past `valid_until` claims fail closed as inactive for discovery ranking.

authority Zone revocation in FED_QUERY discovery makes signed capability credentials inactive for revoked workers: revoked workers still expose trusted credential history when a signature exists, but `discovery_evidence.credential.active` becomes `false`, and revoked workers get no credential score boost. This is local authority Zone evidence checked by Node and Go query ranking, not network revocation sync, not a distributed registry, and not a third-party service.

The package proof manifest includes `proof_digest`, computed as `sha256(canonical(proof without proof_digest or signature))`. It also includes a package proof signer Agent descriptor and `signature`, signed over that same proof body by the signer key.

The package proof verifier command accepts `package-proof <manifest.json> [trusted-signers.json]` and checks the persisted package proof manifest against the generated tarball's byte SHA-256, npm SHA-1 shasum, npm SHA-512 integrity string, file size, canonical proof digest, signer descriptor, signer `package.proof.sign` capability, and package proof signature.

When a trusted signer file is supplied, it MUST be either a raw descriptor array or an object with a `signers` array. Null files and objects without signer lists fail with `trusted package signer list missing`. Trusted signer descriptors MUST also declare `package.proof.sign`.

The package proof verifier rejects `null` and array manifests before reading package proof fields.

The package proof verifier rejects unsafe tarball paths before reading tarball bytes. Absolute paths, backslashes, empty paths, `.` segments, and `..` segments are invalid.

The package proof verifier resolves safe tarball paths relative to the package proof manifest file. The package proof producer writes `tarball` and `manifest` as package-directory-relative file names so the generated package proof directory can be copied and verified from another working directory. This is local directory portability, not package signing, SBOM, or a public package release.

The package proof verifier requires `filename` to equal the final path segment of `tarball`. This prevents a manifest from presenting one package filename while verifying bytes from a different tarball path.

The package proof verifier requires `manifest` to equal the final path segment of the verifier input path. This prevents a package proof file from presenting one manifest filename while being verified through another file.

The package proof verifier requires `name`, `version`, and `filename` to be non-empty strings before package identity interpolation. It then requires `filename` to equal `<name>-<version>.tgz` for the current local npm package proof. This binds the proof's package identity metadata to the tarball filename without reading tarball members.

The package proof verifier rejects malformed packaged file lists before reading tarball bytes. The `files` field MUST be a non-empty array of unique safe relative paths; absolute paths, backslashes, empty segments, `.` segments, and `..` segments are invalid. This validates proof metadata shape; it is not a tarball member proof, package signature, or SBOM.

The package proof verifier requires `shasum`, `integrity`, and `sha256` to be non-empty strings and `size` to be a non-negative safe integer before reading tarball bytes.

The package proof verifier rejects npm `shasum` or `integrity` values that do not match the tarball bytes. This verifies npm-owned digest metadata.

After successful package proof verification, the verifier JSON returns the verified package name, version, filename, tarball path, size, npm shasum, npm integrity, ASP SHA-256, proof digest, and signer Agent ID.

The implemented package proof signature is an ASP object signature over local package proof metadata. It is not npm registry signing, release transparency, package publish, or SBOM.

The release trust producer command is `node scripts/release-trust.mjs`. It consumes the existing `state/package-proof/package-proof.json`, verifies that package proof first, then writes `state/package-proof/release-trust.json` as an ASP-native signed release-trust/SBOM manifest.

The release trust format is `asp-release-trust/v1`: not CycloneDX, not SPDX, not SLSA provenance, not npm registry signing, not package publish, not release transparency, and not a generic supply-chain platform. The repo is zero-dependency and refuses capability claims it cannot verify; emitting unvalidated CycloneDX would itself be an overclaim.

The release trust verifier command accepts `release-trust <release-trust.json> [trusted-release-signers.json]` and verifies the referenced package proof, the manifest-relative tarball bytes, package name, version, filename, tarball, SHA-256, size, packaged file list, package proof digest, release trust digest, release signer descriptor, release signer `release.trust.sign` capability, release trust signature, and optional trusted release signer pin.

Release trust staleness means `package_proof_digest` no longer matches the verified referenced package proof. Releases do not expire by elapsed time; `released_at` MUST be a valid UTC timestamp with the same ISO 8601 shape used by observed reachability evidence and MUST NOT be beyond the verifier's future skew allowance.

Trusted release signer pinning applies to the release signer only. It does not pin or replace the embedded package proof signer trust decision, because the release trust verifier verifies the referenced package proof as package proof evidence and then separately checks the release signer.

The sandbox proof verifier command is `node asp-verify.mjs sandbox-proof <frame.json> <trusted-zones.json> [required-sandbox-class]`. It first verifies the input as a trusted `FED_RECEIPT` frame, then verifies the embedded `local.sandbox.v1` proof signature using the receipt signing Zone, and checks task id, authority Zone, worker, policy digest, sandbox claim, and sandbox evidence binding.

The current sandbox proof verifier returns `sandbox_class: "local-process"` only for local-process sandbox evidence. It requires mode, isolation level, network surface, command digest, binary digest, and transcript digest evidence before accepting the proof. Passing `remote-attestation` as the required sandbox class fails closed unless future signed attestation evidence is implemented. This is not hardware remote attestation, not container namespace execution, and not a VM/TEE claim.

The sandbox attestation verifier command is `node asp-verify.mjs sandbox-attestation <frame.json> <trusted-zones.json> <attestation.json> <trusted-attestors.json>`. It verifies the trusted receipt and local sandbox proof first, then verifies `asp-sandbox-attestation/v1` signed evidence from a trusted attestor descriptor with `sandbox.attest` capability.

Sandbox attestation evidence binds the receipt digest, task id, sandbox digest, sandbox claim, policy digest, sandbox class, runtime identity, observed timestamp, attestor descriptor, attestation digest, and attestor signature. Evidence is rejected when stale, future-dated, mismatched, unsigned, signed by an untrusted attestor, or signed by a descriptor without `sandbox.attest`. This proves signed attestation evidence only; it is not hardware remote attestation, not container namespace execution, and not a TEE quote.

The external reachability observer can use `AGNET_REACHABILITY_OBSERVER_SEED_HEX` to derive a stable observer Zone descriptor before it signs `external-reachability` evidence. This supports pre-pinned observer identity for a hosted observer; the real hosted external-host observer run is still pending.

Implemented Go checks:

```bash
go run ./cmd/go-fed-discovery --verify-receipt <receipt.json> [--verify-task <task.json>]
go run ./cmd/go-fed-discovery --verify-audit <audit.log>
```

Implemented Go package path:

```go
verifier.VerifyFederatedReceipt(frame, trustedZones)
```

## Conformance Evidence

The current cross-implementation fixtures are:

- `test-vectors/asp-v9.24-fed-task-open.json`
- `test-vectors/asp-v9.25-fed-receipt.json`
- `test-vectors/asp-v10.38-fed-swarm-close.json`

Node and Go both verify the task and receipt fixtures. Node verifies the Swarm close fixture; Go verifies audit-backed Swarm close behavior through integration tests.

## Version Boundary

This draft is intentionally narrow. It documents the proof layer already exercised by the repository tests and CLIs. Anything outside that verified surface belongs in a later ASP draft.
