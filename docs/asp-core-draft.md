# ASP Core Draft

Status: Draft 0, implementation-backed.

ASP Core is the narrow proof layer of Agent Space Protocol. It defines the minimum objects a third party needs to verify an agent task: identity, signed task, receipt, artifacts, and audit evidence.

This draft describes the local-first prototype at `v11.65-protocol`. It is not a full Agent Space product spec.

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

- Scheduling.
- Semantic routing.
- Reputation.
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
- `receipt.task_digest` is a 64-hex digest and matches supplied signed task evidence when present.
- `receipt.to` matches the worker Agent ID.
- The worker receipt signature is valid.
- Go receipt verification rejects malformed `approvals` and `approval_grants` list entries before approval grant count and signature checks.
- `artifact_refs` and `artifact_manifests` match when manifests are present.

## Artifacts

Artifacts are referenced by URI. The implemented local URI form is:

```text
artifact://local/<task-id>/<name>
```

Local artifact byte verification MUST reject missing, non-`artifact://local/`, or path-escaping manifest URIs before filesystem reads.

Filesystem audit artifact verification MUST reject malformed manifest `sha256` values before constructing digest-addressed sidecar or mirror paths.

Receipt artifact manifest verification MUST reject malformed manifest `sha256` values before accepting signed artifact metadata.

Receipt and audit artifact manifest verification MUST reject negative or non-integer manifest `size` values before accepting signed artifact metadata or comparing local bytes.

Go receipt and audit artifact manifest verification MUST reject non-string manifest `uri` values before comparing artifact refs or reading local bytes. Node already enforces string manifest fields in the shared artifact manifest helper.

Go receipt and audit artifact manifest verification MUST reject present non-string manifest `afp` values before comparing AFP strings. When present, `afp` MUST equal `afp:sha256:<sha256>`.

Go receipt and audit artifact manifest verification MUST reject non-string manifest `media_type` values before accepting signed artifact metadata or comparing local bytes. Node already enforces string manifest fields in the shared artifact manifest helper.

Go receipt and audit artifact manifest verification MUST reject non-string manifest `manifest_hash` values before accepting signed artifact metadata or comparing local bytes. Node already enforces string manifest fields in the shared artifact manifest helper.

Go receipt and audit artifact manifest verification MUST reject malformed `artifact_refs` and `artifact_manifests` list entries instead of silently filtering non-string refs or non-object manifests. This is an artifact verifier boundary, not a generic list parsing rule for every Go helper.

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
- Manifest URI mismatch.
- Manifest count mismatch.
- AFP mismatch when `afp` is present.
- Manifest hash mismatch.
- Local sidecar mismatch.
- Local byte size mismatch.
- Local byte digest mismatch.

## Audit

The audit log is JSONL plus an audit hash chain.

Each append links to the previous audit head. Verifiers check that entries preserve the chain and that receipt or artifact evidence can be tied back to the audited task.

The audit hash chain is accountability evidence, not a global consensus layer.

## Swarm Close

`FED_SWARM_CLOSE` binds a Swarm id to a signed list of completed step receipts.

The implemented Node verifier checks the close frame object and type, trusted Zone store presence, signing Zone object and descriptor, close proof object, close signature presence and verification, the signed Swarm id, the frame/body Swarm id match, and the structure of `step_receipts`. It requires at least one step receipt, requires each step receipt to be an object with `step_id`, a safe `task_id` token, and a 64-hex `receipt_digest`, and rejects duplicate or NUL-bearing Swarm identities.

This Node verifier is not an audit-backed completeness verifier. The audit-backed same-log Swarm completeness checks are implemented on the Go verifier path.

Go audit-backed Swarm dependency verification MUST reject malformed `after` and `input_artifacts` list entries instead of silently filtering them before dependency count and digest checks.

Go audit-backed Swarm close proof verification MUST reject malformed `step_receipts` list entries instead of silently filtering them before close step count, order, task, and digest checks.

## Verification Commands

Implemented Node checks:

```bash
bash scripts/proof-demo.sh
bash scripts/docker-proof-demo.sh
node asp-verify.mjs artifact <manifest.json>
node asp-verify.mjs fed-receipt <frame.json> <trusted-zones.json> [task.json]
node asp-verify.mjs fed-receipt-artifacts <frame.json> <trusted-zones.json> [task.json]
node asp-verify.mjs swarm-close <frame.json> <trusted-zones.json>
```

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
