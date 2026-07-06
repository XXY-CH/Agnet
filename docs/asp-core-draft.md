# ASP Core Draft

Status: Draft 0, implementation-backed.

ASP Core is the narrow proof layer of Agent Space Protocol. It defines the minimum objects a third party needs to verify an agent task: identity, signed task, receipt, artifacts, and audit evidence.

This draft describes the local-first prototype at `v11.4-protocol`. It is not a full Agent Space product spec.

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

- The origin Zone descriptor.
- The requester descriptor.
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

`task_digest` is the SHA-256 digest of the canonical signed task object, encoded as 64 lowercase hex characters. Current verifiers require this field to be present and well formed. They do not yet look up the original task from an external task store.

Verifiers MUST check:

- The Zone descriptor is trusted.
- The Zone binding resolves the worker alias and Agent ID.
- `receipt.executing_zone` matches the signing Zone.
- `receipt.task_digest` is a 64-hex digest.
- `receipt.to` matches the worker Agent ID.
- The worker receipt signature is valid.
- `artifact_refs` and `artifact_manifests` match when manifests are present.

## Artifacts

Artifacts are referenced by URI. The implemented local URI form is:

```text
artifact://local/<task-id>/<name>
```

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

The implemented Node verifier checks the signing Zone, the close signature, the frame/body Swarm id match, and the structure of `step_receipts`. It requires at least one step receipt and each step receipt must include `step_id`, `task_id`, and a 64-hex `receipt_digest`.

This Node verifier is not an audit-backed completeness verifier. The audit-backed same-log Swarm completeness checks are implemented on the Go verifier path.

## Verification Commands

Implemented Node checks:

```bash
bash scripts/proof-demo.sh
bash scripts/docker-proof-demo.sh
node asp-verify.mjs artifact <manifest.json>
node asp-verify.mjs fed-receipt <frame.json> <trusted-zones.json>
node asp-verify.mjs fed-receipt-artifacts <frame.json> <trusted-zones.json>
node asp-verify.mjs swarm-close <frame.json> <trusted-zones.json>
```

Implemented Go checks:

```bash
go run ./cmd/go-fed-discovery --verify-receipt <receipt.json>
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
