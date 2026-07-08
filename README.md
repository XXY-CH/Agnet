# Agnet

Agnet is an accountability layer for agent work.

MCP makes tools callable. A2A and similar protocols coordinate agents. Agnet focuses on the missing proof layer: after an agent does work, a third party should be able to verify what was requested, who accepted it, what policy applied, which sandbox was claimed, which artifacts were produced, and which audit entry anchored the receipt.

Status: research prototype, local-first, v13 active at `v13.15-protocol`.
Historical baseline: v12 closed at `v12.45-protocol`.

## Why This Exists

Agent systems are starting to coordinate across tools, runtimes, and organizations. Coordination is not enough. The hard question is accountability:

- Which identity signed the task?
- Which worker executed it?
- Which policy and approval evidence allowed it?
- Which artifact bytes were produced?
- Which sandbox claim was made, and was it honestly supported?
- Can the receipt be verified without trusting the original server?
- Can the audit history detect tampering?

Agnet is the narrow proof layer for those questions.

## Current Shape

Agnet currently includes two implementations:

- Node prototype runtime and federation gateway.
- Go gateway with Human Gateway UI, task execution, receipts, artifact verification, queue actions, sandbox evidence, TLS/mTLS, and audit verification.

The current prototype proves:

- Ed25519 `aid:` agent identity and Zone identity with descriptor body object presence validation, registry file shape validation, Zone descriptor object presence validation, Zone binding object presence validation, Zone revocation object presence validation, descriptor public key presence validation, and object signature type validation before crypto parsing.
- Ed25519 `did:key` bridge fields for descriptors, with missing-input validation and without replacing `aid:`.
- Signed tasks, events, artifacts, checkpoints, and receipts.
- `FED_TASK_OPEN` verifies frame object/type, origin Zone descriptor and payload object presence, local worker descriptor context presence and identity validation, task signature presence, and requester Zone bindings at the federation boundary.
- Task ids are constrained to a small ASCII token format before execution or queue state, and malformed signed task write/data-domain scopes fail closed before execution.
- Hash-chained JSONL audit logs.
- Receipt and local artifact closure verification through Go and Node CLIs.
- Node receipt verifier CLI outputs and proof summary JSON include stable `receipt_digest` values for external reports.
- Node verifier CLI trusted-Zone files are signature-checked before use.
- Node receipt verifiers reject missing/non-`FED_RECEIPT` frames, missing signing Zone, worker, receipt body objects, invalid worker descriptor identity, or receipt signatures, Go receipt verifiers reject non-`FED_RECEIPT` frames, and signed receipts whose `origin_zone` is not trusted fail closed.
- Node task, receipt, and Swarm close verifiers reject missing trusted Zone stores before reading trust entries; the Node task-open verifier also rejects missing local worker descriptor context before reading the worker alias.
- Node trusted Zone files reject missing Zone lists before reading entries and preserve raw descriptor-array inputs.
- Node registry files reject missing agent lists, missing entries, and missing descriptors before reading registry fields.
- Node agent resolution rejects missing registry context before reading registry entries.
- Node rotation and alias rebinding proof verifiers reject missing proof/descriptor objects and malformed descriptor inputs before field reads or crypto parsing.
- Node Zone binding verifiers reject missing binding context/descriptor objects before field reads.
- Node Zone revocation verifiers reject missing revocation context/descriptor/list objects before field reads.
- Node capability credential and credential status helpers reject missing proof objects and malformed authority/subject descriptor inputs before field reads or crypto parsing.
- Node `FED_RECEIPT` verification now checks optional receipt-carried checkpoint evidence: `checkpoint_refs` and `checkpoints` list shape, list count, task binding, parent chain, ref matching, and worker `checkpoint_signature`; `asp-verify.mjs fed-receipt` fails closed on malformed checkpoint evidence.
- Node and Go receipt verifiers require `task_digest` as a compact anchor to the signed task object, Node and Go receipt verification reject unsafe receipt task ids, Go protocol signing and digest verification use no-HTML-escape canonical JSON for `<>&` parity with Node, Node receipt verification rejects malformed artifact manifest URI/ref shapes, receipt artifact verification rejects malformed artifact manifest URIs, malformed artifact manifest SHA-256 values, non-integer or negative manifest sizes, malformed Go manifest AFP strings, malformed Go manifest media types or manifest hashes, malformed Go artifact list entries, type-coerced Go mirror index entries, null Go mirror index entries, missing Go mirror index SHA-256 values, unsafe Go mirror index SHA-256 values, unsafe Go mirror index manifest hashes, invalid Go mirror index AFP values, mismatched Go mirror index AFP strings, invalid Go mirror index sizes, invalid Go mirror index media types, and invalid Go mirror index URIs, and Node receipt/artifact CLIs, the Go receipt CLI, and bidirectional Node/Go interop checks can compare task digests against supplied or in-memory signed task evidence.
- Minimal npm-facing package contract for the existing Node verifier CLI and `asp-core.mjs` exports, plus an npm tarball proof that emits and persists package filename, size, SHA-1 shasum, SHA-512 integrity, ASP-style SHA-256, canonical `proof_digest`, packaged file list, a package proof verifier command, package proof manifest object validation, package proof tarball path safety, manifest-relative package tarball verification, npm shasum/integrity verification, verified package metadata output, package filename/tarball binding, packaged file list shape validation, package manifest filename binding, package identity filename binding, and package proof signer capability validation.
- Release trust/SBOM evidence in ASP-native `asp-release-trust/v1` format, with `scripts/release-trust.mjs` consuming the existing package proof artifact, `asp-verify.mjs release-trust <release-trust.json> [trusted-release-signers.json]` verifying package proof binding, tarball bytes, release signer capability, release signature, trusted release signer pins, package proof digest freshness, package name/version/filename/tarball/size/SHA-256/file-list binding, and invalid timestamp/unsafe-path/mismatch/unsigned/wrong-signer/untrusted-signer negative gates; this is not CycloneDX, not SPDX, not SLSA provenance, not npm registry signing, not package publish, not release transparency, and not a generic supply-chain platform.
- Sandbox proof verification through `asp-verify.mjs sandbox-proof <frame.json> <trusted-zones.json> [required-sandbox-class]`, which verifies a signed `local.sandbox.v1` proof inside a trusted `FED_RECEIPT`, checks the proof is bound to task, authority, worker, policy, claim, and sandbox evidence, requires command/binary/transcript digest evidence, returns verifier-owned `sandbox_class: "local-process"`, and fails closed when `remote-attestation` is required without signed attestation evidence.
- Signed sandbox attestation verification through `asp-verify.mjs sandbox-attestation <frame.json> <trusted-zones.json> <attestation.json> <trusted-attestors.json>`, which verifies `asp-sandbox-attestation/v1` evidence from a trusted `sandbox.attest` signer, binds it to the same receipt digest, task id, sandbox digest, sandbox claim, policy digest, and freshness window, and still reports `hardware_attestation: false`.
- Evidence-first semantic discovery/reputation ranking in the Node federation gateway, where `FED_QUERY` may carry an intent string and returns inspectable identity, capability, credential, audit-backed reputation, and ranking evidence; semantic-only candidates cannot outrank exact capability candidates with trusted credential and reputation evidence. The Go federation gateway now closes semantic parity by ranking candidates with exact-match, credential trust, receipt count, and semantic intent overlap while returning `discovery_evidence` and `ranking` per match. In v13.14, `discovery_evidence.reputation` includes `completed_receipts`, `last_completed_at`, `revocation_count`, and labelled `agent_score` components: `receipt_score`, `credential_score`, `freshness_score`, and `revocation_penalty`.
- Capability credentials may carry a `valid_until` ISO UTC expiry in claims; expired credentials lower discovery score and report `active: false` in discovery evidence.
- Authority Zone revocation in FED_QUERY discovery sets `discovery_evidence.credential.active: false`; revoked workers lose credential contribution in `agent_score`, while signed credentials remain inspectable as trusted history.
- Scheduler-owned ready-DAG Swarm execution in the Go federation gateway, where `FED_SWARM_SCHEDULE` accepts out-of-order signed DAG steps, executes them in dependency-ready order, and signs close proof scheduler evidence with the executed step order.
- One-command proof demo, Docker proof demo, Docker public-listen proof, and Docker external reachability observer wrapper that emit or consume verifier-ready receipt/trust files, expose receipt digests, verified artifact counts, verified artifact URIs, verified artifact byte digests, verified artifact manifest hashes, signed transport proof fields, and signed reachability evidence fields, verify local artifact closure, and support base-image override env vars for restricted Docker environments.
- The proof-bundle verifier owns three reachability scopes: `local-interface` without observer evidence, `container-observer` when trusted observer evidence has `vantage: "container"`, and `external-host` only when trusted observer evidence has `vantage: "external-host"` and a globally routable literal-IP `listen_host`; valid observer evidence binds `vantage`, `observed_host`, `observed_port`, `observed_at`, the same transport proof, the same receipt digest, and returns `reachability_observer_zid`.
- The external reachability observer can use `AGNET_REACHABILITY_OBSERVER_SEED_HEX` for a pre-pinned observer identity before a hosted run; the real hosted external-host observer run is still pending.
- Public-listen proof script that starts the Go federation gateway on a non-loopback host or explicit `AGNET_PUBLIC_LISTEN_HOST`, can keep the listener alive with `AGNET_PUBLIC_PROOF_KEEPALIVE_MS` for hosted observation, proves `public_transport: true`, completes authenticated `FED_RESOLVE`, `FED_QUERY`, `FED_TASK_OPEN`, `FED_AUDIT_QUERY`, `FED_ARTIFACT_READ`, and `FED_SWARM_OPEN` round trips, verifies fetched artifact bytes, proves out-of-receipt and post-receipt-tampered artifact reads are rejected, confirms the signed task receipt includes the gateway transport proof, writes and verifies an object-shaped proof bundle manifest with type-checked, preflighted, bundle-relative, and traversal-safe proof file paths, plus required signed `fed+tcp` / non-loopback non-unspecified `listen_host` / `port` / `public_transport: true` proof via `asp-verify.mjs proof-bundle <bundle.json> [external-trusted-zones.json]`, rejects bundle-supplied `reachability_scope`, returns `proof_bundle_verify`, and writes a two-step Swarm close proof frame plus trusted Zone file with a reproducible close digest and summary `swarm_close_verify` result from the Node CLI.
- The Hosted Reachability Observer GitHub Actions workflow can run the signed external-host observer and proof-bundle verifier from a hosted runner using caller-supplied verifier-ready bundle files and a pinned observer seed. Workflow run `28916288568` reached the hosted observer step but failed with `ENETUNREACH` against the current IPv6 listener, so the real hosted external-host observer run is still pending.
- Historical v12 reachability wording remains true at its narrower level: proof-bundle can return `reachability_scope: "external-host"` only for trusted signed external reachability evidence; v13.1 additionally splits container-observer from external-host and requires a globally routable literal-IP `listen_host` for the current external-host scope.
- Node artifact manifests, AFP strings, sidecars, local URI/path validation, local byte verification, CLI verification, object presence validation, and manifest metadata verification; Go filesystem artifact manifests, AFP strings, strict artifact ref/manifest list entries and artifact lookup, mirror index object-entry, required SHA-256, URI, AFP, size, media type, manifest-hash digest, and exact field matching validation, SHA-256, size, media type, and manifest hash field validation before digest-addressed path or byte checks, content-addressed mirrors, and GC plan/apply.
- Human approval evidence for direct and queued execution, with malformed receipt approval evidence list rejection, receipt policy scope list rejection, receipt policy scope scalar rejection, and worker policy approval-required list rejection.
- Protocol-native checkpoint evidence, with malformed receipt checkpoint evidence list rejection and runtime lookup rejection.
- Explicit queue claim, lease expiry, reclaim, retry, resume, and drain flows, with signed queue action grant scope list validation.
- Sandbox claim binding and fail-closed unsupported sandbox probes.
- Node to Go and Go to Node `FED_TASK_OPEN` interoperability.
- Shared `FED_TASK_OPEN`, `FED_RECEIPT`, and `FED_SWARM_CLOSE` conformance fixtures, including fail-closed checks for missing-frame, missing-zone, missing-proof, missing-signature, missing-identity, malformed-step, unsafe-task-id, NUL-bearing, empty, and duplicate-step Swarm close proofs.
- Minimal two-step `FED_SWARM_OPEN` with signed dependency evidence and malformed step dependency list rejection, plus `FED_SWARM_SCHEDULE` ready-DAG execution.
- Swarm audit verification for declared dependency steps, delimiter-safe step identity, malformed dependency list rejection, malformed close step receipt list rejection, artifact manifests, upstream receipt digests, and single ordered complete audit-backed Zone-signed close proofs over Swarms that appeared in the same audit.

It is not yet a production Agent Net, public federation network, DID-native identity layer, automatic decomposer, economic layer, or container-isolated runtime.

## Where Agnet Fits

| Layer | Examples | Agnet position |
| --- | --- | --- |
| Tool calling | MCP | Complements it by recording verifiable tool execution evidence. |
| Coordination | A2A, AGNTCY-style coordination | Complements it by signing task outcomes and receipts. |
| Identity and routing | ANP, DID ecosystems | Current core uses `aid:` Ed25519 identities and exposes a narrow `did:key` bridge. |
| Economy | Fetch.ai, Autonolas, on-chain markets | Out of scope for now; receipts could become settlement inputs later. |
| Accountability | Receipts, artifacts, audit, sandbox claims | Agnet's current focus. |

The intended strategy is not to replace MCP, A2A, ANP, or AGNTCY. The useful path is to make Agnet receipts small enough to attach to those systems.

## Quick Start

Prerequisites:

- Node.js with the built-in `node:test` runner.
- Go matching `go.mod`.

Run the smallest Node proof:

```bash
node mvp-demo.mjs
```

Run the one-command local proof demo:

```bash
bash scripts/proof-demo.sh
```

The script writes `state/proof-demo-fed-receipt.json` and `state/proof-demo-trusted-zones.json`, then verifies the receipt plus local artifact bytes with `asp-verify.mjs fed-receipt-artifacts`.

Run the Docker proof demo when Docker is available:

```bash
bash scripts/docker-proof-demo.sh
```

If Docker Hub access is flaky or restricted, override the base image:

```bash
AGNET_NODE_BASE_IMAGE=node:22-bookworm-slim bash scripts/docker-proof-demo.sh
```

Run the local public-listen proof:

```bash
bash scripts/public-node-proof.sh
```

Run the Docker public-listen proof when Docker is available:

```bash
bash scripts/docker-public-node-proof.sh
```

Its build-stage base images can be overridden with:

```bash
AGNET_GO_BASE_IMAGE=golang:1.26.1-bookworm AGNET_NODE_BASE_IMAGE=node:22-bookworm-slim bash scripts/docker-public-node-proof.sh
```

Run the external reachability observer in Docker against an existing proof bundle:

```bash
bash scripts/docker-external-reachability-observer.sh state/public-node-proof-bundle.json state/public-node-proof-observed-bundle.json state/public-node-proof-observer-trusted-zones.json
```

This wrapper uses Docker's host gateway and proves only the `container-observer` scope. It is not real hosted external-host reachability by itself; `external-host` also requires a globally routable literal-IP listen host, and hostname listen hosts are out of scope for this slice.

Run the full local verification suite:

```bash
go test ./...
node --test --test-concurrency=1 go-fed-discovery.test.mjs
node --test --test-concurrency=1 *.test.mjs
```

Run the minimal local Node runtime:

```bash
node agent-runtime.mjs worker
node agent-runtime.mjs request agent://local/summarizer
```

Run the Go sandbox probe:

```bash
go run ./cmd/go-fed-discovery --sandbox-probe container-namespace
```

The probe is expected to report unsupported container isolation unless a future container runtime slice implements it. The point is honest evidence, not overclaiming.

## Important Commands

Verify one receipt JSON record:

```bash
go run ./cmd/go-fed-discovery --verify-receipt path/to/receipt.json --verify-task path/to/task.json
```

Verify one Node `FED_RECEIPT` frame:

```bash
node asp-verify.mjs fed-receipt frame.json trusted-zones.json
```

Run the same verifier through the local npm package contract:

```bash
npm exec --package . -- asp-verify fed-receipt frame.json trusted-zones.json
```

Create a local npm package artifact proof:

```bash
node scripts/package-proof.mjs
```

Verify the local npm package artifact proof:

```bash
node asp-verify.mjs package-proof state/package-proof/package-proof.json
```

Verify one Node `FED_RECEIPT` frame plus its local artifact bytes:

```bash
node asp-verify.mjs fed-receipt-artifacts frame.json trusted-zones.json task.json
```

Verify one Node `FED_SWARM_CLOSE` frame signature and digest:

```bash
node asp-verify.mjs swarm-close frame.json trusted-zones.json
```

Verify one public proof bundle manifest:

```bash
node asp-verify.mjs proof-bundle state/public-node-proof-bundle.json
```

Verify one Node local artifact manifest:

```bash
node asp-verify.mjs artifact artifacts/task_001/summary.md.manifest.json
```

Verify an audit log:

```bash
go run ./cmd/go-fed-discovery --verify-audit --audit state/go-fed-audit.log
```

Start the Go federation gateway:

```bash
go run ./cmd/go-fed-discovery \
  --port 9090 \
  --ws-port 9091 \
  --human-port 8080
```

Optional hardening flags include:

- `--listen-host`
- `--tls-cert`
- `--tls-key`
- `--tls-client-ca`
- `--human-token`
- `--human-actor-policy`
- `--artifact-store`

## Repository Map

- `cmd/go-fed-discovery/main.go` - Go gateway, CLI verifier, Human Gateway, queue, Swarm seed.
- `verifier/` - reusable Go `FED_RECEIPT` frame verifier package.
- `scripts/proof-demo.sh` - one-command local proof demo.
- `scripts/docker-proof-demo.sh` - Docker wrapper for the local proof demo.
- `scripts/package-proof.mjs` - local npm tarball artifact proof.
- `scripts/release-trust.mjs` - ASP-native release trust/SBOM manifest over the local package proof artifact.
- `scripts/public-node-proof.sh` - local public-listen federation proof.
- `scripts/external-reachability-observer.mjs` - TCP observer that writes signed external reachability evidence for a proof bundle.
- `scripts/docker-public-node-proof.sh` - Docker wrapper for the public-listen federation proof.
- `scripts/docker-external-reachability-observer.sh` - Docker wrapper for the external reachability observer.
- `package.json` - local npm-facing verifier bin and Node export contract.
- `*.mjs` - Node prototype runtime, federation gateway, tests, and demos.
- `test-vectors/` - shared protocol vectors.
- `docs/implementation-status.md` - current capability matrix.
- `docs/agent-space-ultimate-vision.md` - long-range vision.
- `docs/agent-space-architecture.md` - architecture overview.
- `docs/asp-core-draft.md` - narrow English draft for the implemented proof layer.
- `docs/v13-roadmap.md` - active v13 roadmap.
- `docs/v13.0-boundary.md` - v13 opening boundary.
- `docs/v13.1-boundary.md` - v13.1 reachability scope boundary.
- `docs/v13.2-boundary.md` - v13.2 release trust/SBOM boundary.
- `docs/v13.4-boundary.md` - v13.4 semantic discovery/reputation ranking boundary.
- `docs/v13.5-boundary.md` - v13.5 scheduler-owned ready-DAG Swarm boundary.
- `docs/v13.6-boundary.md` - v13.6 sandbox proof verifier boundary.
- `docs/v13.7-boundary.md` - v13.7 signed sandbox attestation verifier boundary.
- `docs/v13.8-boundary.md` - v13.8 pinned external observer identity boundary.
- `docs/v13.9-boundary.md` - v13.9 hosted observer runner and IPv6 blocker boundary.
- `docs/v13.10-boundary.md` - v13.10 Go FED_QUERY semantic discovery parity boundary.
- `docs/v13.11-boundary.md` - v13.11 audit-backed receipt-count reputation boundary.
- `docs/v13.12-boundary.md` - v13.12 credential valid_until expiry boundary.
- `docs/v13.13-boundary.md` - v13.13 authority Zone revocation discovery boundary.
- `docs/v13.14-boundary.md` - v13.14 multi-signal agent score reputation boundary.
- `docs/v13.15-boundary.md` - v13.15 Node receipt checkpoint verification boundary.
- `docs/v12-roadmap.md` - closed v12 roadmap.
- `docs/v12.45-boundary.md` - latest closed boundary.
- `docs/v12.44-boundary.md` - package proof signer capability boundary.
- `docs/v12.43-boundary.md` - package proof byte metadata shape boundary.
- `docs/v12.42-boundary.md` - package proof identity shape boundary.
- `docs/v12.41-boundary.md` - package proof metadata preflight boundary.
- `docs/v12.40-boundary.md` - trusted signer list shape boundary.
- `docs/v12.39-boundary.md` - package proof trusted signer pin boundary.
- `docs/v12.38-boundary.md` - package proof ASP signature boundary.
- `docs/v12.37-boundary.md` - core substrate recenter boundary.
- `docs/v12.35-boundary.md` - Docker external reachability observer wrapper boundary.
- `docs/v12.34-boundary.md` - external reachability observer boundary.
- `docs/v12.33-boundary.md` - external reachability evidence gate boundary.
- `docs/v12.32-boundary.md` - Go canonical JSON HTML escape parity boundary.
- `docs/v12.31-boundary.md` - package proof identity filename binding boundary.
- `docs/v12.30-boundary.md` - package proof manifest filename binding boundary.
- `docs/v12.29-boundary.md` - package proof file list shape boundary.
- `docs/v12.28-boundary.md` - package proof filename binding boundary.
- `docs/v12.27-boundary.md` - package proof verified metadata output boundary.
- `docs/v12.26-boundary.md` - package proof npm digest verification boundary.
- `docs/v12.25-boundary.md` - package proof manifest-relative tarball boundary.
- `docs/v12.24-boundary.md` - package proof tarball path safety boundary.
- `docs/v12.23-boundary.md` - package proof manifest object boundary.
- `docs/v12.22-boundary.md` - package proof verifier command boundary.
- `docs/v12.21-boundary.md` - package proof digest boundary.
- `docs/v12.20-boundary.md` - package proof manifest boundary.
- `docs/v12.19-boundary.md` - package artifact SHA-256 boundary.
- `docs/v12.18-boundary.md` - package artifact proof boundary.
- `docs/v12.17-boundary.md` - proof bundle reachability scope ownership boundary.
- `docs/v12.16-boundary.md` - proof bundle reachability scope boundary.
- `docs/v12.15-boundary.md` - proof bundle unspecified host gate boundary.
- `docs/v12.14-boundary.md` - proof bundle listen host gate boundary.
- `docs/v12.13-boundary.md` - proof bundle federation transport gate boundary.
- `docs/v12.12-boundary.md` - proof bundle transport proof shape boundary.
- `docs/v12.11-boundary.md` - proof bundle public transport gate boundary.
- `docs/v12.10-boundary.md` - verifier CLI exact arity boundary.
- `docs/v12.9-boundary.md` - proof bundle exact CLI arity boundary.
- `docs/v12.8-boundary.md` - proof bundle CLI arity boundary.
- `docs/v12.7-boundary.md` - proof bundle path preflight boundary.
- `docs/v12.6-boundary.md` - proof bundle manifest object boundary.
- `docs/v12.5-boundary.md` - proof bundle type gate boundary.
- `docs/v12.4-boundary.md` - proof bundle path safety boundary.
- `docs/v12.3-boundary.md` - bundle-relative proof file paths boundary.
- `docs/v12.2-boundary.md` - public proof summary bundle verification boundary.
- `docs/v12.1-boundary.md` - proof bundle verifier command boundary.
- `docs/v12.0-boundary.md` - public proof bundle manifest boundary.
- `docs/v11-roadmap.md` - closed v11 roadmap.
- `docs/v11.79-boundary.md` - public transport receipt proof boundary.
- `docs/v11.78-boundary.md` - Node receipt artifact URI/ref shape boundary.
- `docs/v11.77-boundary.md` - Node receipt task id token boundary.
- `docs/v11.76-boundary.md` - Go receipt task id token boundary.
- `docs/v11.75-boundary.md` - Go receipt policy scope scalar shape boundary.
- `docs/v11.74-boundary.md` - Go receipt policy scope list shape boundary.
- `docs/v11.73-boundary.md` - Go worker approval required list shape boundary.
- `docs/v11.72-boundary.md` - Go task data domains list shape boundary.
- `docs/v11.71-boundary.md` - Go task write scope list shape boundary.
- `docs/v11.70-boundary.md` - Go queue grant scope list shape boundary.
- `docs/v11.69-boundary.md` - Go FED_SWARM_OPEN after list shape boundary.
- `docs/v11.68-boundary.md` - Go receipt artifact lookup list shape boundary.
- `docs/v11.67-boundary.md` - Go runtime checkpoint lookup list shape boundary.
- `docs/v11.66-boundary.md` - Go receipt checkpoint list shape boundary.
- `docs/v11.65-boundary.md` - Go receipt approval list shape boundary.
- `docs/v11.64-boundary.md` - Go Swarm close step list shape boundary.
- `docs/v11.63-boundary.md` - Go Swarm dependency list shape boundary.
- `docs/v11.62-boundary.md` - Go artifact mirror index AFP type boundary.
- `docs/v11.61-boundary.md` - Go artifact manifest AFP boundary.
- `docs/v11.60-boundary.md` - Go artifact manifest URI boundary.
- `docs/v11.59-boundary.md` - Go artifact mirror index URI boundary.
- `docs/v11.58-boundary.md` - Go artifact mirror index media type boundary.
- `docs/v11.57-boundary.md` - Go artifact mirror index size boundary.
- `docs/v11.56-boundary.md` - Go artifact mirror index AFP boundary.
- `docs/v11.55-boundary.md` - Go artifact mirror index manifest hash boundary.
- `docs/v11.54-boundary.md` - Go artifact mirror index digest presence boundary.
- `docs/v11.53-boundary.md` - Go artifact mirror index digest boundary.
- `docs/v11.52-boundary.md` - Go artifact mirror index entry boundary.
- `docs/v11.51-boundary.md` - Go artifact mirror index shape boundary.
- `docs/v11.50-boundary.md` - Go artifact list shape boundary.
- `docs/v11.49-boundary.md` - Go artifact manifest hash shape boundary.
- `docs/v11.48-boundary.md` - Go artifact media type shape boundary.
- `docs/v11.47-boundary.md` - receipt artifact size shape boundary.
- `docs/v11.46-boundary.md` - receipt artifact digest shape boundary.
- `docs/v11.45-boundary.md` - Go artifact digest path boundary.
- `docs/v11.44-boundary.md` - Node local artifact path boundary.
- `docs/v11.43-boundary.md` - Node local artifact URI boundary.
- `docs/v11.42-boundary.md` - Node proof verifier malformed descriptor fail-closed boundary.
- `docs/v11.41-boundary.md` - Node descriptor body object presence boundary.
- `docs/v11.40-boundary.md` - Node resolveAgent registry context boundary.
- `docs/v11.39-boundary.md` - Node registry file shape boundary.
- `docs/v11.38-boundary.md` - Node trusted Zone file shape boundary.
- `docs/v11.37-boundary.md` - Node Zone revocation object presence boundary.
- `docs/v11.36-boundary.md` - Node Zone binding object presence boundary.
- `docs/v11.35-boundary.md` - Node rotation proof object presence boundary.
- `docs/v11.34-boundary.md` - Node credential object presence boundary.
- `docs/v11.33-boundary.md` - Node artifact manifest object presence boundary.
- `docs/v11.32-boundary.md` - Node did:key input presence boundary.
- `docs/v11.31-boundary.md` - Node Zone descriptor object presence boundary.
- `docs/v11.30-boundary.md` - Node shared object signature fail-closed boundary.
- `docs/v11.29-boundary.md` - Node descriptor public key presence boundary.
- `docs/v11.28-boundary.md` - FED_RECEIPT worker descriptor identity boundary.
- `docs/v11.27-boundary.md` - FED_TASK_OPEN worker descriptor identity boundary.
- `docs/v11.26-boundary.md` - FED_TASK_OPEN and FED_RECEIPT signature presence boundary.
- `docs/v11.25-boundary.md` - FED_TASK_OPEN worker context presence boundary.
- `docs/v11.24-boundary.md` - Node trusted Zone store presence boundary.
- `docs/v11.23-boundary.md` - FED_TASK_OPEN and FED_RECEIPT payload object presence boundary.
- `docs/v11.22-boundary.md` - FED_TASK_OPEN and FED_RECEIPT Zone descriptor presence boundary.
- `docs/v11.21-boundary.md` - FED_TASK_OPEN and FED_RECEIPT frame object presence boundary.
- `docs/v11.20-boundary.md` - FED_SWARM_CLOSE frame object presence boundary.
- `docs/v11.19-boundary.md` - FED_SWARM_CLOSE step receipt object presence boundary.
- `docs/v11.18-boundary.md` - FED_SWARM_CLOSE signing Zone presence boundary.
- `docs/v11.17-boundary.md` - FED_SWARM_CLOSE close proof presence boundary.
- `docs/v11.16-boundary.md` - FED_SWARM_CLOSE close signature presence boundary.
- `docs/v11.15-boundary.md` - FED_SWARM_CLOSE step task id validation boundary.
- `docs/v11.14-boundary.md` - FED_SWARM_CLOSE NUL identity validation boundary.
- `docs/v11.13-boundary.md` - FED_SWARM_CLOSE Swarm identity presence boundary.
- `docs/v11.12-boundary.md` - FED_SWARM_CLOSE duplicate step validation boundary.
- `docs/v11.11-boundary.md` - FED_TASK_OPEN frame type validation boundary.
- `docs/v11.10-boundary.md` - FED_RECEIPT frame type validation boundary.
- `docs/v11.9-boundary.md` - Node-to-Go interop receipt task binding boundary.
- `docs/v11.8-boundary.md` - Go-to-Node interop receipt task binding boundary.
- `docs/v11.7-boundary.md` - Go receipt CLI task evidence boundary.
- `docs/v11.6-boundary.md` - artifact closure task evidence parity boundary.
- `docs/v11.5-boundary.md` - optional receipt task evidence verification boundary.
- `docs/v11.4-boundary.md` - receipt task digest binding boundary.
- `docs/v11.3-boundary.md` - task id token validation boundary.
- `docs/v11.2-boundary.md` - Swarm close structural validation boundary.
- `docs/v11.1-boundary.md` - requester Zone binding boundary.
- `docs/v11.0-boundary.md` - receipt origin trust boundary.
- `docs/v10-roadmap.md` - closed v10 roadmap.
- `docs/v10.47-boundary.md` - v10 closeout boundary.
- `docs/v9-roadmap.md` - closed v9 roadmap.

## Roadmap

v9 and v10 are closed. v11 is closed at `v11.79-protocol`, v12 is closed at `v12.45-protocol`, and v13 is active at `v13.15-protocol`. V13 is aimed at five larger Ultimate-facing evidence gates: real hosted/public reachability, release trust/SBOM, strong sandbox/remote attestation, semantic discovery/reputation ranking, and dynamic Swarm scheduling.

v13.15 closes Node receipt checkpoint verification: `verifyFederatedReceipt` and `asp-verify.mjs fed-receipt` now fail closed when receipt-carried `checkpoint_refs` and `checkpoints` have malformed list shape, mismatched count, wrong task binding, broken parent chain, ref mismatch, or invalid worker checkpoint signatures.

v13.14 closes multi-signal agent score in reputation: Node and Go `FED_QUERY` now enrich `discovery_evidence.reputation` with `last_completed_at`, `revocation_count`, and a labelled `agent_score` object. `ranking.score` now uses `agent_score.total` plus exact capability and semantic intent scores, so receipt, credential, freshness, and revocation effects remain inspectable inside reputation evidence.

v13.13 closes authority Zone revocation in FED_QUERY discovery: revoked workers report `discovery_evidence.credential.active: false`; revoked workers lose credential contribution in `agent_score`, while non-revoked workers keep the existing active credential behavior.

v13.12 closes credential validity windows: Capability credentials may carry a `valid_until` ISO UTC expiry in claims; expired credentials lower discovery score and report `active: false` in discovery evidence.

v13.10 closes Go FED_QUERY semantic parity: the Go federation gateway now ranks candidates by exact-match, credential trust, receipt count, and semantic intent overlap — matching the Node v13.4 surface.

v13.9 hosted observer runner support is complete as the latest reachability support slice: `scripts/public-node-proof.mjs` accepts `AGNET_PUBLIC_LISTEN_HOST` and `AGNET_PUBLIC_PROOF_KEEPALIVE_MS`, and the Hosted Reachability Observer workflow can run the signed external-host observer plus verifier from GitHub Actions. Workflow run `28916288568` failed with `ENETUNREACH` against the current IPv6 listener, so this is not a hosted reachability success. v13.8 pinned external observer identity is complete: `scripts/external-reachability-observer.mjs` can use `AGNET_REACHABILITY_OBSERVER_SEED_HEX` so verifier trust can be pinned before the observer runs. v13.7 signed sandbox attestation verification is complete as a verifier-owned evidence gate over trusted attestor signatures. v13.6 sandbox proof verification is complete as a verifier-owned local-process class gate with fail-closed required-class checks. v13.5 dynamic Swarm scheduling is complete as a Go ready-DAG primitive with scheduler evidence in close proof. v13.4 semantic discovery/reputation ranking is complete as a Node federation gateway primitive with inspectable ranking evidence. v13.2 release trust/SBOM is complete in ASP-native `asp-release-trust/v1` form. v13.1 reachability evidence gates are active: verifier-owned scope classes and observer evidence binding landed with tests; real hosted external-host evidence is still pending as the v13.1 exit criterion.

v13.11 closes audit-backed receipt-count reputation: Node and Go semantic discovery now count completed receipts from their persisted audit logs before ranking candidates. receipt counts come from the persisted audit log; this is not a hardcoded demo value, not cross-session learned scoring, and not a third-party reputation service.

The protocol tag advanced with v13.15 because it is the latest complete slice; upper-layer demo/master-agent orchestration plus A2A/ARD compatibility stay outside the current core.

The current v13.9 reachability support surface makes the hosted attempt reproducible without hiding the network boundary: set `AGNET_PUBLIC_LISTEN_HOST` to an explicit global literal IP, optionally set `AGNET_PUBLIC_PROOF_KEEPALIVE_MS` to keep the local proof listener alive, then dispatch the Hosted Reachability Observer workflow with the generated bundle files and a pinned observer seed. The first recorded run, `28916288568`, failed with `ENETUNREACH` from the GitHub-hosted runner to the current IPv6 listener. The runner exists, but the real hosted external-host observer run is still pending.

The current v13.8 reachability support surface keeps observer trust pre-pinnable: set `AGNET_REACHABILITY_OBSERVER_SEED_HEX` to a 32-byte hex Ed25519 seed before running `scripts/external-reachability-observer.mjs`, and the observer emits the same signed Zone descriptor and `observer_zid` each run. This gives a pre-pinned observer identity for a future hosted external-host run; the real hosted external-host observer run is still pending.

The current v13.7 sandbox attestation proof surface keeps attestation evidence separate from runtime claims: `asp-verify.mjs sandbox-attestation <frame.json> <trusted-zones.json> <attestation.json> <trusted-attestors.json>` verifies the signed receipt and local sandbox proof first, then verifies signed `asp-sandbox-attestation/v1` evidence from a trusted `sandbox.attest` attestor. The evidence must bind receipt digest, task id, sandbox digest, sandbox claim, policy digest, sandbox class, runtime identity, and freshness. This proves a signed attestation evidence chain, not hardware attestation; hardware attestation remains pending.

The current v13.6 sandbox proof surface keeps isolation claims verifier-owned: `asp-verify.mjs sandbox-proof <frame.json> <trusted-zones.json> [required-sandbox-class]` verifies the signed receipt first, then verifies the embedded signed `local.sandbox.v1` proof, checks task/authority/worker/policy/claim/sandbox binding, requires command, binary, and transcript digests, reports `sandbox_class: "local-process"`, and rejects `remote-attestation` or any other stronger required class unless matching signed evidence exists. This is not hardware remote attestation, not container namespace execution, and not a VM/TEE claim.

The current v13.5 Swarm scheduling proof surface keeps execution proof-owned: `FED_SWARM_SCHEDULE` accepts a signed Swarm DAG, schedules out-of-order steps in deterministic dependency-ready order, reuses the existing per-step receipt and artifact dependency evidence, and signs `scheduler.mode: "ready-dag"` plus `scheduler.step_order` into the same `FED_SWARM_CLOSE` proof. This is not automatic task decomposition, not parallel execution, not upper-layer master-agent orchestration, and not economic settlement.

The current v13.15 checkpoint proof surface keeps checkpoint evidence receipt-local and verifier-owned: Node `FED_RECEIPT` verification accepts signed checkpoint evidence only when `checkpoint_refs` and `checkpoints` align, each checkpoint binds the receipt task, the parent chain starts at `receipt.resumed_from` or `null`, and the worker checkpoint signature verifies. This is not model KV/cache restore, not external checkpoint storage, and not scheduler orchestration.

The current v13.14 agent score reputation proof surface keeps ranking evidence labelled and local: Node and Go `FED_QUERY` expose `discovery_evidence.reputation.agent_score` with `receipt_score`, `credential_score`, `freshness_score`, and `revocation_penalty`, and compute `ranking.score` from `agent_score.total` plus exact capability and semantic intent scores. `last_completed_at` is read from completed receipt audit evidence when present, and `revocation_count` comes from signed local authority Zone revocations. This is deterministic local discovery evidence, not a market, not a distributed registry, and not a third-party scoring service.

The current v13.12 credential validity proof surface keeps credential activity verifier-owned: Capability credentials may carry a `valid_until` ISO UTC expiry in claims; expired credentials lower discovery score and report `active: false` in discovery evidence. Credentials without `valid_until` keep the previous active behavior, while malformed or past timestamps fail closed as inactive.

The current v13.4/v13.10 semantic discovery proof surface keeps ranking deterministic and evidence-first: `FED_QUERY` may include an intent string, exact capability matches and trusted capability credentials outrank semantic-only token overlap, and Node plus Go results expose `discovery_evidence` plus `ranking` reasons. This is not a vector database, not a global reputation coin, not a public marketplace, and not scheduler integration.

The current v13.2 release trust proof surface keeps the release artifact on the existing package proof path: `scripts/package-proof.mjs` produces the tarball and package proof, `scripts/release-trust.mjs` verifies that package proof and writes `state/package-proof/release-trust.json`, and `asp-verify.mjs release-trust <release-trust.json> [trusted-release-signers.json]` verifies the release manifest against the referenced package proof and tarball bytes. The evidence binds package name, version, filename, tarball path, tarball SHA-256, tarball size, package proof digest, release signer identity, and packaged file list; stale release trust means the referenced package proof drifted from `package_proof_digest`, not that the release expired by elapsed time. Trusted release signer pinning covers the release signer only and does not pin the embedded package proof signer. Format is `asp-release-trust/v1`: not CycloneDX, not SPDX, not SLSA provenance, not npm registry signing, not package publish, not release transparency, and not a generic supply-chain platform.

The current v13.1 reachability proof surface keeps scope verifier-owned: `asp-verify.mjs proof-bundle` reports `reachability_scope: "local-interface"` without observer evidence, upgrades to `container-observer` when trusted signed evidence has `vantage: "container"`, upgrades to `external-host` only when trusted signed evidence has `vantage: "external-host"` and the signed receipt `listen_host` is a globally routable literal IP, returns `reachability_observer_zid` for observer-backed scopes, and rejects bundle-supplied `reachability_scope`. Observer evidence binds `vantage`, observed endpoint fields, freshness, the same transport proof, and the same receipt digest; hostname listen hosts are out of scope for external-host in this slice.

The closed v12 proof surface starts from the verified proof/accountability core and makes it easier to consume externally: the public-listen proof now writes one bundle manifest over the verifier-ready receipt, trusted-Zone, artifact, signed transport, and Swarm close evidence files, and `asp-verify.mjs proof-bundle` verifies one manifest against the existing verifier outputs while rejecting non-object manifests, checking proof type, preflighting safe proof-file paths before reads, requiring signed `fed+tcp`, non-loopback non-unspecified `listen_host`, `port`, and `public_transport: true` evidence, reporting verifier-owned `reachability_scope: "local-interface"` by default, upgrading to `reachability_scope: "external-host"` only when an extra caller-supplied trusted-Zone file validates signed external reachability evidence bound to the same transport proof and receipt digest, and rejecting bundle-supplied `reachability_scope`. `scripts/external-reachability-observer.mjs` can run a TCP connect to the bundle target and write the signed observer evidence plus observer trusted-Zone file; `scripts/docker-external-reachability-observer.sh` runs that observer from a Docker container with host-gateway access. This is containerized observer tooling, not hosted deployment or real outside-host proof by itself. The verifier CLI rejects unsupported extra positional arguments across verifier CLI commands. The local package proof now creates a real npm tarball under `state/package-proof/`, writes `state/package-proof/package-proof.json` with npm-owned shasum, integrity, size, packaged file list, SHA-256, and canonical `proof_digest`, ASP signer descriptor, and ASP package proof signature, verifies it with `asp-verify.mjs package-proof`, rejects non-object package proof manifests, rejects unsafe package tarball paths before reads, resolves package tarball paths relative to the package proof manifest, binds `filename` to the tarball path basename, binds `manifest` to the verifier input filename, binds package name/version to the npm tarball filename after scalar identity checks, verifies npm shasum/integrity against the tarball bytes, validates package byte metadata shape before reading tarball bytes, validates package proof metadata before reading tarball bytes, rejects malformed packaged file lists, verifies the signer descriptor and package proof signature, requires package proof signers and trusted package signers to declare `package.proof.sign`, optionally pins the signer to a caller-supplied trusted signer file, rejects trusted signer files with missing signer lists before reading fields, and returns verified size, shasum, integrity, `signer_aid`, and trusted-signer fields in verifier JSON.

The closed v11 proof core remains in force: task and receipt verifiers require valid `FED_TASK_OPEN` / `FED_RECEIPT` frame objects, correct frame types, required Zone descriptor objects, required payload objects, and a trusted Zone store; receipt artifact manifests now require string URI/ref evidence, real 64-hex SHA-256 values, and non-negative integer sizes in Node and Go reusable verifier paths; Go protocol signing, signature verification, and digest paths use no-HTML-escape canonical JSON for `<>&` parity with Node; Go public-listen task receipts now include signed transport proof fields for the configured federation listener; Go receipt and audit artifact verifiers also reject non-string manifest media types, non-string manifest hashes, and malformed artifact ref/manifest list entries before accepting signed metadata or serving bytes; Node local artifact verification rejects non-`artifact://local/` URIs and escaping local artifact paths before filesystem reads; Go artifact audit verification rejects non-hex manifest SHA-256 values before digest-addressed sidecar or mirror path reads and rejects malformed manifest sizes before byte checks; Node proof verifiers now return false for malformed descriptor inputs instead of leaking parser errors; Node descriptor body helpers reject missing descriptor objects before removing signature fields; Node agent resolution rejects missing registry context before reading registry entries; Node registry files reject missing agent lists, missing entries, and missing descriptors before reading registry fields; Node trusted Zone files reject missing Zone lists before reading entries and preserve raw descriptor-array inputs; Node Zone revocation verifiers reject missing revocation context/descriptor/list objects before field reads; Node Zone binding verifiers reject missing binding context/descriptor objects before field reads; Node rotation and alias rebinding proof verifiers now reject missing proof/descriptor objects before field reads; Node capability credential and credential status helpers now reject missing proof objects before field reads; Node artifact manifest helpers and local artifact verification now reject missing manifest objects before field reads; Node `did:key` bridge helpers now reject missing inputs before descriptor or string field reads; Node Zone descriptor loading now rejects missing or non-object descriptor values before reading descriptor fields; Node descriptor public keys and shared object signatures now fail closed before crypto parsing; Node task/receipt verification also requires local verifier context, signed task/receipt signatures before crypto verification, valid local worker descriptor identity, and safe signed receipt task ids, signed receipt `origin_zone` values must name a trusted Zone, `FED_TASK_OPEN` requires a requester Zone binding, Node `FED_SWARM_CLOSE` rejects missing-frame, missing-zone, missing-proof, missing-signature, missing-identity, malformed-step, unsafe-task-id, NUL-bearing, structurally empty, or duplicate-step close proofs, task ids now fail closed unless they are safe protocol tokens, receipts now carry `task_digest` to anchor the signed task body, and Node/Go verifier paths can reject supplied or in-memory task evidence whose digest does not match.

Highest-value next directions:

1. Prove real hosted/public reachability only with external-host evidence.
2. Keep release trust/SBOM bound to the produced package artifact and signer evidence.
3. Extend sandbox proof beyond local-process only with fail-closed runtime proof and signed attestation evidence.
4. Extend semantic discovery/reputation ranking beyond the current Node primitive only with inspectable evidence inputs.
5. Extend Swarm scheduling beyond the current ready-DAG primitive while preserving complete close proof accountability.

## Current Boundaries

Agnet is deliberately not claiming:

- Production security.
- Public network deployment.
- Real container namespace isolation.
- DID-native identity, DID document resolution, or DID service routing.
- A2A, ANP, or AGNTCY compatibility.
- Token economy or settlement.
- Dynamic Swarm decomposition or parallel scheduler-owned execution.
- Real hosted external-host observer evidence and hardware remote attestation remain pending v13 gates.

Those may become later work, but they are not current capabilities.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md). The short version:

- Keep changes boundary-first.
- Add a failing test before changing behavior.
- Prefer verifier evidence over broader framework code.
- Do not claim a capability until a test or command proves it.

## Security

This is a research prototype. Do not use it as a production security boundary. See [SECURITY.md](SECURITY.md).

## License

No open-source license has been selected yet. Until a license is added, the default copyright rules apply. Contributors should not assume reuse rights beyond repository access.
