# Agnet

Agnet is an accountability layer for agent work.

MCP makes tools callable. A2A and similar protocols coordinate agents. Agnet focuses on the missing proof layer: after an agent does work, a third party should be able to verify what was requested, who accepted it, what policy applied, which sandbox was claimed, which artifacts were produced, and which audit entry anchored the receipt.

Status: research prototype, local-first, v10 closed at `v10.47-protocol`.

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

- Ed25519 `aid:` agent identity and Zone identity.
- Ed25519 `did:key` bridge fields for descriptors, without replacing `aid:`.
- Signed tasks, events, artifacts, checkpoints, and receipts.
- Hash-chained JSONL audit logs.
- Receipt and local artifact closure verification through Go and Node CLIs.
- Node receipt verifier CLI outputs and proof summary JSON include stable `receipt_digest` values for external reports.
- Node verifier CLI trusted-Zone files are signature-checked before use.
- Minimal npm-facing package contract for the existing Node verifier CLI and `asp-core.mjs` exports.
- One-command proof demo, Docker proof demo, and Docker public-listen proof that emit verifier-ready receipt/trust files, expose receipt digests, verified artifact counts, verified artifact URIs, verified artifact byte digests, and verified artifact manifest hashes, verify local artifact closure, and support base-image override env vars for restricted Docker environments.
- Public-listen proof script that starts the Go federation gateway on `0.0.0.0`, proves `public_transport: true`, completes authenticated `FED_RESOLVE`, `FED_QUERY`, `FED_TASK_OPEN`, `FED_AUDIT_QUERY`, `FED_ARTIFACT_READ`, and `FED_SWARM_OPEN` round trips, verifies fetched artifact bytes, proves out-of-receipt and post-receipt-tampered artifact reads are rejected, and writes a two-step Swarm close proof frame plus trusted Zone file with a reproducible close digest and summary `swarm_close_verify` result from the Node CLI.
- Node artifact manifests, AFP strings, sidecars, local byte verification, CLI verification, and manifest metadata verification; Go filesystem artifact manifests, AFP strings, content-addressed mirrors, and GC plan/apply.
- Human approval evidence for direct and queued execution.
- Explicit queue claim, lease expiry, reclaim, retry, resume, and drain flows.
- Sandbox claim binding and fail-closed unsupported sandbox probes.
- Node to Go and Go to Node `FED_TASK_OPEN` interoperability.
- Shared `FED_TASK_OPEN`, `FED_RECEIPT`, and `FED_SWARM_CLOSE` conformance fixtures.
- Minimal two-step `FED_SWARM_OPEN` with signed dependency evidence.
- Swarm audit verification for declared dependency steps, delimiter-safe step identity, artifact manifests, upstream receipt digests, and single ordered complete audit-backed Zone-signed close proofs over Swarms that appeared in the same audit.

It is not yet a production Agent Net, public federation network, DID-native identity layer, scheduler, economic layer, or container-isolated runtime.

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
go run ./cmd/go-fed-discovery --verify-receipt path/to/receipt.json
```

Verify one Node `FED_RECEIPT` frame:

```bash
node asp-verify.mjs fed-receipt frame.json trusted-zones.json
```

Run the same verifier through the local npm package contract:

```bash
npm exec --package . -- asp-verify fed-receipt frame.json trusted-zones.json
```

Verify one Node `FED_RECEIPT` frame plus its local artifact bytes:

```bash
node asp-verify.mjs fed-receipt-artifacts frame.json trusted-zones.json
```

Verify one Node `FED_SWARM_CLOSE` frame signature and digest:

```bash
node asp-verify.mjs swarm-close frame.json trusted-zones.json
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
- `scripts/public-node-proof.sh` - local public-listen federation proof.
- `scripts/docker-public-node-proof.sh` - Docker wrapper for the public-listen federation proof.
- `package.json` - local npm-facing verifier bin and Node export contract.
- `*.mjs` - Node prototype runtime, federation gateway, tests, and demos.
- `test-vectors/` - shared protocol vectors.
- `docs/implementation-status.md` - current capability matrix.
- `docs/agent-space-ultimate-vision.md` - long-range vision.
- `docs/agent-space-architecture.md` - architecture overview.
- `docs/asp-core-draft.md` - narrow English draft for the implemented proof layer.
- `docs/v10-roadmap.md` - closed v10 roadmap.
- `docs/v10.47-boundary.md` - latest closed boundary.
- `docs/v9-roadmap.md` - closed v9 roadmap.

## Roadmap

v9 and v10 are closed. v10 made the proof layer easier to verify externally: identity bridge first, then Node artifact manifest parity, AFP hash strings, receipt-side manifest metadata checks, local artifact byte checks, minimal verifier CLIs with trusted-Zone descriptor validation and stable receipt digests, a local npm-facing verifier package contract, one-receipt local artifact closure verification, a narrow ASP Core draft, a reusable Go receipt-frame verifier package, a one-command local proof demo, verified Docker proof demos with overrideable base images, a verifier-ready local public-listen resolve/query/task/audit/artifact/swarm proof with negative artifact-read coverage for out-of-receipt and post-receipt-tampered artifact reads, verifier-ready local proof receipt closure files, summary receipt digests, artifact counts, artifact URIs, artifact byte digests, and artifact manifest hashes, and single ordered complete audit-backed Zone-signed Swarm close proof frames plus trusted Zone files tied to same-audit receipts with reproducible close digests and summary `swarm_close_verify`, a narrow Node `swarm-close` verifier command, and a shared `FED_SWARM_CLOSE` conformance vector.

Highest-value next directions:

1. Add public reachability proof only after the local proof contract stays stable.
2. Add package signing or SBOM only after package publication becomes real.
3. Continue Swarm proof work only where it adds verifiable accountability, not scheduler breadth.

## Current Boundaries

Agnet is deliberately not claiming:

- Production security.
- Public network deployment.
- Real container namespace isolation.
- DID-native identity, DID document resolution, or DID service routing.
- A2A, ANP, or AGNTCY compatibility.
- Token economy or settlement.
- Dynamic Swarm decomposition or scheduler-owned DAG execution.

Those may become v11+ work, but they are not current capabilities.

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
