# Agnet

Agnet is an accountability layer for agent work.

MCP makes tools callable. A2A and similar protocols coordinate agents. Agnet focuses on the missing proof layer: after an agent does work, a third party should be able to verify what was requested, who accepted it, what policy applied, which sandbox was claimed, which artifacts were produced, and which audit entry anchored the receipt.

Status: research prototype, local-first, v10 active at `v10.6-protocol`.

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
- Node artifact manifests, sidecars, local byte verification, CLI verification, and manifest metadata verification; Go filesystem artifact manifests, content-addressed mirrors, and GC plan/apply.
- Human approval evidence for direct and queued execution.
- Explicit queue claim, lease expiry, reclaim, retry, resume, and drain flows.
- Sandbox claim binding and fail-closed unsupported sandbox probes.
- Node to Go and Go to Node `FED_TASK_OPEN` interoperability.
- Shared `FED_TASK_OPEN` and `FED_RECEIPT` conformance fixtures.
- Minimal two-step `FED_SWARM_OPEN` with signed dependency evidence.
- Swarm audit verification for declared dependency steps, unique step identity, artifact manifests, and upstream receipt digests.

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

Verify one Node `FED_RECEIPT` frame plus its local artifact bytes:

```bash
node asp-verify.mjs fed-receipt-artifacts frame.json trusted-zones.json
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

- `cmd/go-fed-discovery/main.go` - Go gateway, verifier, Human Gateway, queue, Swarm seed.
- `*.mjs` - Node prototype runtime, federation gateway, tests, and demos.
- `test-vectors/` - shared protocol vectors.
- `docs/implementation-status.md` - current capability matrix.
- `docs/agent-space-ultimate-vision.md` - long-range vision.
- `docs/agent-space-architecture.md` - architecture overview.
- `docs/v10-roadmap.md` - active v10 roadmap.
- `docs/v10.6-boundary.md` - latest closed boundary.
- `docs/v9-roadmap.md` - closed v9 roadmap.

## Roadmap

v9 is closed. v10 is making the proof layer easier to verify externally: identity bridge first, then Node artifact manifest parity, receipt-side manifest metadata checks, local artifact byte checks, minimal verifier CLIs, and one-receipt local artifact closure verification.

Highest-value next directions:

1. Publish an English ASP Core draft for the narrow proof layer.
2. Extract receipt verification into a small Go package and npm package.
3. Provide a first public node or Docker-based demo.
4. Continue Swarm proof work without building a broad scheduler too early.

## Current Boundaries

Agnet is deliberately not claiming:

- Production security.
- Public network deployment.
- Real container namespace isolation.
- DID-native identity, DID document resolution, or DID service routing.
- A2A, ANP, or AGNTCY compatibility.
- Token economy or settlement.
- Dynamic Swarm decomposition or scheduler-owned DAG execution.

Those may become v10+ work, but they are not current capabilities.

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
