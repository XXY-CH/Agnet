# Agent Space MVP

Current status: `v5.9`.

Start here:

- Current implementation matrix: [docs/implementation-status.md](docs/implementation-status.md)
- Gap to Agent Net and Octo: [docs/agent-net-gap.md](docs/agent-net-gap.md)
- Latest boundary: [docs/v5.9-boundary.md](docs/v5.9-boundary.md)
- v5 roadmap: [docs/v5-roadmap.md](docs/v5-roadmap.md)

Current boundary: [docs/v0-boundary.md](docs/v0-boundary.md), [docs/v0.1-boundary.md](docs/v0.1-boundary.md), [docs/v0.2-boundary.md](docs/v0.2-boundary.md), [docs/v0.3-boundary.md](docs/v0.3-boundary.md), [docs/v0.4-boundary.md](docs/v0.4-boundary.md), [docs/v0.5-boundary.md](docs/v0.5-boundary.md), [docs/v0.6-boundary.md](docs/v0.6-boundary.md), [docs/v0.7-boundary.md](docs/v0.7-boundary.md), [docs/v0.8-boundary.md](docs/v0.8-boundary.md), [docs/v0.9-boundary.md](docs/v0.9-boundary.md), [docs/v1-boundary.md](docs/v1-boundary.md), [docs/v1.1-boundary.md](docs/v1.1-boundary.md), [docs/v1.2-boundary.md](docs/v1.2-boundary.md), [docs/v1.3-boundary.md](docs/v1.3-boundary.md), [docs/v1.4-boundary.md](docs/v1.4-boundary.md), [docs/v1.5-boundary.md](docs/v1.5-boundary.md), [docs/v1.6-boundary.md](docs/v1.6-boundary.md), [docs/v2-boundary.md](docs/v2-boundary.md), [docs/v2.1-boundary.md](docs/v2.1-boundary.md), [docs/v2.2-boundary.md](docs/v2.2-boundary.md), [docs/v2.3-boundary.md](docs/v2.3-boundary.md), [docs/v2.4-boundary.md](docs/v2.4-boundary.md), [docs/v3-boundary.md](docs/v3-boundary.md), [docs/v3.1-boundary.md](docs/v3.1-boundary.md), [docs/v3.2-boundary.md](docs/v3.2-boundary.md), [docs/v3.3-boundary.md](docs/v3.3-boundary.md), [docs/v3.4-boundary.md](docs/v3.4-boundary.md), [docs/v3.5-boundary.md](docs/v3.5-boundary.md), [docs/v3.6-boundary.md](docs/v3.6-boundary.md), [docs/v3.7-boundary.md](docs/v3.7-boundary.md), [docs/v3.8-boundary.md](docs/v3.8-boundary.md), [docs/v3.9-boundary.md](docs/v3.9-boundary.md), [docs/v4-boundary.md](docs/v4-boundary.md), [docs/v4.1-boundary.md](docs/v4.1-boundary.md), [docs/v4.2-boundary.md](docs/v4.2-boundary.md), [docs/v4.3-boundary.md](docs/v4.3-boundary.md), [docs/v4.4-boundary.md](docs/v4.4-boundary.md), [docs/v4.5-boundary.md](docs/v4.5-boundary.md), [docs/v5.0-boundary.md](docs/v5.0-boundary.md), [docs/v5.1-boundary.md](docs/v5.1-boundary.md), [docs/v5.2-boundary.md](docs/v5.2-boundary.md), [docs/v5.3-boundary.md](docs/v5.3-boundary.md), [docs/v5.4-boundary.md](docs/v5.4-boundary.md), [docs/v5.5-boundary.md](docs/v5.5-boundary.md), [docs/v5.6-boundary.md](docs/v5.6-boundary.md), [docs/v5.7-boundary.md](docs/v5.7-boundary.md), [docs/v5.8-boundary.md](docs/v5.8-boundary.md), [docs/v5.9-boundary.md](docs/v5.9-boundary.md)

Run the smallest proof:

```bash
node mvp-demo.mjs
```

Run the check:

```bash
node --test --test-concurrency=1 *.test.mjs
go test ./...
```

Run two local Agent processes:

```bash
node agent-runtime.mjs worker
node agent-runtime.mjs request agent://local/summarizer
```

Run a minimal two-Zone federation:

```bash
node federation-gateway.mjs serve 8990 state/zone-b-trust.json
node federation-gateway.mjs resolve 8990 state/zone-a-trust.json agent://zone-b/summarizer
node federation-gateway.mjs query 8990 state/zone-a-trust.json summarize.text
node federation-gateway.mjs audit 8990 state/zone-a-trust.json go_fed_task_verified
node federation-gateway.mjs request-capability 8990 state/zone-a-trust.json summarize.text
node federation-gateway.mjs request 8990 state/zone-a-trust.json
```

It proves:

- `aid:` is derived from an Ed25519 public key.
- Runtime identities persist private keys under `state/keys/`.
- `agent://` is only a local alias.
- `state/registry.json` resolves `agent://` to `aid:` and public key material.
- The local Zone signs `agent://` alias to `aid:` bindings.
- Trusted Zone stores verify remote `zid:` descriptors before federation.
- Go verifies the signed capability credential vector.
- A task is signed by the requester.
- The worker rejects a network-enabled task by policy.
- A write task produces approval events before execution.
- Go tool approval grants are signed by the Zone authority and visible in the Human Gateway receipt view.
- Go external/MCP tools run from a local temporary sandbox directory with restricted environment evidence in the receipt.
- Go signs sandbox proof evidence and includes it in receipts.
- Go emits signed protocol-native checkpoint evidence and records checkpoint refs in receipts.
- Go accepts `FED_TASK_RESUME` and records resumed receipts linked to parent checkpoints.
- Go accepts signed `FED_TASK_CANCEL` and records worker-signed cancellation receipts.
- Go accepts `FED_TASK_RETRY` and records retry lineage in receipts.
- Go binds declared sandbox claims into receipts and signed sandbox proofs.
- Go records external/MCP tool command digests in sandbox evidence.
- Go records tool output digest alignment with artifact manifests.
- Go records MCP initialize session metadata in sandbox evidence.
- Go records MCP resources/prompts count and digest evidence.
- Go records MCP tool list count and digest evidence.
- Go records artifact manifest digest evidence in artifact events and receipts.
- Go records canonical policy scope evidence and stable policy deny codes.
- Go query results include Zone-signed credential status evidence.
- Federation can query remote signed audit receipt proof by task id.
- A worker emits events, writes an artifact, and signs a receipt.
- `state/audit.log` records hash-chained events and receipts as JSON lines.

Skipped: TLS, QUIC, DHT, DID, token economy. Add them after this local loop is boring.
