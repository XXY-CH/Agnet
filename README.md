# Agent Space MVP

Current boundary: [docs/v0-boundary.md](docs/v0-boundary.md), [docs/v0.1-boundary.md](docs/v0.1-boundary.md), [docs/v0.2-boundary.md](docs/v0.2-boundary.md), [docs/v0.3-boundary.md](docs/v0.3-boundary.md), [docs/v0.4-boundary.md](docs/v0.4-boundary.md)

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

It proves:

- `aid:` is derived from an Ed25519 public key.
- `agent://` is only a local alias.
- `state/registry.json` resolves `agent://` to `aid:` and public key material.
- The local Zone signs `agent://` alias to `aid:` bindings.
- A task is signed by the requester.
- The worker rejects a network-enabled task by policy.
- A write task produces approval events before execution.
- A worker emits events, writes an artifact, and signs a receipt.
- `state/audit.log` records hash-chained events and receipts as JSON lines.

Skipped: WebSocket, QUIC, DHT, DID, token economy. Add them after this local loop is boring.
