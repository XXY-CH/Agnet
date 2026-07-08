# Development

This repository is a local-first research prototype. Keep changes boundary-first: write or update tests, preserve immutable boundary docs, and only claim capabilities proved by verifier output or tests.

## Prerequisites

- Node.js with the built-in `node:test` runner.
- Go matching `go.mod`.
- Docker only for Docker proof scripts.

## Focused commands

```bash
node --test --test-concurrency=1 docs-contract.test.mjs
node --test --test-concurrency=1 *.test.mjs
go test ./...
```

Run the local proof demo:

```bash
bash scripts/proof-demo.sh
node asp-verify.mjs fed-receipt-artifacts state/proof-demo-fed-receipt.json state/proof-demo-trusted-zones.json
```

Run package and release trust proof:

```bash
node scripts/package-proof.mjs
node asp-verify.mjs package-proof state/package-proof/package-proof.json
node scripts/release-trust.mjs
node asp-verify.mjs release-trust state/package-proof/release-trust.json
```

Run public-listen proof:

```bash
bash scripts/public-node-proof.sh
node asp-verify.mjs proof-bundle state/public-node-proof-bundle.json
```

## Go gateway commands

```bash
go run ./cmd/go-fed-discovery --print-zone
go run ./cmd/go-fed-discovery --verify-receipt path/to/receipt.json --verify-task path/to/task.json
go run ./cmd/go-fed-discovery --verify-audit --audit state/go-fed-audit.log
go run ./cmd/go-fed-discovery --sandbox-probe container-namespace
go run ./cmd/go-fed-discovery --artifact-store state/artifact-mirror --artifact-store-gc-plan
go run ./cmd/go-fed-discovery --interop-request 9090
```

Build the Go packages with:

```bash
go test ./...
```

## Contribution rules

- Keep changes boundary-first.
- Add or update failing tests before changing behavior.
- Prefer verifier evidence over broad framework code.
- Do not loosen immutable boundary docs to make tests pass.
- Do not claim production security, public reachability, hardware attestation, or global network behavior unless a verifier-owned proof proves it.

## Docs contract

`docs-contract.test.mjs` guards public docs phrasing across roadmap, boundary, draft, status, and README files. After README or docs restructuring, run:

```bash
node --test --test-concurrency=1 docs-contract.test.mjs
```
