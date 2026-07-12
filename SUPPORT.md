# Support

Agnet is an experimental protocol and runtime prototype. Support is best-effort.

## Where to Ask

- Use GitHub Issues for reproducible bugs, documentation gaps, and scoped feature proposals.
- Use GitHub Discussions if they are enabled for design questions.
- For vulnerabilities, follow [SECURITY.md](SECURITY.md) instead of filing a public issue.

## Good Bug Reports

Include:

- Commit or tag.
- Operating system.
- Node and Go versions.
- Exact command.
- Full failure output.
- Whether `go test ./...` and `node --test --test-concurrency=1 test/*.test.mjs` pass.

## Scope

Current support focuses on:

- Receipt verification.
- Audit verification.
- Artifact manifest verification.
- Local federation tests.
- Human Gateway local flows.
- Queue and Swarm proof behavior.

Out of scope for current support:

- Production deployment.
- Hosted infrastructure.
- Wallets, settlement, or token economics.
- DID-native identity.
- A2A/ANP/AGNTCY integration.
- Container isolation guarantees.
