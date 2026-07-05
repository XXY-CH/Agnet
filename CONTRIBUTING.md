# Contributing to Agnet

Agnet is a research prototype for verifiable agent work. Contributions are welcome, but the project should stay narrow: accountability evidence first, broad platform features later.

## Ground Rules

- Start from the current boundary docs before changing behavior.
- Keep the smallest useful slice.
- Prefer existing verifier/runtime paths over new abstractions.
- Do not add dependencies unless the feature clearly needs them.
- Do not claim public deployment, DID compatibility, container isolation, scheduler behavior, or A2A/ANP/AGNTCY compatibility unless the code and tests prove it.

## Development Setup

Run the normal checks:

```bash
go test ./...
node --test --test-concurrency=1 go-fed-discovery.test.mjs
node --test --test-concurrency=1 *.test.mjs
```

Run `go-fed-discovery.test.mjs` separately from the full `*.test.mjs` command. They touch shared local state and can produce false audit-chain failures if run in parallel.

## Change Process

1. Pick one boundary.
2. Write or update a test that fails for the missing behavior.
3. Make the smallest implementation change.
4. Update README or docs if the public capability changed.
5. Run the relevant focused test, then the full checks above.

For protocol-facing changes, include:

- What is newly proven.
- What remains explicitly out of scope.
- Which command or test verifies the claim.

## Pull Requests

Good PRs are small and evidence-backed. Include:

- Summary of the boundary.
- Tests run.
- Any skipped or intentionally deferred work.
- Compatibility notes if wire formats, receipt fields, or verifier behavior changed.

## Commit Messages

Prefer decision-oriented commit messages. The first line should explain why the change exists, not just what changed.

Useful trailers:

```text
Constraint: ...
Rejected: ... | ...
Confidence: high|medium|low
Scope-risk: narrow|moderate|broad
Directive: ...
Tested: ...
Not-tested: ...
```
