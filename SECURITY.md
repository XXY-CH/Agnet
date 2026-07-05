# Security Policy

Agnet is a research prototype. It should not be used as a production security boundary.

## Supported Versions

Only the current `main` branch is supported for security review.

## Reporting a Vulnerability

Do not open a public issue for a vulnerability that could expose keys, bypass verification, weaken signature checks, or make audit tampering look valid.

Preferred reporting path:

1. Use GitHub private vulnerability reporting if it is enabled for the repository.
2. If private reporting is unavailable, contact a maintainer privately before publishing details.

Include:

- Affected commit or tag.
- Steps to reproduce.
- Expected verification failure.
- Actual behavior.
- Any audit, receipt, artifact, or signature sample needed to reproduce.

## Current Security Boundaries

Current claims:

- Ed25519 signatures are used for agent, Zone, task, receipt, approval, sandbox, and checkpoint evidence.
- Audit logs are hash-chained JSONL.
- Receipts and local artifacts can be verified by the Go verifier.
- Unsupported sandbox claims fail closed before tool execution.

Current non-claims:

- No production hardening.
- No real container namespace isolation.
- No remote attestation.
- No public network trust model.
- No encrypted key store.
- No multi-tenant authorization model.

Treat local key files, audit logs, and artifact stores as sensitive.
