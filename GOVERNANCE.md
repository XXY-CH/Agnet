# Governance

Agnet is currently a single-maintainer research project.

## Project Direction

The project direction is:

1. Accountability evidence.
2. Receipt and audit verification.
3. Honest runtime claims.
4. Compatibility bridges only after the core proof layer is stable.

Agnet should complement MCP, A2A, ANP, AGNTCY, and other agent coordination systems instead of trying to replace them.

## Decision Rules

Protocol and verifier changes should answer:

- What new fact can a third party verify?
- Which signed object carries the evidence?
- Which command or test proves it?
- What remains out of scope?

Changes that broaden the project into scheduling, public networking, economic settlement, DID-native identity, or external protocol compatibility should start with a short design note or roadmap entry.

## Maintainer Authority

Maintainers may reject changes that:

- Add broad framework code without a current proof need.
- Claim capabilities that tests do not prove.
- Break existing conformance vectors without a migration note.
- Expand the protocol surface without a boundary document.

## Future Governance

If the project gains external users or co-authors, governance should move toward:

- Public protocol drafts.
- Versioned conformance suites.
- Named maintainers for Go, Node, docs, and test vectors.
- A clear license and contribution agreement.
