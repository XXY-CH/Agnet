---
name: Agnet
last_updated: 2026-07-22
---

# Agnet Strategy

## Target problem

Autonomous Agents can call tools across platforms, but independent operators cannot reliably establish who is authorized, what work was accepted, which bytes were produced, whether delivery survived endpoint changes, or which result and charge are authoritative. Existing HTTP/RPC, registry, relay, and marketplace stacks make their infrastructure operator or fixed endpoint part of the trust boundary.

## Our approach

Agnet builds a transport-neutral, self-sovereign evidence and authority fabric: identity, bounded capability, task, Artifact, Receipt, custody, and settlement facts remain independently verifiable while transport, relay, storage, discovery, and payment providers remain replaceable. We prove the local evidence narrow waist first, then extend it through explicit AFP compatibility, delivery, and settlement contracts rather than treating a chain, token, or opaque semantic rank as authority.

## Who it's for

**Primary:** Independent Agent developer or operator — they are hiring Agnet to delegate bounded work to another independently operated Agent while retaining cryptographic identity, local acceptance policy, verifiable output, and a defensible execution record.

## Key metrics

- **Verified Direct-task completion rate** - Fraction of invited AFP Direct tasks that produce one independently verified terminal Receipt and all declared Artifact bytes; measured by AFP conformance runs and later runtime telemetry.
- **Authority downgrade rejection rate** - Every attempted governed-to-Direct, expired-grant, exceeded-scope, or stale-fence transition is rejected before execution; measured by AFP adversarial vectors.
- **Recovery integrity rate** - Reconnect, relay migration, cancellation, expiry, and restart scenarios preserve one authoritative/contested outcome without silent re-execution; measured by custody and recovery fault suites.
- **Provider portability coverage** - Supported transport, relay, storage, and settlement adapters preserving identical AFP verifier outcomes; measured by adapter conformance matrices.

## Tracks

### Sovereign Agent Fabric

Freeze AFP semantics for identity, grants, task/evidence, delivery custody, and verifier-first compatibility.

_Why it serves the approach:_ It removes platforms and endpoints from the Agent authority root without discarding the proven U1–U30 evidence core.

### Resilient Delivery and Coordination

Build endpoint-independent encrypted delivery, replaceable peer paths, capability discovery/offers, and task-scoped Direct Swarms.

_Why it serves the approach:_ Independent Agents must be able to work through migration, offline intervals, and hostile or replaceable intermediaries without losing authority lineage.

### Verifiable Economy and Human Control

Bind resource facts to budgets, settlement adapters, disputes, approvals, and assurance-aware product surfaces.

_Why it serves the approach:_ Programmable settlement is useful only when it is tied to verified work and remains accountable to a human/operator policy.

## Not working on

- Replacing TCP/IP, QUIC, TLS, libp2p, or the public Internet with an Agnet network stack.
- Making a blockchain, token, marketplace, DNS owner, registry, or Zone mandatory for Agent identity or baseline Direct work.
- Treating semantic ranking, discovery position, or reputation as task authorization or global truth.
- Claiming public deployment, global discovery, Direct Swarm, or settlement before AFP conformance evidence exists.

## Marketing

**One-liner:** The sovereign, verifiable coordination and settlement fabric for the Agent Internet.

**Key message:** Agnet makes Agent work portable across runtimes, endpoints, relays, and payment rails: authorization is bounded, evidence is independently verifiable, and infrastructure remains replaceable.
