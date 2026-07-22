# Architecture

Agnet is the sovereign, verifiable coordination and settlement fabric for the Agent Internet. **AFP — Agnet Fabric Protocol** is its transport-neutral target architecture. The repository currently implements **ASP v14**, a local-first proof layer that validates signed tasks, execution receipts, Artifact evidence, audit records, sandbox claims, and governed federation boundaries.

AFP does not replace TCP/IP, QUIC, TLS, HTTP, or libp2p. Those layers move bytes and establish paths. AFP defines Agent-level identity, capability-bound authority, task lineage, mailbox custody, Artifact context, receipt finality, and optional settlement facts.

## Layer map

```text
Product / Semantic OS
  principal intent, approvals, explainability, operator controls

Economy and settlement adapters
  offers, budgets, metering, escrow or credit authorization, charges, disputes

AFP evidence and authority fabric
  aid, descriptor, capability grant, task, event, artifact, receipt, fence
  mailbox custody, cancellation, replay, settlement commitment

Discovery and delivery plane
  capability query, signed offer, encrypted mailbox, relay, DHT route hints

Reusable peer substrate
  local IPC, HTTPS/QUIC adapters, libp2p discovery/relay/pubsub

Internet underlay
  TCP/IP, QUIC, TLS, WebSocket, HTTP, cloud and edge networks
```

ASP v14 is the implemented predecessor proof surface inside AFP's evidence-and-authority layer. It is not yet AFP v1. No current frame, artifact prefix, CLI, package name, or vector is silently relabelled as AFP.

## Implemented surfaces

| Layer | Implemented in this repo | Main files |
| --- | --- | --- |
| ASP v14 proof core | `aid:` identities, Zone descriptors, signatures, credentials, revocation, sandbox proof, sandbox attestation, package/release trust | `asp-core.mjs`, `asp-verify.mjs`, `test/capability-credential.test.mjs`, `test/revocation.test.mjs`, `test/sandbox-proof.test.mjs`, `test/release-trust.test.mjs` |
| Agent task evidence | `FED_TASK_OPEN`, signed receipts, Artifacts, checkpoints, audit hash chain, queue/resume evidence | `federation-gateway.mjs`, `cmd/go-fed-discovery/main.go`, `test-vectors/`, `verifier/` |
| Governed discovery | `FED_RESOLVE`, evidence-first `FED_QUERY`, credentials, reputation, routing signals, cross-Zone trust provenance | `federation-gateway.mjs`, `test/go-fed-discovery.test.mjs`, `test/zone-registry.test.mjs` |
| Local Swarm | `FED_SWARM_OPEN`, serial Node `FED_SWARM_SCHEDULE`, `FED_SWARM_CLOSE`, micro-contracts, dependency-ready scheduling, migration logs, and Go-local Phase C durable journal/lease/receipt/close/disband proof | `federation-gateway.mjs`, `cmd/go-fed-discovery/main.go`, `test/go-fed-discovery.test.mjs` |
| Local transport edge | Local TCP federation, optional WebSocket/Human Gateway paths, TLS/mTLS on the Go listener | `cmd/go-fed-discovery/main.go`, `scripts/public-node-proof.mjs` |
| AFP v1 target | Sovereign delivery, capability grants, relay custody, public discovery, Direct Swarm, and settlement adapters | `docs/afp-v1-design.md` |

## Current proof flow

1. A requester signs a task body with an Ed25519 `aid:` descriptor.
2. In the implemented governed profile, the task crosses a Zone boundary as `FED_TASK_OPEN`, including the origin Zone, requester descriptor, requester Zone binding, and signed task.
3. The worker verifies Zone trust, descriptor identity, task signature, task id shape, and policy before work is accepted.
4. Execution emits events, Artifacts, optional approvals/checkpoints/sandbox evidence, and a worker-signed receipt.
5. A receipt returns as `FED_RECEIPT`; verifiers check frame type, Zone trust, worker identity, Zone binding, receipt signature, `task_digest`, Artifact manifests, and optional checkpoints.
6. Swarm closes bind step receipts into a Zone-signed `FED_SWARM_CLOSE`; v14 also binds micro-contracts and failure migration logs.
7. CLI verifiers (`asp-verify.mjs` and Go flags) replay the checks without trusting the original runtime.

AFP's sovereign Direct profile will preserve task, event, Artifact, receipt, fence, and verifier meanings while replacing the mandatory Zone binding with explicit peer authentication, selected trust profile, capability grant, and delivery/custody evidence.

## Node and Go relationship

The Node implementation is the compact reference surface for protocol primitives and the verifier CLI. The Go gateway is the larger federation/runtime slice with TCP serving, Human Gateway UI, queue flows, Swarm scheduling, artifact mirror checks, TLS/mTLS, and reusable receipt verifier package.

Shared JSON vectors in `test-vectors/` keep interop anchored. Node and Go both verify `FED_TASK_OPEN` and `FED_RECEIPT` vectors; Node verifies the `FED_SWARM_CLOSE` vector; Go verifies audit-backed Swarm behavior through integration tests.
### v14.11 / Phase C durable local Swarm boundary

Phase C U19-U30 is complete for the Go-local runtime. Its same-host filesystem journal under OS process locks is authoritative and materializes replayable views; workers execute at-least-once, while a fenced signed receipt commitment is exactly-once. Deterministic parallel ready waves, a byte-stable close, output verification, and irreversible signed disband all derive from that journal. Observed crash/concurrency proof boundaries cover journal/view replacement and close/disband append faults, receipt synchronization before response, stale-lease rejection after reclaim, concurrent-coordinator exclusion, and ready-wave barriers.

Node is a pure verifier of fixed offline U29 vectors for this durable format. Live public proof excludes durable Swarm completion; Phase C makes no claim of real container smoke, cross-host operation, remote artifact handling, or exactly-once worker execution.


## Remaining layers and ordered target programs

The next architecture step is not a public launch. It is **AF0**, the AFP v1 design freeze: canonical schemas, domain separation, downgrade rules, threat/economic model, and compatibility vectors.

After AF0, the sovereign path is ordered as: invited Direct work; asynchronous encrypted mailbox and relay custody; direct/relayed reachability on a reusable peer substrate; privacy-bounded capability discovery and signed offers; task-scoped Direct Swarm; settlement adapters; assurance-aware product convergence.

The U31–U68 program remains the governed/private profile. It consumes AFP's common schema decisions and retains its strict private endpoint, consensus, attestation, organization, and zero-egress constraints. It is not a prerequisite for an Agent to own an `aid:` or complete an invited Direct task.

## What is deliberately outside the current implementation

The repository does not yet implement AFP v1, public P2P/DHT routing, encrypted relay custody, capability grants, public discovery, Direct Swarm, settlement, a global reputation graph, production deployment, or real hardware/container attestation. These later layers may consume ASP v14 receipts, but current local proof claims do not imply their completion.
