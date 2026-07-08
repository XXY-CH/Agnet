# Architecture

Agnet implements the Agent Space Protocol (ASP) as a local-first proof layer for agent work. The repository is intentionally narrow: it proves signed tasks, execution receipts, artifact evidence, audit records, sandbox claims, and federation trust boundaries without claiming to be a production Agent Net.

## Layer map

```text
Human Society
  goals, approvals, governance, legal responsibility

Semantic OS
  personal lead agents, organizational entry points, task boards

Agent Economy
  service markets, reputation, quotas, settlement, liability

Agent Swarm Layer
  dynamic teams, roles, collaboration topology, task DAGs

Trust & Verification Layer
  identity, credentials, sandbox claims, attestation, audit, verification

Agent Task Fabric
  signed tasks, event streams, artifacts, receipts, checkpoints

Agent Discovery Layer
  Agent IDs, capability addressing, semantic recall, reputation ranking

Agent Overlay Network
  Zones, federation, P2P relay, DHT, edge gateways

Internet Underlay
  TCP/IP, QUIC, TLS, WebSocket, HTTP, cloud and edge networks
```

ASP is the narrow waist across the middle layers. A runtime may schedule, route, or execute however it wants, but the proof layer must still leave verifier-readable evidence.

## Implemented surfaces

| Layer | Implemented in this repo | Main files |
| --- | --- | --- |
| Trust & Verification | `aid:` identities, Zone descriptors, signatures, credentials, revocation, sandbox proof, sandbox attestation, package/release trust | `asp-core.mjs`, `asp-verify.mjs`, `capability-credential.test.mjs`, `revocation.test.mjs`, `sandbox-proof.test.mjs`, `release-trust.test.mjs` |
| Agent Task Fabric | `FED_TASK_OPEN`, signed receipts, artifacts, checkpoints, audit hash chain, queue/resume evidence | `federation-gateway.mjs`, `cmd/go-fed-discovery/main.go`, `test-vectors/`, `verifier/` |
| Agent Discovery | `FED_RESOLVE`, evidence-first `FED_QUERY`, credentials, reputation, routing signals, cross-zone trust provenance | `federation-gateway.mjs`, `go-fed-discovery.test.mjs`, `zone-registry.test.mjs` |
| Agent Swarm Layer | `FED_SWARM_OPEN`, `FED_SWARM_SCHEDULE`, `FED_SWARM_CLOSE`, micro-contracts, dependency-ready scheduling, migration logs | `federation-gateway.mjs`, `cmd/go-fed-discovery/main.go`, `go-fed-discovery.test.mjs` |
| Overlay edge | Local TCP federation, optional WebSocket/Human Gateway paths, TLS/mTLS on the Go listener | `cmd/go-fed-discovery/main.go`, `scripts/public-node-proof.mjs` |

## Proof flow

1. A requester signs a task body with an Ed25519 `aid:` descriptor.
2. The task crosses a Zone boundary as `FED_TASK_OPEN`, including the origin Zone, requester descriptor, requester Zone binding, and signed task.
3. The worker verifies Zone trust, descriptor identity, task signature, task id shape, and policy before work is accepted.
4. Execution emits events, artifacts, optional approvals/checkpoints/sandbox evidence, and a worker-signed receipt.
5. A receipt returns as `FED_RECEIPT`; verifiers check frame type, Zone trust, worker identity, Zone binding, receipt signature, `task_digest`, artifact manifests, and optional checkpoints.
6. Swarm closes bind step receipts into a Zone-signed `FED_SWARM_CLOSE`; v14 also binds micro-contracts and failure migration logs.
7. CLI verifiers (`asp-verify.mjs` and Go flags) replay the checks without trusting the original runtime.

## Node and Go relationship

The Node implementation is the compact reference surface for protocol primitives and the verifier CLI. The Go gateway is the larger federation/runtime slice with TCP serving, Human Gateway UI, queue flows, Swarm scheduling, artifact mirror checks, TLS/mTLS, and reusable receipt verifier package.

Shared JSON vectors in `test-vectors/` keep interop anchored. Node and Go both verify `FED_TASK_OPEN` and `FED_RECEIPT` vectors; Node verifies the `FED_SWARM_CLOSE` vector; Go verifies audit-backed Swarm behavior through integration tests.

## What is deliberately outside

ASP does not implement a global overlay, production deployment boundary, public discovery graph, token economy, DID-native resolver, automatic decomposer, or real hardware/container attestation. Those may consume ASP receipts later, but they are not current repo capabilities.
