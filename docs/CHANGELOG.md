# Changelog

All notable changes from v13.0 through v14.11 are summarized here. Format follows Keep a Changelog with concise Added / Changed / Fixed bullets.

## [v14.11] - Apple Container private-workspace isolation proof

### Added
- Darwin Apple Container runs now use one agent-owned private `0700` workspace bind-mounted read-write at `/work`, with workspace identity and exact postflight entry validation.
### Changed
- Apple execution no longer relies on pre/post copy operations, separate input/result mounts, or an Apple `/work` tmpfs; it applies `nofile=64:64` and `nproc=64:64` alongside existing read-only root, non-root, network/DNS, capability, CPU, and memory constraints.
### Fixed
- Symlinks, hardlinks, devices, unexpected paths, workspace substitution, and aggregate/result overflow fail closed before result promotion. The Darwin smoke proves the private-workspace path but is not full Docker isolation parity and does not claim Apple tmpfs quota or PID parity beyond the nproc ulimit.

## [v14.10] - Node FED_SWARM_SCHEDULE ready-DAG parity

### Added
- Node accepts `FED_SWARM_SCHEDULE`, validates missing dependencies, duplicate step IDs, self-dependencies, and a cycle or unresolvable graph before execution, then orders ready steps by original input order.
### Changed
- Successful scheduled Swarms execute serially and sign close `scheduler: { mode: "ready-dag", step_order: [...] }`; the Node close verifier requires that order to match ordered `step_receipts` position by position.
### Fixed
- Out-of-order Node DAG inputs now preserve existing signed task, artifact/receipt dependency, micro-contract, migration, conflict resolution, plan digest, close, and audit evidence instead of failing on input order. No parallel execution, no resource scheduling, no economic ranking, no LLM scheduling, and no new trust inputs were added.

## [v14.9] - Cross-netns reachability evidence

### Added
- `cross-netns` reachability scope proves trusted observer TCP reachability from a separate network namespace / VM over a private literal IP.
- `scripts/container-cross-netns-observer.sh` runs the observer with Apple `container` and `vantage: "cross-netns"`.
### Changed
- `asp-verify.mjs proof-bundle` now maps trusted `container`, `cross-netns`, and `external-host` vantage evidence to distinct verifier-owned scopes.
### Fixed
- Cross-netns evidence fails closed for loopback, globally routable IPs, and tampered observer signatures without claiming public reachability.

## [v14.4] - Task failure migration

### Added
- Node and Go Swarm execution retry a failed step once on a different same-capability worker and record `migration_log` in `FED_SWARM_CLOSE`.
### Changed
- Swarm close proof now signs migration entries with the close body so the original failed worker stays visible.
### Fixed
- Close verification rejects migration logs that reference missing step receipts.

## [v14.3] - Cross-zone trust chains

### Added
- `zoneTrustDelegation` and `verifyZoneTrustDelegation` create and verify signed local Zone delegation records.
### Changed
- `FED_QUERY` evidence now carries `zone_trust_chain`, with direct trust represented as `[]`.
### Fixed
- Tampered delegation capabilities and wrong delegated Zone subjects fail closed.

## [v14.2] - Multi-signal FED_QUERY routing

### Added
- `discovery_evidence.routing` exposes cost, latency, availability, and `signals_used` for Node and Go queries.
### Changed
- `agent_score.total` incorporates labelled routing signals while ranking stays deterministic.
### Fixed
- Missing or malformed signal evidence no longer fabricates ranking advantage.

## [v14.1] - Swarm micro-contracts

### Added
- Node and Go Swarm closes include signed worker micro-contracts for cost, latency, capability proof, and policy digest.
### Changed
- `FED_SWARM_CLOSE` verification checks micro-contract digest and signature against each step worker.
### Fixed
- Tampered micro-contract signatures reject close proof verification.

## [v14.0] - Opening boundary

### Added
- v14 roadmap and boundary docs for Overlay, Swarm, and multi-signal routing work.
### Changed
- Public docs moved active protocol status to `v14.0-protocol` and then v14.4 as slices completed.
### Fixed
- v14 non-claims keep local-first federation from being described as a global Agent Net.

## [v13.15] - Node receipt checkpoint verification

### Added
- Node `FED_RECEIPT` verification checks optional `checkpoint_refs` and `checkpoints` evidence.
### Changed
- `asp-verify.mjs fed-receipt` inherits checkpoint evidence validation.
### Fixed
- Ref mismatch, task mismatch, parent-chain breakage, and invalid worker checkpoint signatures fail closed.

## [v13.14] - Multi-signal agent score reputation

### Added
- Node and Go reputation evidence reports `completed_receipts`, `last_completed_at`, `revocation_count`, and labelled `agent_score` components.
### Changed
- Ranking now uses `agent_score.total` plus exact capability and semantic intent scores.
### Fixed
- Missing receipt timestamps do not invent freshness contribution.

## [v13.13] - Authority Zone revocation discovery

### Added
- Node and Go `FED_QUERY` apply signed local authority Zone revocations to credential activity.
### Changed
- Revoked workers remain inspectable but lose active credential contribution in `agent_score`.
### Fixed
- Revoked workers now report `discovery_evidence.credential.active: false`.

## [v13.12] - Credential validity windows

### Added
- Capability credentials may carry `valid_until` ISO UTC expiry claims.
### Changed
- Discovery only adds credential contribution when the credential is active.
### Fixed
- Malformed, unparseable, non-string, and past expiry values fail closed as inactive.

## [v13.11] - Audit-backed receipt-count reputation

### Added
- Node and Go discovery count completed receipts from persisted audit logs.
### Changed
- `discovery_evidence.reputation.completed_receipts` is now audit-backed instead of demo-fixed.
### Fixed
- Missing, empty, unreadable, or partially malformed audit logs fail safe to zero receipts.

## [v13.10] - Go FED_QUERY semantic discovery parity

### Added
- Go `FED_QUERY` supports semantic `intent`, token overlap scoring, ranking reasons, and discovery evidence.
### Changed
- Go query results sort by score descending with alias tiebreaking, mirroring Node semantics.
### Fixed
- Go parity gap for evidence-first semantic discovery was closed for the scoped surface.

## [v13.9] - Hosted observer runner

### Added
- GitHub Hosted Reachability Observer workflow runs signed external-host observer and verifier from caller-supplied bundles.
### Changed
- `scripts/public-node-proof.mjs` accepts `AGNET_PUBLIC_LISTEN_HOST` and `AGNET_PUBLIC_PROOF_KEEPALIVE_MS`.
### Fixed
- Hosted reachability status records the `ENETUNREACH` IPv6 blocker instead of claiming success.

## [v13.8] - Pinned external observer identity

### Added
- `scripts/external-reachability-observer.mjs` supports `AGNET_REACHABILITY_OBSERVER_SEED_HEX` for stable observer identity.
### Changed
- Verifiers can pre-pin an observer Zone descriptor before a hosted run.
### Fixed
- Observer trust no longer depends on a fresh unpinned identity for each run.

## [v13.7] - Signed sandbox attestation verifier

### Added
- `asp-verify.mjs sandbox-attestation` verifies `asp-sandbox-attestation/v1` evidence from trusted `sandbox.attest` signers.
### Changed
- Attestation evidence binds receipt digest, task id, sandbox digest, policy, class, runtime identity, and freshness.
### Fixed
- Stale, future, mismatched, unsigned, wrong-capability, and untrusted attestation evidence fails closed.

## [v13.6] - Sandbox proof verifier

### Added
- `asp-verify.mjs sandbox-proof` verifies signed `local.sandbox.v1` proof inside trusted receipts.
### Changed
- Sandbox class is verifier-owned and currently reports only `local-process`.
### Fixed
- Required stronger classes such as `remote-attestation` fail closed without matching evidence.

## [v13.5] - Dynamic Swarm scheduling

### Added
- `FED_SWARM_SCHEDULE` executes signed Swarm DAG steps in deterministic dependency-ready order.
### Changed
- Close proof carries signed scheduler evidence with `mode: "ready-dag"` and executed `step_order`.
### Fixed
- Out-of-order DAG inputs preserve receipt and artifact dependency proof instead of hiding schedule order.

## [v13.4] - Semantic discovery and reputation ranking

### Added
- Node `FED_QUERY` accepts `intent` and returns `discovery_evidence` plus ranking reasons.
### Changed
- Exact capability, credential, receipt-count evidence, and semantic overlap are exposed rather than hidden.
### Fixed
- Semantic-only candidates cannot outrank exact trusted evidence candidates on the scoped proof surface.

## [v13.3] - Strong sandbox and remote attestation gate

### Added
- Roadmap gate for verifier-owned sandbox classes and remote attestation evidence.
### Changed
- Local-process proof is documented as honest evidence, not strong isolation.
### Fixed
- Unsupported container/remote attestation claims remain pending and fail closed.

## [v13.2] - Release trust and SBOM

### Added
- `asp-release-trust/v1`, `scripts/release-trust.mjs`, and `asp-verify.mjs release-trust`.
### Changed
- Release evidence is bound to the existing package proof artifact and signer capability.
### Fixed
- Malformed, stale, mismatched, unsigned, wrong-signer, untrusted-signer, unsafe-path, invalid timestamp, and extra-argument evidence rejects.

## [v13.1] - Hosted public reachability evidence

### Added
- Verifier-owned reachability scopes: `local-interface`, `container-observer`, and `external-host`.
### Changed
- Observer evidence must bind vantage, endpoint, freshness, receipt digest, and transport proof.
### Fixed
- Bundle-owned reachability labels, stale evidence, wrong endpoints, untrusted observers, and non-routable external-host evidence fail closed.

## [v13.0] - Opening alignment

### Added
- v13 roadmap and opening boundary for hosted reachability, release trust, sandbox, discovery/reputation, and Swarm scheduling gates.
### Changed
- Roadmap moved from v12 proof-surface micro-slices to larger evidence gates.
### Fixed
- Public docs separate planned Ultimate-layer work from current verified capability.
