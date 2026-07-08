# Agent Space v14 Roadmap

状态：active at v14.0
目标：从 v13 已经证明的 Task Fabric + Trust + Discovery 底层继续向 Ultimate 上推三层：更深的 Agent Overlay Network、更强的 Agent Swarm Layer、以及 Multi-signal routing。

v14 仍然是 local-first protocol proof。它要把跨 Zone、Swarm 协商、失败迁移、以及 FED_QUERY 多信号路由做成可验证的本地/联邦证据面，而不是宣称已经有全球 Agent Net。

诚实边界：v14 stays local-first；no P2P DHT；no token economy；no public marketplace；no production overlay；no automatic economic settlement。

## v14.0: Opening Boundary

状态：active
目标：打开 v14，并把路线从 v13 的底层 proof surface 对准三层缺口：Overlay Network、Agent Swarm Layer、Multi-signal routing。

新增：

- `docs/v14-roadmap.md` records the active v14 slices.
- `docs/v14.0-boundary.md` states the v14 opening boundary and non-goals.
- README, ASP Core draft, implementation status, and docs contract point at `v14.0-protocol`.

不做：

- 不实现 P2P DHT。
- 不实现 token economy。
- 不实现 public marketplace。
- 不实现 production Agent Net。
- 不把 local-first federation 说成 global overlay。
- 不把 Swarm micro-contracts 说成 settlement or payment。

验收：

- Public docs consistently report v14 active at `v14.0-protocol`.
- The v14 roadmap names the next Overlay, Swarm, and routing layers without claiming terminal completion.
- `docs-contract.test.mjs` guards the v14 opening wording and non-claims.

## v14.1: Swarm Micro-contracts

状态：active
目标：candidates sign cost+latency+capability micro-contract before Swarm selection/execution, so every Swarm step carries pre-execution worker commitments.

新增：

- Before a Swarm step executes, the selected worker emits a signed `micro_contract: "ok"` event.
- A micro-contract binds `swarm_id`, `step_id`, worker descriptor, declared `cost_estimate.tokens`, declared `cost_estimate.seconds`, `capability_proof`, `policy_digest`, `contract_digest`, and worker Ed25519 `signature`.
- `FED_SWARM_CLOSE.close.micro_contracts` carries one micro-contract per completed step.
- Node `verifySwarmClose` validates micro-contract digest and signature against the worker descriptor bound to the signed close step receipt.
- Node and Go Swarm execution both emit micro-contract events and close evidence.

不做：

- 不做 pricing market。
- 不做 payment or settlement。
- 不做 token economy。
- 不做 SLA enforcement beyond declared proof fields.
- 不做 candidate auction or automatic decomposer.

验收：

- Node Swarm close carries `micro_contracts`, each with `signature`, `cost_estimate`, and `capability_proof`.
- Go Swarm close carries `micro_contracts`, and Node `verifySwarmClose` accepts valid contracts.
- Tampering a micro-contract signature makes `verifySwarmClose` reject the close proof.
- Existing signed step receipt and close proof verification remains in force.

## v14.2: Multi-signal FED_QUERY routing

状态：complete
目标：add cost/latency/availability signals to ranking so FED_QUERY no longer ranks only by capability, credential, receipt-count reputation, freshness, revocation penalty, and semantic overlap.

新增：

- FED_QUERY results expose `discovery_evidence.routing` with `cost_score`, `latency_score`, `availability_score`, and `signals_used` as labelled ranking components.
- Ranking stays deterministic and evidence-first for fixed input.
- Missing signal evidence fails safe to neutral/low contribution instead of invented scores.
- FED_QUERY explanations show how cost, latency, availability, reputation, capability, and semantic signals affected order.

不做：

- 不做 opaque ML router。
- 不做 global reputation oracle。
- 不做 public marketplace。
- 不做 token-weighted ranking。
- 不做 predictive availability service without local evidence.

验收：

- Node and Go FED_QUERY include cost/latency/availability signal evidence.
- Tests prove a lower-cost/lower-latency/available candidate can outrank a weaker alternative only when labelled evidence supports it.
- Tests prove missing or malformed signal evidence does not fabricate ranking advantage.

## v14.3: Cross-zone trust chains

状态：complete
目标：Zone A trusts Zone B's worker through a signed trust delegation chain, rather than only direct local trust stores.

新增：

- `zoneTrustDelegation(authorityZone, delegateZoneDescriptor, capabilities)` creates a Zone A-signed delegation record with `delegator`, `delegate`, `capabilities`, and `delegator_descriptor`.
- `verifyZoneTrustDelegation(delegation, trustedAuthorityDescriptor)` verifies the trusted delegator Zone, the delegation signature, and the `capabilities` array shape.
- FED_QUERY discovery evidence carries `zone_trust_chain`; direct local Zone membership uses `zone_trust_chain: []`, while cross-zone provenance can carry the signed delegation record.

不做：

- 不做 global PKI。
- 不做 DID-native universal resolver。
- 不做 network revocation sync。
- 不做 cross-zone legal liability system。
- 不把 one signed chain called universal trust.

验收：

- Positive test: Zone A accepts Zone B's worker through a signed delegation chain.
- Negative tests reject tampered capability and wrong delegated Zone subject.
- Direct trust store behavior remains compatible for local-first deployments through empty `zone_trust_chain: []` evidence.

## v14.4: Task failure migration

状态：complete
目标：worker failure triggers re-assignment to the next available same-capability candidate while preserving signed migration evidence and Swarm audit continuity.

新增：

- Node and Go Swarm execution retry a failed step once on a different worker with the same capability.
- `FED_SWARM_CLOSE.close.migration_log` records `{ step_id, original_worker_aid, reason, migrated_to_worker_aid, migration_at }` for each migration.
- `migration_log` is signed as part of the close body by `close_signature`; individual migration entries do not carry separate signatures.
- The final step receipt remains bound to the replacement worker, while the migration log keeps the original failed worker visible.

不做：

- 不做 invisible retry loops。
- 不做 model KV/cache restore。
- 不做 distributed worker pool。
- 不做 automatic decomposition or human-free high-risk escalation.

验收：

- A worker failure causes re-assignment to a next available same-capability candidate and preserves failure evidence in `migration_log`.
- Tests prove close verification rejects migrated closes whose `migration_log` references a missing step receipt.
- Migration does not hide the original failed worker or mutate prior receipts; `migrated_to_worker_aid` names the replacement worker.

## v14 非目标

- No P2P DHT.
- No token economy.
- No public marketplace.
- No production global Agent Net.
- No NAT traversal or relay mesh.
- No automatic task decomposition unless a later slice explicitly scopes it.
- No upper-layer demo/master-agent orchestration in this repository.
- No A2A/ARD compatibility unless explicitly re-scoped later.

## 验收

```bash
node --test --test-concurrency=1 docs-contract.test.mjs
node --test --test-concurrency=1 *.test.mjs
gofmt -l . && git diff --check
go test ./...
```
