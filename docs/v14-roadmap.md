# Agent Space v14 Roadmap

状态：active at v14.9
目标：从 v13 已经证明的 Task Fabric + Trust + Discovery 底层继续向 Ultimate 上推三层：更深的 Agent Overlay Network、更强的 Agent Swarm Layer、以及 Multi-signal routing。

v14 仍然是 local-first protocol proof。它要把跨 Zone、Swarm 协商、失败迁移、同产物冲突消解、以及 FED_QUERY 多信号路由做成可验证的本地/联邦证据面，而不是宣称已经有全球 Agent Net。

诚实边界：v14 stays local-first；no P2P DHT；no token economy；no public marketplace；no production overlay；no automatic economic settlement；no voting/quorum；no automatic merge of conflicting content。

## v14.0: Opening Boundary

状态：complete
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

状态：complete
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

## v14.5: Intent Decomposition

状态：complete
目标：implement Swarm lifecycle step 2 — `主理 Agent 拆解目标和约束` — as a signed local-first decomposition proof before candidate selection.

新增：

- `swarmPlan(zone, swarmId, intent, steps, policyDigest)` emits a signed `FED_SWARM_PLAN` frame before `FED_SWARM_OPEN`.
- The plan maps the human or upstream Agent `intent` into ordered step specs with `step_id`, `capability`, `constraint`, and `depends_on` fields.
- `FED_SWARM_PLAN.plan.plan_digest` is the SHA-256 digest of canonical `{ intent, steps }`, and `plan_signature` is the Zone Ed25519 signature over the plan body.
- `verifySwarmPlan(frame, trustedZones)` validates the Zone descriptor, local Zone trust, non-empty step shape, NUL-free `step_id`, `policy_digest`, `plan_digest`, and `plan_signature`.
- `FED_SWARM_OPEN.swarm.plan_digest` may link the later open/close path to the plan. When present, `FED_SWARM_CLOSE.close.plan_digest` carries the same value, and `verifySwarmClose` requires it to be a 64-hex digest.

不做：

- 不做 LLM orchestration。
- 不做 automatic candidate selection。
- 不做 automatic risk policy synthesis。
- 不做 distributed planner service。
- 不 cross-reference the plan frame inside `verifySwarmClose`; callers connect the `FED_SWARM_PLAN` to the close proof by `plan_digest`.

验收：

- A two-step `swarmPlan` verifies through `verifySwarmPlan`.
- Tampered `plan_signature`, empty `steps`, and NUL-bearing `step_id` fail closed.
- A Swarm close carrying `plan_digest` verifies when the digest is 64-hex.
- A Swarm close with malformed `plan_digest` fails `verifySwarmClose`.

## v14.6: Knowledge Gateway Proto

状态：complete
目标：implement the Ultimate §8 Knowledge Gateway seam as local-first signed query/response proof, so Agent Task Fabric can consume cited freshness/license evidence without every Agent scraping the web directly.

新增：

- `knowledgeQuery(requesterZone, intent, sources, policyDigest)` emits a signed `FED_KNOWLEDGE_QUERY` frame.
- `FED_KNOWLEDGE_QUERY.query.query_digest` is the SHA-256 digest of canonical `{ intent, sources, policy_digest, query_id }`, and `query_signature` is the requester Zone Ed25519 signature over the query body.
- `verifyKnowledgeQuery(frame, trustedZones)` validates the Zone descriptor, local Zone trust, source list, 64-hex `policy_digest`, recomputed `query_digest`, and Zone signature.
- `knowledgeResponse(gatewayZone, queryId, results, queryDigest)` emits a signed `FED_KNOWLEDGE_RESPONSE` frame.
- Each result carries `source`, `title`, `summary`, `freshness_at`, and `license` as local Knowledge Gateway evidence.
- `FED_KNOWLEDGE_RESPONSE.response.result_digest` is the SHA-256 digest of canonical `{ query_id, query_digest, results }`, and `response_signature` is the gateway Zone Ed25519 signature over the response body.
- `verifyKnowledgeResponse(frame, trustedZones, queryFrame)` validates gateway Zone trust, response signature, result digest, and the response `query_digest` binding to the verified query frame.

不做：

- Not a web crawler.
- Not HTTP fetching or browser automation.
- Not a semantic cache.
- Not a vector store.
- Not a RAG pipeline.
- Not source reputation scoring, source conflict resolution, or license compliance automation.

验收：

- `knowledgeQuery` verifies through `verifyKnowledgeQuery` for a trusted requester Zone.
- `knowledgeResponse` verifies through `verifyKnowledgeResponse` and binds to the original `query_digest`.
- Tampered query and response signatures fail closed.
- A response with the wrong `query_digest` fails closed.
- An untrusted query Zone fails closed.

## v14.7: Policy and risk routing signals

状态：complete
目标：extend the v14.2 multi-signal FED_QUERY ranking surface with verifier-owned policy and risk match signals derived only from existing policy scope, credential trust, revocation, and receipt reputation evidence.

新增：

- `discovery_evidence.routing.policy_match` scores how well a worker descriptor `policy` satisfies the query/task `scope` constraints already enforced at execution time, including network and write-prefix allowances.
- `discovery_evidence.routing.risk_match` scores lower-risk matches from existing active capability credential evidence, signed revocation state, and completed-receipt reputation.
- `agent_score.total` includes `policy_match` and `risk_match` with the same neutral fallback pattern as v14.2 routing signals.
- `ranking.reasons` can include `policy_match` and `risk_match` when those verifier-owned signals positively contribute.
- Node and Go FED_QUERY keep deterministic score-descending, alias-ascending ordering.

不做：

- Not a new trust oracle.
- Not a new policy language.
- Not global risk scoring, marketplace ranking, remote reputation feeds, or opaque ML routing.
- Not a bypass around `enforcePolicy`; execution policy checks remain authoritative.

验收：

- Node and Go FED_QUERY expose integer `policy_match` and `risk_match` under `discovery_evidence.routing`.
- Missing policy/risk evidence falls back to neutral score `5` and does not fabricate an advantage.
- Tests prove policy-scope mismatch lowers ranking and signed revocation lowers risk match.

## v14.8: Swarm Conflict Resolution

状态：complete
目标：When two Swarm steps write the same artifact ref with different sha256 digests, the gateway deterministically resolves the conflict and records signed evidence in the Swarm close proof.

新增：

- Node and Go Swarm close paths detect duplicate `artifact_ref` / manifest `uri` writes whose SHA-256 digests differ.
- The deterministic rule chooses the candidate produced by the worker with the higher agent_score reputation; equal scores choose alias ascending and record `reason: "alias_tiebreak"`.
- `FED_SWARM_CLOSE.close.conflict_resolutions` entries bind `swarm_id`, `artifact_ref`, `candidate_step_ids`, `chosen_step_id`, `chosen_worker`, `reason`, `resolution_digest`, and Zone `signature`.
- Node `verifySwarmClose` verifies every conflict resolution digest, candidate-step subset, chosen-step binding, chosen worker descriptor, and Zone signature against the close signing Zone.
- Node and Go emit the same signed conflict resolution object as task event evidence before the signed close frame.

不做：

- No voting/quorum.
- No automatic merge of conflicting content.
- No payment/settlement.
- Still local-first; no global arbitration service or remote reputation oracle.

验收：

- Node Swarm conflict test proves higher agent_score reputation wins and tampered resolution signatures fail closed.
- Go Swarm conflict test proves Go-produced `conflict_resolutions` are accepted by Node `verifySwarmClose`.
- Vector test proves a conflict resolution whose candidate step is absent from close step receipts is rejected.

## v14.9: Cross-Netns Reachability Evidence

状态：complete
目标：Add an honest third reachability tier, `cross-netns`, for trusted observer evidence from a separate network namespace / VM over a private inter-namespace IP.

新增：

- `asp-verify.mjs proof-bundle` now accepts trusted `vantage: "cross-netns"` evidence and reports verifier-owned `reachability_scope: "cross-netns"`.
- The cross-netns gate requires a literal private IP listen host: not loopback or unspecified, and not globally routable.
- `scripts/external-reachability-observer.mjs` accepts `<container|cross-netns|external-host>` vantage values.
- `scripts/container-cross-netns-observer.sh` runs the observer from an Apple `container` separate-VM model with default `${AGNET_NODE_BASE_IMAGE:-node:24-alpine}`.
- The boundary records the real Apple `container` experiment where a second VM reached gateway private IP `192.168.64.6/24`.

不做：

- Not public reachability.
- Not hosted external-host completion.
- Not NAT traversal or global routing.
- Not a weakening of the v13.1 hosted external-host pending / `ENETUNREACH` status.

验收：

- Happy cross-netns proof over `192.168.64.6` verifies as `reachability_scope: "cross-netns"` with `reachability_observer_zid`.
- Loopback and globally routable cross-netns listen hosts fail closed with the private inter-namespace IP error.
- Tampered cross-netns observer signatures fail closed.

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
