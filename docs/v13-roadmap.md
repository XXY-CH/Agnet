# Agent Space v13 Roadmap

状态：active at v13.12
目标：从 v12 已闭合的 proof surface 继续向 Ultimate 推进，集中处理真实 hosted/public reachability、release trust/SBOM、strong sandbox/remote attestation、semantic discovery/reputation ranking、dynamic Swarm scheduling 五个大门槛。

v13 uses larger evidence gates instead of many tiny versions. 每个 v13 slice 都必须能用测试、脚本、外部证据或 verifier 输出证明边界已经收住；没有证据的能力只作为 planned，不写成 current capability。

## v13.0: V13 Opening Alignment

状态：complete
目标：打开 v13，并把它对准 Ultimate 的下一组核心缺口，而不是继续扩写 v12 proof-surface micro-slices。

新增：

- `docs/v13-roadmap.md` records the active v13 gates.
- `docs/v13.0-boundary.md` states the v13 opening boundary and non-goals.
- README, ASP Core draft, implementation status, and docs contract point at `v13.0-protocol`.

不做：

- 不实现新的 runtime feature。
- 不实现 hosted public node。
- 不实现 semantic routing。
- 不实现 reputation scoring。
- 不实现 scheduler-owned DAG execution。
- 不实现 container namespace sandbox。
- 不实现 remote attestation。
- 不实现 SBOM。
- 不实现 release transparency。
- 不实现 upper-layer demo/master-agent orchestration; upper-layer demo/master-agent orchestration stays outside this repository.
- 不实现 A2A/ARD compatibility; A2A/ARD compatibility stays parked.

## v13.1: Hosted Public Reachability Evidence

状态：active
目标：把 v12 的 local-interface proof 推进到 verifier-owned reachability scope classes while keeping the real hosted external-host observer run pending as the exit criterion.

新增：

- `proof-bundle` now distinguishes `local-interface`, `container-observer`, and `external-host` without accepting bundle-owned labels.
- Observer evidence binds `vantage`, observed endpoint, freshness, the same receipt digest, and the same transport proof that `proof-bundle` verifies.
- Valid trusted observer evidence returns `reachability_observer_zid` for both `container-observer` and `external-host` scopes.
- `external-host` additionally requires a globally routable literal-IP listen host; hostname listen hosts are out of scope for this slice.
- Negative gates reject stale, future, wrong-host, wrong-port, wrong-digest, invalid-vantage, untrusted-observer, unsigned, bundle-owned-scope, and non-routable external-host evidence.
- Pinned external observer identity landed in v13.8: `scripts/external-reachability-observer.mjs` accepts `AGNET_REACHABILITY_OBSERVER_SEED_HEX` so a verifier can pre-pin the observer Zone descriptor before a hosted run.
- GitHub hosted observer runner landed in v13.9: the Hosted Reachability Observer workflow decodes verifier-ready proof bundle files, runs `scripts/external-reachability-observer.mjs` with `external-host`, and runs `asp-verify.mjs proof-bundle` against the observed bundle.
- `scripts/public-node-proof.mjs` now accepts `AGNET_PUBLIC_LISTEN_HOST` for explicit global literal-IP listeners and `AGNET_PUBLIC_PROOF_KEEPALIVE_MS` to keep the proof listener alive during a hosted observation window.
- Recorded hosted attempt `28916288568` reached the GitHub hosted observer step, then failed with `ENETUNREACH` from the runner to the current IPv6 listener.

Remaining exit criterion:

- A real hosted external-host observer run against a globally routable literal-IP listener has not happened yet; the real hosted external-host observer run is still pending.
- The current blocker is environmental/network reachability, not verifier acceptance: the next successful close needs an IPv4-routable listener, a hosted observer with IPv6 route, or a real hosted node with a globally routable literal IP.

不做：

- 不把 same-host, LAN-only, or container-only observer evidence labeled as hosted public reachability.
- 不把 `container-observer` collapsed into `external-host`; it is a distinct verifier-owned scope.
- 不支持 hostname listen hosts for `external-host` in this slice.
- 不做 NAT traversal, relay network, QUIC, or DHT.
- 不做 production deployment automation beyond the proof needed for this gate.

## v13.2: Release Trust and SBOM

状态：complete
目标：把 v12 package proof 推进到 release trust/SBOM evidence over the produced artifact.

新增：

- Recorded format choice: `asp-release-trust/v1`, an ASP-native signed release-trust/SBOM manifest.
- Explicit non-claims: not CycloneDX, not SPDX, not SLSA provenance, not npm registry signing, not package publish, not release transparency, not a generic supply-chain platform.
- `scripts/release-trust.mjs` consumes the existing package proof artifact path, verifies the package proof first, and writes signed release trust evidence for the produced tarball.
- `asp-verify.mjs release-trust <release-trust.json> [trusted-release-signers.json]` verifies package-proof binding, tarball bytes, release signer capability, trusted release signer pins, and manifest signature.
- Negative gates reject malformed, stale, mismatched, unsigned, wrong-signer, untrusted-signer, unsafe-path, invalid timestamp, and extra-argument release trust evidence.
- `release-trust.test.mjs` covers happy path, trusted signer pinning, and fail-closed release trust mutations; `docs-contract.test.mjs` guards the public docs boundary.

验收边界：

- The release artifact is produced by the existing package proof path and bound by a narrowly documented release trust producer.
- Release trust/SBOM evidence binds package name, version, tarball bytes, package proof digest, signer identity, and packaged file list.
- Verifier commands reject malformed, stale, mismatched, unsigned, and wrong-signer release trust evidence.
- The format choice is recorded before implementation; no implicit claim of registry publish or ecosystem signing.

不做：

- 不做 package publish。
- 不做 npm registry signing claim。
- 不做 generic supply-chain platform。

## v13.3: Strong Sandbox and Remote Attestation

状态：active
目标：把 honest local-process sandbox evidence 推进到 verifier-owned sandbox proof class validation.

已完成：

- `asp-verify.mjs sandbox-proof <frame.json> <trusted-zones.json> [required-sandbox-class]` verifies a signed `local.sandbox.v1` proof embedded in a verified `FED_RECEIPT` frame.
- Sandbox proof checks task id, authority Zone, worker, policy digest, sandbox claim, and sandbox evidence binding before accepting the proof.
- Sandbox evidence must include mode, isolation level, network surface, command digest, binary digest, and transcript digest.
- The verifier reports verifier-owned `sandbox_class: "local-process"` for the current local sandbox proof.
- Required stronger classes such as `remote-attestation` fail closed unless matching signed evidence exists.
- `asp-verify.mjs sandbox-attestation <frame.json> <trusted-zones.json> <attestation.json> <trusted-attestors.json>` verifies signed `asp-sandbox-attestation/v1` evidence.
- Signed sandbox attestation evidence binds receipt digest, task id, sandbox digest, sandbox claim, policy digest, sandbox class, runtime identity, freshness, and a trusted `sandbox.attest` attestor signature.

Remaining exit criterion:

- Hardware remote attestation remains unimplemented and fail-closed. Signed sandbox attestation evidence is not hardware remote attestation by itself.
- Real container namespace/VM/TEE isolation remains unimplemented and must not be inferred from local-process proof.

验收边界：

- Sandbox mode claims are verifier-owned and fail closed when the required runtime or evidence class is unavailable.
- Stronger sandbox evidence must record runtime identity, policy, mounted write surface, network surface, command identity, and transcript/artifact digests.
- Remote attestation evidence, if implemented in this gate, must be signed, bound to the task/receipt digest, and rejected when stale or mismatched.

不做：

- 不把 unsupported container namespace probes called supported。
- 不把 local sandbox proof called hardware remote attestation。
- 不做 broad VM/container orchestration unless the proof requires it.

## v13.4: Semantic Discovery and Reputation Ranking

状态：complete
目标：在 Node federation gateway 上增加证据优先的 semantic discovery/reputation ranking primitive

新增：

- `FED_QUERY` may carry an `intent` string in the Node federation gateway.
- Candidate results expose `discovery_evidence` for identity, exact/semantic capability match, trusted credential state, and receipt-count reputation input.
- Ranking output is deterministic for a fixed input and explains score components through `ranking.score` and `ranking.reasons`.
- The exact capability candidate with trusted credential and receipt-count evidence outranks the semantic-only candidate.
- `federation-gateway.test.mjs` covers the evidence-first ranking boundary; `docs-contract.test.mjs` guards the public wording.

不做：

- No vector database, no global reputation coin, no public marketplace, and no Go query parity in this slice.
- 不做 opaque vector-only routing。
- 不做 scheduler integration。

## v13.5: Dynamic Swarm Scheduling

状态：complete
目标：把 explicit two-step Swarm proof 推进到 scheduler-owned ready-DAG execution primitive.

新增：

- `FED_SWARM_SCHEDULE` accepts a signed Swarm DAG in the Go federation gateway.
- The scheduler accepts out-of-order input steps and executes them in deterministic dependency-ready order.
- Every scheduled step still uses the existing signed task execution path and produces audit-backed receipts.
- `FED_SWARM_CLOSE` remains complete, ordered, deduplicated, digest-checked, and tied to the same audit.
- Close proof carries signed scheduler evidence with `mode: "ready-dag"` and the executed `step_order`.
- `go-fed-discovery.test.mjs` covers out-of-order ready-DAG execution, dependency artifact binding, and close proof scheduler evidence.

不做：

- No automatic task decomposition, no parallel worker pool, no upper-layer master-agent orchestration, and no economic settlement in this slice.
- 不做 upper-layer demo/master-agent orchestration。
- 不做 agent chat room。
- 不做 economic settlement。

## v13.10: Go FED_QUERY Semantic Discovery Parity

状态：complete
目标：Add Go-side semantic intent scoring and evidence-first ranking to FED_QUERY, closing the Go parity gap deferred in v13.4.

新增：

- `cmd/go-fed-discovery/main.go` `FED_QUERY` now accepts an `intent` string and calls `queryMatch`.
- `queryMatch` returns `discovery_evidence` with `capability`, `credential`, and `reputation` fields, plus `ranking.score` and `ranking.reasons` — mirroring the Node federation-gateway.mjs surface from v13.4.
- `semanticScore` and `tokenize` helpers compute token-overlap intent scoring over alias and capabilities.
- Results are sorted by ranking score descending (alias ascending as a tiebreaker).
- `go-fed-discovery.test.mjs` covers semantic intent query, discovery_evidence shape, ranking score comparison, and ranking reasons.

不做：

- No vector database, no global reputation coin, no public marketplace, and no scheduler integration.
- No Go query parity for the semantic-only edge cases beyond what the Node side already specifies.

## v13.11: Audit-Backed Receipt-Count Reputation

状态：complete
目标：Replace semantic discovery reputation's hardcoded completed-receipt demo value with counts read from the persisted audit log in Node and Go.

新增：

- Node federation gateway reputation counts completed `fed_receipt` audit records for each worker AID from the persisted audit log.
- Go FED_QUERY reputation counts completed `go_fed_receipt` audit records for each worker AID from `f.Audit.Path`.
- Missing, empty, unreadable, or partially malformed audit logs fail safe to zero counted receipts instead of inventing reputation.
- `discovery_evidence.reputation.completed_receipts` remains inspectable, and receipt counts come from the persisted audit log.
- `federation-gateway.test.mjs`, `go-fed-discovery.test.mjs`, and `docs-contract.test.mjs` cover the audit-backed receipt-count boundary.

不做：

- No cross-session ML.
- No global graph.
- No third-party reputation oracle.
- No global reputation coin.
- not a hardcoded demo value, not cross-session ML, not a global reputation oracle.

## v13.12: Credential Validity Window

状态：complete
目标：Add optional `valid_until` expiry to capability credentials so discovery evidence can distinguish trusted-but-expired credentials from active credentials.

新增：

- Capability credentials may carry a `valid_until` ISO UTC expiry in claims; expired credentials lower discovery score and report `active: false` in discovery evidence.
- Node credential verification rejects malformed, non-string, unparseable, or past `valid_until` claims before treating a credential as active.
- Node and Go `FED_QUERY` ranking only adds the credential score boost and `credential_active` reason when the credential is active.
- Credentials without `valid_until` keep the existing active behavior.
- `capability-credential.test.mjs`, `federation-gateway.test.mjs`, `go-fed-discovery.test.mjs`, and `docs-contract.test.mjs` cover the credential validity window boundary.

不做：

- No credential lifecycle service.
- No key custody changes.
- No inter-zone credential transport protocol.
- No distributed credential registry.

## v13 非目标

- No fake public reachability without external-host evidence.
- No upper-layer demo/master-agent orchestration in this repository.
- No A2A/ARD compatibility in v13 unless explicitly re-scoped later.
- No economy/settlement layer.
- No UI/product-platform expansion beyond proof inspection needed by a gate.
- No broad rewrite of v12 verifier/package proof surfaces.

## 验收

```bash
node --test --test-concurrency=1 docs-contract.test.mjs
gofmt -l . && git diff --check
go test ./...
node --test --test-concurrency=1 *.test.mjs
```
