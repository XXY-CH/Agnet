# Agent Space v13 Roadmap

状态：active at v13.2
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

Remaining exit criterion:

- A real hosted external-host observer run against a globally routable literal-IP listener has not happened yet.

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

状态：planned
目标：从 honest local-process sandbox evidence 推进到 stronger isolation and remote attestation evidence.

验收边界：

- Sandbox mode claims are verifier-owned and fail closed when the required runtime is unavailable.
- Strong sandbox evidence records runtime identity, policy, mounted write surface, network surface, command identity, and transcript/artifact digests.
- Remote attestation evidence, if implemented in this gate, must be signed, bound to the task/receipt digest, and rejected when stale or mismatched.

不做：

- 不把 unsupported container namespace probes called supported。
- 不把 local sandbox proof called hardware remote attestation。
- 不做 broad VM/container orchestration unless the proof requires it.

## v13.4: Semantic Discovery and Reputation Ranking

状态：planned
目标：在现有 identity/capability query 上增加语义发现和信誉排序，但保持身份、凭证、策略和 receipt evidence 优先。

验收边界：

- Candidate discovery returns inspectable candidate sets with identity, capability, credential, policy, availability, and evidence fields.
- Ranking output is deterministic for a fixed input and explains score components instead of hiding behind an opaque vector score.
- Reputation inputs come from signed/audited receipts or explicitly scoped local evidence.
- Negative tests prove untrusted, missing-evidence, policy-incompatible, or identity-mismatched candidates cannot outrank valid candidates just by semantic similarity.

不做：

- 不做 global reputation coin。
- 不做 opaque vector-only routing。
- 不做 public marketplace。

## v13.5: Dynamic Swarm Scheduling

状态：planned
目标：把 v9/v10 的 explicit two-step Swarm proof 推进到 scheduler-owned task DAG execution.

验收边界：

- A scheduler can build or accept a DAG, assign steps to workers, execute ready steps, and produce audit-backed receipts for every completed step.
- Close proof remains complete, ordered, deduplicated, digest-checked, and tied to the same audit.
- Failure, retry, dependency, conflict, and approval boundaries are explicit in receipt/audit evidence.
- Tests cover ready-step ordering, parallel-safe dependencies, failed-step blocking, retry lineage, duplicate-step rejection, and close proof completeness.

不做：

- 不做 upper-layer demo/master-agent orchestration。
- 不做 agent chat room。
- 不做 economic settlement。

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
