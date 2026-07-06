# Agent Space v10 Roadmap

状态：active
目标：把 v9 已经闭合的 proof/accountability core 推向更容易被外部生态验证和复用的形态，同时继续避免过早做调度器、产品平台或兼容性宣称。

## v10.0: Ed25519 did:key Identity Bridge

状态：complete
目标：Agent Descriptor can expose a W3C-visible `did:key` bridge for the same Ed25519 public key that already defines the canonical `aid:`.

新增：

- Node descriptors include `did_key` derived from `public_key_spki`.
- Go descriptors include `did_key` derived from the same Ed25519 key material.
- Node exports helpers to derive `did:key` from descriptors/SPKI and to round-trip `did:key` back to SPKI.
- Go exports local helpers to derive and round-trip the same bridge.
- Descriptor verification rejects a mismatched optional `did_key`.
- Shared test vectors prove Node and Go agree on the stable requester DID.

不做：

- 不把 `did:key` 变成 canonical identity。
- 不替换 `aid:`。
- 不实现 DID document。
- 不实现 DID resolver。
- 不实现 DID service endpoints。
- 不做 ANP/A2A/AGNTCY compatibility。
- 不做 public identity registry。

## v10.1: Node Artifact Manifest Parity

状态：complete
目标：Node artifact writes produce the same minimal manifest evidence shape already used by Go.

新增：

- Node `writeArtifact` persists `<artifact>.manifest.json`.
- Node artifact manifests include `uri`, `sha256`, `size`, `media_type`, and `manifest_hash`.
- Node MVP, local runtime, and federation gateway receipts bind `artifact_manifests`.
- Node `artifact.created` events carry the produced manifest.

不做：

- 不做 Node content-addressed mirror。
- 不做 Node artifact verify/read API。
- 不做 Node artifact-store GC。
- 不做 object-store backend。
- 不做 Node receipt verifier CLI。

## v10.2: Node Receipt Artifact Manifest Verification

状态：complete
目标：Node `FED_RECEIPT` verification rejects signed-but-invalid artifact manifest metadata.

新增：

- `verifyFederatedReceipt` validates optional `artifact_manifests`.
- Manifest count must match `artifact_refs`.
- Manifest `uri`, required fields, `size`, and `manifest_hash` are checked.
- A signed bad manifest hash is rejected by the vector test.

不做：

- 不读取 artifact bytes。
- 不验证 Node sidecar files。
- 不做 Node artifact verify/read API。
- 不做 receipt store/search。
- 不做 Go verifier package extraction。

## v10.3: Node Local Artifact Verification

状态：complete
目标：Node can verify local artifact bytes and sidecar files against a receipt artifact manifest.

新增：

- `verifyLocalArtifact(manifest)` verifies one local artifact.
- It reuses receipt manifest metadata checks.
- It rejects mismatched sidecar JSON.
- It rejects local artifact size or SHA-256 mismatches.

不做：

- 不做 Node artifact verify/read API。
- 不做 content-addressed mirror。
- 不做 artifact-store GC。
- 不做 remote artifact fetch。
- 不做 batch verifier。

## v10.4: Node Artifact Verify CLI

状态：complete
目标：Expose local Node artifact verification through one command.

新增：

- `node asp-verify.mjs artifact <manifest.json>` verifies one local artifact manifest file.
- The command prints JSON on success.
- The command exits non-zero and prints the verifier error on failure.

不做：

- 不做 npm package。
- 不做 receipt verifier CLI。
- 不做 HTTP artifact verify/read API。
- 不做 batch verification。
- 不做 remote artifact fetch。

## v10.5: Node FED_RECEIPT Verify CLI

状态：complete
目标：Expose Node `FED_RECEIPT` verification through the existing minimal CLI.

新增：

- `node asp-verify.mjs fed-receipt <frame.json> <trusted-zones.json>` verifies one frame.
- The command reuses `verifyFederatedReceipt`.
- The command prints JSON on success.
- The command exits non-zero and prints the verifier error on failure.

不做：

- 不做 npm package。
- 不做 batch verification。
- 不做 receipt store/search。
- 不做 audit-log scan。
- 不做 HTTP verifier service。

## v10.6: Node FED_RECEIPT Local Artifact Closure CLI

状态：complete
目标：Verify one `FED_RECEIPT` frame and the local artifact bytes named by its signed manifests through the existing minimal CLI.

新增：

- `node asp-verify.mjs fed-receipt-artifacts <frame.json> <trusted-zones.json>` verifies one frame.
- The command reuses `verifyFederatedReceipt`.
- The command verifies each signed local artifact manifest with `verifyLocalArtifact`.
- The command rejects artifact refs without artifact manifests because local bytes cannot be checked.
- The command prints JSON on success.
- The command exits non-zero and prints the verifier error on failure.

不做：

- 不做 npm package。
- 不做 batch receipt verification。
- 不做 receipt store/search。
- 不做 audit-log scan。
- 不做 remote artifact fetch。
- 不做 HTTP verifier service。
- 不做 object-store backend。

## v10.7: ASP Core Draft

状态：complete
目标：Publish a narrow English ASP Core draft for the implemented proof layer.

新增：

- `docs/asp-core-draft.md` documents identity, Zone trust, `FED_TASK_OPEN`, `FED_RECEIPT`, artifact manifests, local artifact byte checks, and audit hash-chain evidence.
- The draft states that `aid:` is canonical and `did:key` is only an Ed25519 bridge field.
- The draft explicitly keeps compatibility, scheduling, public discovery, remote artifact fetch, receipt stores, batch verification, reputation, payments, and product UI out of scope.
- `docs-contract.test.mjs` guards the core boundary phrases.

不做：

- 不做 npm package。
- 不做 HTTP verifier service。
- 不做 public node。
- 不做 Docker demo。
- 不做 A2A/ANP/AGNTCY compatibility。
- 不做 DID document resolver。
- 不做 scheduler。
- 不做 semantic routing。

## v10.8: Go FED_RECEIPT Verifier Package

状态：complete
目标：Expose Go `FED_RECEIPT` frame verification as a reusable package function.

新增：

- `agnet/verifier.VerifyFederatedReceipt(frame, trustedZones)` verifies one `FED_RECEIPT` frame.
- The Go discovery gateway interop receipt path delegates to the package function.
- The package verifies trusted Zone identity, worker descriptor identity, `did:key` bridge consistency, Zone binding, `executing_zone`, worker target, receipt signature, and signed artifact manifest metadata when present.
- `verifier/receipt_test.go` proves the package verifies the shared receipt fixture and rejects an `executing_zone` mismatch.

不做：

- 不做 npm package。
- 不做 Go module split。
- 不做 HTTP verifier service。
- 不做 batch receipt verification。
- 不做 receipt store/search。
- 不做 audit-log scan。
- 不做 remote artifact fetch。
- 不做 local artifact byte verification in the package。
- 不做 public node。

## v10.9: One-command Local Proof Demo

状态：complete
目标：Provide a one-command local proof demo using existing prototype and verifier paths.

新增：

- `scripts/proof-demo.sh` runs `node mvp-demo.mjs`.
- The script verifies the generated local artifact manifest with `node asp-verify.mjs artifact`.
- The script prints one JSON result with `proof_demo`, `task_id`, `receipt_signature`, `artifact_verify`, and `artifact_uri`.
- `proof-demo.test.mjs` proves the script runs and returns the expected proof summary.

不做：

- 不做 Docker image。
- 不做 public node。
- 不做 HTTP verifier service。
- 不做 long-running daemon。
- 不做 package release。
- 不做 remote artifact fetch。
- 不做 receipt store/search。

## v10.10: Docker Proof Demo Contract

状态：complete
目标：Add a minimal Docker proof demo contract around the existing local proof demo.

新增：

- `Dockerfile` runs `bash scripts/proof-demo.sh` in a Node image.
- `.dockerignore` keeps local state, artifacts, logs, and `.git` out of the image build context.
- `scripts/docker-proof-demo.sh` builds `agnet-proof-demo` and runs it.
- `docker-demo.test.mjs` guards that the Docker demo delegates to the local proof script.

不做：

- 不做 Docker Compose。
- 不做 public node。
- 不做 HTTP verifier service。
- 不做 long-running daemon。
- 不做 package release。
- 不做 remote artifact fetch。
- 不做 receipt store/search。
- 不声称本机已经运行过 Docker image；当前验证环境 Docker daemon 不可用。

## v10.11: Local Proof Receipt Closure Files

状态：complete
目标：Make the one-command local proof demo emit verifier-ready receipt closure files.

新增：

- `mvp-demo.mjs` includes `origin_zone` and `executing_zone` in its signed local receipt.
- `mvp-demo.mjs` emits a local `FED_RECEIPT` frame and trusted Zone set for the same demo receipt.
- `scripts/proof-demo.sh` writes `state/proof-demo-fed-receipt.json` and `state/proof-demo-trusted-zones.json`.
- `scripts/proof-demo.sh` verifies those files with `node asp-verify.mjs fed-receipt-artifacts`.
- `proof-demo.test.mjs` proves the emitted files can be re-verified by the existing CLI.

不做：

- 不做 Docker image 实跑声明。
- 不做 npm package。
- 不做 HTTP verifier service。
- 不做 public node。
- 不做 batch verification。
- 不做 receipt store/search。
- 不做 remote artifact fetch。
- 不做 Swarm scheduler。
- 不做 A2A/ANP/AGNTCY compatibility。

## v10.12: Zone-signed Swarm Close Proof

状态：complete
目标：Make `FED_SWARM_CLOSE` carry a Zone-signed close proof for completed Swarm steps.

新增：

- Go `FED_SWARM_CLOSE` includes a `close` proof object.
- `close.step_receipts` lists completed steps in execution order with `step_id`, `task_id`, and `receipt_digest`.
- `close.close_signature` is signed by the local Zone authority key.
- `go-fed-discovery.test.mjs` verifies the close proof contents and signature.

不做：

- 不做 dynamic Swarm decomposition。
- 不做 scheduler-owned DAG execution。
- 不做 parallel Swarm execution。
- 不做 conflict/merge receipts。
- 不做 cross-Zone Swarm。
- 不做 Swarm UI。
- 不做 receipt store/search。
- 不做 A2A/ANP/AGNTCY compatibility。

## v10.13: Audit-backed Swarm Close Verification

状态：complete
目标：Make Swarm close proof audit-backed and verifier-checked.

新增：

- Go `executeSwarm` appends `go_swarm_close` audit records with the Zone-signed close proof.
- `--verify-audit` verifies `go_swarm_close.close_signature`.
- `--verify-audit` checks close `step_receipts` against same-audit Swarm receipt state by `step_id`, `task_id`, and `receipt_digest`.
- `go-fed-discovery.test.mjs` proves live Swarm close records appear through the Human Gateway audit API.
- `cmd/go-fed-discovery/main_test.go` proves a tampered close receipt digest is rejected.

不做：

- 不做 dynamic Swarm decomposition。
- 不做 scheduler-owned DAG execution。
- 不做 parallel Swarm execution。
- 不做 conflict/merge receipts。
- 不做 cross-Zone Swarm。
- 不做 Swarm UI。
- 不做 receipt store/search。
- 不做 A2A/ANP/AGNTCY compatibility。

## v10.14: Complete Swarm Close Summary Verification

状态：complete
目标：Make Swarm close proof complete, not just individually valid.

新增：

- `--verify-audit` rejects `go_swarm_close` records that omit completed same-audit Swarm steps.
- `--verify-audit` rejects duplicate `close.step_receipts` entries for the same step id.
- Existing close proof signature, task id, and receipt digest checks still apply.
- `cmd/go-fed-discovery/main_test.go` proves incomplete and duplicate close summaries are rejected.

不做：

- 不做 dynamic Swarm decomposition。
- 不做 scheduler-owned DAG execution。
- 不做 parallel Swarm execution。
- 不做 conflict/merge receipts。
- 不做 cross-Zone Swarm。
- 不做 Swarm UI。
- 不做 receipt store/search。
- 不做 A2A/ANP/AGNTCY compatibility。

## v10.15: Ordered Swarm Close Summary Verification

状态：complete
目标：Make Swarm close proof order match same-audit completion order.

新增：

- `--verify-audit` preserves same-audit Swarm step completion order while scanning receipts.
- `--verify-audit` rejects `go_swarm_close.step_receipts` whose order differs from completed Swarm receipt order.
- Existing close proof completeness, duplicate-step, signature, task id, and receipt digest checks still apply.
- `cmd/go-fed-discovery/main_test.go` proves a reversed close summary is rejected.

不做：

- 不做 dynamic Swarm decomposition。
- 不做 scheduler-owned DAG execution。
- 不做 parallel Swarm execution。
- 不做 conflict/merge receipts。
- 不做 cross-Zone Swarm。
- 不做 Swarm UI。
- 不做 receipt store/search。
- 不做 A2A/ANP/AGNTCY compatibility。

## v10.16: Duplicate Swarm Close Rejection

状态：complete
目标：Reject duplicate Swarm close proofs in the same audit.

新增：

- `--verify-audit` tracks closed Swarm ids while scanning audit records.
- A second `go_swarm_close` record for the same `swarm_id` is rejected.
- Existing close proof signature, completeness, duplicate-step, ordering, task id, and receipt digest checks still apply.
- `cmd/go-fed-discovery/main_test.go` proves duplicate close records are rejected.

不做：

- 不做 dynamic Swarm decomposition。
- 不做 scheduler-owned DAG execution。
- 不做 parallel Swarm execution。
- 不做 conflict/merge receipts。
- 不做 cross-Zone Swarm。
- 不做 Swarm UI。
- 不做 receipt store/search。
- 不做 A2A/ANP/AGNTCY compatibility。

## v10.17: Known Swarm Close Rejection

状态：complete
目标：Reject close proofs for Swarms that have no same-audit receipts.

新增：

- `--verify-audit` requires a `go_swarm_close` proof to reference a Swarm id with at least one completed step receipt earlier in the same audit.
- Empty `step_receipts` can no longer close an audit-absent Swarm.
- Existing close proof signature, duplicate-close, completeness, duplicate-step, ordering, task id, and receipt digest checks still apply.
- `cmd/go-fed-discovery/main_test.go` proves unknown empty Swarm close proofs are rejected.

不做：

- 不做 dynamic Swarm decomposition。
- 不做 scheduler-owned DAG execution。
- 不做 parallel Swarm execution。
- 不做 conflict/merge receipts。
- 不做 cross-Zone Swarm。
- 不做 Swarm UI。
- 不做 receipt store/search。
- 不做 A2A/ANP/AGNTCY compatibility。
- 不做 cross-audit Swarm lifecycle storage。

## v10.18: Delimiter-Safe Swarm IDs

状态：complete
目标：Reject NUL-bearing Swarm ids before they can cross the internal receipt key delimiter.

新增：

- `FED_SWARM_OPEN` rejects `swarm_id`, `step_id`, and dependency ids containing NUL bytes.
- `--verify-audit` rejects Swarm receipt identities and close proof step identities containing NUL bytes.
- The verifier preserves the internal `swarm_id + "\x00" + step_id` boundary.
- `cmd/go-fed-discovery/main_test.go` proves NUL-bearing Swarm receipt ids are rejected.

不做：

- 不做 full Swarm id normalization。
- 不做 dynamic Swarm decomposition。
- 不做 scheduler-owned DAG execution。
- 不做 parallel Swarm execution。
- 不做 conflict/merge receipts。
- 不做 cross-Zone Swarm。
- 不做 Swarm UI。
- 不做 receipt store/search。
- 不做 A2A/ANP/AGNTCY compatibility。

## v10.19: Minimal AFP Artifact Manifests

状态：complete
目标：Add minimal AFP hash interoperability where it clarifies artifact proof.

新增：

- Node and Go artifact manifests include `afp: "afp:sha256:<sha256>"`.
- Node receipt/local artifact verification rejects mismatched `afp` when present.
- Go audit verification and the reusable Go receipt verifier reject mismatched `afp` when present.
- ASP Core draft documents the narrow `afp:sha256:<sha256>` manifest field.

不做：

- 不做 AFP full spec。
- 不做 multihash/multicodec。
- 不做 remote artifact fetch。
- 不做 public node。
- 不做 receipt store/search。

## v10.20: Docker Proof Output

状态：complete
目标：Publish verified Docker proof demo output.

新增：

- Verified `bash scripts/docker-proof-demo.sh` on Docker Server `29.0.1`.
- The Docker proof run produced `proof_demo: "ok"`, `artifact_verify: "ok"`, and `fed_receipt_artifacts_verify: "ok"`.
- `docs/v10.20-boundary.md` records the proof output.

不做：

- 不做 public node。
- 不做 hosted demo。
- 不做 image publishing。
- 不做 supply-chain attestation。
- 不做 container namespace sandbox。

## v10.21: Local Public-Listen Proof

状态：complete
目标：Add a local public-node proof path without claiming real public deployment.

新增：

- `scripts/public-node-proof.sh` builds the Go gateway and runs a proof helper.
- `scripts/public-node-proof.mjs` starts the gateway with `--listen-host 0.0.0.0`.
- The proof output includes `public_node_proof: "ok"`, `listen_host: "0.0.0.0"`, `public_transport: true`, and `transport: "fed+tcp"`.
- `public-node-proof.test.mjs` runs the proof script end to end.

不做：

- 不做公网可达性证明。
- 不做 NAT / relay。
- 不做 hosted public node。
- 不做 TLS certificate issuance。
- 不做 QUIC。
- 不做 deployment automation。

## v10.22: Public-Listen Resolve Proof

状态：complete
目标：Prove the local public-listen node can serve one authenticated federation frame.

新增：

- `scripts/public-node-proof.mjs` creates a trusted proof origin Zone.
- The proof helper connects to the public-listen gateway over TCP.
- It completes `HELLO` / `AUTH`.
- It sends `FED_RESOLVE` for `agent://zone-b/summarizer`.
- The proof output includes `resolve_alias: "agent://zone-b/summarizer"` and `resolve_close: true`.

不做：

- 不做公网可达性证明。
- 不做 NAT / relay。
- 不做 hosted public node。
- 不做 TLS certificate issuance。
- 不做 QUIC。
- 不做 deployment automation。
- 不做 broad protocol probe suite beyond one `FED_RESOLVE` round trip。

## v10.23: Public-Listen Query Proof

状态：complete
目标：Prove the local public-listen node can answer a capability query.

新增：

- `scripts/public-node-proof.mjs` sends authenticated `FED_QUERY` for `summarize.text`.
- The proof output includes `query_capability: "summarize.text"`.
- The proof output includes `query_match_count: 1`.
- The proof output includes `query_status: "active"`.
- The existing authenticated `FED_RESOLVE` proof remains.

不做：

- 不做公网可达性证明。
- 不做 NAT / relay。
- 不做 hosted public node。
- 不做 TLS certificate issuance。
- 不做 QUIC。
- 不做 deployment automation。
- 不做 broad protocol probe suite beyond `FED_RESOLVE` and `FED_QUERY`。

## v10.24: Public-Listen Task Proof

状态：complete
目标：Prove the local public-listen node can execute a signed task.

新增：

- `scripts/public-node-proof.mjs` sends authenticated `FED_TASK_OPEN` to `agent://zone-b/summarizer`.
- The proof output includes `task_id: "public_node_probe_task"`.
- The proof output includes `task_receipt: true`.
- The proof output includes `task_close: true`.
- The public proof watchdog is 60 seconds to cover full verification runs after task execution was added.

不做：

- 不做公网可达性证明。
- 不做 NAT / relay。
- 不做 hosted public node。
- 不做 TLS certificate issuance。
- 不做 QUIC。
- 不做 deployment automation。
- 不做 broad protocol probe suite beyond `FED_RESOLVE`, `FED_QUERY`, and one `FED_TASK_OPEN`。

## v10.25: Public-Listen Audit Proof

状态：complete
目标：Prove the local public-listen node can return audit receipt proof for the task it executed.

新增：

- `scripts/public-node-proof.mjs` sends authenticated `FED_AUDIT_QUERY` after the public-listen task completes.
- The audit query requests `public_node_probe_task`.
- The proof output includes `audit_task_id: "public_node_probe_task"`.
- The proof output includes `audit_receipt: true`.
- The proof output includes `audit_close: true`.
- The existing public-listen resolve, query, and task execution proof remains.

不做：

- 不做公网可达性证明。
- 不做 NAT / relay。
- 不做 hosted public node。
- 不做 TLS certificate issuance。
- 不做 QUIC。
- 不做 deployment automation。
- 不做 remote audit sync。
- 不做 audit search/index。
- 不做 broad protocol probe suite beyond the one proof path.

## Next Candidates

1. Make the public proof verifier-ready by emitting the fetched `FED_RECEIPT` frame and trusted Zone set.
2. Add an npm-facing verifier only when the existing Node exports are not enough.
3. Continue Swarm proof work only where it adds verifiable accountability, not scheduler breadth.
