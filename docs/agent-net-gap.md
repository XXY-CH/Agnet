# Agent Net Gap

状态：v10.23 assessment

## 一句话

当前项目是 Agent Net 的 protocol seed，不是 Agent Net 产品。

它已经抓住了真正 Agent Net 的底层骨架：identity with a narrow Ed25519 `did:key` bridge、Node/Go artifact manifest evidence and local verification CLI、minimal AFP `afp:sha256:<sha256>` strings、Node/Go receipt verification CLIs、one-receipt local artifact closure verification、implementation-backed ASP Core draft、reusable Go `FED_RECEIPT` verifier package、one-command local proof demo with verifier-ready receipt/trust files、verified Docker proof demo、local public-listen resolve/query proof、signed task、policy、artifact、receipt、audit、federation、Node/Go bidirectional task interop、Go federation explicit bind host primitive、shared `FED_TASK_OPEN` / `FED_RECEIPT` conformance fixtures，以及 Go 侧最小 explicit Swarm DAG seed、single ordered complete audit-backed Zone-signed Swarm close proof tied to same-audit receipts、delimiter-safe Swarm ids 和同 audit Swarm dependency step/receipt verification。

它还缺产品面、运行面、部署面、多人协作面和真实工具执行面。

## 离真正 Agent Net 还有多远

### Protocol core

进度：约 95%。

已有：

- Ed25519 Agent/Zone identity。
- Ed25519 Agent descriptor `did:key` bridge in Node and Go, while `aid:` remains canonical。
- Node and Go receipts can bind artifact manifests, not only artifact refs。
- Node and Go artifact manifests include minimal AFP strings in the `afp:sha256:<sha256>` shape。
- Node `FED_RECEIPT` verification rejects signed artifact manifest metadata with a bad manifest hash。
- Node can verify local artifact bytes, AFP strings, and sidecars against the receipt manifest。
- Node exposes local artifact verification through `asp-verify.mjs artifact <manifest.json>`。
- Node exposes single `FED_RECEIPT` frame verification through `asp-verify.mjs fed-receipt <frame.json> <trusted-zones.json>`。
- Node exposes single `FED_RECEIPT` frame plus local artifact byte verification through `asp-verify.mjs fed-receipt-artifacts <frame.json> <trusted-zones.json>`。
- `docs/asp-core-draft.md` captures the narrow implemented proof layer in English。
- Go exposes reusable `agnet/verifier.VerifyFederatedReceipt` for one `FED_RECEIPT` frame。
- `scripts/proof-demo.sh` runs the local MVP, emits verifier-ready receipt/trust files, and verifies the generated artifact manifest plus local receipt closure。
- `Dockerfile` and `scripts/docker-proof-demo.sh` produce a verified Docker proof demo output on Docker Server `29.0.1`。
- `scripts/public-node-proof.sh` starts the Go federation gateway on `0.0.0.0`, proves `public_transport: true` locally, and completes authenticated `FED_RESOLVE` / `FED_QUERY` TCP round trips。
- shared Node/Go `FED_TASK_OPEN` and `FED_RECEIPT` conformance fixtures。
- Go `FED_SWARM_OPEN` explicit two-step DAG seed with signed artifact dependency evidence。
- Go `FED_SWARM_CLOSE` carries one ordered complete audit-backed Zone-signed close proof over ordered same-audit step receipt digests。
- Go audit verification rejects duplicate Swarm step receipts, including artifactless duplicates, NUL-bearing Swarm ids, and signed Swarm dependency claims that do not match declared dependency steps, upstream step artifact manifests, or receipt digests in the same audit。
- `agent://` alias -> `aid:` descriptor。
- signed task。
- policy scope。
- event stream。
- artifact ref。
- signed receipt。
- hash-chained audit。
- Zone federation。
- capability credential。
- Go discovery/trust path through v2.4。
- Go trusted Zone store applies local Zone revocations。
- Go trusted Zone store rejects tampered local Zone revocations at load time。
- Go minimal execution path in v3。
- Go audit path in v3.1。
- Go multi-worker registry in v3.2。
- WebSocket binding in v3.3。
- Thin Human Gateway in v3.4。
- Built-in pure-text tool adapter in v3.5。
- External stdio tool adapter in v3.6。
- Minimal MCP stdio tools/call in v3.7。
- Simulated external/MCP tool approval gate in v3.8。
- Signed local approval evidence and sandbox evidence in v3.9。
- Protocol-native checkpoint evidence in v4。
- Artifact manifest digest evidence in v4.1。
- Canonical policy scope evidence in v4.2。
- Zone-signed credential status evidence in v4.3。
- Authenticated session handshake in v4.4。
- Remote audit proof query in v4.5。
- Signed sandbox proof evidence in v5.0。
- Minimal checkpoint resume parent link in v5.1。
- Signed cancellation receipt evidence in v5.2。
- Retry lineage evidence in v5.3。
- Sandbox claim binding in v5.4。
- Tool command provenance digest in v5.5。
- Tool output digest alignment in v5.6。
- MCP initialize metadata evidence in v5.7。
- MCP resources/prompts metadata evidence in v5.8。
- MCP tools/list metadata evidence in v5.9。
- MCP selected tool binding in v5.10。
- MCP selected tool schema digest in v5.11。
- MCP tools/call argument digest in v5.12。
- MCP required argument gate in v5.13。
- Sandbox isolation level evidence in v5.14。

主要缺：

- credential revocation feed / renewal beyond local Zone revocation。
- richer routing beyond exact matches。
- DID-native document/resolver/service endpoint semantics。

### Runtime core

进度：约 87%。

已有：

- Node prototype runtime。
- Node federation execution path。
- Node audit appends are serialized inside one process。
- Go discovery gateway with minimal deterministic execution。
- Go audit verifier for execution evidence, including larger JSONL audit entries。
- Go exact-match multi-worker routing。
- Go built-in pure-text tool execution。
- Go external stdio tool execution envelope。
- Go minimal MCP stdio tools/call execution。
- Simulated tool approval gate。
- Minimal `FED_TASK_RESUME` execution that links a new receipt to a parent checkpoint。
- Signed `FED_TASK_CANCEL` evidence with worker cancellation receipts。
- `FED_TASK_RETRY` lineage evidence with normal task execution。
- Sandbox claim binding prevents overclaiming local-temp-dir as stronger isolation。
- Unsupported sandbox claims are rejected before Human Gateway approval and external/MCP tool startup。
- External/MCP sandbox evidence records tool command, executable binary, and result transcript digests。
- External/MCP result transcripts are persisted as local artifacts linked from signed receipts。
- Tool output digest aligns signed receipt with artifact manifest。
- A single Go receipt record can be verified directly from a JSON file。
- Artifact manifests persist as local sidecars and are retrievable through a read-only Human Gateway API。
- Artifacts are also written under a local content-addressed SHA-256 path。
- Artifacts can also mirror bytes and manifest sidecars to a configured filesystem artifact store。
- Audit verification rejects local artifact bytes that no longer match signed manifests。
- Audit verification rejects named artifact sidecars that no longer match signed manifests。
- Audit verification rejects digest-addressed artifact sidecars that no longer match signed manifests。
- Audit verification can reject filesystem artifact mirror bytes, sidecars, or index entries that no longer match signed manifests。
- MCP sandbox evidence records protocol/server initialize metadata。
- MCP resources/prompts surfaces are recorded as count+digest evidence。
- MCP tools surface is recorded as count+digest evidence。
- Selected MCP tool is bound to a `tools/list` descriptor digest。
- Selected MCP tool input schema is recorded as digest evidence。
- MCP tool arguments are recorded as digest evidence。
- MCP tool arguments are rejected when selected schema required fields are missing。
- External/MCP sandbox evidence records explicit `local-process` isolation level。
- External/MCP tool environments bind `HOME`, `TMPDIR`, and `XDG_CACHE_HOME` to the local sandbox directory。
- Completed/cancelled Go tasks persist minimal state files linked to receipt digests。
- Go task, approval, queue, requester registry, and requester rebinding JSON state files are replaced through same-directory temp files and rename。
- Failed Go task execution persists error state before a receipt exists。
- Signed task cancellation interrupts a running external tool through the in-memory runtime registry。
- Running Go tasks persist state before external/MCP execution completes。
- Failed Go queue items can be explicitly retried with durable retry/backoff state。
- Human Gateway exposes durable queue state and explicit local claim/drain actions。
- Human Gateway can enqueue already signed tasks through the local queue action API。
- Checkpoint resume can be queued durably before explicit drain。
- Queued checkpoint resume records restored parent checkpoint state digest evidence。
- Human/local queue actions are recorded as hash-chained audit evidence。
- Human/local queue actions require signed action grants。
- Human/local queue action grants bind a local actor string。
- Human/local queue actions pass a configurable local actor allowlist。
- Human/local queue action audit records include actor evidence and local policy result evidence when the policy gate is reached。
- Human/local queue action grants carry action scope and expiry。
- Human/local queue action grants are rejected on replay through a durable local nonce index。
- Human Gateway can draft, locally sign, and enqueue queued tasks through the existing queue action path。
- Human Gateway can accept externally signed requester tasks through the draft endpoint without holding the requester private key。
- Human Gateway write actions can require a bearer token before mutation。
- Human Gateway exposes its local deployment security posture through `/api/security`。
- Human Gateway page can generate, export, import, rotate, bind the alias for, and use a browser-held requester key to submit signed queue drafts。
- Human Gateway can issue a Zone-signed requester alias rebinding proof after verifying browser requester rotation proof。
- Human Gateway persists rebound requester aliases in a multi-alias local registry JSON file。
- Human Gateway exposes the local requester registry as a read-only API and table。
- Human Gateway exposes a local requester alias rebinding history API and table。
- Direct Go tool tasks wait for explicit Human Gateway approval before execution。
- Go approval state modifications are serialized inside one process。
- Queued Go drains wait for explicit Human Gateway approval before tool execution。
- Human Gateway approvals can deny or expire before tool execution。
- Human Gateway direct approvals preserve named local `human://...` actors in signed approval grants。
- Human Gateway direct approval actors pass a configurable local allowlist。
- Human Gateway direct approvals can derive the actor from configured local bearer approval sessions。
- Human Gateway direct approval body actors cannot mismatch the configured bearer session actor。
- Human Gateway exposes read-only local approval session state through `/api/session`。
- Human Gateway page displays local approval session state from `/api/session`。
- Human Gateway receipt table links all receipt artifacts, including persisted tool transcripts。
- Human Gateway receipt table links artifacts to their task-scoped manifest proof API, whose HEAD response exposes proof headers without bytes。
- Human Gateway exposes task-scoped audit receipt proofs with audit hashes through `/api/audit?task_id=...` and receipt proof links。
- Human Gateway verifies and reads receipt-scoped artifacts through `/api/artifacts/verify?task_id=...&uri=...`, `GET/HEAD /api/artifacts/read?task_id=...&uri=...`, signed proof headers, verify proof fields, receipt digest headers, audit hash headers, and receipt links。
- Human Gateway streams completed tool transcripts through `/api/transcripts/stream?task_id=...` with receipt/audit/transcript proof headers。
- Human Gateway receipt rows can load completed task transcript streams into a local transcript viewer。
- Human Gateway reads running external tool stdout snapshots through `/api/transcripts/live?task_id=...`。
- Human Gateway running task rows can load live transcript snapshots into the local transcript viewer。
- Human Gateway live transcript loading polls the running snapshot until another transcript is selected。
- MCP stdio responses are copied into live transcript snapshots as NDJSON。
- Filesystem artifact mirrors maintain and verify an `objects.ndjson` content-addressed object index, can produce a GC plan, and can delete orphaned mirror objects from that plan。
- Explicit Swarm seed executes two ordered Go worker steps with NUL-delimited id hardening, signs the downstream artifact dependency into the receipt, appends one close proof to audit, and verifies complete close proof step order and digests against same-audit receipts; empty close proofs for audit-absent Swarms are rejected。
- Audit verification checks Swarm dependency step uniqueness even without artifacts, plus dependency step ids, artifact manifest, and receipt digest claims against prior completed steps in the same audit。

主要缺：

- dynamic Swarm decomposition, candidate selection, scheduler-owned DAG execution, parallel execution, conflict resolution, and cross-Zone Swarm。
- richer MCP sessions/resources/prompts。
- real container namespace sandbox; unsupported `container-namespace` claims currently fail before approval/tool start, persist runtime probe evidence, can distinguish missing versus configured `AGNET_CONTAINER_RUNTIME` candidates, can fingerprint readable runtime binaries with `runtime_sha256`, and can be checked with `--sandbox-probe` or required fail-closed with `--sandbox-require`。
- Node cross-process audit locking and distributed audit log sync。
- cross-process approval locking。
- broader concurrency model。
- encrypted browser-side private-key storage。
- browser multi-key manager。
- Human Gateway requester selector UI。
- server-side rotation registry。
- passphrase-protected requester key export。
- roles / full login system。
- token storage / rotation。
- model KV/cache checkpoint restore。
- automatic retry / backoff scanning。
- package signature / SBOM provenance。
- SSE/WebSocket live transcript tailing protocol。
- long-running MCP session reuse。
- full MCP resource/prompt catalog storage。
- full MCP schema verification。
- remote object-store API and retention policy beyond the verified filesystem mirror index。

### Network layer

进度：约 30%。

已有：

- newline JSON over local TCP。
- Go federation TCP can bind an explicitly configured host while defaulting to `127.0.0.1`。
- WebSocket text-frame binding。
- authenticated session handshake。
- local process proof。

主要缺：

- QUIC binding / public transport deployment; Go federation TCP can run with mTLS client certificate verification, bind certificate URI SANs to the claimed Zone identity, bind a configured host, and prove local `0.0.0.0` authenticated `FED_RESOLVE` / `FED_QUERY` round trips, but no public reachability/NAT/relay proof exists yet。
- public gateway deployment。
- NAT/proxy story。
- service discovery beyond static trusted stores。
- observability and ops。

### Product layer

进度：约 19%。

已有：

- CLI/test flows。
- read-only Human Gateway。
- simulated approval events。
- direct Human Gateway approval API。
- queued drain Human Gateway approval gate。
- approval denial/expiry gate。
- named local human actor evidence in direct approval grants。
- configurable local approval actor allowlist。
- local bearer approval session actor mapping。
- local approval session/body actor mismatch rejection。
- read-only local approval session state API and page panel。
- signed approval receipts visible through Human Gateway。
- transcript artifact links visible through Human Gateway receipts。
- artifact manifest links visible through Human Gateway receipts。
- task-scoped audit receipt proof links visible through Human Gateway receipts。
- receipt-scoped artifact verify/read links visible through Human Gateway receipts。
- local deployment security posture API。
- browser-held requester key, rotation proof, rebinding proof API, local requester registry, requester registry table, alias rebinding UI, rebinding history table, and signed draft UI。
- running task live transcript snapshot button, polling, MCP response snapshots, artifact mirror object index, and viewer load action。
- read-only artifact manifest API。
- checkpoint evidence receipts。
- docs and protocol proofs。

主要缺：

- roles / full login system。
- artifact browser。
- audit viewer。
- admin / tenant model。
- installation and deployment story。

## 与 Octo 的差距

参考对象：

- [Mininglamp-OSS/OCTO](https://github.com/Mininglamp-OSS/OCTO)
- [octo-server](https://github.com/Mininglamp-OSS/octo-server)

Octo 当前更像 AI-native team collaboration product。

它的强项是人类和 Agent 的协作界面：

- Space / Category / Channel / Thread。
- web / desktop / mobile / admin clients。
- Go server。
- REST + WebSocket。
- Lobster agent orchestration。
- WuKongIM messaging/control plane。
- MySQL / Redis / MinIO deployment stack。

Agent Space 当前更像 lower-level task fabric。

它的强项是协议可信边界：

- Agent/Zone cryptographic identity。
- signed descriptor。
- signed task。
- Zone binding。
- capability credential。
- signed receipt。
- audit hash chain。
- cross-Zone federation proof。

## 对比矩阵

| Area | Octo | Agent Space |
| --- | --- | --- |
| Primary shape | collaboration product | protocol/runtime proof |
| Human workspace | strong | missing |
| Multi-client app | strong | missing |
| Messaging substrate | strong | local proof only |
| Agent orchestration | product-level | protocol-level |
| Cryptographic task identity | unclear from top-level docs | strong |
| Signed receipt/audit | unclear from top-level docs | strong prototype |
| Federation trust model | not the main visible layer | core focus |
| Deployment | Docker Compose stack | test/local only |
| Best next move | deepen trust/runtime layer | add execution + thin UI later |

## Practical Read

Octo is ahead as an app.

Agent Space is ahead as a signed task / federation protocol seed.

Trying to clone Octo now would pull this project sideways into chat/product surface before the protocol spine is strong enough.

The right path is:

```text
v4.4 authenticated session handshake
```

After v5.1, comparing with Octo is useful mainly for the Human Gateway/product layer, not for replacing Agent Space's protocol spine.

Octo should be treated as a possible Human Gateway layer above Agent Space, not as the thing to copy line by line.
