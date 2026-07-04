# Agent Space v8 Roadmap

状态：v8.15 complete; v8.16+ planned
目标：把 v7 的 durable queue/Human Gateway proof 推向更真实的产品控制面，先补 human approval，再补身份/key UX 和部署安全。

## v8.0: Human Gateway Explicit Approval

状态：complete
目标：direct tool task execution must pause on pending Human Gateway approval instead of auto-granting before tool execution.

新增：

- Direct `FED_TASK_OPEN`, `FED_TASK_RESUME`, and `FED_TASK_RETRY` executions with tool approval requirements write pending approval state.
- Human Gateway serves `GET /api/approvals`.
- Human Gateway serves `POST /api/approvals/actions` for explicit local `approve`.
- Approved tasks resume execution and emit the existing signed `approval.granted` event.
- Human Gateway page renders an Approvals table.

不做：

- 不阻塞 queued drain approval。
- 不做 browser-side identity/key UX。
- 不做 login/session identity。
- 不做 approval denial/expiry。
- 不做 public deployment。

## v8.1: Queued Drain Explicit Approval

状态：complete
目标：queued drain must pause on pending Human Gateway approval before tool execution.

新增：

- `FED_QUEUE_DRAIN` writes pending approval state when the queued worker requires tool approval.
- Human Gateway queue `drain` action also waits for explicit approval before returning completed execution.
- Approved queued drains emit the existing signed `approval.granted` event and receipt evidence.
- Failed queued drains still require approval before tool/schema execution can fail.

不做：

- 不做 approval denial/expiry。
- 不做 login/session identity。
- 不做 scheduler auto-drain。
- 不做 browser-side identity/key UX。
- 不做 public deployment。

## v8.2: Approval Denial and Expiry

状态：complete
目标：pending approvals can deny or expire before tool execution.

新增：

- Human Gateway `POST /api/approvals/actions` supports local `deny`.
- Pending approval state records `expires_at`.
- Denied approvals stop execution before `task.started`.
- Expired approvals stop execution before `task.started` and persist `expired` state.

不做：

- 不做 denial reason schema。
- 不做 role model。
- 不做 login/session identity。
- 不做 background expiry scanner。
- 不做 public deployment。

## v8.3: Browser-held Requester Draft Boundary

状态：complete
目标：Human Gateway draft endpoint can accept externally signed requester tasks without owning the requester private key.

新增：

- `POST /api/queue/drafts` accepts `requester` and signed `task`.
- The external requester `aid` and task signature are preserved.
- External draft enqueue reuses the existing actor-bound queue action grant path.
- `/api/queue` exposes the newly queued external draft task.
- `go_queue_action` audit records the enqueue with actor policy evidence.

不做：

- 不做 browser private-key storage。
- 不做 WebCrypto UI。
- 不做 login/session identity。
- 不做 requester key management UI。
- 不做 public deployment。

## v8.4: Human Gateway Write Token

状态：complete
目标：Human Gateway write actions can require a local bearer token before mutation.

新增：

- Go gateway accepts `--human-token`.
- `POST /api/approvals/actions` requires `Authorization: Bearer <token>` when configured.
- `POST /api/queue/actions` requires the same token when configured.
- `POST /api/queue/drafts` requires the same token when configured.
- Unauthenticated writes return `401` before queue or approval mutation.

不做：

- 不做 login/session identity。
- 不做 role model。
- 不做 CSRF/session cookies。
- 不做 TLS/QUIC/public transport。
- 不做 token storage or rotation。
- 不开放非 localhost bind。

## v8.5: Human Gateway Security Posture

状态：complete
目标：Human Gateway exposes its local deployment security posture as a read-only API.

新增：

- `GET /api/security` reports the local bind host.
- `GET /api/security` reports whether the Human Gateway write token is required.
- `GET /api/security` reports that public transport is not enabled.

不做：

- 不做 login/session identity。
- 不做 role model。
- 不做 CSRF/session cookies。
- 不做 TLS/QUIC/public transport。
- 不做 token storage or rotation。
- 不开放非 localhost bind。

## v8.6: Browser Requester Key UI

状态：complete
目标：Human Gateway page can manage a browser-held requester key and submit signed queue drafts without giving the private key to Go.

新增：

- Human Gateway page exposes a Browser Requester Key panel.
- Browser WebCrypto generates an Ed25519 requester key.
- Browser `localStorage` keeps the requester private key under `agent-space-browser-requester`.
- The browser derives `aid`, self-signs `descriptor_signature`, signs a draft task, and posts it to `POST /api/queue/drafts`.
- The draft submit path reuses the existing external signed draft enqueue verification path.

不做：

- 不做 login/session identity。
- 不做 role model。
- 不做 encrypted key store。
- 不做 cross-browser key sync。
- 不做 key rotation UI。
- 不做 polished task builder。
- 不做 public deployment。

## v8.7: Browser Requester Key Import/Export

状态：complete
目标：Human Gateway page can export and import the browser-held requester key bundle without giving the private key to Go.

新增：

- Browser Requester Key panel exposes `Export Key`.
- Browser Requester Key panel exposes `Import Key`.
- Export copies the current `{ descriptor, privateJwk }` bundle into a browser text field.
- Import stores that same bundle shape back under `agent-space-browser-requester`.
- Imported keys reuse the existing signed draft submission path.

不做：

- 不做 encrypted key store。
- 不做 passphrase-protected export。
- 不做 key rotation ceremony。
- 不做 multi-key account manager。
- 不做 cross-browser sync。
- 不做 login/session identity。
- 不做 server-side key custody。
- 不做 public deployment。

## v8.8: Browser Requester Key Rotation Proof

状态：complete
目标：Human Gateway page can rotate the browser-held requester key and produce a browser-side Agent rotation proof without giving either private key to Go.

新增：

- Browser Requester Key panel exposes `Rotate Key`.
- Rotation generates a fresh browser requester key.
- The browser signs `{ previous_aid, next_aid }` with the previous requester private key.
- The browser signs the same body with the next requester private key.
- The new stored key bundle includes `previous_descriptor` and `rotation_proof`.

不做：

- 不做 Zone alias rebinding。
- 不做 server-side rotation registry。
- 不做 automatic key rotation schedule。
- 不做 multi-key account manager。
- 不做 encrypted key store。
- 不做 passphrase-protected export。
- 不做 compromised-key recovery。
- 不做 login/session identity。
- 不做 public deployment。

## v8.9: Requester Alias Rebinding Proof API

状态：complete
目标：Human Gateway can issue a Zone-signed requester alias rebinding proof after verifying a browser requester rotation proof.

新增：

- Human Gateway serves `POST /api/requester/rebindings`.
- The endpoint requires the existing Human Gateway write token when configured.
- Go verifies `previous_descriptor`, `next_descriptor`, and `rotation_proof`.
- Go signs `alias_rebinding_proof` with the local Zone authority key.
- The proof embeds the verified `agent_rotation_proof`.

不做：

- 不持久更新 registry alias binding。
- 不做 server-side rotation registry。
- 不做 browser UI for rebinding submission。
- 不做 automatic rebinding after rotation。
- 不做 multi-key account manager。
- 不做 compromised-key recovery。
- 不做 login/session identity。
- 不做 public deployment。

## v8.10: Requester Alias Registry Persistence

状态：complete
目标：Human Gateway persists the Zone-approved browser requester alias rebinding into a local registry file that existing registry tooling can resolve.

新增：

- `POST /api/requester/rebindings` writes `state/go-fed-discovery-requester-registry.json`.
- The registry uses the existing Node registry shape.
- The registry stores the rotated `next_descriptor`.
- The registry stores a Zone-signed `zone_binding` for `agent://browser/requester`.
- Existing `loadRegistry` / `resolveAgent` can resolve the rebound requester alias.

不做：

- 不做 browser UI for rebinding submission。
- 不做 multi-requester registry。
- 不做 rebinding history table。
- 不做 server-side rotation registry。
- 不做 remote registry sync。
- 不做 automatic rebinding after rotation。
- 不做 multi-tenant admin model。
- 不做 login/session identity。
- 不做 public deployment。

## v8.11: Browser Requester Alias Rebinding UI

状态：complete
目标：Human Gateway page can submit the browser-held requester rotation bundle to the existing requester alias rebinding API.

新增：

- Browser Requester Key panel exposes `Bind Alias`.
- The button reads `previous_descriptor`, current `descriptor`, and `rotation_proof` from the browser-held requester bundle.
- The browser posts those values as `previous_descriptor`, `next_descriptor`, and `rotation_proof` to `POST /api/requester/rebindings`.
- The request reuses the existing Human Gateway bearer token input.
- The response renders in the existing browser requester status area.

不做：

- 不做 automatic rebinding after rotation。
- 不做 multi-requester registry。
- 不做 rebinding history table。
- 不做 server-side rotation registry。
- 不做 encrypted key store。
- 不做 passphrase-protected export。
- 不做 login/session identity。
- 不做 public deployment。

## v8.12: Requester Rebinding History

状态：complete
目标：Human Gateway keeps a local requester alias rebinding history that humans can inspect.

新增：

- Successful `POST /api/requester/rebindings` appends a history record to `state/go-fed-discovery-requester-rebindings.json`.
- The history record stores alias, previous `aid`, next `aid`, Zone id, proof digest, and the Zone-signed alias rebinding proof.
- `GET /api/requester/rebindings` returns the local history.
- Human Gateway renders a `Requester Rebindings` table.

不做：

- 不做 multi-requester registry。
- 不做 server-side rotation registry。
- 不做 remote registry sync。
- 不做 automatic rebinding after rotation。
- 不做 audit hash-chain entry for rebinding history。
- 不做 login/session identity。
- 不做 public deployment。

## v8.13: Multi-requester Registry Upsert

状态：complete
目标：The local requester registry preserves multiple requester aliases instead of replacing the registry on each rebinding.

新增：

- Successful `POST /api/requester/rebindings` upserts the rebound requester alias into `state/go-fed-discovery-requester-registry.json`.
- New aliases append a new `agents[]` entry.
- Existing aliases replace their current `agents[]` entry.
- The registry keeps the existing Node registry shape.
- Existing `loadRegistry` / `resolveAgent` can resolve more than one rebound requester alias.

不做：

- 不做 browser multi-key manager。
- 不做 Human Gateway requester selector UI。
- 不做 alias delete/disable。
- 不做 conflict policy beyond same-alias replace。
- 不做 server-side rotation registry。
- 不做 remote registry sync。
- 不做 login/session identity。
- 不做 public deployment。

## v8.14: Requester Registry View

状态：complete
目标：Human Gateway exposes the local requester registry as a read-only API and table.

新增：

- Human Gateway serves `GET /api/requester/registry`.
- The endpoint returns the existing local requester registry JSON shape.
- Human Gateway renders a `Requester Registry` table.
- The table shows requester alias, requester `aid`, and Zone binding id.
- The table reflects multiple requester aliases persisted by v8.13.

不做：

- 不做 browser multi-key manager。
- 不做 Human Gateway requester selector UI。
- 不做 alias delete/disable。
- 不做 registry mutation API。
- 不做 server-side browser private-key custody。
- 不做 login/session identity。
- 不做 public deployment。

## v8.15: Durable Queue Grant Nonce Index

状态：complete
目标：Human Gateway queue action grants are consumed through a durable local nonce index instead of replay checks depending on audit scans.

新增：

- Verified queue action grants create a local grant-use record in the audit-derived `*-queue-grants` directory.
- The grant-use filename is the existing grant digest.
- The grant-use record stores grant digest, action, task id, actor, and consumed timestamp.
- Reusing the same grant digest is rejected through exclusive local file creation.
- Existing `go_queue_action` audit evidence remains unchanged.

不做：

- 不做 distributed nonce service。
- 不做 configurable actor authorization policy。
- 不做 login/session identity。
- 不做 token storage or rotation。
- 不做 public deployment。
- 不做 A2A/ARD compatibility。

## 后续方向

- v8.16: configurable actor authorization policy, container sandbox hardening, or another small Ultimate-aligned governance/runtime slice.

Container sandbox and public transport remain separate hardening tracks。
