# Agent Space v8 Roadmap

状态：v8.9 complete; v8.10+ planned
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

## 后续方向

- v8.10: persistent alias binding registry update, browser rebinding UI, or the next deployable transport/security hardening slice.

Container sandbox and public transport remain separate hardening tracks。
