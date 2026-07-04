# Agent Space v8 Roadmap

状态：v8.0 complete; v8.1+ planned
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

## 后续方向

- v8.1: extend explicit approval to queued drain.
- v8.2: browser-side requester/key UX.
- v8.3: deployable gateway security boundary.

Container sandbox and public transport remain separate hardening tracks。
