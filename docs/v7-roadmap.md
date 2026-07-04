# Agent Space v7 Roadmap

状态：v7.8 complete; v7.9+ planned
目标：从 durable task state 进入 durable scheduler queue，让任务生命周期有本地所有权、可恢复入口和后续调度面。

## v7.0: Durable Queue Enqueue

状态：complete
目标：签名任务可以先进入本地持久队列，而不是只能同步执行。

新增：

- `FED_TASK_ENQUEUE` frame。
- Existing task signature, target, and policy checks reused before queue acceptance。
- One queue JSON file per queued task。
- Queue item records task id, queued status, worker, origin zone, and task digest。

不做：

- 不做 drain worker。
- 不做 lease/claim。
- 不做 retry/backoff。
- 不做 priority。
- 不做 Human Gateway action。

## v7.1: Explicit Queue Drain

状态：complete
目标：通过显式 frame drain 一个 queued task，并复用现有执行链。

新增：

- `FED_QUEUE_DRAIN` frame。
- Queue item stores origin zone descriptor, requester descriptor, and signed task。
- Drain re-verifies the stored task through existing `verifyTaskOpen`。
- Drain updates queue state from queued to running to completed。
- Completed queue item records receipt digest。

不做：

- 不做 automatic drain loop。
- 不做 leases。
- 不做 retry/backoff。
- 不做 priority。
- 不做 Human Gateway action。

## v7.2: Queue Claim Lease

状态：complete
目标：drain 前必须先 claim queued task，并用 `lease_id` 证明调度所有权。

新增：

- `FED_QUEUE_CLAIM` frame。
- Queue item records `claimed` state, `lease_owner`, and `lease_id`。
- `FED_QUEUE_DRAIN` requires the matching `lease_id`。
- Completed queue item preserves lease fields。

不做：

- 不做 lease expiry。
- 不做 reclaim。
- 不做 automatic drain loop。
- 不做 retry/backoff。
- 不做 priority。

## v7.3: Queue Lease Reclaim

状态：complete
目标：claimed task 的 lease 过期后不能继续 drain，但可以被显式 reclaim 换 owner/lease。

新增：

- Claim records `lease_expires_at`。
- `FED_QUEUE_DRAIN` rejects expired leases。
- `FED_QUEUE_RECLAIM` only reclaims expired claimed queue items。
- Reclaim changes `lease_owner`, `lease_id`, and `lease_expires_at`。

不做：

- 不做 automatic drain loop。
- 不做 automatic lease scan。
- 不做 retry/backoff。
- 不做 priority。

## v7.4: Queue Retry Backoff

状态：complete
目标：failed queue item 可以被显式 retry 重新排队，并记录 retry/backoff 状态。

新增：

- `FED_QUEUE_RETRY` frame。
- Retry only accepts failed queue items as parents。
- Retry queue item records `retry_of`, `retry_attempt`, and `retry_after_at`。
- `FED_QUEUE_CLAIM` rejects queued retry items while `retry_after_at` is still in the future。

不做：

- 不做 automatic retry。
- 不做 automatic backoff scan。
- 不做 retry worker。
- 不做 priority。
- 不做 multi-node scheduler。

## v7.5: Human Gateway Queue Actions

状态：complete
目标：Human Gateway exposes explicit local queue actions without adding an automatic scheduler loop.

新增：

- `GET /api/queue` returns durable queue state files。
- `POST /api/queue/actions` supports `claim` and `drain`。
- Human Gateway page renders a Queue table。
- Drain action reuses the existing queue drain path and records normal audit/state evidence。

不做：

- 不做 enqueue form。
- 不做 retry form。
- 不做 automatic scheduler loop。
- 不做 auth/login。
- 不做 multi-node scheduler。

## v7.6: Human Gateway Queue Creation

状态：complete
目标：Human Gateway can create durable queued work from an already signed task.

新增：

- `POST /api/queue/actions` supports `enqueue`。
- Enqueue action accepts `origin_zone`, `requester`, and a signed `task`。
- Enqueue action reuses the same verification and queue write path as `FED_TASK_ENQUEUE`。
- `/api/queue` exposes the newly queued item。

不做：

- 不做 browser-side signing。
- 不做 requester private-key storage。
- 不做 task drafting form。
- 不做 automatic scheduler loop。
- 不做 auth/login。

## v7.7: Queued Checkpoint Resume

状态：complete
目标：checkpoint resume can enter the durable queue before execution.

新增：

- `FED_QUEUE_RESUME` frame。
- Queue resume requires an existing `checkpoint_id`。
- Queue item records `resume_checkpoint`。
- `FED_QUEUE_DRAIN` passes the stored parent checkpoint into the existing execution path。
- Drained receipt records `resumed_from`。

不做：

- 不恢复 model KV/cache。
- 不做 state restore service。
- 不做 automatic scheduler loop。
- 不做 long-running MCP session resume。
- 不做 artifact merge。

## v7.8: Queue Action Audit Evidence

状态：complete
目标：Human/local queue actions become first-class audit evidence.

新增：

- Human Gateway `POST /api/queue/actions` records `go_queue_action` audit entries。
- Successful actions record `action`, `task_id`, `source`, `status`, and `result_digest`。
- Failed actions record `action`, `task_id`, `source`, `status`, and `error`。
- Audit verification covers queue action records through the existing hash chain。

不做：

- 不签名 queue action。
- 不做 auth/login。
- 不做 approval workflow。
- 不把 federation frames 全量改成 action audit。
- 不做 append-only queue action index。

## 后续方向

- checkpoint state restore after queued execution exists
- Human Gateway task drafting/signing surface

Container sandbox and public transport remain separate hardening tracks。
