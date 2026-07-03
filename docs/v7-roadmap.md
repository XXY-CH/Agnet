# Agent Space v7 Roadmap

状态：v7.2 complete; v7.3+ planned
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

## 后续方向

- lease expiry and reclaim
- retry/backoff state
- Human Gateway task creation and queue actions
- checkpoint restore after queued execution exists

Container sandbox and public transport remain separate hardening tracks。
