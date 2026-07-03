# Agent Space v7 Roadmap

状态：v7.0 complete; v7.1+ planned
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

## 后续方向

- queue drain worker
- lease/claim and crash recovery
- retry/backoff state
- Human Gateway task creation and queue actions
- checkpoint restore after queued execution exists

Container sandbox and public transport remain separate hardening tracks。
