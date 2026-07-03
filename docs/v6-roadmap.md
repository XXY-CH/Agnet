# Agent Space v6 Roadmap

状态：v6.3 complete; v6.4+ planned
目标：从 v5 的工具执行证据链推进到 durable task runtime，让任务不只是一次性 receipt，而是有可恢复、可操作、可查询的运行状态。

## v6.0: Durable Task State File

状态：complete
目标：为 Go completed/cancelled task 写入最小持久状态文件。

新增：

- Per-task JSON state under the audit-derived task state directory。
- `status` for completed/cancelled tasks。
- `receipt_digest` linking task state back to the signed receipt。

不做：

- 不做 scheduler queue。
- 不做 live process interruption。
- 不做 checkpoint restore。
- 不做 task search index。
- 不做 database。

## v6.1: Failed Task State

状态：complete
目标：任务在执行阶段失败且还没有 receipt 时，也要留下 durable state。

新增：

- Failed task JSON state with `status: "failed"`。
- Error evidence in the failed task state。

不做：

- 不做 failed receipt。
- 不做 retry scheduler。
- 不做 live process interruption。
- 不做 checkpoint restore。

## v6.2: Live External Task Cancellation

状态：complete
目标：签名 `FED_TASK_CANCEL` 到达时，中断正在运行的 external tool process。

新增：

- In-memory `task_id -> cancel` runtime registry。
- External tool execution derives its timeout context from the task context。
- Cancelling a running task aborts the process before timeout。

不做：

- 不做 persisted running registry。
- 不做 scheduler queue。
- 不做 distributed/multi-node cancellation。
- 不做 checkpoint restore。

## v6.3: Running Task State

状态：complete
目标：任务进入运行态后，先持久化 `status: "running"`，再由完成/取消/失败覆盖。

新增：

- Running task JSON state before external/MCP execution finishes。
- Final task state overwrites the running state file。

不做：

- 不做 task state index。
- 不做 Human Gateway task table。
- 不做 scheduler queue。
- 不做 persisted running process handles。

## 后续方向

- Human Gateway task state view
- checkpoint-backed restore
- scheduler queue
- Human Gateway task list/actions

Container sandbox remains a separate runtime-hardening track, not the first v6 durable-runtime slice。
