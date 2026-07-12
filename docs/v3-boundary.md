# Agent Space v3 Boundary

状态：v3 complete
目标：让 Go 拥有最小 task execution path。

## v3 新增

- Go `FED_TASK_OPEN` moves from verification-only to execution。
- Go emits minimal task events:
  - `task.accepted`
  - `task.started`
  - `artifact.created`
  - `task.completed`
- Go writes one deterministic artifact for the task。
- Go signs `FED_RECEIPT` with the worker key。
- Node requester verifies:
  - remote Zone descriptor
  - worker descriptor
  - Zone binding
  - receipt signature
  - receipt task/zone/worker/artifact fields

## 为什么这是 v3

v2.x moved trust and discovery responsibilities into Go。

v3 starts moving execution responsibility into Go:

```text
Node requester
  -> FED_TASK_OPEN
Go gateway/runtime
  -> verify task
  -> execute minimal deterministic worker
  -> write artifact
  -> sign receipt
Node requester
  -> verify receipt
```

This is the first point where Go is no longer only a discovery gateway.

## v3 不新增

- 不做 real tool execution。
- 不做 sandbox。
- 不做 multi-worker registry。
- 不做 scheduler。
- 不做 human approval UI。
- 不做 public transport。
- 不做 encrypted key store。

## 验收

```bash
node --test --test-concurrency=1 test/*.test.mjs
go test ./...
```

新增 Node -> Go execution test:

```text
FED_TASK_OPEN
  -> FED_TASK_EVENT task.accepted
  -> FED_TASK_EVENT task.started
  -> FED_TASK_EVENT artifact.created
  -> FED_TASK_EVENT task.completed
  -> FED_RECEIPT
  -> FED_TASK_CLOSE
```

The test fails if Go only returns `FED_TASK_VERIFIED`。
