# Agent Space v4 Boundary

状态：v4 complete
目标：增加 protocol-native checkpoint evidence，不引入 Git/worktree/merge 等上层协作操作。

## v4 新增

- Go emits `checkpoint.created` during `FED_TASK_OPEN` execution。
- Checkpoint object includes:
  - `checkpoint_id`
  - `task_id`
  - `parent_checkpoint`
  - `event_index`
  - `state_digest`
  - `artifact_refs`
  - `policy_digest`
  - `created_by`
  - `checkpoint_signature`
- Receipt records:
  - `checkpoint_refs`
  - `checkpoints`
- Go audit verifier checks checkpoint refs, parent link shape, and worker signature。
- Node integration test verifies checkpoint event, receipt refs, and checkpoint signature。

## 为什么这是 v4

v3.9 proved signed approval evidence before tool execution。

v4 moves to the evidence-chain layer from the ultimate vision:

```text
task.started
  -> checkpoint.created
  -> signed checkpoint object
  -> receipt records checkpoint refs
  -> audit verifier checks checkpoint evidence
```

This is Git-like only in the evidence-chain sense: signed hashes and parent links, not Git operations。

## v4 不新增

- 不恢复任务。
- 不保存模型 KV/cache。
- 不做文件工作区。
- 不做 Git commit / branch / merge。
- 不做 checkpoint storage service。
- 不做 checkpoint resume。

## 验收

```bash
go test ./...
node --test --test-concurrency=1 test/*.test.mjs
```

The Go integration test must fail if checkpoint evidence is missing from event stream, receipt, or audit verification。
