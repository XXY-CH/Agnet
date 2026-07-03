# Agent Space v4 Boundary

状态：v4 complete
目标：给外部/MCP tool execution 增加 task-scoped Git worktree context，证明高风险工具任务可以在独立文件上下文中运行并留下 receipt evidence。

## v4 新增

- Worker profile supports `context_repo`。
- Go external/MCP tools can run from a detached Git worktree created from `context_repo` HEAD。
- Tool input / MCP `tools/call` arguments include `context` evidence。
- Receipt records:
  - `context.mode: "git-worktree"`
  - `context.repo`
  - `context.base_head`
  - `context.worktree`
- Go audit verifier checks receipt context shape。
- Human Gateway receipt table shows context mode。
- Node integration test verifies MCP tool cwd is the task worktree and receipt context evidence exists。

## 为什么这是 v4

v3.9 proved signed approval evidence before tool execution。

v4 starts the scoped workspace layer:

```text
FED_TASK_OPEN
  -> signed approval grant
  -> create detached Git worktree from repo HEAD
  -> run MCP/external tool inside that worktree
  -> artifact captures worktree cwd
  -> receipt records context evidence
  -> audit verifier checks context shape
```

This moves Agnet toward Swarm-safe file context without jumping into a product workspace。

## v4 不新增

- 不做 A2A translation layer。
- 不做 realtime context sync。
- 不做 CRDT/shared memory。
- 不做 branch merge / signed merge。
- 不做 conflict resolution。
- 不做 long-running task checkpoints。
- 不做 container/gVisor/Firecracker sandbox。

## 验收

```bash
go test ./...
node --test --test-concurrency=1 *.test.mjs
```

The Go integration test must fail if MCP tool execution does not run from Git worktree context when `context_repo` is configured。
