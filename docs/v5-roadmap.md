# Agent Space v5 Roadmap

状态：v5.2 complete; v5.3+ planned
目标：从 v4 的 evidence chain 推进到更强运行面，但仍保持 `agent-space-ultimate-vision.md` 的底层窄腰：identity、signed task、event stream、scoped policy、artifact reference、audit receipt、federation。

## v5.0: Signed Sandbox Proof

状态：complete
目标：把 receipt 里的 sandbox evidence 升级成可验证 proof。

新增：

- `sandbox_proof` object。
- Zone authority signs sandbox proof with `sandbox_signature`。
- Proof binds:
  - `task_id`
  - `worker`
  - `policy_digest`
  - sandbox evidence
- Go audit verifier checks proof signature and receipt alignment。
- Remote audit query returns the signed sandbox proof because it is part of the receipt。

不做：

- 不做 Docker/gVisor/Firecracker runtime。
- 不做 OS-level network enforcement。
- 不做 hardware attestation。
- 不做 sandbox broker service。

## v5.1: Checkpoint Resume

状态：complete
目标：从 v4 checkpoint evidence 走到最小 resume flow。

新增：

- `FED_TASK_RESUME`
- resume request binds to `checkpoint_id`
- resumed receipt references parent checkpoint。
- resumed checkpoint records `parent_checkpoint`。

不做：

- 不恢复模型 KV/cache。
- 不做 durable scheduler。
- 不做 long-running MCP session resume。

## v5.2: Signed Cancellation Evidence

状态：complete
目标：让取消意图进入 signed task fabric 和 audit proof。

新增：

- `FED_TASK_CANCEL`
- signed `cancel` object
- `task.cancelled` event
- worker-signed cancellation receipt
- remote audit query returns cancellation receipt

不做：

- 不中断正在运行的 external/MCP process。
- 不做 task scheduler。
- 不做 task state table。
- 不做 authorization UI。

## 后续方向

- retry evidence
- container sandbox proof
- long-running MCP sessions
- scheduling / retry
- public transport hardening

A2A compatibility 仍应是 adapter 层，不进入底层窄腰。
