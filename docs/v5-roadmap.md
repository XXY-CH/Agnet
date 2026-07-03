# Agent Space v5 Roadmap

状态：v5.9 complete; v5.10+ planned
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

## v5.3: Retry Evidence

状态：complete
目标：让 retry lineage 进入 receipt 和 audit proof。

新增：

- `FED_TASK_RETRY`
- `retry_of`
- retry task uses normal signed task verification
- retried receipt records `retry_of`
- remote audit query returns retried receipt

不做：

- 不做 automatic retry。
- 不做 backoff。
- 不做 retry queue。
- 不做 scheduler。
- 不验证旧 task 是否存在。

## v5.4: Sandbox Claim Boundary

状态：complete
目标：让 declared sandbox claim 和 actual sandbox evidence 一起进入 receipt/proof。

新增：

- worker profile `sandbox_claim`
- receipt `sandbox_claim`
- `sandbox_proof.sandbox_claim`
- execution rejects claim/mode mismatch
- audit verifier checks receipt/proof claim alignment

不做：

- 不做 Docker/gVisor/Firecracker。
- 不做 OS-level network enforcement。
- 不做 hardware attestation。
- 不把 `local-temp-dir` 描述成 container。

## v5.5: Tool Command Provenance

状态：complete
目标：把 external/MCP tool command identity 绑定进 sandbox evidence。

新增：

- `tool_command_digest` in external/MCP sandbox evidence
- receipt carries digest through sandbox evidence
- signed sandbox proof covers digest because it signs sandbox evidence

不做：

- 不做 tool registry。
- 不做 binary hash。
- 不做 package signature verification。
- 不暴露完整 local command line。
- 不做 supply-chain policy。

## v5.6: Tool Output Digest

状态：complete
目标：把 tool output digest 显式绑定到 artifact manifest。

新增：

- receipt `tool_output_digest`
- verifier checks digest equals artifact manifest `sha256`
- remote audit proof returns digest through signed receipt

不做：

- 不做 multi-artifact output graph。
- 不做 streamed output chunks。
- 不做 content-addressed artifact store。
- 不做 separate tool transcript storage。

## v5.7: MCP Session Metadata

状态：complete
目标：把 MCP initialize 返回的 protocol/server metadata 绑定进 sandbox evidence。

新增：

- `sandbox.mcp_session.protocol_version`
- `sandbox.mcp_session.server_info`
- signed sandbox proof covers metadata because it signs sandbox evidence

不做：

- 不做 long-running MCP session reuse。
- 不做 session resume。
- 不做 resources/prompts/list。
- 不做 MCP server registry。
- 不做 server signature verification。

## v5.8: MCP Resources/Prompts Evidence

状态：complete
目标：记录 MCP resources/prompts surface 的摘要。

新增：

- one `resources/list` probe
- one `prompts/list` probe
- `mcp_resources_count`
- `mcp_resources_digest`
- `mcp_prompts_count`
- `mcp_prompts_digest`

不做：

- 不保存完整 resources/prompts 列表。
- 不读取 resource contents。
- 不执行 prompts/get。
- 不做 long-running MCP session reuse。
- 不做 MCP registry。

## v5.9: MCP Tool List Evidence

状态：complete
目标：记录 MCP tools/list surface 的摘要。

新增：

- one `tools/list` probe
- `mcp_tools_count`
- `mcp_tools_digest`

不做：

- 不保存完整 tools catalog。
- 不验证 tool input schema。
- 不做 tool registry。
- 不做 tool selection/ranking。
- 不做 long-running MCP session reuse。

## 后续方向

- MCP selected tool binding
- container sandbox proof
- long-running MCP sessions
- scheduling / retry
- public transport hardening

A2A compatibility 仍应是 adapter 层，不进入底层窄腰。
