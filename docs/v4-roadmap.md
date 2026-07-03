# Agent Space v4 Roadmap

状态：v4.4 complete; v4.5+ planned
目标：回到 `agent-space-ultimate-vision.md` 的底层窄腰，推进 evidence chain / checkpoint / policy / artifact / transport，而不是做 Git/worktree/merge 这类上层协作操作。

## 路线判断

v4 之后的主线应继续强化：

```text
Agent identity
+ Signed task
+ Event stream
+ Scoped policy
+ Artifact reference
+ Audit receipt
+ Federation
```

这里唯一“像 Git”的部分是证据链：

- hash-chained audit log
- signed receipt
- checkpoint hash
- parent/child evidence link
- content digest

不应把真实 Git branch / worktree / merge / review queue 放进底层 runtime。

## v4: Protocol-Native Checkpoint Evidence

状态：complete
目标：让长任务可以留下可恢复、可审计的 checkpoint evidence，但不实现真正恢复。

新增：

- `checkpoint.created` event。
- Checkpoint object:
  - `checkpoint_id`
  - `task_id`
  - `parent_checkpoint`
  - `event_index`
  - `state_digest`
  - `artifact_refs`
  - `policy_digest`
  - `created_by`
  - `checkpoint_signature`
- Receipt records checkpoint refs。
- Audit verifier checks checkpoint signature and parent link shape。

不做：

- 不恢复任务。
- 不保存模型 KV/cache。
- 不做文件工作区。
- 不做 Git commit / branch / merge。

## v4.1: Artifact Manifest Digest

状态：complete
目标：artifact reference 不只是 URI，还带 digest manifest。

新增：

- `artifact.manifest` object。
- Artifact digest / size / media type。
- Receipt records artifact manifest hash。
- Audit verifier checks receipt artifact digest shape。

不做：

- 不做对象存储。
- 不做远程 artifact 下载。
- 不做 artifact browser。

## v4.2: Richer Policy Scope

状态：complete
目标：把当前 network/write subset 扩展成更明确的 task policy scope。

新增：

- Canonical policy scope:
  - `network`
  - `write`
  - `tools`
  - `data_domains`
  - `approval_required`
  - `expires_at`
- Task / receipt record `policy_digest`。
- Policy deny events include stable reason codes。

不做：

- 不做 UI policy editor。
- 不做 org admin。
- 不做 dynamic policy service。

## v4.3: Credential Status / Revocation Feed

状态：complete
目标：能力凭证不只是签发，还能被查询状态和撤销。

新增：

- Zone-signed credential status list。
- Capability credential status check。
- Revocation evidence in audit / receipt when a task is denied。

不做：

- 不做 OCSP-like public service。
- 不做 distributed revocation network。

## v4.4: Authenticated Session Handshake

状态：complete
目标：把 local TCP / WebSocket transport 从“信任连接里带签名任务”推进到“连接本身有身份握手”。

新增：

- `HELLO`
- `AUTH`
- challenge signature
- session id
- peer descriptor binding

不做：

- 不做 TLS/QUIC。
- 不做 NAT/public gateway。
- 不做 OAuth。

## v4.5: Remote Audit Query

状态：planned
目标：联邦双方能按 task/query 拉取最小 audit proof。

新增：

- `FED_AUDIT_QUERY`
- `FED_AUDIT_RESULT`
- minimal receipt / checkpoint / artifact manifest proof。

不做：

- 不做完整日志同步。
- 不做跨 Zone 搜索。
- 不做产品级 audit viewer。

## 后续 v5 方向

v5 才考虑更强运行面：

- container sandbox proof
- checkpoint resume
- long-running MCP sessions
- scheduling / retry
- public transport hardening

A2A compatibility 仍应是 adapter 层，不进入 v4 底层主线。
