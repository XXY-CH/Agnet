# Agent Space v1 Boundary

状态：v1 candidate  
目标：证明两个独立 Zone 可以通过 Federation Gateway 完成跨 Zone signed task。

## v1 新增

- `federation-gateway.mjs`
- Federation frame：
  - `FED_TASK_OPEN`
  - `FED_TASK_EVENT`
  - `FED_RECEIPT`
  - `FED_TASK_CLOSE`
  - `FED_TASK_ERROR`
- Zone A trusted store 验证 Zone B。
- Zone B trusted store 验证 Zone A。
- Zone A requester 向 Zone B gateway 发送 signed task。
- Zone B gateway 验证：
  - origin Zone descriptor
  - requester descriptor
  - task signature
  - worker policy
- Zone B 本地 worker 生成 events、artifact 和 receipt。
- Zone B 返回 worker descriptor、Zone binding 和 signed receipt。
- Zone A 验证：
  - remote Zone descriptor 在 trusted store 中
  - worker descriptor
  - Zone binding
  - receipt signature
- 双边 audit：
  - Zone B 写 `fed_event` 和 `fed_receipt`
  - Zone A 写 `fed_remote_receipt`
- 新增 two-Zone integration test。

## v1 运行形态

```text
Zone A requester
  -> trusted Zone B descriptor
  -> FED_TASK_OPEN
  -> Zone B Federation Gateway
  -> Zone B worker
  -> FED_TASK_EVENT
  -> FED_RECEIPT
  -> Zone A verifies remote receipt
```

## v1 验收

```bash
node --test --test-concurrency=1 *.test.mjs
go test ./...
```

必须通过：

```text
Federation Gateway completes a cross-Zone task
```

## v1 不新增

- 不做公网 federation。
- 不做 WebSocket/QUIC federation transport。
- 不做 remote registry discovery。
- 不做 semantic routing。
- 不做 multi-hop federation。
- 不做 MCP/A2A adapter。
- 不做 sandbox。
- 不做 billing。
- 不做 UI。

## v1 判断

v0.9 之前证明的是单 Zone Agent Space。

v1 证明的是最小跨 Zone Agent Space：

```text
trusted zid
  -> gateway frame
  -> remote worker execution
  -> signed remote receipt
  -> local verification
```

这就是 Federation Gateway 的第一条活链路。

后续 federation frame contract 和 untrusted Zone negative test 见 `docs/v1.1-boundary.md`。
