# ASP-009 Local Transport

状态：Draft 0  
范围：定义 MVP 的本机双进程传输，不定义 WebSocket/QUIC。

## 1. 目标

证明两个 Agent runtime 可以通过真实连接交换任务帧，而不是单进程函数调用。

## 2. Transport URI

MVP 使用：

```text
asp+tcp://127.0.0.1:<port>
```

这不是终局 transport，只是本机开发和测试用绑定。

## 3. Frame 编码

每个 frame 是一行 JSON：

```text
<json>\n
```

不支持二进制 payload。大文件必须走 artifact ref。

## 4. Frame 类型

```text
TASK_OPEN    requester -> worker，打开任务
TASK_EVENT   worker -> requester，发送任务事件
RECEIPT      worker -> requester，发送签名 receipt
TASK_CLOSE   worker -> requester，关闭任务
TASK_ERROR   worker -> requester，返回错误并关闭
```

## 5. TASK_OPEN

```json
{
  "type": "TASK_OPEN",
  "task": {
    "task_id": "task_123",
    "from": "aid:ed25519:...",
    "to": "agent://local/summarizer",
    "intent": "Summarize this request",
    "scope": {
      "network": false,
      "write": ["artifact://local/"]
    },
    "budget": {
      "time_seconds": 30
    },
    "signature": "..."
  },
  "requester": {
    "alias": "agent://local/requester",
    "aid": "aid:ed25519:...",
    "public_key_spki": "...",
    "transports": []
  }
}
```

Worker 必须：

1. 从 `requester.public_key_spki` 重算 requester `aid`。
2. 验证 task signature。
3. 检查 worker policy。
4. 决定执行、审批、拒绝或报错。

## 6. 运行命令

```bash
node agent-runtime.mjs worker 8787
node agent-runtime.mjs request agent://local/summarizer
```

## 7. 非目标

- 不做 TLS。
- 不做 WebSocket。
- 不做 QUIC。
- 不做流量压缩。
- 不做 frame 分片。

这些等 `asp+tcp` 证明协议闭环后再加。
