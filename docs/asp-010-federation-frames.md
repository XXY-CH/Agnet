# ASP-010 Federation Frames

状态：Draft 0  
范围：定义 v1 本机 Federation Gateway frame contract。

## Transport

v1 使用 newline JSON over TCP：

```text
fed+tcp://127.0.0.1:<port>
```

这是本机 federation proof，不是公网 transport。

## Frames

```text
FED_RESOLVE      Zone A -> Zone B
FED_RESOLVE_RESULT Zone B -> Zone A
FED_QUERY        Zone A -> Zone B
FED_QUERY_RESULT Zone B -> Zone A
FED_TASK_OPEN    Zone A -> Zone B
FED_TASK_VERIFIED Zone B -> Zone A
FED_TASK_EVENT   Zone B -> Zone A
FED_RECEIPT      Zone B -> Zone A
FED_TASK_CLOSE   Zone B -> Zone A
FED_TASK_ERROR   Zone B -> Zone A
```

## FED_RESOLVE

```json
{
  "type": "FED_RESOLVE",
  "origin_zone": { "...": "Zone A descriptor" },
  "alias": "agent://zone-b/summarizer"
}
```

Zone B must reject the frame unless `origin_zone` exists in its trusted Zone store.

## FED_RESOLVE_RESULT

```json
{
  "type": "FED_RESOLVE_RESULT",
  "zone": { "...": "Zone B descriptor" },
  "worker": { "...": "Zone B worker descriptor" },
  "zone_binding": { "...": "Zone B alias -> aid binding" }
}
```

Zone A must reject the result unless `zone` exists in its trusted Zone store and `zone_binding` binds `worker.alias` to `worker.aid`.

## FED_QUERY

```json
{
  "type": "FED_QUERY",
  "origin_zone": { "...": "Zone A descriptor" },
  "capability": "summarize.text"
}
```

Zone B must reject the frame unless `origin_zone` exists in its trusted Zone store.

## FED_QUERY_RESULT

```json
{
  "type": "FED_QUERY_RESULT",
  "zone": { "...": "Zone B descriptor" },
  "capability": "summarize.text",
  "matches": [
    {
      "worker": { "...": "Zone B worker descriptor" },
      "zone_binding": { "...": "Zone B alias -> aid binding" },
      "credentials": [
        {
          "issuer": "zid:ed25519:...",
          "subject": "aid:ed25519:...",
          "capability": "summarize.text",
          "claims": {
            "level": "L1",
            "evidence": ["zone-b-local-worker"]
          },
          "signature": "..."
        }
      ]
    }
  ]
}
```

v1.3 only supports exact string matching against `worker.capabilities`. No vectors, rankings, or semantic expansion.

v1.5 adds signed capability credentials to each match. The credential issuer is a Zone/authority, the subject is the worker `aid`, and the capability must also appear inside the worker's signed descriptor.

`request-capability` is a convenience flow:

```text
FED_QUERY summarize.text
  -> first verified match
  -> FED_TASK_OPEN to matched alias
```

It is not a scheduler. It does not rank candidates.

## FED_TASK_OPEN

```json
{
  "type": "FED_TASK_OPEN",
  "origin_zone": {
    "name": "zone://a",
    "zid": "zid:ed25519:...",
    "public_key_spki": "...",
    "zone_signature": "..."
  },
  "requester": {
    "alias": "agent://zone-a/requester",
    "aid": "aid:ed25519:...",
    "public_key_spki": "...",
    "transports": [],
    "policy": {},
    "descriptor_signature": "..."
  },
  "task": {
    "task_id": "fed_task_123",
    "from": "aid:ed25519:...",
    "to": "agent://zone-b/summarizer",
    "intent": "Summarize through a trusted remote Zone.",
    "scope": {
      "network": false,
      "write": ["artifact://local/"]
    },
    "budget": {
      "time_seconds": 30
    },
    "signature": "..."
  }
}
```

Zone B must reject the frame unless:

- `origin_zone` verifies as a self-signed Zone descriptor.
- `origin_zone.zid` exists in Zone B trusted Zone store.
- `requester` verifies as a self-signed Agent descriptor.
- `task.from` equals `requester.aid`.
- `task.signature` verifies against requester public key.
- local worker policy accepts the task scope.

## FED_TASK_VERIFIED

```json
{
  "type": "FED_TASK_VERIFIED",
  "task_id": "fed_task_123",
  "by": "aid:ed25519:...",
  "zone": "zid:ed25519:..."
}
```

`FED_TASK_VERIFIED` is a v2.4 Go gateway response for verification-only task-open handling.

It means the remote gateway accepted the frame as valid, but it does not mean the task executed.

Zone A must not treat this as a receipt.

## FED_RECEIPT

```json
{
  "type": "FED_RECEIPT",
  "zone": { "...": "Zone B descriptor" },
  "worker": { "...": "Zone B worker descriptor" },
  "zone_binding": { "...": "Zone B alias -> aid binding" },
  "receipt": {
    "task_id": "fed_task_123",
    "from": "aid:ed25519:...",
    "origin_zone": "zid:ed25519:...",
    "executing_zone": "zid:ed25519:...",
    "to": "aid:ed25519:...",
    "artifact_refs": ["artifact://local/fed_task_123/federated-summary.md"],
    "event_count": 7,
    "approvals": ["write"],
    "signature": "..."
  }
}
```

Zone A must reject the receipt unless:

- `zone` verifies as a self-signed Zone descriptor.
- `zone.zid` exists in Zone A trusted Zone store.
- `worker` verifies as a self-signed Agent descriptor.
- `zone_binding` binds worker alias to worker `aid`.
- `receipt.signature` verifies against worker public key.

## Non-goals

- No remote registry discovery.
- No semantic routing.
- No multi-hop forwarding.
- No public transport.
- No TLS/QUIC/WebSocket binding.
