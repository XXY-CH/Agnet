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
HELLO           Zone A -> Zone B, then Zone B -> Zone A
AUTH            Zone A -> Zone B
AUTH_OK         Zone B -> Zone A
FED_RESOLVE      Zone A -> Zone B
FED_RESOLVE_RESULT Zone B -> Zone A
FED_QUERY        Zone A -> Zone B
FED_QUERY_RESULT Zone B -> Zone A
FED_AUDIT_QUERY  Zone A -> Zone B
FED_AUDIT_RESULT Zone B -> Zone A
FED_AUDIT_CLOSE  Zone B -> Zone A
FED_TASK_OPEN    Zone A -> Zone B
FED_TASK_RESUME  Zone A -> Zone B
FED_TASK_RETRY   Zone A -> Zone B
FED_TASK_CANCEL  Zone A -> Zone B
FED_TASK_VERIFIED Zone B -> Zone A
FED_TASK_EVENT   Zone B -> Zone A
FED_RECEIPT      Zone B -> Zone A
FED_TASK_CLOSE   Zone B -> Zone A
FED_CANCEL_CLOSE Zone B -> Zone A
FED_TASK_ERROR   Zone B -> Zone A
```

## HELLO / AUTH

v4.4 requires a session handshake before federation frames.

Client hello:

```json
{
  "type": "HELLO",
  "origin_zone": { "...": "Zone A descriptor" }
}
```

Server hello:

```json
{
  "type": "HELLO",
  "zone": { "...": "Zone B descriptor" },
  "session_id": "session:...",
  "challenge": "..."
}
```

Client auth:

```json
{
  "type": "AUTH",
  "origin_zone": { "...": "Zone A descriptor" },
  "auth": {
    "session_id": "session:...",
    "challenge": "...",
    "peer_zid": "zid:ed25519:...",
    "remote_zid": "zid:ed25519:...",
    "auth_signature": "..."
  }
}
```

The `auth_signature` signs `session_id`, `challenge`, `peer_zid`, and `remote_zid` with the origin Zone key. The server rejects non-handshake frames until `AUTH` verifies, then binds later `origin_zone.zid` to the authenticated peer.

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

## FED_AUDIT_QUERY

```json
{
  "type": "FED_AUDIT_QUERY",
  "origin_zone": { "...": "Zone A descriptor" },
  "task_id": "go_fed_task_verified"
}
```

Zone B must reject the frame unless the session is authenticated and `origin_zone` matches the session peer.

## FED_AUDIT_RESULT

```json
{
  "type": "FED_AUDIT_RESULT",
  "zone": { "...": "Zone B descriptor" },
  "worker": { "...": "Zone B worker descriptor" },
  "zone_binding": { "...": "Zone B alias -> aid binding" },
  "task_id": "go_fed_task_verified",
  "receipt": {
    "task_id": "go_fed_task_verified",
    "checkpoint_refs": ["checkpoint:sha256:..."],
    "checkpoints": [{ "...": "signed checkpoint" }],
    "artifact_manifests": [{ "...": "artifact digest manifest" }],
    "sandbox_proof": { "...": "signed sandbox proof" },
    "signature": "..."
  }
}
```

Zone A must reject the result unless `zone` is trusted, `zone_binding` binds the worker, `receipt.task_id` matches the query, and `receipt.signature` verifies against the worker key. v4.5 returns the minimal receipt proof only; it does not sync the full audit log.

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

## FED_TASK_RESUME

```json
{
  "type": "FED_TASK_RESUME",
  "origin_zone": { "...": "Zone A descriptor" },
  "requester": { "...": "requester descriptor" },
  "checkpoint_id": "checkpoint:sha256:...",
  "task": {
    "task_id": "fed_task_124",
    "from": "aid:ed25519:...",
    "to": "agent://zone-b/summarizer",
    "intent": "Resume from a signed checkpoint.",
    "scope": { "network": false },
    "budget": { "time_seconds": 30 },
    "signature": "..."
  }
}
```

v5.1 treats resume as a new signed task that binds to a parent checkpoint id. The resumed receipt must include `resumed_from`, and its signed checkpoint must set `parent_checkpoint` to the requested checkpoint id.

This is not a durable scheduler or state restore. It only proves the protocol link from old checkpoint evidence to a new auditable execution.

## FED_TASK_RETRY

```json
{
  "type": "FED_TASK_RETRY",
  "origin_zone": { "...": "Zone A descriptor" },
  "requester": { "...": "requester descriptor" },
  "retry_of": "fed_task_123",
  "task": {
    "task_id": "fed_task_124",
    "from": "aid:ed25519:...",
    "to": "agent://zone-b/summarizer",
    "intent": "Retry with updated constraints.",
    "scope": { "network": false },
    "budget": { "time_seconds": 30 },
    "signature": "..."
  }
}
```

v5.3 treats retry as a new signed task with lineage. Zone B verifies the task as usual, executes it normally, and records `retry_of` in the worker-signed receipt.

This is not automatic retry. There is no backoff, retry queue, scheduler, or lookup that proves the old task exists.

## FED_TASK_CANCEL

```json
{
  "type": "FED_TASK_CANCEL",
  "origin_zone": { "...": "Zone A descriptor" },
  "requester": { "...": "requester descriptor" },
  "cancel": {
    "task_id": "fed_task_123",
    "from": "aid:ed25519:...",
    "to": "agent://zone-b/summarizer",
    "reason": "operator requested cancellation",
    "signature": "..."
  }
}
```

v5.2 treats cancellation as signed protocol evidence. Zone B verifies the requester and cancel signature, emits `task.cancelled`, and returns a worker-signed cancellation receipt that remote audit query can fetch by `task_id`.

This is not live process interruption. The current gateway does not keep a scheduler or task state table.

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
- No TLS/QUIC public transport.
