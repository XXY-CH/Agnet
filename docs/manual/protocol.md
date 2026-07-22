# Protocol reference — implemented ASP v14

This reference describes the **implemented ASP v14** wire surface. ASP frames are newline-delimited JSON objects on prototype governed federation transports. Frame verification is intentionally fail-closed: wrong frame type, missing object fields, malformed ids, untrusted Zones, or invalid signatures reject before later field reads.

It is not an AFP v1 specification. AFP — Agnet Fabric Protocol — is the transport-neutral sovereign Agent Fabric target documented in [`docs/afp-v1-design.md`](../afp-v1-design.md). AFP will preserve the proven task, event, Artifact, checkpoint, receipt, fence, close, and verifier semantics where applicable; it will not silently reinterpret an existing `FED_*` frame, `asp-*` artifact field, vector, or CLI as an AFP object.

## Common objects

| Object | Required fields | Notes |
| --- | --- | --- |
| Agent descriptor | `aid`, `alias`, `public_key_spki`, `capabilities`, `transports`, `policy`, `signature` | `aid:` is canonical. Optional `did_key` must derive from the same Ed25519 public key. |
| Zone descriptor | `zid`, `name`, `public_key_spki`, `signature` | Trusted Zone files are `{ "zones": [...] }` or a raw descriptor array. |
| Zone binding | `zone`, `alias`, `aid`, `signature` | Binds an Agent alias and AID to a Zone. |
| Signed task | `task_id`, `from`, `to`, `intent`, `scope`, `budget`, `signature` | `task_id` matches `^[A-Za-z0-9._:-]{1,128}$`. |
| Artifact manifest | `uri`, `sha256`, `size`, optional `media_type`, `afp`, `manifest_hash` | Local URI form is `artifact://local/<task-id>/<name>`. |

### AFP migration boundary

Current `FED_*` frames require the governed federation context described below. AFP's future Direct profile must instead bind a selected trust profile, authenticated peer, explicit capability grant, delivery/custody lineage, and local policy decision. A failed governed verification must never retry as Direct traffic by removing Zone evidence.

AFP design names such as `IntentQuery`, `Offer`, `CapabilityGrant`, `MailboxEnvelope`, `CustodyReceipt`, and `SettlementCommit` are not valid current wire frames. See the AFP design document for their planned invariants.

## `FED_TASK_OPEN`

Carries a signed task across a federation boundary.

```json
{
  "type": "FED_TASK_OPEN",
  "origin_zone": {},
  "requester": {},
  "requester_zone_binding": {},
  "task": {}
}
```

Verifier checks: frame object/type, origin Zone descriptor, trusted Zone store, requester descriptor, task object, local worker descriptor context, worker identity, task signature, requester Zone binding, task target, task id token, and worker policy.

## `FED_RECEIPT`

Returns signed execution evidence.

```json
{
  "type": "FED_RECEIPT",
  "zone": {},
  "worker": {},
  "zone_binding": {},
  "receipt": {}
}
```

Receipt fields include `task_id`, `task_digest`, `from`, `to`, `origin_zone`, `executing_zone`, `artifact_refs`, `artifact_manifests`, `event_count`, `signature`, and optional `checkpoint_refs` / `checkpoints`. `task_digest` is the SHA-256 digest of the canonical signed task object. Optional checkpoint evidence must bind the same task, match refs, preserve the parent chain, and verify worker checkpoint signatures.

## Swarm frames

### `FED_SWARM_OPEN`

Starts an explicit Swarm DAG. The current shape carries `origin_zone`, `requester`, `requester_zone_binding`, and `swarm` with `swarm_id` plus `steps`. Each step has an id, capability/worker target, signed task body, optional `after` dependency list, and optional artifact input requirements.

### `FED_SWARM_SCHEDULE`

Node and Go gateways both support scheduler-owned ready-DAG execution. They accept out-of-order signed steps, execute in deterministic dependency-ready order, and sign scheduler evidence with `mode: "ready-dag"` and `step_order` into the close proof. This preserves serial execution only: it is not automatic task decomposition, parallel economic scheduling, or resource orchestration.
### Durable local execution boundary

Phase C U19-U30 is complete for the Go-local runtime: a same-host filesystem journal under OS process locks is authoritative and produces replayable views. Workers execute at-least-once; only a fenced signed receipt commitment is exactly-once. The journal records deterministic parallel ready waves, keeps a byte-stable close, and allows irreversible signed disband only after output verification. Observed crash/concurrency proof boundaries cover journal/view replacement and close/disband append faults, receipt synchronization before response, stale-lease rejection after reclaim, concurrent-coordinator exclusion, and ready-wave barriers.

Node is a pure verifier of fixed offline U29 vectors for this durable format. Live public proof excludes durable Swarm completion; Phase C makes no claim of real container smoke, cross-host operation, remote artifact handling, or exactly-once worker execution.
The Phase C Go-local durable runtime is separate from the serial `FED_SWARM_SCHEDULE` compatibility surface above; its parallelism is bounded to deterministic same-host journal ready waves.



### `FED_SWARM_PLAN`

`FED_SWARM_PLAN` makes a `swarmPlan` digestible before execution. The `plan_digest` evidence binds proposed Swarm steps before a scheduler or gateway executes them; see `docs/v14.5-boundary.md`.


### `FED_KNOWLEDGE_QUERY` / `FED_KNOWLEDGE_RESPONSE`

v14.6 Knowledge Gateway frames bind a requester Zone's signed `intent`, `sources`, `policy_digest`, generated `query_id`, and `query_digest` to a gateway Zone's signed results. Each response result carries `source`, `title`, `summary`, `freshness_at`, and `license`, and `verifyKnowledgeResponse` requires the response `query_digest` to match the verified query frame. This is not a web crawler, semantic cache, vector store, or RAG pipeline.

### `FED_SWARM_CLOSE`

Closes a Swarm with a Zone-signed proof.

```json
{
  "type": "FED_SWARM_CLOSE",
  "swarm_id": "swarm://...",
  "zone": {},
  "close": {
    "swarm_id": "swarm://...",
    "step_receipts": [],
    "close_signature": "..."
  }
}
```

The close body may also carry `micro_contracts` (v14.1) and `migration_log` (v14.4). `migration_log` entries contain `step_id`, `original_worker_aid`, `reason`, `migrated_to_worker_aid`, and `migration_at`, and are covered by `close_signature`.

## Discovery and lookup frames

| Frame | Direction | Fields | Response |
| --- | --- | --- | --- |
| `FED_RESOLVE` | client → gateway | `origin_zone`, `alias` | `FED_RESOLVE_RESULT`, then `FED_RESOLVE_CLOSE` |
| `FED_QUERY` | client → gateway | `origin_zone`, `capability`, optional `intent` | `FED_QUERY_RESULT`, then `FED_QUERY_CLOSE` |

`FED_QUERY_RESULT.matches[]` carries `worker`, `zone`, `zone_binding`, `credential_statuses`, `discovery_evidence`, and `ranking`. Evidence includes capability match, credential trust/activity, reputation, routing, and `zone_trust_chain` provenance.

## Audit and artifact frames

| Frame | Purpose | Response |
| --- | --- | --- |
| `FED_AUDIT_QUERY` | Fetch audit-backed receipt evidence by `task_id` | `FED_AUDIT_RESULT`, then `FED_AUDIT_CLOSE` |
| `FED_ARTIFACT_READ` | Fetch a verified artifact by `task_id` and `uri` | artifact result frame, then `FED_ARTIFACT_CLOSE` |

## Queue and Human Gateway frames

The Go gateway also supports queue-oriented frames such as `FED_TASK_ENQUEUE`, `FED_QUEUE_RESUME`, `FED_QUEUE_ACCEPTED`, and `FED_QUEUE_CLOSE`. Queue action grants are signed and verify `scope.actions` before queue authorization is accepted.

## Error frame

`FED_TASK_ERROR` carries `error` and, in Go, optional `code`. It is emitted for unsupported frames, authentication failures, trust failures, policy failures, malformed evidence, and execution errors.
