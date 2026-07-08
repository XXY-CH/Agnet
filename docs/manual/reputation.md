# Reputation and discovery

ASP discovery is evidence-first. `FED_QUERY` returns ranked matches, but every ranking input is exposed in `discovery_evidence` and `ranking` so callers can inspect why a worker won.

## Discovery flow

A query carries an origin Zone, a required capability, and optional semantic `intent`. The gateway verifies the origin Zone, evaluates candidates, returns `FED_QUERY_RESULT`, then closes with `FED_QUERY_CLOSE`.

Each match may include:

- `worker` descriptor.
- `zone` descriptor and `zone_binding`.
- `credential_statuses`.
- `discovery_evidence.capability`.
- `discovery_evidence.credential`.
- `discovery_evidence.reputation`.
- `discovery_evidence.routing`.
- `discovery_evidence.zone_trust_chain`.
- `ranking.score` and `ranking.reasons`.

## `agent_score`

`agent_score` is a labelled local reputation object, not a global score. Current components are:

| Component | Meaning |
| --- | --- |
| `receipt_score` | Contribution from completed receipts counted in the persisted audit log. |
| `credential_score` | Contribution from trusted and active capability credentials. |
| `freshness_score` | Contribution from recent `last_completed_at` audit evidence. |
| `revocation_penalty` | Penalty from signed local authority Zone revocations. |
| `total` | Composite score used by ranking, capped by the implementation. |

Missing timestamps fail safe to no freshness contribution. Missing or unreadable audit logs fail safe to zero counted receipts rather than inventing reputation.

## Routing signals

v14.2 adds `discovery_evidence.routing`:

| Signal | Source |
| --- | --- |
| `cost_score` | Descriptor `policy.cost_tokens_per_task`. |
| `latency_score` | Descriptor `policy.latency_ms_p95`. |
| `availability_score` | Local audit evidence over recent entries. |
| `signals_used` | Labels for present routing evidence. |

Missing cost, latency, or availability evidence stays neutral and does not fabricate an advantage.

## Semantic matching

`intent` uses deterministic token overlap over alias and capabilities. Exact capability matches and trusted credentials outrank semantic-only candidates when the evidence supports it. This is not a vector database, opaque ML router, public marketplace, remote reputation oracle, or token-weighted graph.

## Cross-zone provenance

Direct local trust uses `zone_trust_chain: []`. Cross-zone matches can include signed Zone delegation records. The chain is provenance evidence for the local verifier; it is not universal trust or a global PKI.
