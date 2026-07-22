# AFP v1 Contract — AF0

**Status:** Normative AF0 protocol contract; implementation-neutral.  
**Version:** `1.0`  
**Normative words:** **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, and **MAY** use RFC 2119 meanings.

AFP AF0 freezes the pure-verifier boundary: canonical bytes, signed-object shapes, explicit evidence inputs, and refusal rules. With AF1–AF7's architecture decisions now recorded in `docs/afp-v1-design.md`, AF0 admits implementation against that contract; AF0 itself still implements no runtime. It neither specifies nor claims networking, P2P reachability, mailboxes, storage, discovery, execution, payment rails, or AF1 runtime behavior. AFP is additive to the implemented ASP v14 proof surface; supplied ASP objects are evidence, never AFP frames.

## 1. Pure verifier and primitives

A verifier receives an object and every required evidence item as explicit inputs and returns one stable result. It MUST NOT fetch, execute, store, route, infer a missing fact, use an ambient clock, or treat a signature as authority. `verification_time` is a REQUIRED exact UTC RFC 3339 input for **every full-envelope verification**; omission fails `AFP_VERIFICATION_TIME_REQUIRED`. It is the only clock used for envelope, lease, charter, custody, revocation-freshness, and receipt-expiry checks.

`aid:` remains the implemented self-certifying Agent identity. AFP MUST NOT mint, alias, or derive another identity. A content reference is not access authority; delivery/custody is not execution authority; and a rail/payment assertion is not receipt authority.

A signed or digested boundary is one canonical JSON value encoded as UTF-8: no BOM, prefix, suffix, trailing data, or alternate raw representation. Parsers MUST reject malformed UTF-8, duplicate keys, `NaN`, infinities, floats, `-0`, unsafe integers, U+2028, and U+2029. Values are objects, arrays, `null`, booleans, strings, and integers in `[-9007199254740991,9007199254740991]`. Object names sort lexicographically by UTF-8 bytes; arrays retain order; serialization has no insignificant whitespace. Strings use UTF-8 literally except `"`, `\`, and U+0000–U+001F, which use short JSON escapes where available and otherwise lowercase `\u00xx`. Non-control Unicode and `/` MUST NOT be gratuitously escaped.

All named identifiers are non-empty strings. `issued_at`, `expires_at`, `delivery_expiry`, `expiry`, and lease expiry are exact UTC `YYYY-MM-DDTHH:MM:SSZ` instants: no fraction, offset, or leap-second spelling. `expires_at` is strictly later than `issued_at`.

A **digest** is exactly 32 SHA-256 bytes in unpadded RFC 4648 base64url. Every field named `digest` or ending `_digest`, including a nested proof and settlement idempotency key, uses that representation. Ed25519 signatures are 64 bytes in the same encoding. Hex is allowed only in diagnostic vector fields ending `_hex`.

## 2. Negotiation, profile, and route binding

Before a non-local AFP object is processed, the verifier receives one canonical transcript with exactly these fields and no extras:

```json
{"issuer":"aid:…","peer":"aid:…","issuer_versions":["1.0"],"peer_versions":["1.0"],"selected_version":"1.0","selected_profile":"direct","route_context_digest":"…"}
```

Version arrays are non-empty and duplicate-free; `selected_version` occurs once in each and is `1.0`. Selection is exact-string intersection, never range matching. `selected_profile` is exactly `local`, `direct`, `governed`, `a2a-baseline`, or `a2a-afp`; non-local transcripts MUST NOT select `local`. The negotiation digest is ASCII `AFP-NEGOTIATION-V1\0` followed by canonical UTF-8 transcript bytes.

For a non-local route, the first verified object is `afp.route-binding`: it is verified directly against the supplied transcript (and does not require a prior binding), and its issuer/peer direction, version, profile, negotiation digest, and route-context digest exactly match that transcript. Later non-local objects require a supplied verified route-binding record with those same values. Any mutation fails `AFP_NEGOTIATION_BINDING_MISMATCH`.

A signed envelope profile is one of those five values. Route is separately exactly `local`, `direct`, `relayed`, or `store-forward`; `relayed` is not a profile. `local` requires a supplied verifier-local policy decision; absence fails `AFP_LOCAL_POLICY_REQUIRED`.

Every profile change, including direct→governed and a cross-family change, is a **new session**: it requires a new verified exact transcript, a new route binding, and a new supplied local-policy decision. A failed stronger→weaker attempt is rejected as `AFP_PROFILE_RETRY_REJECTED` even if it supplies a fresh transcript, binding, or policy flags; those inputs cannot turn the retry into a continuation. Only a separately identified new session is eligible for evaluation.

## 3. Domains, references, and envelopes

| Purpose | Exact byte preimage |
| --- | --- |
| Signature | ASCII `AFP-SIGNATURE-V1\0` + `kind` + NUL + `spec_version` + NUL + `profile` + NUL + canonical UTF-8 body |
| Object digest | ASCII `AFP-DIGEST-V1\0` + `kind` + NUL + `spec_version` + NUL + `profile` + NUL + canonical UTF-8 body |
| Negotiation digest | ASCII `AFP-NEGOTIATION-V1\0` + canonical UTF-8 transcript |
| Settlement idempotency | ASCII `AFP-SETTLEMENT-IDEMPOTENCY-V1\0` + settlement authority + NUL + fact kind + NUL + committed fact digest |

`kind`, `spec_version`, and `profile` are ASCII; NUL is `0x00`. Signatures are Ed25519 over the signature preimage; object, negotiation, and idempotency values are SHA-256 over their corresponding preimages.

A reference resolves only from a supplied verified evidence item whose digest exactly matches. A verifier MUST NOT fetch, substitute, infer, or self-assert a missing reference. Every non-root `predecessor_digest` is such a supplied verified reference. Positive task-claim, task-event, checkpoint, and custody-receipt cases therefore list it in `verified_references`.

Every AFP envelope is exactly:

```json
{"body":{"kind":"…","spec_version":"1.0","profile":"…","issuer":"aid:…","audience":"aid:…","nonce":"…","issued_at":"…","expires_at":"…","payload":{}},"signature":{"alg":"Ed25519","value":"…"}}
```

The outer object has exactly `body` and `signature`; `signature` exactly `alg` and `value`; and body exactly the displayed fields. `alg` is `Ed25519`; audience is never a wildcard; nonce is a non-empty issuer-unique replay token for the validity interval.

### AgentDescriptor bootstrap exception

`afp.agent-descriptor` alone is self-certifying for **key control**. Its raw 32-byte Ed25519 `signing_key` is converted to the exact Ed25519 SPKI encoding; its `aid:` is derived under implemented `asp-agent-id-v1\0`; and the descriptor signature verifies under that same key. This proves only control of that key. Self-signature does **not** confer acceptance, pinning, TOFU, governance, route, capability, or any other authority; acceptance/pinning/TOFU is explicit verifier-local policy. Every other AFP kind resolves its signing key only from supplied accepted external descriptor/governance evidence, never from a signature-adjacent field.

The ordered full-envelope pipeline returns the first failure only: (1) canonical bytes; (2) outer/body/signature shape; (3) required `verification_time`; (4) negotiation and profile/route binding; (5) known kind/profile; (6) primitives and time order; (7) issuer/audience and key resolution, applying the AgentDescriptor exception above; (8) signature; (9) object digest and replay key; (10) payload invariants; (11) supplied references, revocation, authority, custody, receipt, settlement, and local-policy evidence.

## 4. Catalogue and evidence invariants

Every payload is an object containing exactly its listed fields. `limits` and `budget` are exactly `{"max_bytes":safe-nonnegative-int,"max_cost":safe-nonnegative-int,"max_time_ms":safe-nonnegative-int}`. A payload `revocation_proof` is exactly `{"status":"unrevoked","digest":"<base64url32>"}`. Its supplied evidence is exactly `{"digest":"…","status":"unrevoked","verified":true,"fresh":true}`; missing, malformed, stale, unknown, or revoked proof fails `AFP_REVOCATION_PROOF_REJECTED`. `facts`, `artifact_manifest_digests`, `task_digests`, and `recipients` are non-empty duplicate-free arrays; digest arrays contain only base64url32 digests.

| Kind | Exact payload fields and invariants |
| --- | --- |
| `afp.agent-descriptor` | `aid`, `descriptor_id`, `signing_key`, `capabilities`, `route_hints`, `revocation_proof`; `aid` equals issuer and follows the §3 bootstrap derivation; capabilities and route_hints are non-empty string arrays. |
| `afp.capability-advertisement` | `advertisement_id`, `subject`, `actions`, `resources`, `limits`, `provenance_digest`; subject equals issuer. |
| `afp.intent-query` | `intent_id`, `requester`, `constraints`, `budget`, `privacy`, `idempotency_key`; requester equals issuer; constraints is exactly `{"action":string,"resource":string}`; privacy is `private` or `shared`; idempotency_key is a digest. |
| `afp.offer` | `offer_id`, `intent_digest`, `provider`, `advertisement_digest`, `terms`, `assurance_digest`; provider equals issuer; terms is limits. |
| `afp.capability-grant` | `grant_id`, `subject`, `actions`, `resources`, `limits`, `delegate`, `revocation_proof`, plus `parent_grant_digest` only for a child; subject equals audience. Root and child each require a full revocation proof. |
| `afp.task-open` | `task_id`, `requester`, `intent_digest`, `offer_digest`, `grant_digest`, `budget_authorization_digest`, `idempotency_key`, `attempt`, `fence`; requester equals issuer; attempt/fence are positive safe integers. |
| `afp.task-claim` | `task_id`, `attempt`, `claim_id`, `owner`, `lease`, `fence`, `sequence`, `predecessor_digest`; owner equals issuer; lease is exactly `{"expires_at":RFC3339}`; attempt/fence/sequence are positive safe integers. |
| `afp.task-event` | `task_id`, `attempt`, `event_id`, `event`, `sequence`, `predecessor_digest`, `fence`, `facts`, `authority_evidence_digest`; event is `submitted`, `cancelled`, `expired`, `accepted`, `rejected`, `executing`, `completed`, or `failed`. |
| `afp.checkpoint` | `task_id`, `attempt`, `checkpoint_id`, `state_digest`, `sequence`, `predecessor_digest`, `fence`; attempt/fence/sequence are positive safe integers. |
| `afp.artifact-manifest` | `artifact_id`, `task_id`, `attempt`, `bytes_digest`, `size`, `media_type`, `recipients`, `access_grant_digest`; attempt is positive; size non-negative. |
| `afp.mailbox-envelope` | `mail_id`, `route_binding_digest`, `recipient`, `ciphertext_digest`, `delivery_expiry`, `task_id`; recipient equals audience; asserts submitted delivery material only. |
| `afp.custody-receipt` | `custody_id`, `mail_digest`, `task_id`, `attempt`, `state`, `sequence`, `predecessor_digest`, `custodian`; state is `submitted`, `custody-accepted`, or `delivered`; custodian equals issuer. |
| `afp.receipt-commit` | `receipt_id`, `task_id`, `attempt`, `terminal`, `fence`, `lineage_digest`, `artifact_manifest_digests`, `verification_digest`, `authority_evidence_digest`; terminal is `rejected`, `completed`, `failed`, `cancelled`, or `expired`. |
| `afp.assurance-evidence` | `assurance_id`, `subject`, `profile`, `claim`, `evidence_digest`, `scope`; profile equals envelope profile; subject equals audience; claim is `verified` or `unverified`; scope is exactly `{"kind":"task","task_id":string}`. |
| `afp.route-binding` | `route_id`, `subject`, `route`, `peer`, `negotiation_digest`, `route_context_digest`; subject equals issuer and peer equals audience. |
| `afp.direct-swarm-charter` | `charter_id`, `swarm_id`, `members`, `authority_rule`, `task_digests`, `fence_rule`, `expiry`; members are unique aids; authority/fence rules non-empty; `issued_at < expiry <= expires_at`, evaluated at `verification_time`. No implicit member acceptance or multisignature is defined. |
| `afp.settlement-commit` | `settlement_id`, `settlement_authority`, `fact_kind`, `committed_fact_digest`, `budget_authorization_digest`, `receipt_or_custody_digest`, `idempotency_key`; authority equals issuer; fact_kind is `custody`, `storage`, `execution`, or `verification`; key equals the §3 derivation. |

`local` policy is a supplied explicit verifier decision, not an envelope assertion. `direct` requires authenticated aids, explicit grants, and independently bound route. `governed` additionally requires supplied governance provenance/policy but never replaces aid identity. `a2a-baseline` cannot assert AFP custody, execution, fence, receipt, or settlement authority; a signed attempted receipt still fails `AFP_RECEIPT_AUTHORITY_UNAVAILABLE`. `a2a-afp` preserves AFP bytes and semantics.

A task-event or receipt-commit authority requires supplied verified grant, claim, charter, or governance evidence. Its matching digest names envelope issuer and subject and lists the event or terminal. The envelope issuer must match it. No unsigned, self-authored, implicit, or fetched authority is accepted.

## 5. Capability attenuation and revocation

Attenuation is verified from full signed parent and child `afp.capability-grant` envelopes, not detached maps. The child `parent_grant_digest` resolves to a supplied verified parent envelope. The child issuer equals the parent subject, child subject and body audience are immutable from the parent, parent delegate is `true`, actions/resources are subsets, each limit is lower-or-equal, and child expiry is not later than parent expiry. Issuer mismatch fails `AFP_CAPABILITY_ISSUER_MISMATCH`; subject or audience mutation fails `AFP_CAPABILITY_SUBJECT_MUTATION`; expiry expansion fails `AFP_CAPABILITY_EXPIRY_EXPANSION`. Parent and child revocation proofs independently resolve to fresh verified unrevoked evidence. A child cannot widen delegation, privacy, route, or revocation scope.

## 6. Custody, receipt, and settlement

A custody lineage is a complete supplied chain with exactly one root (`sequence:1`, `predecessor_digest:null`) and each non-root predecessor supplied as verified reference. Facts have exactly `sequence`, `predecessor_digest`, `state`, and `fact_digest`; fact digests are unique; each successor sequence is strictly greater; and a second descendant of a used predecessor is a fork. A positive custody receipt additionally supplies `custody_lineage` containing that one root and full chain. Missing lineage or predecessor fails `AFP_CUSTODY_LINEAGE_INVALID`; forks or incompatible terminal conclusions fail `AFP_CUSTODY_CONTESTED`.

Before a proposed execution, an already verified lineage state `cancelled` fails `AFP_CUSTODY_CANCELLED`; a verified delivery/lease expiry at or before `verification_time` fails `AFP_CUSTODY_EXPIRED`; and a proposed `executing` state without supplied verified execution authority bound to task, attempt, issuer, and fence fails `AFP_CUSTODY_EXECUTION_UNAUTHORIZED`. These are the first custody-specific failures after lineage integrity.

Receipt expectation is the supplied exact object with only `task_id`, `attempt`, `receipt_fence`, `current_fence`, `sequence`, `predecessor_sequence`, `receipt_digest`, `custody_digest`, `lineage_digest`, `expected_task_id`, `expected_attempt`, `verified_references`, `actual_receipt_object_digest`, and `actual_receipt_payload`. `verified_references` contains verified references for all three digests. `actual_receipt_object_digest` binds the actual receipt envelope object digest. `actual_receipt_payload` is the exact object `{task_id, attempt, fence, lineage_digest}`. Task/attempt/fence/lineage values must agree across the expectation, actual payload, and receipt; task equals `expected_task_id`, attempt equals `expected_attempt`, receipt fence equals current fence, and sequence is predecessor plus one. Any missing, additional, malformed, or mismatched expectation or payload field fails `AFP_RECEIPT_FENCE_VIOLATION`.

Settlement receives the signed settlement commit and an exact supplied `verified_status` object with booleans `committed`, `uncontested`, `unexpired`, `unrevoked`, `current_fence`, `profile_sufficient`, `digest_valid`, and `budget_bound`. Charging needs every value true, resolving receipt/custody and budget evidence, and recomputed idempotency. A missing or unresolved budget authorization is first-failure `AFP_BUDGET_AUTHORIZATION_REQUIRED`; a false supplied status is `AFP_SETTLEMENT_REFUSED`; unsupported fact kind is `AFP_UNSUPPORTED_SETTLEMENT_FACT`. A rail claim that represents payment processing but is supplied as receipt/custody/authority semantics is `AFP_RAIL_SEMANTICS_REJECTED`.

## 7. ASP v14 compatibility

AFP v1 does not accept, relabel, or wrap ASP v14 material as AFP. `FED_TASK_*`, `FED_RECEIPT`, `FED_RESOLVE*`, `FED_QUERY*`, `FED_AUDIT*`, `FED_ARTIFACT*`, `FED_KNOWLEDGE*`, `FED_SWARM*`, and `FED_QUEUE*` fail `AFP_ASP_FRAME_REJECTED`. Existing ASP vectors fail `AFP_ASP_VECTOR_REJECTED`; legacy `afp:sha256:<digest>` where an AFP value is expected fails `AFP_ASP_LEGACY_FIELD_REJECTED`.

## 8. Stable errors and vectors

A verifier returns one token. `AFP_OK` succeeds; vectors use no implementation prose.

| Area | Tokens |
| --- | --- |
| Canonical/shape | `AFP_NONCANONICAL_JSON`, `AFP_DUPLICATE_KEY`, `AFP_TRAILING_DATA`, `AFP_INVALID_STRING`, `AFP_UNKNOWN_FIELD`, `AFP_MISSING_FIELD` |
| Negotiation/profile | `AFP_UNSUPPORTED_VERSION`, `AFP_VERSION_NEGOTIATION_FAILED`, `AFP_NEGOTIATION_REQUIRED`, `AFP_NEGOTIATION_BINDING_MISMATCH`, `AFP_INVALID_PROFILE`, `AFP_INVALID_ROUTE`, `AFP_PROFILE_DOWNGRADE_REJECTED`, `AFP_PROFILE_RETRY_REJECTED`, `AFP_LOCAL_POLICY_REQUIRED` |
| Envelope/time/key | `AFP_INVALID_KIND`, `AFP_INVALID_TIMESTAMP`, `AFP_TIME_ORDER_INVALID`, `AFP_VERIFICATION_TIME_REQUIRED`, `AFP_KEY_RESOLUTION_FAILED`, `AFP_SIGNATURE_FORMAT_INVALID`, `AFP_SIGNATURE_INVALID`, `AFP_DIGEST_MISMATCH`, `AFP_REPLAY_DETECTED` |
| Reference/capability | `AFP_REFERENCE_INVALID`, `AFP_AUTHORITY_EVIDENCE_REJECTED`, `AFP_PARENT_REFERENCE_REQUIRED`, `AFP_DELEGATION_FORBIDDEN`, `AFP_CAPABILITY_ISSUER_MISMATCH`, `AFP_CAPABILITY_ACTION_EXPANSION`, `AFP_CAPABILITY_RESOURCE_EXPANSION`, `AFP_CAPABILITY_LIMIT_EXPANSION`, `AFP_CAPABILITY_EXPIRY_EXPANSION`, `AFP_CAPABILITY_SUBJECT_MUTATION`, `AFP_REVOCATION_PROOF_REJECTED`, `AFP_RECEIPT_AUTHORITY_UNAVAILABLE` |
| Custody/receipt | `AFP_CUSTODY_LINEAGE_INVALID`, `AFP_CUSTODY_CONTESTED`, `AFP_CUSTODY_CANCELLED`, `AFP_CUSTODY_EXPIRED`, `AFP_CUSTODY_EXECUTION_UNAUTHORIZED`, `AFP_RECEIPT_FENCE_VIOLATION` |
| Settlement/ASP | `AFP_SETTLEMENT_REFUSED`, `AFP_UNSUPPORTED_SETTLEMENT_FACT`, `AFP_BUDGET_AUTHORIZATION_REQUIRED`, `AFP_RAIL_SEMANTICS_REJECTED`, `AFP_ASP_FRAME_REJECTED`, `AFP_ASP_VECTOR_REJECTED`, `AFP_ASP_LEGACY_FIELD_REJECTED` |

`test-vectors/afp-v1-af0.json` is the AF0 corpus. Its `inventory.category_counts` is an authoritative, disjoint partition of every case and sums to `total_cases`; `signed_positive_envelopes` is an intentionally overlapping cryptographic coverage count. AF0 completes only when independent pure verifiers accept every positive vector and return the single expected token for every negative vector. Passing AF0 implements none of AF1 networking, P2P, reachability, storage, payment rails, or runtime execution.
