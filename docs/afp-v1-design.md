---
artifact_contract: ce-unified-plan/v1
artifact_readiness: implementation-ready
execution: code
product_contract_source: afp-v1-design
af0_contract: docs/afp-v1-contract.md
---

# AFP v1 — Agnet Fabric Protocol construction plan

**Status:** Implementation-ready architecture plan; no AFP runtime is implemented by this document.  
**Date:** 2026-07-22  
**Supersedes:** No implemented `ASP` frame, CLI, artifact prefix, vector, or package name.  
**Applies to:** Future sovereign/public and governed/private remote-work implementation.

## Admission and contract preservation

This plan freezes the AF1–AF7 runtime architecture, package choices, boundaries, and proof obligations; AF0 remains the pure verifier contract in `docs/afp-v1-contract.md`.

The Product Contract is unchanged. This source contains no `R*`, `F*`, or `AE*` identifiers to rewrite; no such identifiers are introduced. Existing AF0, U1–U30, and U31–U68 names retain their meaning.

The preserved dependency correction is:

AF0 ─┬─> AF1 -> AF2 -> AF3 -> AF4 -> AF5 -> AF6 -> AF7
AF0 now admits implementation but does not itself implement runtimes.
     └─> U31–U68 governed/private profile (parallel, not a prerequisite of AF1–AF7)

AF7 ships `AssuranceProjection` and `afp-gateway` independently after AF6. A later explicit plan mutation may let U59/U60 consume that stable projection; neither U59 nor U60 gates AF7, and AF7 is not a U59/U60 dependency.

All paths, symbols, and third-party modules below are **proposed implementation targets**, not assertions that they exist today. No ASP object is relabelled, wrapped, or silently accepted as AFP.
`afp:sha256:<digest>` Artifact fingerprint is a legacy optional **ASP v14 manifest field**; it is not an AFP v1 namespace, object digest, or compatibility alias.

---

## Purpose and fixed architecture

Agnet is the sovereign, verifiable coordination and settlement fabric for the Agent Internet. AFP is the protocol family above replaceable transports: it binds who is authorized to request work, the authority that accepted it, the evidence produced, and which terminal or settlement commitment is valid.

AFP is transport-neutral at the evidence layer, not a replacement for TCP/IP, QUIC, or libp2p. `aid:` remains the sole self-certifying Agent identity; a content reference is not access authority, custody is not execution authority, and a rail assertion is not receipt authority.

| Program | Fixed outcome | Must prove before the next program |
| --- | --- | --- |
| **AF0 — Protocol freeze** | Canonical AFP objects, signatures, negotiation, authority, and refusal semantics | Independent pure Node and Go verification; no ASP-to-AFP fallback. |
| **AF1 — Sovereign Core** | Invited, numeric-endpoint HTTPS/2 Direct work with pinned descriptors | Two independent operators complete one bounded Direct task without Zone, relay, or discovery. |
| **AF2 — Asynchronous delivery** | Encrypted durable mailbox and untrusted relay custody | Offline delivery cannot manufacture acceptance or revive a cancelled or expired lineage. |
| **AF3 — P2P reachability** | libp2p direct/relayed paths behind one injected path seam | A path change is observable and retains identity or requires re-authentication. |
| **AF4 — Capability discovery and offers** | Signed capability-reference discovery and bilateral encrypted matching | Discovery creates candidates only; it never grants trust, authority, or a registry dependency. |
| **AF5 — Direct Swarm** | Task-scoped Raft authority with AFP fences | Majority selects one terminal lineage; no quorum is read-only and cannot commit terminal state. |
| **AF6 — Settlement adapters** | Rail-neutral, idempotent settlement from receipt/custody facts | Changing rails cannot change task, receipt, or authority semantics. |
| **AF7 — Product convergence** | Standalone machine-readable assurance projection and `afp-gateway` | Every edge exposes its assurance properties; no generic verified badge exists. |

## Narrow-waist invariants and global non-goals

1. Every non-local session uses AF0 negotiation and a signed route binding. Direct, relayed, store-forward, governed, `a2a-baseline`, and `a2a-afp` remain distinct profiles/routes.
2. The runtime consumes AF0 canonical bytes and verifier results; it never relaxes first-failure tokens or derives authority from network success, a relay, a DHT, a payment, or a signature alone.
3. The initial delivery order is invited Direct (AF1), durable encrypted mailbox (AF2), reachability (AF3), discovery (AF4), Swarm (AF5), settlement (AF6), then convergence (AF7). Public discovery, markets, and Zone-free Swarm membership do not precede the AF1 exit evidence.
4. U1–U30 remain valid as the local proof kernel for task/event/artifact/checkpoint/fence/receipt semantics. AFP consumes them through explicit adapters and evidence, rather than renaming their files, vectors, frames, or artifacts.
5. The U31–U68 governed/private profile consumes AF0 semantics but does not become an identity service, mandatory path, or prerequisite for Direct work.

AFP v1 does not add a network-layer replacement, mandatory blockchain/token/provider, global semantic routing authority, objective reputation, exactly-once execution, anonymous unrestricted tools, public DHT content publication, or generic assurance branding.

---

## Output structure and shared seams

```text
internal/afp/
  direct/       # AF1 invited HTTPS/2 session and descriptor pinning
  mailbox/      # AF2 envelope crypto, journals, RelayAdapter
  path/         # AF3 injected PathManager and route evidence
  discovery/    # AF4 capability-reference advertisements and bilateral matching
  swarm/        # AF5 charter acceptance, Raft persistence, fence authority
  settlement/   # AF6 RailAdapter and durable settlement outbox
  assurance/    # AF7 AssuranceProjection and A2A binding
cmd/
  afp-directd/  # AF1 process
  afp-relayd/   # AF2 untrusted store-forward process
  afp-pathd/    # AF3 libp2p path process
  afp-discoveryd/ # AF4 optional discovery process
  afp-swarmd/   # AF5 participant process
  afp-gateway/  # AF7 standalone server-rendered assurance gateway
```

Cross-unit interfaces are intentionally narrow and AFP-shaped:

| Interface | Owner | Contract |
| --- | --- | --- |
| `VerifiedAFP` | AF0 adapter | Canonical envelope digest, verified route binding, evidence digests, and stable verifier token; callers receive no partially accepted object. |
| `DescriptorStore` | AF1 | Lookup/store a signed descriptor by `aid:` and pinned SPKI digest; pin changes require explicit local approval. |
| `Journal` | AF2 | Append before externally observable transition; expose replay in sequence order and a durable high-water mark. |
| `PathManager` | AF3 | Establish/observe authenticated Direct or relayed paths and return immutable route evidence; it has no task, grant, or receipt authority. |
| `AdvertisementIndex` | AF4 | Publish/resolve signed capability-advertisement references only; it cannot store an `IntentQuery` body. |
| `FenceAuthority` | AF5 | Resolve the current Raft term/index-derived AFP fence for a Swarm; no result is available without quorum. |
| `RailAdapter` | AF6 | Reserve/commit/reverse a named settlement fact idempotently; it cannot create receipts or task transitions. |
| `AssuranceProjection` | AF7 | JSON/API representation of identity, confidentiality, authorization, execution, receipt, route/profile, and evidence limitations. |

All journals use canonical AFP envelope bytes plus local metadata; plaintext application payloads, private keys, and unencrypted IntentQuery text are never placed in a relay, DHT, or diagnostic log. Persistence is local filesystem storage with restrictive permissions. A crash may require replay and at-least-once worker delivery, but must not create a second authority transition or terminal receipt.

---

## Implementation units

### AF1. Sovereign Core — invited Direct session

**Dependencies/packages/interfaces:** Depends on AF0 and the existing `aid:` identity/verifier surface. Add no third-party transport dependency: use planned Go standard-library `net`, `net/http`, `crypto/tls`, `crypto/x509`, `crypto/ed25519`, `encoding/base64`, `encoding/json`, and `os`. Introduce proposed symbols `direct.Server`, `direct.InvitedClient`, `direct.PinnedDescriptor`, `direct.DescriptorStore`, `direct.MailboxKey`, and `direct.NegotiatedSession`. AF1 reserves exactly one signed `AgentDescriptor.route_hints` entry as `afp-mailbox-x25519-v1:<mailbox-epoch>:<base64url-32-byte-public-key>`; `<mailbox-epoch>` is a canonical unsigned safe integer (`0` or nonzero decimal without leading zero), and the pinned replacement epoch must be strictly greater than the persisted epoch. `direct.MailboxKey` rejects zero or multiple current entries, malformed keys, and non-increasing epochs. The descriptor's Ed25519 signature authenticates that recipient X25519 public key. The HTTP endpoint accepts numeric IP literals only; hostname lookup, Zone lookup, relay, rendezvous, DHT, and discovery are absent from this unit.

**Process boundary and persistence:** `cmd/afp-directd` is the only AF1 network process. It binds an operator-configured numeric address, exposes HTTPS/2 over TLS 1.3, and passes canonical AFP objects to the AF0 adapter. `direct.DescriptorStore` persists accepted peer descriptor bytes, descriptor digest, SPKI digest, selected signed mailbox-key hint and epoch, accepted `aid:`, endpoint, and explicit local pin decision in an append-only local file; replacement is a new approval record, never TOFU mutation. No service owns both peers' keys.

**Crypto and fault model:** TLS authenticates the numeric endpoint channel; the signed `AgentDescriptor` and its Ed25519-derived `aid:` establish peer identity. The client verifies the descriptor signature, expected `aid:`, pinned Ed25519 SPKI digest, and selected mailbox-key hint before AFP negotiation. The AF1 route context canonically includes the descriptor digest, selected mailbox-key hint, mailbox epoch, numeric endpoint, and TLS peer certificate digest; AF0's application transcript and `afp.route-binding` commit that context digest. AF2 may ECDH only to the mailbox key recovered from a verified current route binding and its matching pinned descriptor. A changed certificate, descriptor, SPKI, mailbox key/epoch, route context, profile, or negotiated version closes the session before task handling. Network timeout, reset, duplicate request, or restart produces no inferred acceptance; idempotency and AF0 replay evidence decide recovery.

**Migration/rollback:** Additive `direct` profile only. ASP remains on its current path and rejected AFP traffic stays rejected; no protocol auto-detection or compatibility shim. Rollback stops `afp-directd`, preserves descriptor/pin journal evidence read-only, and disables the Direct listener without deleting task evidence.

**Files/symbols:** Create `internal/afp/direct/server.go`, `client.go`, `descriptor_store.go`, `mailbox_key.go`, `session.go`, `tls_config.go`, and `cmd/afp-directd/main.go`; adapt AF0 only through `internal/afp/direct/af0_adapter.go`. The final names may vary only at low-level package organization; the described seam and authority split are fixed.

**Test harness and failure injection:** Use Go's standard `testing`, loopback numeric endpoints, an independently supplied AF0 vector verifier, and a two-process integration harness. Inject expired descriptors, wrong `aid:`, SPKI mismatch, malformed/multiple/rolled-back mailbox-key hints, TLS-version downgrade, transcript/route-binding or mailbox-key-context mutation, duplicate TaskOpen, abrupt close after journal append, and a peer restart. The harness must observe stable AF0 refusal tokens and a single accepted Direct lineage rather than transport success alone.

**Exit evidence:** Two separately configured operator processes at numeric endpoints complete an invited bounded Direct task. Evidence includes both pinned descriptors, TLS/AFP negotiation transcript, signed route binding, explicit grant, task lineage, artifact manifest, and one independently verified receipt; neither process uses a Zone, relay, or discovery service.

**Non-goals:** DNS names, CA-based peer identity, automatic key rotation, NAT traversal, offline mailbox, public listener defaults, and arbitrary endpoint scanning.

**Implementation-time unknowns:** Connection/read/write deadlines, journal rotation size, listener concurrency, and certificate lifetime are low-level tuning only; they may not alter numeric invitation, descriptor/SPKI pinning, TLS 1.3, AFP binding, or Ed25519 authority.

### AF2. Asynchronous delivery — encrypted mailbox and untrusted custody

**Dependencies/packages/interfaces:** Depends on AF0 and AF1 identity/descriptor pinning, including AF1's selected signed `afp-mailbox-x25519-v1` route hint and verified current route binding. Use planned Go standard-library `crypto/ecdh` (X25519), `crypto/hkdf` (HKDF-SHA256), `crypto/aes`, `crypto/cipher` (AES-256-GCM), `crypto/rand`, `crypto/sha256`, `net/http`, `os`, and `sync`. Introduce `mailbox.MailboxKeyResolver`, `EnvelopeSealer`, `EnvelopeOpener`, `Journal`, `RelayAdapter`, `CustodyStateMachine`, and `LineageGuard`. `MailboxKeyResolver` accepts only the pinned descriptor and matching AF0 route-binding context recorded by AF1; it never accepts a relay-supplied key. `RelayAdapter` is an untrusted bounded HTTP store-forward API; it accepts opaque ciphertext and can sign only AF0 custody evidence with its declared custodian identity.

**Process boundary and persistence:** The sender and recipient own separate durable `outbox` and `inbox` journals; `cmd/afp-relayd` is a separately deployed untrusted process with a bounded opaque-object store and its own durable `custody` journal. Each state change (`submitted`, `custody-accepted`, `delivered`, cancellation, expiry, local acceptance) is appended and `fsync`ed before acknowledgement; compacted files are written to a sibling temporary name, `fsync`ed, atomically renamed, and the parent directory is synced. Relay retention is bounded by ciphertext size, mailbox epoch, and delivery expiry. Relay persistence contains ciphertext, expiry, and custody lineage only.

**Crypto and fault model:** Every mail uses a fresh ephemeral X25519 sender key and the recipient X25519 public key resolved only by `MailboxKeyResolver`; before ECDH it verifies the descriptor signature/SPKI pin, selected mailbox-key hint, epoch, and AF0 route-binding digest against the persisted AF1 session. Derive a per-message AES-256-GCM key with HKDF-SHA256 over the shared secret and domain-separated context containing mailbox epoch, sender/recipient `aid:`, route-binding digest, descriptor digest, and mail id; authenticate the immutable AFP mailbox metadata as AEAD associated data. Generate a unique GCM nonce with `crypto/rand`; never reuse an ephemeral private key or nonce. The relay cannot decrypt, alter, replay into a new route, extend expiry, substitute a recipient key, accept work, execute work, or commit a receipt. A sender crash after append/retry yields duplicate opaque delivery attempts but one journaled lineage. A recipient crash after decrypt before durable append redelivers; acceptance is possible only after the recipient's durable verified state permits it.

**Migration/rollback:** This adds `store-forward` route handling without changing Direct behavior. Existing direct sessions can opt out of mailbox use. Rollback disables mailbox submission and leaves journals replayable/read-only; it does not purge custody evidence or reinterpret it as execution evidence.

**Files/symbols:** Create `internal/afp/mailbox/crypto.go`, `journal.go`, `relay_adapter.go`, `custody.go`, `lineage.go`, `relay_store.go`, `cmd/afp-relayd/main.go`, and AF1 integration `internal/afp/direct/mailbox_bridge.go`.

**Test harness and failure injection:** Use an in-process bounded relay plus sender/recipient processes and a fake durable filesystem fault layer. Inject process death between append/fsync/rename/ack, torn temp file, duplicate POST, reordered relay response, omitted custody receipt, ciphertext/AAD/tag mutation, descriptor/route-binding/mailbox-key mismatch or relay-supplied recipient key, expired delivery, cancellation racing delivery, key/nonce reuse guard failure, disk-full, and relay eviction. The harness asserts decryption only by the intended recipient, recovery from valid journal prefix, no revived cancelled/expired lineage, and no relay-created acceptance/execution/receipt.

**Exit evidence:** An offline pinned recipient receives, decrypts, durably records, and later processes a valid encrypted TaskOpen through a bounded relay. The sender obtains custody evidence only; the recipient's independently verified acceptance and final receipt remain separate. Cancellation and expiry cases demonstrate refusal after replay/reconnect.

**Non-goals:** Relay trust, relay key custody, multi-relay replication, public mailbox discovery, anonymous mail, exactly-once application execution, and using transport TLS as message confidentiality.

**Implementation-time unknowns:** Store quota, retry backoff, compaction threshold, retention period, and HTTP response batching are tuning variables; they cannot change ephemeral-X25519/HKDF/AES-GCM encryption, durable transition order, or custody/acceptance separation.

### AF3. P2P reachability — replaceable authenticated paths

**Dependencies/packages/interfaces:** Depends on AF0, AF1 descriptor/pin semantics, and AF2 envelope semantics where store-forward is used. Add planned (not currently present) `github.com/libp2p/go-libp2p` and its QUIC-v1, Circuit Relay v2, AutoNAT, hole-punching, identify, and connection/resource-manager facilities. Introduce `path.PathManager`, `path.Path`, `path.RouteEvidence`, and `path.Policy`; AF1/AF2 depend only on the injected `PathManager` interface, never libp2p concrete types. The Node verifier remains an independent AF0 verifier and must not import or trust the Go path implementation.

**Process boundary and persistence:** `cmd/afp-pathd` owns a libp2p host and optional path lifecycle. Direct and relay listeners are explicit operator opt-ins, disabled by default, and configured independently from AFP identity acceptance. Persist peer descriptor/pin references and append-only route evidence (peer identity mapping, selected path type, observed multiaddress digest, negotiation/route-binding digest, timestamps, and failure class); do not persist private NAT observations as authority evidence.

**Crypto and fault model:** libp2p authenticates transport peers and `identify` supplies transport metadata, but AFP accepts a path only after descriptor/pin validation and a fresh AF0 route binding. QUIC, circuit relay, AutoNAT, and hole punching are availability mechanisms only. Resource/connection-manager limits bound connections, streams, bytes, and peer pressure. A changed libp2p peer key, changed pinned AFP descriptor/SPKI, unauthenticated path migration, relay substitution, exhausted resource limit, or path loss either yields fresh re-authentication plus new route binding or fails closed. Route evidence describes the actual path but never confers grant, execution, or receipt authority.

**Migration/rollback:** Keep AF1 HTTPS/2 Direct as the first path implementation. Introduce `PathManager` with a Direct adapter before enabling libp2p. Rollback removes the opt-in libp2p listener and falls back only by establishing a new authenticated AF1 Direct session; it never carries an existing route binding across a transport migration.

**Files/symbols:** Create `internal/afp/path/manager.go`, `direct_manager.go`, `libp2p_manager.go`, `route_evidence.go`, `policy.go`, `cmd/afp-pathd/main.go`, plus AF1/AF2 constructor changes that accept `PathManager`.

**Test harness and failure injection:** Use a local multi-host libp2p harness with separate AFP identities, AF0 Node/Go verifier checks, and test-only NAT/relay fixtures. Inject direct-path failure, relay-only availability, post-connect descriptor mismatch, peer-key rotation, identify spoof/mismatch, path migration without binding refresh, circuit exhaustion, stream/connection limit exhaustion, relay disconnect, hole-punch failure, and stale route evidence. Assert that route choice is observable, a path loss does not alter authority, and a re-established path requires fresh authentication/binding.

**Exit evidence:** Two pinned AFP peers complete an AF1-compatible task over an observed QUIC-v1 Direct path and, separately, over Circuit Relay v2. Both paths produce identical AFP authority/receipt verification outcomes while route evidence accurately names the path and resource controls bound abuse.

**Non-goals:** libp2p as an AFP identity root, automatic public listeners, DHT discovery, pubsub task transport, treating multiaddresses as authorization, or replacing independent Node verification.

**Implementation-time unknowns:** Connection limits, stream limits, AutoNAT sampling, relay selection order, hole-punch retry interval, and evidence retention are tuning only; the injected interface, opt-in listeners, authentication reset rule, and route-evidence requirement are fixed.

### AF4. Capability discovery and offers — private candidate creation

**Dependencies/packages/interfaces:** Depends on AF0 signed `CapabilityAdvertisement`, AF1 descriptor/pin policy, AF3 `PathManager`, and AF2 encrypted bilateral delivery. Add planned libp2p rendezvous support and planned `github.com/libp2p/go-libp2p-kad-dht` only for signed capability-advertisement references. Introduce `discovery.AdvertisementIndex`, `AdvertisementPublisher`, `CandidateResolver`, `BilateralMatcher`, `FreshnessVerifier`, and `PeerQuota`. Neither index method accepts an `IntentQuery` body; IntentQuery natural language never enters rendezvous, DHT records, pubsub, logs, or metrics.

**Process boundary and persistence:** `cmd/afp-discoveryd` is optional and has no task/receipt authority. It publishes signed, expiry-bounded advertisement references and resolves candidate references through rendezvous/DHT. The requesting Agent locally chooses candidates, then sends its encrypted IntentQuery and receives encrypted Offer bilaterally over AF2/AF3. Persist local advertisement issuance/revocation records, resolved reference cache, provenance/freshness verdicts, per-peer quota state, and audit digests; persist neither third-party natural-language query text nor plaintext offer terms outside the participating peers.

**Crypto and fault model:** Every advertisement is an AF0-signed statement whose subject, provenance digest, expiry, and revocation evidence are independently verified before use. DHT/rendezvous can replay, suppress, equivocate, enumerate, or return stale references; local policy treats those conditions as candidate-quality signals or rejection, never trust. Bilateral query/offer confidentiality is AF2 envelope confidentiality. Per-peer token buckets cap lookup, publication, resolve, query, and offer rates; local policy also caps candidate fan-out and disclosure class. A discovery result cannot bypass descriptor pinning, grant verification, policy, route binding, or an explicit Offer/TaskOpen lineage.

**Migration/rollback:** Discovery is additive and disabled until AF1–AF3 exit evidence exists. Rollback unpublishes/local-revokes advertisements where possible, stops discovery listeners, clears only derived cache entries, and preserves signed issuance/revocation audit records. Existing bilateral work remains valid; no task becomes invalid merely because a discovery index disappears.

**Files/symbols:** Create `internal/afp/discovery/index.go`, `rendezvous.go`, `dht.go`, `advertisement.go`, `matcher.go`, `freshness.go`, `quota.go`, `policy.go`, and `cmd/afp-discoveryd/main.go`.

**Test harness and failure injection:** Use controlled rendezvous/DHT fixtures plus separate requestor/provider processes. Inject stale/revoked/forged advertisement references, provenance mismatch, DHT equivocation, enumeration pressure, request floods, token-bucket exhaustion/refill, encrypted-query delivery failure, Offer replay/expiry, and index outage. Inspect fixture records to prove no IntentQuery plaintext/natural language was published. Assert that local policy rejects a valid-looking but unauthorized candidate and that a valid discovery reference alone produces no execution.

**Exit evidence:** A provider publishes only a signed capability-advertisement reference. A requester resolves it with provenance/freshness evidence, sends an encrypted bilateral query, receives an encrypted signed Offer, and still requires descriptor pinning, grant, and local policy before AF1/AF2 task acceptance. Rate-limit evidence and a no-query-publication audit accompany the flow.

**Non-goals:** Natural-language DHT search, public task queues, global reputation, discovery as authorization, mandatory registry operation, semantic model standardization, or relay-backed plaintext matching.

**Implementation-time unknowns:** Advertisement TTL, cache bounds, token refill rates, candidate cap, DHT namespace names, and rendezvous refresh cadence are tuning only; reference-only publication, bilateral encryption, provenance/freshness/revocation, and local policy remain fixed.

### AF5. Direct Swarm — task-scoped majority authority

**Dependencies/packages/interfaces:** Depends on AF0 charter/task/receipt/fence semantics, AF1 identity/grants, AF3 `PathManager`, and AF2 for durable delivery when needed. Add planned (not currently present) `go.etcd.io/raft/v3`. Introduce `swarm.Charter`, `MemberAcceptance`, `RaftStore`, `FenceAuthority`, `CommitApplier`, and `WorkerDispatcher`. A static voter set exists only after every member's signed acceptance is verified against the charter; membership changes are out of scope for this release.

**Process boundary and persistence:** `cmd/afp-swarmd` runs one Raft participant per accepted member. Every Swarm has its own directory containing a Raft WAL, snapshot, accepted charter/member evidence, applied-index marker, immutable AFP event/receipt lineage, and worker delivery journal. Raft log/snapshot persistence is separate from AFP object verification; the commit applier re-verifies proposed authority/evidence before producing externally visible state. Workers are at-least-once and run outside the Raft state-machine critical section.

**Crypto and fault model:** The charter names static voters, task scope, expiry, and fence rule. Each accepted member signs its acceptance; no implicit membership or TCP/libp2p peer presence counts as a voter. The committed Raft term/index derives the monotonic AFP fence, and each claim/event/receipt must bind it. Majority quorum is required for mutable authority and every terminal commitment. Without quorum, the participant is read-only: it may serve already committed evidence but may not accept work, advance a terminal lineage, issue a receipt, or settle a terminal fact. Split brain, stale leader, replayed proposal, reordered replication, snapshot/WAL recovery, and worker retry are contained by term/index/fence, idempotency, and AF0 lineage verification. External side effects are explicitly at-least-once; they require a downstream idempotency key and cannot be represented as exactly-once.

**Migration/rollback:** Create Swarm state only after charter acceptance, never migrate existing Zone/U31 consensus state in place. Rollback stops participants, preserves WAL/snapshot/evidence for forensic replay, and starts no replacement Swarm without a new charter and acceptances. A recovered process replays committed state; it does not infer uncommitted work from a worker journal.

**Files/symbols:** Create `internal/afp/swarm/charter.go`, `acceptance.go`, `raft_store.go`, `node.go`, `fence.go`, `applier.go`, `worker.go`, `recovery.go`, and `cmd/afp-swarmd/main.go`.

**Test harness and failure injection:** Use a multi-process static-voter harness with deterministic Raft transport and external idempotent worker stub. Inject leader crash before/after commit, voter partition/loss of quorum, duplicate acceptance, non-member proposal, stale term/index, conflicting terminal proposal, WAL truncation/corruption, snapshot restore, delayed/reordered replication, repeated worker callback, and no-quorum read attempt. Assert a single terminal receipt under majority, no terminal commit without majority, read-only behavior during quorum loss, and at-least-once worker delivery without duplicate AFP authority.

**Exit evidence:** Three accepted voters execute a task-scoped Swarm; a majority commits one fence-bound terminal receipt. A partition that removes majority prevents terminal commitment while prior evidence remains readable. Restart from WAL/snapshot reconstructs the same committed lineage, and repeated worker delivery is demonstrably idempotent downstream.

**Non-goals:** Dynamic membership, geographic/global consensus, Zone membership reuse, exactly-once workers, Raft as a global registry, consensus on plaintext private query data, or quorum-free emergency terminal receipts.

**Implementation-time unknowns:** Election/heartbeat timing, snapshot cadence, WAL segment size, worker concurrency, and backpressure thresholds are tuning only; static signed acceptance, per-Swarm persistence, term/index fence, majority rule, and read-only no-quorum behavior are fixed.

### AF6. Settlement adapters — rail-neutral durable commitments

**Dependencies/packages/interfaces:** Depends on AF0 settlement/receipt/custody verification and the authoritative outcomes of AF1–AF5, but not on any specific chain, token, bank, escrow, or provider. Introduce `settlement.RailAdapter`, `SettlementOutbox`, `FactValidator`, `IdempotencyKey`, `LocalCreditAdapter`, and `SettlementCoordinator`. `RailAdapter` operations are reserve, commit, reverse/refund where supported, and lookup by AFP settlement idempotency key. The built-in `LocalCreditAdapter` is the mandatory conformance/reference adapter, not a production payment mandate.

**Process boundary and persistence:** `settlement` is an in-process AFP authority consumer or a separately deployed adapter process with no ability to create TaskOpen, TaskEvent, or ReceiptCommit. A durable local settlement outbox records validated fact digest, budget authorization digest, receipt/custody digest, rail name, idempotency key, state, and adapter response before retries. The local-credit ledger is separately durable and append-only. Secrets for optional external rails remain outside AFP journals and are never carried in signed AFP facts.

**Crypto and fault model:** Before enqueue/commit, recompute AF0 settlement idempotency and require a verified, uncontested, unexpired, unrevoked, current-fence, profile-sufficient, budget-bound receipt/custody fact. A rail success does not create receipt authority; a rail failure does not rewrite task state. Lost adapter responses, duplicate dispatch, process crash after provider acceptance, and reversal race are handled by durable outbox replay and idempotency. `LocalCreditAdapter` proves those semantics with deterministic local balances and intentionally has no external payment authority.

**Migration/rollback:** Start with the local-credit reference adapter only. Add future rails as new `RailAdapter` implementations behind explicit configuration and a one-way outbox version. Rollback disables a rail for new reservations, drains/reconciles known outbox entries by idempotency, and preserves commitment evidence; it does not undo a receipt or reinterpret a charge as task authority.

**Files/symbols:** Create `internal/afp/settlement/adapter.go`, `outbox.go`, `coordinator.go`, `facts.go`, `idempotency.go`, `local_credit.go`, and `cmd/afp-settlementd/main.go` if process isolation is selected.

**Test harness and failure injection:** Use the deterministic `LocalCreditAdapter`, crashable outbox store, and fake rail responses. Inject duplicate submit, timeout after rail acceptance, insufficient budget, stale/revoked/contested receipt, wrong fence, mismatched fact digest, adapter restart, corrupted outbox entry, reversal failure, and rail semantic overclaim. Assert one rail commitment per idempotency key, refusal before invalid fact reaches the rail, replay-safe recovery, and unchanged task/receipt evidence across rail replacement.

**Exit evidence:** A completed Direct/Swarm receipt and a custody fact each independently produce a valid, budget-bound settlement request to `LocalCreditAdapter`; duplicate delivery commits once. Invalid, stale, no-quorum, or contested facts are refused before adapter dispatch. Replacing the local adapter with a test rail preserves AFP receipt/task verification byte-for-byte.

**Non-goals:** Mandatory blockchain, token, stablecoin, provider account, multi-rail smart routing, credit-risk underwriting, payment-derived authorization, or settlement of raw packets.

**Implementation-time unknowns:** Outbox retry cadence, local-credit storage limit, adapter circuit-breaker thresholds, reconciliation interval, and optional-process deployment are tuning only; rail neutrality, durable idempotency, and fact/authority separation are fixed.

### AF7. Product convergence — standalone assurance, `afp-gateway`, and A2A binding

**Dependencies/packages/interfaces:** Depends on AF0 verification and AF1–AF6 evidence as available, shipping independently after AF6 with no U59/U60 dependency. Introduce exactly one `assurance.AssuranceProjection` JSON/API contract, `ProjectionBuilder`, `A2ABinding`, and `gateway.RenderAssurance`. The standalone `afp-gateway` is server-rendered and consumes that projection; it must not recompute assurance in browser code. A later explicit U59/U60 plan mutation may consume the stable projection without importing AFP runtime internals. `a2a-baseline` binding reports the baseline's explicit lack of AFP custody/execution/fence/receipt/settlement authority; `a2a-afp` binding preserves AFP bytes, profile, and verification semantics.

**Process boundary and persistence:** `cmd/afp-gateway` exposes the projection API and renders the server-side Human Gateway view. It reads verified AFP evidence through a read-only projection store/cache keyed by task/attempt/receipt digest. Browser sessions receive a rendered representation and opaque references, not signing keys, grants, unencrypted mailbox payloads, or mutable authority controls. Projection cache is disposable derived data; canonical evidence stays in AF1–AF6 journals/evidence stores.

**Projection contract:** One versioned JSON shape represents, without collapsing, `identity`, `confidentiality`, `authorization`, `execution`, `receipt`, `settlement`, `route`, `profile`, `evidence`, and `limitations`. Each property includes `state` (`proven`, `not-proven`, `unavailable`, or `contested`), evidence digest references, and a human explanation. A projection is never a boolean `verified`. The renderer must visibly distinguish authenticated identity from confidential delivery, authorized execution, verified artifact, terminal receipt, and settled fact. A2A mode appears as a binding descriptor, not an inference: `a2a-baseline` has unavailable AFP authority properties; `a2a-afp` links the supplied AFP evidence/digests.

**Crypto and fault model:** AF7 performs no signing and accepts only AF0-verified evidence records. Missing evidence renders `not-proven` or `unavailable`; conflicting evidence renders `contested`; unknown state never inherits a stronger state from route, UI role, payment, or A2A label. Cache corruption/miss forces a read-only rebuild from verified evidence or an explicit unavailable view. A compromised browser can misrepresent pixels but cannot mutate the server projection or produce AFP evidence; user actions that could affect authority remain in their owning AF1–AF6 processes with explicit re-verification.

**Migration/rollback:** Add the projection API alongside existing product views; do not replace existing evidence objects or force clients to infer AFP state. Introduce a versioned content type and server-rendered route. Rollback removes the new route/API exposure and discards derived cache only; it retains source evidence and never substitutes a generic verified badge.

**Files/symbols:** Create `internal/afp/assurance/projection.go`, `builder.go`, `a2a.go`, `store.go`, `internal/afp/gateway/handler.go`, `render.go`, `templates/assurance.html`, and `cmd/afp-gateway/main.go`. No U59/U60 adaptation is included in AF7; a later explicit plan mutation may define a narrow consumer interface for the stable projection.

**Test harness and failure injection:** Use AF0 positive/negative evidence fixtures, a server-rendering harness, and an A2A fixture pair. Inject missing descriptor, no encryption evidence, valid identity but absent grant, execution without receipt, contested receipt, stale route binding, cache corruption, `a2a-baseline` attempted AFP receipt, malformed `a2a-afp` binding, and an attempted generic verified rendering. Assert JSON/API and rendered HTML express identical property states and limitations, `a2a-baseline` never claims AFP authority, and no renderer path emits a generic verified badge.

**Exit evidence:** The standalone `afp-gateway` displays Direct, relayed/store-forward, governed, and A2A-associated work through the same AssuranceProjection. For each row/detail view, the operator can inspect evidence digests and the separate identity/confidentiality/authorization/execution/receipt properties. A baseline A2A task visibly reports unavailable AFP authority, while an `a2a-afp` task links independently verifiable AFP evidence.

**Non-goals:** A generic verified UI label, client-side authority inference, browser-held keys, a second assurance schema, automatic A2A trust elevation, replacement of U59, or using visual state as protocol evidence.

**Implementation-time unknowns:** Cache TTL, page pagination, display wording, localization, and template layout are tuning only; the one projection contract, server-rendering integration, property separation, and A2A baseline/extension distinction are fixed.

---

## Cross-cutting migration, rollback, and verification contract

**Migration:** Introduce AFP as an additive, versioned runtime family. AF0 accepts only AFP canonical envelopes; ASP v14 remains implemented and separate. Each unit lands behind an explicit profile/route configuration and consumes the prior unit's exit evidence. No implementation may treat a successful transport, discovery lookup, relay custody, consensus log entry, rail response, or UI state as a substitute for AF0 authority/evidence checks.

**Rollback:** Disable new listeners, publishers, adapters, or renderer routes first; preserve signed evidence, journals, descriptor pins, WAL/snapshots, and outbox records as read-only forensic material. Never delete or convert AFP evidence to hide a rollback. A rollback cannot cause a weaker profile retry to inherit a stronger session, and it cannot reclassify custody/payment/UI state as execution/receipt authority.

**Verification sequence:**

1. AF0 Node and Go verifiers independently accept the AF0 positive corpus and return the expected token for each negative corpus case.
2. AF1 proves invited numeric HTTPS/2/TLS-1.3 Direct work with descriptors/SPKI pins and route binding.
3. AF2 proves encrypted durable store-forward custody and refusal of cancellation/expiry resurrection.
4. AF3 proves the same AFP identity/authority over observed Direct and Circuit Relay v2 paths with fresh binding on change.
5. AF4 proves signed reference-only discovery plus encrypted bilateral query/offer and abuse bounds.
6. AF5 proves static accepted voters, majority terminal authority, and read-only no-quorum recovery.
7. AF6 proves rail-neutral idempotent settlement from valid receipt/custody facts using local credit.
8. AF7 proves a single projection/rendering contract that never overstates A2A or any weaker assurance property.

No implementation tests are run by this planning change. Each listed harness and failure-injection case is a mandatory implementation acceptance obligation, not evidence that it already exists or passed.

## Sources

- `docs/afp-v1-contract.md` — normative AF0 canonical object, negotiation, authority, and stable-error contract.
- `afp/contract.go`, `afp/verifier.go`, `afp-contract.mjs` — current independent verifier surfaces to preserve, not AFP runtime implementations.
- [libp2p specifications](https://github.com/libp2p/specs) — planned reusable peer transport/reachability primitives.
- [A2A](https://github.com/a2aproject/A2A) — interoperability baseline/extension surface, not an AFP authority replacement.
