import assert from "node:assert/strict";
import { createHash, createPrivateKey } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { test } from "node:test";

import {
  canonical,
  computeAid,
  publicKeyFromDescriptor,
  createZone,
  signObject,
  swarmDisband,
  swarmJournalEntry,
  verifySwarmCloseV2,
  verifySwarmDisband,
  verifySwarmJournal,
} from "./asp-core.mjs";

const ZERO_HASH = "0".repeat(64);
const hex = (value) => createHash("sha256").update(typeof value === "string" ? value : canonical(value)).digest("hex");

function openedPayload() {
  return {
    schema_version: 1,
    spec: {
      schema_version: 1,
      swarm_id: "swarm://node-parity/alpha",
      plan: "eyJmb3JtYXQiOiJwbGFuIn0",
      binding: "eyJmb3JtYXQiOiJiaW5kaW5nIn0",
      request: "eyJmb3JtYXQiOiJyZXF1ZXN0In0",
      authority_generation_pin: { store_path: "test", passphrase_file: "test", record_digest: "a".repeat(64) },
      steps: [{ step_id: "prepare", candidates: [{ alias: "agent://worker", aid: computeAid(publicKeyFromDescriptor({ public_key_spki: "MCowBQYDK2VwAyEA3eO8zsfzpmoRFfRdcg9NwTXDrnxOItyjj9se_WpJX_g" })), generation_pin: { store_path: "test", passphrase_file: "test", record_digest: "b".repeat(64) }, public_key_spki: "MCowBQYDK2VwAyEA3eO8zsfzpmoRFfRdcg9NwTXDrnxOItyjj9se_WpJX_g", descriptor_digest: "c".repeat(64) }], attempt_policy: { max_attempts: 1 } }],
    },
  };
}

function entry(sequence, kind, payload, prior = sequence - 1, previousHash = ZERO_HASH) {
  return swarmJournalEntry({
    format: "agnet-local-swarm-journal/v1",
    sequence,
    prior_state_version: prior,
    state_version: prior + 1,
    kind,
    payload,
    timestamp: `2026-07-12T13:14:${String(14 + sequence).padStart(2, "0")}.123456789Z`,
    prev_hash: previousHash,
  });
}

test("pure journal builds canonical hashes and rejects chain, version, and transition tampering", () => {
  const first = entry(1, "swarm.opened", openedPayload());
  const second = entry(2, "wave.ready", { schema_version: 1, wave: { step_ids: ["prepare"], recorded_at: "2026-07-12T13:14:16.123456789Z" } }, 1, first.hash);
  const verified = verifySwarmJournal([first, second]);
  assert.equal(verified.head, second.hash);
  assert.equal(verified.state.version, 2);
  assert.equal(Object.isFrozen(verified.state), true);
  const { hash: _ignoredHash, ...firstWithoutHash } = first;
  assert.throws(() => swarmJournalEntry({ ...firstWithoutHash, sequence: Number.MAX_SAFE_INTEGER + 1 }), /safe integer/i);
  assert.throws(() => verifySwarmJournal([{ ...first, hash: "f".repeat(64) }]), /hash/i);
  assert.throws(() => verifySwarmJournal([{ ...first, version: 2 }]), /field|hash/i);
  const { hash: _unknownHash, ...unknownPreimage } = first;
  assert.throws(() => verifySwarmJournal([swarmJournalEntry({ ...unknownPreimage, kind: "unknown.transition" })]), /kind|transition/i);
  assert.throws(() => verifySwarmJournal([first, { ...second, sequence: 3 }]), /sequence/i);
});

test("pure journal reducer enforces ready DAG ordering, dispatch readiness, and monotonic fences", () => {
  const opened = entry(1, "swarm.opened", openedPayload());
  const ready = entry(2, "wave.ready", { schema_version: 1, wave: { step_ids: ["prepare"], recorded_at: "2026-07-12T13:14:16.123456789Z" } }, 1, opened.hash);
  const dispatched = entry(3, "wave.dispatched", { schema_version: 1, wave: { step_ids: ["prepare"], recorded_at: "2026-07-12T13:14:16.123456789Z" }, claims: [{ step_id: "prepare", owner: "coordinator", fence: 1, attempt: 1, candidate_index: 0, capability: "", candidate: openedPayload().spec.steps[0].candidates[0], deadline: "2026-07-12T13:15:00Z" }] }, 2, ready.hash);
  assert.equal(verifySwarmJournal([opened, ready, dispatched]).state.steps[0].status, "running");
  const duplicateReady = entry(2, "wave.ready", { schema_version: 1, wave: { step_ids: ["prepare", "prepare"], recorded_at: "2026-07-12T13:14:16.123456789Z" } }, 1, opened.hash);
  assert.throws(() => verifySwarmJournal([opened, duplicateReady]), /duplicate/i);
  const unreadyDispatch = entry(2, "wave.dispatched", { schema_version: 1, wave: { step_ids: ["prepare"], recorded_at: "2026-07-12T13:14:16.123456789Z" }, claims: [] }, 1, opened.hash);
  assert.throws(() => verifySwarmJournal([opened, unreadyDispatch]), /ready|dispatch/i);
  const observed = entry(4, "lease.observed", { schema_version: 1, claim: dispatched.payload.claims[0], outcome: "reported" }, 3, dispatched.hash);
  assert.equal(verifySwarmJournal([opened, ready, dispatched, observed]).state.steps[0].observations.length, 2);
  const wrongCandidate = structuredClone(dispatched);
  wrongCandidate.payload.claims[0].candidate.alias = "agent://attacker";
  const { hash: _wrongCandidateHash, ...wrongCandidatePreimage } = wrongCandidate;
  assert.throws(() => verifySwarmJournal([opened, ready, swarmJournalEntry({ ...wrongCandidatePreimage, prev_hash: ready.hash })]), /dispatch|candidate|readiness/i);
});

test("pure journal reducer rejects observations and signed receipts at a lease deadline", async () => {
  const vector = await loadDurableVector("asp-u29-node-swarm-durable.json");
  const lateObservation = structuredClone(vector.journal.slice(0, 4));
  lateObservation.at(-1).timestamp = lateObservation.at(-1).payload.claim.deadline;
  assert.throws(() => verifySwarmJournal(rechain(lateObservation)), /observation.*live|observation.*fence/i);

  const lateReceipt = structuredClone(vector.journal.slice(0, 6));
  lateReceipt.at(-1).timestamp = lateReceipt.at(-1).payload.claim.deadline;
  assert.throws(() => verifySwarmJournal(rechain(lateReceipt)), /receipt.*live|receipt.*invalid/i);
});

test("pure journal reducer renews exact live leases and expires them before retry migration", () => {
  const opened = entry(1, "swarm.opened", openedPayload());
  const wave = { step_ids: ["prepare"], recorded_at: "2026-07-12T13:14:16.123456789Z" };
  const ready = entry(2, "wave.ready", { schema_version: 1, wave }, 1, opened.hash);
  const claim = { step_id: "prepare", owner: "coordinator", fence: 1, attempt: 1, candidate_index: 0, capability: "", candidate: openedPayload().spec.steps[0].candidates[0], deadline: "2026-07-12T13:14:18.123456789Z" };
  const dispatched = entry(3, "wave.dispatched", { schema_version: 1, wave, claims: [claim] }, 2, ready.hash);
  const renewedClaim = { ...claim, deadline: "2026-07-12T13:14:20.123456789Z" };
  const renewed = entry(4, "lease.renewed", { schema_version: 1, claim: renewedClaim }, 3, dispatched.hash);
  const observed = entry(5, "lease.observed", { schema_version: 1, claim: renewedClaim, outcome: "reported" }, 4, renewed.hash);
  const renewedState = verifySwarmJournal([opened, ready, dispatched, renewed, observed]).state;
  assert.equal(renewedState.leases[0].deadline, renewedClaim.deadline);
  assert.equal(renewedState.steps[0].observations.at(-1).outcome, "reported");

  const wrongOwner = entry(4, "lease.renewed", { schema_version: 1, claim: { ...renewedClaim, owner: "attacker" } }, 3, dispatched.hash);
  assert.throws(() => verifySwarmJournal(rechain([opened, ready, dispatched, wrongOwner])), /renewal.*live|renewal.*lease/i);
  const nonExtending = entry(4, "lease.renewed", { schema_version: 1, claim }, 3, dispatched.hash);
  assert.throws(() => verifySwarmJournal(rechain([opened, ready, dispatched, nonExtending])), /renewal.*live|renewal.*lease/i);

  const retryOpenedPayload = openedPayload();
  retryOpenedPayload.spec.steps[0].attempt_policy.max_attempts = 2;
  retryOpenedPayload.spec.steps[0].candidates.push({ ...retryOpenedPayload.spec.steps[0].candidates[0], alias: "agent://worker/retry" });
  const retryOpened = entry(1, "swarm.opened", retryOpenedPayload);
  const retryReady = entry(2, "wave.ready", { schema_version: 1, wave }, 1, retryOpened.hash);
  const firstClaim = { ...claim, candidate: retryOpenedPayload.spec.steps[0].candidates[0] };
  const firstDispatch = entry(3, "wave.dispatched", { schema_version: 1, wave, claims: [firstClaim] }, 2, retryReady.hash);
  const expired = entry(4, "lease.expired", { schema_version: 1, now: "2026-07-12T13:14:18.123456789Z", claims: [firstClaim] }, 3, firstDispatch.hash);
  const expiredState = verifySwarmJournal([retryOpened, retryReady, firstDispatch, expired]).state;
  assert.equal(expiredState.status, "open");
  assert.equal(expiredState.steps[0].status, "pending");
  assert.equal(expiredState.steps[0].attempts, 1);
  assert.equal(expiredState.steps[0].observations.at(-1).outcome, "expired");

  const staleObservation = entry(5, "lease.observed", { schema_version: 1, claim: firstClaim, outcome: "late" }, 4, expired.hash);
  assert.throws(() => verifySwarmJournal(rechain([retryOpened, retryReady, firstDispatch, expired, staleObservation])), /observation.*live|observation.*fence/i);
  const retryWave = { step_ids: ["prepare"], recorded_at: "2026-07-12T13:14:19.123456789Z" };
  const retryReadyAfterExpiry = entry(5, "wave.ready", { schema_version: 1, wave: retryWave }, 4, expired.hash);
  const retryClaim = { ...firstClaim, owner: "coordinator-retry", fence: 2, attempt: 2, candidate_index: 1, candidate: retryOpenedPayload.spec.steps[0].candidates[1], deadline: "2026-07-12T13:14:22.123456789Z" };
  const retryDispatch = entry(6, "wave.dispatched", { schema_version: 1, wave: retryWave, claims: [retryClaim] }, 5, retryReadyAfterExpiry.hash);
  const retryState = verifySwarmJournal([retryOpened, retryReady, firstDispatch, expired, retryReadyAfterExpiry, retryDispatch]).state;
  assert.equal(retryState.last_fence, 2);
  assert.deepEqual(retryState.leases, [retryClaim]);
  assert.equal(retryState.steps[0].attempts, 2);
  const staleAfterMigration = entry(7, "lease.observed", { schema_version: 1, claim: firstClaim, outcome: "late" }, 6, retryDispatch.hash);
  assert.throws(() => verifySwarmJournal(rechain([retryOpened, retryReady, firstDispatch, expired, retryReadyAfterExpiry, retryDispatch, staleAfterMigration])), /observation.*live|observation.*fence/i);
});

test("pure journal reducer retains active leases behind the ready-wave barrier and requires canonical lease timestamps", () => {
  const multiStepPayload = openedPayload();
  multiStepPayload.spec.steps[0].attempt_policy.max_attempts = 2;
  multiStepPayload.spec.steps.push({ ...structuredClone(multiStepPayload.spec.steps[0]), step_id: "verify" });
  const opened = entry(1, "swarm.opened", multiStepPayload);
  const wave = { step_ids: ["prepare", "verify"], recorded_at: "2026-07-12T13:14:16.123456789Z" };
  const ready = entry(2, "wave.ready", { schema_version: 1, wave }, 1, opened.hash);
  const firstClaim = { step_id: "prepare", owner: "coordinator", fence: 1, attempt: 1, candidate_index: 0, capability: "", candidate: multiStepPayload.spec.steps[0].candidates[0], deadline: "2026-07-12T13:14:18.123456789Z" };
  const secondClaim = { step_id: "verify", owner: "coordinator", fence: 2, attempt: 1, candidate_index: 0, capability: "", candidate: multiStepPayload.spec.steps[1].candidates[0], deadline: "2026-07-12T13:14:30.123456789Z" };
  const dispatched = entry(3, "wave.dispatched", { schema_version: 1, wave, claims: [firstClaim, secondClaim] }, 2, ready.hash);
  const expired = entry(4, "lease.expired", { schema_version: 1, now: firstClaim.deadline, claims: [firstClaim] }, 3, dispatched.hash);
  const prematureRetry = entry(5, "wave.ready", { schema_version: 1, wave: { step_ids: ["prepare"], recorded_at: "2026-07-12T13:14:19.123456789Z" } }, 4, expired.hash);
  assert.throws(() => verifySwarmJournal(rechain([opened, ready, dispatched, expired, prematureRetry])), /ready.*(barrier|wave)|leasing/i);

  const singleOpened = entry(1, "swarm.opened", openedPayload());
  const singleWave = { step_ids: ["prepare"], recorded_at: "2026-07-12T13:14:16.123456789Z" };
  const singleReady = entry(2, "wave.ready", { schema_version: 1, wave: singleWave }, 1, singleOpened.hash);
  const noncanonicalDeadline = { step_id: "prepare", owner: "coordinator", fence: 1, attempt: 1, candidate_index: 0, capability: "", candidate: openedPayload().spec.steps[0].candidates[0], deadline: "2026-07-12T13:14:18.10Z" };
  const noncanonicalDispatch = entry(3, "wave.dispatched", { schema_version: 1, wave: singleWave, claims: [noncanonicalDeadline] }, 2, singleReady.hash);
  assert.throws(() => verifySwarmJournal([singleOpened, singleReady, noncanonicalDispatch]), /dispatch.*claim|dispatch.*readiness/i);
});

test("disband is canonical, signed, and bound to completed output", () => {
  const zone = createZone("zone://node-parity");
  const completed = {
    swarm_id: "swarm://node-parity/alpha",
    plan_digest: "a".repeat(64),
    execution_graph_digest: "b".repeat(64),
    close_digest: "c".repeat(64),
    output_verification_digest: "d".repeat(64),
    completed_at: "2026-07-12T13:14:15Z",
  };
  const disband = swarmDisband(zone, completed);
  assert.equal(disband.format, "asp-swarm-disband/v1");
  assert.equal(verifySwarmDisband(disband, zone.descriptor, completed).digest, hex(disband));
  assert.throws(() => verifySwarmDisband({ ...disband, close_digest: "e".repeat(64) }, zone.descriptor, completed), /binding|signature/i);
  assert.throws(() => swarmDisband(zone, { ...completed, completed_at: "not-a-time" }), /timestamp/i);
});

test("v2 close verifier accepts exact parallel-ready-dag evidence and rejects wave mismatch", () => {
  const zone = createZone("zone://node-parity-close");
  const digest = "a".repeat(64);
  const wave = { step_ids: ["prepare"], recorded_at: "2026-07-12T13:14:15Z" };
  const closeBody = {
    format: "asp-swarm-close/v2",
    swarm_id: "swarm://node-parity/close",
    plan_digest: digest,
    execution_graph_digest: "b".repeat(64),
    step_receipts: [{ step_id: "prepare", task_id: "prepare", signed_receipt_digest: "c".repeat(64), observations: [{ attempt: 1, candidate: { alias: "agent://worker" }, owner: "coordinator", fence: 1, outcome: "reported", observed_at: "2026-07-12T13:14:16Z" }] }],
    final_output: { step_id: "prepare", task_id: "prepare", signed_receipt_digest: "c".repeat(64), artifact: { uri: "artifact://final", sha256: "d".repeat(64), manifest_hash: "e".repeat(64) }, selection_rule: "single-terminal-result" },
    scheduler: { mode: "parallel-ready-dag", ready_waves: [wave], dispatch_waves: [{ wave, attempts: [{ step_id: "prepare", owner: "coordinator", fence: 1, attempt: 1, candidate_index: 0, capability: "analysis", candidate: { alias: "agent://worker" }, deadline: "2026-07-12T13:15:15Z" }] }] },
  };
  const frame = { type: "FED_SWARM_CLOSE", swarm_id: closeBody.swarm_id, zone: zone.descriptor, close: { ...closeBody, close_signature: signObject(zone.privateKey, closeBody) } };
  assert.equal(verifySwarmCloseV2(frame, new Map([[zone.zid, zone.descriptor]])).format, "asp-swarm-close/v2");
  const mismatched = structuredClone(frame);
  mismatched.close.scheduler.dispatch_waves[0].wave.step_ids = ["other"];
  mismatched.close.close_signature = signObject(zone.privateKey, (() => { const { close_signature, ...body } = mismatched.close; return body; })());
  assert.throws(() => verifySwarmCloseV2(mismatched, new Map([[zone.zid, zone.descriptor]])), /wave|scheduler/i);
});

test("pure Node durable surface does not expose durability or scheduler operations", async () => {
  const surface = await import("./asp-core.mjs");
  for (const name of ["appendSwarmJournal", "openSwarmJournal", "writeSwarmJournal", "scheduleSwarm", "runSwarm", "spawnSwarm"]) {
    assert.equal(name in surface, false, `${name} must not be exported`);
  }
});

async function loadDurableVector(name) {
  return JSON.parse(await readFile(new URL(`./test-vectors/${name}`, import.meta.url), "utf8"));
}

function rechain(entries) {
  let previousHash = ZERO_HASH;
  return entries.map(({ hash: _hash, ...entry }) => {
    const rebuilt = swarmJournalEntry({ ...entry, prev_hash: previousHash });
    previousHash = rebuilt.hash;
    return rebuilt;
  });
}

function nodePrivateKeyFromSeed(seedByte) {
  const seed = Buffer.alloc(32, seedByte);
  return createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]), format: "der", type: "pkcs8" });
}

function nodeCloseBody(state) {
  const binding = JSON.parse(Buffer.from(state.spec.binding, "base64url").toString("utf8"));
  const receipts = state.spec.steps.map((specStep) => {
    const step = state.steps.find((item) => item.step_id === specStep.step_id);
    const receipt = state.receipts[specStep.step_id];
    return {
      step_id: specStep.step_id,
      task_id: specStep.task_id,
      signed_receipt_digest: receipt.digest,
      observations: step.observations.map(({ claim, outcome, observed_at }) => ({ attempt: claim.attempt, candidate: claim.candidate, owner: claim.owner, fence: claim.fence, outcome, observed_at })),
    };
  });
  const referenced = new Set(state.spec.steps.flatMap((step) => step.depends_on ?? []));
  const terminal = state.spec.steps.filter((step) => !referenced.has(step.step_id));
  assert.equal(terminal.length, 1, "fixture must have one terminal step");
  const terminalIndex = state.spec.steps.findIndex((step) => step.step_id === terminal[0].step_id);
  return {
    format: "asp-swarm-close/v2",
    swarm_id: state.spec.swarm_id,
    plan_digest: binding.plan_digest,
    execution_graph_digest: binding.execution_graph_digest,
    step_receipts: receipts,
    final_output: { step_id: terminal[0].step_id, task_id: terminal[0].task_id, signed_receipt_digest: receipts[terminalIndex].signed_receipt_digest, artifact: state.receipts[terminal[0].step_id].result, selection_rule: "single-terminal-result" },
    scheduler: { mode: "parallel-ready-dag", ready_waves: state.ready_waves, dispatch_waves: state.dispatch_waves },
  };
}

function sharedNodeVectorInput(goVector) {
  return {
    deterministicEvents: goVector.journal.slice(0, 10).map(({ kind, payload, timestamp }) => ({ kind, payload: structuredClone(payload), timestamp })),
    outputTemplate: structuredClone(goVector.journal.find((entry) => entry.kind === "output.verified").payload),
  };
}

function buildNodeCreatedDurableVector(input) {
  const journal = [];
  const append = (kind, payload, timestamp) => {
    const previous = journal.at(-1);
    const priorStateVersion = previous?.state_version ?? 0;
    journal.push(swarmJournalEntry({ format: "agnet-local-swarm-journal/v1", sequence: journal.length + 1, prior_state_version: priorStateVersion, state_version: priorStateVersion + 1, kind, payload, timestamp, prev_hash: previous?.hash ?? ZERO_HASH }));
  };
  for (const event of input.deterministicEvents) append(event.kind, event.payload, event.timestamp);
  const authorityKey = nodePrivateKeyFromSeed(8);
  const state = verifySwarmJournal(journal).state;
  const closeBody = nodeCloseBody(state);
  const close = { ...closeBody, close_signature: signObject(authorityKey, closeBody) };
  const closeRaw = canonical(close);
  const closeBytes = Buffer.from(closeRaw).toString("base64url");
  const closeDigest = hex(closeRaw);
  append("close.stored", { schema_version: 1, close: closeBytes, digest: closeDigest }, journal.at(-1).timestamp);
  const outputPayload = structuredClone(input.outputTemplate);
  delete outputPayload.close;
  delete outputPayload.close_digest;
  delete outputPayload.completion_signature;
  Object.assign(outputPayload, { close: closeBytes, close_digest: closeDigest });
  outputPayload.completion_signature = signObject(authorityKey, outputPayload);
  append("output.verified", outputPayload, outputPayload.completed_at);
  const outputDigest = hex(outputPayload);
  const authorityZone = { privateKey: authorityKey, descriptor: state.spec.local_authority, zid: state.spec.local_authority.zid };
  const disband = swarmDisband(authorityZone, { swarm_id: state.spec.swarm_id, plan_digest: close.plan_digest, execution_graph_digest: close.execution_graph_digest, close_digest: closeDigest, output_verification_digest: outputDigest, completed_at: outputPayload.completed_at });
  const disbandRaw = canonical(disband);
  const disbandBytes = Buffer.from(disbandRaw).toString("base64url");
  append("swarm.disbanded", { schema_version: 1, disband: disbandBytes, digest: hex(disbandRaw) }, outputPayload.completed_at);
  const verified = verifySwarmJournal(journal);
  return {
    format: "asp-swarm-durable-parity-vector/v1",
    origin: "node",
    journal,
    evidence: {
      close: closeBytes,
      proof: outputPayload.proof,
      disband: disbandBytes,
      frozen_authority: state.spec.local_authority,
      frozen_workers: state.spec.steps.flatMap((step) => step.candidates.map((candidate) => JSON.parse(candidate.descriptor))),
      trust_inputs_digest: outputPayload.trust_inputs_digest,
    },
    expected: { head: verified.head, state_version: verified.state.version, swarm_id: state.spec.swarm_id, status: verified.state.status, close_digest: verified.state.stored_close.digest, proof_digest: outputPayload.proof_digest, disband_digest: verified.state.disband.digest },
  };
}

test("Node emits the fixed Node-origin durable vector with pure constructors and deterministic signing", async () => {
  const generated = buildNodeCreatedDurableVector(sharedNodeVectorInput(await loadDurableVector("asp-u29-go-swarm-durable.json")));
  assert.equal(generated.evidence.frozen_authority.zid, generated.journal[0].payload.spec.local_authority.zid);
  if (process.env.UPDATE_U29_NODE_VECTOR === "1") {
    await writeFile(new URL("./test-vectors/asp-u29-node-swarm-durable.json", import.meta.url), `${JSON.stringify(generated, null, 2)}\n`, { mode: 0o600 });
  } else {
    assert.deepEqual(generated, await loadDurableVector("asp-u29-node-swarm-durable.json"));
  }
});

test("Go-created and Node-created U29 vectors carry completed immutable evidence", async () => {
  for (const name of ["asp-u29-go-swarm-durable.json", "asp-u29-node-swarm-durable.json"]) {

    const vector = await loadDurableVector(name);
    assert.equal(vector.format, "asp-swarm-durable-parity-vector/v1");
    assert.ok(["go", "node"].includes(vector.origin));
    assert.ok(vector.evidence.close && vector.evidence.proof && vector.evidence.disband);
    assert.ok(vector.evidence.frozen_authority?.zid);
    assert.ok(Array.isArray(vector.evidence.frozen_workers) && vector.evidence.frozen_workers.length > 0);
    assert.match(vector.evidence.trust_inputs_digest, /^[0-9a-f]{64}$/);
    const verified = verifySwarmJournal(vector.journal);
    assert.equal(verified.head, vector.expected.head);
    assert.equal(verified.state.version, vector.expected.state_version);
    assert.equal(verified.state.status, "disbanded");
    assert.equal(verified.state.stored_close.digest, vector.expected.close_digest);
    assert.equal(verified.state.output_verification.trust_inputs_digest, vector.evidence.trust_inputs_digest);
    assert.equal(verified.state.disband.digest, vector.expected.disband_digest);
    const closeEntry = vector.journal.find((entry) => entry.kind === "close.stored");
    const proofEntry = vector.journal.find((entry) => entry.kind === "output.verified");
    const disbandEntry = vector.journal.find((entry) => entry.kind === "swarm.disbanded");
    assert.equal(closeEntry.payload.close, vector.evidence.close);
    assert.equal(proofEntry.payload.proof, vector.evidence.proof);
    assert.equal(disbandEntry.payload.disband, vector.evidence.disband);

    const closeMismatch = structuredClone(vector.journal);
    closeMismatch.find((entry) => entry.kind === "close.stored").payload.digest = "0".repeat(64);
    assert.throws(() => verifySwarmJournal(rechain(closeMismatch)), /close|digest/i);
    const noncanonicalClose = structuredClone(vector.journal);
    noncanonicalClose.find((entry) => entry.kind === "close.stored").payload.close += "*";
    assert.throws(() => verifySwarmJournal(rechain(noncanonicalClose)), /close|invalid/i);
    const legacyDigest = structuredClone(vector.journal);
    legacyDigest.find((entry) => entry.kind === "output.verified").payload.close_digest = "0".repeat(64);
    assert.throws(() => verifySwarmJournal(rechain(legacyDigest)), /output|close|signature/i);
    const badDisband = structuredClone(vector.journal);
    const encodedDisband = badDisband.find((entry) => entry.kind === "swarm.disbanded").payload.disband;
    const disband = JSON.parse(Buffer.from(encodedDisband, "base64url").toString("utf8"));
    disband.disband_signature = "A".repeat(disband.disband_signature.length);
    badDisband.find((entry) => entry.kind === "swarm.disbanded").payload.disband = Buffer.from(canonical(disband)).toString("base64url");
    badDisband.find((entry) => entry.kind === "swarm.disbanded").payload.digest = hex(canonical(disband));
    assert.throws(() => verifySwarmJournal(rechain(badDisband)), /disband|signature/i);
    const alteredTrust = structuredClone(vector.journal);
    alteredTrust.find((entry) => entry.kind === "output.verified").payload.trust_inputs_digest = "f".repeat(64);
    assert.throws(() => verifySwarmJournal(rechain(alteredTrust)), /output|trust|signature/i);
  }
});

test("swarm.opened rejects unknown and malformed frozen seed material", async () => {
  const vector = await loadDurableVector("asp-u29-node-swarm-durable.json");
  const opened = vector.journal[0];
  const mutations = [
    (spec) => { spec.unexpected = true; },
    (spec) => { spec.steps[0].unexpected = true; },
    (spec) => { spec.steps[0].attempt_policy.unexpected = true; },
    (spec) => { spec.steps[0].candidates[0].unexpected = true; },
    (spec) => { spec.steps[0].candidates[0].generation_pin.unexpected = true; },
    (spec) => { spec.authority_generation_pin.unexpected = true; },
    (spec) => { spec.plan = "eyJwbGFuIjoidW5jYW5vbmljYWwiLCAieiI6MX0"; },
    (spec) => { spec.authority_generation_pin.record_digest = "not-a-digest"; },
    (spec) => { spec.steps[0].attempt_policy.max_attempts = Number.MAX_SAFE_INTEGER + 1; },
  ];
  for (const mutate of mutations) {
    const changed = structuredClone(opened);
    mutate(changed.payload.spec);
    assert.throws(() => verifySwarmJournal(rechain([changed])), /swarm|durable|authority|worker|safe integer/i);
  }
});

test("receipt.committed rejects an outer result that the signed receipt did not bind", async () => {
  const vector = await loadDurableVector("asp-u29-node-swarm-durable.json");
  const changed = structuredClone(vector.journal.slice(0, 6));
  changed.at(-1).payload.result.uri = "artifact://tampered";
  assert.throws(() => verifySwarmJournal(rechain(changed)), /receipt|signature/i);
});

test("close.stored rejects a validly re-signed close inconsistent with replay evidence", async () => {
  const vector = await loadDurableVector("asp-u29-node-swarm-durable.json");
  const authorityKey = nodePrivateKeyFromSeed(8);
  const mutations = [
    (close) => { close.scheduler.ready_waves[0].step_ids.reverse(); },
    (close) => { close.scheduler.dispatch_waves[0].attempts.reverse(); },
    (close) => { close.step_receipts.reverse(); },
    (close) => { close.plan_digest = "f".repeat(64); },
    (close) => { close.execution_graph_digest = "e".repeat(64); },
    (close) => { close.final_output.artifact.uri = "artifact://tampered"; },
  ];
  for (const mutate of mutations) {
    const changed = structuredClone(vector.journal);
    const closeEntry = changed.find((item) => item.kind === "close.stored");
    const close = JSON.parse(Buffer.from(closeEntry.payload.close, "base64url").toString("utf8"));
    mutate(close);
    delete close.close_signature;
    close.close_signature = signObject(authorityKey, close);
    const raw = canonical(close);
    closeEntry.payload.close = Buffer.from(raw).toString("base64url");
    closeEntry.payload.digest = hex(raw);
    const closeIndex = changed.findIndex((item) => item.kind === "close.stored");
    assert.throws(() => verifySwarmJournal(rechain(changed.slice(0, closeIndex + 1))), /close.*(evidence|mismatch|invalid)|swarm close/i);
  }
});
