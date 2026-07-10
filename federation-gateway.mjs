import net from "node:net";
import { createHash, randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import {
  appendAudit,
  approvalReasons,
  b64url,
  canonical,
  capabilityCredential,
  enforcePolicy,
  loadOrCreateAgent,
  loadOrCreateZone,
  loadTrustedZones,
  publicKeyFromDescriptor,
  resolveAgent,
  signObject,
  validateTaskId,
  verifyFederatedReceipt,
  verifyFederatedTaskOpen,
  verifySwarmExecutionBinding,
  verifySwarmPlan,
  verifyObject,
  verifyCapabilityCredential,
  verifyCredentialStatus,
  verifyZoneDescriptor,
  writeArtifact,
  zoneBinding,
  verifyZoneRevocation,
  verifyZoneBinding,
  zoneRevocation,
} from "./asp-core.mjs";

function send(socket, frame) {
  socket.write(`${JSON.stringify(frame)}\n`);
}

function digestHex(value) {
  return createHash("sha256").update(canonical(value)).digest("hex");
}

function tokenize(value) {
  return String(value ?? "").toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
}

function semanticScore(intent, descriptor) {
  const intentTokens = new Set(tokenize(intent));
  if (intentTokens.size === 0) return 0;
  const candidateTokens = new Set(tokenize(`${descriptor.alias} ${descriptor.capabilities.join(" ")}`));
  return [...intentTokens].filter((token) => candidateTokens.has(token)).length;
}

function costSignal(policy) {
  const cost = policy?.cost_tokens_per_task;
  if (!Number.isSafeInteger(cost)) return { score: 5, used: false };
  return { score: Math.max(0, Math.min(10, 10 - Math.floor(cost / 100))), used: true };
}

function latencySignal(policy) {
  const latency = policy?.latency_ms_p95;
  if (!Number.isSafeInteger(latency)) return { score: 5, used: false };
  if (latency <= 100) return { score: 10, used: true };
  if (latency <= 500) return { score: 7, used: true };
  if (latency <= 2000) return { score: 4, used: true };
  return { score: 1, used: true };
}

function availabilitySignal(started, completed, hasAuditData) {
  if (!hasAuditData) return { score: 5, used: false };
  const safeStarted = Number.isSafeInteger(started) && started > 0 ? started : 0;
  const safeCompleted = Number.isSafeInteger(completed) && completed > 0 ? completed : 0;
  const denominator = safeStarted > 0 ? safeStarted : 1;
  return { score: Math.max(0, Math.min(10, Math.floor((safeCompleted / denominator) * 10))), used: true };
}

function policyMatchSignal(policy, taskScope) {
  const scope = taskScope && typeof taskScope === "object" ? taskScope : {};
  const hasNetworkConstraint = typeof scope.network === "boolean";
  const writeTargets = Array.isArray(scope.write) ? scope.write.filter((target) => typeof target === "string") : [];
  const used = hasNetworkConstraint || writeTargets.length > 0;
  if (!used) return { score: 5, used: false };
  if (scope.network === true && policy?.allow_network !== true) return { score: 0, used: true };
  for (const target of writeTargets) {
    const allowed = (policy?.write_prefixes ?? []).some((prefix) => typeof prefix === "string" && target.startsWith(prefix));
    if (!allowed) return { score: 0, used: true };
  }
  return { score: 10, used: true };
}

function riskMatchSignal(credentialClaims, active, completedReceipts, revocationCount) {
  const used = credentialClaims !== null || revocationCount > 0;
  if (!used) return { score: 5, used: false };
  let score = 5;
  if (active) score += 3;
  else score -= 2;
  if (completedReceipts > 0) score += 2;
  score -= Math.min(revocationCount * 5, 10);
  return { score: Math.max(0, Math.min(10, score)), used: true };
}


function routingSignals(worker, credentialClaims, taskScope, active, completedReceipts, revocationCount) {
  const cost = costSignal(worker.descriptor.policy);
  const latency = latencySignal(worker.descriptor.policy);
  const availability = availabilitySignal(
    credentialClaims?.availability_started,
    credentialClaims?.availability_completed,
    credentialClaims?.availability_has_audit_data === true,
  );
  const policy = policyMatchSignal(worker.descriptor.policy, taskScope);
  const risk = riskMatchSignal(credentialClaims, active, completedReceipts, revocationCount);
  const signals_used = [cost.used, latency.used, availability.used, policy.used, risk.used].filter(Boolean).length;
  return { cost_score: cost.score, latency_score: latency.score, availability_score: availability.score, policy_match: policy.score, risk_match: risk.score, signals_used };
}

function auditRecordForWorker(record, aid) {
  if (record?.kind === "fed_receipt" && record.to === aid) return true;
  if (record?.kind === "fed_event" && record.by === aid) return true;
  return false;
}

function auditRecordIsCompleted(record) {
  if (record?.kind === "fed_receipt" && record.status === "completed") return true;
  if (record?.kind === "fed_event" && record.type === "task.completed") return true;
  return false;
}
async function countCompletedReceiptsFromAudit(auditPath, aid) {
  let text;
  try {
    text = await readFile(auditPath, "utf8");
  } catch (error) {
    if (error.code === "ENOENT") return { count: 0, lastCompletedAt: null, availabilityStarted: 0, availabilityCompleted: 0, availabilityHasAuditData: false };
    return { count: 0, lastCompletedAt: null, availabilityStarted: 0, availabilityCompleted: 0, availabilityHasAuditData: false };
  }
  let count = 0;
  let lastCompletedAt = null;
  let lastCompletedTime = -Infinity;
  const records = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    let entry;
    try {
      entry = JSON.parse(line);
    } catch {
      continue;
    }
    const record = entry?.record;
    if (!record) continue;
    records.push(record);
    if (record?.kind !== "fed_receipt" || record.to !== aid || record.status !== "completed") continue;
    count++;
    const timestamp = record.completed_at ?? record.completedAt ?? record.last_completed_at ?? record.timestamp ?? record.receipt?.completed_at ?? record.receipt?.completedAt ?? record.receipt?.timestamp ?? null;
    const time = Date.parse(timestamp);
    if (Number.isFinite(time) && time > lastCompletedTime) {
      lastCompletedTime = time;
      lastCompletedAt = timestamp;
    }
  }
  let availabilityStarted = 0;
  let availabilityCompleted = 0;
  let availabilityHasAuditData = false;
  for (const record of records.slice(-50)) {
    if (!auditRecordForWorker(record, aid)) continue;
    if (record.kind === "fed_event" && record.type === "task.started") availabilityStarted++;
    if (auditRecordIsCompleted(record)) availabilityCompleted++;
    if (record.kind === "fed_event" && (record.type === "task.started" || record.type === "task.completed")) availabilityHasAuditData = true;
    if (record.kind === "fed_receipt") availabilityHasAuditData = true;
  }
  return { count, lastCompletedAt, availabilityStarted, availabilityCompleted, availabilityHasAuditData };
}

function countRevocationsForWorker(revocations, aid, alias) {
  return (revocations ?? []).filter((revocation) => revocation.subject === aid || revocation.subject === alias).length;
}

function computeAgentScore(completedReceipts, lastCompletedAt, revocationCount, active, costScore, latencyScore, availabilityScore, policyMatch, riskMatch) {
  const receipt_score = Math.min(completedReceipts, 20) * 2;
  const credential_score = active ? 30 : 0;
  let freshness_score = 0;
  const completedTime = Date.parse(lastCompletedAt);
  if (Number.isFinite(completedTime)) {
    const age = Date.now() - completedTime;
    if (age >= 0 && age <= 60 * 60 * 1000) freshness_score = 10;
    else if (age >= 0 && age <= 24 * 60 * 60 * 1000) freshness_score = 5;
  }
  const cost_score = Number.isFinite(costScore) ? costScore : 5;
  const latency_score = Number.isFinite(latencyScore) ? latencyScore : 5;
  const availability_score = Number.isFinite(availabilityScore) ? availabilityScore : 5;
  const policy_match = Number.isFinite(policyMatch) ? policyMatch : 5;
  const risk_match = Number.isFinite(riskMatch) ? riskMatch : 5;
  const revocation_penalty = Math.min(revocationCount * 10, receipt_score + credential_score + freshness_score);
  const total = Math.max(0, Math.min(100, receipt_score + credential_score + freshness_score + cost_score + latency_score + availability_score + policy_match + risk_match - revocation_penalty));
  return { total, receipt_score, credential_score, freshness_score, cost_score, latency_score, availability_score, policy_match, risk_match, revocation_penalty };
}


export function queryMatch(zone, worker, capability, intent, credentialClaims = null, taskScope = null) {
  const exact = worker.descriptor.capabilities.includes(capability);
  const semantic = semanticScore(intent, worker.descriptor);
  if (!exact && semantic === 0) return null;
  const credentials = exact && credentialClaims ? [
    capabilityCredential(zone, worker.descriptor, capability, credentialClaims),
  ] : [];
  const completedReceipts = Number.isSafeInteger(credentialClaims?.completed_receipts) ? credentialClaims.completed_receipts : 0;
  const lastCompletedAt = typeof credentialClaims?.last_completed_at === "string" ? credentialClaims.last_completed_at : null;
  let active = credentials.length > 0 && verifyCapabilityCredential(credentials[0], zone.descriptor, worker.descriptor);
  const validRevocations = (zone.revocations ?? []).filter((revocation) => verifyZoneRevocation(revocation, zone.descriptor));
  const revocationCount = countRevocationsForWorker(validRevocations, worker.descriptor.aid, worker.descriptor.alias);
  if (revocationCount > 0) active = false;
  const routing = routingSignals(worker, credentialClaims, taskScope, active, completedReceipts, revocationCount);
  const agentScore = computeAgentScore(completedReceipts, lastCompletedAt, revocationCount, active, routing.cost_score, routing.latency_score, routing.availability_score, routing.policy_match, routing.risk_match);
  const reasons = [];
  if (exact) reasons.push("capability_exact");
  if (semantic > 0) reasons.push("semantic_match");
  if (active) reasons.push("credential_active");
  if (completedReceipts > 0) reasons.push("reputation_receipts");
  if (routing.policy_match > 5) reasons.push("policy_match");
  if (routing.risk_match > 5) reasons.push("risk_match");
  const score = agentScore.total + (exact ? 50 : 0) + semantic;
  return {
    worker: worker.descriptor,
    zone_binding: zoneBinding(zone, worker.descriptor),
    credentials,
    discovery_evidence: {
      identity: { zone: zone.zid, aid: worker.aid, alias: worker.alias },
      capability: { exact, semantic: semantic > 0 },
      credential: { trusted: credentials.length > 0, active },
      reputation: { completed_receipts: completedReceipts, last_completed_at: lastCompletedAt, revocation_count: revocationCount, agent_score: agentScore },
      routing,
    },
    ranking: { score, reasons },
  };
}

function readFrames(socket, onFrame) {
  let buffer = "";
  socket.on("data", (chunk) => {
    buffer += chunk;
    for (;;) {
      const index = buffer.indexOf("\n");
      if (index === -1) break;
      const line = buffer.slice(0, index);
      buffer = buffer.slice(index + 1);
      if (line.trim()) onFrame(JSON.parse(line));
    }
  });
}

function verifyTrustedZone(trustedZones, descriptor) {
  const { descriptor: verified } = verifyZoneDescriptor(descriptor);
  const trusted = trustedZones.get(verified.zid);
  if (!trusted || trusted.public_key_spki !== verified.public_key_spki) {
    throw new Error(`untrusted zone: ${verified.zid}`);
  }
  return verified;
}

function sessionAuthBody(sessionId, challenge, peerZid, remoteZid) {
  return { session_id: sessionId, challenge, peer_zid: peerZid, remote_zid: remoteZid };
}

function serverSessionHandler(socket, trustedZones, zone) {
  const session = {};
  return (frame) => {
    if (frame.type === "HELLO") {
      const peer = verifyTrustedZone(trustedZones, frame.origin_zone);
      session.id = `session:${b64url(randomBytes(16))}`;
      session.challenge = b64url(randomBytes(32));
      session.peerZid = peer.zid;
      send(socket, { type: "HELLO", zone: zone.descriptor, session_id: session.id, challenge: session.challenge });
      return true;
    }
    if (frame.type === "AUTH") {
      const peer = verifyTrustedZone(trustedZones, frame.origin_zone);
      if (peer.zid !== session.peerZid) throw new Error("session origin mismatch");
      const auth = frame.auth ?? {};
      const body = sessionAuthBody(session.id, session.challenge, peer.zid, zone.zid);
      if (
        auth.session_id !== body.session_id ||
        auth.challenge !== body.challenge ||
        auth.peer_zid !== body.peer_zid ||
        auth.remote_zid !== body.remote_zid
      ) {
        throw new Error("session auth body mismatch");
      }
      if (!verifyObject(publicKeyFromDescriptor(peer), body, auth.auth_signature)) {
        throw new Error("session auth signature verification failed");
      }
      session.authenticated = true;
      send(socket, { type: "AUTH_OK", session_id: session.id });
      return true;
    }
    if (!session.authenticated) throw new Error("session not authenticated");
    if (frame.origin_zone?.zid !== session.peerZid) throw new Error("session origin mismatch");
    return false;
  };
}

function clientSessionHandler(socket, trustedZones, zone, onAuthenticated) {
  const session = {};
  return (frame) => {
    if (frame.type === "HELLO") {
      const remote = verifyTrustedZone(trustedZones, frame.zone);
      session.id = frame.session_id;
      session.challenge = frame.challenge;
      const body = sessionAuthBody(session.id, session.challenge, zone.zid, remote.zid);
      send(socket, { type: "AUTH", origin_zone: zone.descriptor, auth: { ...body, auth_signature: signObject(zone.privateKey, body) } });
      return true;
    }
    if (frame.type === "AUTH_OK") {
      if (frame.session_id !== session.id) throw new Error("session id mismatch");
      onAuthenticated();
      return true;
    }
    return false;
  };
}

async function sendEvent(socket, event) {
  await appendAudit({ kind: "fed_event", ...event });
  send(socket, { type: "FED_TASK_EVENT", event });
}

function swarmAfterSteps(value) {
  if (value === undefined) return [];
  if (!Array.isArray(value)) throw new Error("swarm after invalid");
  return value.map((item) => {
    if (typeof item !== "string" || item === "" || item.includes("\0")) throw new Error("swarm after invalid");
    return item;
  });
}

function scheduleSwarmSteps(items) {
  const pending = new Map();
  const afterByStep = new Map();
  const inputOrder = [];
  for (const item of items) {
    if (!item || typeof item !== "object" || Array.isArray(item)) throw new Error("swarm step invalid");
    const stepId = item.step_id;
    if (typeof stepId !== "string" || stepId === "" || stepId.includes("\0")) throw new Error("swarm step_id missing");
    if (pending.has(stepId)) throw new Error(`duplicate swarm step: ${stepId}`);
    const after = swarmAfterSteps(item.after);
    if (after.includes(stepId)) throw new Error("swarm schedule dependency unresolved");
    pending.set(stepId, item);
    afterByStep.set(stepId, after);
    inputOrder.push(stepId);
  }

  for (const after of afterByStep.values()) {
    for (const dependency of after) {
      if (!pending.has(dependency)) throw new Error("swarm schedule dependency unresolved");
    }
  }

  const done = new Set();
  const ordered = [];
  const stepOrder = [];
  while (pending.size > 0) {
    let progressed = false;
    for (const stepId of inputOrder) {
      const step = pending.get(stepId);
      if (!step || !afterByStep.get(stepId).every((dependency) => done.has(dependency))) continue;
      ordered.push(step);
      stepOrder.push(stepId);
      done.add(stepId);
      pending.delete(stepId);
      progressed = true;
    }
    if (!progressed) throw new Error("swarm schedule dependency unresolved");
  }
  return { steps: ordered, scheduler: { mode: "ready-dag", step_order: stepOrder } };
}

function microContractForStep(worker, swarmId, stepId, task) {
  const policyDigest = digestHex({ worker: worker.aid, policy: worker.descriptor.policy, task_scope: task.scope ?? null });
  const body = {
    micro_contract: "ok",
    swarm_id: swarmId,
    step_id: stepId,
    worker: worker.descriptor,
    cost_estimate: {
      tokens: Math.max(1, Math.ceil(canonical(task).length / 4)),
      seconds: Number.isSafeInteger(task.budget?.time_seconds) ? task.budget.time_seconds : 30,
    },
    capability_proof: worker.descriptor.capabilities.join(","),
    policy_digest: policyDigest,
  };
  return { ...body, contract_digest: digestHex(body), signature: signObject(worker.privateKey, body) };
}

function taskArtifactUri(task, fallback) {
  if (task.artifact_ref === undefined) return fallback;
  if (typeof task.artifact_ref !== "string" || task.artifact_ref === "" || task.artifact_ref.includes("\0")) throw new Error("task artifact_ref invalid");
  return task.artifact_ref;
}

function workerAgentScore(worker, agentScores) {
  const score = agentScores?.get(worker.aid)?.total;
  return Number.isFinite(score) ? score : 0;
}

function conflictResolutionForGroup(zone, swarmId, artifactRef, entries, agentScores) {
  const candidates = entries.map((entry) => ({
    ...entry,
    score: workerAgentScore({ aid: entry.worker.aid }, agentScores),
    alias: typeof entry.worker.alias === "string" ? entry.worker.alias : "",
  }));
  const sorted = [...candidates].sort((left, right) => right.score - left.score || left.alias.localeCompare(right.alias));
  const chosen = sorted[0];
  const runnerUp = sorted[1];
  const body = {
    swarm_id: swarmId,
    artifact_ref: artifactRef,
    candidate_step_ids: entries.map((entry) => entry.step_id),
    chosen_step_id: chosen.step_id,
    chosen_worker: chosen.worker,
    reason: chosen.score > runnerUp.score ? "higher_reputation" : "alias_tiebreak",
  };
  return { ...body, resolution_digest: digestHex(body), signature: signObject(zone.privateKey, body) };
}

function swarmConflictResolutions(zone, swarmId, completed, stepReceipts, agentScores) {
  const byArtifact = new Map();
  const stepWorker = new Map(stepReceipts.map((step) => [step.step_id, step.worker]));
  for (const step of stepReceipts) {
    const receipt = completed.get(step.step_id);
    for (const manifest of receipt?.artifact_manifests ?? []) {
      if (!manifest || typeof manifest.uri !== "string" || typeof manifest.sha256 !== "string") continue;
      if (!byArtifact.has(manifest.uri)) byArtifact.set(manifest.uri, []);
      byArtifact.get(manifest.uri).push({ step_id: step.step_id, worker: stepWorker.get(step.step_id), sha256: manifest.sha256 });
    }
  }
  const resolutions = [];
  for (const [artifactRef, entries] of byArtifact) {
    const distinctStepIds = new Set(entries.map((entry) => entry.step_id));
    const distinctDigests = new Set(entries.map((entry) => entry.sha256));
    if (distinctStepIds.size >= 2 && distinctDigests.size >= 2) {
      resolutions.push(conflictResolutionForGroup(zone, swarmId, artifactRef, entries, agentScores));
    }
  }
  return resolutions;
}


async function executeLocalTask(socket, zone, originZone, worker, signedTask, task, receiptExtra = {}) {
  await sendEvent(socket, { type: "task.accepted", task_id: task.task_id, by: worker.aid, zone: zone.zid });
  const approvals = approvalReasons(worker.descriptor, task);
  if (approvals.length > 0) {
    await sendEvent(socket, { type: "approval.required", task_id: task.task_id, reasons: approvals });
    await sendEvent(socket, {
      type: "approval.granted",
      task_id: task.task_id,
      by: "human://zone-b/operator",
      reasons: approvals,
    });
  }
  await sendEvent(socket, { type: "task.started", task_id: task.task_id, by: worker.aid, zone: zone.zid });
  await sendEvent(socket, { type: "task.progress", task_id: task.task_id, progress: 0.5 });

  const artifactUri = taskArtifactUri(task, `artifact://local/${task.task_id}/federated-summary.md`);
  const artifact = await writeArtifact(artifactUri, `# Federated Summary\n\nCompleted ${task.task_id} from ${originZone.zid}.\n`);
  await sendEvent(socket, { type: "artifact.created", task_id: task.task_id, uri: artifactUri, manifest: artifact.manifest });
  await sendEvent(socket, { type: "task.completed", task_id: task.task_id, by: worker.aid, zone: zone.zid });

  const receipt = {
    task_id: task.task_id,
    task_digest: digestHex(signedTask),
    from: task.from,
    origin_zone: originZone.zid,
    executing_zone: zone.zid,
    to: worker.aid,
    status: "completed",
    artifact_refs: [artifactUri],
    artifact_manifests: [artifact.manifest],
    event_count: approvals.length > 0 ? 7 : 5,
    approvals,
    ...receiptExtra,
  };
  const signedReceipt = { ...receipt, signature: signObject(worker.privateKey, receipt) };
  await appendAudit({ kind: "fed_receipt", ...signedReceipt });
  send(socket, {
    type: "FED_RECEIPT",
    zone: zone.descriptor,
    worker: worker.descriptor,
    zone_binding: zoneBinding(zone, worker.descriptor),
    receipt: signedReceipt,
  });
  send(socket, { type: "FED_TASK_CLOSE", task_id: task.task_id });
  return signedReceipt;
}

function workerCapabilities(worker) {
  return Array.isArray(worker?.descriptor?.capabilities) ? worker.descriptor.capabilities : [];
}

function sharesCapability(left, right) {
  const rightCapabilities = new Set(workerCapabilities(right));
  return workerCapabilities(left).some((capability) => rightCapabilities.has(capability));
}

function nextMigrationCandidate(workers, originalWorker, capability, stepId) {
  const sharedCandidates = workers.filter((worker) => worker.aid !== originalWorker.aid && sharesCapability(originalWorker, worker));
  const exactCandidate = sharedCandidates.find((worker) => workerCapabilities(worker).includes(capability)) ?? null;
  if (!exactCandidate && sharedCandidates.length > 0) {
    throw new Error(`execution binding migration worker capability missing: ${stepId}`);
  }
  return exactCandidate;
}

function normalizeExecutableSwarmStep(item) {
  if (!item || typeof item !== "object" || Array.isArray(item)) throw new Error("swarm step invalid");
  const stepId = item.step_id;
  if (typeof stepId !== "string" || stepId === "" || stepId.includes("\0")) throw new Error("swarm step_id missing");
  return { step_id: stepId, depends_on: swarmAfterSteps(item.after), task: item.task };
}
function validateOrderedSwarmDependencies(steps) {
  const completed = new Set();
  for (const step of steps) {
    for (const dependency of step.dependsOn) {
      if (!completed.has(dependency)) throw new Error(`swarm dependency not completed: ${dependency}`);
    }
    completed.add(step.stepId);
  }
}


function verifiedSwarmRequester(frame) {
  verifyZoneBinding({ zone: frame.origin_zone, zone_binding: frame.requester_zone_binding }, frame.requester, "requester");
  try {
    return resolveAgent(new Map([[frame.requester.alias, frame.requester]]), frame.requester.alias);
  } catch (error) {
    throw new Error(`swarm requester invalid: ${error.message}`);
  }
}

function verifySwarmSignedTask(frame, requester, signedTask, originalWorker) {
  if (!signedTask || typeof signedTask !== "object" || Array.isArray(signedTask)) throw new Error("execution binding signed task missing");
  const { signature, ...task } = signedTask;
  validateTaskId(task.task_id);
  if (task.from !== frame.requester.aid) throw new Error("task sender does not match requester descriptor");
  if (task.to !== originalWorker.alias) throw new Error(`task target does not match worker alias: ${task.to}`);
  if (typeof signature !== "string" || signature === "") throw new Error("task signature missing");
  if (!verifyObject(requester.publicKey, task, signature)) throw new Error("task signature verification failed");
  let policyError = null;
  try {
    enforcePolicy(originalWorker.descriptor, task);
  } catch (error) {
    policyError = error;
  }
  return { task, policyError };
}

function preflightSwarmExecution(trustedZones, frame, workers, readyDag) {
  const originZone = verifyTrustedZone(trustedZones, frame.origin_zone);
  if (!frame.requester || typeof frame.requester !== "object" || Array.isArray(frame.requester)) throw new Error("swarm requester missing");
  if (!frame.requester_zone_binding || typeof frame.requester_zone_binding !== "object" || Array.isArray(frame.requester_zone_binding)) throw new Error("requester zone binding missing");
  if (!frame.swarm || typeof frame.swarm !== "object" || Array.isArray(frame.swarm)) throw new Error("swarm body missing");
  const swarmId = frame.swarm.swarm_id;
  if (typeof swarmId !== "string" || swarmId === "" || swarmId.includes("\0")) throw new Error("swarm_id missing");
  if (!Array.isArray(frame.swarm.steps) || frame.swarm.steps.length === 0) throw new Error("swarm steps missing");
  if (!frame.swarm.plan || typeof frame.swarm.plan !== "object" || Array.isArray(frame.swarm.plan)) throw new Error("swarm plan missing");
  const verifiedPlan = verifySwarmPlan(frame.swarm.plan, trustedZones);
  if (verifiedPlan.zone.zid !== originZone.zid || verifiedPlan.zone.public_key_spki !== originZone.public_key_spki) {
    throw new Error("swarm plan origin mismatch");
  }
  if (!frame.swarm.execution_binding || typeof frame.swarm.execution_binding !== "object" || Array.isArray(frame.swarm.execution_binding)) {
    throw new Error("execution binding missing");
  }

  const requester = verifiedSwarmRequester(frame);
  const executableSteps = frame.swarm.steps.map(normalizeExecutableSwarmStep);
  const taskEvidence = executableSteps.map((step) => {
    const originalWorker = workers.find((candidate) => candidate.alias === step.task?.to);
    if (!originalWorker) throw new Error(`task target does not match worker alias: ${step.task?.to}`);
    try {
      resolveAgent(new Map([[originalWorker.descriptor.alias, originalWorker.descriptor]]), originalWorker.descriptor.alias);
    } catch (error) {
      throw new Error(`execution binding worker invalid: ${error.message}`);
    }
    const verifiedTask = verifySwarmSignedTask(frame, requester, step.task, originalWorker);
    return { ...step, signedTask: step.task, task: verifiedTask.task, originalWorker, originalPolicyError: verifiedTask.policyError };
  });
  const verifiedBinding = verifySwarmExecutionBinding(
    frame.swarm.execution_binding,
    verifiedPlan,
    executableSteps,
    taskEvidence.map((step) => step.originalWorker.descriptor),
  );
  if (verifiedBinding.swarmId !== swarmId) throw new Error("execution binding swarm_id mismatch");

  const verifiedSteps = taskEvidence.map((step, index) => {
    const bindingStep = verifiedBinding.steps[index];
    const migrationWorker = nextMigrationCandidate(workers, step.originalWorker, bindingStep.capability, bindingStep.step_id);
    if (migrationWorker) enforcePolicy(migrationWorker.descriptor, step.task);
    if (!migrationWorker && step.originalPolicyError) {
      throw step.originalPolicyError;
    }
    return Object.freeze({
      ...step,
      stepId: bindingStep.step_id,
      dependsOn: bindingStep.depends_on,
      capability: bindingStep.capability,
      taskDigest: bindingStep.task_digest,
      migrationWorker,
    });
  });
  if (verifiedSteps.some((step) => step.migrationWorker)) {
    verifySwarmExecutionBinding(
      frame.swarm.execution_binding,
      verifiedPlan,
      executableSteps,
      verifiedSteps.map((step) => (step.migrationWorker ?? step.originalWorker).descriptor),
    );
  }

  const scheduled = readyDag ? scheduleSwarmSteps(frame.swarm.steps) : null;
  if (!scheduled) validateOrderedSwarmDependencies(verifiedSteps);
  const verifiedByStepId = new Map(verifiedSteps.map((step) => [step.stepId, step]));
  const executionSteps = scheduled ? scheduled.steps.map((step) => verifiedByStepId.get(step.step_id)) : verifiedSteps;
  if (executionSteps.some((step) => !step)) throw new Error("swarm schedule dependency unresolved");
  return Object.freeze({
    originZone,
    swarmId,
    planDigest: verifiedBinding.planDigest,
    executionGraphDigest: verifiedBinding.executionGraphDigest,
    signedSteps: Object.freeze([...verifiedSteps]),
    executionSteps: Object.freeze([...executionSteps]),
    scheduler: scheduled?.scheduler ?? null,
  });
}

async function executeSwarm(socket, trustedZones, zone, workers, frame, agentScores = new Map(), readyDag = false) {
  workers = Array.isArray(workers) ? workers : [workers];
  const context = preflightSwarmExecution(trustedZones, frame, workers, readyDag);
  const completed = new Map();
  const stepReceipts = [];
  const microContracts = [];
  const migrationLog = [];
  for (const step of context.executionSteps) {
    const inputArtifacts = [];
    for (const dependency of step.dependsOn) {
      const receipt = completed.get(dependency);
      if (!receipt) throw new Error(`swarm dependency not completed: ${dependency}`);
      const manifest = receipt.artifact_manifests?.[0];
      if (!manifest) throw new Error(`swarm dependency artifact missing: ${dependency}`);
      inputArtifacts.push({
        step_id: dependency,
        uri: manifest.uri,
        sha256: manifest.sha256,
        manifest_hash: manifest.manifest_hash,
        receipt_digest: digestHex(receipt),
      });
    }
    const swarmProof = {
      swarm_id: context.swarmId,
      step_id: step.stepId,
      after: step.dependsOn,
      input_artifacts: inputArtifacts,
      plan_digest: context.planDigest,
      execution_graph_digest: context.executionGraphDigest,
      capability: step.capability,
      task_digest: step.taskDigest,
    };
    let failure = step.originalPolicyError;
    if (!failure) {
      try {
        const microContract = microContractForStep(step.originalWorker, context.swarmId, step.stepId, step.task);
        await sendEvent(socket, microContract);
        const signedReceipt = await executeLocalTask(socket, zone, context.originZone, step.originalWorker, step.signedTask, step.task, { swarm: swarmProof });
        microContracts.push(microContract);
        completed.set(step.stepId, signedReceipt);
        stepReceipts.push({ step_id: step.stepId, task_id: signedReceipt.task_id, receipt_digest: digestHex(signedReceipt), worker: step.originalWorker.descriptor });
        continue;
      } catch (error) {
        failure = error;
      }
    }

    if (!step.migrationWorker) throw failure;
    const microContract = microContractForStep(step.migrationWorker, context.swarmId, step.stepId, step.task);
    await sendEvent(socket, microContract);
    const signedReceipt = await executeLocalTask(socket, zone, context.originZone, step.migrationWorker, step.signedTask, step.task, { swarm: swarmProof });
    microContracts.push(microContract);
    completed.set(step.stepId, signedReceipt);
    stepReceipts.push({ step_id: step.stepId, task_id: signedReceipt.task_id, receipt_digest: digestHex(signedReceipt), worker: step.migrationWorker.descriptor });
    migrationLog.push({
      step_id: step.stepId,
      original_worker_aid: step.originalWorker.aid,
      reason: failure.message,
      migrated_to_worker_aid: step.migrationWorker.aid,
      migration_at: new Date().toISOString(),
    });
  }
  const conflictResolutions = swarmConflictResolutions(zone, context.swarmId, completed, stepReceipts, agentScores);
  for (const resolution of conflictResolutions) await sendEvent(socket, resolution);
  const closeBody = {
    swarm_id: context.swarmId,
    plan_digest: context.planDigest,
    execution_graph_digest: context.executionGraphDigest,
    step_receipts: stepReceipts,
    micro_contracts: microContracts,
    migration_log: migrationLog,
    ...(conflictResolutions.length > 0 ? { conflict_resolutions: conflictResolutions } : {}),
    ...(context.scheduler ? { scheduler: context.scheduler } : {}),
  };
  const closeProof = { ...closeBody, close_signature: signObject(zone.privateKey, closeBody) };
  await appendAudit({ kind: "fed_swarm_close", zone: zone.descriptor, close: closeProof });
  send(socket, { type: "FED_SWARM_CLOSE", swarm_id: context.swarmId, zone: zone.descriptor, close: closeProof });
}

async function serve(port, trustedZonesFile) {
  const trustedZones = await loadTrustedZones(trustedZonesFile);
  const zone = await loadOrCreateZone("zone://b", "state/keys/fed-zone-b.pkcs8");
  const worker = await loadOrCreateAgent(
    "agent://zone-b/summarizer",
    "state/keys/fed-zone-b-summarizer.pkcs8",
    { allow_network: false, approval_required: ["write"], write_prefixes: ["artifact://local/"] },
    [`fed+tcp://127.0.0.1:${port}`],
    ["summarize.text", "migration.shared"],
  );
  const semanticWorker = await loadOrCreateAgent(
    "agent://zone-b/semantic-summarize-text-fast",
    "state/keys/fed-zone-b-semantic-summarizer.pkcs8",
    { allow_network: false, approval_required: ["write"], write_prefixes: ["artifact://local/"] },
    [`fed+tcp://127.0.0.1:${port}`],
    ["summarize.text.fast", "migration.shared"],
  );
  const migrationWorker = await loadOrCreateAgent(
    "agent://zone-b/migration-summarizer",
    "state/keys/fed-zone-b-migration-summarizer.pkcs8",
    { allow_network: true, approval_required: ["write"], write_prefixes: ["artifact://local/"] },
    [`fed+tcp://127.0.0.1:${port}`],
    ["summarize.text", "migration.shared"],
  );
  const knownWorkers = [worker, semanticWorker, migrationWorker];
  const receiptCounts = new Map(await Promise.all(
    knownWorkers.map(async (knownWorker) => [knownWorker.aid, await countCompletedReceiptsFromAudit("state/audit.log", knownWorker.aid)]),
  ));
  const agentScores = new Map(knownWorkers.map((knownWorker) => {
    const capability = workerCapabilities(knownWorker)[0] ?? "";
    const counts = receiptCounts.get(knownWorker.aid);
    const match = queryMatch(zone, knownWorker, capability, "", {
      level: "L1",
      evidence: ["zone-b-local-worker"],
      completed_receipts: counts?.count ?? 0,
      last_completed_at: counts?.lastCompletedAt ?? null,
      availability_started: counts?.availabilityStarted ?? 0,
      availability_completed: counts?.availabilityCompleted ?? 0,
      availability_has_audit_data: counts?.availabilityHasAuditData === true,
    });
    return [knownWorker.aid, match?.discovery_evidence?.reputation?.agent_score ?? { total: 0 }];
  }));


  const server = net.createServer((socket) => {
    const session = serverSessionHandler(socket, trustedZones, zone);
    readFrames(socket, async (frame) => {
      try {
        if (session(frame)) return;
        if (frame.type === "FED_RESOLVE") {
          verifyTrustedZone(trustedZones, frame.origin_zone);
          if (frame.alias !== worker.alias) throw new Error(`remote alias not found: ${frame.alias}`);
          send(socket, {
            type: "FED_RESOLVE_RESULT",
            zone: zone.descriptor,
            worker: worker.descriptor,
            zone_binding: zoneBinding(zone, worker.descriptor),
          });
          send(socket, { type: "FED_RESOLVE_CLOSE", alias: frame.alias });
          return;
        }
        if (frame.type === "FED_QUERY") {
          verifyTrustedZone(trustedZones, frame.origin_zone);
          const matches = [
            queryMatch(zone, worker, frame.capability, frame.intent, {
              level: "L1",
              evidence: ["zone-b-local-worker"],
              completed_receipts: receiptCounts.get(worker.aid)?.count ?? 0,
              last_completed_at: receiptCounts.get(worker.aid)?.lastCompletedAt ?? null,
              availability_started: receiptCounts.get(worker.aid)?.availabilityStarted ?? 0,
              availability_completed: receiptCounts.get(worker.aid)?.availabilityCompleted ?? 0,
              availability_has_audit_data: receiptCounts.get(worker.aid)?.availabilityHasAuditData === true,
            }, frame.scope),
            queryMatch(zone, semanticWorker, frame.capability, frame.intent, null, frame.scope),
          ].filter(Boolean).sort((a, b) => b.ranking.score - a.ranking.score || a.worker.alias.localeCompare(b.worker.alias));
          send(socket, { type: "FED_QUERY_RESULT", zone: zone.descriptor, capability: frame.capability, matches });
          send(socket, { type: "FED_QUERY_CLOSE", capability: frame.capability });
          return;
        }
        if (frame.type === "FED_SWARM_OPEN" || frame.type === "FED_SWARM_SCHEDULE") {
          await executeSwarm(socket, trustedZones, zone, knownWorkers, frame, agentScores, frame.type === "FED_SWARM_SCHEDULE");
          return;
        }
        if (frame.type !== "FED_TASK_OPEN") throw new Error(`unsupported frame: ${frame.type}`);
        const { originZone, task } = verifyFederatedTaskOpen(frame, trustedZones, worker.descriptor);
        await executeLocalTask(socket, zone, originZone, worker, frame.task, task);
      } catch (error) {
        send(socket, { type: "FED_TASK_ERROR", error: error.message });
        socket.end();
      }
    });
  });

  server.listen(port, "127.0.0.1", () => {
    console.log(JSON.stringify({ zone: zone.zid, worker: worker.aid, listening: port }));
  });
}

async function request(port, trustedZonesFile, alias = "agent://zone-b/summarizer") {
  const trustedZones = await loadTrustedZones(trustedZonesFile);
  const zone = await loadOrCreateZone("zone://a", "state/keys/fed-zone-a.pkcs8");
  const requester = await loadOrCreateAgent("agent://zone-a/requester", "state/keys/fed-zone-a-requester.pkcs8");
  const task = {
    task_id: `fed_task_${Date.now()}`,
    from: requester.aid,
    to: alias,
    intent: "Summarize through a trusted remote Zone.",
    scope: { network: false },
    budget: { time_seconds: 30 },
  };
  const signedTask = { ...task, signature: signObject(requester.privateKey, task) };

  const socket = net.createConnection(port, "127.0.0.1");
  const events = [];
  let receipt;
  const done = new Promise((resolve, reject) => {
    socket.on("error", reject);
    const session = clientSessionHandler(socket, trustedZones, zone, () => {
      send(socket, { type: "FED_TASK_OPEN", origin_zone: zone.descriptor, requester: requester.descriptor, requester_zone_binding: zoneBinding(zone, requester.descriptor), task: signedTask });
    });
    readFrames(socket, (frame) => {
      if (session(frame)) return;
      if (frame.type === "FED_TASK_EVENT") events.push(frame.event);
      if (frame.type === "FED_RECEIPT") {
        receipt = verifyFederatedReceipt(frame, trustedZones, signedTask).signedReceipt;
      }
      if (frame.type === "FED_TASK_ERROR") reject(new Error(frame.error));
      if (frame.type === "FED_TASK_CLOSE") resolve();
    });
  });

  socket.on("connect", () => {
    send(socket, { type: "HELLO", origin_zone: zone.descriptor });
  });
  await done;
  socket.end();
  await appendAudit({ kind: "fed_remote_receipt", ...receipt });
  console.log(JSON.stringify({ zone: zone.zid, requester: requester.aid, events, receipt }, null, 2));
}

async function resolveRemote(port, trustedZonesFile, alias = "agent://zone-b/summarizer") {
  const trustedZones = await loadTrustedZones(trustedZonesFile);
  const zone = await loadOrCreateZone("zone://a", "state/keys/fed-zone-a.pkcs8");
  const socket = net.createConnection(port, "127.0.0.1");
  let result;
  const done = new Promise((resolve, reject) => {
    socket.on("error", reject);
    const session = clientSessionHandler(socket, trustedZones, zone, () => {
      send(socket, { type: "FED_RESOLVE", origin_zone: zone.descriptor, alias });
    });
    readFrames(socket, (frame) => {
      if (session(frame)) return;
      if (frame.type === "FED_RESOLVE_RESULT") {
        verifyTrustedZone(trustedZones, frame.zone);
        const resolved = resolveAgent(
          new Map([[frame.worker.alias, { descriptor: frame.worker, zone: frame.zone, zone_binding: frame.zone_binding }]]),
          frame.worker.alias,
        );
        result = { zone: frame.zone.zid, alias: frame.worker.alias, aid: resolved.descriptor.aid };
      }
      if (frame.type === "FED_TASK_ERROR") reject(new Error(frame.error));
      if (frame.type === "FED_RESOLVE_CLOSE") resolve();
    });
  });

  socket.on("connect", () => {
    send(socket, { type: "HELLO", origin_zone: zone.descriptor });
  });
  await done;
  socket.end();
  console.log(JSON.stringify(result, null, 2));
}

async function queryRemote(port, trustedZonesFile, capability = "summarize.text", print = true, intent) {
  const trustedZones = await loadTrustedZones(trustedZonesFile);
  const zone = await loadOrCreateZone("zone://a", "state/keys/fed-zone-a.pkcs8");
  const socket = net.createConnection(port, "127.0.0.1");
  let result;
  const done = new Promise((resolve, reject) => {
    socket.on("error", reject);
    const session = clientSessionHandler(socket, trustedZones, zone, () => {
      send(socket, { type: "FED_QUERY", origin_zone: zone.descriptor, capability, ...(intent ? { intent } : {}) });
    });
    readFrames(socket, (frame) => {
      if (session(frame)) return;
      if (frame.type === "FED_QUERY_RESULT") {
        const remoteZone = verifyTrustedZone(trustedZones, frame.zone);
        const matches = frame.matches.map((match) => {
          const resolved = resolveAgent(
            new Map([[match.worker.alias, { descriptor: match.worker, zone: frame.zone, zone_binding: match.zone_binding }]]),
            match.worker.alias,
          );
          const credentials = match.credentials ?? [];
          const credentialStatuses = match.credential_statuses ?? [];
          for (const credential of credentials) {
            if (!verifyCapabilityCredential(credential, frame.zone, resolved.descriptor)) {
              throw new Error(`capability credential verification failed: ${credential.capability}`);
            }
          }
          for (let index = 0; index < credentialStatuses.length; index += 1) {
            if (!verifyCredentialStatus(credentialStatuses[index], credentials[index], frame.zone)) {
              throw new Error(`credential status verification failed: ${credentials[index]?.capability}`);
            }
            if (credentialStatuses[index].status !== "active") {
              throw new Error(`credential is not active: ${credentials[index]?.capability}`);
            }
          }
          return {
            alias: resolved.descriptor.alias,
            aid: resolved.descriptor.aid,
            capabilities: resolved.descriptor.capabilities,
            credentials,
            credential_statuses: credentialStatuses,
            discovery_evidence: match.discovery_evidence,
            ranking: match.ranking,
          };
        });
        result = { zone: remoteZone.zid, capability: frame.capability, matches };
      }
      if (frame.type === "FED_TASK_ERROR") reject(new Error(frame.error));
      if (frame.type === "FED_QUERY_CLOSE") resolve();
    });
  });

  socket.on("connect", () => {
    send(socket, { type: "HELLO", origin_zone: zone.descriptor });
  });
  await done;
  socket.end();
  if (print) console.log(JSON.stringify(result, null, 2));
  return result;
}

async function auditRemote(port, trustedZonesFile, taskId) {
  if (!taskId) throw new Error("audit task_id missing");
  const trustedZones = await loadTrustedZones(trustedZonesFile);
  const zone = await loadOrCreateZone("zone://a", "state/keys/fed-zone-a.pkcs8");
  const socket = net.createConnection(port, "127.0.0.1");
  let result;
  const done = new Promise((resolve, reject) => {
    socket.on("error", reject);
    const session = clientSessionHandler(socket, trustedZones, zone, () => {
      send(socket, { type: "FED_AUDIT_QUERY", origin_zone: zone.descriptor, task_id: taskId });
    });
    readFrames(socket, (frame) => {
      if (session(frame)) return;
      if (frame.type === "FED_AUDIT_RESULT") {
        const verified = verifyFederatedReceipt({ ...frame, type: "FED_RECEIPT" }, trustedZones);
        if (verified.receipt.task_id !== taskId) throw new Error("audit receipt task mismatch");
        result = {
          zone: verified.zone.zid,
          task_id: taskId,
          worker: verified.worker,
          receipt: verified.signedReceipt,
        };
      }
      if (frame.type === "FED_TASK_ERROR") reject(new Error(frame.error));
      if (frame.type === "FED_AUDIT_CLOSE") resolve();
    });
  });

  socket.on("connect", () => {
    send(socket, { type: "HELLO", origin_zone: zone.descriptor });
  });
  await done;
  socket.end();
  console.log(JSON.stringify(result, null, 2));
}

async function requestCapability(port, trustedZonesFile, capability = "summarize.text") {
  const result = await queryRemote(port, trustedZonesFile, capability, false);
  const [match] = result.matches;
  if (!match) throw new Error(`no remote capability match: ${capability}`);
  await request(port, trustedZonesFile, match.alias);
}

async function main() {
  const [mode, portArg, trustedZonesFile, value, ...rest] = process.argv.slice(2);
  if (mode === "serve") {
    await serve(Number(portArg ?? 8990), trustedZonesFile ?? "state/trusted-zones.json");
  } else if (mode === "request") {
    await request(Number(portArg ?? 8990), trustedZonesFile ?? "state/trusted-zones.json", value);
  } else if (mode === "resolve") {
    await resolveRemote(Number(portArg ?? 8990), trustedZonesFile ?? "state/trusted-zones.json", value);
  } else if (mode === "query") {
    await queryRemote(Number(portArg ?? 8990), trustedZonesFile ?? "state/trusted-zones.json", value, true, rest.join(" ") || undefined);
  } else if (mode === "audit") {
    await auditRemote(Number(portArg ?? 8990), trustedZonesFile ?? "state/trusted-zones.json", value);
  } else if (mode === "request-capability") {
    await requestCapability(Number(portArg ?? 8990), trustedZonesFile ?? "state/trusted-zones.json", value);
  } else {
    console.error(
      "usage: node federation-gateway.mjs serve <port> <trusted-zones.json> | request <port> <trusted-zones.json> [agent://alias] | resolve <port> <trusted-zones.json> [agent://alias] | query <port> <trusted-zones.json> [capability] | audit <port> <trusted-zones.json> <task_id> | request-capability <port> <trusted-zones.json> [capability]",
    );
    process.exitCode = 2;
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
