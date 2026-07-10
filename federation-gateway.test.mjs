import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { lstat, mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import net from "node:net";
import { test } from "node:test";
import { promisify } from "node:util";
import { AUDIT_ZERO_HASH, auditEntry, canonical, createZone, loadOrCreateAgent, loadOrCreateZone, publicKeyFromDescriptor, signObject, signedReceiptDigest, swarmExecutionBinding, swarmPlan, verifyObject, verifySwarmClose, verifySwarmPlan, verifyZoneTrustDelegation, writeTrustedZones, zoneBinding, zoneRevocation, zoneTrustDelegation } from "./asp-core.mjs";
import { queryMatch } from "./federation-gateway.mjs";

const execFileAsync = promisify(execFile);
async function writeAuditLog(records) {
  await mkdir("state", { recursive: true });
  let prevHash = AUDIT_ZERO_HASH;
  const lines = records.map((record) => {
    if (typeof record === "string") return record;
    const entry = auditEntry(prevHash, record);
    prevHash = entry.hash;
    return JSON.stringify(entry);
  });
  await writeFile("state/audit.log", lines.join("\n") + "\n");
  await writeFile("state/audit.head", `${prevHash}\n`);
}

async function snapshotPersistentPath(path) {
  let info;
  try {
    info = await lstat(path);
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
  if (!info.isDirectory()) {
    return { type: "file", bytes: (await readFile(path)).toString("base64") };
  }
  const entries = {};
  for (const name of (await readdir(path)).sort()) {
    entries[name] = await snapshotPersistentPath(`${path}/${name}`);
  }
  return { type: "directory", entries };
}

async function snapshotPersistentState(paths) {
  return Object.fromEntries(await Promise.all(paths.map(async (path) => [path, await snapshotPersistentPath(path)])));
}

async function assertPersistentPathAbsent(path, message) {
  await assert.rejects(lstat(path), (error) => error.code === "ENOENT", message);
}

test("Zone trust delegation verifies authority signature and rejects tampering", () => {
  const zoneA = createZone("zone://authority-a");
  const zoneB = createZone("zone://delegate-b");
  const delegation = zoneTrustDelegation(zoneA, zoneB.descriptor, ["summarize.text"]);

  assert.equal(delegation.delegator, zoneA.zid);
  assert.equal(delegation.delegate, zoneB.zid);
  assert.deepEqual(delegation.capabilities, ["summarize.text"]);
  assert.equal(verifyZoneTrustDelegation(delegation, zoneA.descriptor), true);
  assert.equal(
    verifyZoneTrustDelegation({ ...delegation, capabilities: ["translate.text"] }, zoneA.descriptor),
    false,
  );
  assert.equal(
    verifyZoneTrustDelegation({ ...delegation, delegate: "zid:ed25519:tampered" }, zoneA.descriptor),
    false,
  );
});


function waitForGateway(child) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("gateway did not start")), 3000);
    child.stdout.on("data", (chunk) => {
      const line = chunk.toString().split("\n").find((item) => item.trim().startsWith("{"));
      if (!line) return;
      clearTimeout(timer);
      resolve(JSON.parse(line));
    });
    child.once("error", reject);
    child.once("exit", (code) => {
      if (code !== null && code !== 0) reject(new Error(`gateway exited early: ${code}`));
    });
  });
}

function exchangeRawFrame(port, frame) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(port, "127.0.0.1");
    let buffer = "";
    socket.on("error", reject);
    socket.on("connect", () => {
      socket.write(`${JSON.stringify(frame)}\n`);
    });
    socket.on("data", (chunk) => {
      buffer += chunk.toString();
      const lines = buffer.split("\n");
      buffer = lines.pop();
      for (const line of lines) {
        if (!line.trim()) continue;
        socket.end();
        resolve(JSON.parse(line));
      }
    });
  });
}

function exchangeFramesUntil(port, frame, signingZone, closeType) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(port, "127.0.0.1");
    const frames = [];
    let buffer = "";
    socket.on("error", reject);
    socket.on("connect", () => {
      socket.write(`${JSON.stringify({ type: "HELLO", origin_zone: frame.origin_zone })}\n`);
    });
    socket.on("data", (chunk) => {
      buffer += chunk.toString();
      const lines = buffer.split("\n");
      buffer = lines.pop();
      for (const line of lines) {
        if (!line.trim()) continue;
        const parsed = JSON.parse(line);
        if (parsed.type === "HELLO") {
          const authBody = { session_id: parsed.session_id, challenge: parsed.challenge, peer_zid: frame.origin_zone.zid, remote_zid: parsed.zone.zid };
          socket.write(`${JSON.stringify({ type: "AUTH", origin_zone: frame.origin_zone, auth: { ...authBody, auth_signature: signObject(signingZone.privateKey, authBody) } })}\n`);
          continue;
        }
        if (parsed.type === "AUTH_OK") {
          socket.write(`${JSON.stringify(frame)}\n`);
          continue;
        }
        frames.push(parsed);
        if (parsed.type === closeType || parsed.type === "FED_TASK_ERROR") {
          socket.end();
          resolve(frames);
        }
      }
    });
  });
}
function swarmCapabilityForTask(task) {
  return task?.to?.includes("translator") ? "translate.text" : "summarize.text";
}

function withSwarmExecutionBinding(coordinator, frame, { plan = null } = {}) {
  const executableSteps = frame.swarm.steps.map((step) => ({ step_id: step.step_id, depends_on: step.after ?? [], task: step.task }));
  const planFrame = plan ?? swarmPlan(
    coordinator,
    frame.swarm.swarm_id,
    `Execute ${frame.swarm.swarm_id}.`,
    frame.swarm.steps.map((step) => ({ step_id: step.step_id, capability: swarmCapabilityForTask(step.task), depends_on: step.after ?? [] })),
    "c".repeat(64),
  );
  return {
    ...frame,
    swarm: {
      swarm_id: frame.swarm.swarm_id,
      plan: planFrame,
      execution_binding: swarmExecutionBinding(coordinator, planFrame, executableSteps),
      steps: frame.swarm.steps,
    },
  };
}

function withManuallySignedSwarmExecutionBinding(coordinator, frame) {
  const planSteps = frame.swarm.steps.map((step) => ({ step_id: step.step_id, capability: swarmCapabilityForTask(step.task), depends_on: step.after ?? [] }));
  const plan = swarmPlan(coordinator, frame.swarm.swarm_id, `Reject ${frame.swarm.swarm_id}.`, planSteps, "d".repeat(64));
  const steps = frame.swarm.steps.map((step) => ({
    step_id: step.step_id,
    depends_on: step.after ?? [],
    capability: swarmCapabilityForTask(step.task),
    task_digest: createHash("sha256").update(canonical(step.task)).digest("hex"),
  }));
  const body = {
    format: "asp-swarm-execution-binding/v1",
    swarm_id: frame.swarm.swarm_id,
    plan_digest: plan.plan.plan_digest,
    steps,
    execution_graph_digest: createHash("sha256").update(canonical({ swarm_id: frame.swarm.swarm_id, plan_digest: plan.plan.plan_digest, steps })).digest("hex"),
  };
  return {
    ...frame,
    swarm: { swarm_id: frame.swarm.swarm_id, plan, execution_binding: { ...body, binding_signature: signObject(coordinator.privateKey, body) }, steps: frame.swarm.steps },
  };
}


test("Federation Gateway queryMatch scores only active credentials", async () => {
  const zone = await loadOrCreateZone("zone://query-match-zone", "state/keys/query-match-zone.pkcs8");
  const worker = await loadOrCreateAgent("agent://query-match/summarizer", "state/keys/query-match-summarizer.pkcs8", {}, ["asp+local://demo"], ["summarize.text"]);
  const futureMatch = queryMatch(zone, worker, "summarize.text", "", {
    evidence: ["local-demo"],
    completed_receipts: 0,
    valid_until: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
  });
  const pastMatch = queryMatch(zone, worker, "summarize.text", "", {
    evidence: ["local-demo"],
    completed_receipts: 0,
    valid_until: new Date(Date.now() - 60 * 60 * 1000).toISOString(),
  });
  const invalidMatch = queryMatch(zone, worker, "summarize.text", "", {
    evidence: ["local-demo"],
    completed_receipts: 0,
    valid_until: "tomorrow",
  });
  const revokedMatch = queryMatch({ ...zone, revocations: [zoneRevocation(zone, worker.aid, "test")] }, worker, "summarize.text", "", {
    evidence: ["local-demo"],
    completed_receipts: 0,
    valid_until: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
  });

  assert.deepEqual(futureMatch.discovery_evidence.credential, { trusted: true, active: true });
  assert.equal(futureMatch.ranking.score, 108);
  assert.ok(futureMatch.ranking.reasons.includes("credential_active"));
  assert.deepEqual(pastMatch.discovery_evidence.credential, { trusted: true, active: false });
  assert.equal(pastMatch.ranking.score, 73);
  assert.equal(pastMatch.ranking.reasons.includes("credential_active"), false);
  assert.deepEqual(invalidMatch.discovery_evidence.credential, { trusted: true, active: false });
  assert.equal(invalidMatch.ranking.score, 73);
  assert.equal(invalidMatch.ranking.reasons.includes("credential_active"), false);
  assert.deepEqual(revokedMatch.discovery_evidence.credential, { trusted: true, active: false });
  assert.equal(revokedMatch.ranking.score, 70);
  assert.equal(revokedMatch.ranking.reasons.includes("credential_active"), false);
});

test("Federation Gateway queryMatch exposes multi-signal agent reputation score", async () => {
  const zone = await loadOrCreateZone("zone://query-match-agent-score-zone", "state/keys/query-match-agent-score-zone.pkcs8");
  const worker = await loadOrCreateAgent("agent://query-match/agent-score-summarizer", "state/keys/query-match-agent-score-summarizer.pkcs8", {}, ["asp+local://demo"], ["summarize.text"]);
  const lastCompletedAt = new Date(Date.now() - 30 * 60 * 1000).toISOString();

  const match = queryMatch(zone, worker, "summarize.text", "", {
    evidence: ["local-demo"],
    completed_receipts: 5,
    last_completed_at: lastCompletedAt,
    valid_until: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
  });

  const reputation = match.discovery_evidence.reputation;
  assert.equal(reputation.completed_receipts, 5);
  assert.equal(reputation.revocation_count, 0);
  assert.ok(reputation.agent_score, "expected reputation.agent_score to be exposed");
  assert.equal(reputation.agent_score.receipt_score, 10);
  assert.equal(reputation.agent_score.credential_score, 30);
  assert.equal(reputation.agent_score.freshness_score, 10);
  assert.equal(reputation.agent_score.cost_score, 5);
  assert.equal(reputation.agent_score.latency_score, 5);
  assert.equal(reputation.agent_score.availability_score, 5);
  assert.equal(reputation.agent_score.policy_match, 5);
  assert.equal(reputation.agent_score.risk_match, 10);
  assert.equal(reputation.agent_score.revocation_penalty, 0);
  assert.equal(reputation.agent_score.total, 80);
  assert.ok(reputation.agent_score.total > 0);
  assert.equal(reputation.last_completed_at, lastCompletedAt);
  assert.equal(
    reputation.agent_score.total,
    reputation.agent_score.receipt_score + reputation.agent_score.credential_score + reputation.agent_score.freshness_score + reputation.agent_score.cost_score + reputation.agent_score.latency_score + reputation.agent_score.availability_score + reputation.agent_score.policy_match + reputation.agent_score.risk_match - reputation.agent_score.revocation_penalty,
  );
  assert.equal(match.ranking.score, reputation.agent_score.total + 50);
});

test("Federation Gateway queryMatch exposes v14.2 routing evidence signals", async () => {
  const zone = await loadOrCreateZone("zone://query-match-routing-zone", "state/keys/query-match-routing-zone.pkcs8");
  const worker = await loadOrCreateAgent(
    "agent://query-match/routing-summarizer",
    "state/keys/query-match-routing-summarizer.pkcs8",
    { cost_tokens_per_task: 1 },
    ["asp+local://demo"],
    ["summarize.text"],
  );

  const match = queryMatch(zone, worker, "summarize.text", "", {
    evidence: ["local-demo"],
    completed_receipts: 1,
    valid_until: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
  });

  const routing = match.discovery_evidence.routing;
  assert.deepEqual(
    {
      cost_score: Number.isFinite(routing?.cost_score),
      latency_score: Number.isFinite(routing?.latency_score),
      availability_score: Number.isFinite(routing?.availability_score),
      signals_used: Number.isSafeInteger(routing?.signals_used) && routing.signals_used > 0,
    },
    {
      cost_score: true,
      latency_score: true,
      availability_score: true,
      signals_used: true,
    },
  );
});

test("Federation Gateway queryMatch exposes v14.7 policy and risk routing signals", async () => {
  const zone = await loadOrCreateZone("zone://query-match-policy-risk-zone", "state/keys/query-match-policy-risk-zone.pkcs8");
  const worker = await loadOrCreateAgent(
    "agent://query-match/policy-risk-summarizer",
    "state/keys/query-match-policy-risk-summarizer.pkcs8",
    { allow_network: false, write_prefixes: ["artifact://local/"] },
    ["asp+local://demo"],
    ["summarize.text"],
  );
  const credentialClaims = {
    evidence: ["local-demo"],
    completed_receipts: 3,
    valid_until: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
  };
  const taskScope = { network: false, write: ["artifact://local/result.md"] };

  const match = queryMatch(zone, worker, "summarize.text", "", credentialClaims, taskScope);
  const networkDeniedMatch = queryMatch(zone, worker, "summarize.text", "", credentialClaims, { ...taskScope, network: true });
  const revokedMatch = queryMatch({ ...zone, revocations: [zoneRevocation(zone, worker.aid, "policy risk regression")] }, worker, "summarize.text", "", credentialClaims, taskScope);

  assert.equal(match.discovery_evidence.routing.policy_match, 10);
  assert.equal(match.discovery_evidence.routing.risk_match, 10);
  assert.equal(match.discovery_evidence.routing.signals_used, 2);
  assert.equal(match.discovery_evidence.reputation.agent_score.policy_match, 10);
  assert.equal(match.discovery_evidence.reputation.agent_score.risk_match, 10);
  assert.ok(match.ranking.reasons.includes("policy_match"));
  assert.ok(match.ranking.reasons.includes("risk_match"));

  assert.equal(networkDeniedMatch.discovery_evidence.routing.policy_match, 0);
  assert.ok(networkDeniedMatch.ranking.score < match.ranking.score);
  assert.equal(networkDeniedMatch.ranking.reasons.includes("policy_match"), false);

  assert.ok(revokedMatch.discovery_evidence.routing.risk_match < match.discovery_evidence.routing.risk_match);
  assert.equal(revokedMatch.ranking.reasons.includes("risk_match"), false);
});

test("Federation Gateway queryMatch ranks lower-cost workers above equivalent neutral-cost workers", async () => {
  const zone = await loadOrCreateZone("zone://query-match-cost-ranking-zone", "state/keys/query-match-cost-ranking-zone.pkcs8");
  const lowCostWorker = await loadOrCreateAgent(
    "agent://query-match/low-cost-summarizer",
    "state/keys/query-match-low-cost-summarizer.pkcs8",
    { cost_tokens_per_task: 1 },
    ["asp+local://demo"],
    ["summarize.text"],
  );
  const neutralCostWorker = await loadOrCreateAgent(
    "agent://query-match/neutral-cost-summarizer",
    "state/keys/query-match-neutral-cost-summarizer.pkcs8",
    {},
    ["asp+local://demo"],
    ["summarize.text"],
  );
  const credentialClaims = {
    evidence: ["local-demo"],
    completed_receipts: 1,
    valid_until: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
  };

  const lowCostMatch = queryMatch(zone, lowCostWorker, "summarize.text", "", credentialClaims);
  const neutralCostMatch = queryMatch(zone, neutralCostWorker, "summarize.text", "", credentialClaims);

  assert.ok(
    lowCostMatch.ranking.score > neutralCostMatch.ranking.score,
    `expected low-cost worker to outrank neutral-cost worker; got ${lowCostMatch.ranking.score} <= ${neutralCostMatch.ranking.score}`,
  );
});

test("Federation Gateway queryMatch applies matching zone revocations as an agent score penalty", async () => {
  const zone = await loadOrCreateZone("zone://query-match-agent-score-revocation-zone", "state/keys/query-match-agent-score-revocation-zone.pkcs8");
  const worker = await loadOrCreateAgent("agent://query-match/agent-score-revoked-summarizer", "state/keys/query-match-agent-score-revoked-summarizer.pkcs8", {}, ["asp+local://demo"], ["summarize.text"]);
  const lastCompletedAt = new Date(Date.now() - 30 * 60 * 1000).toISOString();
  const credentialClaims = {
    evidence: ["local-demo"],
    completed_receipts: 5,
    last_completed_at: lastCompletedAt,
    valid_until: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
  };

  const cleanMatch = queryMatch(zone, worker, "summarize.text", "", credentialClaims);
  const revokedMatch = queryMatch({ ...zone, revocations: [zoneRevocation(zone, worker.aid, "agent score regression")] }, worker, "summarize.text", "", credentialClaims);

  const cleanScore = cleanMatch.discovery_evidence.reputation.agent_score;
  const revokedReputation = revokedMatch.discovery_evidence.reputation;
  const revokedScore = revokedReputation.agent_score;

  assert.equal(revokedReputation.completed_receipts, 5);
  assert.equal(revokedReputation.revocation_count, 1);
  assert.ok(revokedScore, "expected revoked reputation.agent_score to be exposed");
  assert.equal(revokedScore.receipt_score, 10);
  assert.equal(revokedScore.credential_score, 0);
  assert.equal(revokedScore.freshness_score, 10);
  assert.equal(revokedScore.revocation_penalty, 10);
  assert.equal(revokedReputation.last_completed_at, lastCompletedAt);
  assert.equal(revokedScore.total, revokedScore.receipt_score + revokedScore.credential_score + revokedScore.freshness_score + revokedScore.cost_score + revokedScore.latency_score + revokedScore.availability_score + revokedScore.policy_match + revokedScore.risk_match - revokedScore.revocation_penalty);
  assert.ok(revokedScore.revocation_penalty > 0);
  assert.ok(revokedScore.total < cleanScore.total);
  assert.equal(revokedMatch.ranking.score, revokedScore.total + 50);
});

test("Federation Gateway completes a cross-Zone task", async () => {
  const port = 8991;
  const zoneA = await loadOrCreateZone("zone://a", "state/keys/fed-zone-a.pkcs8");
  const zoneB = await loadOrCreateZone("zone://b", "state/keys/fed-zone-b.pkcs8");
  await writeTrustedZones("state/zone-a-trust.json", [zoneB, zoneA]);
  await writeTrustedZones("state/zone-b-trust.json", [zoneA]);

  const gateway = spawn(process.execPath, ["federation-gateway.mjs", "serve", String(port), "state/zone-b-trust.json"], {
    cwd: process.cwd(),
    stdio: ["ignore", "pipe", "pipe"],
  });

  try {
    const started = await waitForGateway(gateway);
    assert.equal(started.zone, zoneB.zid);

    const { stdout } = await execFileAsync(process.execPath, [
      "federation-gateway.mjs",
      "request",
      String(port),
      "state/zone-a-trust.json",
    ]);
    const result = JSON.parse(stdout);

    assert.equal(result.zone, zoneA.zid);
    assert.equal(result.receipt.origin_zone, zoneA.zid);
    assert.equal(result.receipt.executing_zone, zoneB.zid);
    assert.equal(result.events.at(-1).type, "task.completed");
    assert.equal(result.receipt.event_count, result.events.length);
  } finally {
    gateway.kill("SIGINT");
  }
});

test("rejects unsigned or substituted executable Swarm before execution", async (t) => {
  const port = 9032;
  const zoneA = await loadOrCreateZone("zone://a", "state/keys/fed-zone-a.pkcs8");
  const requester = await loadOrCreateAgent("agent://zone-a/requester", "state/keys/fed-zone-a-requester.pkcs8");
  await writeTrustedZones("state/zone-b-u2-preflight-trust.json", [zoneA]);
  const gateway = spawn(process.execPath, ["federation-gateway.mjs", "serve", String(port), "state/zone-b-u2-preflight-trust.json"], {
    cwd: process.cwd(),
    stdio: ["ignore", "pipe", "pipe"],
  });

  const runId = `${process.pid}_${Date.now()}`;
  const persistentPaths = ["state/audit.log", "state/audit.head", "state/audit-tasks", "artifacts"];
  const buildFrame = ({ name, type = "FED_SWARM_OPEN", definitions }) => {
    const swarmId = `swarm://local/node-u2-${runId}-${name}`;
    const steps = definitions.map(({ stepId, after = [], capability = "summarize.text", to = "agent://zone-b/summarizer", network = false }) => {
      const task = {
        task_id: `node_u2_${runId}_${name}_${stepId}`,
        from: requester.aid,
        to,
        intent: `Execute ${name} ${stepId}.`,
        scope: { network },
        budget: { time_seconds: 30 },
      };
      return { step_id: stepId, ...(after.length > 0 ? { after } : {}), capability, task: { ...task, signature: signObject(requester.privateKey, task) } };
    });
    const planSteps = steps.map((step) => ({ step_id: step.step_id, capability: step.capability, depends_on: step.after ?? [] }));
    const plan = swarmPlan(zoneA, swarmId, `U2 ${name}.`, planSteps, "a".repeat(64));
    const executableSteps = steps.map(({ step_id, after = [], task }) => ({ step_id, depends_on: after, task }));
    const executionBinding = swarmExecutionBinding(zoneA, plan, executableSteps);
    return {
      type,
      origin_zone: zoneA.descriptor,
      requester: requester.descriptor,
      requester_zone_binding: zoneBinding(zoneA, requester.descriptor),
      swarm: { swarm_id: swarmId, plan, execution_binding: executionBinding, steps: steps.map(({ capability: _capability, ...step }) => step) },
    };
  };

  const cases = [];
  const missingPlan = buildFrame({ name: "missing-plan", definitions: [{ stepId: "only" }] });
  delete missingPlan.swarm.plan;
  cases.push({ name: "missing FED_SWARM_PLAN", frame: missingPlan, error: /swarm plan missing/ });

  const missingBinding = buildFrame({ name: "missing-binding", definitions: [{ stepId: "only" }] });
  delete missingBinding.swarm.execution_binding;
  cases.push({ name: "missing execution binding", frame: missingBinding, error: /execution binding missing/ });

  const strippedFormat = buildFrame({ name: "stripped-format", definitions: [{ stepId: "only" }] });
  delete strippedFormat.swarm.execution_binding.format;
  cases.push({ name: "stripped execution binding format", frame: strippedFormat, error: /execution binding fields invalid/ });

  const changedTask = buildFrame({ name: "changed-task", definitions: [{ stepId: "only" }] });
  const changedTaskBody = { ...changedTask.swarm.steps[0].task, intent: "Substituted after binding." };
  delete changedTaskBody.signature;
  changedTask.swarm.steps[0].task = { ...changedTaskBody, signature: signObject(requester.privateKey, changedTaskBody) };
  cases.push({ name: "changed signed task", frame: changedTask, error: /execution binding task_digest mismatch/ });

  const reordered = buildFrame({ name: "reordered", type: "FED_SWARM_SCHEDULE", definitions: [{ stepId: "first" }, { stepId: "second" }] });
  reordered.swarm.steps.reverse();
  cases.push({ name: "reordered schedule input", frame: reordered, error: /execution binding executable step order mismatch/ });

  const reconnected = buildFrame({ name: "reconnected", definitions: [{ stepId: "first" }, { stepId: "second", after: ["first"] }] });
  delete reconnected.swarm.steps[1].after;
  cases.push({ name: "dependency reconnection", frame: reconnected, error: /execution binding executable depends_on mismatch/ });

  const substitutedCapability = buildFrame({ name: "capability", definitions: [{ stepId: "only", capability: "translate.text" }] });
  cases.push({ name: "capability substitution", frame: substitutedCapability, error: /execution binding worker capability missing/ });
  const migratedCapability = buildFrame({
    name: "migrated-capability",
    definitions: [{ stepId: "only", capability: "summarize.text.fast", to: "agent://zone-b/semantic-summarize-text-fast" }],
  });
  cases.push({ name: "migrated worker lacks exact signed capability", frame: migratedCapability, error: /execution binding migration worker capability missing/ });
  const substitutedMigrationPolicy = buildFrame({ name: "migration-policy", definitions: [{ stepId: "only", to: "agent://zone-b/migration-summarizer", network: true }] });
  cases.push({ name: "migration worker policy substitution", frame: substitutedMigrationPolicy, error: /policy denied network access/ });

  const substitutedTerminal = buildFrame({ name: "terminal", definitions: [{ stepId: "terminal" }] });
  substitutedTerminal.swarm.steps[0].step_id = "replacement";
  cases.push({ name: "terminal-step substitution", frame: substitutedTerminal, error: /execution binding executable step order mismatch/ });

  const invalidGraph = buildFrame({ name: "invalid-graph", type: "FED_SWARM_SCHEDULE", definitions: [{ stepId: "only", after: ["missing"] }] });
  cases.push({ name: "graph preflight rejection", frame: invalidGraph, error: /swarm schedule dependency unresolved/ });
  const invalidOpenGraph = buildFrame({ name: "invalid-open-graph", definitions: [{ stepId: "first" }, { stepId: "second", after: ["missing"] }] });
  cases.push({ name: "open graph preflight rejection", frame: invalidOpenGraph, error: /swarm dependency not completed: missing/ });

  try {
    await waitForGateway(gateway);
    for (const candidate of cases) {
      await t.test(candidate.name, async () => {
        const taskIds = candidate.frame.swarm.steps.map((step) => step.task.task_id);
        const persistentBefore = await snapshotPersistentState(persistentPaths);
        const frames = await exchangeFramesUntil(port, candidate.frame, zoneA, "FED_SWARM_CLOSE");
        const effects = {
          emitted_task_events: frames.filter((frame) => frame.type === "FED_TASK_EVENT").length,
          emitted_artifacts: frames.filter((frame) => frame.type === "FED_TASK_EVENT" && frame.event?.type === "artifact.created").length,
          emitted_receipts: frames.filter((frame) => frame.type === "FED_RECEIPT").length,
          emitted_closes: frames.filter((frame) => frame.type === "FED_TASK_CLOSE" || frame.type === "FED_SWARM_CLOSE").length,
        };
        assert.deepEqual(effects, { emitted_task_events: 0, emitted_artifacts: 0, emitted_receipts: 0, emitted_closes: 0 }, `${candidate.name}: ${JSON.stringify(effects)}`);
        assert.deepEqual(frames.map((frame) => frame.type), ["FED_TASK_ERROR"], candidate.name);
        assert.match(frames[0].error, candidate.error, candidate.name);
        const persistentAfter = await snapshotPersistentState(persistentPaths);
        assert.deepEqual(persistentAfter, persistentBefore, `${candidate.name}: persistent state changed`);
        for (const taskId of taskIds) {
          await assertPersistentPathAbsent(`state/audit-tasks/${encodeURIComponent(taskId)}.json`, `${candidate.name}: task state persisted for ${taskId}`);
          await assertPersistentPathAbsent(`artifacts/${taskId}`, `${candidate.name}: artifact path persisted for ${taskId}`);
        }
      });
    }
    await t.test("propagates verified plan and graph digests", async () => {
      const valid = buildFrame({ name: "valid", definitions: [{ stepId: "first" }, { stepId: "second", after: ["first"] }] });
      const frames = await exchangeFramesUntil(port, valid, zoneA, "FED_SWARM_CLOSE");
      const close = frames.at(-1).close;
      assert.equal(close.plan_digest, valid.swarm.plan.plan.plan_digest);
      assert.equal(close.execution_graph_digest, valid.swarm.execution_binding.execution_graph_digest);
      for (const receipt of frames.filter((frame) => frame.type === "FED_RECEIPT").map((frame) => frame.receipt)) {
        assert.equal(receipt.swarm.plan_digest, close.plan_digest);
        assert.equal(receipt.swarm.execution_graph_digest, close.execution_graph_digest);
      }
    });
  } finally {
    gateway.kill("SIGINT");
  }
});

test("derives final_output only from one terminal result in gateway v2 close", async () => {
  const port = 9034;
  const zoneA = await loadOrCreateZone("zone://a", "state/keys/fed-zone-a.pkcs8");
  const zoneB = await loadOrCreateZone("zone://b", "state/keys/fed-zone-b.pkcs8");
  const requester = await loadOrCreateAgent("agent://zone-a/requester", "state/keys/fed-zone-a-requester.pkcs8");
  await writeTrustedZones("state/zone-b-u3-final-output-trust.json", [zoneA]);
  const gateway = spawn(process.execPath, ["federation-gateway.mjs", "serve", String(port), "state/zone-b-u3-final-output-trust.json"], {
    cwd: process.cwd(),
    stdio: ["ignore", "pipe", "pipe"],
  });

  try {
    await waitForGateway(gateway);
    const taskFor = (taskId, intent) => {
      const body = {
        task_id: taskId,
        from: requester.aid,
        to: "agent://zone-b/summarizer",
        intent,
        scope: { network: false },
        budget: { time_seconds: 30 },
      };
      return { ...body, signature: signObject(requester.privateKey, body) };
    };
    const frame = withSwarmExecutionBinding(zoneA, {
      type: "FED_SWARM_SCHEDULE",
      origin_zone: zoneA.descriptor,
      requester: requester.descriptor,
      requester_zone_binding: zoneBinding(zoneA, requester.descriptor),
      swarm: {
        swarm_id: "swarm://local/node_u3_final_output",
        steps: [
          { step_id: "final", after: ["draft"], task: taskFor("node_u3_final", "Produce the terminal result.") },
          { step_id: "draft", task: taskFor("node_u3_draft", "Produce the dependency result.") },
        ],
      },
    });
    const frames = await exchangeFramesUntil(port, frame, zoneA, "FED_SWARM_CLOSE");
    assert.notEqual(frames.at(-1).type, "FED_TASK_ERROR", frames.at(-1).error);
    const receiptFrames = frames.filter((candidate) => candidate.type === "FED_RECEIPT");
    assert.deepEqual(receiptFrames.map((candidate) => candidate.receipt.swarm.step_id), ["draft", "final"]);
    const receipts = new Map(receiptFrames.map((candidate) => [candidate.receipt.swarm.step_id, candidate.receipt]));
    for (const receipt of receipts.values()) {
      assert.deepEqual(receipt.result_artifact, {
        uri: receipt.artifact_manifests[0].uri,
        sha256: receipt.artifact_manifests[0].sha256,
        manifest_hash: receipt.artifact_manifests[0].manifest_hash,
      });
    }

    const closeFrame = frames.at(-1);
    const close = closeFrame.close;
    assert.equal(close.format, "asp-swarm-close/v2");
    assert.equal(close.plan_digest, frame.swarm.plan.plan.plan_digest);
    assert.equal(close.execution_graph_digest, frame.swarm.execution_binding.execution_graph_digest);
    assert.deepEqual(close.step_receipts.map((step) => step.step_id), ["final", "draft"]);
    assert.deepEqual(close.scheduler.step_order, ["draft", "final"]);
    for (const step of close.step_receipts) {
      assert.equal(step.signed_receipt_digest, signedReceiptDigest(receipts.get(step.step_id)));
      assert.equal(step.receipt_digest, undefined);
    }
    const finalReceipt = receipts.get("final");
    assert.deepEqual(close.final_output, {
      step_id: "final",
      task_id: finalReceipt.task_id,
      signed_receipt_digest: signedReceiptDigest(finalReceipt),
      artifact: finalReceipt.result_artifact,
      selection_rule: "single-terminal-result",
    });
    const verified = verifySwarmClose(closeFrame, new Map([[zoneB.zid, zoneB.descriptor]]));
    assert.equal(verified.closeDigest, createHash("sha256").update(canonical(close)).digest("hex"));

    const resigned = (mutate) => {
      const candidate = structuredClone(closeFrame);
      const { close_signature: _signature, ...body } = candidate.close;
      mutate(body);
      candidate.close = { ...body, close_signature: signObject(zoneB.privateKey, body) };
      return candidate;
    };
    assert.throws(() => verifySwarmClose(resigned((body) => delete body.format), new Map([[zoneB.zid, zoneB.descriptor]])), /swarm close format missing/);
    assert.throws(() => verifySwarmClose(resigned((body) => delete body.execution_graph_digest), new Map([[zoneB.zid, zoneB.descriptor]])), /swarm close v2 fields invalid/);
    assert.throws(() => verifySwarmClose(resigned((body) => { body.unexpected = true; }), new Map([[zoneB.zid, zoneB.descriptor]])), /swarm close v2 fields invalid/);
    assert.throws(() => verifySwarmClose(resigned((body) => { body.final_output.unexpected = true; }), new Map([[zoneB.zid, zoneB.descriptor]])), /swarm close final output fields invalid/);
    assert.throws(() => verifySwarmClose(resigned((body) => { body.final_output.artifact.unexpected = true; }), new Map([[zoneB.zid, zoneB.descriptor]])), /swarm close final output artifact fields invalid/);
    assert.throws(() => verifySwarmClose(resigned((body) => { body.final_output.signed_receipt_digest = "8".repeat(64); }), new Map([[zoneB.zid, zoneB.descriptor]])), /swarm close final output receipt digest mismatch/);
    assert.throws(() => verifySwarmClose(resigned((body) => { body.format = "asp-swarm-close/v1"; }), new Map([[zoneB.zid, zoneB.descriptor]])), /swarm close v1 fields invalid/);
  } finally {
    gateway.kill("SIGINT");
  }
});

test("Swarm decomposition plan verifies and links to close plan digest", async () => {
  const port = 9021;
  const zoneA = await loadOrCreateZone("zone://a", "state/keys/fed-zone-a.pkcs8");
  const zoneB = await loadOrCreateZone("zone://b", "state/keys/fed-zone-b.pkcs8");
  const requester = await loadOrCreateAgent("agent://zone-a/requester", "state/keys/fed-zone-a-requester.pkcs8");
  await writeTrustedZones("state/fed-trusted-zones.json", [zoneA]);
  const child = spawn(process.execPath, ["federation-gateway.mjs", "serve", String(port), "state/fed-trusted-zones.json"], { stdio: ["ignore", "pipe", "inherit"] });
  try {
    await waitForGateway(child);
    const steps = [
      { step_id: "1", capability: "summarize.text", constraint: { max_tokens: 500 }, depends_on: [] },
      { step_id: "2", capability: "summarize.text", constraint: { max_tokens: 250 }, depends_on: ["1"] },
    ];
    const planFrame = swarmPlan(zoneA, "swarm://local/node_swarm_plan", "Summarize text then produce a shorter follow-up.", steps, "a".repeat(64));
    assert.equal(planFrame.type, "FED_SWARM_PLAN");
    assert.equal(verifySwarmPlan(planFrame, new Map([[zoneA.zid, zoneA.descriptor]])).plan.plan_digest, planFrame.plan.plan_digest);

    const tamperedSignature = structuredClone(planFrame);
    tamperedSignature.plan.plan_signature = "bad";
    assert.throws(
      () => verifySwarmPlan(tamperedSignature, new Map([[zoneA.zid, zoneA.descriptor]])),
      /swarm plan signature verification failed/,
    );

    const emptySteps = structuredClone(planFrame);
    emptySteps.plan.steps = [];
    assert.throws(
      () => verifySwarmPlan(emptySteps, new Map([[zoneA.zid, zoneA.descriptor]])),
      /swarm plan steps missing/,
    );

    const nulStep = structuredClone(planFrame);
    nulStep.plan.steps[0].step_id = "bad\0step";
    assert.throws(
      () => verifySwarmPlan(nulStep, new Map([[zoneA.zid, zoneA.descriptor]])),
      /swarm plan step invalid/,
    );

    const summaryTask = {
      task_id: "node_swarm_plan_summary",
      from: requester.aid,
      to: "agent://zone-b/summarizer",
      intent: "Summarize after a signed Swarm plan.",
      scope: { network: false },
      budget: { time_seconds: 30 },
    };
    const followupTask = {
      task_id: "node_swarm_plan_followup",
      from: requester.aid,
      to: "agent://zone-b/summarizer",
      intent: "Use the planned dependency artifact.",
      scope: { network: false },
      budget: { time_seconds: 30 },
    };
    const frames = await exchangeFramesUntil(port, withSwarmExecutionBinding(zoneA, {
      type: "FED_SWARM_OPEN",
      origin_zone: zoneA.descriptor,
      requester: requester.descriptor,
      requester_zone_binding: zoneBinding(zoneA, requester.descriptor),
      swarm: {
        swarm_id: "swarm://local/node_swarm_plan",
        steps: [
          { step_id: "1", task: { ...summaryTask, signature: signObject(requester.privateKey, summaryTask) } },
          { step_id: "2", after: ["1"], task: { ...followupTask, signature: signObject(requester.privateKey, followupTask) } },
        ],
      },
    }, { plan: planFrame }), zoneA, "FED_SWARM_CLOSE");
    assert.notEqual(frames.at(-1).type, "FED_TASK_ERROR", frames.at(-1).error);

    const closeFrame = frames.at(-1);
    assert.equal(closeFrame.close.plan_digest, planFrame.plan.plan_digest);
    assert.equal(closeFrame.close.scheduler, undefined);
    assert.equal(verifySwarmClose(closeFrame, new Map([[zoneB.zid, zoneB.descriptor]])).close.plan_digest, planFrame.plan.plan_digest);

    const malformedPlanDigest = structuredClone(closeFrame);
    malformedPlanDigest.close.plan_digest = "not-hex";
    const { close_signature, ...malformedCloseBody } = malformedPlanDigest.close;
    malformedPlanDigest.close.close_signature = signObject(zoneB.privateKey, malformedCloseBody);
    assert.throws(
      () => verifySwarmClose(malformedPlanDigest, new Map([[zoneB.zid, zoneB.descriptor]])),
      /swarm close plan digest invalid/,
    );
  } finally {
    child.kill();
  }
});

test("Federation Gateway schedules out-of-order Swarm steps in deterministic ready-DAG order", async () => {
  const port = 9023;
  const zoneA = await loadOrCreateZone("zone://a", "state/keys/fed-zone-a.pkcs8");
  const zoneB = await loadOrCreateZone("zone://b", "state/keys/fed-zone-b.pkcs8");
  const requester = await loadOrCreateAgent("agent://zone-a/requester", "state/keys/fed-zone-a-requester.pkcs8");
  await writeTrustedZones("state/zone-b-schedule-trust.json", [zoneA]);
  const child = spawn(process.execPath, ["federation-gateway.mjs", "serve", String(port), "state/zone-b-schedule-trust.json"], { stdio: ["ignore", "pipe", "inherit"] });
  try {
    await waitForGateway(child);
    const prefaceTask = {
      task_id: "node_swarm_scheduled_preface",
      from: requester.aid,
      to: "agent://zone-b/summarizer",
      intent: "Run first among simultaneously ready roots by original input order.",
      scope: { network: false },
      budget: { time_seconds: 30 },
    };
    const summaryTask = {
      task_id: "node_swarm_scheduled_summary",
      from: requester.aid,
      to: "agent://zone-b/summarizer",
      intent: "Summarize as the scheduler-ready Swarm DAG step.",
      scope: { network: false },
      budget: { time_seconds: 30 },
    };
    const followupTask = {
      task_id: "node_swarm_scheduled_followup",
      from: requester.aid,
      to: "agent://zone-b/summarizer",
      intent: "Use the summary after the scheduler resolves the dependency.",
      scope: { network: false },
      budget: { time_seconds: 30 },
    };
    const frames = await exchangeFramesUntil(port, withSwarmExecutionBinding(zoneA, {
      type: "FED_SWARM_SCHEDULE",
      origin_zone: zoneA.descriptor,
      requester: requester.descriptor,
      requester_zone_binding: zoneBinding(zoneA, requester.descriptor),
      swarm: {
        swarm_id: "swarm://local/node_ready_dag",
        steps: [
          { step_id: "preface", task: { ...prefaceTask, signature: signObject(requester.privateKey, prefaceTask) } },
          { step_id: "followup", after: ["preface", "summary"], task: { ...followupTask, signature: signObject(requester.privateKey, followupTask) } },
          { step_id: "summary", task: { ...summaryTask, signature: signObject(requester.privateKey, summaryTask) } },
        ],
      },
    }), zoneA, "FED_SWARM_CLOSE");

    assert.notEqual(frames.at(-1).type, "FED_TASK_ERROR", frames.at(-1).error);
    assert.deepEqual(frames.filter((frame) => frame.type === "FED_RECEIPT").map((frame) => frame.receipt.swarm.step_id), ["preface", "summary", "followup"]);
    const closeFrame = frames.at(-1);
    assert.deepEqual(closeFrame.close.scheduler, { mode: "ready-dag", step_order: ["preface", "summary", "followup"] });
    assert.deepEqual(closeFrame.close.step_receipts.map((step) => step.step_id), ["preface", "followup", "summary"]);
    assert.equal(closeFrame.close.format, "asp-swarm-close/v2");
    assert.deepEqual(verifySwarmClose(closeFrame, new Map([[zoneB.zid, zoneB.descriptor]])).close.scheduler, closeFrame.close.scheduler);
  } finally {
    child.kill();
  }
});

test("Federation Gateway rejects invalid ready-DAG graphs before executing any step", async () => {
  const port = 9025;
  const zoneA = await loadOrCreateZone("zone://a", "state/keys/fed-zone-a.pkcs8");
  const requester = await loadOrCreateAgent("agent://zone-a/requester", "state/keys/fed-zone-a-requester.pkcs8");
  await writeTrustedZones("state/zone-b-schedule-preflight-trust.json", [zoneA]);
  const child = spawn(process.execPath, ["federation-gateway.mjs", "serve", String(port), "state/zone-b-schedule-preflight-trust.json"], { stdio: ["ignore", "pipe", "inherit"] });
  try {
    await waitForGateway(child);
    const taskFor = (taskId) => {
      const task = {
        task_id: taskId,
        from: requester.aid,
        to: "agent://zone-b/summarizer",
        intent: `Preflight ${taskId}.`,
        scope: { network: false },
        budget: { time_seconds: 30 },
      };
      return { ...task, signature: signObject(requester.privateKey, task) };
    };
    const cases = [
      {
        name: "duplicate step IDs",
        error: "execution binding duplicate step_id",
        steps: [
          { step_id: "duplicate", task: taskFor("node_swarm_duplicate_first") },
          { step_id: "duplicate", task: taskFor("node_swarm_duplicate_second") },
        ],
      },
      {
        name: "missing dependency",
        error: "swarm schedule dependency unresolved",
        steps: [{ step_id: "dependent", after: ["missing"], task: taskFor("node_swarm_missing_dependency") }],
      },
      {
        name: "self-dependency",
        error: "swarm schedule dependency unresolved",
        steps: [{ step_id: "self", after: ["self"], task: taskFor("node_swarm_self_dependency") }],
      },
    ];

    for (const graphCase of cases) {
      const frames = await exchangeFramesUntil(port, withManuallySignedSwarmExecutionBinding(zoneA, {
        type: "FED_SWARM_SCHEDULE",
        origin_zone: zoneA.descriptor,
        requester: requester.descriptor,
        requester_zone_binding: zoneBinding(zoneA, requester.descriptor),
        swarm: { swarm_id: `swarm://local/${graphCase.name.replaceAll(" ", "-")}`, steps: graphCase.steps },
      }), zoneA, "FED_SWARM_CLOSE");
      assert.deepEqual(frames, [{ type: "FED_TASK_ERROR", error: graphCase.error }], graphCase.name);
      assert.equal(frames.some((frame) => frame.type === "FED_RECEIPT" || frame.type === "FED_SWARM_CLOSE"), false, graphCase.name);
    }
  } finally {
    child.kill();
  }
});

test("Federation Gateway rejects an unresolvable ready-DAG before executing any step", async () => {
  const port = 9024;
  const zoneA = await loadOrCreateZone("zone://a", "state/keys/fed-zone-a.pkcs8");
  const requester = await loadOrCreateAgent("agent://zone-a/requester", "state/keys/fed-zone-a-requester.pkcs8");
  await writeTrustedZones("state/zone-b-schedule-cycle-trust.json", [zoneA]);
  const child = spawn(process.execPath, ["federation-gateway.mjs", "serve", String(port), "state/zone-b-schedule-cycle-trust.json"], { stdio: ["ignore", "pipe", "inherit"] });
  try {
    await waitForGateway(child);
    const firstTask = {
      task_id: "node_swarm_cycle_first",
      from: requester.aid,
      to: "agent://zone-b/summarizer",
      intent: "Cycle first.",
      scope: { network: false },
      budget: { time_seconds: 30 },
    };
    const secondTask = { ...firstTask, task_id: "node_swarm_cycle_second", intent: "Cycle second." };
    const frames = await exchangeFramesUntil(port, withSwarmExecutionBinding(zoneA, {
      type: "FED_SWARM_SCHEDULE",
      origin_zone: zoneA.descriptor,
      requester: requester.descriptor,
      requester_zone_binding: zoneBinding(zoneA, requester.descriptor),
      swarm: {
        swarm_id: "swarm://local/node_ready_dag_cycle",
        steps: [
          { step_id: "first", after: ["second"], task: { ...firstTask, signature: signObject(requester.privateKey, firstTask) } },
          { step_id: "second", after: ["first"], task: { ...secondTask, signature: signObject(requester.privateKey, secondTask) } },
        ],
      },
    }), zoneA, "FED_SWARM_CLOSE");

    assert.deepEqual(frames, [{ type: "FED_TASK_ERROR", error: "swarm schedule dependency unresolved" }]);
    assert.equal(frames.some((frame) => frame.type === "FED_RECEIPT" || frame.type === "FED_SWARM_CLOSE"), false);
  } finally {
    child.kill();
  }
});

test("Federation Gateway closes Swarm steps with signed micro-contracts", async () => {
  const port = 8998;
  const zoneA = await loadOrCreateZone("zone://a", "state/keys/fed-zone-a.pkcs8");
  const zoneB = await loadOrCreateZone("zone://b", "state/keys/fed-zone-b.pkcs8");
  const requester = await loadOrCreateAgent("agent://zone-a/requester", "state/keys/fed-zone-a-requester.pkcs8", {}, ["fed+tcp://127.0.0.1:8998"], ["request.task"]);
  await writeTrustedZones("state/zone-a-trust.json", [zoneB, zoneA]);
  await writeTrustedZones("state/zone-b-trust.json", [zoneA]);

  const gateway = spawn(process.execPath, ["federation-gateway.mjs", "serve", String(port), "state/zone-b-trust.json"], {
    cwd: process.cwd(),
    stdio: ["ignore", "pipe", "pipe"],
  });

  try {
    await waitForGateway(gateway);
    const summaryTask = {
      task_id: "node_swarm_micro_contract_summary",
      from: requester.aid,
      to: "agent://zone-b/summarizer",
      intent: "Summarize before signing the Swarm close.",
      scope: { network: false },
      budget: { time_seconds: 30 },
    };
    const followupTask = {
      task_id: "node_swarm_micro_contract_followup",
      from: requester.aid,
      to: "agent://zone-b/summarizer",
      intent: "Use the first step artifact after a micro-contract.",
      scope: { network: false },
      budget: { time_seconds: 30 },
    };

    const frames = await exchangeFramesUntil(port, withSwarmExecutionBinding(zoneA, {
      type: "FED_SWARM_OPEN",
      origin_zone: zoneA.descriptor,
      requester: requester.descriptor,
      requester_zone_binding: zoneBinding(zoneA, requester.descriptor),
      swarm: {
        swarm_id: "swarm://local/node_swarm_micro_contracts",
        steps: [
          { step_id: "summary", task: { ...summaryTask, signature: signObject(requester.privateKey, summaryTask) } },
          { step_id: "followup", after: ["summary"], task: { ...followupTask, signature: signObject(requester.privateKey, followupTask) } },
        ],
      },
    }), zoneA, "FED_SWARM_CLOSE");
    assert.notEqual(frames.at(-1).type, "FED_TASK_ERROR", frames.at(-1).error);

    const microContractEvents = frames.filter((frame) => frame.type === "FED_TASK_EVENT" && frame.event.micro_contract === "ok");
    assert.deepEqual(microContractEvents.map((frame) => frame.event.step_id), ["summary", "followup"]);
    const closeFrame = frames.at(-1);
    const close = closeFrame.close;
    assert.equal(close.micro_contracts.length, 2);
    assert.deepEqual(close.micro_contracts.map((contract) => contract.step_id), ["summary", "followup"]);
    for (const contract of close.micro_contracts) {
      assert.equal(contract.micro_contract, "ok");
      assert.equal(contract.swarm_id, "swarm://local/node_swarm_micro_contracts");
      assert.equal(contract.worker.aid, close.step_receipts.find((step) => step.step_id === contract.step_id).worker.aid);
      assert.match(contract.capability_proof, /summarize\.text/);
      assert.equal(typeof contract.cost_estimate.tokens, "number");
      assert.equal(typeof contract.cost_estimate.seconds, "number");
      assert.match(contract.policy_digest, /^[0-9a-f]{64}$/);
      assert.match(contract.contract_digest, /^[0-9a-f]{64}$/);
      assert.equal(typeof contract.signature, "string");
      const { contract_digest, signature, ...contractBody } = contract;
      assert.equal(contract_digest, createHash("sha256").update(canonical(contractBody)).digest("hex"));
      assert.equal(verifyObject(publicKeyFromDescriptor(contract.worker), contractBody, signature), true);
    }
    assert.equal(verifySwarmClose(closeFrame, new Map([[zoneB.zid, zoneB.descriptor]])).close.swarm_id, "swarm://local/node_swarm_micro_contracts");

    const tamperedClose = structuredClone(closeFrame);
    tamperedClose.close.micro_contracts[0].signature = "bad";
    assert.throws(
      () => verifySwarmClose(tamperedClose, new Map([[zoneB.zid, zoneB.descriptor]])),
      /micro-contract signature verification failed/,
    );
  } finally {
    gateway.kill("SIGINT");
  }
});

test("Federation Gateway migrates a failed Swarm step to the next same-capability worker", async () => {
  const port = 9014;
  const zoneA = await loadOrCreateZone("zone://a", "state/keys/fed-zone-a.pkcs8");
  const zoneB = await loadOrCreateZone("zone://b", "state/keys/fed-zone-b.pkcs8");
  const requester = await loadOrCreateAgent("agent://zone-a/requester", "state/keys/fed-zone-a-requester.pkcs8", {}, [`fed+tcp://127.0.0.1:${port}`], ["request.task"]);
  await writeTrustedZones("state/zone-a-migration-trust.json", [zoneB, zoneA]);
  await writeTrustedZones("state/zone-b-migration-trust.json", [zoneA]);

  const gateway = spawn(process.execPath, ["federation-gateway.mjs", "serve", String(port), "state/zone-b-migration-trust.json"], {
    cwd: process.cwd(),
    stdio: ["ignore", "pipe", "pipe"],
  });

  try {
    await waitForGateway(gateway);
    const migratingTask = {
      task_id: "node_swarm_migration_network_retry",
      from: requester.aid,
      to: "agent://zone-b/summarizer",
      intent: "Retry a failed Swarm step on the next same-capability worker.",
      scope: { network: true },
      budget: { time_seconds: 30 },
    };

    const frames = await exchangeFramesUntil(port, withSwarmExecutionBinding(zoneA, {
      type: "FED_SWARM_OPEN",
      origin_zone: zoneA.descriptor,
      requester: requester.descriptor,
      requester_zone_binding: zoneBinding(zoneA, requester.descriptor),
      swarm: {
        swarm_id: "swarm://local/node_swarm_failure_migration",
        steps: [
          { step_id: "summary", task: { ...migratingTask, signature: signObject(requester.privateKey, migratingTask) } },
        ],
      },
    }), zoneA, "FED_SWARM_CLOSE");
    assert.notEqual(frames.at(-1).type, "FED_TASK_ERROR", frames.at(-1).error);

    const closeFrame = frames.at(-1);
    assert.equal(closeFrame.type, "FED_SWARM_CLOSE");
    const verifiedClose = verifySwarmClose(closeFrame, new Map([[zoneB.zid, zoneB.descriptor]]));
    const { close } = verifiedClose;
    assert.equal(close.swarm_id, "swarm://local/node_swarm_failure_migration");
    assert.equal(close.migration_log.length, 1);

    const [migration] = close.migration_log;
    assert.equal(migration.step_id, "summary");
    assert.match(migration.original_worker_aid, /^aid:ed25519:/);
    assert.match(migration.migrated_to_worker_aid, /^aid:ed25519:/);
    assert.notEqual(migration.original_worker_aid, migration.migrated_to_worker_aid);
    assert.equal(migration.reason, "policy denied network access");
    assert.match(migration.migration_at, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
    assert.equal(new Date(migration.migration_at).toISOString(), migration.migration_at);

    const finalReceiptFrame = frames.filter((frame) => frame.type === "FED_RECEIPT").at(-1);
    assert.equal(finalReceiptFrame.worker.aid, migration.migrated_to_worker_aid);
    assert.equal(finalReceiptFrame.receipt.to, migration.migrated_to_worker_aid);
    const finalStepReceipt = close.step_receipts.find((step) => step.step_id === migration.step_id);
    assert.equal(finalStepReceipt.worker.aid, migration.migrated_to_worker_aid);
    assert.ok(finalStepReceipt.worker.capabilities.includes("summarize.text"));

    const tamperedClose = structuredClone(closeFrame);
    tamperedClose.close.migration_log[0].reason = "different failure";
    assert.throws(
      () => verifySwarmClose(tamperedClose, new Map([[zoneB.zid, zoneB.descriptor]])),
      /swarm close signature verification failed/,
    );
  } finally {
    gateway.kill("SIGINT");
  }
});

test("Federation Gateway rejects an untrusted origin Zone", async () => {
  const port = 8992;
  const zoneB = await loadOrCreateZone("zone://b", "state/keys/fed-zone-b.pkcs8");
  await writeTrustedZones("state/zone-a-trust-untrusted-test.json", [zoneB]);
  await writeTrustedZones("state/zone-b-empty-trust.json", []);

  const gateway = spawn(process.execPath, ["federation-gateway.mjs", "serve", String(port), "state/zone-b-empty-trust.json"], {
    cwd: process.cwd(),
    stdio: ["ignore", "pipe", "pipe"],
  });

  try {
    await waitForGateway(gateway);

    await assert.rejects(
      () =>
        execFileAsync(process.execPath, [
          "federation-gateway.mjs",
          "request",
          String(port),
          "state/zone-a-trust-untrusted-test.json",
        ]),
      (error) => error.stderr.includes("untrusted zone"),
    );
  } finally {
    gateway.kill("SIGINT");
  }
});

test("Federation Gateway resolves a remote agent alias", async () => {
  const port = 8993;
  const zoneA = await loadOrCreateZone("zone://a", "state/keys/fed-zone-a.pkcs8");
  const zoneB = await loadOrCreateZone("zone://b", "state/keys/fed-zone-b.pkcs8");
  await writeTrustedZones("state/zone-a-resolve-trust.json", [zoneB]);
  await writeTrustedZones("state/zone-b-resolve-trust.json", [zoneA]);

  const gateway = spawn(process.execPath, ["federation-gateway.mjs", "serve", String(port), "state/zone-b-resolve-trust.json"], {
    cwd: process.cwd(),
    stdio: ["ignore", "pipe", "pipe"],
  });

  try {
    await waitForGateway(gateway);

    const { stdout } = await execFileAsync(process.execPath, [
      "federation-gateway.mjs",
      "resolve",
      String(port),
      "state/zone-a-resolve-trust.json",
      "agent://zone-b/summarizer",
    ]);
    const result = JSON.parse(stdout);

    assert.equal(result.zone, zoneB.zid);
    assert.equal(result.alias, "agent://zone-b/summarizer");
    assert.match(result.aid, /^aid:ed25519:/);
  } finally {
    gateway.kill("SIGINT");
  }
});

test("Federation Gateway queries exact remote capabilities", async () => {
  const port = 8994;
  const zoneA = await loadOrCreateZone("zone://a", "state/keys/fed-zone-a.pkcs8");
  const zoneB = await loadOrCreateZone("zone://b", "state/keys/fed-zone-b.pkcs8");
  await writeTrustedZones("state/zone-a-query-trust.json", [zoneB]);
  await writeTrustedZones("state/zone-b-query-trust.json", [zoneA]);

  const gateway = spawn(process.execPath, ["federation-gateway.mjs", "serve", String(port), "state/zone-b-query-trust.json"], {
    cwd: process.cwd(),
    stdio: ["ignore", "pipe", "pipe"],
  });

  try {
    await waitForGateway(gateway);

    const unauthenticated = await exchangeRawFrame(port, {
      type: "FED_QUERY",
      origin_zone: zoneA.descriptor,
      capability: "summarize.text",
    });
    assert.equal(unauthenticated.type, "FED_TASK_ERROR");
    assert.match(unauthenticated.error, /session not authenticated/);

    const hit = await execFileAsync(process.execPath, [
      "federation-gateway.mjs",
      "query",
      String(port),
      "state/zone-a-query-trust.json",
      "summarize.text",
    ]);
    const hitResult = JSON.parse(hit.stdout);
    assert.equal(hitResult.zone, zoneB.zid);
    assert.equal(hitResult.matches.length, 1);
    assert.equal(hitResult.matches[0].alias, "agent://zone-b/summarizer");
    assert.deepEqual(hitResult.matches[0].capabilities, ["summarize.text"]);
    assert.equal(hitResult.matches[0].credentials[0].capability, "summarize.text");
    assert.equal(hitResult.matches[0].credentials[0].claims.level, "L1");

    const miss = await execFileAsync(process.execPath, [
      "federation-gateway.mjs",
      "query",
      String(port),
      "state/zone-a-query-trust.json",
      "translate.text",
    ]);
    const missResult = JSON.parse(miss.stdout);
    assert.equal(missResult.matches.length, 0);
  } finally {
    gateway.kill("SIGINT");
  }
});
test("Federation Gateway reports audit-backed completed receipt reputation", async () => {
  const port = 9001;
  const zoneA = await loadOrCreateZone("zone://a", "state/keys/fed-zone-a.pkcs8");
  const zoneB = await loadOrCreateZone("zone://b", "state/keys/fed-zone-b.pkcs8");
  const worker = await loadOrCreateAgent("agent://zone-b/summarizer", "state/keys/fed-zone-b-summarizer.pkcs8");
  const auditLastCompletedAt = new Date(Date.now() - 30 * 60 * 1000).toISOString();
  await writeTrustedZones("state/zone-a-audit-backed-query-trust.json", [zoneB]);
  await writeTrustedZones("state/zone-b-audit-backed-query-trust.json", [zoneA]);
  await writeAuditLog([
    { kind: "fed_receipt", to: worker.aid, status: "completed", task_id: "audit_backed_1", completed_at: auditLastCompletedAt },
    { kind: "fed_receipt", to: worker.aid, status: "completed", task_id: "audit_backed_2", completed_at: auditLastCompletedAt },
    { kind: "fed_receipt", to: worker.aid, status: "completed", task_id: "audit_backed_3", completed_at: auditLastCompletedAt },
    { kind: "fed_receipt", to: worker.aid, status: "completed", task_id: "audit_backed_4", completed_at: auditLastCompletedAt },
    { kind: "fed_receipt", to: worker.aid, status: "pending", task_id: "audit_backed_pending" },
    { kind: "fed_receipt", to: "aid:other", status: "completed", task_id: "audit_backed_other" },
    "malformed audit line",
  ]);

  const gateway = spawn(process.execPath, ["federation-gateway.mjs", "serve", String(port), "state/zone-b-audit-backed-query-trust.json"], {
    cwd: process.cwd(),
    stdio: ["ignore", "pipe", "pipe"],
  });

  try {
    await waitForGateway(gateway);

    const { stdout } = await execFileAsync(process.execPath, [
      "federation-gateway.mjs",
      "query",
      String(port),
      "state/zone-a-audit-backed-query-trust.json",
      "summarize.text",
    ]);
    const result = JSON.parse(stdout);

    assert.equal(result.matches[0].alias, "agent://zone-b/summarizer");
    assert.equal(result.matches[0].discovery_evidence.reputation.completed_receipts, 4);
    assert.equal(result.matches[0].discovery_evidence.reputation.last_completed_at, auditLastCompletedAt);
    const reputation = result.matches[0].discovery_evidence.reputation;
    assert.equal(reputation.revocation_count, 0);
    assert.ok(reputation.agent_score, "expected audit-backed reputation.agent_score to be exposed");
    assert.equal(reputation.agent_score.receipt_score, 8);
    assert.equal(reputation.agent_score.credential_score, 30);
    assert.equal(reputation.agent_score.freshness_score, 10);
    assert.equal(reputation.agent_score.revocation_penalty, 0);
    assert.equal(
      reputation.agent_score.total,
      reputation.agent_score.receipt_score + reputation.agent_score.credential_score + reputation.agent_score.freshness_score + reputation.agent_score.cost_score + reputation.agent_score.latency_score + reputation.agent_score.availability_score + reputation.agent_score.policy_match + reputation.agent_score.risk_match - reputation.agent_score.revocation_penalty,
    );
    assert.equal(result.matches[0].ranking.score, reputation.agent_score.total + 50);
  } finally {
    gateway.kill("SIGINT");
  }
});


test("Federation Gateway ranks semantic discovery by verifiable evidence first", async () => {
  const port = 8996;
  const zoneA = await loadOrCreateZone("zone://a", "state/keys/fed-zone-a.pkcs8");
  const zoneB = await loadOrCreateZone("zone://b", "state/keys/fed-zone-b.pkcs8");
  await writeTrustedZones("state/zone-a-semantic-query-trust.json", [zoneB]);
  await writeTrustedZones("state/zone-b-semantic-query-trust.json", [zoneA]);
  const worker = await loadOrCreateAgent("agent://zone-b/summarizer", "state/keys/fed-zone-b-summarizer.pkcs8");
  await writeAuditLog([
    { kind: "fed_receipt", to: worker.aid, status: "completed", task_id: "semantic_query_1" },
    { kind: "fed_receipt", to: worker.aid, status: "completed", task_id: "semantic_query_2" },
    { kind: "fed_receipt", to: worker.aid, status: "completed", task_id: "semantic_query_3" },
  ]);


  const gateway = spawn(process.execPath, ["federation-gateway.mjs", "serve", String(port), "state/zone-b-semantic-query-trust.json"], {
    cwd: process.cwd(),
    stdio: ["ignore", "pipe", "pipe"],
  });

  try {
    await waitForGateway(gateway);

    const { stdout } = await execFileAsync(process.execPath, [
      "federation-gateway.mjs",
      "query",
      String(port),
      "state/zone-a-semantic-query-trust.json",
      "summarize.text",
      "summarize text quickly",
    ]);
    const result = JSON.parse(stdout);

    assert.equal(result.matches.length, 2);
    assert.equal(result.matches[0].alias, "agent://zone-b/summarizer");
    assert.equal(result.matches[1].alias, "agent://zone-b/semantic-summarize-text-fast");
    assert.deepEqual(result.matches[0].discovery_evidence.capability, { exact: true, semantic: true });
    assert.deepEqual(result.matches[0].discovery_evidence.credential, { trusted: true, active: true });
    assert.equal(result.matches[0].discovery_evidence.reputation.completed_receipts, 3);
    assert.deepEqual(result.matches[1].discovery_evidence.credential, { trusted: false, active: false });
    assert.ok(result.matches[0].ranking.score > result.matches[1].ranking.score);
    assert.ok(result.matches[0].ranking.reasons.includes("credential_active"));
    assert.ok(result.matches[0].ranking.reasons.includes("reputation_receipts"));
  } finally {
    gateway.kill("SIGINT");
  }
});

test("Federation Gateway hands off task from capability query result", async () => {
  const port = 8995;
  const zoneA = await loadOrCreateZone("zone://a", "state/keys/fed-zone-a.pkcs8");
  const zoneB = await loadOrCreateZone("zone://b", "state/keys/fed-zone-b.pkcs8");
  await writeTrustedZones("state/zone-a-capability-handoff-trust.json", [zoneB, zoneA]);
  await writeTrustedZones("state/zone-b-capability-handoff-trust.json", [zoneA]);

  const gateway = spawn(process.execPath, ["federation-gateway.mjs", "serve", String(port), "state/zone-b-capability-handoff-trust.json"], {
    cwd: process.cwd(),
    stdio: ["ignore", "pipe", "pipe"],
  });

  try {
    await waitForGateway(gateway);

    const { stdout } = await execFileAsync(process.execPath, [
      "federation-gateway.mjs",
      "request-capability",
      String(port),
      "state/zone-a-capability-handoff-trust.json",
      "summarize.text",
    ]);
    const result = JSON.parse(stdout);

    assert.equal(result.zone, zoneA.zid);
    assert.equal(result.receipt.executing_zone, zoneB.zid);
    assert.equal(result.events.at(-1).type, "task.completed");
  } finally {
    gateway.kill("SIGINT");
  }
});

test("Go client completes a task against Node Federation Gateway", async () => {
  const port = 8997;
  const goAuthorityKey = "state/go-client-zone.seed";
  const goRequesterKey = "state/go-client-requester.seed";
  await writeFile(goAuthorityKey, "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f\n");
  await writeFile(goRequesterKey, "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f\n");
  const zoneB = await loadOrCreateZone("zone://b", "state/keys/fed-zone-b.pkcs8");
  const goZone = JSON.parse((await execFileAsync("go", [
    "run",
    "./cmd/go-fed-discovery",
    "--print-zone",
    "--authority-key",
    goAuthorityKey,
  ])).stdout);
  await writeTrustedZones("state/go-client-trusts-node.json", [zoneB, goZone]);
  await writeFile("state/node-trusts-go-client.json", `${JSON.stringify({ zones: [goZone] }, null, 2)}\n`);

  const gateway = spawn(process.execPath, ["federation-gateway.mjs", "serve", String(port), "state/node-trusts-go-client.json"], {
    cwd: process.cwd(),
    stdio: ["ignore", "pipe", "pipe"],
  });

  try {
    await waitForGateway(gateway);

    const { stdout } = await execFileAsync("go", [
      "run",
      "./cmd/go-fed-discovery",
      "--interop-request",
      String(port),
      "--trusted",
      "state/go-client-trusts-node.json",
      "--authority-key",
      goAuthorityKey,
      "--worker-key",
      goRequesterKey,
    ]);
    const result = JSON.parse(stdout);
    assert.equal(result.origin_zone, goZone.zid);
    assert.equal(result.receipt.executing_zone, zoneB.zid);
    assert.equal(result.events.at(-1).type, "task.completed");
  } finally {
    gateway.kill("SIGINT");
  }
});

test("Node client rejects Go receipt when task evidence digest mismatches", async () => {
  const port = 8998;
  const zoneA = await loadOrCreateZone("zone://a", "state/keys/fed-zone-a.pkcs8");
  const zoneB = await loadOrCreateZone("zone://b", "state/keys/fed-zone-b.pkcs8");
  const worker = await loadOrCreateAgent("agent://zone-b/summarizer", "state/keys/fed-zone-b-summarizer.pkcs8");
  await writeTrustedZones("state/node-client-task-evidence-trust.json", [zoneB, zoneA]);

  const server = net.createServer((socket) => {
    let buffer = "";
    socket.on("error", () => {});
    socket.on("data", (chunk) => {
      buffer += chunk.toString();
      const lines = buffer.split("\n");
      buffer = lines.pop();
      for (const line of lines) {
        if (!line.trim()) continue;
        const frame = JSON.parse(line);
        if (frame.type === "HELLO") {
          socket.write(`${JSON.stringify({ type: "HELLO", zone: zoneB.descriptor, session_id: "session:test", challenge: "challenge:test" })}\n`);
        } else if (frame.type === "AUTH") {
          socket.write(`${JSON.stringify({ type: "AUTH_OK", session_id: "session:test" })}\n`);
        } else if (frame.type === "FED_TASK_OPEN") {
          const receipt = {
            task_id: frame.task.task_id,
            task_digest: "0".repeat(64),
            from: frame.task.from,
            origin_zone: frame.origin_zone.zid,
            executing_zone: zoneB.zid,
            to: worker.aid,
            artifact_refs: [],
            event_count: 0,
            approvals: [],
          };
          socket.write(`${JSON.stringify({ type: "FED_RECEIPT", zone: zoneB.descriptor, worker: worker.descriptor, zone_binding: zoneBinding(zoneB, worker.descriptor), receipt: { ...receipt, signature: signObject(worker.privateKey, receipt) } })}\n`);
          socket.write(`${JSON.stringify({ type: "FED_TASK_CLOSE", task_id: frame.task.task_id })}\n`);
        }
      }
    });
  });
  await new Promise((resolve) => server.listen(port, "127.0.0.1", resolve));

  try {
    await assert.rejects(
      () =>
        execFileAsync(process.execPath, [
          "federation-gateway.mjs",
          "request",
          String(port),
          "state/node-client-task-evidence-trust.json",
        ]),
      (error) => error.stderr.includes("receipt task_digest mismatch"),
    );
  } finally {
    server.close();
  }
});

test("Federation Gateway rejects capability handoff when no match exists", async () => {
  const port = 8996;
  const zoneA = await loadOrCreateZone("zone://a", "state/keys/fed-zone-a.pkcs8");
  const zoneB = await loadOrCreateZone("zone://b", "state/keys/fed-zone-b.pkcs8");
  await writeTrustedZones("state/zone-a-capability-miss-trust.json", [zoneB]);
  await writeTrustedZones("state/zone-b-capability-miss-trust.json", [zoneA]);

  const gateway = spawn(process.execPath, ["federation-gateway.mjs", "serve", String(port), "state/zone-b-capability-miss-trust.json"], {
    cwd: process.cwd(),
    stdio: ["ignore", "pipe", "pipe"],
  });

  try {
    await waitForGateway(gateway);

    await assert.rejects(
      () =>
        execFileAsync(process.execPath, [
          "federation-gateway.mjs",
          "request-capability",
          String(port),
          "state/zone-a-capability-miss-trust.json",
          "translate.text",
        ]),
      (error) => error.stderr.includes("no remote capability match"),
    );
  } finally {
    gateway.kill("SIGINT");
  }
});

test("Federation Gateway resolves conflicting Swarm artifact refs by higher reputation", async () => {
  const port = 9022;
  const zoneA = await loadOrCreateZone("zone://a", "state/keys/fed-zone-a.pkcs8");
  const zoneB = await loadOrCreateZone("zone://b", "state/keys/fed-zone-b.pkcs8");
  const requester = await loadOrCreateAgent("agent://zone-a/requester", "state/keys/fed-zone-a-requester.pkcs8", {}, [`fed+tcp://127.0.0.1:${port}`], ["request.task"]);
  const highReputationWorker = await loadOrCreateAgent("agent://zone-b/migration-summarizer", "state/keys/fed-zone-b-migration-summarizer.pkcs8");
  await writeTrustedZones("state/zone-a-conflict-resolution-trust.json", [zoneB, zoneA]);
  await writeTrustedZones("state/zone-b-conflict-resolution-trust.json", [zoneA]);
  await writeAuditLog([
    { kind: "fed_receipt", to: highReputationWorker.aid, status: "completed", task_id: "prior_conflict_win_1", completed_at: new Date().toISOString() },
    { kind: "fed_receipt", to: highReputationWorker.aid, status: "completed", task_id: "prior_conflict_win_2", completed_at: new Date().toISOString() },
  ]);

  const gateway = spawn(process.execPath, ["federation-gateway.mjs", "serve", String(port), "state/zone-b-conflict-resolution-trust.json"], {
    cwd: process.cwd(),
    stdio: ["ignore", "pipe", "pipe"],
  });

  try {
    await waitForGateway(gateway);
    const artifactRef = "artifact://local/swarm-conflict/shared-summary.md";
    const lowTask = {
      task_id: "node_swarm_conflict_low",
      from: requester.aid,
      to: "agent://zone-b/summarizer",
      intent: "Write the low-reputation Swarm conflict candidate.",
      artifact_ref: artifactRef,
      scope: { network: false, write: [artifactRef] },
      budget: { time_seconds: 30 },
    };
    const highTask = {
      task_id: "node_swarm_conflict_high",
      from: requester.aid,
      to: "agent://zone-b/migration-summarizer",
      intent: "Write the high-reputation Swarm conflict candidate.",
      artifact_ref: artifactRef,
      scope: { network: false, write: [artifactRef] },
      budget: { time_seconds: 30 },
    };
    const frames = await exchangeFramesUntil(port, withSwarmExecutionBinding(zoneA, {
      type: "FED_SWARM_OPEN",
      origin_zone: zoneA.descriptor,
      requester: requester.descriptor,
      requester_zone_binding: zoneBinding(zoneA, requester.descriptor),
      swarm: {
        swarm_id: "swarm://local/node_conflict_resolution",
        steps: [
          { step_id: "low", task: { ...lowTask, signature: signObject(requester.privateKey, lowTask) } },
          { step_id: "high", task: { ...highTask, signature: signObject(requester.privateKey, highTask) } },
        ],
      },
    }), zoneA, "FED_SWARM_CLOSE");

    assert.notEqual(frames.at(-1).type, "FED_TASK_ERROR", frames.at(-1).error);
    const closeFrame = frames.at(-1);
    const close = closeFrame.close;
    assert.equal(Array.isArray(close.conflict_resolutions), true, "FED_SWARM_CLOSE close body must include conflict_resolutions");
    assert.equal(close.conflict_resolutions.length, 1);
    const [resolution] = close.conflict_resolutions;
    assert.equal(resolution.swarm_id, "swarm://local/node_conflict_resolution");
    assert.equal(resolution.artifact_ref, artifactRef);
    assert.deepEqual(resolution.candidate_step_ids, ["low", "high"]);
    assert.equal(resolution.chosen_step_id, "high");
    assert.equal(resolution.chosen_worker.alias, "agent://zone-b/migration-summarizer");
    assert.equal(resolution.reason, "higher_reputation");
    assert.match(resolution.resolution_digest, /^[0-9a-f]{64}$/);
    assert.equal(typeof resolution.signature, "string");
    const { resolution_digest, signature, ...resolutionBody } = resolution;
    assert.equal(resolution_digest, createHash("sha256").update(canonical(resolutionBody)).digest("hex"));
    assert.equal(verifyObject(publicKeyFromDescriptor(zoneB.descriptor), resolutionBody, signature), true);
    assert.equal(verifySwarmClose(closeFrame, new Map([[zoneB.zid, zoneB.descriptor]])).close.conflict_resolutions[0].chosen_step_id, "high");

    const tampered = structuredClone(closeFrame);
    tampered.close.conflict_resolutions[0].signature = "bad";
    assert.throws(
      () => verifySwarmClose(tampered, new Map([[zoneB.zid, zoneB.descriptor]])),
      /conflict resolution signature verification failed/,
    );
  } finally {
    gateway.kill("SIGINT");
  }
});
