import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import net from "node:net";
import { test } from "node:test";
import { promisify } from "node:util";
import { AUDIT_ZERO_HASH, auditEntry, canonical, createZone, loadOrCreateAgent, loadOrCreateZone, publicKeyFromDescriptor, signObject, verifyObject, verifySwarmClose, verifyZoneTrustDelegation, writeTrustedZones, zoneBinding, zoneRevocation, zoneTrustDelegation } from "./asp-core.mjs";
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
  assert.equal(futureMatch.ranking.score, 95);
  assert.ok(futureMatch.ranking.reasons.includes("credential_active"));
  assert.deepEqual(pastMatch.discovery_evidence.credential, { trusted: true, active: false });
  assert.equal(pastMatch.ranking.score, 65);
  assert.equal(pastMatch.ranking.reasons.includes("credential_active"), false);
  assert.deepEqual(invalidMatch.discovery_evidence.credential, { trusted: true, active: false });
  assert.equal(invalidMatch.ranking.score, 65);
  assert.equal(invalidMatch.ranking.reasons.includes("credential_active"), false);
  assert.deepEqual(revokedMatch.discovery_evidence.credential, { trusted: true, active: false });
  assert.equal(revokedMatch.ranking.score, 65);
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
  assert.equal(reputation.agent_score.revocation_penalty, 0);
  assert.equal(reputation.agent_score.total, 65);
  assert.ok(reputation.agent_score.total > 0);
  assert.equal(reputation.last_completed_at, lastCompletedAt);
  assert.equal(
    reputation.agent_score.total,
    reputation.agent_score.receipt_score + reputation.agent_score.credential_score + reputation.agent_score.freshness_score + reputation.agent_score.cost_score + reputation.agent_score.latency_score + reputation.agent_score.availability_score - reputation.agent_score.revocation_penalty,
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
  assert.equal(revokedScore.total, revokedScore.receipt_score + revokedScore.credential_score + revokedScore.freshness_score + revokedScore.cost_score + revokedScore.latency_score + revokedScore.availability_score - revokedScore.revocation_penalty);
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

    const frames = await exchangeFramesUntil(port, {
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
    }, zoneA, "FED_SWARM_CLOSE");
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
      reputation.agent_score.receipt_score + reputation.agent_score.credential_score + reputation.agent_score.freshness_score + reputation.agent_score.cost_score + reputation.agent_score.latency_score + reputation.agent_score.availability_score - reputation.agent_score.revocation_penalty,
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
