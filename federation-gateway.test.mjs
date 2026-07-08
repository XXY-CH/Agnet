import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import net from "node:net";
import { test } from "node:test";
import { promisify } from "node:util";
import { AUDIT_ZERO_HASH, auditEntry, loadOrCreateAgent, loadOrCreateZone, signObject, writeTrustedZones, zoneBinding } from "./asp-core.mjs";
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

  assert.deepEqual(futureMatch.discovery_evidence.credential, { trusted: true, active: true });
  assert.equal(futureMatch.ranking.score, 80);
  assert.ok(futureMatch.ranking.reasons.includes("credential_active"));
  assert.deepEqual(pastMatch.discovery_evidence.credential, { trusted: true, active: false });
  assert.equal(pastMatch.ranking.score, 50);
  assert.equal(pastMatch.ranking.reasons.includes("credential_active"), false);
  assert.deepEqual(invalidMatch.discovery_evidence.credential, { trusted: true, active: false });
  assert.equal(invalidMatch.ranking.score, 50);
  assert.equal(invalidMatch.ranking.reasons.includes("credential_active"), false);
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
  await writeTrustedZones("state/zone-a-audit-backed-query-trust.json", [zoneB]);
  await writeTrustedZones("state/zone-b-audit-backed-query-trust.json", [zoneA]);
  await writeAuditLog([
    { kind: "fed_receipt", to: worker.aid, status: "completed", task_id: "audit_backed_1" },
    { kind: "fed_receipt", to: worker.aid, status: "completed", task_id: "audit_backed_2" },
    { kind: "fed_receipt", to: worker.aid, status: "completed", task_id: "audit_backed_3" },
    { kind: "fed_receipt", to: worker.aid, status: "completed", task_id: "audit_backed_4" },
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
