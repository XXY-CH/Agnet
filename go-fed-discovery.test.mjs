import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { readFile, rm, writeFile } from "node:fs/promises";
import net from "node:net";
import { test } from "node:test";
import { promisify } from "node:util";
import { loadOrCreateAgent, loadOrCreateZone, resolveAgent, signObject, verifyObject, writeTrustedZones } from "./asp-core.mjs";

const execFileAsync = promisify(execFile);

function waitForGoGateway(child) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("go gateway did not start")), 5000);
    child.stdout.on("data", (chunk) => {
      const line = chunk.toString().split("\n").find((item) => item.trim().startsWith("{"));
      if (!line) return;
      clearTimeout(timer);
      resolve(JSON.parse(line));
    });
    child.once("error", reject);
    child.once("exit", (code) => {
      if (code !== null && code !== 0) reject(new Error(`go gateway exited early: ${code}`));
    });
  });
}

function exchangeFrames(port, frame, closeType = "FED_TASK_CLOSE") {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(port, "127.0.0.1");
    const frames = [];
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
        const item = JSON.parse(line);
        frames.push(item);
        if (item.type === "FED_TASK_ERROR") {
          socket.end();
          resolve(frames);
        }
        if (item.type === closeType) {
          socket.end();
          resolve(frames);
        }
      }
    });
  });
}

test("Go discovery gateway serves FED_RESOLVE and FED_QUERY to Node client", async () => {
  const port = 9091;
  const zoneA = await loadOrCreateZone("zone://a", "state/keys/fed-zone-a.pkcs8");
  const requester = await loadOrCreateAgent("agent://zone-a/requester", "state/keys/go-fed-requester.pkcs8");
  const fixture = JSON.parse(await readFile("test-vectors/asp-v1.5-capability-credential.json", "utf8"));
  const goFixture = JSON.parse(JSON.stringify(fixture));
  delete goFixture.authority_seed_hex;
  delete goFixture.worker_seed_hex;
  delete goFixture.worker;
  delete goFixture.zone_binding;
  await writeFile("state/go-fed-discovery-dynamic-worker.json", `${JSON.stringify(goFixture, null, 2)}\n`);
  await writeFile("state/go-fed-discovery-authority.seed", `${fixture.authority_seed_hex}\n`);
  await writeFile("state/go-fed-discovery-worker.seed", `${fixture.worker_seed_hex}\n`);
  await rm("state/go-fed-discovery-audit.log", { force: true });
  await writeTrustedZones("state/go-fed-discovery-trusted-origin.json", [zoneA]);
  await writeFile("state/node-trusts-go-discovery.json", `${JSON.stringify({ zones: [fixture.authority] }, null, 2)}\n`);
  await execFileAsync("go", ["build", "-o", "state/go-fed-discovery-test", "./cmd/go-fed-discovery"]);

  const gateway = spawn("./state/go-fed-discovery-test", [
    "--port",
    String(port),
    "--trusted",
    "state/go-fed-discovery-trusted-origin.json",
    "--fixture",
    "state/go-fed-discovery-dynamic-worker.json",
    "--authority-key",
    "state/go-fed-discovery-authority.seed",
    "--worker-key",
    "state/go-fed-discovery-worker.seed",
    "--audit",
    "state/go-fed-discovery-audit.log",
  ], {
    cwd: process.cwd(),
    stdio: ["ignore", "pipe", "pipe"],
  });

  try {
    await waitForGoGateway(gateway);

    const resolved = await execFileAsync(process.execPath, [
      "federation-gateway.mjs",
      "resolve",
      String(port),
      "state/node-trusts-go-discovery.json",
      "agent://zone-b/summarizer",
    ]);
    const resolvedResult = JSON.parse(resolved.stdout);
    assert.equal(resolvedResult.zone, fixture.authority.zid);
    assert.equal(resolvedResult.aid, fixture.worker.aid);

    const queried = await execFileAsync(process.execPath, [
      "federation-gateway.mjs",
      "query",
      String(port),
      "state/node-trusts-go-discovery.json",
      "summarize.text",
    ]);
    const queriedResult = JSON.parse(queried.stdout);
    assert.equal(queriedResult.matches.length, 1);
    assert.equal(queriedResult.matches[0].aid, fixture.worker.aid);
    assert.equal(queriedResult.matches[0].credentials[0].issuer, fixture.authority.zid);
    assert.equal(queriedResult.matches[0].credentials[0].subject, fixture.worker.aid);

    const task = {
      task_id: "go_fed_task_verified",
      from: requester.aid,
      to: fixture.worker_profile.alias,
      intent: "Verify FED_TASK_OPEN in Go.",
      scope: { network: false },
      budget: { time_seconds: 30 },
    };
    const executionFrames = await exchangeFrames(port, {
      type: "FED_TASK_OPEN",
      origin_zone: zoneA.descriptor,
      requester: requester.descriptor,
      task: { ...task, signature: signObject(requester.privateKey, task) },
    });
    assert.deepEqual(executionFrames.map((frame) => frame.type), [
      "FED_TASK_EVENT",
      "FED_TASK_EVENT",
      "FED_TASK_EVENT",
      "FED_TASK_EVENT",
      "FED_RECEIPT",
      "FED_TASK_CLOSE",
    ]);
    assert.deepEqual(
      executionFrames.slice(0, 4).map((frame) => frame.event.type),
      ["task.accepted", "task.started", "artifact.created", "task.completed"],
    );
    const receiptFrame = executionFrames[4];
    assert.equal(receiptFrame.zone.zid, fixture.authority.zid);
    const resolvedWorker = resolveAgent(
      new Map([[receiptFrame.worker.alias, {
        descriptor: receiptFrame.worker,
        zone: receiptFrame.zone,
        zone_binding: receiptFrame.zone_binding,
      }]]),
      receiptFrame.worker.alias,
    );
    const receiptBody = { ...receiptFrame.receipt };
    delete receiptBody.signature;
    assert.equal(verifyObject(resolvedWorker.publicKey, receiptBody, receiptFrame.receipt.signature), true);
    assert.equal(receiptFrame.receipt.task_id, task.task_id);
    assert.equal(receiptFrame.receipt.origin_zone, zoneA.zid);
    assert.equal(receiptFrame.receipt.executing_zone, fixture.authority.zid);
    assert.equal(receiptFrame.receipt.to, fixture.worker.aid);
    assert.equal(receiptFrame.receipt.artifact_refs[0], "artifact://local/go_fed_task_verified/go-summary.md");
    assert.equal(receiptFrame.receipt.event_count, 4);
    const artifactText = await readFile("artifacts/go_fed_task_verified/go-summary.md", "utf8");
    assert.match(artifactText, /Completed go_fed_task_verified/);

    const deniedTask = {
      ...task,
      task_id: "go_fed_task_denied",
      scope: { network: true },
    };
    const deniedFrames = await exchangeFrames(port, {
      type: "FED_TASK_OPEN",
      origin_zone: zoneA.descriptor,
      requester: requester.descriptor,
      task: { ...deniedTask, signature: signObject(requester.privateKey, deniedTask) },
    });
    assert.equal(deniedFrames[0].type, "FED_TASK_ERROR");
    assert.match(deniedFrames[0].error, /policy denied network access/);

    const verifiedAudit = await execFileAsync("./state/go-fed-discovery-test", [
      "--verify-audit",
      "--audit",
      "state/go-fed-discovery-audit.log",
    ]);
    assert.match(verifiedAudit.stdout, /"go_audit_verify":"ok"/);
  } finally {
    gateway.kill("SIGINT");
  }
});
