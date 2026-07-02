import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
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

function wsAccept(key) {
  return createHash("sha1")
    .update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`)
    .digest("base64");
}

function encodeWebSocketText(text) {
  const payload = Buffer.from(text);
  const mask = randomBytes(4);
  const header = payload.length < 126
    ? Buffer.from([0x81, 0x80 | payload.length])
    : Buffer.from([0x81, 0x80 | 126, payload.length >> 8, payload.length & 0xff]);
  const masked = Buffer.alloc(payload.length);
  for (let index = 0; index < payload.length; index += 1) {
    masked[index] = payload[index] ^ mask[index % 4];
  }
  return Buffer.concat([header, mask, masked]);
}

function decodeWebSocketFrames(buffer) {
  const frames = [];
  let offset = 0;
  while (offset + 2 <= buffer.length) {
    const opcode = buffer[offset] & 0x0f;
    let length = buffer[offset + 1] & 0x7f;
    let headerLength = 2;
    if (length === 126) {
      if (offset + 4 > buffer.length) break;
      length = buffer.readUInt16BE(offset + 2);
      headerLength = 4;
    }
    if (length === 127) throw new Error("large websocket frames are not needed in this test");
    if (offset + headerLength + length > buffer.length) break;
    if (opcode === 1) frames.push(JSON.parse(buffer.subarray(offset + headerLength, offset + headerLength + length).toString()));
    offset += headerLength + length;
  }
  return { frames, rest: buffer.subarray(offset) };
}

function exchangeWebSocketFrames(port, frame, closeType) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(port, "127.0.0.1");
    const key = randomBytes(16).toString("base64");
    const frames = [];
    let handshook = false;
    let buffer = Buffer.alloc(0);
    socket.on("error", reject);
    socket.on("connect", () => {
      socket.write([
        "GET /fed HTTP/1.1",
        "Host: 127.0.0.1",
        "Upgrade: websocket",
        "Connection: Upgrade",
        `Sec-WebSocket-Key: ${key}`,
        "Sec-WebSocket-Version: 13",
        "",
        "",
      ].join("\r\n"));
    });
    socket.on("data", (chunk) => {
      try {
        buffer = Buffer.concat([buffer, chunk]);
        if (!handshook) {
          const marker = buffer.indexOf("\r\n\r\n");
          if (marker < 0) return;
          const headers = buffer.subarray(0, marker).toString();
          assert.match(headers, /101 Switching Protocols/);
          assert.equal(headers.toLowerCase().includes(`sec-websocket-accept: ${wsAccept(key).toLowerCase()}`), true);
          handshook = true;
          buffer = buffer.subarray(marker + 4);
          socket.write(encodeWebSocketText(JSON.stringify(frame)));
        }
        const decoded = decodeWebSocketFrames(buffer);
        buffer = decoded.rest;
        frames.push(...decoded.frames);
        if (frames.some((item) => item.type === closeType || item.type === "FED_TASK_ERROR")) {
          socket.end();
          resolve(frames);
        }
      } catch (error) {
        socket.destroy();
        reject(error);
      }
    });
  });
}

test("Go discovery gateway serves FED_RESOLVE and FED_QUERY to Node client", async () => {
  const port = 9091;
  const wsPort = 9092;
  const zoneA = await loadOrCreateZone("zone://a", "state/keys/fed-zone-a.pkcs8");
  const requester = await loadOrCreateAgent("agent://zone-a/requester", "state/keys/go-fed-requester.pkcs8");
  const fixture = JSON.parse(await readFile("test-vectors/asp-v1.5-capability-credential.json", "utf8"));
  const goFixture = JSON.parse(JSON.stringify(fixture));
  delete goFixture.authority_seed_hex;
  delete goFixture.worker_seed_hex;
  delete goFixture.worker;
  delete goFixture.zone_binding;
  goFixture.worker_profiles = [
    { ...fixture.worker_profile },
    {
      key_file: "state/go-fed-discovery-translator.seed",
      alias: "agent://zone-b/translator",
      transports: ["fed+tcp://127.0.0.1:8991"],
      capabilities: ["translate.text"],
      policy: { allow_network: false },
    },
  ];
  delete goFixture.worker_profile;
  await writeFile("state/go-fed-discovery-dynamic-worker.json", `${JSON.stringify(goFixture, null, 2)}\n`);
  await writeFile("state/go-fed-discovery-authority.seed", `${fixture.authority_seed_hex}\n`);
  await writeFile("state/go-fed-discovery-worker.seed", `${fixture.worker_seed_hex}\n`);
  await writeFile("state/go-fed-discovery-translator.seed", "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f\n");
  await rm("state/go-fed-discovery-audit.log", { force: true });
  await writeTrustedZones("state/go-fed-discovery-trusted-origin.json", [zoneA]);
  await writeFile("state/node-trusts-go-discovery.json", `${JSON.stringify({ zones: [fixture.authority] }, null, 2)}\n`);
  await execFileAsync("go", ["build", "-o", "state/go-fed-discovery-test", "./cmd/go-fed-discovery"]);

  const gateway = spawn("./state/go-fed-discovery-test", [
    "--port",
    String(port),
    "--ws-port",
    String(wsPort),
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

    const translated = await execFileAsync(process.execPath, [
      "federation-gateway.mjs",
      "query",
      String(port),
      "state/node-trusts-go-discovery.json",
      "translate.text",
    ]);
    const translatedResult = JSON.parse(translated.stdout);
    assert.equal(translatedResult.matches.length, 1);
    assert.equal(translatedResult.matches[0].alias, "agent://zone-b/translator");
    assert.equal(translatedResult.matches[0].credentials[0].capability, "translate.text");

    const wsFrames = await exchangeWebSocketFrames(wsPort, {
      type: "FED_QUERY",
      origin_zone: zoneA.descriptor,
      capability: "translate.text",
    }, "FED_QUERY_CLOSE");
    assert.deepEqual(wsFrames.map((frame) => frame.type), ["FED_QUERY_RESULT", "FED_QUERY_CLOSE"]);
    assert.equal(wsFrames[0].matches[0].worker.alias, "agent://zone-b/translator");

    const resolvedTranslator = await execFileAsync(process.execPath, [
      "federation-gateway.mjs",
      "resolve",
      String(port),
      "state/node-trusts-go-discovery.json",
      "agent://zone-b/translator",
    ]);
    const resolvedTranslatorResult = JSON.parse(resolvedTranslator.stdout);
    assert.equal(resolvedTranslatorResult.alias, "agent://zone-b/translator");

    const task = {
      task_id: "go_fed_task_verified",
      from: requester.aid,
      to: "agent://zone-b/translator",
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
    assert.equal(receiptFrame.worker.alias, "agent://zone-b/translator");
    assert.equal(receiptFrame.receipt.to, receiptFrame.worker.aid);
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
