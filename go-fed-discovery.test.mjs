import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { readFile, rm, writeFile } from "node:fs/promises";
import net from "node:net";
import { test } from "node:test";
import { promisify } from "node:util";
import { canonical, capabilityCredentialId, loadOrCreateAgent, loadOrCreateZone, publicKeyFromDescriptor, resolveAgent, signObject, verifyCredentialStatus, verifyObject, writeTrustedZones } from "./asp-core.mjs";

const execFileAsync = promisify(execFile);

function waitForGoGateway(child, port) {
  return new Promise((resolve, reject) => {
    let stderr = "";
    let stdout = "";
    let done = false;
    const fail = (error) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      clearInterval(poller);
      reject(error);
    };
    const pass = () => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      clearInterval(poller);
      resolve();
    };
    const timer = setTimeout(() => fail(new Error(`go gateway did not start: stdout=${stdout.trim()} stderr=${stderr.trim()}`)), 60000);
    const poller = setInterval(() => {
      const socket = net.createConnection(port, "127.0.0.1");
      socket.once("connect", () => {
        socket.end();
        pass();
      });
      socket.once("error", () => {
        socket.destroy();
      });
    }, 50);
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });
    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });
    child.once("error", fail);
    child.once("exit", (code) => {
      if (code !== null && code !== 0) {
        fail(new Error(`go gateway exited early: ${code}: stdout=${stdout.trim()} stderr=${stderr.trim()}`));
      }
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
      socket.write(`${JSON.stringify({ type: "HELLO", origin_zone: frame.origin_zone })}\n`);
    });
    socket.on("data", (chunk) => {
      buffer += chunk.toString();
      const lines = buffer.split("\n");
      buffer = lines.pop();
      for (const line of lines) {
        if (!line.trim()) continue;
        const item = JSON.parse(line);
        if (item.type === "HELLO") {
          const body = authBody(item.session_id, item.challenge, frame.origin_zone.zid, item.zone.zid);
          socket.write(`${JSON.stringify({
            type: "AUTH",
            origin_zone: frame.origin_zone,
            auth: { ...body, auth_signature: signObject(zoneA.privateKey, body) },
          })}\n`);
          continue;
        }
        if (item.type === "AUTH_OK") {
          socket.write(`${JSON.stringify(frame)}\n`);
          continue;
        }
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

let zoneA;

function authBody(sessionId, challenge, peerZid, remoteZid) {
  return { session_id: sessionId, challenge, peer_zid: peerZid, remote_zid: remoteZid };
}

function queueActionGrant(action, taskId, task, extra = {}) {
  const body = {
    action,
    task_id: taskId,
    task_digest: task ? createHash("sha256").update(canonical(task)).digest("hex") : null,
    actor: "human://local",
    authority: zoneA.descriptor.zid,
    authority_descriptor: zoneA.descriptor,
    scope: { actions: [action] },
    expires_at: "2099-01-01T00:00:00Z",
    ...extra,
  };
  return { ...body, grant_signature: signObject(zoneA.privateKey, body) };
}

function exchangeUnauthenticatedFrame(port, frame) {
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

async function freePorts(count) {
  const servers = await Promise.all(Array.from({ length: count }, () => new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve(server));
  })));
  const ports = servers.map((server) => server.address().port);
  await Promise.all(servers.map((server) => new Promise((resolve) => {
    server.close(resolve);
  })));
  return ports;
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
          socket.write(encodeWebSocketText(JSON.stringify({ type: "HELLO", origin_zone: frame.origin_zone })));
        }
        const decoded = decodeWebSocketFrames(buffer);
        buffer = decoded.rest;
        for (const item of decoded.frames) {
          if (item.type === "HELLO") {
            const body = authBody(item.session_id, item.challenge, frame.origin_zone.zid, item.zone.zid);
            socket.write(encodeWebSocketText(JSON.stringify({
              type: "AUTH",
              origin_zone: frame.origin_zone,
              auth: { ...body, auth_signature: signObject(zoneA.privateKey, body) },
            })));
            continue;
          }
          if (item.type === "AUTH_OK") {
            socket.write(encodeWebSocketText(JSON.stringify(frame)));
            continue;
          }
          frames.push(item);
        }
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
  const [port, wsPort, humanPort] = await freePorts(3);
  zoneA = await loadOrCreateZone("zone://a", "state/keys/fed-zone-a.pkcs8");
  const requester = await loadOrCreateAgent("agent://zone-a/requester", "state/keys/go-fed-requester.pkcs8");
  const fixture = JSON.parse(await readFile("test-vectors/asp-v1.5-capability-credential.json", "utf8"));
  const goFixture = JSON.parse(JSON.stringify(fixture));
  delete goFixture.authority_seed_hex;
  delete goFixture.worker_seed_hex;
  delete goFixture.worker;
  delete goFixture.zone_binding;
  goFixture.worker_profiles = [
    { ...fixture.worker_profile, tool: "summarize.mock" },
    {
      key_file: "state/go-fed-discovery-translator.seed",
      alias: "agent://zone-b/translator",
      tool: "mcp.stdio",
      tool_name: "translate",
      tool_command: [process.execPath, `${process.cwd()}/state/go-fed-mcp-server.mjs`],
      sandbox_claim: "local-temp-dir",
      transports: ["fed+tcp://127.0.0.1:8991"],
      capabilities: ["translate.text"],
      policy: { allow_network: false, approval_required: ["tool"] },
    },
    {
      key_file: "state/go-fed-discovery-strict-translator.seed",
      alias: "agent://zone-b/strict-translator",
      tool: "mcp.stdio",
      tool_name: "translate",
      tool_command: [process.execPath, `${process.cwd()}/state/go-fed-mcp-server.mjs`, "--require-locale"],
      sandbox_claim: "local-temp-dir",
      transports: ["fed+tcp://127.0.0.1:8992"],
      capabilities: ["translate.strict"],
      policy: { allow_network: false, approval_required: ["tool"] },
    },
    {
      key_file: "state/go-fed-discovery-slow.seed",
      alias: "agent://zone-b/slow",
      tool: "external.stdio",
      tool_command: [process.execPath, `${process.cwd()}/state/go-fed-slow-tool.mjs`],
      sandbox_claim: "local-temp-dir",
      transports: ["fed+tcp://127.0.0.1:8993"],
      capabilities: ["slow.text"],
      policy: { allow_network: false, approval_required: ["tool"] },
    },
  ];
  delete goFixture.worker_profile;
  await writeFile("state/go-fed-discovery-dynamic-worker.json", `${JSON.stringify(goFixture, null, 2)}\n`);
  await writeFile("state/go-fed-discovery-authority.seed", `${fixture.authority_seed_hex}\n`);
  await writeFile("state/go-fed-discovery-worker.seed", `${fixture.worker_seed_hex}\n`);
  await writeFile("state/go-fed-discovery-translator.seed", "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f\n");
  await writeFile("state/go-fed-discovery-strict-translator.seed", "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf\n");
  await writeFile("state/go-fed-discovery-slow.seed", "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf\n");
  await writeFile("state/go-fed-mcp-server.mjs", `
import readline from "node:readline";
const requireLocale = process.argv.includes("--require-locale");
const rl = readline.createInterface({ input: process.stdin });
rl.on("line", (line) => {
  const message = JSON.parse(line);
  if (message.method === "initialize") {
    process.stdout.write(JSON.stringify({
      jsonrpc: "2.0",
      id: message.id,
      result: { protocolVersion: message.params.protocolVersion, capabilities: { tools: {} }, serverInfo: { name: "test-mcp", version: "0" } }
    }) + "\\n");
  } else if (message.method === "resources/list") {
    process.stdout.write(JSON.stringify({
      jsonrpc: "2.0",
      id: message.id,
      result: { resources: [{ uri: "memory://public/docs", name: "public docs" }] }
    }) + "\\n");
  } else if (message.method === "prompts/list") {
    process.stdout.write(JSON.stringify({
      jsonrpc: "2.0",
      id: message.id,
      result: { prompts: [{ name: "translate" }] }
    }) + "\\n");
  } else if (message.method === "tools/list") {
    process.stdout.write(JSON.stringify({
      jsonrpc: "2.0",
      id: message.id,
      result: { tools: [{ name: "translate", inputSchema: { type: "object", properties: { intent: { type: "string" }, locale: { type: "string" } }, required: requireLocale ? ["intent", "locale"] : ["intent"] } }] }
    }) + "\\n");
  } else if (message.method === "tools/call") {
    const args = message.params.arguments;
    process.stdout.write(JSON.stringify({
      jsonrpc: "2.0",
      id: message.id,
      result: { content: [{ type: "text", text: \`# MCP Tool Translation\\n\\nTask: \${args.task_id}\\nTranslation: \${String(args.intent).toUpperCase()}\\nCWD: \${process.cwd()}\\n\` }] }
    }) + "\\n");
    process.exit(0);
  }
});
`);
  await writeFile("state/go-fed-slow-tool.mjs", `
setTimeout(() => {
  process.stdout.write(JSON.stringify({ text: "# Slow Tool\\n\\nFinished" }));
}, 5000);
`);
  await rm("state/go-fed-discovery-audit.log", { force: true });
  await rm("state/go-fed-discovery-audit-tasks", { recursive: true, force: true });
  await rm("state/go-fed-discovery-audit-queue", { recursive: true, force: true });
  await writeTrustedZones("state/go-fed-discovery-trusted-origin.json", [zoneA]);
  await writeFile("state/node-trusts-go-discovery.json", `${JSON.stringify({ zones: [fixture.authority] }, null, 2)}\n`);
  const gateway = spawn("go", [
    "run",
    "./cmd/go-fed-discovery",
    "--port",
    String(port),
    "--ws-port",
    String(wsPort),
    "--human-port",
    String(humanPort),
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
    detached: true,
    stdio: ["ignore", "pipe", "pipe"],
  });

  try {
    await waitForGoGateway(gateway, port);

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
    assert.equal(queriedResult.matches[0].credential_statuses[0].status, "active");
    assert.equal(
      queriedResult.matches[0].credential_statuses[0].credential_id,
      capabilityCredentialId(queriedResult.matches[0].credentials[0]),
    );

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
    assert.equal(translatedResult.matches[0].credential_statuses[0].status, "active");

    const unauthenticated = await exchangeUnauthenticatedFrame(port, {
      type: "FED_QUERY",
      origin_zone: zoneA.descriptor,
      capability: "translate.text",
    });
    assert.equal(unauthenticated.type, "FED_TASK_ERROR");
    assert.match(unauthenticated.error, /session not authenticated/);

    const wsFrames = await exchangeWebSocketFrames(wsPort, {
      type: "FED_QUERY",
      origin_zone: zoneA.descriptor,
      capability: "translate.text",
    }, "FED_QUERY_CLOSE");
    assert.deepEqual(wsFrames.map((frame) => frame.type), ["FED_QUERY_RESULT", "FED_QUERY_CLOSE"]);
    assert.equal(wsFrames[0].matches[0].worker.alias, "agent://zone-b/translator");
    assert.equal(
      verifyCredentialStatus(wsFrames[0].matches[0].credential_statuses[0], wsFrames[0].matches[0].credentials[0], fixture.authority),
      true,
    );

    const resolvedTranslator = await execFileAsync(process.execPath, [
      "federation-gateway.mjs",
      "resolve",
      String(port),
      "state/node-trusts-go-discovery.json",
      "agent://zone-b/translator",
    ]);
    const resolvedTranslatorResult = JSON.parse(resolvedTranslator.stdout);
    assert.equal(resolvedTranslatorResult.alias, "agent://zone-b/translator");
    const resolvedSlow = await execFileAsync(process.execPath, [
      "federation-gateway.mjs",
      "resolve",
      String(port),
      "state/node-trusts-go-discovery.json",
      "agent://zone-b/slow",
    ]);
    const resolvedSlowResult = JSON.parse(resolvedSlow.stdout);
    assert.equal(resolvedSlowResult.alias, "agent://zone-b/slow");

    const task = {
      task_id: "go_fed_task_verified",
      from: requester.aid,
      to: "agent://zone-b/translator",
      intent: "Verify FED_TASK_OPEN in Go.",
      scope: { network: false, data_domains: ["public.docs"], expires_at: "2026-07-03T12:00:00Z" },
      budget: { time_seconds: 30 },
    };
    const queuedTask = {
      ...task,
      task_id: "go_fed_task_queued",
      intent: "Queue before scheduler execution.",
    };
    const queuedFrames = await exchangeFrames(port, {
      type: "FED_TASK_ENQUEUE",
      origin_zone: zoneA.descriptor,
      requester: requester.descriptor,
      task: { ...queuedTask, signature: signObject(requester.privateKey, queuedTask) },
    }, "FED_QUEUE_CLOSE");
    assert.deepEqual(queuedFrames.map((frame) => frame.type), ["FED_QUEUE_ACCEPTED", "FED_QUEUE_CLOSE"]);
    const queuedState = JSON.parse(await readFile("state/go-fed-discovery-audit-queue/go_fed_task_queued.json", "utf8"));
    assert.equal(queuedState.task_id, queuedTask.task_id);
    assert.equal(queuedState.status, "queued");
    assert.equal(queuedState.worker, resolvedTranslatorResult.aid);
    assert.equal(queuedState.origin_zone, zoneA.zid);
    assert.match(queuedState.task_digest, /^[0-9a-f]{64}$/);

    const claimFrames = await exchangeFrames(port, {
      type: "FED_QUEUE_CLAIM",
      origin_zone: zoneA.descriptor,
      task_id: queuedTask.task_id,
      owner: "scheduler://local",
      lease_seconds: -1,
    }, "FED_QUEUE_CLAIM_CLOSE");
    assert.deepEqual(claimFrames.map((frame) => frame.type), ["FED_QUEUE_CLAIMED", "FED_QUEUE_CLAIM_CLOSE"]);
    assert.match(claimFrames[0].lease_id, /^lease:sha256:[0-9a-f]{64}$/);
    const claimedQueueState = JSON.parse(await readFile("state/go-fed-discovery-audit-queue/go_fed_task_queued.json", "utf8"));
    assert.equal(claimedQueueState.status, "claimed");
    assert.equal(claimedQueueState.lease_owner, "scheduler://local");
    assert.equal(claimedQueueState.lease_id, claimFrames[0].lease_id);
    assert.match(claimedQueueState.lease_expires_at, /^\d{4}-\d{2}-\d{2}T/);

    const expiredDrainFrames = await exchangeFrames(port, {
      type: "FED_QUEUE_DRAIN",
      origin_zone: zoneA.descriptor,
      task_id: queuedTask.task_id,
      lease_id: claimFrames[0].lease_id,
    });
    assert.equal(expiredDrainFrames[0].type, "FED_TASK_ERROR");
    assert.match(expiredDrainFrames[0].error, /queue lease expired/);

    const reclaimFrames = await exchangeFrames(port, {
      type: "FED_QUEUE_RECLAIM",
      origin_zone: zoneA.descriptor,
      task_id: queuedTask.task_id,
      owner: "scheduler://reclaimer",
    }, "FED_QUEUE_RECLAIM_CLOSE");
    assert.deepEqual(reclaimFrames.map((frame) => frame.type), ["FED_QUEUE_RECLAIMED", "FED_QUEUE_RECLAIM_CLOSE"]);
    assert.match(reclaimFrames[0].lease_id, /^lease:sha256:[0-9a-f]{64}$/);
    assert.notEqual(reclaimFrames[0].lease_id, claimFrames[0].lease_id);
    const reclaimedQueueState = JSON.parse(await readFile("state/go-fed-discovery-audit-queue/go_fed_task_queued.json", "utf8"));
    assert.equal(reclaimedQueueState.status, "claimed");
    assert.equal(reclaimedQueueState.lease_owner, "scheduler://reclaimer");
    assert.equal(reclaimedQueueState.lease_id, reclaimFrames[0].lease_id);
    assert.match(reclaimedQueueState.lease_expires_at, /^\d{4}-\d{2}-\d{2}T/);
    assert.notEqual(reclaimedQueueState.lease_expires_at, claimedQueueState.lease_expires_at);

    const drainedFrames = await exchangeFrames(port, {
      type: "FED_QUEUE_DRAIN",
      origin_zone: zoneA.descriptor,
      task_id: queuedTask.task_id,
      lease_id: reclaimFrames[0].lease_id,
    });
    assert.deepEqual(drainedFrames.map((frame) => frame.type), [
      "FED_TASK_EVENT",
      "FED_TASK_EVENT",
      "FED_TASK_EVENT",
      "FED_TASK_EVENT",
      "FED_TASK_EVENT",
      "FED_TASK_EVENT",
      "FED_TASK_EVENT",
      "FED_RECEIPT",
      "FED_TASK_CLOSE",
    ]);
    const drainedReceipt = drainedFrames[7].receipt;
    assert.equal(drainedReceipt.task_id, queuedTask.task_id);
    const drainedQueueState = JSON.parse(await readFile("state/go-fed-discovery-audit-queue/go_fed_task_queued.json", "utf8"));
    assert.equal(drainedQueueState.status, "completed");
    assert.equal(drainedQueueState.lease_id, reclaimFrames[0].lease_id);
    assert.equal(drainedQueueState.receipt_digest, createHash("sha256").update(JSON.stringify(drainedReceipt)).digest("hex"));

    const failedQueuedTask = {
      ...task,
      task_id: "go_fed_task_queued_failed",
      to: "agent://zone-b/strict-translator",
      intent: "Queue a task that fails before receipt.",
    };
    const failedQueuedFrames = await exchangeFrames(port, {
      type: "FED_TASK_ENQUEUE",
      origin_zone: zoneA.descriptor,
      requester: requester.descriptor,
      task: { ...failedQueuedTask, signature: signObject(requester.privateKey, failedQueuedTask) },
    }, "FED_QUEUE_CLOSE");
    assert.deepEqual(failedQueuedFrames.map((frame) => frame.type), ["FED_QUEUE_ACCEPTED", "FED_QUEUE_CLOSE"]);
    const failedClaimFrames = await exchangeFrames(port, {
      type: "FED_QUEUE_CLAIM",
      origin_zone: zoneA.descriptor,
      task_id: failedQueuedTask.task_id,
      owner: "scheduler://local",
    }, "FED_QUEUE_CLAIM_CLOSE");
    assert.deepEqual(failedClaimFrames.map((frame) => frame.type), ["FED_QUEUE_CLAIMED", "FED_QUEUE_CLAIM_CLOSE"]);
    const failedDrainFrames = await exchangeFrames(port, {
      type: "FED_QUEUE_DRAIN",
      origin_zone: zoneA.descriptor,
      task_id: failedQueuedTask.task_id,
      lease_id: failedClaimFrames[0].lease_id,
    });
    assert.equal(failedDrainFrames.at(-1).type, "FED_TASK_ERROR");
    assert.match(failedDrainFrames.at(-1).error, /mcp tool arguments missing required field: locale/);
    const failedQueueState = JSON.parse(await readFile("state/go-fed-discovery-audit-queue/go_fed_task_queued_failed.json", "utf8"));
    assert.equal(failedQueueState.status, "failed");

    const retryQueuedTask = {
      ...failedQueuedTask,
      task_id: "go_fed_task_queued_retry",
      intent: "Retry queued failed task with backoff state.",
    };
    const retryQueueFrames = await exchangeFrames(port, {
      type: "FED_QUEUE_RETRY",
      origin_zone: zoneA.descriptor,
      requester: requester.descriptor,
      retry_of: failedQueuedTask.task_id,
      retry_after_seconds: 30,
      task: { ...retryQueuedTask, signature: signObject(requester.privateKey, retryQueuedTask) },
    }, "FED_QUEUE_RETRY_CLOSE");
    assert.deepEqual(retryQueueFrames.map((frame) => frame.type), ["FED_QUEUE_RETRY_ACCEPTED", "FED_QUEUE_RETRY_CLOSE"]);
    const retryQueueState = JSON.parse(await readFile("state/go-fed-discovery-audit-queue/go_fed_task_queued_retry.json", "utf8"));
    assert.equal(retryQueueState.status, "queued");
    assert.equal(retryQueueState.retry_of, failedQueuedTask.task_id);
    assert.equal(retryQueueState.retry_attempt, 1);
    assert.match(retryQueueState.retry_after_at, /^\d{4}-\d{2}-\d{2}T/);

    const retryBackoffClaimFrames = await exchangeFrames(port, {
      type: "FED_QUEUE_CLAIM",
      origin_zone: zoneA.descriptor,
      task_id: retryQueuedTask.task_id,
      owner: "scheduler://too-early",
    });
    assert.equal(retryBackoffClaimFrames[0].type, "FED_TASK_ERROR");
    assert.match(retryBackoffClaimFrames[0].error, /queue retry backoff active/);

    const humanQueuedTask = {
      ...task,
      task_id: "go_fed_task_human_queue_action",
      intent: "Drain through Human Gateway queue action.",
    };
    const humanQueuedFrames = await exchangeFrames(port, {
      type: "FED_TASK_ENQUEUE",
      origin_zone: zoneA.descriptor,
      requester: requester.descriptor,
      task: { ...humanQueuedTask, signature: signObject(requester.privateKey, humanQueuedTask) },
    }, "FED_QUEUE_CLOSE");
    assert.deepEqual(humanQueuedFrames.map((frame) => frame.type), ["FED_QUEUE_ACCEPTED", "FED_QUEUE_CLOSE"]);
    const queueResponse = await fetch(`http://127.0.0.1:${humanPort}/api/queue`);
    assert.equal(queueResponse.status, 200);
    const queueBody = await queueResponse.json();
    assert.equal(queueBody.queue.some((item) => item.task_id === humanQueuedTask.task_id && item.status === "queued"), true);

    const unauthorisedHumanClaimResponse = await fetch(`http://127.0.0.1:${humanPort}/api/queue/actions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ action: "claim", task_id: humanQueuedTask.task_id, owner: "human://local" }),
    });
    assert.equal(unauthorisedHumanClaimResponse.status, 400);
    assert.match(await unauthorisedHumanClaimResponse.text(), /queue action grant missing/);

    const expiredGrantClaimResponse = await fetch(`http://127.0.0.1:${humanPort}/api/queue/actions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        action: "claim",
        task_id: humanQueuedTask.task_id,
        owner: "human://local",
        actor: "human://local",
        action_grant: queueActionGrant("claim", humanQueuedTask.task_id, null, { expires_at: "2000-01-01T00:00:00Z" }),
      }),
    });
    assert.equal(expiredGrantClaimResponse.status, 400);
    assert.match(await expiredGrantClaimResponse.text(), /queue action grant expired/);

    const outOfScopeGrantClaimResponse = await fetch(`http://127.0.0.1:${humanPort}/api/queue/actions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        action: "claim",
        task_id: humanQueuedTask.task_id,
        owner: "human://local",
        actor: "human://local",
        action_grant: queueActionGrant("claim", humanQueuedTask.task_id, null, { scope: { actions: ["drain"] } }),
      }),
    });
    assert.equal(outOfScopeGrantClaimResponse.status, 400);
    assert.match(await outOfScopeGrantClaimResponse.text(), /queue action grant scope mismatch/);

    const missingActorGrantClaimResponse = await fetch(`http://127.0.0.1:${humanPort}/api/queue/actions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        action: "claim",
        task_id: humanQueuedTask.task_id,
        owner: "human://local",
        action_grant: queueActionGrant("claim", humanQueuedTask.task_id),
      }),
    });
    assert.equal(missingActorGrantClaimResponse.status, 400);
    assert.match(await missingActorGrantClaimResponse.text(), /queue action actor missing/);

    const actorMismatchGrantClaimResponse = await fetch(`http://127.0.0.1:${humanPort}/api/queue/actions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        action: "claim",
        task_id: humanQueuedTask.task_id,
        owner: "human://local",
        actor: "human://other",
        action_grant: queueActionGrant("claim", humanQueuedTask.task_id),
      }),
    });
    assert.equal(actorMismatchGrantClaimResponse.status, 400);
    assert.match(await actorMismatchGrantClaimResponse.text(), /queue action grant actor mismatch/);

    const actorPolicyDeniedClaimResponse = await fetch(`http://127.0.0.1:${humanPort}/api/queue/actions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        action: "claim",
        task_id: humanQueuedTask.task_id,
        owner: "human://guest",
        actor: "human://guest",
        action_grant: queueActionGrant("claim", humanQueuedTask.task_id, null, { actor: "human://guest" }),
      }),
    });
    assert.equal(actorPolicyDeniedClaimResponse.status, 400);
    assert.match(await actorPolicyDeniedClaimResponse.text(), /queue action actor policy denied/);

    const humanClaimGrant = queueActionGrant("claim", humanQueuedTask.task_id);
    const humanClaimResponse = await fetch(`http://127.0.0.1:${humanPort}/api/queue/actions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        action: "claim",
        task_id: humanQueuedTask.task_id,
        owner: "human://local",
        actor: "human://local",
        action_grant: humanClaimGrant,
      }),
    });
    assert.equal(humanClaimResponse.status, 200);
    const humanClaimBody = await humanClaimResponse.json();
    assert.match(humanClaimBody.lease_id, /^lease:sha256:[0-9a-f]{64}$/);

    const replayedHumanClaimResponse = await fetch(`http://127.0.0.1:${humanPort}/api/queue/actions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        action: "claim",
        task_id: humanQueuedTask.task_id,
        owner: "human://local",
        actor: "human://local",
        action_grant: humanClaimGrant,
      }),
    });
    assert.equal(replayedHumanClaimResponse.status, 400);
    assert.match(await replayedHumanClaimResponse.text(), /queue action grant replay/);

    const humanDrainResponse = await fetch(`http://127.0.0.1:${humanPort}/api/queue/actions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        action: "drain",
        task_id: humanQueuedTask.task_id,
        lease_id: humanClaimBody.lease_id,
        actor: "human://local",
        action_grant: queueActionGrant("drain", humanQueuedTask.task_id),
      }),
    });
    assert.equal(humanDrainResponse.status, 200);
    const humanDrainedQueueState = JSON.parse(await readFile("state/go-fed-discovery-audit-queue/go_fed_task_human_queue_action.json", "utf8"));
    assert.equal(humanDrainedQueueState.status, "completed");
    assert.equal(humanDrainedQueueState.lease_owner, "human://local");

    const humanCreatedQueuedTask = {
      ...task,
      task_id: "go_fed_task_human_created_queue",
      intent: "Create queued task through Human Gateway action.",
    };
    const signedHumanCreatedQueuedTask = { ...humanCreatedQueuedTask, signature: signObject(requester.privateKey, humanCreatedQueuedTask) };
    const humanEnqueueResponse = await fetch(`http://127.0.0.1:${humanPort}/api/queue/actions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        action: "enqueue",
        origin_zone: zoneA.descriptor,
        requester: requester.descriptor,
        task: signedHumanCreatedQueuedTask,
        actor: "human://local",
        action_grant: queueActionGrant("enqueue", humanCreatedQueuedTask.task_id, signedHumanCreatedQueuedTask),
      }),
    });
    assert.equal(humanEnqueueResponse.status, 200);
    const humanEnqueueBody = await humanEnqueueResponse.json();
    assert.equal(humanEnqueueBody.task_id, humanCreatedQueuedTask.task_id);
    const humanCreatedQueueResponse = await fetch(`http://127.0.0.1:${humanPort}/api/queue`);
    assert.equal(humanCreatedQueueResponse.status, 200);
    const humanCreatedQueueBody = await humanCreatedQueueResponse.json();
    assert.equal(humanCreatedQueueBody.queue.some((item) => item.task_id === humanCreatedQueuedTask.task_id && item.status === "queued"), true);

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
      "FED_TASK_EVENT",
      "FED_TASK_EVENT",
      "FED_TASK_EVENT",
      "FED_RECEIPT",
      "FED_TASK_CLOSE",
    ]);
    assert.deepEqual(
      executionFrames.slice(0, 7).map((frame) => frame.event.type),
      ["task.accepted", "approval.required", "approval.granted", "task.started", "checkpoint.created", "artifact.created", "task.completed"],
    );
    const checkpointEvent = executionFrames[4].event.checkpoint;
    const artifactEvent = executionFrames[5].event;
    const approvalGrant = executionFrames[2].event.grant;
    const authorityPublicKey = publicKeyFromDescriptor(fixture.authority);
    const approvalBody = { ...approvalGrant };
    delete approvalBody.approval_signature;
    assert.equal(verifyObject(authorityPublicKey, approvalBody, approvalGrant.approval_signature), true);
    assert.equal(approvalGrant.task_id, task.task_id);
    assert.equal(approvalGrant.authority, fixture.authority.zid);
    assert.deepEqual(approvalGrant.reasons, ["tool"]);
    const receiptFrame = executionFrames[7];
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
    assert.deepEqual(receiptFrame.receipt.artifact_manifests, [artifactEvent.manifest]);
    assert.equal(artifactEvent.manifest.uri, receiptFrame.receipt.artifact_refs[0]);
    assert.match(artifactEvent.manifest.sha256, /^[0-9a-f]{64}$/);
    assert.equal(receiptFrame.receipt.tool_output_digest, artifactEvent.manifest.sha256);
    assert.equal(artifactEvent.manifest.media_type, "text/markdown; charset=utf-8");
    assert.match(artifactEvent.manifest.manifest_hash, /^[0-9a-f]{64}$/);
    assert.equal(receiptFrame.receipt.event_count, 7);
    assert.deepEqual(receiptFrame.receipt.approvals, ["tool"]);
    assert.deepEqual(receiptFrame.receipt.approval_grants, [approvalGrant]);
    assert.deepEqual(receiptFrame.receipt.checkpoint_refs, [checkpointEvent.checkpoint_id]);
    assert.deepEqual(receiptFrame.receipt.checkpoints, [checkpointEvent]);
    const checkpointBody = { ...checkpointEvent };
    delete checkpointBody.checkpoint_signature;
    assert.equal(verifyObject(resolvedWorker.publicKey, checkpointBody, checkpointEvent.checkpoint_signature), true);
    assert.match(checkpointEvent.checkpoint_id, /^checkpoint:sha256:[0-9a-f]{64}$/);
    assert.equal(checkpointEvent.task_id, task.task_id);
    assert.equal(checkpointEvent.parent_checkpoint, null);
    assert.equal(checkpointEvent.event_index, 5);
    assert.match(checkpointEvent.state_digest, /^[0-9a-f]{64}$/);
    assert.deepEqual(checkpointEvent.artifact_refs, []);
    assert.match(checkpointEvent.policy_digest, /^[0-9a-f]{64}$/);
    assert.equal(checkpointEvent.created_by, receiptFrame.worker.aid);
    assert.deepEqual(receiptFrame.receipt.policy_scope, {
      network: false,
      write: [],
      tools: ["mcp.stdio"],
      data_domains: ["public.docs"],
      approval_required: ["tool"],
      expires_at: "2026-07-03T12:00:00Z",
    });
    assert.match(receiptFrame.receipt.policy_digest, /^[0-9a-f]{64}$/);
    assert.equal(receiptFrame.receipt.policy_digest, checkpointEvent.policy_digest);
    assert.equal(receiptFrame.receipt.sandbox.mode, "local-temp-dir");
    assert.equal(receiptFrame.receipt.sandbox.isolation_level, "local-process");
    assert.notEqual(receiptFrame.receipt.sandbox.isolation_level, "container");
    assert.equal(receiptFrame.receipt.sandbox.kind, "mcp");
    assert.deepEqual(receiptFrame.receipt.sandbox.env, ["PATH=/usr/bin:/bin"]);
    assert.equal(receiptFrame.receipt.sandbox.network, "not_granted");
    assert.match(receiptFrame.receipt.sandbox.tool_command_digest, /^[0-9a-f]{64}$/);
    assert.deepEqual(receiptFrame.receipt.sandbox.mcp_session, {
      protocol_version: "2025-11-25",
      server_info: { name: "test-mcp", version: "0" },
    });
    assert.equal(receiptFrame.receipt.sandbox.mcp_resources_count, 1);
    assert.match(receiptFrame.receipt.sandbox.mcp_resources_digest, /^[0-9a-f]{64}$/);
    assert.equal(receiptFrame.receipt.sandbox.mcp_prompts_count, 1);
    assert.match(receiptFrame.receipt.sandbox.mcp_prompts_digest, /^[0-9a-f]{64}$/);
    assert.equal(receiptFrame.receipt.sandbox.mcp_tools_count, 1);
    assert.match(receiptFrame.receipt.sandbox.mcp_tools_digest, /^[0-9a-f]{64}$/);
    assert.equal(receiptFrame.receipt.sandbox.mcp_selected_tool, "translate");
    assert.match(receiptFrame.receipt.sandbox.mcp_selected_tool_digest, /^[0-9a-f]{64}$/);
    assert.match(receiptFrame.receipt.sandbox.mcp_selected_tool_schema_digest, /^[0-9a-f]{64}$/);
    assert.match(receiptFrame.receipt.sandbox.mcp_tool_arguments_digest, /^[0-9a-f]{64}$/);
    assert.equal(receiptFrame.receipt.sandbox.mcp_tool_arguments, undefined);
    assert.equal(receiptFrame.receipt.sandbox_claim, "local-temp-dir");
    const sandboxProof = receiptFrame.receipt.sandbox_proof;
    assert.equal(sandboxProof.proof_type, "local.sandbox.v1");
    assert.equal(sandboxProof.task_id, task.task_id);
    assert.equal(sandboxProof.authority, fixture.authority.zid);
    assert.equal(sandboxProof.worker, receiptFrame.worker.aid);
    assert.equal(sandboxProof.policy_digest, receiptFrame.receipt.policy_digest);
    assert.deepEqual(sandboxProof.sandbox, receiptFrame.receipt.sandbox);
    assert.equal(sandboxProof.sandbox.isolation_level, receiptFrame.receipt.sandbox.isolation_level);
    assert.equal(sandboxProof.sandbox.tool_command_digest, receiptFrame.receipt.sandbox.tool_command_digest);
    assert.deepEqual(sandboxProof.sandbox.mcp_session, receiptFrame.receipt.sandbox.mcp_session);
    assert.equal(sandboxProof.sandbox.mcp_resources_digest, receiptFrame.receipt.sandbox.mcp_resources_digest);
    assert.equal(sandboxProof.sandbox.mcp_prompts_digest, receiptFrame.receipt.sandbox.mcp_prompts_digest);
    assert.equal(sandboxProof.sandbox.mcp_tools_digest, receiptFrame.receipt.sandbox.mcp_tools_digest);
    assert.equal(sandboxProof.sandbox.mcp_selected_tool_digest, receiptFrame.receipt.sandbox.mcp_selected_tool_digest);
    assert.equal(sandboxProof.sandbox.mcp_selected_tool_schema_digest, receiptFrame.receipt.sandbox.mcp_selected_tool_schema_digest);
    assert.equal(sandboxProof.sandbox.mcp_tool_arguments_digest, receiptFrame.receipt.sandbox.mcp_tool_arguments_digest);
    assert.equal(sandboxProof.sandbox_claim, receiptFrame.receipt.sandbox_claim);
    const sandboxProofBody = { ...sandboxProof };
    delete sandboxProofBody.sandbox_signature;
    assert.equal(verifyObject(authorityPublicKey, sandboxProofBody, sandboxProof.sandbox_signature), true);
    assert.equal(receiptFrame.receipt.tool, "mcp.stdio");
    const artifactText = await readFile("artifacts/go_fed_task_verified/go-summary.md", "utf8");
    assert.match(artifactText, /MCP Tool Translation/);
    assert.match(artifactText, /VERIFY FED_TASK_OPEN IN GO\./);
    assert.match(artifactText, /agnet-mcp-/);
    assert.equal(artifactEvent.manifest.size, Buffer.byteLength(artifactText));
    assert.equal(artifactEvent.manifest.sha256, createHash("sha256").update(artifactText).digest("hex"));

    const auditQuery = await execFileAsync(process.execPath, [
      "federation-gateway.mjs",
      "audit",
      String(port),
      "state/node-trusts-go-discovery.json",
      task.task_id,
    ]);
    const auditQueryResult = JSON.parse(auditQuery.stdout);
    assert.equal(auditQueryResult.zone, fixture.authority.zid);
    assert.equal(auditQueryResult.task_id, task.task_id);
    assert.equal(auditQueryResult.receipt.task_id, task.task_id);
    assert.deepEqual(auditQueryResult.receipt.sandbox_proof, sandboxProof);
    assert.deepEqual(auditQueryResult.receipt.checkpoints, [checkpointEvent]);
    assert.deepEqual(auditQueryResult.receipt.artifact_manifests, [artifactEvent.manifest]);

    const auditFrames = await exchangeFrames(port, {
      type: "FED_AUDIT_QUERY",
      origin_zone: zoneA.descriptor,
      task_id: task.task_id,
    }, "FED_AUDIT_CLOSE");
    assert.deepEqual(auditFrames.map((frame) => frame.type), ["FED_AUDIT_RESULT", "FED_AUDIT_CLOSE"]);
    assert.equal(auditFrames[0].task_id, task.task_id);
    assert.deepEqual(auditFrames[0].receipt.checkpoints, [checkpointEvent]);
    assert.deepEqual(auditFrames[0].receipt.artifact_manifests, [artifactEvent.manifest]);

    const resumeTask = {
      ...task,
      task_id: "go_fed_task_resumed",
      intent: "Resume FED_TASK_OPEN from checkpoint.",
    };
    const resumeFrames = await exchangeFrames(port, {
      type: "FED_TASK_RESUME",
      origin_zone: zoneA.descriptor,
      requester: requester.descriptor,
      checkpoint_id: checkpointEvent.checkpoint_id,
      task: { ...resumeTask, signature: signObject(requester.privateKey, resumeTask) },
    });
    assert.deepEqual(resumeFrames.map((frame) => frame.type), [
      "FED_TASK_EVENT",
      "FED_TASK_EVENT",
      "FED_TASK_EVENT",
      "FED_TASK_EVENT",
      "FED_TASK_EVENT",
      "FED_TASK_EVENT",
      "FED_TASK_EVENT",
      "FED_RECEIPT",
      "FED_TASK_CLOSE",
    ]);
    const resumedCheckpoint = resumeFrames[4].event.checkpoint;
    const resumeReceipt = resumeFrames[7].receipt;
    assert.equal(resumedCheckpoint.task_id, resumeTask.task_id);
    assert.equal(resumedCheckpoint.parent_checkpoint, checkpointEvent.checkpoint_id);
    assert.equal(resumeReceipt.task_id, resumeTask.task_id);
    assert.equal(resumeReceipt.resumed_from, checkpointEvent.checkpoint_id);
    assert.deepEqual(resumeReceipt.checkpoint_refs, [resumedCheckpoint.checkpoint_id]);
    assert.deepEqual(resumeReceipt.checkpoints, [resumedCheckpoint]);

    const queuedResumeTask = {
      ...task,
      task_id: "go_fed_task_queued_resume",
      intent: "Queue resume from checkpoint.",
    };
    const queuedResumeFrames = await exchangeFrames(port, {
      type: "FED_QUEUE_RESUME",
      origin_zone: zoneA.descriptor,
      requester: requester.descriptor,
      checkpoint_id: checkpointEvent.checkpoint_id,
      task: { ...queuedResumeTask, signature: signObject(requester.privateKey, queuedResumeTask) },
    }, "FED_QUEUE_RESUME_CLOSE");
    assert.deepEqual(queuedResumeFrames.map((frame) => frame.type), ["FED_QUEUE_RESUME_ACCEPTED", "FED_QUEUE_RESUME_CLOSE"]);
    const queuedResumeState = JSON.parse(await readFile("state/go-fed-discovery-audit-queue/go_fed_task_queued_resume.json", "utf8"));
    assert.equal(queuedResumeState.status, "queued");
    assert.equal(queuedResumeState.resume_checkpoint, checkpointEvent.checkpoint_id);

    const queuedResumeClaimFrames = await exchangeFrames(port, {
      type: "FED_QUEUE_CLAIM",
      origin_zone: zoneA.descriptor,
      task_id: queuedResumeTask.task_id,
      owner: "scheduler://resume",
    }, "FED_QUEUE_CLAIM_CLOSE");
    assert.deepEqual(queuedResumeClaimFrames.map((frame) => frame.type), ["FED_QUEUE_CLAIMED", "FED_QUEUE_CLAIM_CLOSE"]);
    const queuedResumeDrainFrames = await exchangeFrames(port, {
      type: "FED_QUEUE_DRAIN",
      origin_zone: zoneA.descriptor,
      task_id: queuedResumeTask.task_id,
      lease_id: queuedResumeClaimFrames[0].lease_id,
    });
    assert.deepEqual(queuedResumeDrainFrames.map((frame) => frame.type), [
      "FED_TASK_EVENT",
      "FED_TASK_EVENT",
      "FED_TASK_EVENT",
      "FED_TASK_EVENT",
      "FED_TASK_EVENT",
      "FED_TASK_EVENT",
      "FED_TASK_EVENT",
      "FED_RECEIPT",
      "FED_TASK_CLOSE",
    ]);
    const queuedResumeReceipt = queuedResumeDrainFrames[7].receipt;
    const queuedResumeCheckpoint = queuedResumeDrainFrames[4].event.checkpoint;
    assert.equal(queuedResumeReceipt.task_id, queuedResumeTask.task_id);
    assert.equal(queuedResumeReceipt.resumed_from, checkpointEvent.checkpoint_id);
    assert.equal(queuedResumeCheckpoint.parent_checkpoint, checkpointEvent.checkpoint_id);

    const unknownCheckpointTask = {
      ...task,
      task_id: "go_fed_task_resume_unknown_checkpoint",
      intent: "Resume from an unknown checkpoint.",
    };
    const unknownCheckpointFrames = await exchangeFrames(port, {
      type: "FED_TASK_RESUME",
      origin_zone: zoneA.descriptor,
      requester: requester.descriptor,
      checkpoint_id: `checkpoint:sha256:${"0".repeat(64)}`,
      task: { ...unknownCheckpointTask, signature: signObject(requester.privateKey, unknownCheckpointTask) },
    });
    assert.equal(unknownCheckpointFrames[0].type, "FED_TASK_ERROR");
    assert.match(unknownCheckpointFrames[0].error, /resume checkpoint not found/);

    const retryTask = {
      ...task,
      task_id: "go_fed_task_retried",
      intent: "Retry FED_TASK_OPEN with lineage evidence.",
    };
    const retryFrames = await exchangeFrames(port, {
      type: "FED_TASK_RETRY",
      origin_zone: zoneA.descriptor,
      requester: requester.descriptor,
      retry_of: task.task_id,
      task: { ...retryTask, signature: signObject(requester.privateKey, retryTask) },
    });
    assert.deepEqual(retryFrames.map((frame) => frame.type), [
      "FED_TASK_EVENT",
      "FED_TASK_EVENT",
      "FED_TASK_EVENT",
      "FED_TASK_EVENT",
      "FED_TASK_EVENT",
      "FED_TASK_EVENT",
      "FED_TASK_EVENT",
      "FED_RECEIPT",
      "FED_TASK_CLOSE",
    ]);
    const retryReceipt = retryFrames[7].receipt;
    assert.equal(retryReceipt.task_id, retryTask.task_id);
    assert.equal(retryReceipt.retry_of, task.task_id);

    const retryAuditFrames = await exchangeFrames(port, {
      type: "FED_AUDIT_QUERY",
      origin_zone: zoneA.descriptor,
      task_id: retryTask.task_id,
    }, "FED_AUDIT_CLOSE");
    assert.deepEqual(retryAuditFrames.map((frame) => frame.type), ["FED_AUDIT_RESULT", "FED_AUDIT_CLOSE"]);
    assert.equal(retryAuditFrames[0].receipt.retry_of, task.task_id);

    const strictTask = {
      ...task,
      task_id: "go_fed_task_missing_mcp_required_arg",
      to: "agent://zone-b/strict-translator",
    };
    const strictFrames = await exchangeFrames(port, {
      type: "FED_TASK_OPEN",
      origin_zone: zoneA.descriptor,
      requester: requester.descriptor,
      task: { ...strictTask, signature: signObject(requester.privateKey, strictTask) },
    });
    assert.equal(strictFrames.at(-1).type, "FED_TASK_ERROR");
    assert.match(strictFrames.at(-1).error, /mcp tool arguments missing required field: locale/);
    const failedTaskState = JSON.parse(await readFile("state/go-fed-discovery-audit-tasks/go_fed_task_missing_mcp_required_arg.json", "utf8"));
    assert.equal(failedTaskState.task_id, strictTask.task_id);
    assert.equal(failedTaskState.status, "failed");
    assert.match(failedTaskState.error, /mcp tool arguments missing required field: locale/);

    const missingRetryOfFrames = await exchangeFrames(port, {
      type: "FED_TASK_RETRY",
      origin_zone: zoneA.descriptor,
      requester: requester.descriptor,
      task: { ...retryTask, task_id: "go_fed_retry_missing_parent", signature: signObject(requester.privateKey, { ...retryTask, task_id: "go_fed_retry_missing_parent" }) },
    });
    assert.equal(missingRetryOfFrames[0].type, "FED_TASK_ERROR");
    assert.match(missingRetryOfFrames[0].error, /retry_of missing/);

    const cancel = {
      task_id: "go_fed_task_cancelled",
      from: requester.aid,
      to: "agent://zone-b/translator",
      reason: "operator requested cancellation",
    };
    const cancelFrames = await exchangeFrames(port, {
      type: "FED_TASK_CANCEL",
      origin_zone: zoneA.descriptor,
      requester: requester.descriptor,
      cancel: { ...cancel, signature: signObject(requester.privateKey, cancel) },
    }, "FED_CANCEL_CLOSE");
    assert.deepEqual(cancelFrames.map((frame) => frame.type), [
      "FED_TASK_EVENT",
      "FED_RECEIPT",
      "FED_CANCEL_CLOSE",
    ]);
    assert.deepEqual(cancelFrames[0].event, {
      type: "task.cancelled",
      task_id: cancel.task_id,
      by: requester.aid,
      worker: receiptFrame.worker.aid,
      reason: cancel.reason,
    });
    const cancelReceipt = cancelFrames[1].receipt;
    const cancelReceiptBody = { ...cancelReceipt };
    delete cancelReceiptBody.signature;
    assert.equal(verifyObject(resolvedWorker.publicKey, cancelReceiptBody, cancelReceipt.signature), true);
    assert.equal(cancelReceipt.task_id, cancel.task_id);
    assert.equal(cancelReceipt.status, "cancelled");
    assert.deepEqual(cancelReceipt.cancel, { ...cancel, signature: signObject(requester.privateKey, cancel) });

    const completedTaskState = JSON.parse(await readFile("state/go-fed-discovery-audit-tasks/go_fed_task_verified.json", "utf8"));
    assert.equal(completedTaskState.task_id, task.task_id);
    assert.equal(completedTaskState.status, "completed");
    assert.equal(completedTaskState.worker, receiptFrame.worker.aid);
    assert.equal(completedTaskState.receipt_digest, createHash("sha256").update(JSON.stringify(receiptFrame.receipt)).digest("hex"));

    const cancelledTaskState = JSON.parse(await readFile("state/go-fed-discovery-audit-tasks/go_fed_task_cancelled.json", "utf8"));
    assert.equal(cancelledTaskState.task_id, cancel.task_id);
    assert.equal(cancelledTaskState.status, "cancelled");
    assert.equal(cancelledTaskState.worker, receiptFrame.worker.aid);
    assert.equal(cancelledTaskState.receipt_digest, createHash("sha256").update(JSON.stringify(cancelReceipt)).digest("hex"));

    const slowTask = {
      ...task,
      task_id: "go_fed_task_live_cancelled",
      to: "agent://zone-b/slow",
      intent: "Run slowly until cancelled.",
    };
    const slowStartedAt = Date.now();
    const slowExecution = exchangeFrames(port, {
      type: "FED_TASK_OPEN",
      origin_zone: zoneA.descriptor,
      requester: requester.descriptor,
      task: { ...slowTask, signature: signObject(requester.privateKey, slowTask) },
    });
    await new Promise((resolve) => setTimeout(resolve, 250));
    const runningTaskState = JSON.parse(await readFile("state/go-fed-discovery-audit-tasks/go_fed_task_live_cancelled.json", "utf8"));
    assert.equal(runningTaskState.task_id, slowTask.task_id);
    assert.equal(runningTaskState.status, "running");
    assert.equal(runningTaskState.worker, resolvedSlowResult.aid);
    const liveCancel = {
      task_id: slowTask.task_id,
      from: requester.aid,
      to: "agent://zone-b/slow",
      reason: "stop running slow task",
    };
    const liveCancelFrames = await exchangeFrames(port, {
      type: "FED_TASK_CANCEL",
      origin_zone: zoneA.descriptor,
      requester: requester.descriptor,
      cancel: { ...liveCancel, signature: signObject(requester.privateKey, liveCancel) },
    }, "FED_CANCEL_CLOSE");
    assert.equal(liveCancelFrames[1].receipt.status, "cancelled");
    const slowFrames = await slowExecution;
    assert.equal(slowFrames.at(-1).type, "FED_TASK_ERROR");
    assert.match(slowFrames.at(-1).error, /external tool cancelled/);
    assert.ok(Date.now() - slowStartedAt < 1500);

    const cancelAuditFrames = await exchangeFrames(port, {
      type: "FED_AUDIT_QUERY",
      origin_zone: zoneA.descriptor,
      task_id: cancel.task_id,
    }, "FED_AUDIT_CLOSE");
    assert.deepEqual(cancelAuditFrames.map((frame) => frame.type), ["FED_AUDIT_RESULT", "FED_AUDIT_CLOSE"]);
    assert.equal(cancelAuditFrames[0].receipt.status, "cancelled");
    assert.equal(cancelAuditFrames[0].receipt.cancel.task_id, cancel.task_id);

    const tamperedCancelFrames = await exchangeFrames(port, {
      type: "FED_TASK_CANCEL",
      origin_zone: zoneA.descriptor,
      requester: requester.descriptor,
      cancel: { ...cancel, reason: "tampered", signature: signObject(requester.privateKey, cancel) },
    }, "FED_CANCEL_CLOSE");
    assert.equal(tamperedCancelFrames[0].type, "FED_TASK_ERROR");
    assert.match(tamperedCancelFrames[0].error, /cancel signature verification failed/);

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
    assert.equal(deniedFrames[0].code, "policy.network_denied");
    assert.match(deniedFrames[0].error, /policy denied network access/);

    const verifiedAudit = await execFileAsync("go", [
      "run",
      "./cmd/go-fed-discovery",
      "--verify-audit",
      "--audit",
      "state/go-fed-discovery-audit.log",
    ]);
    assert.match(verifiedAudit.stdout, /"go_audit_verify":"ok"/);

    const auditResponse = await fetch(`http://127.0.0.1:${humanPort}/api/audit`);
    assert.equal(auditResponse.status, 200);
    const auditBody = await auditResponse.json();
    assert.equal(auditBody.entries.length, 77);
    const queueActionRecords = auditBody.entries
      .map((entry) => entry.record)
      .filter((record) => record.kind === "go_queue_action");
    assert.equal(queueActionRecords.some((record) => record.action === "claim" && record.task_id === humanQueuedTask.task_id && record.status === "ok"), true);
    assert.equal(queueActionRecords.some((record) => record.action === "drain" && record.task_id === humanQueuedTask.task_id && record.status === "ok"), true);
    assert.equal(queueActionRecords.some((record) => record.action === "enqueue" && record.task_id === humanCreatedQueuedTask.task_id && record.status === "ok"), true);
    assert.equal(queueActionRecords.some((record) => record.action === "claim" && record.task_id === humanQueuedTask.task_id && record.status === "error" && /grant missing/.test(record.error)), true);
    assert.equal(queueActionRecords.some((record) => record.action === "claim" && record.task_id === humanQueuedTask.task_id && record.status === "error" && /grant expired/.test(record.error)), true);
    assert.equal(queueActionRecords.some((record) => record.action === "claim" && record.task_id === humanQueuedTask.task_id && record.status === "error" && /scope mismatch/.test(record.error)), true);
    assert.equal(queueActionRecords.some((record) => record.action === "claim" && record.task_id === humanQueuedTask.task_id && record.status === "error" && /actor missing/.test(record.error)), true);
    assert.equal(queueActionRecords.some((record) => record.action === "claim" && record.task_id === humanQueuedTask.task_id && record.status === "error" && /actor mismatch/.test(record.error)), true);
    assert.equal(queueActionRecords.some((record) => record.action === "claim" && record.task_id === humanQueuedTask.task_id && record.status === "error" && /actor policy denied/.test(record.error)), true);
    assert.equal(queueActionRecords.some((record) => record.action === "claim" && record.task_id === humanQueuedTask.task_id && record.status === "error" && /grant replay/.test(record.error)), true);
    assert.equal(queueActionRecords.filter((record) => record.status === "ok").every((record) => /^[0-9a-f]{64}$/.test(record.grant_digest)), true);

    const tasksResponse = await fetch(`http://127.0.0.1:${humanPort}/api/tasks`);
    assert.equal(tasksResponse.status, 200);
    const tasksBody = await tasksResponse.json();
    const taskStates = new Map(tasksBody.tasks.map((item) => [item.task_id, item]));
    assert.equal(taskStates.get("go_fed_task_verified").status, "completed");
    assert.equal(taskStates.get("go_fed_task_cancelled").status, "cancelled");
    assert.equal(taskStates.get("go_fed_task_missing_mcp_required_arg").status, "failed");
    assert.equal(taskStates.get("go_fed_task_live_cancelled").status, "cancelled");

    const pageResponse = await fetch(`http://127.0.0.1:${humanPort}/`);
    assert.equal(pageResponse.status, 200);
    const pageText = await pageResponse.text();
    assert.match(pageText, /Agent Space Human Gateway/);
    assert.match(pageText, /Tasks/);
    assert.match(pageText, /Queue/);
    assert.match(pageText, /go_fed_task_human_queue_action/);
    assert.match(pageText, /go_fed_task_live_cancelled/);
    assert.match(pageText, /cancelled/);
    assert.match(pageText, /agent:\/\/zone-b\/translator/);
    assert.match(pageText, /go_fed_task_verified/);
    assert.match(pageText, /1 signed/);
    assert.match(pageText, /local-temp-dir/);

    const artifactResponse = await fetch(`http://127.0.0.1:${humanPort}/artifacts/go_fed_task_verified/go-summary.md`);
    assert.equal(artifactResponse.status, 200);
    assert.match(await artifactResponse.text(), /MCP Tool Translation/);
  } finally {
    try {
      process.kill(-gateway.pid, "SIGINT");
    } catch {
      gateway.kill("SIGINT");
    }
  }
});
