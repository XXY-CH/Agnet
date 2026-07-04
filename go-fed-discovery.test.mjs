import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { readFile, rm, writeFile } from "node:fs/promises";
import net from "node:net";
import { test } from "node:test";
import { promisify } from "node:util";
import { canonical, capabilityCredentialId, createAgent, loadOrCreateAgent, loadOrCreateZone, loadRegistry, publicKeyFromDescriptor, resolveAgent, rotationProof, signObject, verifyAliasRebindingProof, verifyCredentialStatus, verifyObject, writeTrustedZones } from "./asp-core.mjs";

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

function exchangeFramesUntil(port, frame, predicate, closeType = "FED_TASK_CLOSE") {
  const frames = [];
  let checkpointResolved = false;
  let resolveCheckpoint;
  let rejectCheckpoint;
  let resolveDone;
  let rejectDone;
  const checkpoint = new Promise((resolve, reject) => {
    resolveCheckpoint = resolve;
    rejectCheckpoint = reject;
  });
  const done = new Promise((resolve, reject) => {
    resolveDone = resolve;
    rejectDone = reject;
  });
  const socket = net.createConnection(port, "127.0.0.1");
  let buffer = "";
  const fail = (error) => {
    rejectCheckpoint(error);
    rejectDone(error);
  };
  socket.on("error", fail);
  socket.on("connect", () => {
    socket.write(`${JSON.stringify({ type: "HELLO", origin_zone: frame.origin_zone })}\n`);
  });
  socket.on("data", (chunk) => {
    try {
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
        if (!checkpointResolved && predicate(item, frames)) {
          checkpointResolved = true;
          resolveCheckpoint(frames);
        }
        if (item.type === "FED_TASK_ERROR" || item.type === closeType) {
          socket.end();
          if (!checkpointResolved) {
            checkpointResolved = true;
            resolveCheckpoint(frames);
          }
          resolveDone(frames);
        }
      }
    } catch (error) {
      socket.destroy();
      fail(error);
    }
  });
  return { checkpoint, done };
}

let zoneA;
let humanToken;

function authBody(sessionId, challenge, peerZid, remoteZid) {
  return { session_id: sessionId, challenge, peer_zid: peerZid, remote_zid: remoteZid };
}

function humanHeaders() {
  return { "content-type": "application/json", authorization: `Bearer ${humanToken}` };
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

async function approveTask(humanPort, taskId, actor = "human://local") {
  const response = await fetch(`http://127.0.0.1:${humanPort}/api/approvals/actions`, {
    method: "POST",
    headers: humanHeaders(),
    body: JSON.stringify({ action: "approve", task_id: taskId, actor }),
  });
  assert.equal(response.status, 200);
  return response.json();
}

async function denyTask(humanPort, taskId) {
  const response = await fetch(`http://127.0.0.1:${humanPort}/api/approvals/actions`, {
    method: "POST",
    headers: humanHeaders(),
    body: JSON.stringify({ action: "deny", task_id: taskId, actor: "human://local" }),
  });
  assert.equal(response.status, 200);
  return response.json();
}

async function waitForPendingApproval(humanPort, taskId) {
  for (let attempt = 0; attempt < 40; attempt += 1) {
    const response = await fetch(`http://127.0.0.1:${humanPort}/api/approvals`);
    assert.equal(response.status, 200);
    const body = await response.json();
    const pending = body.approvals.find((item) => item.task_id === taskId && item.status === "pending");
    if (pending) return pending;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error(`pending approval not found for ${taskId}`);
}

async function approvalState(humanPort, taskId) {
  const response = await fetch(`http://127.0.0.1:${humanPort}/api/approvals`);
  assert.equal(response.status, 200);
  const body = await response.json();
  return body.approvals.find((item) => item.task_id === taskId);
}

async function exchangeFramesWithHumanApproval(port, humanPort, frame, taskId, closeType = "FED_TASK_CLOSE") {
  const run = exchangeFramesUntil(
    port,
    frame,
    (item) => item.type === "FED_TASK_EVENT" && item.event.type === "approval.required",
    closeType,
  );
  const frames = await run.checkpoint;
  if (frames.some((item) => item.type === "FED_TASK_EVENT" && item.event.type === "approval.required")) {
    await approveTask(humanPort, taskId);
  }
  return run.done;
}

async function fetchQueueActionWithHumanApproval(humanPort, taskId, body) {
  const responsePromise = fetch(`http://127.0.0.1:${humanPort}/api/queue/actions`, {
    method: "POST",
    headers: humanHeaders(),
    body: JSON.stringify(body),
  });
  const pending = await waitForPendingApproval(humanPort, taskId);
  assert.equal(pending.reasons.includes("tool"), true);
  await approveTask(humanPort, taskId);
  return responsePromise;
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
  humanToken = "test-human-gateway-token";
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
      result: { content: [{ type: "text", text: \`# MCP Tool Translation\\n\\nTask: \${args.task_id}\\nTranslation: \${String(args.intent).toUpperCase()}\\nCWD: \${process.cwd()}\\nHOME: \${process.env.HOME}\\nTMPDIR: \${process.env.TMPDIR}\\nXDG_CACHE_HOME: \${process.env.XDG_CACHE_HOME}\\n\` }] }
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
  await rm("state/go-fed-discovery-audit-approvals", { recursive: true, force: true });
  await rm("state/go-fed-discovery-audit-queue-grants", { recursive: true, force: true });
  await rm("state/go-fed-artifact-store", { recursive: true, force: true });
  await rm("state/go-fed-discovery-requester-registry.json", { force: true });
  await rm("state/go-fed-discovery-requester-rebindings.json", { force: true });
  await writeFile("state/go-fed-discovery-actor-policy.json", `${JSON.stringify({
    queue_actions: {
      "human://local": ["enqueue", "claim", "drain"],
      "human://guest": ["enqueue"],
    },
    approval_actions: {
      "human://local": ["approve", "deny"],
      "human://operator": ["approve"],
    },
  }, null, 2)}\n`);
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
    "--human-token",
    humanToken,
    "--human-actor-policy",
    "state/go-fed-discovery-actor-policy.json",
    "--artifact-store",
    "state/go-fed-artifact-store",
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

    const drainRun = exchangeFramesUntil(port, {
      type: "FED_QUEUE_DRAIN",
      origin_zone: zoneA.descriptor,
      task_id: queuedTask.task_id,
      lease_id: reclaimFrames[0].lease_id,
    }, (item) => item.type === "FED_TASK_EVENT" && item.event.type === "approval.required");
    await drainRun.checkpoint;
    const drainPending = await waitForPendingApproval(humanPort, queuedTask.task_id);
    assert.equal(drainPending.reasons.includes("tool"), true);
    await approveTask(humanPort, queuedTask.task_id);
    const drainedFrames = await drainRun.done;
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
    const failedDrainFrames = await exchangeFramesWithHumanApproval(port, humanPort, {
      type: "FED_QUEUE_DRAIN",
      origin_zone: zoneA.descriptor,
      task_id: failedQueuedTask.task_id,
      lease_id: failedClaimFrames[0].lease_id,
    }, failedQueuedTask.task_id);
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

    const securityResponse = await fetch(`http://127.0.0.1:${humanPort}/api/security`);
    assert.equal(securityResponse.status, 200);
    const securityBody = await securityResponse.json();
    assert.equal(securityBody.listen_host, "127.0.0.1");
    assert.equal(securityBody.write_token_required, true);
    assert.equal(securityBody.public_transport, false);

    const missingTokenQueueActionResponse = await fetch(`http://127.0.0.1:${humanPort}/api/queue/actions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ action: "claim", task_id: humanQueuedTask.task_id, owner: "human://local" }),
    });
    assert.equal(missingTokenQueueActionResponse.status, 401);
    assert.match(await missingTokenQueueActionResponse.text(), /human gateway token required/);

    const rawTokenQueueActionResponse = await fetch(`http://127.0.0.1:${humanPort}/api/queue/actions`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: humanToken },
      body: JSON.stringify({ action: "claim", task_id: humanQueuedTask.task_id, owner: "human://local" }),
    });
    assert.equal(rawTokenQueueActionResponse.status, 401);
    assert.match(await rawTokenQueueActionResponse.text(), /human gateway token required/);

    const missingTokenApprovalResponse = await fetch(`http://127.0.0.1:${humanPort}/api/approvals/actions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ action: "approve", task_id: humanQueuedTask.task_id, actor: "human://local" }),
    });
    assert.equal(missingTokenApprovalResponse.status, 401);
    assert.match(await missingTokenApprovalResponse.text(), /human gateway token required/);

    const unauthorisedHumanClaimResponse = await fetch(`http://127.0.0.1:${humanPort}/api/queue/actions`, {
      method: "POST",
      headers: humanHeaders(),
      body: JSON.stringify({ action: "claim", task_id: humanQueuedTask.task_id, owner: "human://local" }),
    });
    assert.equal(unauthorisedHumanClaimResponse.status, 400);
    assert.match(await unauthorisedHumanClaimResponse.text(), /queue action grant missing/);

    const expiredGrantClaimResponse = await fetch(`http://127.0.0.1:${humanPort}/api/queue/actions`, {
      method: "POST",
      headers: humanHeaders(),
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
      headers: humanHeaders(),
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
      headers: humanHeaders(),
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
      headers: humanHeaders(),
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
      headers: humanHeaders(),
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

    const guestCreatedQueuedTask = {
      ...task,
      task_id: "go_fed_task_guest_created_queue",
      intent: "Create queued task through configured guest actor policy.",
    };
    const signedGuestCreatedQueuedTask = { ...guestCreatedQueuedTask, signature: signObject(requester.privateKey, guestCreatedQueuedTask) };
    const guestCreatedQueueResponse = await fetch(`http://127.0.0.1:${humanPort}/api/queue/actions`, {
      method: "POST",
      headers: humanHeaders(),
      body: JSON.stringify({
        action: "enqueue",
        origin_zone: zoneA.descriptor,
        requester: requester.descriptor,
        task: signedGuestCreatedQueuedTask,
        actor: "human://guest",
        action_grant: queueActionGrant("enqueue", guestCreatedQueuedTask.task_id, signedGuestCreatedQueuedTask, { actor: "human://guest" }),
      }),
    });
    assert.equal(guestCreatedQueueResponse.status, 200);
    const guestCreatedQueueBody = await guestCreatedQueueResponse.json();
    assert.equal(guestCreatedQueueBody.task_id, guestCreatedQueuedTask.task_id);

    const humanClaimGrant = queueActionGrant("claim", humanQueuedTask.task_id);
    const humanClaimGrantDigest = createHash("sha256").update(canonical(humanClaimGrant)).digest("hex");
    const humanClaimResponse = await fetch(`http://127.0.0.1:${humanPort}/api/queue/actions`, {
      method: "POST",
      headers: humanHeaders(),
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
    const grantUse = JSON.parse(await readFile(`state/go-fed-discovery-audit-queue-grants/${humanClaimGrantDigest}.json`, "utf8"));
    assert.equal(grantUse.grant_digest, humanClaimGrantDigest);
    assert.equal(grantUse.action, "claim");
    assert.equal(grantUse.task_id, humanQueuedTask.task_id);
    assert.equal(grantUse.actor, "human://local");

    const replayedHumanClaimResponse = await fetch(`http://127.0.0.1:${humanPort}/api/queue/actions`, {
      method: "POST",
      headers: humanHeaders(),
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

    const humanDrainResponse = await fetchQueueActionWithHumanApproval(humanPort, humanQueuedTask.task_id, {
      action: "drain",
      task_id: humanQueuedTask.task_id,
      lease_id: humanClaimBody.lease_id,
      actor: "human://local",
      action_grant: queueActionGrant("drain", humanQueuedTask.task_id),
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
      headers: humanHeaders(),
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

    const humanDraftedTaskId = "go_fed_task_human_drafted_queue";
    const humanDraftResponse = await fetch(`http://127.0.0.1:${humanPort}/api/queue/drafts`, {
      method: "POST",
      headers: humanHeaders(),
      body: JSON.stringify({
        task_id: humanDraftedTaskId,
        to: "agent://zone-b/translator",
        intent: "Draft and sign queued task through Human Gateway.",
        scope: task.scope,
        budget: task.budget,
      }),
    });
    assert.equal(humanDraftResponse.status, 200);
    const humanDraftBody = await humanDraftResponse.json();
    assert.equal(humanDraftBody.task.task_id, humanDraftedTaskId);
    assert.equal(humanDraftBody.task.from, humanDraftBody.requester.aid);
    assert.match(humanDraftBody.task.signature, /^[A-Za-z0-9_-]+$/);
    const humanDraftedQueueResponse = await fetch(`http://127.0.0.1:${humanPort}/api/queue`);
    assert.equal(humanDraftedQueueResponse.status, 200);
    const humanDraftedQueueBody = await humanDraftedQueueResponse.json();
    assert.equal(humanDraftedQueueBody.queue.some((item) => item.task_id === humanDraftedTaskId && item.status === "queued"), true);

    const browserHeldTask = {
      ...task,
      task_id: "go_fed_task_browser_signed_draft",
      intent: "Enqueue browser-held signed requester task through Human Gateway.",
    };
    const signedBrowserHeldTask = { ...browserHeldTask, signature: signObject(requester.privateKey, browserHeldTask) };
    const browserHeldDraftResponse = await fetch(`http://127.0.0.1:${humanPort}/api/queue/drafts`, {
      method: "POST",
      headers: humanHeaders(),
      body: JSON.stringify({
        requester: requester.descriptor,
        task: signedBrowserHeldTask,
      }),
    });
    assert.equal(browserHeldDraftResponse.status, 200);
    const browserHeldDraftBody = await browserHeldDraftResponse.json();
    assert.equal(browserHeldDraftBody.requester.aid, requester.aid);
    assert.equal(browserHeldDraftBody.task.task_id, browserHeldTask.task_id);
    assert.equal(browserHeldDraftBody.task.from, requester.aid);
    assert.equal(browserHeldDraftBody.task.signature, signedBrowserHeldTask.signature);
    const browserHeldQueueResponse = await fetch(`http://127.0.0.1:${humanPort}/api/queue`);
    assert.equal(browserHeldQueueResponse.status, 200);
    const browserHeldQueueBody = await browserHeldQueueResponse.json();
    assert.equal(browserHeldQueueBody.queue.some((item) => item.task_id === browserHeldTask.task_id && item.status === "queued"), true);

    const previousBrowserRequester = createAgent("agent://browser/requester");
    const nextBrowserRequester = createAgent("agent://browser/requester");
    const browserRotationProof = rotationProof(previousBrowserRequester, nextBrowserRequester);
    const browserRebindingResponse = await fetch(`http://127.0.0.1:${humanPort}/api/requester/rebindings`, {
      method: "POST",
      headers: humanHeaders(),
      body: JSON.stringify({
        previous_descriptor: previousBrowserRequester.descriptor,
        next_descriptor: nextBrowserRequester.descriptor,
        rotation_proof: browserRotationProof,
      }),
    });
    assert.equal(browserRebindingResponse.status, 200);
    const browserRebindingBody = await browserRebindingResponse.json();
    assert.equal(browserRebindingBody.alias_rebinding_proof.alias, "agent://browser/requester");
    assert.equal(browserRebindingBody.alias_rebinding_proof.agent_rotation_proof.previous_aid, previousBrowserRequester.aid);
    assert.equal(verifyAliasRebindingProof(
      browserRebindingBody.alias_rebinding_proof,
      browserRebindingBody.authority_descriptor,
      previousBrowserRequester.descriptor,
      nextBrowserRequester.descriptor,
    ), true);
    const browserRequesterRegistry = await loadRegistry("state/go-fed-discovery-requester-registry.json");
    const reboundBrowserRequester = resolveAgent(browserRequesterRegistry, "agent://browser/requester");
    assert.equal(reboundBrowserRequester.descriptor.aid, nextBrowserRequester.aid);
    assert.equal(reboundBrowserRequester.zone.zid, browserRebindingBody.authority_descriptor.zid);
    const browserRebindingHistoryResponse = await fetch(`http://127.0.0.1:${humanPort}/api/requester/rebindings`);
    assert.equal(browserRebindingHistoryResponse.status, 200);
    const browserRebindingHistoryBody = await browserRebindingHistoryResponse.json();
    assert.equal(browserRebindingHistoryBody.rebindings.length, 1);
    assert.equal(browserRebindingHistoryBody.rebindings[0].alias, "agent://browser/requester");
    assert.equal(browserRebindingHistoryBody.rebindings[0].previous_aid, previousBrowserRequester.aid);
    assert.equal(browserRebindingHistoryBody.rebindings[0].next_aid, nextBrowserRequester.aid);

    const previousBrowserAssistant = createAgent("agent://browser/assistant");
    const nextBrowserAssistant = createAgent("agent://browser/assistant");
    const browserAssistantRotationProof = rotationProof(previousBrowserAssistant, nextBrowserAssistant);
    const browserAssistantRebindingResponse = await fetch(`http://127.0.0.1:${humanPort}/api/requester/rebindings`, {
      method: "POST",
      headers: humanHeaders(),
      body: JSON.stringify({
        previous_descriptor: previousBrowserAssistant.descriptor,
        next_descriptor: nextBrowserAssistant.descriptor,
        rotation_proof: browserAssistantRotationProof,
      }),
    });
    assert.equal(browserAssistantRebindingResponse.status, 200);
    const multiRequesterRegistry = await loadRegistry("state/go-fed-discovery-requester-registry.json");
    assert.equal(resolveAgent(multiRequesterRegistry, "agent://browser/requester").descriptor.aid, nextBrowserRequester.aid);
    assert.equal(resolveAgent(multiRequesterRegistry, "agent://browser/assistant").descriptor.aid, nextBrowserAssistant.aid);
    const requesterRegistryResponse = await fetch(`http://127.0.0.1:${humanPort}/api/requester/registry`);
    assert.equal(requesterRegistryResponse.status, 200);
    const requesterRegistryBody = await requesterRegistryResponse.json();
    assert.equal(requesterRegistryBody.agents.length, 2);
    assert.equal(requesterRegistryBody.agents.some((entry) => entry.descriptor.alias === "agent://browser/requester"), true);
    assert.equal(requesterRegistryBody.agents.some((entry) => entry.descriptor.alias === "agent://browser/assistant"), true);

    const deniedApprovalTask = {
      ...task,
      task_id: "go_fed_task_approval_denied",
      intent: "Require explicit denial before tool execution.",
    };
    const deniedApprovalExecution = exchangeFramesUntil(port, {
      type: "FED_TASK_OPEN",
      origin_zone: zoneA.descriptor,
      requester: requester.descriptor,
      task: { ...deniedApprovalTask, signature: signObject(requester.privateKey, deniedApprovalTask) },
    }, (item) => item.type === "FED_TASK_EVENT" && item.event.type === "approval.required");
    await deniedApprovalExecution.checkpoint;
    const denyBody = await denyTask(humanPort, deniedApprovalTask.task_id);
    assert.equal(denyBody.approval.task_id, deniedApprovalTask.task_id);
    assert.equal(denyBody.approval.status, "denied");
    const deniedApprovalFrames = await deniedApprovalExecution.done;
    assert.equal(deniedApprovalFrames.at(-1).type, "FED_TASK_ERROR");
    assert.match(deniedApprovalFrames.at(-1).error, /approval denied/);
    assert.equal(deniedApprovalFrames.some((frame) => frame.type === "FED_TASK_EVENT" && frame.event.type === "task.started"), false);
    const deniedApprovalState = await approvalState(humanPort, deniedApprovalTask.task_id);
    assert.equal(deniedApprovalState.status, "denied");

    const expiredApprovalTask = {
      ...task,
      task_id: "go_fed_task_approval_expired",
      intent: "Expire pending approval before tool execution.",
      approval_expires_at: "2000-01-01T00:00:00Z",
    };
    const expiredApprovalFrames = await exchangeFrames(port, {
      type: "FED_TASK_OPEN",
      origin_zone: zoneA.descriptor,
      requester: requester.descriptor,
      task: { ...expiredApprovalTask, signature: signObject(requester.privateKey, expiredApprovalTask) },
    });
    assert.equal(expiredApprovalFrames.at(-1).type, "FED_TASK_ERROR");
    assert.match(expiredApprovalFrames.at(-1).error, /approval expired/);
    assert.equal(expiredApprovalFrames.some((frame) => frame.type === "FED_TASK_EVENT" && frame.event.type === "task.started"), false);
    const expiredApprovalState = await approvalState(humanPort, expiredApprovalTask.task_id);
    assert.equal(expiredApprovalState.status, "expired");

    const execution = exchangeFramesUntil(port, {
      type: "FED_TASK_OPEN",
      origin_zone: zoneA.descriptor,
      requester: requester.descriptor,
      task: { ...task, signature: signObject(requester.privateKey, task) },
    }, (item) => item.type === "FED_TASK_EVENT" && item.event.type === "approval.required");
    const approvalRequiredFrames = await execution.checkpoint;
    assert.deepEqual(
      approvalRequiredFrames.map((frame) => frame.type),
      ["FED_TASK_EVENT", "FED_TASK_EVENT"],
    );
    assert.deepEqual(
      approvalRequiredFrames.map((frame) => frame.event.type),
      ["task.accepted", "approval.required"],
    );
    const pendingApprovalResponse = await fetch(`http://127.0.0.1:${humanPort}/api/approvals`);
    assert.equal(pendingApprovalResponse.status, 200);
    const pendingApprovalBody = await pendingApprovalResponse.json();
    assert.equal(pendingApprovalBody.approvals.some((item) => item.task_id === task.task_id && item.status === "pending" && item.reasons.includes("tool")), true);
    const guestApprovalResponse = await fetch(`http://127.0.0.1:${humanPort}/api/approvals/actions`, {
      method: "POST",
      headers: humanHeaders(),
      body: JSON.stringify({ action: "approve", task_id: task.task_id, actor: "human://guest" }),
    });
    assert.equal(guestApprovalResponse.status, 400);
    assert.match(await guestApprovalResponse.text(), /approval actor policy denied/);
    const approveBody = await approveTask(humanPort, task.task_id, "human://operator");
    assert.equal(approveBody.approval.task_id, task.task_id);
    assert.equal(approveBody.approval.by, "human://operator");
    assert.match(approveBody.approval.approval_signature, /^[A-Za-z0-9_-]+$/);
    const executionFrames = await execution.done;
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
    assert.equal(approvalGrant.by, "human://operator");
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
    const transcriptRef = "artifact://local/go_fed_task_verified/tool-transcript.json";
    assert.deepEqual(receiptFrame.receipt.artifact_refs, ["artifact://local/go_fed_task_verified/go-summary.md", transcriptRef]);
    assert.deepEqual(receiptFrame.receipt.artifact_manifests[0], artifactEvent.manifest);
    const transcriptManifest = receiptFrame.receipt.artifact_manifests[1];
    assert.equal(transcriptManifest.uri, transcriptRef);
    assert.equal(transcriptManifest.media_type, "application/json; charset=utf-8");
    assert.equal(transcriptManifest.sha256, receiptFrame.receipt.sandbox.tool_transcript_digest);
    assert.match(transcriptManifest.manifest_hash, /^[0-9a-f]{64}$/);
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
    assert.deepEqual(receiptFrame.receipt.sandbox.env, [
      "PATH=/usr/bin:/bin",
      `HOME=${receiptFrame.receipt.sandbox.cwd}`,
      `TMPDIR=${receiptFrame.receipt.sandbox.cwd}`,
      `XDG_CACHE_HOME=${receiptFrame.receipt.sandbox.cwd}/cache`,
    ]);
    assert.equal(receiptFrame.receipt.sandbox.network, "not_granted");
    assert.match(receiptFrame.receipt.sandbox.tool_command_digest, /^[0-9a-f]{64}$/);
    assert.match(receiptFrame.receipt.sandbox.tool_binary_digest, /^[0-9a-f]{64}$/);
    assert.match(receiptFrame.receipt.sandbox.tool_transcript_digest, /^[0-9a-f]{64}$/);
    assert.equal(receiptFrame.receipt.sandbox.tool_transcript_ref, transcriptRef);
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
    assert.equal(sandboxProof.sandbox.tool_binary_digest, receiptFrame.receipt.sandbox.tool_binary_digest);
    assert.equal(sandboxProof.sandbox.tool_transcript_digest, receiptFrame.receipt.sandbox.tool_transcript_digest);
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
    const escapedSandboxCwd = receiptFrame.receipt.sandbox.cwd.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    assert.match(artifactText, new RegExp(`HOME: ${escapedSandboxCwd}`));
    assert.match(artifactText, new RegExp(`TMPDIR: ${escapedSandboxCwd}`));
    assert.match(artifactText, new RegExp(`XDG_CACHE_HOME: ${escapedSandboxCwd}/cache`));
    assert.equal(artifactEvent.manifest.size, Buffer.byteLength(artifactText));
    assert.equal(artifactEvent.manifest.sha256, createHash("sha256").update(artifactText).digest("hex"));
    const artifactManifestSidecar = JSON.parse(await readFile("artifacts/go_fed_task_verified/go-summary.md.manifest.json", "utf8"));
    assert.deepEqual(artifactManifestSidecar, artifactEvent.manifest);
    const digestArtifactPath = `artifacts/by-sha256/${artifactEvent.manifest.sha256}`;
    assert.equal(await readFile(digestArtifactPath, "utf8"), artifactText);
    const digestArtifactManifestSidecar = JSON.parse(await readFile(`${digestArtifactPath}.manifest.json`, "utf8"));
    assert.deepEqual(digestArtifactManifestSidecar, artifactEvent.manifest);
    const mirrorArtifactPath = `state/go-fed-artifact-store/by-sha256/${artifactEvent.manifest.sha256}`;
    assert.equal(await readFile(mirrorArtifactPath, "utf8"), artifactText);
    const mirrorArtifactManifestSidecar = JSON.parse(await readFile(`${mirrorArtifactPath}.manifest.json`, "utf8"));
    assert.deepEqual(mirrorArtifactManifestSidecar, artifactEvent.manifest);
    const transcriptText = await readFile("artifacts/go_fed_task_verified/tool-transcript.json", "utf8");
    assert.equal(createHash("sha256").update(transcriptText).digest("hex"), receiptFrame.receipt.sandbox.tool_transcript_digest);
    assert.match(JSON.parse(transcriptText).result.content[0].text, /MCP Tool Translation/);
    const transcriptManifestSidecar = JSON.parse(await readFile("artifacts/go_fed_task_verified/tool-transcript.json.manifest.json", "utf8"));
    assert.deepEqual(transcriptManifestSidecar, transcriptManifest);
    const mirrorTranscriptPath = `state/go-fed-artifact-store/by-sha256/${transcriptManifest.sha256}`;
    assert.equal(await readFile(mirrorTranscriptPath, "utf8"), transcriptText);
    const mirrorTranscriptManifestSidecar = JSON.parse(await readFile(`${mirrorTranscriptPath}.manifest.json`, "utf8"));
    assert.deepEqual(mirrorTranscriptManifestSidecar, transcriptManifest);

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
    assert.deepEqual(auditQueryResult.receipt.artifact_manifests, [artifactEvent.manifest, transcriptManifest]);

    const auditFrames = await exchangeFrames(port, {
      type: "FED_AUDIT_QUERY",
      origin_zone: zoneA.descriptor,
      task_id: task.task_id,
    }, "FED_AUDIT_CLOSE");
    assert.deepEqual(auditFrames.map((frame) => frame.type), ["FED_AUDIT_RESULT", "FED_AUDIT_CLOSE"]);
    assert.equal(auditFrames[0].task_id, task.task_id);
    assert.deepEqual(auditFrames[0].receipt.checkpoints, [checkpointEvent]);
    assert.deepEqual(auditFrames[0].receipt.artifact_manifests, [artifactEvent.manifest, transcriptManifest]);

    const resumeTask = {
      ...task,
      task_id: "go_fed_task_resumed",
      intent: "Resume FED_TASK_OPEN from checkpoint.",
    };
    const resumeFrames = await exchangeFramesWithHumanApproval(port, humanPort, {
      type: "FED_TASK_RESUME",
      origin_zone: zoneA.descriptor,
      requester: requester.descriptor,
      checkpoint_id: checkpointEvent.checkpoint_id,
      task: { ...resumeTask, signature: signObject(requester.privateKey, resumeTask) },
    }, resumeTask.task_id);
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
    const queuedResumeDrainFrames = await exchangeFramesWithHumanApproval(port, humanPort, {
      type: "FED_QUEUE_DRAIN",
      origin_zone: zoneA.descriptor,
      task_id: queuedResumeTask.task_id,
      lease_id: queuedResumeClaimFrames[0].lease_id,
    }, queuedResumeTask.task_id);
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
    assert.equal(queuedResumeReceipt.restored_state_digest, checkpointEvent.state_digest);
    assert.equal(queuedResumeCheckpoint.parent_checkpoint, checkpointEvent.checkpoint_id);
    assert.equal(queuedResumeCheckpoint.restored_state_digest, checkpointEvent.state_digest);

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
    const retryFrames = await exchangeFramesWithHumanApproval(port, humanPort, {
      type: "FED_TASK_RETRY",
      origin_zone: zoneA.descriptor,
      requester: requester.descriptor,
      retry_of: task.task_id,
      task: { ...retryTask, signature: signObject(requester.privateKey, retryTask) },
    }, retryTask.task_id);
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
    const strictFrames = await exchangeFramesWithHumanApproval(port, humanPort, {
      type: "FED_TASK_OPEN",
      origin_zone: zoneA.descriptor,
      requester: requester.descriptor,
      task: { ...strictTask, signature: signObject(requester.privateKey, strictTask) },
    }, strictTask.task_id);
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
    const slowExecution = exchangeFramesUntil(port, {
      type: "FED_TASK_OPEN",
      origin_zone: zoneA.descriptor,
      requester: requester.descriptor,
      task: { ...slowTask, signature: signObject(requester.privateKey, slowTask) },
    }, (item) => item.type === "FED_TASK_EVENT" && item.event.type === "approval.required");
    await slowExecution.checkpoint;
    await approveTask(humanPort, slowTask.task_id);
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
    const slowFrames = await slowExecution.done;
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
      "--artifact-store",
      "state/go-fed-artifact-store",
      "--audit",
      "state/go-fed-discovery-audit.log",
    ]);
    assert.match(verifiedAudit.stdout, /"go_audit_verify":"ok"/);
    await writeFile("artifacts/go_fed_task_verified/go-summary.md.manifest.json", "{}\n");
    await assert.rejects(
      execFileAsync("go", [
        "run",
        "./cmd/go-fed-discovery",
        "--verify-audit",
        "--audit",
        "state/go-fed-discovery-audit.log",
      ]),
      /artifact manifest sidecar mismatch/,
    );
    await writeFile("artifacts/go_fed_task_verified/go-summary.md.manifest.json", `${JSON.stringify(artifactEvent.manifest, null, 2)}\n`);
    await writeFile(`${digestArtifactPath}.manifest.json`, "{}\n");
    await assert.rejects(
      execFileAsync("go", [
        "run",
        "./cmd/go-fed-discovery",
        "--verify-audit",
        "--audit",
        "state/go-fed-discovery-audit.log",
      ]),
      /artifact digest sidecar mismatch/,
    );
    await writeFile(`${digestArtifactPath}.manifest.json`, `${JSON.stringify(artifactEvent.manifest, null, 2)}\n`);
    await writeFile("artifacts/go_fed_task_verified/go-summary.md", "x".repeat(Buffer.byteLength(artifactText)));
    await assert.rejects(
      execFileAsync("go", [
        "run",
        "./cmd/go-fed-discovery",
        "--verify-audit",
        "--audit",
        "state/go-fed-discovery-audit.log",
      ]),
      /artifact bytes digest mismatch/,
    );
    await writeFile("artifacts/go_fed_task_verified/go-summary.md", artifactText);
    await writeFile(`${mirrorArtifactPath}.manifest.json`, "{}\n");
    await assert.rejects(
      execFileAsync("go", [
        "run",
        "./cmd/go-fed-discovery",
        "--verify-audit",
        "--artifact-store",
        "state/go-fed-artifact-store",
        "--audit",
        "state/go-fed-discovery-audit.log",
      ]),
      /artifact mirror sidecar mismatch/,
    );
    await writeFile(`${mirrorArtifactPath}.manifest.json`, `${JSON.stringify(artifactEvent.manifest, null, 2)}\n`);
    await writeFile(mirrorArtifactPath, "x".repeat(Buffer.byteLength(artifactText)));
    await assert.rejects(
      execFileAsync("go", [
        "run",
        "./cmd/go-fed-discovery",
        "--verify-audit",
        "--artifact-store",
        "state/go-fed-artifact-store",
        "--audit",
        "state/go-fed-discovery-audit.log",
      ]),
      /artifact mirror bytes digest mismatch/,
    );
    await writeFile(mirrorArtifactPath, artifactText);

    const auditResponse = await fetch(`http://127.0.0.1:${humanPort}/api/audit`);
    assert.equal(auditResponse.status, 200);
    const auditBody = await auditResponse.json();
    assert.equal(auditBody.entries.length, 84);
    const queueActionRecords = auditBody.entries
      .map((entry) => entry.record)
      .filter((record) => record.kind === "go_queue_action");
    assert.equal(queueActionRecords.some((record) => record.action === "claim" && record.task_id === humanQueuedTask.task_id && record.status === "ok" && record.actor === "human://local" && record.actor_policy_result === "allow"), true);
    assert.equal(queueActionRecords.some((record) => record.action === "drain" && record.task_id === humanQueuedTask.task_id && record.status === "ok" && record.actor === "human://local" && record.actor_policy_result === "allow"), true);
    assert.equal(queueActionRecords.some((record) => record.action === "enqueue" && record.task_id === humanCreatedQueuedTask.task_id && record.status === "ok" && record.actor === "human://local" && record.actor_policy_result === "allow"), true);
    assert.equal(queueActionRecords.some((record) => record.action === "enqueue" && record.task_id === humanDraftedTaskId && record.status === "ok" && record.actor === "human://local" && record.actor_policy_result === "allow"), true);
    assert.equal(queueActionRecords.some((record) => record.action === "enqueue" && record.task_id === browserHeldTask.task_id && record.status === "ok" && record.actor === "human://local" && record.actor_policy_result === "allow"), true);
    assert.equal(queueActionRecords.some((record) => record.action === "enqueue" && record.task_id === guestCreatedQueuedTask.task_id && record.status === "ok" && record.actor === "human://guest" && record.actor_policy_result === "allow"), true);
    assert.equal(queueActionRecords.some((record) => record.action === "claim" && record.task_id === humanQueuedTask.task_id && record.status === "error" && /grant missing/.test(record.error) && record.actor === ""), true);
    assert.equal(queueActionRecords.some((record) => record.action === "claim" && record.task_id === humanQueuedTask.task_id && record.status === "error" && /grant expired/.test(record.error) && record.actor === "human://local" && record.actor_policy_result === "allow"), true);
    assert.equal(queueActionRecords.some((record) => record.action === "claim" && record.task_id === humanQueuedTask.task_id && record.status === "error" && /scope mismatch/.test(record.error) && record.actor === "human://local" && record.actor_policy_result === undefined), true);
    assert.equal(queueActionRecords.some((record) => record.action === "claim" && record.task_id === humanQueuedTask.task_id && record.status === "error" && /actor missing/.test(record.error) && record.actor === "human://local" && record.actor_policy_result === undefined), true);
    assert.equal(queueActionRecords.some((record) => record.action === "claim" && record.task_id === humanQueuedTask.task_id && record.status === "error" && /actor mismatch/.test(record.error) && record.actor === "human://other" && record.actor_policy_result === undefined), true);
    assert.equal(queueActionRecords.some((record) => record.action === "claim" && record.task_id === humanQueuedTask.task_id && record.status === "error" && /actor policy denied/.test(record.error) && record.actor === "human://guest" && record.actor_policy_result === "deny"), true);
    assert.equal(queueActionRecords.some((record) => record.action === "claim" && record.task_id === humanQueuedTask.task_id && record.status === "error" && /grant replay/.test(record.error) && record.actor === "human://local" && record.actor_policy_result === "allow"), true);
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
    assert.match(pageText, /Browser Requester Key/);
    assert.match(pageText, /Requester Registry/);
    assert.match(pageText, /agent:\/\/browser\/assistant/);
    assert.match(pageText, /Requester Rebindings/);
    assert.match(pageText, new RegExp(previousBrowserRequester.aid.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
    assert.match(pageText, new RegExp(nextBrowserRequester.aid.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
    assert.match(pageText, /crypto\.subtle\.generateKey/);
    assert.match(pageText, /agent-space-browser-requester/);
    assert.match(pageText, /Export Key/);
    assert.match(pageText, /Import Key/);
    assert.match(pageText, /Rotate Key/);
    assert.match(pageText, /Bind Alias/);
    assert.match(pageText, /browser-export-key/);
    assert.match(pageText, /browser-import-key/);
    assert.match(pageText, /browser-rotate-key/);
    assert.match(pageText, /browser-rebind-key/);
    assert.match(pageText, /rotation_proof/);
    assert.match(pageText, /previous_descriptor/);
    assert.match(pageText, /next_descriptor/);
    assert.match(pageText, /previous_signature/);
    assert.match(pageText, /next_signature/);
    assert.match(pageText, /descriptor_signature/);
    assert.match(pageText, /\/api\/queue\/drafts/);
    assert.match(pageText, /\/api\/requester\/rebindings/);
    assert.match(pageText, /1 signed/);
    assert.match(pageText, /local-temp-dir/);

    const artifactResponse = await fetch(`http://127.0.0.1:${humanPort}/artifacts/go_fed_task_verified/go-summary.md`);
    assert.equal(artifactResponse.status, 200);
    assert.match(await artifactResponse.text(), /MCP Tool Translation/);
    const digestArtifactResponse = await fetch(`http://127.0.0.1:${humanPort}/artifacts/by-sha256/${artifactEvent.manifest.sha256}`);
    assert.equal(digestArtifactResponse.status, 200);
    assert.equal(await digestArtifactResponse.text(), artifactText);
    const artifactManifestResponse = await fetch(`http://127.0.0.1:${humanPort}/api/artifacts/manifest?uri=${encodeURIComponent(artifactEvent.manifest.uri)}`);
    assert.equal(artifactManifestResponse.status, 200);
    assert.deepEqual(await artifactManifestResponse.json(), artifactEvent.manifest);
  } finally {
    try {
      process.kill(-gateway.pid, "SIGINT");
    } catch {
      gateway.kill("SIGINT");
    }
  }
});
