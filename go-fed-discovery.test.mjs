import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { readFile, rm, writeFile } from "node:fs/promises";
import net from "node:net";
import { test } from "node:test";
import { promisify } from "node:util";
import { capabilityCredentialId, loadOrCreateAgent, loadOrCreateZone, publicKeyFromDescriptor, resolveAgent, signObject, verifyCredentialStatus, verifyObject, writeTrustedZones } from "./asp-core.mjs";

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
  ];
  delete goFixture.worker_profile;
  await writeFile("state/go-fed-discovery-dynamic-worker.json", `${JSON.stringify(goFixture, null, 2)}\n`);
  await writeFile("state/go-fed-discovery-authority.seed", `${fixture.authority_seed_hex}\n`);
  await writeFile("state/go-fed-discovery-worker.seed", `${fixture.worker_seed_hex}\n`);
  await writeFile("state/go-fed-discovery-translator.seed", "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f\n");
  await writeFile("state/go-fed-mcp-server.mjs", `
import readline from "node:readline";
const rl = readline.createInterface({ input: process.stdin });
rl.on("line", (line) => {
  const message = JSON.parse(line);
  if (message.method === "initialize") {
    process.stdout.write(JSON.stringify({
      jsonrpc: "2.0",
      id: message.id,
      result: { protocolVersion: message.params.protocolVersion, capabilities: { tools: {} }, serverInfo: { name: "test-mcp", version: "0" } }
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
  await rm("state/go-fed-discovery-audit.log", { force: true });
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

    const task = {
      task_id: "go_fed_task_verified",
      from: requester.aid,
      to: "agent://zone-b/translator",
      intent: "Verify FED_TASK_OPEN in Go.",
      scope: { network: false, data_domains: ["public.docs"], expires_at: "2026-07-03T12:00:00Z" },
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
    assert.equal(receiptFrame.receipt.sandbox.kind, "mcp");
    assert.deepEqual(receiptFrame.receipt.sandbox.env, ["PATH=/usr/bin:/bin"]);
    assert.equal(receiptFrame.receipt.sandbox.network, "not_granted");
    assert.equal(receiptFrame.receipt.sandbox_claim, "local-temp-dir");
    const sandboxProof = receiptFrame.receipt.sandbox_proof;
    assert.equal(sandboxProof.proof_type, "local.sandbox.v1");
    assert.equal(sandboxProof.task_id, task.task_id);
    assert.equal(sandboxProof.authority, fixture.authority.zid);
    assert.equal(sandboxProof.worker, receiptFrame.worker.aid);
    assert.equal(sandboxProof.policy_digest, receiptFrame.receipt.policy_digest);
    assert.deepEqual(sandboxProof.sandbox, receiptFrame.receipt.sandbox);
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
    assert.equal(auditBody.entries.length, 26);

    const pageResponse = await fetch(`http://127.0.0.1:${humanPort}/`);
    assert.equal(pageResponse.status, 200);
    const pageText = await pageResponse.text();
    assert.match(pageText, /Agent Space Human Gateway/);
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
