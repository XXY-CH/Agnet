import { execFile, spawn } from "node:child_process";
import net from "node:net";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { promisify } from "node:util";
import { createHash } from "node:crypto";
import { canonical, createAgent, createZone, publicKeyFromDescriptor, signObject, verifyObject } from "../asp-core.mjs";

const execFileAsync = promisify(execFile);
await mkdir("state", { recursive: true });
const originZone = createZone("zone://public-node-proof-origin");
await writeFile("state/public-node-proof-trusted.json", `${JSON.stringify({ zones: [originZone.descriptor] }, null, 2)}\n`);
const fixture = JSON.parse(await readFile("test-vectors/asp-v1.5-capability-credential.json", "utf8"));
await writeFile("state/public-node-proof-authority.seed", `${fixture.authority_seed_hex}\n`);
await writeFile("state/public-node-proof-worker.seed", `${fixture.worker_seed_hex}\n`);
const receiptFramePath = "state/public-node-proof-fed-receipt.json";
const receiptTrustedPath = "state/public-node-proof-trusted-zones.json";
const swarmCloseFramePath = "state/public-node-proof-swarm-close.json";
const swarmCloseTrustedPath = "state/public-node-proof-swarm-close-trusted-zones.json";
await rm("state/public-node-proof-audit.log", { force: true });
await rm(swarmCloseFramePath, { force: true });
await rm(swarmCloseTrustedPath, { force: true });
await rm("artifacts/public_node_probe_task", { force: true, recursive: true });

const binary = process.argv[2] ?? "state/public-node-proof-go";
const child = spawn(binary, [
  "--listen-host",
  "0.0.0.0",
  "--port",
  "0",
  "--trusted",
  "state/public-node-proof-trusted.json",
  "--authority-key",
  "state/public-node-proof-authority.seed",
  "--worker-key",
  "state/public-node-proof-worker.seed",
  "--audit",
  "state/public-node-proof-audit.log",
], { stdio: ["ignore", "pipe", "inherit"] });
process.on("exit", () => child.kill("SIGTERM"));

const timer = setTimeout(() => {
  child.kill("SIGKILL");
  console.error("public node proof timeout");
  process.exit(1);
}, 60000);

let output = "";
for await (const chunk of child.stdout) {
  output += chunk;
  const line = output.split("\n").find((item) => item.trim().startsWith("{"));
  if (!line) continue;
  const status = JSON.parse(line);
  if (status.public_transport !== true) throw new Error("public transport proof failed");
  const resolved = await resolveAlias(status.port, originZone, "agent://zone-b/summarizer");
  const queried = await queryCapability(status.port, originZone, "summarize.text");
  const task = await openTask(status.port, originZone);
  const audited = await auditTask(status.port, originZone, task.taskId);
  await writeFile(receiptFramePath, `${JSON.stringify(audited.frame, null, 2)}\n`);
  await writeFile(receiptTrustedPath, `${JSON.stringify({ zones: [audited.frame.zone] }, null, 2)}\n`);
  const artifact = await readArtifact(status.port, originZone, task.taskId, audited.frame.receipt.artifact_refs[0]);
  await mkdir(dirname(artifact.file), { recursive: true });
  await writeFile(artifact.file, artifact.bytes);
  const artifactVerify = await execFileAsync(process.execPath, ["asp-verify.mjs", "fed-receipt-artifacts", receiptFramePath, receiptTrustedPath]);
  const artifactReject = await rejectArtifact(status.port, originZone, task.taskId, "artifact://local/public_node_probe_task/not-in-receipt.md");
  await writeFile(artifact.file, tamperedBytes(artifact.bytes));
  const artifactTamperReject = await rejectArtifact(status.port, originZone, task.taskId, audited.frame.receipt.artifact_refs[0]);
  await writeFile(artifact.file, artifact.bytes);
  const swarm = await openSwarm(status.port, originZone);
  await writeFile(swarmCloseFramePath, `${JSON.stringify(swarm.closeFrame, null, 2)}\n`);
  await writeFile(swarmCloseTrustedPath, `${JSON.stringify({ zones: [swarm.closeFrame.zone] }, null, 2)}\n`);
  clearTimeout(timer);
  child.kill("SIGTERM");
  console.log(JSON.stringify({
    public_node_proof: "ok",
    listen_host: status.listen_host,
    port: status.port,
    public_transport: status.public_transport,
    transport: status.transport,
    resolve_alias: resolved.alias,
    resolve_close: resolved.close,
    query_capability: queried.capability,
    query_match_count: queried.matchCount,
    query_status: queried.status,
    task_id: task.taskId,
    task_receipt: task.receipt,
    task_close: task.close,
    audit_task_id: audited.taskId,
    audit_receipt: audited.receipt,
    audit_close: audited.close,
    receipt_frame: receiptFramePath,
    trusted_zones: receiptTrustedPath,
    artifact_file: artifact.file,
    fed_receipt_artifacts_verify: JSON.parse(artifactVerify.stdout).fed_receipt_artifacts_verify,
    artifact_reject: artifactReject.rejected,
    artifact_reject_error: artifactReject.error,
    artifact_tamper_reject: artifactTamperReject.rejected,
    artifact_tamper_error: artifactTamperReject.error,
    swarm_id: swarm.swarmId,
    swarm_step_count: swarm.stepReceipts.length,
    swarm_step_ids: swarm.stepReceipts.map((step) => step.step_id),
    swarm_close_signature: swarm.closeSignature,
    swarm_close_receipts: swarm.closeReceipts,
    swarm_close_digest: swarm.closeDigest,
    swarm_close_frame: swarmCloseFramePath,
    swarm_close_trusted_zones: swarmCloseTrustedPath,
  }));
  process.exit(0);
}

clearTimeout(timer);
process.exitCode = child.exitCode ?? 1;

function authBody(sessionId, challenge, peerZid, remoteZid) {
  return { session_id: sessionId, challenge, peer_zid: peerZid, remote_zid: remoteZid };
}

function resolveAlias(port, zone, alias) {
  let gotResult = false;
  return exchangeFrame(
    port,
    zone,
    { type: "FED_RESOLVE", origin_zone: zone.descriptor, alias },
    "FED_RESOLVE_CLOSE",
    (frame) => {
      if (frame.type === "FED_RESOLVE_RESULT") gotResult = frame.worker?.alias === alias;
      if (frame.type === "FED_RESOLVE_CLOSE") return { alias, close: gotResult && frame.alias === alias };
      return null;
    },
  );
}

function queryCapability(port, zone, capability) {
  let matchCount = 0;
  let status = "";
  return exchangeFrame(
    port,
    zone,
    { type: "FED_QUERY", origin_zone: zone.descriptor, capability },
    "FED_QUERY_CLOSE",
    (frame) => {
      if (frame.type === "FED_QUERY_RESULT") {
        matchCount = frame.matches?.length ?? 0;
        status = frame.matches?.[0]?.credential_statuses?.[0]?.status ?? "";
      }
      if (frame.type === "FED_QUERY_CLOSE") return { capability, matchCount, status };
      return null;
    },
  );
}

function openTask(port, zone) {
  const requester = createAgent("agent://public-node-proof/requester");
  const task = {
    task_id: "public_node_probe_task",
    from: requester.aid,
    to: "agent://zone-b/summarizer",
    intent: "Prove public-listen FED_TASK_OPEN.",
    scope: { network: false },
    budget: { time_seconds: 30 },
  };
  let gotReceipt = false;
  return exchangeFrame(
    port,
    zone,
    {
      type: "FED_TASK_OPEN",
      origin_zone: zone.descriptor,
      requester: requester.descriptor,
      task: { ...task, signature: signObject(requester.privateKey, task) },
    },
    "FED_TASK_CLOSE",
    (frame) => {
      if (frame.type === "FED_RECEIPT") gotReceipt = frame.receipt?.task_id === task.task_id;
      if (frame.type === "FED_TASK_CLOSE") return { taskId: task.task_id, receipt: gotReceipt, close: frame.task_id === task.task_id };
      return null;
    },
  );
}

function auditTask(port, zone, taskId) {
  let gotReceipt = false;
  let resultFrame = null;
  return exchangeFrame(
    port,
    zone,
    { type: "FED_AUDIT_QUERY", origin_zone: zone.descriptor, task_id: taskId },
    "FED_AUDIT_CLOSE",
    (frame) => {
      if (frame.type === "FED_AUDIT_RESULT") {
        resultFrame = frame;
        gotReceipt = frame.receipt?.task_id === taskId;
      }
      if (frame.type === "FED_AUDIT_CLOSE") return { taskId, receipt: gotReceipt, close: frame.task_id === taskId, frame: resultFrame };
      return null;
    },
  );
}

function openSwarm(port, zone) {
  const requester = createAgent("agent://public-node-proof/swarm-requester");
  const summaryTask = {
    task_id: "public_node_swarm_summary",
    from: requester.aid,
    to: "agent://zone-b/summarizer",
    intent: "Prove public-listen FED_SWARM_OPEN summary step.",
    scope: { network: false },
    budget: { time_seconds: 30 },
  };
  const dependentTask = {
    task_id: "public_node_swarm_dependent",
    from: requester.aid,
    to: "agent://zone-b/summarizer",
    intent: "Prove public-listen FED_SWARM_OPEN dependent step.",
    scope: { network: false },
    budget: { time_seconds: 30 },
  };
  const receipts = [];
  return exchangeFrame(
    port,
    zone,
    {
      type: "FED_SWARM_OPEN",
      origin_zone: zone.descriptor,
      requester: requester.descriptor,
      swarm: {
        swarm_id: "swarm://public-node-proof/two-step",
        steps: [
          { step_id: "summary", task: { ...summaryTask, signature: signObject(requester.privateKey, summaryTask) } },
          { step_id: "dependent", after: ["summary"], task: { ...dependentTask, signature: signObject(requester.privateKey, dependentTask) } },
        ],
      },
    },
    "FED_SWARM_CLOSE",
    (frame) => {
      if (frame.type === "FED_RECEIPT") receipts.push(frame.receipt);
      if (frame.type !== "FED_SWARM_CLOSE") return null;
      const close = frame.close;
      const { close_signature, ...body } = close;
      const authorityKey = publicKeyFromDescriptor(fixture.authority);
      const expected = receipts.map((receipt) => ({
        step_id: receipt.swarm.step_id,
        task_id: receipt.task_id,
        receipt_digest: digestJson(receipt),
      }));
      return {
        swarmId: close.swarm_id,
        stepReceipts: close.step_receipts,
        closeSignature: verifyObject(authorityKey, body, close_signature),
        closeReceipts: sameStepReceipts(close.step_receipts, expected),
        closeDigest: digestJson(body),
        closeFrame: { ...frame, zone: fixture.authority },
      };
    },
  );
}

function sameStepReceipts(actual, expected) {
  return actual.length === expected.length && actual.every((step, index) =>
    step.step_id === expected[index].step_id &&
    step.task_id === expected[index].task_id &&
    step.receipt_digest === expected[index].receipt_digest
  );
}

function readArtifact(port, zone, taskId, uri) {
  let artifact = null;
  return exchangeFrame(
    port,
    zone,
    { type: "FED_ARTIFACT_READ", origin_zone: zone.descriptor, task_id: taskId, uri },
    "FED_ARTIFACT_CLOSE",
    (frame) => {
      if (frame.type === "FED_ARTIFACT") {
        artifact = { file: artifactFilePath(frame.uri), bytes: Buffer.from(frame.bytes_b64, "base64url") };
      }
      if (frame.type === "FED_ARTIFACT_CLOSE") return artifact;
      return null;
    },
  );
}

async function rejectArtifact(port, zone, taskId, uri) {
  try {
    await readArtifact(port, zone, taskId, uri);
    return { rejected: false, error: "" };
  } catch (error) {
    return { rejected: true, error: error.message };
  }
}

function digestJson(value) {
  return createHash("sha256").update(canonical(value)).digest("hex");
}

function tamperedBytes(bytes) {
  if (bytes.length === 0) throw new Error("cannot tamper empty artifact");
  const tampered = Buffer.from(bytes);
  tampered[0] ^= 1;
  return tampered;
}

function artifactFilePath(uri) {
  const prefix = "artifact://local/";
  if (!uri.startsWith(prefix)) throw new Error(`unsupported artifact uri: ${uri}`);
  return `artifacts/${uri.slice(prefix.length)}`;
}

function exchangeFrame(port, zone, request, closeType, collect) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(Number(port), "127.0.0.1");
    let buffer = "";
    socket.on("error", reject);
    socket.on("connect", () => {
      socket.write(`${JSON.stringify({ type: "HELLO", origin_zone: zone.descriptor })}\n`);
    });
    socket.on("data", (chunk) => {
      buffer += chunk.toString();
      const lines = buffer.split("\n");
      buffer = lines.pop();
      for (const line of lines) {
        if (!line.trim()) continue;
        const frame = JSON.parse(line);
        if (frame.type === "HELLO") {
          const body = authBody(frame.session_id, frame.challenge, zone.descriptor.zid, frame.zone.zid);
          socket.write(`${JSON.stringify({
            type: "AUTH",
            origin_zone: zone.descriptor,
            auth: { ...body, auth_signature: signObject(zone.privateKey, body) },
          })}\n`);
          continue;
        }
        if (frame.type === "AUTH_OK") {
          socket.write(`${JSON.stringify(request)}\n`);
          continue;
        }
        const result = collect(frame);
        if (frame.type === closeType && result) {
          socket.end();
          resolve(result);
          return;
        }
        if (frame.type === "FED_TASK_ERROR") {
          reject(new Error(frame.error));
        }
      }
    });
  });
}
