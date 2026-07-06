import { spawn } from "node:child_process";
import net from "node:net";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { createAgent, createZone, signObject } from "../asp-core.mjs";

await mkdir("state", { recursive: true });
const originZone = createZone("zone://public-node-proof-origin");
await writeFile("state/public-node-proof-trusted.json", `${JSON.stringify({ zones: [originZone.descriptor] }, null, 2)}\n`);
const fixture = JSON.parse(await readFile("test-vectors/asp-v1.5-capability-credential.json", "utf8"));
await writeFile("state/public-node-proof-authority.seed", `${fixture.authority_seed_hex}\n`);
await writeFile("state/public-node-proof-worker.seed", `${fixture.worker_seed_hex}\n`);
const receiptFramePath = "state/public-node-proof-fed-receipt.json";
const receiptTrustedPath = "state/public-node-proof-trusted-zones.json";

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
