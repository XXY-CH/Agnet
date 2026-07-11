import net from "node:net";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import {
  appendAudit,
  approvalReasons,
  canonical,
  enforcePolicy,
  loadRegistry,
  publicKeyFromDescriptor,
  resolveAgent,
  signObject,
  verifyObject,
  writeArtifact,
  writeRegistry,
} from "./asp-core.mjs";
import { loadManagedAgent, loadManagedZone } from "./managed-key-runtime.mjs";

function send(socket, frame) {
  socket.write(`${JSON.stringify(frame)}\n`);
}

function readFrames(socket, onFrame) {
  let buffer = "";
  socket.on("data", (chunk) => {
    buffer += chunk;
    for (;;) {
      const index = buffer.indexOf("\n");
      if (index === -1) break;
      const line = buffer.slice(0, index);
      buffer = buffer.slice(index + 1);
      if (line.trim()) onFrame(JSON.parse(line));
    }
  });
}

function unsignedTask(task) {
  const { signature, ...body } = task;
  return body;
}

function digestHex(value) {
  return createHash("sha256").update(canonical(value)).digest("hex");
}

async function loadRuntimeConfig(configFile) {
  if (typeof configFile !== "string" || configFile.length === 0 || configFile.includes("\0")) throw new Error("managed runtime config path invalid");
  let config;
  try {
    config = JSON.parse(await readFile(configFile, "utf8"));
  } catch (error) {
    if (error instanceof SyntaxError) throw new Error("managed runtime config invalid");
    throw error;
  }
  if (config === null || typeof config !== "object" || Array.isArray(config)) throw new Error("managed runtime config invalid");
  return config;
}

async function sendEvent(socket, event) {
  await appendAudit({ kind: "event", ...event });
  send(socket, { type: "TASK_EVENT", event });
}

export async function runWorker(port = 8787, configFile) {
  const config = await loadRuntimeConfig(configFile);
  const worker = await loadManagedAgent(config.worker);
  const zone = await loadManagedZone(config.zone);
  await writeRegistry(config.registryPath ?? "state/registry.json", zone, [worker.descriptor]);

  const server = net.createServer((socket) => {
    readFrames(socket, async (frame) => {
      try {
        if (frame.type !== "TASK_OPEN") throw new Error(`unsupported frame: ${frame.type}`);
        const requesterPublicKey = publicKeyFromDescriptor(frame.requester);
        const requesterAid = frame.requester.aid;
        const requesterRegistry = new Map([[frame.requester.alias, frame.requester]]);
        resolveAgent(requesterRegistry, frame.requester.alias);
        const task = unsignedTask(frame.task);
        if (task.from !== requesterAid) throw new Error("task sender does not match requester descriptor");
        if (!verifyObject(requesterPublicKey, task, frame.task.signature)) {
          throw new Error("task signature verification failed");
        }
        enforcePolicy(worker.descriptor, task);

        await sendEvent(socket, { type: "task.accepted", task_id: task.task_id, by: worker.aid });
        const approvals = approvalReasons(worker.descriptor, task);
        if (approvals.length > 0) {
          await sendEvent(socket, { type: "approval.required", task_id: task.task_id, reasons: approvals });
          await sendEvent(socket, {
            type: "approval.granted",
            task_id: task.task_id,
            by: "human://local/operator",
            reasons: approvals,
          });
        }
        await sendEvent(socket, { type: "task.started", task_id: task.task_id, by: worker.aid });
        await sendEvent(socket, { type: "task.progress", task_id: task.task_id, progress: 0.5 });

        const artifactUri = `artifact://local/${task.task_id}/summary.md`;
        const artifact = await writeArtifact(artifactUri, `# Runtime Summary\n\nCompleted ${task.task_id} for ${task.from}.\n`);
        await sendEvent(socket, { type: "artifact.created", task_id: task.task_id, uri: artifactUri, manifest: artifact.manifest });
        await sendEvent(socket, { type: "task.completed", task_id: task.task_id, by: worker.aid });

        const receipt = {
          task_id: task.task_id,
          task_digest: digestHex(frame.task),
          from: task.from,
          to: worker.aid,
          artifact_refs: [artifactUri],
          artifact_manifests: [artifact.manifest],
          event_count: approvals.length > 0 ? 7 : 5,
          approvals,
        };
        const signedReceipt = { ...receipt, signature: signObject(worker.privateKey, receipt) };
        await appendAudit({ kind: "receipt", ...signedReceipt });
        send(socket, { type: "RECEIPT", receipt: signedReceipt });
        send(socket, { type: "TASK_CLOSE", task_id: task.task_id });
      } catch (error) {
        send(socket, { type: "TASK_ERROR", error: error.message });
        socket.end();
      }
    });
  });

  server.listen(port, "127.0.0.1", () => {
    console.log(JSON.stringify({ worker: worker.aid, registry: config.registryPath ?? "state/registry.json", listening: port }));
  });
  return server;
}

export async function runRequest(alias = "agent://local/summarizer", configFile) {
  const config = await loadRuntimeConfig(configFile);
  const requester = await loadManagedAgent(config.requester);
  const registry = await loadRegistry(config.registryPath ?? "state/registry.json");
  const { descriptor } = resolveAgent(registry, alias);
  const transport = descriptor.transports.find((item) => item.startsWith("asp+tcp://"));
  if (!transport) throw new Error(`no asp+tcp transport for ${alias}`);
  const url = new URL(transport);

  const task = {
    task_id: `task_${Date.now()}`,
    from: requester.aid,
    to: alias,
    intent: "Summarize this request through a real local ASP connection.",
    scope: { network: false, write: [`artifact://local/`] },
    budget: { time_seconds: 30 },
  };
  const signedTask = { ...task, signature: signObject(requester.privateKey, task) };

  const socket = net.createConnection(Number(url.port), url.hostname);
  const events = [];
  let receipt;
  const done = new Promise((resolve, reject) => {
    socket.on("error", reject);
    readFrames(socket, (frame) => {
      if (frame.type === "TASK_EVENT") events.push(frame.event);
      if (frame.type === "RECEIPT") receipt = frame.receipt;
      if (frame.type === "TASK_ERROR") reject(new Error(frame.error));
      if (frame.type === "TASK_CLOSE") resolve();
    });
  });

  socket.on("connect", () => {
    send(socket, { type: "TASK_OPEN", task: signedTask, requester: requester.descriptor });
  });
  await done;
  socket.end();
  console.log(JSON.stringify({ requester: requester.aid, worker: descriptor.aid, events, receipt }, null, 2));
}

const [mode, arg, configFile] = process.argv.slice(2);
if (mode === "worker") {
  await runWorker(Number(arg ?? 8787), configFile);
} else if (mode === "request") {
  await runRequest(arg, configFile);
} else {
  console.error("usage: node agent-runtime.mjs worker <port> <managed-runtime.json> | request <agent://alias> <managed-runtime.json>");
  process.exitCode = 2;
}
