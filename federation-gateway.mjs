import net from "node:net";
import {
  appendAudit,
  approvalReasons,
  enforcePolicy,
  loadOrCreateAgent,
  loadOrCreateZone,
  loadTrustedZones,
  publicKeyFromDescriptor,
  resolveAgent,
  signObject,
  verifyObject,
  verifyZoneDescriptor,
  writeArtifact,
  zoneBinding,
} from "./asp-core.mjs";

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

function verifyTrustedZone(trustedZones, descriptor) {
  const { descriptor: verified } = verifyZoneDescriptor(descriptor);
  const trusted = trustedZones.get(verified.zid);
  if (!trusted || trusted.public_key_spki !== verified.public_key_spki) {
    throw new Error(`untrusted zone: ${verified.zid}`);
  }
  return verified;
}

async function sendEvent(socket, event) {
  await appendAudit({ kind: "fed_event", ...event });
  send(socket, { type: "FED_TASK_EVENT", event });
}

async function serve(port, trustedZonesFile) {
  const trustedZones = await loadTrustedZones(trustedZonesFile);
  const zone = await loadOrCreateZone("zone://b", "state/keys/fed-zone-b.pkcs8");
  const worker = await loadOrCreateAgent(
    "agent://zone-b/summarizer",
    "state/keys/fed-zone-b-summarizer.pkcs8",
    { allow_network: false, approval_required: ["write"], write_prefixes: ["artifact://local/"] },
    [`fed+tcp://127.0.0.1:${port}`],
  );

  const server = net.createServer((socket) => {
    readFrames(socket, async (frame) => {
      try {
        if (frame.type !== "FED_TASK_OPEN") throw new Error(`unsupported frame: ${frame.type}`);
        const originZone = verifyTrustedZone(trustedZones, frame.origin_zone);
        const requesterPublicKey = publicKeyFromDescriptor(frame.requester);
        resolveAgent(new Map([[frame.requester.alias, { descriptor: frame.requester }]]), frame.requester.alias);

        const task = unsignedTask(frame.task);
        if (task.from !== frame.requester.aid) throw new Error("task sender does not match requester descriptor");
        if (!verifyObject(requesterPublicKey, task, frame.task.signature)) {
          throw new Error("task signature verification failed");
        }
        enforcePolicy(worker.descriptor, task);

        await sendEvent(socket, { type: "task.accepted", task_id: task.task_id, by: worker.aid, zone: zone.zid });
        const approvals = approvalReasons(worker.descriptor, task);
        if (approvals.length > 0) {
          await sendEvent(socket, { type: "approval.required", task_id: task.task_id, reasons: approvals });
          await sendEvent(socket, {
            type: "approval.granted",
            task_id: task.task_id,
            by: "human://zone-b/operator",
            reasons: approvals,
          });
        }
        await sendEvent(socket, { type: "task.started", task_id: task.task_id, by: worker.aid, zone: zone.zid });
        await sendEvent(socket, { type: "task.progress", task_id: task.task_id, progress: 0.5 });

        const artifactUri = `artifact://local/${task.task_id}/federated-summary.md`;
        await writeArtifact(artifactUri, `# Federated Summary\n\nCompleted ${task.task_id} from ${originZone.zid}.\n`);
        await sendEvent(socket, { type: "artifact.created", task_id: task.task_id, uri: artifactUri });
        await sendEvent(socket, { type: "task.completed", task_id: task.task_id, by: worker.aid, zone: zone.zid });

        const receipt = {
          task_id: task.task_id,
          from: task.from,
          origin_zone: originZone.zid,
          executing_zone: zone.zid,
          to: worker.aid,
          artifact_refs: [artifactUri],
          event_count: approvals.length > 0 ? 7 : 5,
          approvals,
        };
        const signedReceipt = { ...receipt, signature: signObject(worker.privateKey, receipt) };
        await appendAudit({ kind: "fed_receipt", ...signedReceipt });
        send(socket, {
          type: "FED_RECEIPT",
          zone: zone.descriptor,
          worker: worker.descriptor,
          zone_binding: zoneBinding(zone, worker.descriptor),
          receipt: signedReceipt,
        });
        send(socket, { type: "FED_TASK_CLOSE", task_id: task.task_id });
      } catch (error) {
        send(socket, { type: "FED_TASK_ERROR", error: error.message });
        socket.end();
      }
    });
  });

  server.listen(port, "127.0.0.1", () => {
    console.log(JSON.stringify({ zone: zone.zid, worker: worker.aid, listening: port }));
  });
}

async function request(port, trustedZonesFile) {
  const trustedZones = await loadTrustedZones(trustedZonesFile);
  const zone = await loadOrCreateZone("zone://a", "state/keys/fed-zone-a.pkcs8");
  const requester = await loadOrCreateAgent("agent://zone-a/requester", "state/keys/fed-zone-a-requester.pkcs8");
  const task = {
    task_id: `fed_task_${Date.now()}`,
    from: requester.aid,
    to: "agent://zone-b/summarizer",
    intent: "Summarize through a trusted remote Zone.",
    scope: { network: false, write: ["artifact://local/"] },
    budget: { time_seconds: 30 },
  };
  const signedTask = { ...task, signature: signObject(requester.privateKey, task) };

  const socket = net.createConnection(port, "127.0.0.1");
  const events = [];
  let receipt;
  const done = new Promise((resolve, reject) => {
    socket.on("error", reject);
    readFrames(socket, (frame) => {
      if (frame.type === "FED_TASK_EVENT") events.push(frame.event);
      if (frame.type === "FED_RECEIPT") {
        verifyTrustedZone(trustedZones, frame.zone);
        const resolved = resolveAgent(
          new Map([[frame.worker.alias, { descriptor: frame.worker, zone: frame.zone, zone_binding: frame.zone_binding }]]),
          frame.worker.alias,
        );
        const body = { ...frame.receipt };
        delete body.signature;
        if (!verifyObject(resolved.publicKey, body, frame.receipt.signature)) {
          throw new Error("remote receipt signature verification failed");
        }
        receipt = frame.receipt;
      }
      if (frame.type === "FED_TASK_ERROR") reject(new Error(frame.error));
      if (frame.type === "FED_TASK_CLOSE") resolve();
    });
  });

  socket.on("connect", () => {
    send(socket, { type: "FED_TASK_OPEN", origin_zone: zone.descriptor, requester: requester.descriptor, task: signedTask });
  });
  await done;
  socket.end();
  await appendAudit({ kind: "fed_remote_receipt", ...receipt });
  console.log(JSON.stringify({ zone: zone.zid, requester: requester.aid, events, receipt }, null, 2));
}

const [mode, portArg, trustedZonesFile] = process.argv.slice(2);
if (mode === "serve") {
  await serve(Number(portArg ?? 8990), trustedZonesFile ?? "state/trusted-zones.json");
} else if (mode === "request") {
  await request(Number(portArg ?? 8990), trustedZonesFile ?? "state/trusted-zones.json");
} else {
  console.error("usage: node federation-gateway.mjs serve <port> <trusted-zones.json> | request <port> <trusted-zones.json>");
  process.exitCode = 2;
}
