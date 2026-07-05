import net from "node:net";
import { randomBytes } from "node:crypto";
import {
  appendAudit,
  approvalReasons,
  b64url,
  capabilityCredential,
  enforcePolicy,
  loadOrCreateAgent,
  loadOrCreateZone,
  loadTrustedZones,
  publicKeyFromDescriptor,
  resolveAgent,
  signObject,
  verifyObject,
  verifyCapabilityCredential,
  verifyCredentialStatus,
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

function sessionAuthBody(sessionId, challenge, peerZid, remoteZid) {
  return { session_id: sessionId, challenge, peer_zid: peerZid, remote_zid: remoteZid };
}

function serverSessionHandler(socket, trustedZones, zone) {
  const session = {};
  return (frame) => {
    if (frame.type === "HELLO") {
      const peer = verifyTrustedZone(trustedZones, frame.origin_zone);
      session.id = `session:${b64url(randomBytes(16))}`;
      session.challenge = b64url(randomBytes(32));
      session.peerZid = peer.zid;
      send(socket, { type: "HELLO", zone: zone.descriptor, session_id: session.id, challenge: session.challenge });
      return true;
    }
    if (frame.type === "AUTH") {
      const peer = verifyTrustedZone(trustedZones, frame.origin_zone);
      if (peer.zid !== session.peerZid) throw new Error("session origin mismatch");
      const auth = frame.auth ?? {};
      const body = sessionAuthBody(session.id, session.challenge, peer.zid, zone.zid);
      if (
        auth.session_id !== body.session_id ||
        auth.challenge !== body.challenge ||
        auth.peer_zid !== body.peer_zid ||
        auth.remote_zid !== body.remote_zid
      ) {
        throw new Error("session auth body mismatch");
      }
      if (!verifyObject(publicKeyFromDescriptor(peer), body, auth.auth_signature)) {
        throw new Error("session auth signature verification failed");
      }
      session.authenticated = true;
      send(socket, { type: "AUTH_OK", session_id: session.id });
      return true;
    }
    if (!session.authenticated) throw new Error("session not authenticated");
    if (frame.origin_zone?.zid !== session.peerZid) throw new Error("session origin mismatch");
    return false;
  };
}

function clientSessionHandler(socket, trustedZones, zone, onAuthenticated) {
  const session = {};
  return (frame) => {
    if (frame.type === "HELLO") {
      const remote = verifyTrustedZone(trustedZones, frame.zone);
      session.id = frame.session_id;
      session.challenge = frame.challenge;
      const body = sessionAuthBody(session.id, session.challenge, zone.zid, remote.zid);
      send(socket, { type: "AUTH", origin_zone: zone.descriptor, auth: { ...body, auth_signature: signObject(zone.privateKey, body) } });
      return true;
    }
    if (frame.type === "AUTH_OK") {
      if (frame.session_id !== session.id) throw new Error("session id mismatch");
      onAuthenticated();
      return true;
    }
    return false;
  };
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
    ["summarize.text"],
  );

  const server = net.createServer((socket) => {
    const session = serverSessionHandler(socket, trustedZones, zone);
    readFrames(socket, async (frame) => {
      try {
        if (session(frame)) return;
        if (frame.type === "FED_RESOLVE") {
          verifyTrustedZone(trustedZones, frame.origin_zone);
          if (frame.alias !== worker.alias) throw new Error(`remote alias not found: ${frame.alias}`);
          send(socket, {
            type: "FED_RESOLVE_RESULT",
            zone: zone.descriptor,
            worker: worker.descriptor,
            zone_binding: zoneBinding(zone, worker.descriptor),
          });
          send(socket, { type: "FED_RESOLVE_CLOSE", alias: frame.alias });
          return;
        }
        if (frame.type === "FED_QUERY") {
          verifyTrustedZone(trustedZones, frame.origin_zone);
          const matches = worker.descriptor.capabilities.includes(frame.capability)
            ? [{
                worker: worker.descriptor,
                zone_binding: zoneBinding(zone, worker.descriptor),
                credentials: [
                  capabilityCredential(zone, worker.descriptor, frame.capability, {
                    level: "L1",
                    evidence: ["zone-b-local-worker"],
                  }),
                ],
              }]
            : [];
          send(socket, { type: "FED_QUERY_RESULT", zone: zone.descriptor, capability: frame.capability, matches });
          send(socket, { type: "FED_QUERY_CLOSE", capability: frame.capability });
          return;
        }
        if (frame.type !== "FED_TASK_OPEN") throw new Error(`unsupported frame: ${frame.type}`);
        const originZone = verifyTrustedZone(trustedZones, frame.origin_zone);
        const requesterPublicKey = publicKeyFromDescriptor(frame.requester);
        resolveAgent(new Map([[frame.requester.alias, { descriptor: frame.requester }]]), frame.requester.alias);

        const task = unsignedTask(frame.task);
        if (task.from !== frame.requester.aid) throw new Error("task sender does not match requester descriptor");
        if (task.to !== worker.alias) throw new Error(`task target does not match worker alias: ${task.to}`);
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

async function request(port, trustedZonesFile, alias = "agent://zone-b/summarizer") {
  const trustedZones = await loadTrustedZones(trustedZonesFile);
  const zone = await loadOrCreateZone("zone://a", "state/keys/fed-zone-a.pkcs8");
  const requester = await loadOrCreateAgent("agent://zone-a/requester", "state/keys/fed-zone-a-requester.pkcs8");
  const task = {
    task_id: `fed_task_${Date.now()}`,
    from: requester.aid,
    to: alias,
    intent: "Summarize through a trusted remote Zone.",
    scope: { network: false },
    budget: { time_seconds: 30 },
  };
  const signedTask = { ...task, signature: signObject(requester.privateKey, task) };

  const socket = net.createConnection(port, "127.0.0.1");
  const events = [];
  let receipt;
  const done = new Promise((resolve, reject) => {
    socket.on("error", reject);
    const session = clientSessionHandler(socket, trustedZones, zone, () => {
      send(socket, { type: "FED_TASK_OPEN", origin_zone: zone.descriptor, requester: requester.descriptor, task: signedTask });
    });
    readFrames(socket, (frame) => {
      if (session(frame)) return;
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
    send(socket, { type: "HELLO", origin_zone: zone.descriptor });
  });
  await done;
  socket.end();
  await appendAudit({ kind: "fed_remote_receipt", ...receipt });
  console.log(JSON.stringify({ zone: zone.zid, requester: requester.aid, events, receipt }, null, 2));
}

async function resolveRemote(port, trustedZonesFile, alias = "agent://zone-b/summarizer") {
  const trustedZones = await loadTrustedZones(trustedZonesFile);
  const zone = await loadOrCreateZone("zone://a", "state/keys/fed-zone-a.pkcs8");
  const socket = net.createConnection(port, "127.0.0.1");
  let result;
  const done = new Promise((resolve, reject) => {
    socket.on("error", reject);
    const session = clientSessionHandler(socket, trustedZones, zone, () => {
      send(socket, { type: "FED_RESOLVE", origin_zone: zone.descriptor, alias });
    });
    readFrames(socket, (frame) => {
      if (session(frame)) return;
      if (frame.type === "FED_RESOLVE_RESULT") {
        verifyTrustedZone(trustedZones, frame.zone);
        const resolved = resolveAgent(
          new Map([[frame.worker.alias, { descriptor: frame.worker, zone: frame.zone, zone_binding: frame.zone_binding }]]),
          frame.worker.alias,
        );
        result = { zone: frame.zone.zid, alias: frame.worker.alias, aid: resolved.descriptor.aid };
      }
      if (frame.type === "FED_TASK_ERROR") reject(new Error(frame.error));
      if (frame.type === "FED_RESOLVE_CLOSE") resolve();
    });
  });

  socket.on("connect", () => {
    send(socket, { type: "HELLO", origin_zone: zone.descriptor });
  });
  await done;
  socket.end();
  console.log(JSON.stringify(result, null, 2));
}

async function queryRemote(port, trustedZonesFile, capability = "summarize.text", print = true) {
  const trustedZones = await loadTrustedZones(trustedZonesFile);
  const zone = await loadOrCreateZone("zone://a", "state/keys/fed-zone-a.pkcs8");
  const socket = net.createConnection(port, "127.0.0.1");
  let result;
  const done = new Promise((resolve, reject) => {
    socket.on("error", reject);
    const session = clientSessionHandler(socket, trustedZones, zone, () => {
      send(socket, { type: "FED_QUERY", origin_zone: zone.descriptor, capability });
    });
    readFrames(socket, (frame) => {
      if (session(frame)) return;
      if (frame.type === "FED_QUERY_RESULT") {
        const remoteZone = verifyTrustedZone(trustedZones, frame.zone);
        const matches = frame.matches.map((match) => {
          const resolved = resolveAgent(
            new Map([[match.worker.alias, { descriptor: match.worker, zone: frame.zone, zone_binding: match.zone_binding }]]),
            match.worker.alias,
          );
          const credentials = match.credentials ?? [];
          const credentialStatuses = match.credential_statuses ?? [];
          for (const credential of credentials) {
            if (!verifyCapabilityCredential(credential, frame.zone, resolved.descriptor)) {
              throw new Error(`capability credential verification failed: ${credential.capability}`);
            }
          }
          for (let index = 0; index < credentialStatuses.length; index += 1) {
            if (!verifyCredentialStatus(credentialStatuses[index], credentials[index], frame.zone)) {
              throw new Error(`credential status verification failed: ${credentials[index]?.capability}`);
            }
            if (credentialStatuses[index].status !== "active") {
              throw new Error(`credential is not active: ${credentials[index]?.capability}`);
            }
          }
          return {
            alias: resolved.descriptor.alias,
            aid: resolved.descriptor.aid,
            capabilities: resolved.descriptor.capabilities,
            credentials,
            credential_statuses: credentialStatuses,
          };
        });
        result = { zone: remoteZone.zid, capability: frame.capability, matches };
      }
      if (frame.type === "FED_TASK_ERROR") reject(new Error(frame.error));
      if (frame.type === "FED_QUERY_CLOSE") resolve();
    });
  });

  socket.on("connect", () => {
    send(socket, { type: "HELLO", origin_zone: zone.descriptor });
  });
  await done;
  socket.end();
  if (print) console.log(JSON.stringify(result, null, 2));
  return result;
}

async function auditRemote(port, trustedZonesFile, taskId) {
  if (!taskId) throw new Error("audit task_id missing");
  const trustedZones = await loadTrustedZones(trustedZonesFile);
  const zone = await loadOrCreateZone("zone://a", "state/keys/fed-zone-a.pkcs8");
  const socket = net.createConnection(port, "127.0.0.1");
  let result;
  const done = new Promise((resolve, reject) => {
    socket.on("error", reject);
    const session = clientSessionHandler(socket, trustedZones, zone, () => {
      send(socket, { type: "FED_AUDIT_QUERY", origin_zone: zone.descriptor, task_id: taskId });
    });
    readFrames(socket, (frame) => {
      if (session(frame)) return;
      if (frame.type === "FED_AUDIT_RESULT") {
        const remoteZone = verifyTrustedZone(trustedZones, frame.zone);
        const resolved = resolveAgent(
          new Map([[frame.worker.alias, { descriptor: frame.worker, zone: frame.zone, zone_binding: frame.zone_binding }]]),
          frame.worker.alias,
        );
        const body = { ...frame.receipt };
        delete body.signature;
        if (frame.receipt.task_id !== taskId) throw new Error("audit receipt task mismatch");
        if (!verifyObject(resolved.publicKey, body, frame.receipt.signature)) {
          throw new Error("audit receipt signature verification failed");
        }
        result = {
          zone: remoteZone.zid,
          task_id: taskId,
          worker: resolved.descriptor,
          receipt: frame.receipt,
        };
      }
      if (frame.type === "FED_TASK_ERROR") reject(new Error(frame.error));
      if (frame.type === "FED_AUDIT_CLOSE") resolve();
    });
  });

  socket.on("connect", () => {
    send(socket, { type: "HELLO", origin_zone: zone.descriptor });
  });
  await done;
  socket.end();
  console.log(JSON.stringify(result, null, 2));
}

async function requestCapability(port, trustedZonesFile, capability = "summarize.text") {
  const result = await queryRemote(port, trustedZonesFile, capability, false);
  const [match] = result.matches;
  if (!match) throw new Error(`no remote capability match: ${capability}`);
  await request(port, trustedZonesFile, match.alias);
}

async function main() {
  const [mode, portArg, trustedZonesFile, value] = process.argv.slice(2);
  if (mode === "serve") {
    await serve(Number(portArg ?? 8990), trustedZonesFile ?? "state/trusted-zones.json");
  } else if (mode === "request") {
    await request(Number(portArg ?? 8990), trustedZonesFile ?? "state/trusted-zones.json", value);
  } else if (mode === "resolve") {
    await resolveRemote(Number(portArg ?? 8990), trustedZonesFile ?? "state/trusted-zones.json", value);
  } else if (mode === "query") {
    await queryRemote(Number(portArg ?? 8990), trustedZonesFile ?? "state/trusted-zones.json", value);
  } else if (mode === "audit") {
    await auditRemote(Number(portArg ?? 8990), trustedZonesFile ?? "state/trusted-zones.json", value);
  } else if (mode === "request-capability") {
    await requestCapability(Number(portArg ?? 8990), trustedZonesFile ?? "state/trusted-zones.json", value);
  } else {
    console.error(
      "usage: node federation-gateway.mjs serve <port> <trusted-zones.json> | request <port> <trusted-zones.json> [agent://alias] | resolve <port> <trusted-zones.json> [agent://alias] | query <port> <trusted-zones.json> [capability] | audit <port> <trusted-zones.json> <task_id> | request-capability <port> <trusted-zones.json> [capability]",
    );
    process.exitCode = 2;
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
