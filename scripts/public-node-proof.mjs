import { execFile, spawn } from "node:child_process";
import net from "node:net";
import { networkInterfaces } from "node:os";
import { chmod, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { basename, dirname } from "node:path";
import { promisify } from "node:util";
import { canonical, createAgent, createZone, signObject, zoneBinding } from "../asp-core.mjs";

const execFileAsync = promisify(execFile);
await mkdir("state", { recursive: true });
const originZone = createZone("zone://public-node-proof-origin");
await writeFile("state/public-node-proof-trusted.json", `${JSON.stringify({ zones: [originZone.descriptor] }, null, 2)}\n`);
const fixture = JSON.parse(await readFile("test-vectors/asp-v1.5-capability-credential.json", "utf8"));
await Promise.all([
  "state/public-node-proof-authority.seed",
  "state/public-node-proof-worker.seed",
].map((path) => rm(path, { force: true })));
const managedKeys = await createManagedProofKeys(fixture);
const receiptFramePath = "state/public-node-proof-fed-receipt.json";
const receiptTrustedPath = "state/public-node-proof-trusted-zones.json";
const offlineSwarmVectorPath = "test-vectors/asp-u29-node-swarm-durable.json";
const offlineSwarmCloseFramePath = "state/public-node-proof-offline-u29-swarm-close.json";
const offlineSwarmTrustedPath = "state/public-node-proof-offline-u29-trusted-zones.json";
const bundleManifestPath = "state/public-node-proof-bundle.json";
const swarmStateDir = "state/public-node-proof-swarms";
await rm("state/public-node-proof-audit.log", { force: true });
await rm(offlineSwarmCloseFramePath, { force: true });
await rm(offlineSwarmTrustedPath, { force: true });
await rm("artifacts/public_node_probe_task", { force: true, recursive: true });
await rm(swarmStateDir, { force: true, recursive: true });

const binary = process.argv[2] ?? "state/public-node-proof-go";
const listenHost = publicListenHost();
const gatewayHost = listenHost;
const keepAliveMs = Number(process.env.AGNET_PUBLIC_PROOF_KEEPALIVE_MS ?? "0");
if (!Number.isSafeInteger(keepAliveMs) || keepAliveMs < 0) throw new Error("AGNET_PUBLIC_PROOF_KEEPALIVE_MS must be a non-negative integer");
const child = spawn(binary, [
  "--listen-host",
  listenHost,
  "--port",
  "0",
  "--trusted",
  "state/public-node-proof-trusted.json",
  "--authority-store",
  managedKeys.authority.storePath,
  "--authority-passphrase-file",
  managedKeys.authority.passphrasePath,
  "--worker-store",
  managedKeys.worker.storePath,
  "--worker-passphrase-file",
  managedKeys.worker.passphrasePath,
  "--swarm-state-dir",
  swarmStateDir,
  "--audit",
  "state/public-node-proof-audit.log",
], { stdio: ["ignore", "pipe", "inherit"] });
process.on("exit", () => child.kill("SIGTERM"));

const timer = setTimeout(() => {
  child.kill("SIGKILL");
  console.error("public node proof timeout");
  process.exit(1);
}, 60000);

async function createManagedProofKeys(keyFixture) {
  const [authority, worker] = await Promise.all([
    migrateProofKey({
      label: "authority",
      seedHex: keyFixture.authority_seed_hex,
      descriptor: keyFixture.authority,
      identityKind: "zid",
    }),
    migrateProofKey({
      label: "worker",
      seedHex: keyFixture.worker_seed_hex,
      descriptor: keyFixture.worker,
      identityKind: "aid",
    }),
  ]);
  return { authority, worker };
}

async function migrateProofKey({ label, seedHex, descriptor, identityKind }) {
  const storePath = `state/keys/public-node-proof-${label}`;
  const passphrasePath = `state/public-node-proof-${label}.passphrase`;
  const bareKeyPath = `state/public-node-proof-${label}.migration.pkcs8`;
  const descriptorPath = `state/public-node-proof-${label}.migration-descriptor.json`;
  await rm(storePath, { force: true, recursive: true });
  await Promise.all([bareKeyPath, descriptorPath, passphrasePath].map((path) => rm(path, { force: true })));
  await Promise.all([
    writeFile(bareKeyPath, privateKeyPkcs8FromSeed(seedHex), { mode: 0o600 }),
    writeFile(descriptorPath, `${canonical(descriptor)}\n`, { mode: 0o600 }),
    writeFile(passphrasePath, `public-node-proof ${label} passphrase\n`, { mode: 0o600 }),
  ]);
  await Promise.all([bareKeyPath, descriptorPath, passphrasePath].map((path) => chmod(path, 0o600)));
  try {
    await execFileAsync(process.execPath, [
      "agnet-key.mjs",
      "migrate",
      "--store", storePath,
      "--key-file", bareKeyPath,
      "--key-type", "ed25519-pkcs8",
      "--identity-kind", identityKind,
      "--descriptor", descriptorPath,
      "--passphrase-file", passphrasePath,
      "--iterations", "100000",
    ]);
  } finally {
    await Promise.all([bareKeyPath, descriptorPath].map((path) => rm(path, { force: true })));
  }
  return { storePath, passphrasePath };
}

function privateKeyPkcs8FromSeed(seedHex) {
  if (typeof seedHex !== "string" || !/^[a-f0-9]{64}$/i.test(seedHex)) throw new Error("proof fixture seed invalid");
  return Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    Buffer.from(seedHex, "hex"),
  ]);
}

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
  const receiptFrame = { ...audited.frame, type: "FED_RECEIPT" };
  await writeFile(receiptFramePath, `${JSON.stringify(receiptFrame, null, 2)}\n`);
  await writeFile(receiptTrustedPath, `${JSON.stringify({ zones: [receiptFrame.zone, originZone.descriptor] }, null, 2)}\n`);
  const artifact = await readArtifact(status.port, originZone, task.taskId, receiptFrame.receipt.artifact_refs[0]);
  await mkdir(dirname(artifact.file), { recursive: true });
  await writeFile(artifact.file, artifact.bytes);
  const artifactVerify = await execFileAsync(process.execPath, ["asp-verify.mjs", "fed-receipt-artifacts", receiptFramePath, receiptTrustedPath]);
  const artifactProof = JSON.parse(artifactVerify.stdout);
  const artifactReject = await rejectArtifact(status.port, originZone, task.taskId, "artifact://local/public_node_probe_task/not-in-receipt.md");
  await writeFile(artifact.file, tamperedBytes(artifact.bytes));
  const artifactTamperReject = await rejectArtifact(status.port, originZone, task.taskId, audited.frame.receipt.artifact_refs[0]);
  await writeFile(artifact.file, artifact.bytes);
  const offlineSwarm = await verifyOfflineU29Vector();
  clearTimeout(timer);
  const bundle = {
    proof: "public-node-proof",
    receipt_frame: basename(receiptFramePath),
    trusted_zones: basename(receiptTrustedPath),
    receipt_digest: artifactProof.receipt_digest,
    artifact_uris: artifactProof.artifact_uris,
    artifact_sha256s: artifactProof.artifact_sha256s,
    artifact_manifest_hashes: artifactProof.artifact_manifest_hashes,
    transport_proof: receiptFrame.receipt.transport_proof,
    swarm_close_frame: basename(offlineSwarmCloseFramePath),
    swarm_close_trusted_zones: basename(offlineSwarmTrustedPath),
    swarm_close_digest: offlineSwarm.closeDigest,
    offline_swarm_evidence: {
      vector: basename(offlineSwarmVectorPath),
      origin: offlineSwarm.origin,
      journal_verify: offlineSwarm.journalVerify,
      claim_boundary: offlineSwarm.claimBoundary,
    },
  };
  await writeFile(bundleManifestPath, `${JSON.stringify(bundle, null, 2)}\n`);
  const bundleVerify = await execFileAsync(process.execPath, ["asp-verify.mjs", "proof-bundle", bundleManifestPath]);
  const bundleProof = JSON.parse(bundleVerify.stdout);
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
    bundle_manifest: bundleManifestPath,
    proof_bundle_verify: bundleProof.proof_bundle_verify,
    reachability_scope: bundleProof.reachability_scope,
    artifact_file: artifact.file,
    fed_receipt_artifacts_verify: artifactProof.fed_receipt_artifacts_verify,
    artifact_count: artifactProof.artifact_count,
    artifact_uris: artifactProof.artifact_uris,
    artifact_sha256s: artifactProof.artifact_sha256s,
    artifact_manifest_hashes: artifactProof.artifact_manifest_hashes,
    receipt_digest: artifactProof.receipt_digest,
    artifact_reject: artifactReject.rejected,
    artifact_reject_error: artifactReject.error,
    artifact_tamper_reject: artifactTamperReject.rejected,
    artifact_tamper_error: artifactTamperReject.error,
    offline_swarm_vector: offlineSwarmVectorPath,
    offline_swarm_origin: offlineSwarm.origin,
    offline_swarm_journal_verify: offlineSwarm.journalVerify,
    offline_swarm_close_verify: offlineSwarm.closeVerify,
    offline_swarm_claim_boundary: offlineSwarm.claimBoundary,
  }));
  if (keepAliveMs > 0) await new Promise((resolve) => setTimeout(resolve, keepAliveMs));
  child.kill("SIGTERM");
  process.exit(0);
}

function publicListenHost() {
  if (process.env.AGNET_PUBLIC_LISTEN_HOST) return process.env.AGNET_PUBLIC_LISTEN_HOST;
  for (const entries of Object.values(networkInterfaces())) {
    for (const entry of entries ?? []) {
      if (entry.family === "IPv4" && !entry.internal) return entry.address;
    }
  }
  throw new Error("no non-loopback IPv4 listen host available");
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
      requester_zone_binding: zoneBinding(zone, requester.descriptor),
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

async function verifyOfflineU29Vector() {
  const vector = JSON.parse(await readFile(offlineSwarmVectorPath, "utf8"));
  if (vector.format !== "asp-swarm-durable-parity-vector/v1" || vector.origin !== "node") throw new Error("offline U29 vector invalid");
  const close = JSON.parse(Buffer.from(vector.evidence?.close ?? "", "base64url").toString("utf8"));
  if (close.swarm_id !== vector.expected?.swarm_id) throw new Error("offline U29 close swarm mismatch");
  const frame = {
    type: "FED_SWARM_CLOSE",
    swarm_id: close.swarm_id,
    zone: vector.evidence.frozen_authority,
    close,
  };
  await writeFile(offlineSwarmCloseFramePath, `${JSON.stringify(frame, null, 2)}\n`);
  await writeFile(offlineSwarmTrustedPath, `${JSON.stringify({ zones: [frame.zone] }, null, 2)}\n`);
  const [journal, closeProof] = await Promise.all([
    execFileAsync(process.execPath, ["asp-verify.mjs", "swarm-journal", offlineSwarmVectorPath]),
    execFileAsync(process.execPath, ["asp-verify.mjs", "swarm-close", offlineSwarmCloseFramePath, offlineSwarmTrustedPath]),
  ]);
  const journalResult = JSON.parse(journal.stdout);
  const closeResult = JSON.parse(closeProof.stdout);
  if (journalResult.swarm_journal_verify !== "ok" || closeResult.swarm_close_verify !== "ok") throw new Error("offline U29 vector verification failed");
  return {
    origin: vector.origin,
    journalVerify: journalResult.swarm_journal_verify,
    closeVerify: closeResult.swarm_close_verify,
    closeDigest: closeResult.swarm_close_digest,
    claimBoundary: "offline fixed vector; not live public-node execution",
  };
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
    const socket = net.createConnection(Number(port), gatewayHost);
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
