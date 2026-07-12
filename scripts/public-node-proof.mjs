import { execFile, spawn } from "node:child_process";
import net from "node:net";
import { networkInterfaces } from "node:os";
import { chmod, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { basename, dirname } from "node:path";
import { promisify } from "node:util";
import { createHash } from "node:crypto";
import { canonical, createAgent, createZone, publicKeyFromDescriptor, signObject, signedReceiptDigest, swarmExecutionBinding, swarmPlan, verifyObject, zoneBinding } from "../asp-core.mjs";
import { createSwarmOutputTrustInputsForTest, createSwarmOutputVerification } from "../swarm-output-verification.mjs";

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
const swarmCloseFramePath = "state/public-node-proof-swarm-close.json";
const swarmCloseTrustedPath = "state/public-node-proof-swarm-close-trusted-zones.json";
const outputProofFramePath = "state/public-node-proof-output-proof.json";
const outputProofBundlePath = "state/public-node-proof-output-bundle.json";
const outputProofPlanPath = "state/public-node-proof-output-plan.json";
const outputProofBindingPath = "state/public-node-proof-output-binding.json";
const outputProofStepsPath = "state/public-node-proof-output-steps.json";
const outputProofWorkersPath = "state/public-node-proof-output-workers.json";
const outputProofReceiptsPath = "state/public-node-proof-output-receipts.json";
const outputProofAllowlistPath = "state/public-node-proof-output-allowlist.json";
const outputProofVerifierZonesPath = "state/public-node-proof-output-verifier-zones.json";
const outputProofEvidenceZonesPath = "state/public-node-proof-output-evidence-zones.json";
const outputProofArtifactPath = "state/public-node-proof-output-artifact.txt";
const outputProofRevocationsPath = "state/public-node-proof-output-revocations.json";
const bundleManifestPath = "state/public-node-proof-bundle.json";
await rm("state/public-node-proof-audit.log", { force: true });
await rm(swarmCloseFramePath, { force: true });
await rm(swarmCloseTrustedPath, { force: true });
await rm(bundleManifestPath, { force: true });
await rm(outputProofFramePath, { force: true });
await rm(outputProofBundlePath, { force: true });
await rm(outputProofPlanPath, { force: true });
await rm(outputProofBindingPath, { force: true });
await rm(outputProofStepsPath, { force: true });
await rm(outputProofWorkersPath, { force: true });
await rm(outputProofReceiptsPath, { force: true });
await rm(outputProofAllowlistPath, { force: true });
await rm(outputProofVerifierZonesPath, { force: true });
await rm(outputProofEvidenceZonesPath, { force: true });
await rm(outputProofArtifactPath, { force: true });
await rm(outputProofRevocationsPath, { force: true });
await rm("artifacts/public_node_probe_task", { force: true, recursive: true });

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
  const swarm = await openSwarm(status.port, originZone);
  await writeFile(swarmCloseFramePath, `${JSON.stringify(swarm.closeFrame, null, 2)}\n`);
  await writeFile(swarmCloseTrustedPath, `${JSON.stringify({ zones: [swarm.closeFrame.zone] }, null, 2)}\n`);
  const swarmCloseVerify = await execFileAsync(process.execPath, ["asp-verify.mjs", "swarm-close", swarmCloseFramePath, swarmCloseTrustedPath]);
  const swarmCloseProof = JSON.parse(swarmCloseVerify.stdout);
  const outputProof = await createPublicNodeOutputProof(swarm, status.port, originZone, binary);
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
    swarm_close_frame: basename(swarmCloseFramePath),
    swarm_close_trusted_zones: basename(swarmCloseTrustedPath),
    swarm_close_digest: swarm.closeDigest,
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
    swarm_id: swarm.swarmId,
    swarm_step_count: swarm.stepReceipts.length,
    swarm_step_ids: swarm.stepReceipts.map((step) => step.step_id),
    swarm_close_signature: swarm.closeSignature,
    swarm_close_receipts: swarm.closeReceipts,
    swarm_close_verify: swarmCloseProof.swarm_close_verify,
    swarm_close_digest: swarm.closeDigest,
    swarm_plan_digest: swarm.planDigest,
    swarm_execution_graph_digest: swarm.executionGraphDigest,
    swarm_close_frame: swarmCloseFramePath,
    swarm_close_trusted_zones: swarmCloseTrustedPath,
    output_proof_frame: outputProofFramePath,
    output_proof_bundle: outputProofBundlePath,
    output_proof_digest: outputProof.proofDigest,
    output_proof_close_digest: outputProof.closeDigest,
    output_proof_trust_inputs_digest: outputProof.trustInputsDigest,
    output_proof_replay_decision: outputProof.replay_decision,
    output_proof_completion_gate: outputProof.completion_gate,
    verifier_identity_scope: "same-host independent verifier",
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
  const steps = [
    { step_id: "summary", task: { ...summaryTask, signature: signObject(requester.privateKey, summaryTask) } },
    { step_id: "dependent", after: ["summary"], task: { ...dependentTask, signature: signObject(requester.privateKey, dependentTask) } },
  ];
  const plan = swarmPlan(zone, "swarm://public-node-proof/two-step", "Prove a bound public-listen Swarm.", [
    { step_id: "summary", capability: "summarize.text", depends_on: [] },
    { step_id: "dependent", capability: "summarize.text", depends_on: ["summary"] },
  ], "f".repeat(64));
  const executionBinding = swarmExecutionBinding(zone, plan, steps.map((step) => ({ step_id: step.step_id, depends_on: step.after ?? [], task: step.task })));
  const receiptFrames = [];
  return exchangeFrame(
    port,
    zone,
    {
      type: "FED_SWARM_OPEN",
      origin_zone: zone.descriptor,
      requester: requester.descriptor,
      requester_zone_binding: zoneBinding(zone, requester.descriptor),
      swarm: {
        swarm_id: "swarm://public-node-proof/two-step",
        plan,
        execution_binding: executionBinding,
        steps,
      },
    },
    "FED_SWARM_CLOSE",
    (frame) => {
      if (frame.type === "FED_RECEIPT") receiptFrames.push(frame);
      if (frame.type !== "FED_SWARM_CLOSE") return null;
      const close = frame.close;
      const { close_signature, ...body } = close;
      const authorityKey = publicKeyFromDescriptor(fixture.authority);
      const expected = receiptFrames.map(({ receipt }) => ({
        step_id: receipt.swarm.step_id,
        task_id: receipt.task_id,
        signed_receipt_digest: signedReceiptDigest(receipt),
      }));
      return {
        swarmId: close.swarm_id,
        stepReceipts: close.step_receipts,
        closeSignature: verifyObject(authorityKey, body, close_signature),
        closeReceipts: sameStepReceipts(close.step_receipts, expected),
        planDigest: close.plan_digest,
        executionGraphDigest: close.execution_graph_digest,
        closeDigest: digestJson(close),
        closeFrame: { ...frame, zone: fixture.authority },
        plan,
        executionBinding,
        executableSteps: steps.map((step) => ({ step_id: step.step_id, depends_on: step.after ?? [], task: step.task })),
        resolvedWorkers: receiptFrames.map((receiptFrame) => receiptFrame.worker),
        receiptFrames,
        finalOutput: close.final_output,
      };
    },
  );
}
async function createPublicNodeOutputProof(swarm, port, zone, binary) {
  const verifierZone = createZone("zone://public-node-proof/output-verifier");
  const verifierAgent = createAgent("agent://public-node-proof/output-verifier", { allow_network: false }, ["asp+local://public-node-proof"], ["swarm.output.verify"]);
  const verifierZoneBinding = zoneBinding(verifierZone, verifierAgent.descriptor);
  const allowlist = { format: "asp-swarm-output-verifier-allowlist/v1", verifiers: [{ descriptor: verifierAgent.descriptor, zone_binding: verifierZoneBinding, authorizations: ["swarm.output.verify"] }] };
  const trustedZones = { format: "asp-swarm-output-trusted-zones/v1", zones: [verifierZone.descriptor] };
  const revocations = { format: "asp-swarm-output-revocations/v1", revocations: [] };
  const trustInputs = createSwarmOutputTrustInputsForTest(allowlist, trustedZones, revocations);
  const terminalArtifact = swarm.finalOutput.artifact;
  const artifact = await readArtifact(port, zone, swarm.finalOutput.task_id, terminalArtifact.uri);
  await mkdir(dirname(artifact.file), { recursive: true });
  await writeFile(outputProofArtifactPath, artifact.bytes);
  await writeFile(artifact.file, artifact.bytes);
  const evidence = {
    planFrame: swarm.plan,
    executionBinding: swarm.executionBinding,
    executableSteps: swarm.executableSteps,
    resolvedWorkers: swarm.resolvedWorkers,
    closeFrame: swarm.closeFrame,
    receiptFrames: swarm.receiptFrames,
    trustedZones: new Map([[zone.zid, zone.descriptor], [swarm.closeFrame.zone.zid, swarm.closeFrame.zone]]),
    loadArtifactBytes: async (requestedArtifact) => {
      if (requestedArtifact.uri !== terminalArtifact.uri) throw new Error(`unexpected output artifact: ${requestedArtifact.uri}`);
      return artifact.bytes;
    },
  };
  const verification = await createSwarmOutputVerification(evidence, trustInputs, {
    descriptor: verifierAgent.descriptor,
    privateKey: verifierAgent.privateKey,
    zone: verifierZone.descriptor,
    zone_binding: verifierZoneBinding,
  }, {
    verificationId: "public-node-proof-output",
    verifiedAt: "2026-07-11T13:00:00Z",
    now: new Date("2026-07-11T13:00:00Z"),
  });
  await writeFile(outputProofFramePath, `${JSON.stringify(verification.proof, null, 2)}\n`);
  await writeFile(outputProofPlanPath, `${JSON.stringify(swarm.plan, null, 2)}\n`);
  await writeFile(outputProofBindingPath, `${JSON.stringify(swarm.executionBinding, null, 2)}\n`);
  await writeFile(outputProofStepsPath, `${JSON.stringify(swarm.executableSteps, null, 2)}\n`);
  await writeFile(outputProofWorkersPath, `${JSON.stringify(swarm.resolvedWorkers, null, 2)}\n`);
  await writeFile(outputProofReceiptsPath, `${JSON.stringify(swarm.receiptFrames, null, 2)}\n`);
  await writeFile(outputProofEvidenceZonesPath, `${JSON.stringify({ zones: [zone.descriptor, swarm.closeFrame.zone] }, null, 2)}\n`);
  await writeFile(outputProofAllowlistPath, `${JSON.stringify(allowlist, null, 2)}\n`);
  await writeFile(outputProofVerifierZonesPath, `${JSON.stringify(trustedZones, null, 2)}\n`);
  await writeFile(outputProofRevocationsPath, `${JSON.stringify(revocations, null, 2)}\n`);
  await Promise.all([outputProofAllowlistPath, outputProofVerifierZonesPath, outputProofRevocationsPath].map((path) => chmod(path, 0o600)));
  const outputBundle = {
    format: "asp-swarm-output-verification-cli/v1",
    proof: basename(outputProofFramePath),
    plan: basename(outputProofPlanPath),
    execution_binding: basename(outputProofBindingPath),
    executable_steps: basename(outputProofStepsPath),
    resolved_workers: basename(outputProofWorkersPath),
    close: basename(swarmCloseFramePath),
    receipts: basename(outputProofReceiptsPath),
    trusted_zones: basename(outputProofEvidenceZonesPath),
    trust_inputs: {
      allowlist: basename(outputProofAllowlistPath),
      trustedZones: basename(outputProofVerifierZonesPath),
      revocations: basename(outputProofRevocationsPath),
    },
    artifacts: [{ uri: terminalArtifact.uri, path: basename(outputProofArtifactPath) }],
  };
  await writeFile(outputProofBundlePath, `${JSON.stringify(outputBundle, null, 2)}\n`);
  const { stdout } = await execFileAsync(binary, ["--verify-swarm-output-scheduler-gate", outputProofBundlePath], {
    env: { ...process.env, ASP_VERIFY_NOW: "2026-07-11T13:00:00Z" },
  });
  const completion = JSON.parse(stdout);
  return {
    proofDigest: completion.proofDigest,
    closeDigest: completion.closeDigest,
    trustInputsDigest: completion.trustInputsDigest,
    replay_decision: completion.replay_decision,
    completion_gate: completion.completion_gate,
  };
}


function sameStepReceipts(actual, expected) {
  return actual.length === expected.length && actual.every((step, index) =>
    step.step_id === expected[index].step_id &&
    step.task_id === expected[index].task_id &&
    step.signed_receipt_digest === expected[index].signed_receipt_digest
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
