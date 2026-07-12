import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash, createPrivateKey, createPublicKey } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { test } from "node:test";
import { promisify } from "node:util";
import { canonical, computeAid, createAgent, createZone, deriveSwarmFinalOutput, descriptorBody, didKeyFromDescriptor, didKeyFromPublicKeySPKI, publicKeyFromDescriptor, publicKeySPKIFromDidKey, signObject, signedReceiptDigest, swarmExecutionBinding, swarmPlan, verifyFederatedReceipt, verifyFederatedTaskOpen, verifyObject, verifyReceiptArtifactManifests, verifyResultArtifact, verifySwarmClose, verifySwarmExecutionBinding, verifySwarmPlan, writeArtifact, zoneBinding, zoneDescriptorBody } from "../asp-core.mjs"
import { applySwarmOutputVerificationReplay, createSwarmOutputTrustInputsForTest, verifySwarmOutputVerification } from "../swarm-output-verification.mjs"

const execFileAsync = promisify(execFile);

function privateKeyFromSeed(seedHex) {
  const der = Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    Buffer.from(seedHex, "hex"),
  ]);
  return createPrivateKey({ key: der, format: "der", type: "pkcs8" });
}

test("ASP v0 vector is stable in Node", async () => {
  const vector = JSON.parse(await readFile("test-vectors/asp-v0.json", "utf8"));
  const requesterPrivateKey = privateKeyFromSeed(vector.agents.requester.seed_hex);
  const requesterPublicKey = createPublicKey(requesterPrivateKey);
  const workerPrivateKey = privateKeyFromSeed(vector.agents.worker.seed_hex);
  const workerPublicKey = createPublicKey(workerPrivateKey);

  assert.equal(computeAid(requesterPublicKey), vector.agents.requester.aid);
  assert.equal(computeAid(workerPublicKey), vector.agents.worker.aid);
  assert.equal(canonical(vector.task), vector.task_canonical);
  assert.equal(canonical(vector.receipt), vector.receipt_canonical);
  assert.equal(signObject(requesterPrivateKey, vector.task), vector.task_signature);
  assert.equal(signObject(workerPrivateKey, vector.receipt), vector.receipt_signature);
  assert.equal(verifyObject(requesterPublicKey, vector.task, vector.task_signature), true);
  assert.equal(verifyObject(workerPublicKey, vector.receipt, vector.receipt_signature), true);
});

test("Ed25519 descriptors export stable did:key bridges in Node", async () => {
  const vector = JSON.parse(await readFile("test-vectors/asp-v0.json", "utf8"));
  const requester = vector.agents.requester;

  assert.equal(didKeyFromDescriptor(requester), "did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd");
  assert.equal(publicKeySPKIFromDidKey("did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd"), requester.public_key_spki);
  assert.throws(() => didKeyFromPublicKeySPKI(`${requester.public_key_spki}AA`), /expected ed25519 public_key_spki/);

  const generated = createAgent("agent://local/did-key-test");
  assert.equal(generated.descriptor.did_key, didKeyFromDescriptor(generated.descriptor));
});

test("did:key bridge helpers reject missing values in Node", () => {
  for (const descriptor of [null, {}]) {
    assert.throws(() => didKeyFromDescriptor(descriptor), /expected ed25519 public_key_spki/);
  }

  for (const didKey of [null, {}]) {
    assert.throws(() => publicKeySPKIFromDidKey(didKey), /expected did:key z-base58btc value/);
  }
});

test("descriptor public key parsing rejects missing public keys in Node", async () => {
  const vector = JSON.parse(await readFile("test-vectors/asp-v0.json", "utf8"));
  const { public_key_spki, ...descriptorWithoutPublicKey } = vector.agents.requester;

  assert.throws(
    () => publicKeyFromDescriptor(descriptorWithoutPublicKey),
    /descriptor public key missing/,
  );
});

test("descriptor body helpers reject missing descriptor objects in Node", () => {
  for (const descriptor of [null, [], "descriptor"]) {
    assert.throws(() => descriptorBody(descriptor), /descriptor missing/);
  }

  for (const descriptor of [null, [], "zone"]) {
    assert.throws(() => zoneDescriptorBody(descriptor), /zone descriptor missing/);
  }
});

test("object signature verification fails closed on missing signatures in Node", async () => {
  const vector = JSON.parse(await readFile("test-vectors/asp-v0.json", "utf8"));
  const publicKey = createPublicKey(privateKeyFromSeed(vector.agents.requester.seed_hex));

  for (const signature of [undefined, null, {}, []]) {
    assert.equal(verifyObject(publicKey, vector.task, signature), false);
  }
});

test("FED_TASK_OPEN conformance vector verifies in Node", async () => {
  const vector = JSON.parse(await readFile("test-vectors/asp-v9.24-fed-task-open.json", "utf8"));
  const trustedZones = new Map(vector.trusted_zones.map((zone) => [zone.zid, zone]));
  const verified = verifyFederatedTaskOpen(vector.frame, trustedZones, vector.worker);

  assert.equal(canonical(verified.task), vector.task_canonical);
  assert.equal(verified.originZone.zid, vector.expected.origin_zid);
  assert.equal(verified.requester.aid, vector.expected.requester_aid);
  assert.equal(verified.worker.alias, vector.expected.worker_alias);
});

test("FED_TASK_OPEN verification rejects non-task-open frame types in Node", async () => {
  const vector = JSON.parse(await readFile("test-vectors/asp-v9.24-fed-task-open.json", "utf8"));
  const trustedZones = new Map(vector.trusted_zones.map((zone) => [zone.zid, zone]));

  assert.throws(
    () => verifyFederatedTaskOpen({ ...vector.frame, type: "FED_RECEIPT" }, trustedZones, vector.worker),
    /expected FED_TASK_OPEN frame/,
  );
});

test("FED_TASK_OPEN verification rejects missing frame objects in Node", async () => {
  const vector = JSON.parse(await readFile("test-vectors/asp-v9.24-fed-task-open.json", "utf8"));
  const trustedZones = new Map(vector.trusted_zones.map((zone) => [zone.zid, zone]));

  assert.throws(
    () => verifyFederatedTaskOpen(null, trustedZones, vector.worker),
    /expected FED_TASK_OPEN frame/,
  );
});

test("FED_TASK_OPEN verification rejects missing trusted Zone stores in Node", async () => {
  const vector = JSON.parse(await readFile("test-vectors/asp-v9.24-fed-task-open.json", "utf8"));

  assert.throws(
    () => verifyFederatedTaskOpen(vector.frame, undefined, vector.worker),
    /trusted zones missing/,
  );
});

test("FED_TASK_OPEN verification rejects missing worker descriptor context in Node", async () => {
  const vector = JSON.parse(await readFile("test-vectors/asp-v9.24-fed-task-open.json", "utf8"));
  const trustedZones = new Map(vector.trusted_zones.map((zone) => [zone.zid, zone]));

  for (const workerDescriptor of [undefined, null, [], "worker"]) {
    assert.throws(
      () => verifyFederatedTaskOpen(vector.frame, trustedZones, workerDescriptor),
      /task open worker missing/,
    );
  }
});

test("FED_TASK_OPEN verification rejects invalid worker descriptor identity in Node", async () => {
  const vector = JSON.parse(await readFile("test-vectors/asp-v9.24-fed-task-open.json", "utf8"));
  const trustedZones = new Map(vector.trusted_zones.map((zone) => [zone.zid, zone]));
  const { public_key_spki, ...workerWithoutPublicKey } = vector.worker;

  for (const workerDescriptor of [workerWithoutPublicKey, { ...vector.worker, aid: "aid:ed25519:tampered" }]) {
    assert.throws(
      () => verifyFederatedTaskOpen(vector.frame, trustedZones, workerDescriptor),
      /task open worker invalid/,
    );
  }
});

test("FED_TASK_OPEN verification rejects missing origin Zones in Node", async () => {
  const vector = JSON.parse(await readFile("test-vectors/asp-v9.24-fed-task-open.json", "utf8"));
  const trustedZones = new Map(vector.trusted_zones.map((zone) => [zone.zid, zone]));
  const { origin_zone, ...frameWithoutOriginZone } = vector.frame;

  assert.throws(
    () => verifyFederatedTaskOpen(frameWithoutOriginZone, trustedZones, vector.worker),
    /task open origin zone missing/,
  );
});

test("FED_TASK_OPEN verification rejects missing requesters in Node", async () => {
  const vector = JSON.parse(await readFile("test-vectors/asp-v9.24-fed-task-open.json", "utf8"));
  const trustedZones = new Map(vector.trusted_zones.map((zone) => [zone.zid, zone]));
  const { requester, ...frameWithoutRequester } = vector.frame;

  assert.throws(
    () => verifyFederatedTaskOpen(frameWithoutRequester, trustedZones, vector.worker),
    /task open requester missing/,
  );
});

test("FED_TASK_OPEN verification rejects missing tasks in Node", async () => {
  const vector = JSON.parse(await readFile("test-vectors/asp-v9.24-fed-task-open.json", "utf8"));
  const trustedZones = new Map(vector.trusted_zones.map((zone) => [zone.zid, zone]));
  const { task, ...frameWithoutTask } = vector.frame;

  assert.throws(
    () => verifyFederatedTaskOpen(frameWithoutTask, trustedZones, vector.worker),
    /task open task missing/,
  );
});

test("FED_TASK_OPEN verification rejects missing task signatures in Node", async () => {
  const vector = JSON.parse(await readFile("test-vectors/asp-v9.24-fed-task-open.json", "utf8"));
  const trustedZones = new Map(vector.trusted_zones.map((zone) => [zone.zid, zone]));
  const { signature, ...taskWithoutSignature } = vector.frame.task;

  for (const task of [taskWithoutSignature, { ...taskWithoutSignature, signature: "" }, { ...taskWithoutSignature, signature: null }, { ...taskWithoutSignature, signature: [] }]) {
    assert.throws(
      () => verifyFederatedTaskOpen({ ...vector.frame, task }, trustedZones, vector.worker),
      /task signature missing/,
    );
  }
});

test("FED_TASK_OPEN verification rejects unbound requesters in Node", async () => {
  const vector = JSON.parse(await readFile("test-vectors/asp-v9.24-fed-task-open.json", "utf8"));
  const trustedZones = new Map(vector.trusted_zones.map((zone) => [zone.zid, zone]));
  const { requester_zone_binding, ...unboundFrame } = vector.frame;

  assert.throws(
    () => verifyFederatedTaskOpen(unboundFrame, trustedZones, vector.worker),
    /requester zone binding missing/,
  );
});

test("FED_TASK_OPEN verification rejects unsafe task ids in Node", async () => {
  const vector = JSON.parse(await readFile("test-vectors/asp-v9.24-fed-task-open.json", "utf8"));
  const trustedZones = new Map(vector.trusted_zones.map((zone) => [zone.zid, zone]));
  const { signature, ...taskBody } = vector.frame.task;
  const task = { ...taskBody, task_id: "../bad/task" };

  assert.throws(
    () => verifyFederatedTaskOpen({ ...vector.frame, task: { ...task, signature: signObject(privateKeyFromSeed(vector.requester_seed_hex), task) } }, trustedZones, vector.worker),
    /task_id invalid/,
  );
});

test("FED_RECEIPT conformance vector verifies in Node", async () => {
  const vector = JSON.parse(await readFile("test-vectors/asp-v9.25-fed-receipt.json", "utf8"));
  const trustedZones = new Map(vector.trusted_zones.map((zone) => [zone.zid, zone]));
  const verified = verifyFederatedReceipt(vector.frame, trustedZones);

  assert.equal(canonical(verified.receipt), vector.receipt_canonical);
  assert.equal(verified.zone.zid, vector.expected.worker_zid);
  assert.equal(verified.worker.aid, vector.expected.worker_aid);
  assert.equal(verified.receipt.origin_zone, vector.expected.origin_zid);
});

test("FED_RECEIPT verification rejects non-receipt frame types in Node", async () => {
  const vector = JSON.parse(await readFile("test-vectors/asp-v9.25-fed-receipt.json", "utf8"));
  const trustedZones = new Map(vector.trusted_zones.map((zone) => [zone.zid, zone]));

  assert.throws(
    () => verifyFederatedReceipt({ ...vector.frame, type: "FED_TASK_OPEN" }, trustedZones),
    /expected FED_RECEIPT frame/,
  );
});

test("FED_RECEIPT verification rejects missing frame objects in Node", async () => {
  assert.throws(
    () => verifyFederatedReceipt(null, new Map()),
    /expected FED_RECEIPT frame/,
  );
});

test("FED_RECEIPT verification rejects missing trusted Zone stores in Node", async () => {
  const vector = JSON.parse(await readFile("test-vectors/asp-v9.25-fed-receipt.json", "utf8"));

  assert.throws(
    () => verifyFederatedReceipt(vector.frame),
    /trusted zones missing/,
  );
});

test("FED_RECEIPT verification rejects missing signing Zones in Node", async () => {
  const vector = JSON.parse(await readFile("test-vectors/asp-v9.25-fed-receipt.json", "utf8"));
  const trustedZones = new Map(vector.trusted_zones.map((zone) => [zone.zid, zone]));
  const { zone, ...frameWithoutZone } = vector.frame;

  assert.throws(
    () => verifyFederatedReceipt(frameWithoutZone, trustedZones),
    /receipt zone missing/,
  );
});

test("FED_RECEIPT verification rejects missing workers in Node", async () => {
  const vector = JSON.parse(await readFile("test-vectors/asp-v9.25-fed-receipt.json", "utf8"));
  const trustedZones = new Map(vector.trusted_zones.map((zone) => [zone.zid, zone]));
  const { worker, ...frameWithoutWorker } = vector.frame;

  assert.throws(
    () => verifyFederatedReceipt(frameWithoutWorker, trustedZones),
    /receipt worker missing/,
  );
});

test("FED_RECEIPT verification rejects invalid worker descriptor identity in Node", async () => {
  const vector = JSON.parse(await readFile("test-vectors/asp-v9.25-fed-receipt.json", "utf8"));
  const trustedZones = new Map(vector.trusted_zones.map((zone) => [zone.zid, zone]));
  const { public_key_spki, ...workerWithoutPublicKey } = vector.frame.worker;

  for (const worker of [workerWithoutPublicKey, { ...vector.frame.worker, aid: "aid:ed25519:tampered" }]) {
    assert.throws(
      () => verifyFederatedReceipt({ ...vector.frame, worker }, trustedZones),
      /receipt worker invalid/,
    );
  }
});

test("FED_RECEIPT verification rejects missing receipt bodies in Node", async () => {
  const vector = JSON.parse(await readFile("test-vectors/asp-v9.25-fed-receipt.json", "utf8"));
  const trustedZones = new Map(vector.trusted_zones.map((zone) => [zone.zid, zone]));
  const { receipt, ...frameWithoutReceipt } = vector.frame;

  assert.throws(
    () => verifyFederatedReceipt(frameWithoutReceipt, trustedZones),
    /receipt body missing/,
  );
});

test("FED_RECEIPT verification rejects missing receipt signatures in Node", async () => {
  const vector = JSON.parse(await readFile("test-vectors/asp-v9.25-fed-receipt.json", "utf8"));
  const trustedZones = new Map(vector.trusted_zones.map((zone) => [zone.zid, zone]));
  const { signature, ...receiptWithoutSignature } = vector.frame.receipt;

  for (const receipt of [receiptWithoutSignature, { ...receiptWithoutSignature, signature: "" }, { ...receiptWithoutSignature, signature: null }, { ...receiptWithoutSignature, signature: [] }]) {
    assert.throws(
      () => verifyFederatedReceipt({ ...vector.frame, receipt }, trustedZones),
      /receipt signature missing/,
    );
  }
});

test("FED_RECEIPT verification rejects untrusted signed origin zones in Node", async () => {
  const vector = JSON.parse(await readFile("test-vectors/asp-v9.25-fed-receipt.json", "utf8"));
  const trustedZones = new Map(vector.trusted_zones.map((zone) => [zone.zid, zone]));
  trustedZones.delete(vector.frame.receipt.origin_zone);

  assert.throws(
    () => verifyFederatedReceipt(vector.frame, trustedZones),
    /untrusted receipt origin zone/,
  );
});

test("FED_RECEIPT verification rejects missing task digests in Node", async () => {
  const vector = JSON.parse(await readFile("test-vectors/asp-v9.25-fed-receipt.json", "utf8"));
  const trustedZones = new Map(vector.trusted_zones.map((zone) => [zone.zid, zone]));
  const { task_digest, ...receiptWithoutDigest } = vector.frame.receipt;

  assert.throws(
    () => verifyFederatedReceipt({ ...vector.frame, receipt: receiptWithoutDigest }, trustedZones),
    /receipt task_digest missing/,
  );
});

test("FED_RECEIPT verification rejects unsafe task ids in Node", async () => {
  const vector = JSON.parse(await readFile("test-vectors/asp-v9.25-fed-receipt.json", "utf8"));
  const workerPrivateKey = privateKeyFromSeed(vector.worker_seed_hex);
  const trustedZones = new Map(vector.trusted_zones.map((zone) => [zone.zid, zone]));
  const { signature, ...receipt } = vector.frame.receipt;
  const badReceipt = { ...receipt, task_id: "../bad/task" };

  assert.throws(
    () => verifyFederatedReceipt({ ...vector.frame, receipt: { ...badReceipt, signature: signObject(workerPrivateKey, badReceipt) } }, trustedZones),
    /task_id invalid/,
  );
});

test("FED_RECEIPT verification rejects signed artifact manifest hash mismatch in Node", async () => {
  const vector = JSON.parse(await readFile("test-vectors/asp-v9.25-fed-receipt.json", "utf8"));
  const workerPrivateKey = privateKeyFromSeed(vector.worker_seed_hex);
  const trustedZones = new Map(vector.trusted_zones.map((zone) => [zone.zid, zone]));
  const { signature, ...receipt } = vector.frame.receipt;
  const uri = receipt.artifact_refs[0];
  const badReceipt = {
    ...receipt,
    artifact_manifests: [{
      uri,
      sha256: "0".repeat(64),
      size: 12,
      media_type: "text/markdown; charset=utf-8",
      manifest_hash: "1".repeat(64),
    }],
  };

  assert.throws(
    () => verifyFederatedReceipt({ ...vector.frame, receipt: { ...badReceipt, signature: signObject(workerPrivateKey, badReceipt) } }, trustedZones),
    /artifact manifest hash mismatch/,
  );
});

test("FED_RECEIPT verification rejects malformed artifact manifest SHA-256 in Node", async () => {
  const vector = JSON.parse(await readFile("test-vectors/asp-v9.25-fed-receipt.json", "utf8"));
  const workerPrivateKey = privateKeyFromSeed(vector.worker_seed_hex);
  const trustedZones = new Map(vector.trusted_zones.map((zone) => [zone.zid, zone]));
  const { signature, ...receipt } = vector.frame.receipt;
  const uri = receipt.artifact_refs[0];
  const manifest = {
    uri,
    sha256: "../evil",
    size: 12,
    media_type: "text/markdown; charset=utf-8",
    afp: "afp:sha256:../evil",
  };
  const { manifest_hash, ...body } = manifest;
  manifest.manifest_hash = createHash("sha256").update(canonical(body)).digest("hex");
  const badReceipt = { ...receipt, artifact_manifests: [manifest] };

  assert.throws(
    () => verifyFederatedReceipt({ ...vector.frame, receipt: { ...badReceipt, signature: signObject(workerPrivateKey, badReceipt) } }, trustedZones),
    /artifact manifest sha256 invalid/,
  );
});

test("FED_RECEIPT verification rejects malformed artifact manifest size in Node", async () => {
  const vector = JSON.parse(await readFile("test-vectors/asp-v9.25-fed-receipt.json", "utf8"));
  const workerPrivateKey = privateKeyFromSeed(vector.worker_seed_hex);
  const trustedZones = new Map(vector.trusted_zones.map((zone) => [zone.zid, zone]));
  const { signature, ...receipt } = vector.frame.receipt;
  const uri = receipt.artifact_refs[0];

  for (const size of [-1, 1.5]) {
    const manifest = {
      uri,
      sha256: "0".repeat(64),
      size,
      media_type: "text/markdown; charset=utf-8",
      afp: `afp:sha256:${"0".repeat(64)}`,
    };
    const { manifest_hash, ...body } = manifest;
    manifest.manifest_hash = createHash("sha256").update(canonical(body)).digest("hex");
    const badReceipt = { ...receipt, artifact_manifests: [manifest] };

    assert.throws(
      () => verifyFederatedReceipt({ ...vector.frame, receipt: { ...badReceipt, signature: signObject(workerPrivateKey, badReceipt) } }, trustedZones),
      /artifact manifest size invalid/,
    );
  }
});

test("FED_RECEIPT verification rejects malformed artifact manifest URIs in Node", async () => {
  const vector = JSON.parse(await readFile("test-vectors/asp-v9.25-fed-receipt.json", "utf8"));
  const workerPrivateKey = privateKeyFromSeed(vector.worker_seed_hex);
  const trustedZones = new Map(vector.trusted_zones.map((zone) => [zone.zid, zone]));
  const { signature, ...receipt } = vector.frame.receipt;
  const manifest = {
    uri: 5,
    sha256: "0".repeat(64),
    size: 12,
    media_type: "text/markdown; charset=utf-8",
    afp: `afp:sha256:${"0".repeat(64)}`,
  };
  const { manifest_hash, ...body } = manifest;
  manifest.manifest_hash = createHash("sha256").update(canonical(body)).digest("hex");
  const badReceipt = { ...receipt, artifact_refs: [5], artifact_manifests: [manifest] };

  assert.throws(
    () => verifyFederatedReceipt({ ...vector.frame, receipt: { ...badReceipt, signature: signObject(workerPrivateKey, badReceipt) } }, trustedZones),
    /artifact manifest uri invalid/,
  );
});

test("receipt artifact manifest verification rejects missing objects in Node", () => {
  assert.throws(
    () => verifyReceiptArtifactManifests(null),
    /receipt artifact manifest count mismatch/,
  );
  assert.throws(
    () => verifyReceiptArtifactManifests({ artifact_refs: ["artifact://local/missing"], artifact_manifests: [null] }),
    /artifact manifest missing/,
  );
});

function receiptFrameWithCheckpoint(vector, checkpointPatch = {}, receiptPatch = {}) {
  const workerPrivateKey = privateKeyFromSeed(vector.worker_seed_hex);
  const checkpointBody = {
    task_id: vector.expected.task_id,
    parent_checkpoint: null,
    event_index: 5,
    state_digest: "1".repeat(64),
    artifact_refs: vector.frame.receipt.artifact_refs,
    policy_digest: "2".repeat(64),
    created_by: vector.frame.worker.aid,
  };
  checkpointBody.checkpoint_id = `checkpoint:sha256:${createHash("sha256").update(canonical(checkpointBody)).digest("hex")}`;
  const checkpoint = { ...checkpointBody, checkpoint_signature: signObject(workerPrivateKey, checkpointBody), ...checkpointPatch };
  const { signature, ...receipt } = vector.frame.receipt;
  const receiptBody = { ...receipt, checkpoint_refs: [checkpoint.checkpoint_id], checkpoints: [checkpoint], ...receiptPatch };
  return { ...vector.frame, receipt: { ...receiptBody, signature: signObject(workerPrivateKey, receiptBody) } };
}

test("FED_RECEIPT verification accepts signed checkpoint evidence in Node", async () => {
  const vector = JSON.parse(await readFile("test-vectors/asp-v9.25-fed-receipt.json", "utf8"));
  const trustedZones = new Map(vector.trusted_zones.map((zone) => [zone.zid, zone]));
  const frame = receiptFrameWithCheckpoint(vector);
  const verified = verifyFederatedReceipt(frame, trustedZones);

  assert.deepEqual(verified.receipt.checkpoint_refs, [frame.receipt.checkpoints[0].checkpoint_id]);
});

test("FED_RECEIPT verification rejects checkpoint ref mismatch in Node", async () => {
  const vector = JSON.parse(await readFile("test-vectors/asp-v9.25-fed-receipt.json", "utf8"));
  const trustedZones = new Map(vector.trusted_zones.map((zone) => [zone.zid, zone]));
  const frame = receiptFrameWithCheckpoint(vector, {}, { checkpoint_refs: [`checkpoint:sha256:${"0".repeat(64)}`] });

  assert.throws(
    () => verifyFederatedReceipt(frame, trustedZones),
    /checkpoint ref mismatch/,
  );
});

test("FED_RECEIPT verification rejects checkpoint signature mismatch in Node", async () => {
  const vector = JSON.parse(await readFile("test-vectors/asp-v9.25-fed-receipt.json", "utf8"));
  const trustedZones = new Map(vector.trusted_zones.map((zone) => [zone.zid, zone]));
  const frame = receiptFrameWithCheckpoint(vector, { state_digest: "3".repeat(64) });

  assert.throws(
    () => verifyFederatedReceipt(frame, trustedZones),
    /checkpoint signature verification failed/,
  );
});

test("FED_RECEIPT CLI verifies one frame in Node", async () => {
  const vector = JSON.parse(await readFile("test-vectors/asp-v9.25-fed-receipt.json", "utf8"));
  const framePath = "state/node-fed-receipt-frame.json";
  const trustedPath = "state/node-fed-receipt-trusted.json";
  const taskPath = "state/node-fed-receipt-wrong-task.json";
  await writeFile(framePath, `${JSON.stringify(vector.frame, null, 2)}\n`);
  await writeFile(trustedPath, `${JSON.stringify({ zones: vector.trusted_zones }, null, 2)}\n`);
  await writeFile(taskPath, `${JSON.stringify({ task_id: vector.expected.task_id, intent: "wrong task" }, null, 2)}\n`);

  assert.deepEqual(JSON.parse((await execFileAsync("node", ["asp-verify.mjs", "fed-receipt", framePath, trustedPath])).stdout), {
    fed_receipt_verify: "ok",
    task_id: vector.expected.task_id,
    receipt_digest: createHash("sha256").update(vector.receipt_canonical).digest("hex"),
  });
  await assert.rejects(
    () => execFileAsync("node", ["asp-verify.mjs", "fed-receipt", framePath, trustedPath, taskPath]),
    (error) => error.stderr.includes("receipt task_digest mismatch"),
  );
  await assert.rejects(
    () => execFileAsync("node", ["asp-verify.mjs", "fed-receipt", framePath, trustedPath, taskPath, "extra.json"]),
    (error) => error.stderr.includes("usage: node asp-verify.mjs"),
  );
  const checkpointFrame = receiptFrameWithCheckpoint(vector);
  await writeFile(framePath, `${JSON.stringify(checkpointFrame, null, 2)}\n`);
  const { signature: _checkpointSignature, ...checkpointReceipt } = checkpointFrame.receipt;
  assert.deepEqual(JSON.parse((await execFileAsync("node", ["asp-verify.mjs", "fed-receipt", framePath, trustedPath])).stdout), {
    fed_receipt_verify: "ok",
    task_id: vector.expected.task_id,
    receipt_digest: createHash("sha256").update(canonical(checkpointReceipt)).digest("hex"),
  });
  await writeFile(framePath, `${JSON.stringify(receiptFrameWithCheckpoint(vector, { state_digest: "3".repeat(64) }), null, 2)}\n`);
  await assert.rejects(
    () => execFileAsync("node", ["asp-verify.mjs", "fed-receipt", framePath, trustedPath]),
    (error) => error.stderr.includes("checkpoint signature verification failed"),
  );

  await writeFile(framePath, `${JSON.stringify({ ...vector.frame, receipt: { ...vector.frame.receipt, executing_zone: "zid:ed25519:bad" } }, null, 2)}\n`);
  await assert.rejects(
    () => execFileAsync("node", ["asp-verify.mjs", "fed-receipt", framePath, trustedPath]),
    (error) => error.stderr.includes("receipt executing_zone mismatch"),
  );
});

test("FED_RECEIPT artifact CLI verifies one frame and local artifact bytes in Node", async () => {
  const vector = JSON.parse(await readFile("test-vectors/asp-v9.25-fed-receipt.json", "utf8"));
  const artifact = await writeArtifact(
    vector.frame.receipt.artifact_refs[0],
    "# Federated Summary\n\nThe conformance task produced a verifiable local artifact.\n",
  );
  const { signature, ...receipt } = vector.frame.receipt;
  const receiptWithManifest = { ...receipt, artifact_manifests: [artifact.manifest] };
  const frame = { ...vector.frame, receipt: { ...receiptWithManifest, signature: signObject(privateKeyFromSeed(vector.worker_seed_hex), receiptWithManifest) } };
  const framePath = "state/node-fed-receipt-artifact-frame.json";
  const trustedPath = "state/node-fed-receipt-artifact-trusted.json";
  const taskPath = "state/node-fed-receipt-artifact-wrong-task.json";
  await writeFile(framePath, `${JSON.stringify(frame, null, 2)}\n`);
  await writeFile(trustedPath, `${JSON.stringify({ zones: vector.trusted_zones }, null, 2)}\n`);
  await writeFile(taskPath, `${JSON.stringify({ task_id: vector.expected.task_id, intent: "wrong task" }, null, 2)}\n`);

  assert.deepEqual(JSON.parse((await execFileAsync("node", ["asp-verify.mjs", "fed-receipt-artifacts", framePath, trustedPath])).stdout), {
    fed_receipt_artifacts_verify: "ok",
    task_id: vector.expected.task_id,
    artifact_count: 1,
    artifact_uris: [artifact.manifest.uri],
    artifact_sha256s: [artifact.manifest.sha256],
    artifact_manifest_hashes: [artifact.manifest.manifest_hash],
    receipt_digest: createHash("sha256").update(canonical(receiptWithManifest)).digest("hex"),
  });
  await assert.rejects(
    () => execFileAsync("node", ["asp-verify.mjs", "fed-receipt-artifacts", framePath, trustedPath, taskPath]),
    (error) => error.stderr.includes("receipt task_digest mismatch"),
  );
  await assert.rejects(
    () => execFileAsync("node", ["asp-verify.mjs", "fed-receipt-artifacts", framePath, trustedPath, taskPath, "extra.json"]),
    (error) => error.stderr.includes("usage: node asp-verify.mjs"),
  );

  await writeFile("artifacts/fed_task_conformance_001/federated-summary.md", "tampered\n");
  await assert.rejects(
    () => execFileAsync("node", ["asp-verify.mjs", "fed-receipt-artifacts", framePath, trustedPath]),
    (error) => /artifact bytes (size|digest) mismatch/.test(error.stderr),
  );
});

test("signed Swarm execution binding verifies exact plan and executable graph", () => {
  const coordinator = createZone("zone://swarm-execution-binding-test");
  const requester = createAgent("agent://swarm-execution-binding/requester");
  const originalWorker = createAgent("agent://swarm-execution-binding/original", {}, ["asp+local://test"], ["summarize.text"]);
  const migratedWorker = createAgent("agent://swarm-execution-binding/migrated", {}, ["asp+local://test"], ["summarize.text"]);
  const planSteps = [
    { step_id: "draft", capability: "summarize.text", depends_on: [] },
    { step_id: "final", capability: "summarize.text", depends_on: ["draft"] },
  ];
  const planFrame = swarmPlan(coordinator, "swarm://node-test/execution-binding", "Draft and finalize a summary.", planSteps, "a".repeat(64));
  const verifiedPlan = verifySwarmPlan(planFrame, new Map([[coordinator.zid, coordinator.descriptor]]));
  const signedTasks = [
    { task_id: "binding_draft", intent: "Draft the summary.", signature: "task-signature-draft" },
    { task_id: "binding_final", intent: "Finalize the summary.", signature: "task-signature-final" },
  ];
  const executableSteps = [
    { step_id: "draft", depends_on: [], task: signedTasks[0] },
    { step_id: "final", depends_on: ["draft"], task: signedTasks[1] },
  ];
  const resolvedWorkers = [originalWorker.descriptor, migratedWorker.descriptor];
  const binding = swarmExecutionBinding(coordinator, planFrame, executableSteps);
  const expectedSteps = planSteps.map((step, index) => ({
    step_id: step.step_id,
    depends_on: step.depends_on,
    capability: step.capability,
    task_digest: createHash("sha256").update(canonical(signedTasks[index])).digest("hex"),
  }));
  const digestPreimage = { swarm_id: planFrame.plan.swarm_id, plan_digest: planFrame.plan.plan_digest, steps: expectedSteps };
  const expectedDigest = createHash("sha256").update(canonical(digestPreimage)).digest("hex");

  assert.deepEqual(binding.steps, expectedSteps);
  assert.equal(binding.execution_graph_digest, expectedDigest);
  const { binding_signature, ...bindingBody } = binding;
  assert.equal(verifyObject(publicKeyFromDescriptor(coordinator.descriptor), bindingBody, binding_signature), true);
  const verified = verifySwarmExecutionBinding(binding, verifiedPlan, executableSteps, resolvedWorkers);
  assert.deepEqual(verified, {
    swarmId: planFrame.plan.swarm_id,
    planDigest: planFrame.plan.plan_digest,
    steps: expectedSteps,
    executionGraphDigest: expectedDigest,
  });
  assert.equal(Object.isFrozen(verified), true);
  assert.equal(Object.isFrozen(verified.steps), true);
  assert.equal(Object.isFrozen(verified.steps[0]), true);
  assert.equal(Object.isFrozen(verified.steps[0].depends_on), true);

  const signedBindingFor = ({
    format = "asp-swarm-execution-binding/v1",
    swarmId = planFrame.plan.swarm_id,
    planDigest = planFrame.plan.plan_digest,
    steps = expectedSteps,
  } = {}) => {
    const execution_graph_digest = createHash("sha256").update(canonical({ swarm_id: swarmId, plan_digest: planDigest, steps })).digest("hex");
    const body = { format, swarm_id: swarmId, plan_digest: planDigest, steps, execution_graph_digest };
    return { ...body, binding_signature: signObject(coordinator.privateKey, body) };
  };
  const rejects = (candidate, message, candidateSteps = executableSteps, candidateWorkers = resolvedWorkers) => {
    assert.throws(
      () => verifySwarmExecutionBinding(candidate, verifiedPlan, candidateSteps, candidateWorkers),
      message,
    );
  };
  const rejectsPlanSteps = (steps, message) => {
    const plan_digest = createHash("sha256").update(canonical({ intent: planFrame.plan.intent, steps })).digest("hex");
    const planBody = {
      swarm_id: planFrame.plan.swarm_id,
      intent: planFrame.plan.intent,
      steps,
      policy_digest: planFrame.plan.policy_digest,
      plan_digest,
    };
    const candidateVerifiedPlan = {
      zone: coordinator.descriptor,
      plan: { ...planBody, plan_signature: signObject(coordinator.privateKey, planBody) },
    };
    assert.throws(
      () => verifySwarmExecutionBinding(signedBindingFor({ planDigest: plan_digest }), candidateVerifiedPlan, executableSteps, resolvedWorkers),
      message,
    );
  };

  rejectsPlanSteps([{ ...planSteps[0], depends_on: null }, planSteps[1]], /swarm plan step depends_on invalid/);
  for (const constraint of [null, [], "invalid"]) {
    rejectsPlanSteps([{ ...planSteps[0], constraint }, planSteps[1]], /swarm plan step constraint invalid/);
  }

  rejects(signedBindingFor({ swarmId: "swarm://node-test/substituted" }), /execution binding swarm_id mismatch/);
  rejects(signedBindingFor({ planDigest: "b".repeat(64) }), /execution binding plan_digest mismatch/);
  rejects(signedBindingFor({ steps: [...expectedSteps].reverse() }), /execution binding step order mismatch/);
  rejects(signedBindingFor({ steps: expectedSteps.slice(0, 1) }), /execution binding step count mismatch/);
  rejects(signedBindingFor({ steps: [...expectedSteps, { step_id: "extra", depends_on: ["final"], capability: "summarize.text", task_digest: "c".repeat(64) }] }), /execution binding step count mismatch/);
  rejects(signedBindingFor({ steps: [expectedSteps[0], { ...expectedSteps[1], step_id: "draft" }] }), /execution binding duplicate step_id/);
  rejects(signedBindingFor({ steps: [expectedSteps[0], { ...expectedSteps[1], depends_on: [] }] }), /execution binding step depends_on mismatch/);
  rejects(signedBindingFor({ steps: [expectedSteps[0], { ...expectedSteps[1], capability: "translate.text" }] }), /execution binding step capability mismatch/);
  rejects(signedBindingFor({ steps: [{ ...expectedSteps[0], task_digest: "bad" }, expectedSteps[1]] }), /execution binding step task_digest invalid/);
  rejects(signedBindingFor({ steps: [expectedSteps[0], { ...expectedSteps[1], depends_on: ["draft", "draft"] }] }), /execution binding duplicate dependency/);

  const changedTaskSteps = structuredClone(executableSteps);
  changedTaskSteps[1].task.intent = "Substituted task.";
  rejects(binding, /execution binding task_digest mismatch/, changedTaskSteps);
  const changedDependencySteps = structuredClone(executableSteps);
  changedDependencySteps[1].depends_on = [];
  rejects(binding, /execution binding executable depends_on mismatch/, changedDependencySteps);

  rejects({ ...binding, binding_signature: "bad" }, /execution binding signature verification failed/);
  rejects(binding, /execution binding worker capability missing/, executableSteps, [createAgent("agent://swarm-execution-binding/incapable-original", {}, ["asp+local://test"], ["translate.text"]).descriptor, migratedWorker.descriptor]);
  rejects(binding, /execution binding worker capability missing/, executableSteps, [originalWorker.descriptor, createAgent("agent://swarm-execution-binding/incapable-migration", {}, ["asp+local://test"], ["translate.text"]).descriptor]);
  rejects(binding, /execution binding worker capabilities invalid/, executableSteps, [createAgent("agent://swarm-execution-binding/malformed-capabilities", {}, ["asp+local://test"], ["summarize.text", { bad: true }]).descriptor, migratedWorker.descriptor]);
  rejects(binding, /execution binding worker capability duplicate/, executableSteps, [originalWorker.descriptor, createAgent("agent://swarm-execution-binding/duplicate-capability", {}, ["asp+local://test"], ["summarize.text", "summarize.text"]).descriptor]);
  rejects({ ...binding, unexpected: true }, /execution binding fields invalid/);
  rejects(signedBindingFor({ steps: [{ ...expectedSteps[0], unexpected: true }, expectedSteps[1]] }), /execution binding step fields invalid/);
  const { capability: _capability, ...stepWithoutCapability } = expectedSteps[0];
  rejects(signedBindingFor({ steps: [stepWithoutCapability, expectedSteps[1]] }), /execution binding step fields invalid/);
});

test("v2 signed receipt digest includes worker signature", () => {
  const signedReceipt = {
    task_id: "binding_receipt",
    task_digest: "d".repeat(64),
    status: "completed",
    signature: "worker-signature-a",
  };
  const changedSignature = { ...signedReceipt, signature: "worker-signature-b" };

  assert.equal(signedReceiptDigest(signedReceipt), createHash("sha256").update(canonical(signedReceipt)).digest("hex"));
  assert.equal(signedReceiptDigest(changedSignature), createHash("sha256").update(canonical(changedSignature)).digest("hex"));
  assert.notEqual(signedReceiptDigest(signedReceipt), signedReceiptDigest(changedSignature));
  const { signature: _signature, ...unsignedReceipt } = signedReceipt;
  assert.throws(() => signedReceiptDigest(unsignedReceipt), /signed receipt signature missing/);
});

test("result_artifact selects one manifest while auxiliary artifacts remain evidence", () => {
  const manifestFor = (uri, sha256, mediaType = "text/plain") => {
    const body = {
      uri,
      sha256,
      size: 7,
      media_type: mediaType,
      afp: `afp:sha256:${sha256}`,
    };
    return { ...body, manifest_hash: createHash("sha256").update(canonical(body)).digest("hex") };
  };
  const resultManifest = manifestFor("artifact://local/result-selection/result.txt", "1".repeat(64));
  const transcriptManifest = manifestFor("artifact://local/result-selection/transcript.jsonl", "2".repeat(64), "application/x-ndjson");
  const pointer = {
    uri: resultManifest.uri,
    sha256: resultManifest.sha256,
    manifest_hash: resultManifest.manifest_hash,
  };
  const receipt = {
    artifact_refs: [resultManifest.uri, transcriptManifest.uri],
    artifact_manifests: [resultManifest, transcriptManifest],
    result_artifact: pointer,
  };

  assert.deepEqual(verifyResultArtifact(receipt), pointer);
  assert.equal(verifyResultArtifact({ artifact_refs: receipt.artifact_refs, artifact_manifests: receipt.artifact_manifests }), null);
  assert.deepEqual(receipt.artifact_manifests[1], transcriptManifest);

  for (const [name, resultArtifact, message] of [
    ["array of pointers", [pointer, pointer], /result artifact invalid/],
    ["unknown pointer field", { ...pointer, media_type: resultManifest.media_type }, /result artifact fields invalid/],
    ["unknown manifest", { ...pointer, uri: "artifact://local/result-selection/missing.txt" }, /result artifact manifest mismatch/],
    ["sha mismatch", { ...pointer, sha256: "3".repeat(64) }, /result artifact manifest mismatch/],
    ["manifest hash mismatch", { ...pointer, manifest_hash: "4".repeat(64) }, /result artifact manifest mismatch/],
  ]) {
    assert.throws(() => verifyResultArtifact({ ...receipt, result_artifact: resultArtifact }), message, name);
  }

  const zone = createZone("zone://result-artifact-verifier");
  const worker = createAgent("agent://result-artifact-verifier/worker", {}, ["asp+local://result-artifact"], ["summarize.text"]);
  const taskBody = {
    task_id: "result_artifact_receipt",
    from: worker.aid,
    to: worker.alias,
    intent: "Verify the signed result pointer.",
  };
  const signedTask = { ...taskBody, signature: signObject(worker.privateKey, taskBody) };
  const receiptBody = {
    task_id: taskBody.task_id,
    task_digest: createHash("sha256").update(canonical(signedTask)).digest("hex"),
    origin_zone: zone.zid,
    executing_zone: zone.zid,
    to: worker.aid,
    artifact_refs: receipt.artifact_refs,
    artifact_manifests: receipt.artifact_manifests,
    result_artifact: pointer,
  };
  const frameFor = (body) => ({
    type: "FED_RECEIPT",
    zone: zone.descriptor,
    worker: worker.descriptor,
    zone_binding: zoneBinding(zone, worker.descriptor),
    receipt: { ...body, signature: signObject(worker.privateKey, body) },
  });
  const trustedZones = new Map([[zone.zid, zone.descriptor]]);
  assert.deepEqual(verifyFederatedReceipt(frameFor(receiptBody), trustedZones, signedTask).receipt.result_artifact, pointer);
  assert.throws(
    () => verifyFederatedReceipt(frameFor({ ...receiptBody, result_artifact: { ...pointer, sha256: "5".repeat(64) } }), trustedZones, signedTask),
    /result artifact manifest mismatch/,
  );
});

test("derives final_output only from one terminal result", () => {
  const swarmId = "swarm://node-test/final-output";
  const planDigest = "a".repeat(64);
  const executionGraphDigest = "b".repeat(64);
  const steps = [
    { step_id: "draft", depends_on: [], capability: "summarize.text", task_digest: "c".repeat(64) },
    { step_id: "final", depends_on: ["draft"], capability: "summarize.text", task_digest: "d".repeat(64) },
  ];
  const binding = { swarmId, planDigest, executionGraphDigest, steps };
  const manifestFor = (stepId, digit) => {
    const body = {
      uri: `artifact://local/${stepId}/result.txt`,
      sha256: digit.repeat(64),
      size: 8,
      media_type: "text/plain",
      afp: `afp:sha256:${digit.repeat(64)}`,
    };
    return { ...body, manifest_hash: createHash("sha256").update(canonical(body)).digest("hex") };
  };
  const receiptFor = (step, digit, includeResult = true) => {
    const manifest = manifestFor(step.step_id, digit);
    const resultArtifact = { uri: manifest.uri, sha256: manifest.sha256, manifest_hash: manifest.manifest_hash };
    return {
      task_id: `task_${step.step_id}`,
      task_digest: step.task_digest,
      artifact_refs: [manifest.uri],
      artifact_manifests: [manifest],
      ...(includeResult ? { result_artifact: resultArtifact } : {}),
      swarm: {
        swarm_id: swarmId,
        step_id: step.step_id,
        after: step.depends_on,
        plan_digest: planDigest,
        execution_graph_digest: executionGraphDigest,
        capability: step.capability,
        task_digest: step.task_digest,
      },
      signature: `worker-signature-${step.step_id}`,
    };
  };
  const draftReceipt = receiptFor(steps[0], "6");
  const finalReceipt = receiptFor(steps[1], "7");
  const completed = new Map([["draft", draftReceipt], ["final", finalReceipt]]);
  const expected = {
    step_id: "final",
    task_id: "task_final",
    signed_receipt_digest: signedReceiptDigest(finalReceipt),
    artifact: finalReceipt.result_artifact,
    selection_rule: "single-terminal-result",
  };

  assert.deepEqual(deriveSwarmFinalOutput(binding, completed), expected);

  const missingTerminalResult = structuredClone(finalReceipt);
  delete missingTerminalResult.result_artifact;
  assert.throws(
    () => deriveSwarmFinalOutput(binding, new Map([["draft", draftReceipt], ["final", missingTerminalResult]])),
    /terminal result artifact missing/,
  );
  assert.throws(
    () => deriveSwarmFinalOutput({ ...binding, steps: [steps[0], { ...steps[1], depends_on: [] }] }, completed),
    /single terminal step required/,
  );
  const nonTerminalOnly = structuredClone(finalReceipt);
  delete nonTerminalOnly.result_artifact;
  assert.throws(
    () => deriveSwarmFinalOutput(binding, new Map([["draft", draftReceipt], ["final", nonTerminalOnly]])),
    /terminal result artifact missing/,
  );
  const wrongTaskDigest = structuredClone(finalReceipt);
  wrongTaskDigest.task_digest = "e".repeat(64);
  assert.throws(
    () => deriveSwarmFinalOutput(binding, new Map([["draft", draftReceipt], ["final", wrongTaskDigest]])),
    /receipt task digest mismatch/,
  );
  const wrongGraphDigest = structuredClone(finalReceipt);
  wrongGraphDigest.swarm.execution_graph_digest = "f".repeat(64);
  assert.throws(
    () => deriveSwarmFinalOutput(binding, new Map([["draft", draftReceipt], ["final", wrongGraphDigest]])),
    /receipt execution graph digest mismatch/,
  );
  assert.throws(
    () => deriveSwarmFinalOutput(binding, new Map([["draft", draftReceipt]])),
    /completed receipt missing/,
  );
  assert.throws(
    () => deriveSwarmFinalOutput(binding, new Map([["draft", draftReceipt], ["final", finalReceipt], ["extra", finalReceipt]])),
    /completed receipt count mismatch/,
  );
});

test("FED_SWARM_CLOSE verification rejects tampered close signatures in Node", async () => {
  const zone = createZone("zone://swarm-close-test");
  const closeBody = {
    format: "asp-swarm-close/v1",
    swarm_id: "swarm://node-test/two-step",
    step_receipts: [{ step_id: "summary", task_id: "task_1", receipt_digest: "0".repeat(64) }],
  };
  const frame = {
    type: "FED_SWARM_CLOSE",
    swarm_id: closeBody.swarm_id,
    zone: zone.descriptor,
    close: { ...closeBody, close_signature: signObject(zone.privateKey, closeBody) },
  };
  const trustedZones = new Map([[zone.descriptor.zid, zone.descriptor]]);

  assert.equal(verifySwarmClose(frame, trustedZones).closeDigest, createHash("sha256").update(canonical(closeBody)).digest("hex"));
  assert.throws(
    () => verifySwarmClose({ ...frame, close: { ...frame.close, close_signature: "bad" } }, trustedZones),
    /swarm close signature verification failed/,
  );
});
test("FED_SWARM_CLOSE verification validates optional ready-DAG scheduler evidence in Node", () => {
  const zone = createZone("zone://swarm-close-scheduler-test");
  const trustedZones = new Map([[zone.descriptor.zid, zone.descriptor]]);
  const stepReceipts = [
    { step_id: "summary", task_id: "task_1", receipt_digest: "0".repeat(64) },
    { step_id: "followup", task_id: "task_2", receipt_digest: "1".repeat(64) },
  ];
  const frameFor = (scheduler) => {
    const closeBody = { format: "asp-swarm-close/v1", swarm_id: "swarm://node-test/scheduler", step_receipts: stepReceipts, scheduler };
    return {
      type: "FED_SWARM_CLOSE",
      swarm_id: closeBody.swarm_id,
      zone: zone.descriptor,
      close: { ...closeBody, close_signature: signObject(zone.privateKey, closeBody) },
    };
  };

  assert.deepEqual(
    verifySwarmClose(frameFor({ mode: "ready-dag", step_order: ["summary", "followup"] }), trustedZones).close.scheduler,
    { mode: "ready-dag", step_order: ["summary", "followup"] },
  );
  assert.throws(
    () => verifySwarmClose(frameFor({ mode: "ready-dag", step_order: ["followup", "summary"] }), trustedZones),
    /swarm close scheduler step_order mismatch/,
  );
  for (const [scheduler, message] of [
    [{ mode: "parallel", step_order: ["summary", "followup"] }, /swarm close scheduler mode invalid/],
    [{ mode: "ready-dag", step_order: ["summary"] }, /swarm close scheduler step order mismatch/],
    [{ mode: "ready-dag", step_order: ["summary", "summary"] }, /swarm close scheduler step duplicate/],
    [{ mode: "ready-dag", step_order: ["summary", "missing"] }, /swarm close scheduler step missing/],
  ]) {
    assert.throws(() => verifySwarmClose(frameFor(scheduler), trustedZones), message);
  }
});

test("FED_SWARM_CLOSE verification rejects migration log entries for missing step receipts in Node", async () => {
  const zone = createZone("zone://swarm-close-migration-step-test");
  const closeBody = {
    format: "asp-swarm-close/v1",
    swarm_id: "swarm://node-test/migration-step",
    step_receipts: [{ step_id: "summary", task_id: "task_1", receipt_digest: "0".repeat(64) }],
    migration_log: [{
      step_id: "missing-step",
      original_worker_aid: "aid:ed25519:original",
      reason: "policy denied network access",
      migrated_to_worker_aid: "aid:ed25519:migrated",
      migration_at: "2026-07-08T00:00:00.000Z",
    }],
  };
  const frame = {
    type: "FED_SWARM_CLOSE",
    swarm_id: closeBody.swarm_id,
    zone: zone.descriptor,
    close: { ...closeBody, close_signature: signObject(zone.privateKey, closeBody) },
  };
  const trustedZones = new Map([[zone.descriptor.zid, zone.descriptor]]);

  assert.throws(
    () => verifySwarmClose(frame, trustedZones),
    /swarm close migration step missing/,
  );
});

test("FED_SWARM_CLOSE verification rejects conflict resolutions with missing candidate steps in Node", async () => {
  const zone = createZone("zone://swarm-close-conflict-candidate-test");
  const worker = createZone("zone://swarm-close-conflict-worker-test").descriptor;
  const resolutionBody = {
    swarm_id: "swarm://node-test/conflict-candidate",
    artifact_ref: "artifact://local/conflict/shared.md",
    candidate_step_ids: ["summary", "missing-step"],
    chosen_step_id: "summary",
    chosen_worker: worker,
    reason: "higher_reputation",
  };
  const resolution = {
    ...resolutionBody,
    resolution_digest: createHash("sha256").update(canonical(resolutionBody)).digest("hex"),
    signature: signObject(zone.privateKey, resolutionBody),
  };
  const closeBody = {
    format: "asp-swarm-close/v1",
    swarm_id: resolutionBody.swarm_id,
    step_receipts: [{ step_id: "summary", task_id: "task_1", receipt_digest: "0".repeat(64), worker }],
    conflict_resolutions: [resolution],
  };
  const frame = {
    type: "FED_SWARM_CLOSE",
    swarm_id: closeBody.swarm_id,
    zone: zone.descriptor,
    close: { ...closeBody, close_signature: signObject(zone.privateKey, closeBody) },
  };
  const trustedZones = new Map([[zone.descriptor.zid, zone.descriptor]]);

  assert.throws(
    () => verifySwarmClose(frame, trustedZones),
    /swarm close conflict resolution candidate missing/,
  );
});

test("FED_SWARM_CLOSE verification rejects missing frame objects in Node", async () => {
  assert.throws(
    () => verifySwarmClose(null, new Map()),
    /expected FED_SWARM_CLOSE frame/,
  );
});

test("FED_SWARM_CLOSE verification rejects missing trusted Zone stores in Node", async () => {
  const zone = createZone("zone://swarm-close-missing-trust-store-test");
  const closeBody = {
    format: "asp-swarm-close/v1",
    swarm_id: "swarm://node-test/missing-trust-store",
    step_receipts: [{ step_id: "summary", task_id: "task_1", receipt_digest: "0".repeat(64) }],
  };
  const frame = {
    type: "FED_SWARM_CLOSE",
    swarm_id: closeBody.swarm_id,
    zone: zone.descriptor,
    close: { ...closeBody, close_signature: signObject(zone.privateKey, closeBody) },
  };

  assert.throws(
    () => verifySwarmClose(frame),
    /trusted zones missing/,
  );
});

test("FED_SWARM_CLOSE verification rejects missing signing zones in Node", async () => {
  const zone = createZone("zone://swarm-close-missing-zone-test");
  const closeBody = {
    format: "asp-swarm-close/v1",
    swarm_id: "swarm://node-test/missing-zone",
    step_receipts: [{ step_id: "summary", task_id: "task_1", receipt_digest: "0".repeat(64) }],
  };
  const frame = {
    type: "FED_SWARM_CLOSE",
    swarm_id: closeBody.swarm_id,
    close: { ...closeBody, close_signature: signObject(zone.privateKey, closeBody) },
  };
  const trustedZones = new Map([[zone.descriptor.zid, zone.descriptor]]);

  assert.throws(
    () => verifySwarmClose(frame, trustedZones),
    /swarm close zone missing/,
  );
});

test("FED_SWARM_CLOSE verification rejects missing close signatures in Node", async () => {
  const zone = createZone("zone://swarm-close-missing-signature-test");
  const closeBody = {
    format: "asp-swarm-close/v1",
    swarm_id: "swarm://node-test/missing-signature",
    step_receipts: [{ step_id: "summary", task_id: "task_1", receipt_digest: "0".repeat(64) }],
  };
  const frame = {
    type: "FED_SWARM_CLOSE",
    swarm_id: closeBody.swarm_id,
    zone: zone.descriptor,
    close: closeBody,
  };
  const trustedZones = new Map([[zone.descriptor.zid, zone.descriptor]]);

  assert.throws(
    () => verifySwarmClose(frame, trustedZones),
    /swarm close v1 fields invalid/,
  );
});

test("FED_SWARM_CLOSE verification rejects missing close proofs in Node", async () => {
  const zone = createZone("zone://swarm-close-missing-proof-test");
  const frame = {
    type: "FED_SWARM_CLOSE",
    swarm_id: "swarm://node-test/missing-proof",
    zone: zone.descriptor,
  };
  const trustedZones = new Map([[zone.descriptor.zid, zone.descriptor]]);

  assert.throws(
    () => verifySwarmClose(frame, trustedZones),
    /swarm close proof missing/,
  );
});

test("FED_SWARM_CLOSE verification rejects empty close proofs in Node", async () => {
  const zone = createZone("zone://swarm-close-empty-test");
  const closeBody = {
    format: "asp-swarm-close/v1",
    swarm_id: "swarm://node-test/empty",
    step_receipts: [],
  };
  const frame = {
    type: "FED_SWARM_CLOSE",
    swarm_id: closeBody.swarm_id,
    zone: zone.descriptor,
    close: { ...closeBody, close_signature: signObject(zone.privateKey, closeBody) },
  };
  const trustedZones = new Map([[zone.descriptor.zid, zone.descriptor]]);

  assert.throws(
    () => verifySwarmClose(frame, trustedZones),
    /swarm close step receipts missing/,
  );
});

test("FED_SWARM_CLOSE verification rejects duplicate step receipts in Node", async () => {
  const zone = createZone("zone://swarm-close-duplicate-step-test");
  const closeBody = {
    format: "asp-swarm-close/v1",
    swarm_id: "swarm://node-test/duplicate-step",
    step_receipts: [
      { step_id: "summary", task_id: "task_1", receipt_digest: "0".repeat(64) },
      { step_id: "summary", task_id: "task_2", receipt_digest: "1".repeat(64) },
    ],
  };
  const frame = {
    type: "FED_SWARM_CLOSE",
    swarm_id: closeBody.swarm_id,
    zone: zone.descriptor,
    close: { ...closeBody, close_signature: signObject(zone.privateKey, closeBody) },
  };
  const trustedZones = new Map([[zone.descriptor.zid, zone.descriptor]]);

  assert.throws(
    () => verifySwarmClose(frame, trustedZones),
    /swarm close duplicate step receipt/,
  );
});

test("FED_SWARM_CLOSE verification rejects malformed step receipt entries in Node", async () => {
  const zone = createZone("zone://swarm-close-malformed-step-test");
  const closeBody = {
    format: "asp-swarm-close/v1",
    swarm_id: "swarm://node-test/malformed-step",
    step_receipts: [null],
  };
  const frame = {
    type: "FED_SWARM_CLOSE",
    swarm_id: closeBody.swarm_id,
    zone: zone.descriptor,
    close: { ...closeBody, close_signature: signObject(zone.privateKey, closeBody) },
  };
  const trustedZones = new Map([[zone.descriptor.zid, zone.descriptor]]);

  assert.throws(
    () => verifySwarmClose(frame, trustedZones),
    /swarm close v1 step fields invalid/,
  );
});

test("FED_SWARM_CLOSE verification rejects missing Swarm identity in Node", async () => {
  const zone = createZone("zone://swarm-close-missing-id-test");
  const closeBody = {
    format: "asp-swarm-close/v1",
    step_receipts: [{ step_id: "summary", task_id: "task_1", receipt_digest: "0".repeat(64) }],
  };
  const frame = {
    type: "FED_SWARM_CLOSE",
    zone: zone.descriptor,
    close: { ...closeBody, close_signature: signObject(zone.privateKey, closeBody) },
  };
  const trustedZones = new Map([[zone.descriptor.zid, zone.descriptor]]);

  assert.throws(
    () => verifySwarmClose(frame, trustedZones),
    /swarm close v1 fields invalid/,
  );
});

test("FED_SWARM_CLOSE verification rejects NUL-bearing Swarm identities in Node", async () => {
  const zone = createZone("zone://swarm-close-nul-test");
  const trustedZones = new Map([[zone.descriptor.zid, zone.descriptor]]);
  const nulSwarmBody = {
    format: "asp-swarm-close/v1",
    swarm_id: "swarm://node-test/nul\0shadow",
    step_receipts: [{ step_id: "summary", task_id: "task_1", receipt_digest: "0".repeat(64) }],
  };
  const nulStepBody = {
    format: "asp-swarm-close/v1",
    swarm_id: "swarm://node-test/nul-step",
    step_receipts: [{ step_id: "summary\0shadow", task_id: "task_1", receipt_digest: "0".repeat(64) }],
  };

  for (const closeBody of [nulSwarmBody, nulStepBody]) {
    assert.throws(
      () => verifySwarmClose({
        type: "FED_SWARM_CLOSE",
        swarm_id: closeBody.swarm_id,
        zone: zone.descriptor,
        close: { ...closeBody, close_signature: signObject(zone.privateKey, closeBody) },
      }, trustedZones),
      /swarm close identity contains NUL/,
    );
  }
});

test("FED_SWARM_CLOSE verification rejects unsafe task ids in Node", async () => {
  const zone = createZone("zone://swarm-close-unsafe-task-test");
  const closeBody = {
    format: "asp-swarm-close/v1",
    swarm_id: "swarm://node-test/unsafe-task",
    step_receipts: [{ step_id: "summary", task_id: "../bad/task", receipt_digest: "0".repeat(64) }],
  };
  const frame = {
    type: "FED_SWARM_CLOSE",
    swarm_id: closeBody.swarm_id,
    zone: zone.descriptor,
    close: { ...closeBody, close_signature: signObject(zone.privateKey, closeBody) },
  };
  const trustedZones = new Map([[zone.descriptor.zid, zone.descriptor]]);

  assert.throws(
    () => verifySwarmClose(frame, trustedZones),
    /swarm close task invalid/,
  );
});

async function loadSwarmOutputVector(path) {
  const vector = JSON.parse(await readFile(path, "utf8"));
  const trustInputs = createSwarmOutputTrustInputsForTest(vector.trust.allowlist, vector.trust.trusted_zones, vector.trust.revocations);
  const trustedZones = new Map(Object.entries(vector.evidence.trusted_zones));
  const artifactBytesByUri = new Map(Object.entries(vector.evidence.artifacts).map(([uri, encoded]) => [uri, Buffer.from(encoded, "base64url")]));
  const evidence = {
    proof: vector.proof_frame,
    planFrame: vector.evidence.plan_frame,
    executionBinding: vector.evidence.execution_binding,
    executableSteps: vector.evidence.executable_steps,
    resolvedWorkers: vector.evidence.resolved_workers,
    closeFrame: vector.evidence.close_frame,
    receiptFrames: vector.evidence.receipt_frames,
    trustedZones,
    loadArtifactBytes: async (artifact) => {
      const bytes = artifactBytesByUri.get(artifact.uri);
      if (!bytes) throw new Error(`missing vector artifact bytes: ${artifact.uri}`);
      return bytes;
    },
  };
  return { vector, trustInputs, evidence };
}

function expectedReplayStore(record = undefined) {
  let stored = record;
  return {
    async putVerificationReplayIfAbsent(candidate) {
      if (stored === undefined) {
        stored = structuredClone(candidate);
        return { inserted: true, record: structuredClone(stored) };
      }
      return { inserted: false, existing: structuredClone(stored) };
    },
  };
}

async function assertSwarmOutputVectorVerifiesInNode(path, expectedOrigin) {
  const { vector, trustInputs, evidence } = await loadSwarmOutputVector(path);
  assert.equal(vector.format, "asp-swarm-output-vector/v1");
  assert.equal(vector.vector_origin, expectedOrigin);
  assert.equal(canonical(vector.evidence.execution_binding), vector.expected.canonical_binding);
  assert.equal(vector.evidence.execution_binding.execution_graph_digest, vector.expected.execution_graph_digest);
  assert.equal(vector.evidence.close_frame.close.final_output.signed_receipt_digest, vector.expected.signed_receipt_digest);
  assert.equal(canonical(vector.evidence.close_frame.close), vector.expected.canonical_close);
  assert.equal(createHash("sha256").update(vector.expected.canonical_close).digest("hex"), vector.expected.close_digest);
  assert.equal(vector.trust.trust_inputs_digest, vector.expected.trust_inputs_digest);
  assert.equal(canonical(vector.trust.normalized), vector.expected.normalized_trust_inputs);
  assert.equal(canonical(vector.proof_frame.proof), vector.expected.canonical_proof);
  assert.equal(createHash("sha256").update(vector.expected.canonical_proof).digest("hex"), vector.expected.proof_digest);
  assert.match(vector.expected.canonical_close, /<>&/);
  assert.match(vector.expected.canonical_proof, /<>&/);

  const verified = await verifySwarmOutputVerification(vector.proof_frame, evidence, trustInputs, { now: vector.timestamps.now });
  assert.equal(verified.closeDigest, vector.expected.close_digest);
  assert.equal(verified.proofDigest, vector.expected.proof_digest);
  assert.equal(verified.trustInputsDigest, vector.expected.trust_inputs_digest);
  assert.equal(Buffer.from(verified.CloseBytes).toString("utf8"), vector.expected.canonical_close);
  assert.equal(Buffer.from(verified.ProofBytes).toString("utf8"), vector.expected.canonical_proof);

  const accepted = await applySwarmOutputVerificationReplay(vector.proof_frame, evidence, trustInputs, expectedReplayStore(), { now: vector.timestamps.now, expectedCloseDigest: vector.expected.close_digest });
  assert.equal(accepted.replay_decision, "accepted");
  assert.equal(accepted.completion_gate, true);
  assert.equal(Buffer.from(accepted.CloseBytes).toString("utf8"), vector.expected.canonical_close);
  assert.equal(Buffer.from(accepted.ProofBytes).toString("utf8"), vector.expected.canonical_proof);
  return { vector, trustInputs, evidence, accepted };
}

function resignCloseVector(vector, mutate) {
  const key = privateKeyFromSeed(vector.seeds.coordinator_zone);
  const candidate = structuredClone(vector);
  const { close_signature: _signature, ...body } = candidate.evidence.close_frame.close;
  mutate(body);
  candidate.evidence.close_frame.close = { ...body, close_signature: signObject(key, body) };
  return candidate;
}

function resignProofVector(vector, mutate) {
  const key = privateKeyFromSeed(vector.seeds.verifier_agent);
  const candidate = structuredClone(vector);
  const { proof_signature: _signature, ...body } = candidate.proof_frame.proof;
  mutate(body);
  candidate.proof_frame.proof = { ...body, proof_signature: signObject(key, body) };
  return candidate;
}

async function rejectMutatedVectorInNode(vector, trustInputs, mutate, message) {
  const candidate = mutate(structuredClone(vector));
  const trustedZones = new Map(Object.entries(candidate.evidence.trusted_zones));
  const artifacts = new Map(Object.entries(candidate.evidence.artifacts).map(([uri, encoded]) => [uri, Buffer.from(encoded, "base64url")]));
  const evidence = {
    proof: candidate.proof_frame,
    planFrame: candidate.evidence.plan_frame,
    executionBinding: candidate.evidence.execution_binding,
    executableSteps: candidate.evidence.executable_steps,
    resolvedWorkers: candidate.evidence.resolved_workers,
    closeFrame: candidate.evidence.close_frame,
    receiptFrames: candidate.evidence.receipt_frames,
    trustedZones,
    loadArtifactBytes: async (artifact) => artifacts.get(artifact.uri),
  };
  await assert.rejects(
    () => verifySwarmOutputVerification(candidate.proof_frame, evidence, trustInputs, { now: candidate.timestamps.now }),
    message,
  );
}

test("Swarm output vector verifies Node-created proof in Node", async () => {
  await assertSwarmOutputVectorVerifiesInNode("test-vectors/asp-u7-node-created-swarm-output.json", "node-created");
});

test("Swarm output vector verifies Go-created proof in Node", async () => {
  await assertSwarmOutputVectorVerifiesInNode("test-vectors/asp-u7-go-created-swarm-output.json", "go-created");
});

test("Swarm output vector rejects malformed Phase A mutations in Node", async () => {
  const { vector, trustInputs, accepted } = await assertSwarmOutputVectorVerifiesInNode("test-vectors/asp-u7-node-created-swarm-output.json", "node-created");
  const cases = [
    ["unknown close field", (base) => resignCloseVector(base, (body) => { body.unexpected = true; }), /swarm close v2 fields invalid/],
    ["duplicate step receipt", (base) => resignCloseVector(base, (body) => { body.step_receipts = [body.step_receipts[0], body.step_receipts[0]]; }), /swarm close duplicate step receipt/],
    ["missing close format", (base) => resignCloseVector(base, (body) => { delete body.format; }), /swarm close format missing|swarm close v2 fields invalid/],
    ["v2 stripped into v1", (base) => resignCloseVector(base, (body) => { body.format = "asp-swarm-close/v1"; }), /swarm close v1 fields invalid/],
    ["graph mutation", (base) => resignCloseVector(base, (body) => { body.execution_graph_digest = "0".repeat(64); }), /close execution graph digest mismatch/],
    ["result mutation", (base) => resignCloseVector(base, (body) => { body.final_output.artifact.sha256 = "1".repeat(64); }), /swarm close final output receipt digest mismatch|final output mismatch/],
    ["trust mutation", (base) => resignProofVector(base, (body) => { body.trust_inputs_digest = "2".repeat(64); }), /trust inputs digest mismatch/],
    ["timestamp mutation", (base) => resignProofVector(base, (body) => { body.verified_at = "3026-07-11T00:00:00Z"; }), /verified_at future skew invalid/],
  ];
  for (const [name, mutate, message] of cases) {
    await rejectMutatedVectorInNode(vector, trustInputs, mutate, message, name);
  }

  const conflicted = await applySwarmOutputVerificationReplay(vector.proof_frame, {
    ...(await loadSwarmOutputVector("test-vectors/asp-u7-node-created-swarm-output.json")).evidence,
  }, trustInputs, expectedReplayStore({ ...accepted, canonical_proof_sha256: "0".repeat(64), stored_close_digest: "0".repeat(64) }), { now: vector.timestamps.now, expectedCloseDigest: vector.expected.close_digest });
  assert.equal(conflicted.replay_decision, "conflict");
  assert.equal(conflicted.completion_gate, false);
});

test("Explicit legacy v1 close vector verifies in Node", async () => {
  const vector = JSON.parse(await readFile("test-vectors/asp-v10.38-fed-swarm-close.json", "utf8"));
  assert.equal(vector.schema_format, "asp-swarm-close-vector/legacy-v1");
  assert.equal(vector.legacy, true);
  const trustedZones = new Map(vector.trusted_zones.map((zone) => [zone.zid, zone]));
  const verified = verifySwarmClose(vector.frame, trustedZones);
  assert.equal(verified.format, "asp-swarm-close/v1");
  assert.equal(verified.legacy, true);

  assert.equal(verified.closeDigest, vector.expected.swarm_close_digest);
  assert.equal(canonical(vector.close_body), vector.close_canonical);
  assert.equal(verified.close.swarm_id, vector.expected.swarm_id);
  assert.deepEqual(verified.close.step_receipts.map((step) => step.step_id), vector.expected.step_ids);
});

test("FED_SWARM_CLOSE CLI rejects tampered trusted Zone descriptors", async () => {
  const vector = JSON.parse(await readFile("test-vectors/asp-v10.38-fed-swarm-close.json", "utf8"));
  const framePath = "state/node-fed-swarm-close-frame.json";
  const trustedPath = "state/node-fed-swarm-close-trusted.json";
  await writeFile(framePath, `${JSON.stringify(vector.frame, null, 2)}\n`);
  await writeFile(trustedPath, `${JSON.stringify({ zones: vector.trusted_zones }, null, 2)}\n`);

  await assert.rejects(
    () => execFileAsync("node", ["asp-verify.mjs", "swarm-close", framePath, trustedPath, "extra.json"]),
    (error) => error.stderr.includes("usage: node asp-verify.mjs"),
  );

  await writeFile(trustedPath, `${JSON.stringify({ zones: [{ ...vector.trusted_zones[0], zone_signature: "bad" }] }, null, 2)}\n`);

  await assert.rejects(
    () => execFileAsync("node", ["asp-verify.mjs", "swarm-close", framePath, trustedPath]),
    (error) => error.stderr.includes("zone signature verification failed"),
  );
});
