import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash, createPrivateKey, createPublicKey } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { test } from "node:test";
import { promisify } from "node:util";
import { canonical, computeAid, createAgent, createZone, descriptorBody, didKeyFromDescriptor, didKeyFromPublicKeySPKI, publicKeyFromDescriptor, publicKeySPKIFromDidKey, signObject, verifyFederatedReceipt, verifyFederatedTaskOpen, verifyObject, verifyReceiptArtifactManifests, verifySwarmClose, writeArtifact, zoneDescriptorBody } from "./asp-core.mjs";

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

test("FED_SWARM_CLOSE verification rejects tampered close signatures in Node", async () => {
  const zone = createZone("zone://swarm-close-test");
  const closeBody = {
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

test("FED_SWARM_CLOSE verification rejects missing frame objects in Node", async () => {
  assert.throws(
    () => verifySwarmClose(null, new Map()),
    /expected FED_SWARM_CLOSE frame/,
  );
});

test("FED_SWARM_CLOSE verification rejects missing trusted Zone stores in Node", async () => {
  const zone = createZone("zone://swarm-close-missing-trust-store-test");
  const closeBody = {
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
    /swarm close signature missing/,
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
    /swarm close step receipt missing/,
  );
});

test("FED_SWARM_CLOSE verification rejects missing Swarm identity in Node", async () => {
  const zone = createZone("zone://swarm-close-missing-id-test");
  const closeBody = {
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
    /swarm close identity missing/,
  );
});

test("FED_SWARM_CLOSE verification rejects NUL-bearing Swarm identities in Node", async () => {
  const zone = createZone("zone://swarm-close-nul-test");
  const trustedZones = new Map([[zone.descriptor.zid, zone.descriptor]]);
  const nulSwarmBody = {
    swarm_id: "swarm://node-test/nul\0shadow",
    step_receipts: [{ step_id: "summary", task_id: "task_1", receipt_digest: "0".repeat(64) }],
  };
  const nulStepBody = {
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

test("FED_SWARM_CLOSE conformance vector verifies in Node", async () => {
  const vector = JSON.parse(await readFile("test-vectors/asp-v10.38-fed-swarm-close.json", "utf8"));
  const trustedZones = new Map(vector.trusted_zones.map((zone) => [zone.zid, zone]));
  const verified = verifySwarmClose(vector.frame, trustedZones);

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
