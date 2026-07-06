import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash, createPrivateKey, createPublicKey } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { test } from "node:test";
import { promisify } from "node:util";
import { canonical, computeAid, createAgent, createZone, didKeyFromDescriptor, didKeyFromPublicKeySPKI, publicKeySPKIFromDidKey, signObject, verifyFederatedReceipt, verifyFederatedTaskOpen, verifyObject, verifySwarmClose, writeArtifact } from "./asp-core.mjs";

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

test("FED_TASK_OPEN conformance vector verifies in Node", async () => {
  const vector = JSON.parse(await readFile("test-vectors/asp-v9.24-fed-task-open.json", "utf8"));
  const trustedZones = new Map(vector.trusted_zones.map((zone) => [zone.zid, zone]));
  const verified = verifyFederatedTaskOpen(vector.frame, trustedZones, vector.worker);

  assert.equal(canonical(verified.task), vector.task_canonical);
  assert.equal(verified.originZone.zid, vector.expected.origin_zid);
  assert.equal(verified.requester.aid, vector.expected.requester_aid);
  assert.equal(verified.worker.alias, vector.expected.worker_alias);
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

test("FED_RECEIPT CLI verifies one frame in Node", async () => {
  const vector = JSON.parse(await readFile("test-vectors/asp-v9.25-fed-receipt.json", "utf8"));
  const framePath = "state/node-fed-receipt-frame.json";
  const trustedPath = "state/node-fed-receipt-trusted.json";
  await writeFile(framePath, `${JSON.stringify(vector.frame, null, 2)}\n`);
  await writeFile(trustedPath, `${JSON.stringify({ zones: vector.trusted_zones }, null, 2)}\n`);

  assert.deepEqual(JSON.parse((await execFileAsync("node", ["asp-verify.mjs", "fed-receipt", framePath, trustedPath])).stdout), {
    fed_receipt_verify: "ok",
    task_id: vector.expected.task_id,
  });

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
  await writeFile(framePath, `${JSON.stringify(frame, null, 2)}\n`);
  await writeFile(trustedPath, `${JSON.stringify({ zones: vector.trusted_zones }, null, 2)}\n`);

  assert.deepEqual(JSON.parse((await execFileAsync("node", ["asp-verify.mjs", "fed-receipt-artifacts", framePath, trustedPath])).stdout), {
    fed_receipt_artifacts_verify: "ok",
    task_id: vector.expected.task_id,
    artifact_count: 1,
  });

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

test("FED_SWARM_CLOSE conformance vector verifies in Node", async () => {
  const vector = JSON.parse(await readFile("test-vectors/asp-v10.38-fed-swarm-close.json", "utf8"));
  const trustedZones = new Map(vector.trusted_zones.map((zone) => [zone.zid, zone]));
  const verified = verifySwarmClose(vector.frame, trustedZones);

  assert.equal(verified.closeDigest, vector.expected.swarm_close_digest);
  assert.equal(canonical(vector.close_body), vector.close_canonical);
  assert.equal(verified.close.swarm_id, vector.expected.swarm_id);
  assert.deepEqual(verified.close.step_receipts.map((step) => step.step_id), vector.expected.step_ids);
});
