import assert from "node:assert/strict";
import { createPrivateKey, createPublicKey } from "node:crypto";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { canonical, computeAid, createAgent, didKeyFromDescriptor, didKeyFromPublicKeySPKI, publicKeySPKIFromDidKey, signObject, verifyFederatedReceipt, verifyFederatedTaskOpen, verifyObject } from "./asp-core.mjs";

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
