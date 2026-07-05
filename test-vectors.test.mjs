import assert from "node:assert/strict";
import { createPrivateKey, createPublicKey } from "node:crypto";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { canonical, computeAid, signObject, verifyFederatedReceipt, verifyFederatedTaskOpen, verifyObject } from "./asp-core.mjs";

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
