import assert from "node:assert/strict";
import { createPrivateKey } from "node:crypto";
import { chmod, mkdtemp, readFile, readdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { agentFromPrivateKey, canonical, signObject, zoneFromPrivateKey } from "./asp-core.mjs";
import { parseGenerationRecord, verifyGenerationChain, verifyGenerationRecord } from "./managed-key.mjs";
import { migrateKey, rotateAgent } from "./agnet-key.mjs";
import { ManagedKeyStore } from "./managed-key-store.mjs";

const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const AGENT_PASSPHRASE = Buffer.from("u12 agent passphrase\n");
const ZONE_PASSPHRASE = Buffer.from("u12 zone passphrase\n");

function key(start) {
  const seed = Buffer.from(Array.from({ length: 32 }, (_, index) => (start + index) & 0xff));
  return {
    bytes: Buffer.concat([PKCS8_PREFIX, seed]),
    privateKey: createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, seed]), format: "der", type: "pkcs8" }),
  };
}

async function restricted(path, bytes) {
  await writeFile(path, bytes, { mode: 0o600 });
}

async function fixture(name) {
  const root = await mkdtemp(join(tmpdir(), `agnet-u12-${name}-`));
  await chmod(root, 0o700);
  const agentKey = key(0);
  const zoneKey = key(64);
  const agent = agentFromPrivateKey(
    "agent://u12/worker",
    agentKey.privateKey,
    { audience: ["fed"], priority: 7 },
    ["asp+local://u12", "asp+tcp://u12"],
    ["summarize", "verify"],
  );
  const zone = zoneFromPrivateKey("zone://u12", zoneKey.privateKey);
  const paths = {
    agentKey: join(root, "agent.key"),
    agentDescriptor: join(root, "agent-descriptor.json"),
    agentPassphrase: join(root, "agent-passphrase"),
    agentStore: join(root, "agent-store"),
    zoneKey: join(root, "zone.key"),
    zoneDescriptor: join(root, "zone-descriptor.json"),
    zonePassphrase: join(root, "zone-passphrase"),
    zoneStore: join(root, "zone-store"),
  };
  await Promise.all([
    restricted(paths.agentKey, agentKey.bytes),
    restricted(paths.agentDescriptor, Buffer.from(canonical(agent.descriptor))),
    restricted(paths.agentPassphrase, AGENT_PASSPHRASE),
    restricted(paths.zoneKey, zoneKey.bytes),
    restricted(paths.zoneDescriptor, Buffer.from(canonical(zone.descriptor))),
    restricted(paths.zonePassphrase, ZONE_PASSPHRASE),
  ]);
  await migrateKey({
    storePath: paths.agentStore,
    keyPath: paths.agentKey,
    keyType: "ed25519-pkcs8",
    identityKind: "aid",
    descriptorPath: paths.agentDescriptor,
    passphrasePath: paths.agentPassphrase,
    iterations: 100000,
  });
  await migrateKey({
    storePath: paths.zoneStore,
    keyPath: paths.zoneKey,
    keyType: "ed25519-pkcs8",
    identityKind: "zid",
    descriptorPath: paths.zoneDescriptor,
    passphrasePath: paths.zonePassphrase,
    iterations: 100000,
  });
  return { root, agent, zone, paths };
}

async function activeFiles(storePath) {
  return (await readdir(join(storePath, "generations"))).sort();
}

async function rotate(item, store = undefined) {
  return rotateAgent({
    store: store ?? await ManagedKeyStore.open(item.paths.agentStore),
    passphraseFile: item.paths.agentPassphrase,
    zoneStore: await ManagedKeyStore.open(item.paths.zoneStore),
    zonePassphraseFile: item.paths.zonePassphrase,
    iterations: 100000,
  });
}

test("rotateAgent preserves Agent profile, binds the exact verified Zone generation, and activates only after reload", async () => {
  const item = await fixture("happy");
  const result = await rotate(item);
  assert.deepEqual(Object.keys(result), ["operation", "identity_kind", "identity_value", "generation", "record_digest", "envelope_sha256"]);
  assert.equal(result.operation, "rotate");
  assert.equal(result.identity_kind, "aid");
  assert.equal(result.generation, 2);
  assert.notEqual(result.identity_value, item.agent.aid);

  const agentStore = await ManagedKeyStore.open(item.paths.agentStore);
  const loaded = await agentStore.loadActive(AGENT_PASSPHRASE);
  const zoneLoaded = await (await ManagedKeyStore.open(item.paths.zoneStore)).loadActive(ZONE_PASSPHRASE);
  assert.equal(loaded.identity.value, result.identity_value);
  assert.equal(loaded.keyGeneration.generation, 2);
  assert.deepEqual(
    {
      alias: loaded.descriptor.alias,
      transports: loaded.descriptor.transports,
      capabilities: loaded.descriptor.capabilities,
      policy: loaded.descriptor.policy,
    },
    {
      alias: item.agent.descriptor.alias,
      transports: item.agent.descriptor.transports,
      capabilities: item.agent.descriptor.capabilities,
      policy: item.agent.descriptor.policy,
    },
  );
  assert.equal(loaded.record.generation_rebinding.zone_generation, zoneLoaded.keyGeneration.generation);
  assert.equal(loaded.record.generation_rebinding.zone_record_digest, zoneLoaded.keyGeneration.record_digest);
  assert.equal(verifyGenerationRecord(loaded.record, {
    envelopeBytes: await readFile(join(item.paths.agentStore, "generations", "0000000000000002.envelope.json")),
    descriptor: loaded.descriptor,
    previousRecord: item.agentStoreRecord ?? JSON.parse(await readFile(join(item.paths.agentStore, "generations", "0000000000000001.record.json"), "utf8")),
    previousDescriptor: item.agent.descriptor,
    zoneDescriptor: zoneLoaded.descriptor,
    zoneRecord: zoneLoaded.record,
  }).record_digest, result.record_digest);
});

test("rotateAgent rejects a non-Agent target before entropy or writes and leaves Zone untouched", async () => {
  const item = await fixture("zid-target");
  const zidStorePath = join(item.root, "zid-target-store");
  await migrateKey({
    storePath: zidStorePath,
    keyPath: item.paths.zoneKey,
    keyType: "ed25519-pkcs8",
    identityKind: "zid",
    descriptorPath: item.paths.zoneDescriptor,
    passphrasePath: item.paths.zonePassphrase,
    iterations: 100000,
  });
  const beforeTarget = await activeFiles(zidStorePath);
  const beforeZone = await activeFiles(item.paths.zoneStore);
  await assert.rejects(
    rotateAgent({
      store: await ManagedKeyStore.open(zidStorePath),
      passphraseFile: item.paths.zonePassphrase,
      zoneStore: await ManagedKeyStore.open(item.paths.zoneStore),
      zonePassphraseFile: item.paths.zonePassphrase,
      iterations: 100000,
    }),
    /Agent identity|aid/i,
  );
  assert.deepEqual(await activeFiles(zidStorePath), beforeTarget);
  assert.deepEqual(await activeFiles(item.paths.zoneStore), beforeZone);
  const revokedDescriptor = { ...item.zone.descriptor, revoked: true };
  const { zone_signature, ...revokedBody } = revokedDescriptor;
  revokedDescriptor.zone_signature = signObject(item.zone.privateKey, revokedBody);
  const revokedDescriptorPath = join(item.root, "revoked-zone-descriptor.json");
  const revokedZoneStore = join(item.root, "revoked-zone-store");
  await restricted(revokedDescriptorPath, Buffer.from(canonical(revokedDescriptor)));
  await migrateKey({
    storePath: revokedZoneStore,
    keyPath: item.paths.zoneKey,
    keyType: "ed25519-pkcs8",
    identityKind: "zid",
    descriptorPath: revokedDescriptorPath,
    passphrasePath: item.paths.zonePassphrase,
    iterations: 100000,
  });
  const beforeAgent = await activeFiles(item.paths.agentStore);
  const beforeRevokedZone = await activeFiles(revokedZoneStore);
  await assert.rejects(
    rotateAgent({
      store: await ManagedKeyStore.open(item.paths.agentStore),
      passphraseFile: item.paths.agentPassphrase,
      zoneStore: await ManagedKeyStore.open(revokedZoneStore),
      zonePassphraseFile: item.paths.zonePassphrase,
      iterations: 100000,
    }),
    /Zone is revoked/,
  );
  assert.deepEqual(await activeFiles(item.paths.agentStore), beforeAgent);
  assert.deepEqual(await activeFiles(revokedZoneStore), beforeRevokedZone);
});

test("rotation rejects swapped Zone authorization and crashes before activation without changing Zone", async () => {
  const item = await fixture("authorization-and-crash");
  const rotated = await rotate(item);
  const agentStore = await ManagedKeyStore.open(item.paths.agentStore);
  const loaded = await agentStore.loadActive(AGENT_PASSPHRASE);
  const zoneLoaded = await (await ManagedKeyStore.open(item.paths.zoneStore)).loadActive(ZONE_PASSPHRASE);
  const tampered = structuredClone(loaded.record);
  const envelopeBytes = await readFile(join(item.paths.agentStore, "generations", "0000000000000002.envelope.json"));
  const previousRecord = JSON.parse(await readFile(join(item.paths.agentStore, "generations", "0000000000000001.record.json"), "utf8"));
  tampered.generation_rebinding.zone_record_digest = "0".repeat(64);
  assert.throws(() => verifyGenerationRecord(tampered, {
    envelopeBytes,
    descriptor: loaded.descriptor,
    previousRecord,
    previousDescriptor: item.agent.descriptor,
    zoneDescriptor: zoneLoaded.descriptor,
    zoneRecord: zoneLoaded.record,
  }), /rebinding|record digest|signature/i);
  assert.equal(rotated.generation, 2);

  const crashItem = await fixture("crash");
  const zoneBefore = await activeFiles(crashItem.paths.zoneStore);
  const crashingStore = await ManagedKeyStore.open(crashItem.paths.agentStore, {
    testHooks: { fault(point) { if (point === "active-before-publish") throw new Error("fault:active-before-publish"); } },
  });
  await assert.rejects(rotate(crashItem, crashingStore), /fault:active-before-publish/);
  const reopened = await ManagedKeyStore.open(crashItem.paths.agentStore);
  await assert.rejects(reopened.loadActive(AGENT_PASSPHRASE), /requires recovery/);
  assert.equal((await reopened.recover(AGENT_PASSPHRASE)).keyGeneration.generation, 2);
  assert.deepEqual(await activeFiles(crashItem.paths.zoneStore), zoneBefore);
});

test("Node verifies frozen Node-created and Go-created U12 rotation vectors", async () => {
  const vector = JSON.parse(await readFile("test-vectors/agnet-key-rotation-v1.json", "utf8"));
  assert.equal(vector.format, "agnet-key-rotation-test-v1");
  assert.deepEqual(vector.cases.map((item) => item.origin).sort(), ["go-created", "node-created"]);
  for (const item of vector.cases) {
    const zoneRecord = parseGenerationRecord(Buffer.from(item.zone.canonical, "utf8"));
    const records = item.records.map((record) => parseGenerationRecord(Buffer.from(record.canonical, "utf8")));
    const verified = verifyGenerationChain(records, item.records.map((record) => Buffer.from(record.envelope, "base64url")), {
      descriptors: item.records.map((record) => record.descriptor),
      previousDescriptors: item.records.map((record) => record.previous_descriptor),
      zoneDescriptors: item.records.map((record) => record.zone_descriptor),
      zoneRecords: item.records.map((record) => record.zone_record === null ? undefined : zoneRecord),
      activePointer: item.active_pointer,
    });
    assert.equal(verified.at(-1).record_digest, item.active_pointer.record_digest, item.origin);
    assert.equal(records.at(-1).generation_rebinding.zone_record_digest, item.zone.active_pointer.record_digest, item.origin);
  }
});
