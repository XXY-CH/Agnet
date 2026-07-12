import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createPrivateKey } from "node:crypto";
import { chmod, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { promisify } from "node:util";

import { agentFromPrivateKey, canonical, publicKeyFromDescriptor, signObject, verifyObject, zoneFromPrivateKey } from "../asp-core.mjs"
import { migrateKey, rewrapKey } from "../agnet-key.mjs"
import { loadManagedAgent,
loadManagedZone,
loadVerifiedKeyGeneration, } from "../managed-key-runtime.mjs"

const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const PASSPHRASE = Buffer.from("u13 managed runtime passphrase\n");
const NEXT_PASSPHRASE = Buffer.from("u13 managed runtime next passphrase\n");
const execFileAsync = promisify(execFile);

function privateKey(start) {
  return createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, Buffer.from(Array.from({ length: 32 }, (_, index) => (start + index) & 0xff))]), format: "der", type: "pkcs8" });
}

async function restricted(path, bytes) {
  await writeFile(path, bytes, { mode: 0o600 });
  await chmod(path, 0o600);
}

async function migrateFixture(kind, start, profile = {}) {
  const root = await mkdtemp(join(tmpdir(), `agnet-u13-${kind}-`));
  await chmod(root, 0o700);
  const key = kind === "aid"
    ? agentFromPrivateKey(profile.alias ?? "agent://u13/runtime", privateKey(start), profile.policy ?? {}, profile.transports ?? ["asp+local://u13"], profile.capabilities ?? [])
    : zoneFromPrivateKey(profile.name ?? "zone://u13/runtime", privateKey(start));
  const keyPath = join(root, "key.pkcs8");
  const descriptorPath = join(root, "descriptor.json");
  const passphrasePath = join(root, "passphrase");
  const nextPassphrasePath = join(root, "next-passphrase");
  const storePath = join(root, "store");
  await restricted(keyPath, Buffer.from(key.privateKey.export({ format: "der", type: "pkcs8" })));
  await restricted(descriptorPath, Buffer.from(canonical(key.descriptor)));
  await restricted(passphrasePath, PASSPHRASE);
  await restricted(nextPassphrasePath, NEXT_PASSPHRASE);
  await migrateKey({ storePath, keyPath, keyType: "ed25519-pkcs8", identityKind: kind, descriptorPath, passphrasePath, iterations: 100000 });
  return { ...key, storePath, passphrasePath, nextPassphrasePath, descriptorPath };
}

function agentOptions(agent, overrides = {}) {
  return {
    storePath: agent.storePath,
    passphraseFile: agent.passphrasePath,
    alias: agent.alias,
    policy: agent.descriptor.policy,
    transports: agent.descriptor.transports,
    capabilities: agent.descriptor.capabilities,
    ...overrides,
  };
}

test("managed Agent and Zone loaders preserve verified public shapes and publish generation pins", async () => {
  const agent = await migrateFixture("aid", 1, { alias: "agent://u13/managed", capabilities: ["summarize.text"] });
  const zone = await migrateFixture("zid", 65, { name: "zone://u13/managed" });

  const loadedAgent = await loadManagedAgent(agentOptions(agent));
  const loadedZone = await loadManagedZone({ storePath: zone.storePath, passphraseFile: zone.passphrasePath, name: "zone://u13/managed" });

  assert.equal(loadedAgent.aid, agent.aid);
  assert.equal(loadedAgent.descriptor.alias, agent.alias);
  assert.equal(loadedAgent.keyGeneration.record_digest.length, 64);
  assert.equal(loadedZone.zid, zone.zid);
  assert.equal(loadedZone.descriptor.zid, zone.zid);
  assert.equal(loadedZone.keyGeneration.generation, 1);
});

test("pinned reload verifies the requested generation without trusting a changed active pointer", async () => {
  const agent = await migrateFixture("aid", 97, { alias: "agent://u13/pinned" });
  const first = await loadManagedAgent(agentOptions(agent));
  await rewrapKey({ storePath: agent.storePath, identityKind: "aid", descriptorPath: agent.descriptorPath, currentPassphrasePath: agent.passphrasePath, newPassphrasePath: agent.nextPassphrasePath, iterations: 100000 });

  const pinned = await loadVerifiedKeyGeneration(agent.storePath, first.keyGeneration.record_digest, agent.passphrasePath);
  const active = await loadManagedAgent(agentOptions(agent, { passphraseFile: agent.nextPassphrasePath }));

  assert.equal(pinned.keyGeneration.record_digest, first.keyGeneration.record_digest);
  assert.equal(pinned.keyGeneration.generation, 1);
  assert.equal(active.keyGeneration.generation, 2);
  assert.equal(active.keyGeneration.record_digest === first.keyGeneration.record_digest, false);
});

test("managed loaders reject bare-key substitutions, wrong profile aliases, and old passphrases", async () => {
  const agent = await migrateFixture("aid", 129, { alias: "agent://u13/strict" });
  await assert.rejects(loadManagedAgent({ keyFile: join(agent.storePath, "bare.pkcs8"), alias: agent.alias }), /store path invalid|passphrase file path invalid/);
  await assert.rejects(loadManagedAgent(agentOptions(agent, { alias: "agent://u13/wrong" })), /alias mismatch/);
  await assert.rejects(loadManagedAgent(agentOptions(agent, { policy: { allow_network: true } })), /profile mismatch/);
  await rewrapKey({ storePath: agent.storePath, identityKind: "aid", descriptorPath: agent.descriptorPath, currentPassphrasePath: agent.passphrasePath, newPassphrasePath: agent.nextPassphrasePath, iterations: 100000 });
  await assert.rejects(loadManagedAgent(agentOptions(agent)), /authentication failed/);
});

test("Node signs using a Go-created managed generation", async () => {
  const root = await mkdtemp(join(tmpdir(), "agnet-u13-go-generation-"));
  await chmod(root, 0o700);
  const agent = agentFromPrivateKey("agent://u13/go-generation", privateKey(193), {}, ["asp+local://u13"], ["summarize.text"]);
  const keyPath = join(root, "key.pkcs8");
  const descriptorPath = join(root, "descriptor.json");
  const passphrasePath = join(root, "passphrase");
  const storePath = join(root, "store");
  await restricted(keyPath, Buffer.from(agent.privateKey.export({ format: "der", type: "pkcs8" })));
  await restricted(descriptorPath, Buffer.from(canonical(agent.descriptor)));
  await restricted(passphrasePath, PASSPHRASE);
  await execFileAsync("go", ["run", "./cmd/agnet-key", "migrate", "--store", storePath, "--key-file", keyPath, "--key-type", "ed25519-pkcs8", "--identity-kind", "aid", "--descriptor", descriptorPath, "--passphrase-file", passphrasePath, "--iterations", "100000"]);
  const loaded = await loadManagedAgent({
    storePath,
    passphraseFile: passphrasePath,
    alias: agent.alias,
    policy: agent.descriptor.policy,
    transports: agent.descriptor.transports,
    capabilities: agent.descriptor.capabilities,
  });
  const body = { interoperability: "node-signs-go-generation", record_digest: loaded.keyGeneration.record_digest };
  const signature = signObject(loaded.privateKey, body);
  assert.equal(verifyObject(publicKeyFromDescriptor(loaded.descriptor), body, signature), true);
});
