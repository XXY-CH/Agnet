import assert from "node:assert/strict";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { canonical, createAgent, createZone } from "../asp-core.mjs"
import { migrateKey } from "../agnet-key.mjs"
import { loadManagedAgent, loadManagedZone } from "../managed-key-runtime.mjs"

const PASSPHRASE = Buffer.from("persistent identity test passphrase\n");

async function writeRestricted(path, bytes) {
  await writeFile(path, bytes, { mode: 0o600 });
  await chmod(path, 0o600);
}

async function createManagedIdentity(identity, kind) {
  const root = await mkdtemp(join(tmpdir(), `agnet-persistent-${kind}-`));
  await chmod(root, 0o700);
  const keyPath = join(root, "identity.pkcs8");
  const descriptorPath = join(root, "descriptor.json");
  const passphrasePath = join(root, "passphrase");
  const storePath = join(root, "store");
  await writeRestricted(keyPath, Buffer.from(identity.privateKey.export({ format: "der", type: "pkcs8" })));
  await writeRestricted(descriptorPath, Buffer.from(canonical(identity.descriptor)));
  await writeRestricted(passphrasePath, PASSPHRASE);
  await migrateKey({
    storePath,
    keyPath,
    keyType: "ed25519-pkcs8",
    identityKind: kind,
    descriptorPath,
    passphrasePath,
    iterations: 100000,
  });
  return { root, storePath, passphrasePath };
}

test("agent and zone identities survive managed-store restart", async () => {
  const agentSource = createAgent("agent://local/summarizer", {}, ["asp+local://persistent"], ["summarize.text"]);
  const zoneSource = createZone("zone://local");
  const agent = await createManagedIdentity(agentSource, "aid");
  const zone = await createManagedIdentity(zoneSource, "zid");

  try {
    const agentOptions = {
      storePath: agent.storePath,
      passphraseFile: agent.passphrasePath,
      alias: agentSource.alias,
      policy: agentSource.descriptor.policy,
      transports: agentSource.descriptor.transports,
      capabilities: agentSource.descriptor.capabilities,
    };
    const zoneOptions = { storePath: zone.storePath, passphraseFile: zone.passphrasePath, name: zoneSource.name };
    const firstAgent = await loadManagedAgent(agentOptions);
    const firstZone = await loadManagedZone(zoneOptions);
    const secondAgent = await loadManagedAgent(agentOptions);
    const secondZone = await loadManagedZone(zoneOptions);

    assert.equal(firstAgent.aid, agentSource.aid);
    assert.equal(secondAgent.aid, firstAgent.aid);
    assert.equal(secondAgent.descriptor.public_key_spki, firstAgent.descriptor.public_key_spki);
    assert.equal(firstZone.zid, zoneSource.zid);
    assert.equal(secondZone.zid, firstZone.zid);
    assert.equal(secondZone.descriptor.public_key_spki, firstZone.descriptor.public_key_spki);
  } finally {
    await Promise.all([rm(agent.root, { recursive: true, force: true }), rm(zone.root, { recursive: true, force: true })]);
  }
});
