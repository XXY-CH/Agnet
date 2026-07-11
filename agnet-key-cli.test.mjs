import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash, createPrivateKey } from "node:crypto";
import { chmod, mkdtemp, readFile, readdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { promisify } from "node:util";

import { agentFromPrivateKey, canonical, zoneFromPrivateKey } from "./asp-core.mjs";
import { openKeyEnvelope, parseKeyEnvelope } from "./managed-key.mjs";
import { ManagedKeyStore } from "./managed-key-store.mjs";
import { migrateKey, recoverKey, rewrapKey } from "./agnet-key.mjs";

const execFileAsync = promisify(execFile);
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const PASSPHRASE = Buffer.from("u11 current passphrase raw bytes\n");
const NEW_PASSPHRASE = Buffer.from("u11 replacement passphrase raw bytes\n");

function seed(start) {
  return Buffer.from(Array.from({ length: 32 }, (_, index) => (start + index) & 0xff));
}

function pkcs8(start) {
  return Buffer.concat([PKCS8_PREFIX, seed(start)]);
}

function privateKey(start) {
  return createPrivateKey({ key: pkcs8(start), format: "der", type: "pkcs8" });
}

async function privateDirectory(name) {
  const path = await mkdtemp(join(tmpdir(), `agnet-u11-${name}-`));
  await chmod(path, 0o700);
  return path;
}

async function writeRestricted(path, bytes) {
  await writeFile(path, bytes, { mode: 0o600 });
}

async function fixture(keyType = "ed25519-pkcs8", identityKind = "aid") {
  const root = await privateDirectory(`${keyType}-${identityKind}`);
  const material = keyType === "ed25519-pkcs8" ? pkcs8(0) : seed(0);
  const privateKeyValue = privateKey(0);
  const identity = identityKind === "aid"
    ? agentFromPrivateKey("agent://u11/worker", privateKeyValue)
    : zoneFromPrivateKey("zone://u11", privateKeyValue);
  const keyPath = join(root, "bare-key");
  const descriptorPath = join(root, "descriptor.json");
  const currentPassphrasePath = join(root, "current-passphrase");
  const newPassphrasePath = join(root, "new-passphrase");
  const storePath = join(root, "store");
  await writeRestricted(keyPath, material);
  await writeRestricted(descriptorPath, Buffer.from(canonical(identity.descriptor)));
  await writeRestricted(currentPassphrasePath, PASSPHRASE);
  await writeRestricted(newPassphrasePath, NEW_PASSPHRASE);
  return { root, material, keyType, identityKind, identity, keyPath, descriptorPath, currentPassphrasePath, newPassphrasePath, storePath };
}

function metadata(operation, loaded) {
  return {
    operation,
    identity_kind: loaded.identity.kind,
    identity_value: loaded.identity.value,
    generation: loaded.keyGeneration.generation,
    record_digest: loaded.keyGeneration.record_digest,
    envelope_sha256: loaded.keyGeneration.envelope_sha256,
  };
}

test("migrate preserves raw PKCS8 and seed key encodings and identity", async () => {
  for (const [keyType, identityKind] of [["ed25519-pkcs8", "aid"], ["ed25519-seed", "zid"]]) {
    const item = await fixture(keyType, identityKind);
    const result = await migrateKey({
      storePath: item.storePath,
      keyPath: item.keyPath,
      keyType,
      identityKind,
      descriptorPath: item.descriptorPath,
      passphrasePath: item.currentPassphrasePath,
      iterations: 100000,
    });
    assert.deepEqual(Object.keys(result), ["operation", "identity_kind", "identity_value", "generation", "record_digest", "envelope_sha256"]);
    assert.equal(result.operation, "migrate");
    assert.equal(result.identity_kind, identityKind);
    assert.equal(result.identity_value, identityKind === "aid" ? item.identity.aid : item.identity.zid);
    assert.equal(result.generation, 1);
    const loaded = await (await ManagedKeyStore.open(item.storePath)).loadActive(PASSPHRASE);
    assert.deepEqual(loaded.plaintext, item.material);
    assert.deepEqual(result, metadata("migrate", loaded));
  }
});

test("rewrap uses new envelope material and preserves a cross-runtime compatible chain", async () => {
  const item = await fixture();
  const migrated = await migrateKey({
    storePath: item.storePath,
    keyPath: item.keyPath,
    keyType: item.keyType,
    identityKind: item.identityKind,
    descriptorPath: item.descriptorPath,
    passphrasePath: item.currentPassphrasePath,
    iterations: 100000,
  });
  const firstEnvelope = await readFile(join(item.storePath, "generations", "0000000000000001.envelope.json"));
  const rewrapped = await rewrapKey({
    storePath: item.storePath,
    descriptorPath: item.descriptorPath,
    identityKind: item.identityKind,
    currentPassphrasePath: item.currentPassphrasePath,
    newPassphrasePath: item.newPassphrasePath,
    iterations: 100000,
  });
  const secondEnvelope = await readFile(join(item.storePath, "generations", "0000000000000002.envelope.json"));
  assert.equal(rewrapped.operation, "rewrap");
  assert.equal(rewrapped.generation, 2);
  assert.equal(rewrapped.identity_value, migrated.identity_value);
  assert.notEqual(rewrapped.record_digest, migrated.record_digest);
  assert.notDeepEqual(parseKeyEnvelope(firstEnvelope).kdf.salt, parseKeyEnvelope(secondEnvelope).kdf.salt);
  assert.notDeepEqual(parseKeyEnvelope(firstEnvelope).cipher.nonce, parseKeyEnvelope(secondEnvelope).cipher.nonce);
  const loaded = await (await ManagedKeyStore.open(item.storePath)).loadActive(NEW_PASSPHRASE);
  assert.deepEqual(loaded.plaintext, item.material);
  assert.deepEqual(rewrapped, metadata("rewrap", loaded));
  assert.equal((await readdir(join(item.storePath, "generations"))).filter((name) => name.endsWith(".record.json")).length, 2);
});

test("recover delegates to U10 highest generation and does not mint a record", async () => {
  const item = await fixture();
  await migrateKey({ storePath: item.storePath, keyPath: item.keyPath, keyType: item.keyType, identityKind: item.identityKind, descriptorPath: item.descriptorPath, passphrasePath: item.currentPassphrasePath, iterations: 100000 });
  await rewrapKey({ storePath: item.storePath, identityKind: item.identityKind, descriptorPath: item.descriptorPath, currentPassphrasePath: item.currentPassphrasePath, newPassphrasePath: item.newPassphrasePath, iterations: 100000 });
  const recordsBefore = (await readdir(join(item.storePath, "generations"))).filter((name) => name.endsWith(".record.json")).sort();
  const recovered = await recoverKey({ storePath: item.storePath, passphrasePath: item.newPassphrasePath });
  assert.equal(recovered.operation, "recover");
  assert.equal(recovered.generation, 2);
  assert.deepEqual((await readdir(join(item.storePath, "generations"))).filter((name) => name.endsWith(".record.json")).sort(), recordsBefore);
});

test("lifecycle rejects mismatched descriptors, wrong key types, wrong passphrases, unsafe inputs, and invalid KDF bounds", async () => {
  const item = await fixture();
  const other = agentFromPrivateKey("agent://u11/other", privateKey(64));
  const wrongDescriptorPath = join(item.root, "wrong-descriptor.json");
  await writeRestricted(wrongDescriptorPath, Buffer.from(canonical(other.descriptor)));
  await assert.rejects(
    migrateKey({ storePath: item.storePath, keyPath: item.keyPath, keyType: item.keyType, identityKind: item.identityKind, descriptorPath: wrongDescriptorPath, passphrasePath: item.currentPassphrasePath, iterations: 100000 }),
    /identity mismatch/,
  );
  await assert.rejects(
    migrateKey({ storePath: join(item.root, "wrong-type-store"), keyPath: item.keyPath, keyType: "ed25519-seed", identityKind: item.identityKind, descriptorPath: item.descriptorPath, passphrasePath: item.currentPassphrasePath, iterations: 100000 }),
    /seed plaintext length invalid/,
  );
  await assert.rejects(
    migrateKey({ storePath: join(item.root, "bad-kdf-store"), keyPath: item.keyPath, keyType: item.keyType, identityKind: item.identityKind, descriptorPath: item.descriptorPath, passphrasePath: item.currentPassphrasePath, iterations: 99999 }),
    /iterations invalid/,
  );
  const identityKindMismatch = await fixture();
  await assert.rejects(
    migrateKey({ storePath: identityKindMismatch.storePath, keyPath: identityKindMismatch.keyPath, keyType: identityKindMismatch.keyType, identityKind: "zid", descriptorPath: identityKindMismatch.descriptorPath, passphrasePath: identityKindMismatch.currentPassphrasePath, iterations: 100000 }),
    /descriptor identity missing|identity kind mismatch/,
  );
  await migrateKey({ storePath: item.storePath, keyPath: item.keyPath, keyType: item.keyType, identityKind: item.identityKind, descriptorPath: item.descriptorPath, passphrasePath: item.currentPassphrasePath, iterations: 100000 });
  const wrongPassphrasePath = join(item.root, "wrong-passphrase");
  await writeRestricted(wrongPassphrasePath, Buffer.from("wrong passphrase\n"));
  await assert.rejects(
    rewrapKey({ storePath: item.storePath, identityKind: item.identityKind, descriptorPath: item.descriptorPath, currentPassphrasePath: wrongPassphrasePath, newPassphrasePath: item.newPassphrasePath, iterations: 100000 }),
    /authentication failed/,
  );
  const unsafeKeyPath = join(item.root, "unsafe-key");
  await writeFile(unsafeKeyPath, item.material, { mode: 0o644 });
  await assert.rejects(
    migrateKey({ storePath: join(item.root, "unsafe-key-store"), keyPath: unsafeKeyPath, keyType: item.keyType, identityKind: item.identityKind, descriptorPath: item.descriptorPath, passphrasePath: item.currentPassphrasePath, iterations: 100000 }),
    /mode must be 0600/,
  );
});

test("CLI rotates an Agent with a verified Zone generation", async () => {
  const item = await fixture();
  const zone = await fixture("ed25519-pkcs8", "zid");
  await migrateKey({ storePath: item.storePath, keyPath: item.keyPath, keyType: item.keyType, identityKind: item.identityKind, descriptorPath: item.descriptorPath, passphrasePath: item.currentPassphrasePath, iterations: 100000 });
  await migrateKey({ storePath: zone.storePath, keyPath: zone.keyPath, keyType: zone.keyType, identityKind: zone.identityKind, descriptorPath: zone.descriptorPath, passphrasePath: zone.currentPassphrasePath, iterations: 100000 });
  const result = await execFileAsync(process.execPath, ["agnet-key.mjs", "rotate", "--store", item.storePath, "--passphrase-file", item.currentPassphrasePath, "--zone-store", zone.storePath, "--zone-passphrase-file", zone.currentPassphrasePath, "--iterations", "100000"]);
  const output = JSON.parse(result.stdout);
  assert.equal(output.operation, "rotate");
  assert.equal(output.generation, 2);
  assert.equal(output.identity_kind, "aid");
  assert.notEqual(output.identity_value, item.identity.aid);
  assert.equal(result.stderr, "");
});

test("CLI has exact grammar, emits only public metadata, and never emits passphrase bytes", async () => {
  const item = await fixture();
  const migrateArgs = ["agnet-key.mjs", "migrate", "--store", item.storePath, "--key-file", item.keyPath, "--key-type", item.keyType, "--identity-kind", item.identityKind, "--descriptor", item.descriptorPath, "--passphrase-file", item.currentPassphrasePath, "--iterations", "100000"];
  const migrated = await execFileAsync(process.execPath, migrateArgs);
  const output = JSON.parse(migrated.stdout);
  assert.deepEqual(Object.keys(output), ["operation", "identity_kind", "identity_value", "generation", "record_digest", "envelope_sha256"]);
  assert.equal(output.operation, "migrate");
  assert.equal(migrated.stderr, "");
  assert.equal(migrated.stdout.includes(PASSPHRASE.toString("utf8")), false);
  assert.equal(migrated.stdout.includes(NEW_PASSPHRASE.toString("utf8")), false);
  for (const args of [
    ["agnet-key.mjs", "migrate", "--store", item.storePath],
    ["agnet-key.mjs", "migrate", ...migrateArgs.slice(2), "--passphrase", PASSPHRASE.toString("utf8")],
    ["agnet-key.mjs", "rewrap", "--store", item.storePath, "--identity-kind", item.identityKind, "--descriptor", item.descriptorPath, "--current-passphrase-file", item.currentPassphrasePath, "--new-passphrase-file", item.newPassphrasePath, "--extra", "value"],
    ["agnet-key.mjs", "recover", "--store", item.storePath],
  ]) {
    await assert.rejects(
      execFileAsync(process.execPath, args),
      (error) => {
        const combined = `${error.stdout}${error.stderr}`;
        assert.equal(combined.includes(PASSPHRASE.toString("utf8")), false);
        assert.equal(combined.includes(NEW_PASSPHRASE.toString("utf8")), false);
        return true;
      },
    );
  }
  const pkg = JSON.parse(await readFile("package.json", "utf8"));
  assert.equal(pkg.bin["agnet-key"], "./agnet-key.mjs");
  assert.equal(pkg.files.includes("agnet-key.mjs"), true);
  assert.equal(pkg.files.includes("managed-key.mjs"), true);
  assert.equal(pkg.files.includes("managed-key-store.mjs"), true);
  assert.equal(pkg.files.includes("secure-input.mjs"), true);
  assert.equal(pkg.files.includes("secure-input-openat.py"), true);
  assert.equal(createHash("sha256").update(output.record_digest).digest("hex").length, 64);
});
