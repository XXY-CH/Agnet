import assert from "node:assert/strict";
import { createHash, createPrivateKey, createPublicKey } from "node:crypto";
import { chmod, link, mkdtemp, readFile, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { tmpdir } from "node:os";

import { canonical, computeAid, computeZid } from "./asp-core.mjs";
import { openKeyEnvelope, parseKeyEnvelope, readRestrictedFile, sealKeyEnvelope } from "./managed-key.mjs";

const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const PASSPHRASE = Buffer.from("u8 deterministic passphrase <>&\n");

function seedBytes(start = 0) {
  return Buffer.from(Array.from({ length: 32 }, (_, index) => (start + index) & 0xff));
}

function pkcs8FromSeed(seed) {
  return Buffer.concat([PKCS8_PREFIX, seed]);
}

function identityFor(keyType, plaintext, kind) {
  const privateKey = createPrivateKey({
    key: keyType === "ed25519-seed" ? pkcs8FromSeed(plaintext) : plaintext,
    format: "der",
    type: "pkcs8",
  });
  const publicKey = createPublicKey(privateKey);
  return { kind, value: kind === "aid" ? computeAid(publicKey) : computeZid(publicKey) };
}

function mutateEnvelope(bytes, mutate) {
  const envelope = JSON.parse(Buffer.from(bytes).toString("utf8"));
  mutate(envelope);
  return Buffer.from(JSON.stringify(envelope));
}

function nonCanonicalBase64Url(value) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const last = alphabet.indexOf(value.at(-1));
  return `${value.slice(0, -1)}${alphabet[(last & 0b111100) | 0b000001]}`;
}

test("managed key envelopes round-trip PKCS8 and seed identities", () => {
  for (const [keyType, plaintext, kind] of [
    ["ed25519-pkcs8", pkcs8FromSeed(seedBytes(0)), "aid"],
    ["ed25519-seed", seedBytes(64), "zid"],
  ]) {
    const identity = identityFor(keyType, plaintext, kind);
    const envelopeBytes = sealKeyEnvelope({ keyType, plaintext, identity, passphrase: PASSPHRASE, iterations: 100000 });
    const parsed = parseKeyEnvelope(envelopeBytes);
    assert.equal(parsed.format, "agnet-key-envelope/v1");
    assert.equal(parsed.key_type, keyType);
    assert.deepEqual(parsed.identity, identity);
    const opened = openKeyEnvelope({ envelopeBytes, passphrase: PASSPHRASE });
    assert.equal(opened.keyType, keyType);
    assert.deepEqual(opened.identity, identity);
    assert.deepEqual(opened.plaintext, plaintext);
    assert.equal(opened.privateKey.asymmetricKeyType, "ed25519");
  }
});

test("managed key envelope parser rejects duplicate, unknown, and non-exact fields", () => {
  const identity = identityFor("ed25519-seed", seedBytes(96), "aid");
  const envelopeBytes = sealKeyEnvelope({ keyType: "ed25519-seed", plaintext: seedBytes(96), identity, passphrase: PASSPHRASE, iterations: 100000 });
  const text = envelopeBytes.toString("utf8");
  assert.throws(() => parseKeyEnvelope(Buffer.from(text.replace('"format":', '"format":"agnet-key-envelope/v1","format":'))), /duplicate JSON key: format/);
  assert.throws(() => parseKeyEnvelope(Buffer.from(text.replace('"kind":"aid"', '"kind":"aid","kind":"aid"'))), /duplicate JSON key: kind/);
  assert.throws(() => parseKeyEnvelope(envelopeBytes.subarray(0, envelopeBytes.length - 1)), /JSON|object|unterminated|invalid/);
  assert.throws(() => parseKeyEnvelope(mutateEnvelope(envelopeBytes, (value) => { value.extra = true; })), /envelope fields invalid/);
  assert.throws(() => parseKeyEnvelope(mutateEnvelope(envelopeBytes, (value) => { value.identity.extra = true; })), /identity fields invalid/);
  assert.throws(() => parseKeyEnvelope(mutateEnvelope(envelopeBytes, (value) => { value.kdf.extra = true; })), /kdf fields invalid/);
  assert.throws(() => parseKeyEnvelope(mutateEnvelope(envelopeBytes, (value) => { value.cipher.extra = true; })), /cipher fields invalid/);
});

test("managed key envelopes reject malformed crypto parameters and plaintext", () => {
  const seed = seedBytes(128);
  const identity = identityFor("ed25519-seed", seed, "aid");
  const envelopeBytes = sealKeyEnvelope({ keyType: "ed25519-seed", plaintext: seed, identity, passphrase: PASSPHRASE, iterations: 100000 });
  const cases = [
    ["wrong passphrase", envelopeBytes, Buffer.from("wrong"), /authentication failed/],
    ["truncated ciphertext", mutateEnvelope(envelopeBytes, (value) => { const bytes = Buffer.from(value.ciphertext, "base64url"); value.ciphertext = bytes.subarray(1).toString("base64url"); }), PASSPHRASE, /ciphertext length invalid/],
    ["ciphertext content", mutateEnvelope(envelopeBytes, (value) => { const bytes = Buffer.from(value.ciphertext, "base64url"); bytes[0] ^= 1; value.ciphertext = bytes.toString("base64url"); }), PASSPHRASE, /authentication failed/],
    ["tag content", mutateEnvelope(envelopeBytes, (value) => { const bytes = Buffer.from(value.tag, "base64url"); bytes[0] ^= 1; value.tag = bytes.toString("base64url"); }), PASSPHRASE, /authentication failed/],
    ["format mutation", mutateEnvelope(envelopeBytes, (value) => { value.format = "agnet-key-envelope/v2"; }), PASSPHRASE, /envelope format invalid/],
    ["key type mutation", mutateEnvelope(envelopeBytes, (value) => { value.key_type = "ed25519-pkcs8"; }), PASSPHRASE, /ciphertext length invalid|key plaintext invalid|authentication failed/],
    ["identity kind mutation", mutateEnvelope(envelopeBytes, (value) => { value.identity.kind = "zid"; }), PASSPHRASE, /identity value invalid/],
    ["identity value mutation", mutateEnvelope(envelopeBytes, (value) => { value.identity.value = `aid:ed25519:${"A".repeat(43)}`; }), PASSPHRASE, /authentication failed|identity mismatch/],
    ["kdf name mutation", mutateEnvelope(envelopeBytes, (value) => { value.kdf.name = "pbkdf2-sha1"; }), PASSPHRASE, /kdf name invalid/],
    ["padded salt", mutateEnvelope(envelopeBytes, (value) => { value.kdf.salt += "="; }), PASSPHRASE, /exact unpadded base64url/],
    ["noncanonical salt", mutateEnvelope(envelopeBytes, (value) => { value.kdf.salt = nonCanonicalBase64Url(value.kdf.salt); }), PASSPHRASE, /exact unpadded base64url/],
    ["short salt", mutateEnvelope(envelopeBytes, (value) => { value.kdf.salt = "AA"; }), PASSPHRASE, /salt length invalid/],
    ["low iterations", mutateEnvelope(envelopeBytes, (value) => { value.kdf.iterations = 99999; }), PASSPHRASE, /iterations invalid/],
    ["high iterations", mutateEnvelope(envelopeBytes, (value) => { value.kdf.iterations = 2000001; }), PASSPHRASE, /iterations invalid/],
    ["derived key bytes mutation", mutateEnvelope(envelopeBytes, (value) => { value.kdf.derived_key_bytes = 31; }), PASSPHRASE, /derived key bytes invalid/],
    ["cipher name mutation", mutateEnvelope(envelopeBytes, (value) => { value.cipher.name = "aes-128-gcm"; }), PASSPHRASE, /cipher name invalid/],
    ["short nonce", mutateEnvelope(envelopeBytes, (value) => { value.cipher.nonce = "AA"; }), PASSPHRASE, /nonce length invalid/],
    ["tag bytes mutation", mutateEnvelope(envelopeBytes, (value) => { value.cipher.tag_bytes = 12; }), PASSPHRASE, /tag bytes invalid/],
    ["short tag", mutateEnvelope(envelopeBytes, (value) => { value.tag = "AA"; }), PASSPHRASE, /tag length invalid/],
  ];
  for (const [name, candidate, passphrase, expected] of cases) {
    assert.throws(() => openKeyEnvelope({ envelopeBytes: candidate, passphrase }), expected, name);
  }
  for (const size of [31, 33]) {
    assert.throws(
      () => sealKeyEnvelope({ keyType: "ed25519-seed", plaintext: Buffer.alloc(size), identity, passphrase: PASSPHRASE, iterations: 100000 }),
      /seed plaintext length invalid/,
    );
  }
  assert.throws(
    () => sealKeyEnvelope({ keyType: "ed25519-pkcs8", plaintext: Buffer.alloc(48), identity, passphrase: PASSPHRASE, iterations: 100000 }),
    /PKCS8 plaintext invalid/,
  );
});

test("Node opens frozen Node-created and Go-created envelope vectors", async () => {
  const vector = JSON.parse(await readFile("test-vectors/agnet-key-envelope-v1.json", "utf8"));
  assert.equal(vector.format, "agnet-key-envelope-test-v1");
  assert.deepEqual(vector.cases.map((item) => item.origin), ["node-created", "go-created"]);
  for (const item of vector.cases) {
    const envelopeBytes = Buffer.from(item.envelope_canonical, "utf8");
    const passphrase = Buffer.from(item.passphrase, "base64url");
    const opened = openKeyEnvelope({ envelopeBytes, passphrase });
    const parsed = parseKeyEnvelope(envelopeBytes);
    const actualAAD = canonical({ format: parsed.format, key_type: parsed.key_type, identity: parsed.identity, kdf: parsed.kdf, cipher: parsed.cipher });
    assert.equal(actualAAD, item.aad_canonical);
    assert.equal(opened.keyType, item.key_type);
    assert.deepEqual(opened.identity, item.identity);
    assert.equal(opened.plaintext.toString("base64url"), item.plaintext);
    assert.equal(createHash("sha256").update(item.aad_canonical).digest("hex"), item.aad_sha256);
  }
});

test("readRestrictedFile verifies the opened file and parent chain", async () => {
  if (process.platform !== "darwin" && process.platform !== "linux") return;
  const root = await mkdtemp(join(tmpdir(), "agnet-u8-restricted-"));
  await chmod(root, 0o700);
  const safePath = join(root, "passphrase");
  await writeFile(safePath, PASSPHRASE, { mode: 0o600 });
  const opened = await readRestrictedFile(safePath, { label: "passphrase", maxBytes: 1024 });
  assert.deepEqual(opened.bytes, PASSPHRASE);
  assert.equal(opened.evidence.mode, 0o600);
  assert.equal(opened.evidence.nlink, 1);

  const symlinkPath = join(root, "symlink");
  await symlink(safePath, symlinkPath);
  await assert.rejects(readRestrictedFile(symlinkPath, { label: "passphrase", maxBytes: 1024 }), /symbolic link/);

  const hardlinkPath = join(root, "hardlink");
  await link(safePath, hardlinkPath);
  await assert.rejects(readRestrictedFile(safePath, { label: "passphrase", maxBytes: 1024 }), /link count must be (?:one|1)/);

  const unsafeRoot = await mkdtemp(join(tmpdir(), "agnet-u8-unsafe-"));
  await chmod(unsafeRoot, 0o777);
  const unsafePath = join(unsafeRoot, "secret");
  await writeFile(unsafePath, PASSPHRASE, { mode: 0o600 });
  await assert.rejects(readRestrictedFile(unsafePath, { label: "passphrase", maxBytes: 1024 }), /unsafe parent mode/);
});
