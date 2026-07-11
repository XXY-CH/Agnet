import { createHash, generateKeyPairSync } from "node:crypto";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

import { agentFromPrivateKey, canonical } from "./asp-core.mjs";
import {
  createRotationGenerationRecord,
  createSignedGenerationRecord,
  generationBody,
  openKeyEnvelope,
  readRestrictedFile,
  sealKeyEnvelope,
} from "./managed-key.mjs";
import { ManagedKeyStore } from "./managed-key-store.mjs";
import { parseDuplicateSafeJson } from "./secure-input.mjs";

const KEY_TYPES = new Set(["ed25519-pkcs8", "ed25519-seed"]);
const IDENTITY_KINDS = new Set(["aid", "zid"]);
const MIN_ITERATIONS = 100000;
const MAX_ITERATIONS = 2000000;
const PUBLIC_FIELDS = ["operation", "identity_kind", "identity_value", "generation", "record_digest", "envelope_sha256"];

function requirePath(value, label) {
  if (typeof value !== "string" || value.length === 0 || value.includes("\0")) throw new Error(`${label} path invalid`);
  return value;
}

function requireKeyType(value) {
  if (!KEY_TYPES.has(value)) throw new Error("key type invalid");
  return value;
}

function requireIdentityKind(value) {
  if (!IDENTITY_KINDS.has(value)) throw new Error("identity kind invalid");
  return value;
}

function requireIterations(value) {
  if (!Number.isSafeInteger(value) || value < MIN_ITERATIONS || value > MAX_ITERATIONS) throw new Error("kdf iterations invalid");
  return value;
}

async function readPassphrase(path) {
  return (await readRestrictedFile(requirePath(path, "passphrase file"), { label: "passphrase file", maxBytes: 64 * 1024 })).bytes;
}

async function readDescriptor(path) {
  const bytes = (await readRestrictedFile(requirePath(path, "descriptor"), { label: "descriptor", maxBytes: 1024 * 1024 })).bytes;
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new Error("descriptor must be valid UTF-8");
  }
  const descriptor = parseDuplicateSafeJson(text);
  if (descriptor === null || typeof descriptor !== "object" || Array.isArray(descriptor)) throw new Error("descriptor invalid");
  return descriptor;
}

function identityFromDescriptor(descriptor, kind) {
  const value = descriptor[kind];
  if (typeof value !== "string" || value.length === 0 || value.includes("\0")) throw new Error("descriptor identity missing");
  return { kind, value };
}

function publicMetadata(operation, loaded) {
  const result = {
    operation,
    identity_kind: loaded.identity.kind,
    identity_value: loaded.identity.value,
    generation: loaded.keyGeneration.generation,
    record_digest: loaded.keyGeneration.record_digest,
    envelope_sha256: loaded.keyGeneration.envelope_sha256,
  };
  if (canonical(Object.keys(result).sort()) !== canonical([...PUBLIC_FIELDS].sort())) throw new Error("public metadata invalid");
  return Object.freeze(result);
}

function wipe(bytes) {
  if (bytes instanceof Uint8Array) bytes.fill(0);
}

function assertSameIdentity(left, right) {
  if (left.kind !== right.kind || left.value !== right.value) throw new Error("identity comparison failed");
}

function descriptorDigest(descriptor) {
  return createHash("sha256").update(canonical(descriptor)).digest("hex");
}

export async function migrateKey({ storePath, keyPath, keyType, identityKind, descriptorPath, passphrasePath, iterations = 600000 } = {}) {
  const normalizedStorePath = requirePath(storePath, "store");
  const normalizedKeyPath = requirePath(keyPath, "key");
  const normalizedKeyType = requireKeyType(keyType);
  const normalizedIdentityKind = requireIdentityKind(identityKind);
  requireIterations(iterations);
  let bareKey;
  let passphrase;
  let opened;
  let installed;
  try {
    bareKey = (await readRestrictedFile(normalizedKeyPath, { label: "bare key", maxBytes: 1024 * 1024 })).bytes;
    const descriptor = await readDescriptor(descriptorPath);
    const identity = identityFromDescriptor(descriptor, normalizedIdentityKind);
    passphrase = await readPassphrase(passphrasePath);
    const envelopeBytes = sealKeyEnvelope({ keyType: normalizedKeyType, plaintext: bareKey, identity, passphrase, iterations });
    opened = openKeyEnvelope({ envelopeBytes, passphrase });
    const body = generationBody({ identity, generation: 1, operation: "migrate", envelopeBytes, descriptor });
    const record = createSignedGenerationRecord({ body, privateKey: opened.privateKey });
    const store = await ManagedKeyStore.open(normalizedStorePath);
    installed = await store.installGeneration({ envelopeBytes, record, descriptor, passphrase });
    assertSameIdentity(installed.identity, identity);
    if (installed.keyType !== normalizedKeyType || installed.keyGeneration.generation !== 1) throw new Error("migration reload comparison failed");
    return publicMetadata("migrate", installed);
  } finally {
    wipe(bareKey);
    wipe(passphrase);
    wipe(opened?.plaintext);
    wipe(installed?.plaintext);
  }
}

export async function rewrapKey({ storePath, identityKind, descriptorPath, currentPassphrasePath, newPassphrasePath, iterations = 600000 } = {}) {
  const normalizedStorePath = requirePath(storePath, "store");
  const normalizedIdentityKind = requireIdentityKind(identityKind);
  requireIterations(iterations);
  let currentPassphrase;
  let newPassphrase;
  let loaded;
  let installed;
  try {
    currentPassphrase = await readPassphrase(currentPassphrasePath);
    newPassphrase = await readPassphrase(newPassphrasePath);
    const descriptor = await readDescriptor(descriptorPath);
    const store = await ManagedKeyStore.open(normalizedStorePath);
    loaded = await store.loadActive(currentPassphrase);
    if (normalizedIdentityKind !== loaded.identity.kind) throw new Error("identity kind mismatch");
    const identity = identityFromDescriptor(descriptor, normalizedIdentityKind);
    assertSameIdentity(identity, loaded.identity);
    if (descriptorDigest(descriptor) !== loaded.keyGeneration.descriptor_digest) throw new Error("descriptor mismatch");
    if (loaded.record === undefined) throw new Error("active record unavailable");
    const envelopeBytes = sealKeyEnvelope({ keyType: loaded.keyType, plaintext: loaded.plaintext, identity, passphrase: newPassphrase, iterations });
    const body = generationBody({
      identity,
      generation: loaded.keyGeneration.generation + 1,
      operation: "rewrap",
      envelopeBytes,
      descriptor,
      previousRecord: loaded.record,
    });
    const record = createSignedGenerationRecord({ body, privateKey: loaded.privateKey });
    installed = await store.installGeneration({ envelopeBytes, record, descriptor, passphrase: newPassphrase });
    assertSameIdentity(installed.identity, loaded.identity);
    if (installed.keyType !== loaded.keyType || installed.keyGeneration.descriptor_digest !== loaded.keyGeneration.descriptor_digest) {
      throw new Error("rewrap reload comparison failed");
    }
    return publicMetadata("rewrap", installed);
  } finally {
    wipe(currentPassphrase);
    wipe(newPassphrase);
    wipe(loaded?.plaintext);
    wipe(installed?.plaintext);
  }
}

export async function recoverKey({ storePath, passphrasePath } = {}) {
  const normalizedStorePath = requirePath(storePath, "store");
  let passphrase;
  let recovered;
  try {
    passphrase = await readPassphrase(passphrasePath);
    recovered = await (await ManagedKeyStore.open(normalizedStorePath)).recover(passphrase);
    return publicMetadata("recover", recovered);
  } finally {
    wipe(passphrase);
    wipe(recovered?.plaintext);
  }
}

function nextAgentPlaintext(keyType, privateKey) {
  const pkcs8 = Buffer.from(privateKey.export({ format: "der", type: "pkcs8" }));
  if (keyType === "ed25519-pkcs8") return pkcs8;
  if (keyType === "ed25519-seed") return pkcs8.subarray(-32);
  throw new Error("key type invalid");
}

function sameAgentProfile(previousDescriptor, nextDescriptor) {
  return canonical({
    alias: previousDescriptor.alias,
    transports: previousDescriptor.transports,
    capabilities: previousDescriptor.capabilities,
    policy: previousDescriptor.policy,
  }) === canonical({
    alias: nextDescriptor.alias,
    transports: nextDescriptor.transports,
    capabilities: nextDescriptor.capabilities,
    policy: nextDescriptor.policy,
  });
}

export async function rotateAgent({ store, passphraseFile, zoneStore, zonePassphraseFile, iterations = 600000 } = {}) {
  if (!(store instanceof ManagedKeyStore) || !(zoneStore instanceof ManagedKeyStore)) throw new Error("managed key store invalid");
  requireIterations(iterations);
  let passphrase;
  let zonePassphrase;
  let loaded;
  let zoneLoaded;
  let nextPlaintext;
  let installed;
  try {
    passphrase = await readPassphrase(passphraseFile);
    loaded = await store.loadActive(passphrase);
    if (loaded.identity.kind !== "aid") throw new Error("rotation requires an Agent aid identity");
    if (loaded.record === undefined || loaded.descriptor === undefined) throw new Error("active Agent generation unavailable");
    zonePassphrase = await readPassphrase(zonePassphraseFile);
    zoneLoaded = await zoneStore.loadActive(zonePassphrase);
    if (zoneLoaded.identity.kind !== "zid" || zoneLoaded.record === undefined || zoneLoaded.descriptor === undefined) throw new Error("rotation requires a verified Zone zid generation");
    if (zoneLoaded.descriptor.zid !== zoneLoaded.identity.value || zoneLoaded.record.body.identity_value !== zoneLoaded.identity.value) throw new Error("Zone generation identity mismatch");
    if (zoneLoaded.descriptor.revoked === true || zoneLoaded.descriptor.status === "revoked") throw new Error("rotation Zone is revoked");
    const { privateKey } = generateKeyPairSync("ed25519");
    nextPlaintext = nextAgentPlaintext(loaded.keyType, privateKey);
    const nextAgent = agentFromPrivateKey(
      loaded.descriptor.alias,
      privateKey,
      structuredClone(loaded.descriptor.policy),
      structuredClone(loaded.descriptor.transports),
      structuredClone(loaded.descriptor.capabilities),
    );
    if (!sameAgentProfile(loaded.descriptor, nextAgent.descriptor)) throw new Error("Agent profile drift");
    if (nextAgent.aid === loaded.identity.value) throw new Error("rotation reused Agent aid");
    const envelopeBytes = sealKeyEnvelope({
      keyType: loaded.keyType,
      plaintext: nextPlaintext,
      identity: { kind: "aid", value: nextAgent.aid },
      passphrase,
      iterations,
    });
    const body = generationBody({
      identity: { kind: "aid", value: nextAgent.aid },
      generation: loaded.keyGeneration.generation + 1,
      operation: "rotate",
      envelopeBytes,
      descriptor: nextAgent.descriptor,
      previousRecord: loaded.record,
    });
    const zone = {
      descriptor: zoneLoaded.descriptor,
      privateKey: zoneLoaded.privateKey,
    };
    const record = createRotationGenerationRecord({
      body,
      previousAgent: { descriptor: loaded.descriptor, privateKey: loaded.privateKey },
      nextAgent,
      zone,
      zoneGeneration: zoneLoaded.keyGeneration.generation,
      zoneRecordDigest: zoneLoaded.keyGeneration.record_digest,
    });
    installed = await store.installGeneration({
      envelopeBytes,
      record,
      descriptor: nextAgent.descriptor,
      previousDescriptor: loaded.descriptor,
      zoneDescriptor: zoneLoaded.descriptor,
      zoneRecord: zoneLoaded.record,
      expectedIdentity: { kind: "aid", value: nextAgent.aid },
      passphrase,
    });
    assertSameIdentity(installed.identity, { kind: "aid", value: nextAgent.aid });
    if (installed.keyGeneration.generation !== body.generation || installed.keyGeneration.record_digest !== record.record_digest) throw new Error("rotation activation reload comparison failed");
    return publicMetadata("rotate", installed);
  } finally {
    wipe(passphrase);
    wipe(zonePassphrase);
    wipe(nextPlaintext);
    wipe(loaded?.plaintext);
    wipe(zoneLoaded?.plaintext);
    wipe(installed?.plaintext);
  }
}

function parseCliArguments(args, command) {
  const allowed = command === "migrate"
    ? new Set(["--store", "--key-file", "--key-type", "--identity-kind", "--descriptor", "--passphrase-file", "--iterations"])
    : command === "rewrap"
      ? new Set(["--store", "--identity-kind", "--descriptor", "--current-passphrase-file", "--new-passphrase-file", "--iterations"])
      : command === "rotate"
        ? new Set(["--store", "--passphrase-file", "--zone-store", "--zone-passphrase-file", "--iterations"])
        : new Set(["--store", "--passphrase-file"]);
  const values = {};
  for (let index = 0; index < args.length; index += 1) {
    const option = args[index];
    if (!allowed.has(option) || Object.hasOwn(values, option)) throw new Error("invalid command arguments");
    const value = args[index + 1];
    if (value === undefined || value.startsWith("--") || value.length === 0 || value.includes("\0")) throw new Error("invalid command arguments");
    values[option] = value;
    index += 1;
  }
  for (const option of allowed) {
    if (option === "--iterations") continue;
    if (!Object.hasOwn(values, option)) throw new Error("invalid command arguments");
  }
  if (values["--iterations"] !== undefined) {
    if (!/^[0-9]+$/.test(values["--iterations"])) throw new Error("invalid command arguments");
    values["--iterations"] = Number(values["--iterations"]);
    requireIterations(values["--iterations"]);
  }
  return values;
}

export async function runCli(argv = process.argv.slice(2)) {
  if (!Array.isArray(argv) || argv.length === 0) throw new Error("invalid command arguments");
  const [command, ...args] = argv;
  if (command !== "migrate" && command !== "rewrap" && command !== "recover" && command !== "rotate") throw new Error("invalid command arguments");
  const values = parseCliArguments(args, command);
  if (command === "migrate") {
    return migrateKey({
      storePath: values["--store"],
      keyPath: values["--key-file"],
      keyType: values["--key-type"],
      identityKind: values["--identity-kind"],
      descriptorPath: values["--descriptor"],
      passphrasePath: values["--passphrase-file"],
      ...(values["--iterations"] === undefined ? {} : { iterations: values["--iterations"] }),
    });
  }
  if (command === "rewrap") {
    return rewrapKey({
      storePath: values["--store"],
      identityKind: values["--identity-kind"],
      descriptorPath: values["--descriptor"],
      currentPassphrasePath: values["--current-passphrase-file"],
      newPassphrasePath: values["--new-passphrase-file"],
      ...(values["--iterations"] === undefined ? {} : { iterations: values["--iterations"] }),
    });
  }
  if (command === "rotate") {
    return rotateAgent({
      store: await ManagedKeyStore.open(values["--store"]),
      passphraseFile: values["--passphrase-file"],
      zoneStore: await ManagedKeyStore.open(values["--zone-store"]),
      zonePassphraseFile: values["--zone-passphrase-file"],
      ...(values["--iterations"] === undefined ? {} : { iterations: values["--iterations"] }),
    });
  }
  return recoverKey({ storePath: values["--store"], passphrasePath: values["--passphrase-file"] });
}

async function main() {
  try {
    const result = await runCli();
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) {
    const message = error instanceof Error && typeof error.message === "string" && error.message.length > 0 ? error.message : "operation failed";
    process.stderr.write(`agnet-key: ${message}\n`);
    process.exitCode = 1;
  }
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
