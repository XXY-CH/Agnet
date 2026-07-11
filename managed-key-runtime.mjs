import { agentFromPrivateKey, canonical, zoneFromPrivateKey } from "./asp-core.mjs";
import { readRestrictedFile } from "./managed-key.mjs";
import { ManagedKeyStore } from "./managed-key-store.mjs";

function requirePath(value, label) {
  if (typeof value !== "string" || value.length === 0 || value.includes("\0")) throw new Error(`${label} path invalid`);
  return value;
}

function requireString(value, label) {
  if (typeof value !== "string" || value.length === 0 || value.includes("\0")) throw new Error(`${label} invalid`);
  return value;
}

function requireObject(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} invalid`);
  return value;
}

function requireStringArray(value, label) {
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string" || item.length === 0)) throw new Error(`${label} invalid`);
  return value;
}

function wipe(bytes) {
  if (bytes instanceof Uint8Array) bytes.fill(0);
}

function sameCanonical(left, right) {
  return canonical(left) === canonical(right);
}

async function openManagedStore(storePath, passphraseFile) {
  const passphrase = await readRestrictedFile(requirePath(passphraseFile, "passphrase file"), {
    label: "passphrase file",
    maxBytes: 64 * 1024,
  });
  try {
    return { store: await ManagedKeyStore.open(requirePath(storePath, "store")), passphrase: passphrase.bytes };
  } catch (error) {
    wipe(passphrase.bytes);
    throw error;
  }
}

function buildAgent(loaded, { alias, policy, transports, capabilities }) {
  if (loaded.identity.kind !== "aid") throw new Error("managed generation is not an Agent");
  if (loaded.identity.value !== loaded.descriptor.aid) throw new Error("managed Agent descriptor identity mismatch");
  const built = agentFromPrivateKey(
    requireString(alias, "Agent alias"),
    loaded.privateKey,
    requireObject(policy, "Agent policy"),
    requireStringArray(transports, "Agent transports"),
    requireStringArray(capabilities, "Agent capabilities"),
  );
  if (loaded.descriptor.alias !== alias || built.aid !== loaded.identity.value) throw new Error("managed Agent alias mismatch");
  if (!sameCanonical(built.descriptor, loaded.descriptor)) throw new Error("managed Agent profile mismatch");
  return Object.freeze({ ...built, keyGeneration: loaded.keyGeneration });
}

function buildZone(loaded, name) {
  if (loaded.identity.kind !== "zid") throw new Error("managed generation is not a Zone");
  if (loaded.identity.value !== loaded.descriptor.zid) throw new Error("managed Zone descriptor identity mismatch");
  const built = zoneFromPrivateKey(requireString(name, "Zone name"), loaded.privateKey);
  if (built.zid !== loaded.identity.value || built.descriptor.name !== name) throw new Error("managed Zone name mismatch");
  if (!sameCanonical(built.descriptor, loaded.descriptor)) throw new Error("managed Zone profile mismatch");
  return Object.freeze({ ...built, keyGeneration: loaded.keyGeneration });
}

async function loadVerified(storePath, recordDigest, passphraseFile) {
  const { store, passphrase } = await openManagedStore(storePath, passphraseFile);
  let loaded;
  try {
    loaded = await store.loadRecordDigest(requireString(recordDigest, "record digest"), passphrase);
    return loaded;
  } finally {
    wipe(passphrase);
  }
}

export async function loadVerifiedKeyGeneration(storePath, recordDigest, passphraseFile) {
  return loadVerified(storePath, recordDigest, passphraseFile);
}

export async function loadManagedAgent({ storePath, passphraseFile, alias, policy, transports, capabilities, recordDigest = undefined } = {}) {
  const { store, passphrase } = await openManagedStore(storePath, passphraseFile);
  let loaded;
  try {
    loaded = recordDigest === undefined ? await store.loadActive(passphrase) : await store.loadRecordDigest(requireString(recordDigest, "record digest"), passphrase);
    return buildAgent(loaded, { alias, policy, transports, capabilities });
  } finally {
    wipe(passphrase);
    wipe(loaded?.plaintext);
  }
}

export async function loadManagedZone({ storePath, passphraseFile, name, recordDigest = undefined } = {}) {
  const { store, passphrase } = await openManagedStore(storePath, passphraseFile);
  let loaded;
  try {
    loaded = recordDigest === undefined ? await store.loadActive(passphrase) : await store.loadRecordDigest(requireString(recordDigest, "record digest"), passphrase);
    return buildZone(loaded, name);
  } finally {
    wipe(passphrase);
    wipe(loaded?.plaintext);
  }
}
