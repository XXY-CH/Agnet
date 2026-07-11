import {
  createCipheriv,
  createDecipheriv,
  createPrivateKey,
  createPublicKey,
  pbkdf2Sync,
  randomBytes,
} from "node:crypto";

import {
  canonical,
  computeAid,
  computeZid,
  decodeBase64UrlExact,
} from "./asp-core.mjs";
import {
  parseDuplicateSafeJson,
  safeOpenOwnedBytes,
} from "./secure-input.mjs";

export const KEY_ENVELOPE_FORMAT = "agnet-key-envelope/v1";
export const KEY_TYPE_PKCS8 = "ed25519-pkcs8";
export const KEY_TYPE_SEED = "ed25519-seed";
export const IDENTITY_AID = "aid";
export const IDENTITY_ZID = "zid";

const KDF_NAME = "pbkdf2-hmac-sha256";
const CIPHER_NAME = "aes-256-gcm";
const DEFAULT_ITERATIONS = 600000;
const MIN_ITERATIONS = 100000;
const MAX_ITERATIONS = 2000000;
const DERIVED_KEY_BYTES = 32;
const SALT_BYTES = 16;
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const SEED_BYTES = 32;
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const PKCS8_BYTES = PKCS8_PREFIX.length + SEED_BYTES;
const MAX_SECRET_BYTES = 1024 * 1024;

function requireObject(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} invalid`);
  return value;
}

function requireExactFields(value, fields, label) {
  const object = requireObject(value, label);
  const actual = Object.keys(object).sort();
  const expected = [...fields].sort();
  if (actual.length !== expected.length || actual.some((field, index) => field !== expected[index])) throw new Error(`${label} fields invalid`);
  return object;
}

function requireBinary(value, label, length = undefined) {
  const decoded = decodeBase64UrlExact(value, label);
  if (length !== undefined && decoded.length !== length) throw new Error(`${label} length invalid`);
  return decoded;
}

function requireBytes(value, label, { allowEmpty = false } = {}) {
  if (!(value instanceof Uint8Array)) throw new Error(`${label} must be bytes`);
  const bytes = Buffer.from(value);
  if (!allowEmpty && bytes.length === 0) throw new Error(`${label} must not be empty`);
  if (bytes.length > MAX_SECRET_BYTES) throw new Error(`${label} size limit exceeded`);
  return bytes;
}

function validateIdentity(value) {
  const identity = requireExactFields(value, ["kind", "value"], "identity");
  if (identity.kind !== IDENTITY_AID && identity.kind !== IDENTITY_ZID) throw new Error("identity kind invalid");
  const prefix = identity.kind === IDENTITY_AID ? "aid:ed25519:" : "zid:ed25519:";
  if (typeof identity.value !== "string" || !identity.value.startsWith(prefix)) throw new Error("identity value invalid");
  const digest = decodeBase64UrlExact(identity.value.slice(prefix.length), "identity value");
  if (digest.length !== 32) throw new Error("identity value invalid");
  return Object.freeze({ kind: identity.kind, value: identity.value });
}

function privateKeyForPlaintext(keyType, plaintext) {
  if (keyType === KEY_TYPE_SEED) {
    if (plaintext.length !== SEED_BYTES) throw new Error("seed plaintext length invalid");
    return createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, plaintext]), format: "der", type: "pkcs8" });
  }
  if (keyType !== KEY_TYPE_PKCS8) throw new Error("key type invalid");
  if (plaintext.length !== PKCS8_BYTES || !plaintext.subarray(0, PKCS8_PREFIX.length).equals(PKCS8_PREFIX)) throw new Error("PKCS8 plaintext invalid");
  let privateKey;
  try {
    privateKey = createPrivateKey({ key: plaintext, format: "der", type: "pkcs8" });
  } catch {
    throw new Error("PKCS8 plaintext invalid");
  }
  if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("PKCS8 plaintext invalid");
  const exported = privateKey.export({ format: "der", type: "pkcs8" });
  if (!Buffer.from(exported).equals(plaintext)) throw new Error("PKCS8 plaintext invalid");
  return privateKey;
}

function identityForPrivateKey(privateKey, kind) {
  const publicKey = createPublicKey(privateKey);
  return { kind, value: kind === IDENTITY_AID ? computeAid(publicKey) : computeZid(publicKey) };
}

function validatePlaintextIdentity(keyType, plaintext, identity) {
  const privateKey = privateKeyForPlaintext(keyType, plaintext);
  const reconstructed = identityForPrivateKey(privateKey, identity.kind);
  if (reconstructed.value !== identity.value) throw new Error("key identity mismatch");
  return privateKey;
}

function envelopeHeader(envelope) {
  return {
    format: envelope.format,
    key_type: envelope.key_type,
    identity: envelope.identity,
    kdf: envelope.kdf,
    cipher: envelope.cipher,
  };
}

function parseEnvelopeValue(value) {
  const envelope = requireExactFields(value, ["format", "key_type", "identity", "kdf", "cipher", "ciphertext", "tag"], "envelope");
  if (envelope.format !== KEY_ENVELOPE_FORMAT) throw new Error("envelope format invalid");
  if (envelope.key_type !== KEY_TYPE_PKCS8 && envelope.key_type !== KEY_TYPE_SEED) throw new Error("key type invalid");
  const identity = validateIdentity(envelope.identity);
  const kdf = requireExactFields(envelope.kdf, ["name", "salt", "iterations", "derived_key_bytes"], "kdf");
  if (kdf.name !== KDF_NAME) throw new Error("kdf name invalid");
  if (!Number.isSafeInteger(kdf.iterations) || kdf.iterations < MIN_ITERATIONS || kdf.iterations > MAX_ITERATIONS) throw new Error("kdf iterations invalid");
  if (kdf.derived_key_bytes !== DERIVED_KEY_BYTES) throw new Error("kdf derived key bytes invalid");
  requireBinary(kdf.salt, "kdf salt", SALT_BYTES);
  const cipher = requireExactFields(envelope.cipher, ["name", "nonce", "tag_bytes"], "cipher");
  if (cipher.name !== CIPHER_NAME) throw new Error("cipher name invalid");
  if (cipher.tag_bytes !== TAG_BYTES) throw new Error("cipher tag bytes invalid");
  requireBinary(cipher.nonce, "cipher nonce", NONCE_BYTES);
  const expectedCiphertextBytes = envelope.key_type === KEY_TYPE_SEED ? SEED_BYTES : PKCS8_BYTES;
  requireBinary(envelope.ciphertext, "ciphertext", expectedCiphertextBytes);
  requireBinary(envelope.tag, "tag", TAG_BYTES);
  return Object.freeze({
    format: KEY_ENVELOPE_FORMAT,
    key_type: envelope.key_type,
    identity,
    kdf: Object.freeze({ name: KDF_NAME, salt: kdf.salt, iterations: kdf.iterations, derived_key_bytes: DERIVED_KEY_BYTES }),
    cipher: Object.freeze({ name: CIPHER_NAME, nonce: cipher.nonce, tag_bytes: TAG_BYTES }),
    ciphertext: envelope.ciphertext,
    tag: envelope.tag,
  });
}

export function parseKeyEnvelope(bytes) {
  const input = requireBytes(typeof bytes === "string" ? Buffer.from(bytes, "utf8") : bytes, "envelope bytes");
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(input);
  } catch {
    throw new Error("envelope must be valid UTF-8");
  }
  return parseEnvelopeValue(parseDuplicateSafeJson(text));
}

export function sealKeyEnvelope({ keyType, plaintext, identity, passphrase, iterations = DEFAULT_ITERATIONS }) {
  const plaintextBytes = requireBytes(plaintext, "key plaintext");
  const passphraseBytes = requireBytes(passphrase, "passphrase");
  const normalizedIdentity = validateIdentity(identity);
  if (!Number.isSafeInteger(iterations) || iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) throw new Error("kdf iterations invalid");
  validatePlaintextIdentity(keyType, plaintextBytes, normalizedIdentity);
  const salt = randomBytes(SALT_BYTES);
  const nonce = randomBytes(NONCE_BYTES);
  const header = {
    format: KEY_ENVELOPE_FORMAT,
    key_type: keyType,
    identity: normalizedIdentity,
    kdf: { name: KDF_NAME, salt: salt.toString("base64url"), iterations, derived_key_bytes: DERIVED_KEY_BYTES },
    cipher: { name: CIPHER_NAME, nonce: nonce.toString("base64url"), tag_bytes: TAG_BYTES },
  };
  const aad = Buffer.from(canonical(header));
  const derivedKey = pbkdf2Sync(passphraseBytes, salt, iterations, DERIVED_KEY_BYTES, "sha256");
  try {
    const cipher = createCipheriv(CIPHER_NAME, derivedKey, nonce, { authTagLength: TAG_BYTES });
    cipher.setAAD(aad);
    const ciphertext = Buffer.concat([cipher.update(plaintextBytes), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.from(canonical({ ...header, ciphertext: ciphertext.toString("base64url"), tag: tag.toString("base64url") }));
  } finally {
    derivedKey.fill(0);
  }
}

export function openKeyEnvelope({ envelopeBytes, passphrase }) {
  const passphraseBytes = requireBytes(passphrase, "passphrase");
  const envelope = parseKeyEnvelope(envelopeBytes);
  const salt = requireBinary(envelope.kdf.salt, "kdf salt", SALT_BYTES);
  const nonce = requireBinary(envelope.cipher.nonce, "cipher nonce", NONCE_BYTES);
  const ciphertext = requireBinary(envelope.ciphertext, "ciphertext");
  const tag = requireBinary(envelope.tag, "tag", TAG_BYTES);
  const aad = Buffer.from(canonical(envelopeHeader(envelope)));
  const derivedKey = pbkdf2Sync(passphraseBytes, salt, envelope.kdf.iterations, DERIVED_KEY_BYTES, "sha256");
  let plaintext;
  try {
    const decipher = createDecipheriv(CIPHER_NAME, derivedKey, nonce, { authTagLength: TAG_BYTES });
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new Error("envelope authentication failed");
  } finally {
    derivedKey.fill(0);
  }
  let privateKey;
  try {
    privateKey = validatePlaintextIdentity(envelope.key_type, plaintext, envelope.identity);
  } catch (error) {
    plaintext.fill(0);
    throw error;
  }
  return Object.freeze({ keyType: envelope.key_type, identity: envelope.identity, plaintext, privateKey });
}

export async function readRestrictedFile(path, { label = "restricted file", maxBytes = 64 * 1024, testHooks = undefined } = {}) {
  if (typeof label !== "string" || label.length === 0 || label.length > 64 || label.includes("\n") || label.includes("\r")) throw new Error("restricted file label invalid");
  try {
    const opened = await safeOpenOwnedBytes(path, { maxBytes, testHooks });
    return Object.freeze({ bytes: opened.bytes, evidence: opened.evidence });
  } catch (error) {
    throw new Error(`${label}: ${error.message}`);
  }
}
