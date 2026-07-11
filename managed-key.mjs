import {
  createCipheriv,
  createDecipheriv,
  createHash,
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
  descriptorBody,
  publicKeyFromDescriptor,
  rotationProof,
  signObject,
  verifyObject,
  verifyRotationProof,
  verifyZoneDescriptor,
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

export const KEY_GENERATION_FORMAT = "agnet-key-generation/v1";
export const KEY_GENERATION_REBINDING_FORMAT = "agnet-key-generation-rebinding/v1";
export const GENERATION_MIGRATE = "migrate";
export const GENERATION_REWRAP = "rewrap";
export const GENERATION_ROTATE = "rotate";
const ZERO_DIGEST = "0".repeat(64);

function requireHexDigest(value, label) {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) throw new Error(`${label} invalid`);
  return value;
}

function digestCanonical(value) {
  return createHash("sha256").update(canonical(value)).digest("hex");
}

function normalizeGenerationBody(value) {
  const body = requireExactFields(value, ["format", "identity_kind", "identity_value", "generation", "operation", "envelope_sha256", "descriptor_digest", "previous_generation", "previous_record_digest", "activation_state"], "generation body");
  if (body.format !== KEY_GENERATION_FORMAT) throw new Error("generation format invalid");
  validateIdentity({ kind: body.identity_kind, value: body.identity_value });
  if (!Number.isSafeInteger(body.generation) || body.generation < 1) throw new Error("generation invalid");
  if (![GENERATION_MIGRATE, GENERATION_REWRAP, GENERATION_ROTATE].includes(body.operation)) throw new Error("generation operation invalid");
  requireHexDigest(body.envelope_sha256, "generation envelope digest");
  requireHexDigest(body.descriptor_digest, "generation descriptor digest");
  if (!Number.isSafeInteger(body.previous_generation) || body.previous_generation < 0) throw new Error("previous generation invalid");
  requireHexDigest(body.previous_record_digest, "previous record digest");
  if (body.activation_state !== "active") throw new Error("generation activation state invalid");
  return Object.freeze({ ...body });
}

function normalizeRotationProof(value) {
  const proof = requireExactFields(value, ["previous_aid", "next_aid", "previous_signature", "next_signature"], "agent rotation proof");
  validateIdentity({ kind: IDENTITY_AID, value: proof.previous_aid });
  validateIdentity({ kind: IDENTITY_AID, value: proof.next_aid });
  decodeBase64UrlExact(proof.previous_signature, "rotation previous signature");
  decodeBase64UrlExact(proof.next_signature, "rotation next signature");
  return Object.freeze({ ...proof });
}

function normalizeGenerationRebinding(value) {
  const proof = requireExactFields(value, ["format", "zone", "alias", "previous_aid", "next_aid", "generation", "record_digest", "zone_signature"], "generation rebinding");
  if (proof.format !== KEY_GENERATION_REBINDING_FORMAT) throw new Error("generation rebinding format invalid");
  validateIdentity({ kind: IDENTITY_ZID, value: proof.zone });
  if (typeof proof.alias !== "string" || proof.alias === "" || proof.alias.includes("\0")) throw new Error("generation rebinding alias invalid");
  validateIdentity({ kind: IDENTITY_AID, value: proof.previous_aid });
  validateIdentity({ kind: IDENTITY_AID, value: proof.next_aid });
  if (!Number.isSafeInteger(proof.generation) || proof.generation < 1) throw new Error("generation rebinding generation invalid");
  requireHexDigest(proof.record_digest, "generation rebinding record digest");
  decodeBase64UrlExact(proof.zone_signature, "generation rebinding zone signature");
  return Object.freeze({ ...proof });
}

function normalizeGenerationRecordObject(value) {
  const raw = requireObject(value, "generation record");
  const body = normalizeGenerationBody(raw.body);
  requireHexDigest(raw.record_digest, "record digest");
  if (body.operation === GENERATION_ROTATE) {
    requireExactFields(raw, ["body", "record_digest", "previous_descriptor", "next_descriptor", "agent_rotation_proof", "generation_rebinding"], "generation record");
    const previousDescriptor = requireObject(raw.previous_descriptor, "previous descriptor");
    const nextDescriptor = requireObject(raw.next_descriptor, "next descriptor");
    return Object.freeze({
      body,
      record_digest: raw.record_digest,
      previous_descriptor: structuredClone(previousDescriptor),
      next_descriptor: structuredClone(nextDescriptor),
      agent_rotation_proof: normalizeRotationProof(raw.agent_rotation_proof),
      generation_rebinding: normalizeGenerationRebinding(raw.generation_rebinding),
    });
  }
  requireExactFields(raw, ["body", "record_digest", "identity_signature"], "generation record");
  decodeBase64UrlExact(raw.identity_signature, "generation identity signature");
  return Object.freeze({ body, record_digest: raw.record_digest, identity_signature: raw.identity_signature });
}

export function parseGenerationRecord(bytes) {
  const input = requireBytes(typeof bytes === "string" ? Buffer.from(bytes, "utf8") : bytes, "generation record bytes");
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(input);
  } catch {
    throw new Error("generation record must be valid UTF-8");
  }
  return normalizeGenerationRecordObject(parseDuplicateSafeJson(text));
}

function normalizedGenerationRecord(record) {
  if (record instanceof Uint8Array || typeof record === "string") return parseGenerationRecord(record);
  return parseGenerationRecord(Buffer.from(canonical(record)));
}

function verifyIdentityDescriptor(descriptor, identity) {
  const value = requireObject(descriptor, "generation descriptor");
  if (identity.kind === IDENTITY_AID) {
    const publicKey = publicKeyFromDescriptor(value);
    if (computeAid(publicKey) !== identity.value || value.aid !== identity.value) throw new Error("generation descriptor identity mismatch");
    if (!verifyObject(publicKey, descriptorBody(value), value.descriptor_signature)) throw new Error("generation descriptor signature invalid");
    return publicKey;
  }
  const verified = verifyZoneDescriptor(value);
  if (value.zid !== identity.value) throw new Error("generation descriptor identity mismatch");
  return verified.publicKey;
}

export function generationBody({ identity, generation, operation, envelopeBytes, descriptor, previousRecord = undefined, activationState = "active" }) {
  const normalizedIdentity = validateIdentity(identity);
  if (!Number.isSafeInteger(generation) || generation < 1) throw new Error("generation invalid");
  if (![GENERATION_MIGRATE, GENERATION_REWRAP, GENERATION_ROTATE].includes(operation)) throw new Error("generation operation invalid");
  const envelopeInput = requireBytes(envelopeBytes, "generation envelope bytes");
  const envelope = parseKeyEnvelope(envelopeInput);
  if (envelope.identity.kind !== normalizedIdentity.kind || envelope.identity.value !== normalizedIdentity.value) throw new Error("envelope identity mismatch");
  verifyIdentityDescriptor(descriptor, normalizedIdentity);
  const previous = previousRecord === undefined ? undefined : normalizedGenerationRecord(previousRecord);
  if (generation === 1) {
    if (operation !== GENERATION_MIGRATE || previous !== undefined) throw new Error("first generation must migrate");
  } else {
    if (operation === GENERATION_MIGRATE || previous === undefined) throw new Error("generation predecessor missing");
    if (previous.body.generation + 1 !== generation) throw new Error("generation must be contiguous");
  }
  return normalizeGenerationBody({
    format: KEY_GENERATION_FORMAT,
    identity_kind: normalizedIdentity.kind,
    identity_value: normalizedIdentity.value,
    generation,
    operation,
    envelope_sha256: createHash("sha256").update(envelopeInput).digest("hex"),
    descriptor_digest: digestCanonical(descriptor),
    previous_generation: previous?.body.generation ?? 0,
    previous_record_digest: previous?.record_digest ?? ZERO_DIGEST,
    activation_state: activationState,
  });
}

export function recordDigest(body) {
  return digestCanonical(normalizeGenerationBody(body));
}

function generationSignaturePayload(body, digest) {
  return { body, record_digest: digest };
}

export function createSignedGenerationRecord({ body, privateKey }) {
  const normalizedBody = normalizeGenerationBody(body);
  if (normalizedBody.operation === GENERATION_ROTATE) throw new Error("rotate generation requires rotation authorization");
  const digest = recordDigest(normalizedBody);
  return Object.freeze({ body: normalizedBody, record_digest: digest, identity_signature: signObject(privateKey, generationSignaturePayload(normalizedBody, digest)) });
}

function generationRebindingBody({ zoneDescriptor, previousDescriptor, nextDescriptor, generation, digest }) {
  if (previousDescriptor.alias !== nextDescriptor.alias || typeof previousDescriptor.alias !== "string" || previousDescriptor.alias === "") throw new Error("generation rebinding requires matching aliases");
  return {
    format: KEY_GENERATION_REBINDING_FORMAT,
    zone: zoneDescriptor.zid,
    alias: previousDescriptor.alias,
    previous_aid: previousDescriptor.aid,
    next_aid: nextDescriptor.aid,
    generation,
    record_digest: digest,
  };
}

export function generationRebindingProof({ zone, previousDescriptor, nextDescriptor, generation, recordDigest: digest }) {
  const body = generationRebindingBody({ zoneDescriptor: zone.descriptor, previousDescriptor, nextDescriptor, generation, digest });
  return Object.freeze({ ...body, zone_signature: signObject(zone.privateKey, body) });
}

export function createRotationGenerationRecord({ body, previousAgent, nextAgent, zone }) {
  const normalizedBody = normalizeGenerationBody(body);
  if (normalizedBody.operation !== GENERATION_ROTATE || normalizedBody.identity_kind !== IDENTITY_AID || normalizedBody.identity_value !== nextAgent.aid) throw new Error("rotate generation identity mismatch");
  const digest = recordDigest(normalizedBody);
  return Object.freeze({
    body: normalizedBody,
    record_digest: digest,
    previous_descriptor: structuredClone(previousAgent.descriptor),
    next_descriptor: structuredClone(nextAgent.descriptor),
    agent_rotation_proof: rotationProof(previousAgent, nextAgent),
    generation_rebinding: generationRebindingProof({ zone, previousDescriptor: previousAgent.descriptor, nextDescriptor: nextAgent.descriptor, generation: normalizedBody.generation, recordDigest: digest }),
  });
}

export function verifyGenerationRebinding(proof, { zoneDescriptor, previousDescriptor, nextDescriptor, generation, recordDigest: digest }) {
  try {
    const normalized = normalizeGenerationRebinding(proof);
    const { publicKey } = verifyZoneDescriptor(zoneDescriptor);
    const body = generationRebindingBody({ zoneDescriptor, previousDescriptor, nextDescriptor, generation, digest });
    return Object.keys(body).every((key) => normalized[key] === body[key]) && verifyObject(publicKey, body, normalized.zone_signature);
  } catch {
    return false;
  }
}

export function verifyGenerationRecord(record, context) {
  const normalized = normalizedGenerationRecord(record);
  if (recordDigest(normalized.body) !== normalized.record_digest) throw new Error("record digest mismatch");
  const envelopeBytes = requireBytes(context?.envelopeBytes, "generation envelope bytes");
  if (createHash("sha256").update(envelopeBytes).digest("hex") !== normalized.body.envelope_sha256) throw new Error("generation envelope digest mismatch");
  const envelope = parseKeyEnvelope(envelopeBytes);
  if (envelope.identity.kind !== normalized.body.identity_kind || envelope.identity.value !== normalized.body.identity_value) throw new Error("envelope identity mismatch");
  const descriptor = requireObject(context?.descriptor, "generation descriptor");
  const identity = { kind: normalized.body.identity_kind, value: normalized.body.identity_value };
  const descriptorKey = verifyIdentityDescriptor(descriptor, identity);
  if (digestCanonical(descriptor) !== normalized.body.descriptor_digest) throw new Error("descriptor digest mismatch");
  const previous = context?.previousRecord === undefined ? undefined : normalizedGenerationRecord(context.previousRecord);
  if (normalized.body.generation === 1) {
    if (normalized.body.operation !== GENERATION_MIGRATE || normalized.body.previous_generation !== 0 || normalized.body.previous_record_digest !== ZERO_DIGEST || previous !== undefined) throw new Error("first generation predecessor invalid");
  } else {
    if (previous === undefined) throw new Error("generation predecessor missing");
    if (recordDigest(previous.body) !== previous.record_digest) throw new Error("previous record digest mismatch");
    if (normalized.body.operation === GENERATION_MIGRATE) throw new Error("migrate operation only valid for first generation");
    if (normalized.body.generation !== previous.body.generation + 1 || normalized.body.previous_generation !== previous.body.generation) throw new Error("generation must be contiguous");
    if (normalized.body.previous_record_digest !== previous.record_digest) throw new Error("previous record digest mismatch");
    if (normalized.body.operation === GENERATION_REWRAP && (normalized.body.identity_kind !== previous.body.identity_kind || normalized.body.identity_value !== previous.body.identity_value)) throw new Error("rewrap identity drift");
  }
  if (context?.activePointer !== undefined && (context.activePointer.generation !== normalized.body.generation || context.activePointer.record_digest !== normalized.record_digest)) throw new Error("active pointer mismatch");
  if (normalized.body.operation === GENERATION_ROTATE) {
    const previousDescriptor = requireObject(context?.previousDescriptor, "previous descriptor");
    if (normalized.body.identity_value === previous.body.identity_value) throw new Error("rotation must change agent identity");
    const zoneDescriptor = requireObject(context?.zoneDescriptor, "zone descriptor");
    if (canonical(normalized.previous_descriptor) !== canonical(previousDescriptor) || canonical(normalized.next_descriptor) !== canonical(descriptor)) throw new Error("rotation descriptor substitution");
    if (previous.body.identity_kind !== IDENTITY_AID || previous.body.identity_value !== previousDescriptor.aid) throw new Error("rotation previous identity mismatch");
    verifyIdentityDescriptor(previousDescriptor, { kind: IDENTITY_AID, value: previousDescriptor.aid });
    if (digestCanonical(previousDescriptor) !== previous.body.descriptor_digest) throw new Error("previous descriptor digest mismatch");
    if (previousDescriptor.alias !== descriptor.alias) throw new Error("rotation alias mismatch");
    if (!verifyRotationProof(normalized.agent_rotation_proof, previousDescriptor, descriptor)) throw new Error("agent rotation proof invalid");
    if (!verifyGenerationRebinding(normalized.generation_rebinding, { zoneDescriptor, previousDescriptor, nextDescriptor: descriptor, generation: normalized.body.generation, recordDigest: normalized.record_digest })) throw new Error("generation rebinding invalid");
  } else if (!verifyObject(descriptorKey, generationSignaturePayload(normalized.body, normalized.record_digest), normalized.identity_signature)) {
    throw new Error("generation identity signature invalid");
  }
  return normalized;
}

export function verifyGenerationChain(records, envelopes, { descriptors, previousDescriptors = [], zoneDescriptors = [], activePointer = undefined }) {
  if (!Array.isArray(records) || !Array.isArray(envelopes) || !Array.isArray(descriptors) || records.length === 0 || records.length !== envelopes.length || records.length !== descriptors.length) throw new Error("generation chain inputs invalid");
  const verified = [];
  const digests = new Set();
  for (let index = 0; index < records.length; index += 1) {
    const record = verifyGenerationRecord(records[index], {
      envelopeBytes: envelopes[index],
      descriptor: descriptors[index],
      previousRecord: index === 0 ? undefined : verified[index - 1],
      previousDescriptor: previousDescriptors[index],
      zoneDescriptor: zoneDescriptors[index],
      activePointer: index === records.length - 1 ? activePointer : undefined,
    });
    if (digests.has(record.record_digest)) throw new Error("generation replay detected");
    digests.add(record.record_digest);
    verified.push(record);
  }
  return verified;
}
