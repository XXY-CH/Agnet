import { appendFile, chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from "node:crypto";

const AGENT_DOMAIN = Buffer.from("asp-agent-id-v1\0");
const ZONE_DOMAIN = Buffer.from("asp-zone-id-v1\0");
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const ED25519_MULTIKEY_PREFIX = Buffer.from([0xed, 0x01]);
const BASE58BTC = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const TASK_ID_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;

export function b64url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

export function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`)
    .join(",")}}`;
}

export function publicKeyDer(publicKey) {
  return publicKey.export({ type: "spki", format: "der" });
}

export function privateKeyDer(privateKey) {
  return privateKey.export({ type: "pkcs8", format: "der" });
}

export function computeAid(publicKey) {
  const digest = createHash("sha256").update(AGENT_DOMAIN).update(publicKeyDer(publicKey)).digest();
  return `aid:ed25519:${b64url(digest)}`;
}

function base58btc(bytes) {
  let n = 0n;
  for (const byte of bytes) n = (n << 8n) + BigInt(byte);
  let out = "";
  while (n > 0n) {
    out = BASE58BTC[Number(n % 58n)] + out;
    n /= 58n;
  }
  for (const byte of bytes) {
    if (byte !== 0) break;
    out = `1${out}`;
  }
  return out || "1";
}

function base58btcDecode(value) {
  let n = 0n;
  for (const char of value) {
    const index = BASE58BTC.indexOf(char);
    if (index < 0) throw new Error("invalid base58btc character");
    n = n * 58n + BigInt(index);
  }
  let hex = n.toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  const body = n === 0n ? Buffer.alloc(0) : Buffer.from(hex, "hex");
  let zeros = 0;
  for (const char of value) {
    if (char !== "1") break;
    zeros++;
  }
  return Buffer.concat([Buffer.alloc(zeros), body]);
}

export function didKeyFromPublicKey(publicKey) {
  return didKeyFromPublicKeySPKI(b64url(publicKeyDer(publicKey)));
}

export function didKeyFromPublicKeySPKI(publicKeySPKI) {
  if (typeof publicKeySPKI !== "string" || publicKeySPKI === "") throw new Error("expected ed25519 public_key_spki");
  const der = Buffer.from(publicKeySPKI, "base64url");
  if (der.length !== ED25519_SPKI_PREFIX.length + 32 || !der.subarray(0, ED25519_SPKI_PREFIX.length).equals(ED25519_SPKI_PREFIX)) {
    throw new Error("expected ed25519 public_key_spki");
  }
  return `did:key:z${base58btc(Buffer.concat([ED25519_MULTIKEY_PREFIX, der.subarray(ED25519_SPKI_PREFIX.length)]))}`;
}

export function didKeyFromDescriptor(descriptor) {
  return didKeyFromPublicKeySPKI(descriptor?.public_key_spki);
}

export function publicKeySPKIFromDidKey(didKey) {
  if (typeof didKey !== "string" || !didKey.startsWith("did:key:z")) throw new Error("expected did:key z-base58btc value");
  const bytes = base58btcDecode(didKey.slice("did:key:z".length));
  if (bytes.length !== 34 || !bytes.subarray(0, 2).equals(ED25519_MULTIKEY_PREFIX)) {
    throw new Error("expected ed25519 did:key");
  }
  return b64url(Buffer.concat([ED25519_SPKI_PREFIX, bytes.subarray(2)]));
}

export function computeZid(publicKey) {
  const digest = createHash("sha256").update(ZONE_DOMAIN).update(publicKeyDer(publicKey)).digest();
  return `zid:ed25519:${b64url(digest)}`;
}

export function publicKeyFromDescriptor(descriptor) {
  if (typeof descriptor?.public_key_spki !== "string" || descriptor.public_key_spki === "") throw new Error("descriptor public key missing");
  return createPublicKey({
    key: Buffer.from(descriptor.public_key_spki, "base64url"),
    type: "spki",
    format: "der",
  });
}

export function signObject(privateKey, payload) {
  return b64url(sign(null, Buffer.from(canonical(payload)), privateKey));
}

export function verifyObject(publicKey, payload, signature) {
  if (typeof signature !== "string" || signature === "") return false;
  return verify(null, Buffer.from(canonical(payload)), publicKey, Buffer.from(signature, "base64url"));
}

export function descriptorBody(descriptor) {
  if (!descriptor || typeof descriptor !== "object" || Array.isArray(descriptor)) throw new Error("descriptor missing");
  const { descriptor_signature, ...body } = descriptor;
  return body;
}

export function zoneDescriptorBody(descriptor) {
  if (!descriptor || typeof descriptor !== "object" || Array.isArray(descriptor)) throw new Error("zone descriptor missing");
  const { zone_signature, ...body } = descriptor;
  return body;
}

export function createAgent(alias, policy = {}, transports = ["asp+local://demo"], capabilities = []) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return agentFromPrivateKey(alias, privateKey, policy, transports, capabilities);
}

export function agentFromPrivateKey(alias, privateKey, policy = {}, transports = ["asp+local://demo"], capabilities = []) {
  const publicKey = createPublicKey(privateKey);
  const aid = computeAid(publicKey);
  const descriptor = {
    alias,
    aid,
    did_key: didKeyFromPublicKey(publicKey),
    public_key_spki: b64url(publicKeyDer(publicKey)),
    transports,
    capabilities,
    policy,
  };
  return {
    alias,
    aid,
    descriptor: { ...descriptor, descriptor_signature: signObject(privateKey, descriptor) },
    privateKey,
    publicKey,
  };
}

export function createZone(name) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return zoneFromPrivateKey(name, privateKey);
}

export function zoneFromPrivateKey(name, privateKey) {
  const publicKey = createPublicKey(privateKey);
  const zid = computeZid(publicKey);
  const descriptor = {
    name,
    zid,
    public_key_spki: b64url(publicKeyDer(publicKey)),
  };
  return {
    name,
    zid,
    descriptor: { ...descriptor, zone_signature: signObject(privateKey, descriptor) },
    privateKey,
    publicKey,
  };
}

export function verifyZoneDescriptor(zoneDescriptor) {
  if (!zoneDescriptor || typeof zoneDescriptor !== "object" || Array.isArray(zoneDescriptor)) {
    throw new Error("zone descriptor missing");
  }
  const zonePublicKey = publicKeyFromDescriptor({ public_key_spki: zoneDescriptor.public_key_spki });
  const zid = computeZid(zonePublicKey);
  if (zid !== zoneDescriptor.zid) throw new Error(`zone id mismatch: ${zoneDescriptor.name ?? zoneDescriptor.zid}`);
  if (!zoneDescriptor.zone_signature) throw new Error(`zone signature missing: ${zoneDescriptor.zid}`);
  if (!verifyObject(zonePublicKey, zoneDescriptorBody(zoneDescriptor), zoneDescriptor.zone_signature)) {
    throw new Error(`zone signature verification failed: ${zoneDescriptor.zid}`);
  }
  return { descriptor: zoneDescriptor, publicKey: zonePublicKey };
}

export async function writeTrustedZones(file, zones) {
  await writeJson(file, { zones: zones.map((zone) => zone.descriptor ?? zone) });
}

export async function loadTrustedZones(file) {
  const trustStore = JSON.parse(await readFile(file, "utf8"));
  const zones = Array.isArray(trustStore) ? trustStore : trustStore.zones;
  if (!Array.isArray(zones)) throw new Error("trusted zone list missing");
  return new Map(
    zones.map((zoneDescriptor) => {
      verifyZoneDescriptor(zoneDescriptor);
      return [zoneDescriptor.zid, zoneDescriptor];
    }),
  );
}

export async function loadOrCreatePrivateKey(file) {
  try {
    return createPrivateKey({ key: await readFile(file), format: "der", type: "pkcs8" });
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  const { privateKey } = generateKeyPairSync("ed25519");
  await mkdir(dirname(file), { recursive: true });
  await writeFile(file, privateKeyDer(privateKey), { mode: 0o600 });
  await chmod(file, 0o600);
  return privateKey;
}

export async function loadOrCreateAgent(alias, keyFile, policy = {}, transports = ["asp+local://demo"], capabilities = []) {
  return agentFromPrivateKey(alias, await loadOrCreatePrivateKey(keyFile), policy, transports, capabilities);
}

export async function loadOrCreateZone(name, keyFile) {
  return zoneFromPrivateKey(name, await loadOrCreatePrivateKey(keyFile));
}

export function zoneBinding(zone, descriptor) {
  const body = { zone: zone.zid, alias: descriptor.alias, aid: descriptor.aid };
  return { ...body, signature: signObject(zone.privateKey, body) };
}

export function zoneRevocation(zone, subject, reason) {
  const body = { zone: zone.zid, subject, reason };
  return { ...body, signature: signObject(zone.privateKey, body) };
}

export async function writeRegistry(file, zone, descriptors, revocations = []) {
  await writeJson(file, {
    zone: zone.descriptor,
    revocations,
    agents: descriptors.map((descriptor) => ({
      descriptor,
      zone_binding: zoneBinding(zone, descriptor),
    })),
  });
}

export async function writeJson(file, value) {
  await mkdir(dirname(file), { recursive: true });
  await writeFile(file, `${JSON.stringify(value, null, 2)}\n`);
}

export const AUDIT_ZERO_HASH = "0".repeat(64);

export function auditEntry(prevHash, record) {
  const body = { prev_hash: prevHash, record };
  const hash = createHash("sha256").update(canonical(body)).digest("hex");
  return { ...body, hash };
}

export function verifyAuditEntries(entries) {
  let prevHash = AUDIT_ZERO_HASH;
  for (const entry of entries) {
    const expected = auditEntry(prevHash, entry.record);
    if (entry.prev_hash !== prevHash || entry.hash !== expected.hash) return false;
    prevHash = entry.hash;
  }
  return true;
}

let auditLock = Promise.resolve();

export async function appendAudit(record) {
  auditLock = auditLock.then(() => appendAuditUnlocked(record), () => appendAuditUnlocked(record));
  return auditLock;
}

async function appendAuditUnlocked(record) {
  await mkdir("state", { recursive: true });
  let prevHash = AUDIT_ZERO_HASH;
  try {
    prevHash = (await readFile("state/audit.head", "utf8")).trim() || AUDIT_ZERO_HASH;
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  const entry = auditEntry(prevHash, record);
  await appendFile("state/audit.log", `${JSON.stringify(entry)}\n`);
  await writeFile("state/audit.head", `${entry.hash}\n`);
  return entry;
}

export async function loadRegistry(file) {
  const registry = JSON.parse(await readFile(file, "utf8"));
  if (Array.isArray(registry)) {
    return new Map(registry.map((descriptor) => {
      if (!descriptor || typeof descriptor !== "object" || Array.isArray(descriptor)) throw new Error("registry descriptor missing");
      return [descriptor.alias, { descriptor }];
    }));
  }
  if (!Array.isArray(registry.agents)) throw new Error("registry agents missing");
  return new Map(
    registry.agents.map((entry) => {
      if (!entry || typeof entry !== "object" || Array.isArray(entry)) throw new Error("registry entry missing");
      if (!entry.descriptor || typeof entry.descriptor !== "object" || Array.isArray(entry.descriptor)) throw new Error("registry descriptor missing");
      return [
        entry.descriptor.alias,
        {
          descriptor: entry.descriptor,
          zone: registry.zone,
          zone_binding: entry.zone_binding,
          revocations: registry.revocations ?? [],
        },
      ];
    }),
  );
}

export function resolveAgent(registry, alias) {
  if (!registry || typeof registry.get !== "function") throw new Error("registry missing");
  const entry = registry.get(alias);
  if (!entry) throw new Error(`agent alias not found: ${alias}`);
  const descriptor = entry.descriptor ?? entry;
  const publicKey = publicKeyFromDescriptor(descriptor);
  const computedAid = computeAid(publicKey);
  if (computedAid !== descriptor.aid) throw new Error(`descriptor aid mismatch for ${alias}`);
  if (descriptor.did_key && descriptor.did_key !== didKeyFromDescriptor(descriptor)) {
    throw new Error(`descriptor did:key mismatch for ${alias}`);
  }
  if (!descriptor.descriptor_signature) throw new Error(`descriptor signature missing for ${alias}`);
  if (!verifyObject(publicKey, descriptorBody(descriptor), descriptor.descriptor_signature)) {
    throw new Error(`descriptor signature verification failed for ${alias}`);
  }
  if (entry.zone || entry.zone_binding) verifyZoneBinding(entry, descriptor, alias);
  if (entry.revocations?.length) verifyNotRevoked(entry, descriptor, alias);
  return { descriptor, publicKey, zone: entry.zone, zoneBinding: entry.zone_binding };
}

function assertTrustedZones(trustedZones) {
  if (!trustedZones || typeof trustedZones.get !== "function" || typeof trustedZones.has !== "function") throw new Error("trusted zones missing");
}

export function verifyFederatedTaskOpen(frame, trustedZones, workerDescriptor) {
  if (!frame || typeof frame !== "object" || Array.isArray(frame) || frame.type !== "FED_TASK_OPEN") throw new Error("expected FED_TASK_OPEN frame");
  if (!frame.origin_zone || typeof frame.origin_zone !== "object" || Array.isArray(frame.origin_zone)) throw new Error("task open origin zone missing");
  if (!frame.requester || typeof frame.requester !== "object" || Array.isArray(frame.requester)) throw new Error("task open requester missing");
  if (!frame.task || typeof frame.task !== "object" || Array.isArray(frame.task)) throw new Error("task open task missing");
  const originZone = verifyZoneDescriptor(frame.origin_zone).descriptor;
  assertTrustedZones(trustedZones);
  const trusted = trustedZones.get(originZone.zid);
  if (!trusted || trusted.public_key_spki !== originZone.public_key_spki) {
    throw new Error(`untrusted zone: ${originZone.zid}`);
  }
  if (!workerDescriptor || typeof workerDescriptor !== "object" || Array.isArray(workerDescriptor)) throw new Error("task open worker missing");
  let worker;
  try {
    worker = resolveAgent(new Map([[workerDescriptor.alias, workerDescriptor]]), workerDescriptor.alias).descriptor;
  } catch (error) {
    throw new Error(`task open worker invalid: ${error.message}`);
  }
  if (!frame.requester_zone_binding) throw new Error("requester zone binding missing");
  const requester = resolveAgent(new Map([[frame.requester.alias, { descriptor: frame.requester, zone: frame.origin_zone, zone_binding: frame.requester_zone_binding }]]), frame.requester.alias);
  const { signature, ...task } = frame.task;
  validateTaskId(task.task_id);
  if (task.from !== frame.requester.aid) throw new Error("task sender does not match requester descriptor");
  if (task.to !== worker.alias) throw new Error(`task target does not match worker alias: ${task.to}`);
  if (typeof signature !== "string" || signature === "") throw new Error("task signature missing");
  if (!verifyObject(requester.publicKey, task, signature)) {
    throw new Error("task signature verification failed");
  }
  enforcePolicy(worker, task);
  return { originZone, requester: frame.requester, worker, task };
}

export function validateTaskId(taskId) {
  if (typeof taskId !== "string" || !TASK_ID_PATTERN.test(taskId)) throw new Error("task_id invalid");
}

export function verifyFederatedReceipt(frame, trustedZones, signedTask) {
  if (!frame || typeof frame !== "object" || Array.isArray(frame) || frame.type !== "FED_RECEIPT") throw new Error("expected FED_RECEIPT frame");
  if (!frame.zone || typeof frame.zone !== "object" || Array.isArray(frame.zone)) throw new Error("receipt zone missing");
  if (!frame.worker || typeof frame.worker !== "object" || Array.isArray(frame.worker)) throw new Error("receipt worker missing");
  if (!frame.receipt || typeof frame.receipt !== "object" || Array.isArray(frame.receipt)) throw new Error("receipt body missing");
  const zone = verifyZoneDescriptor(frame.zone).descriptor;
  assertTrustedZones(trustedZones);
  const trusted = trustedZones.get(zone.zid);
  if (!trusted || trusted.public_key_spki !== zone.public_key_spki) {
    throw new Error(`untrusted zone: ${zone.zid}`);
  }
  let resolved;
  try {
    resolved = resolveAgent(
      new Map([[frame.worker.alias, { descriptor: frame.worker, zone: frame.zone, zone_binding: frame.zone_binding }]]),
      frame.worker.alias,
    );
  } catch (error) {
    throw new Error(`receipt worker invalid: ${error.message}`);
  }
  const { signature, ...receipt } = frame.receipt;
  if (receipt.executing_zone !== zone.zid) throw new Error("receipt executing_zone mismatch");
  if (!trustedZones.has(receipt.origin_zone)) throw new Error(`untrusted receipt origin zone: ${receipt.origin_zone}`);
  if (typeof receipt.task_digest !== "string" || !/^[0-9a-f]{64}$/.test(receipt.task_digest)) throw new Error("receipt task_digest missing");
  if (signedTask !== undefined && createHash("sha256").update(canonical(signedTask)).digest("hex") !== receipt.task_digest) throw new Error("receipt task_digest mismatch");
  if (receipt.to !== frame.worker.aid) throw new Error("receipt worker mismatch");
  if (typeof signature !== "string" || signature === "") throw new Error("receipt signature missing");
  if (!verifyObject(resolved.publicKey, receipt, signature)) {
    throw new Error("remote receipt signature verification failed");
  }
  verifyReceiptArtifactManifests(receipt);
  return { zone, worker: resolved.descriptor, receipt, signedReceipt: frame.receipt };
}

export function verifySwarmClose(frame, trustedZones) {
  if (!frame || typeof frame !== "object" || Array.isArray(frame) || frame.type !== "FED_SWARM_CLOSE") throw new Error("expected FED_SWARM_CLOSE frame");
  if (!frame.zone || typeof frame.zone !== "object" || Array.isArray(frame.zone)) throw new Error("swarm close zone missing");
  const zone = verifyZoneDescriptor(frame.zone).descriptor;
  assertTrustedZones(trustedZones);
  const trusted = trustedZones.get(zone.zid);
  if (!trusted || trusted.public_key_spki !== zone.public_key_spki) {
    throw new Error(`untrusted zone: ${zone.zid}`);
  }
  if (!frame.close || typeof frame.close !== "object" || Array.isArray(frame.close)) throw new Error("swarm close proof missing");
  const { close_signature, ...closeBody } = frame.close;
  if (typeof close_signature !== "string" || close_signature === "") throw new Error("swarm close signature missing");
  if (typeof closeBody.swarm_id !== "string" || closeBody.swarm_id === "") throw new Error("swarm close identity missing");
  if (closeBody.swarm_id.includes("\0")) throw new Error("swarm close identity contains NUL");
  if (frame.swarm_id !== closeBody.swarm_id) throw new Error("swarm close frame id mismatch");
  if (!Array.isArray(closeBody.step_receipts) || closeBody.step_receipts.length === 0) {
    throw new Error("swarm close step receipts missing");
  }
  const stepIds = new Set();
  for (const step of closeBody.step_receipts) {
    if (!step || typeof step !== "object" || Array.isArray(step)) throw new Error("swarm close step receipt missing");
    if (typeof step.step_id !== "string" || step.step_id === "") throw new Error("swarm close step identity missing");
    if (step.step_id.includes("\0")) throw new Error("swarm close identity contains NUL");
    if (stepIds.has(step.step_id)) throw new Error("swarm close duplicate step receipt");
    stepIds.add(step.step_id);
    if (typeof step.task_id !== "string" || step.task_id === "") throw new Error("swarm close task missing");
    if (!TASK_ID_PATTERN.test(step.task_id)) throw new Error("swarm close task invalid");
    if (typeof step.receipt_digest !== "string" || !/^[0-9a-f]{64}$/.test(step.receipt_digest)) {
      throw new Error("swarm close receipt digest invalid");
    }
  }
  if (!verifyObject(publicKeyFromDescriptor(zone), closeBody, close_signature)) {
    throw new Error("swarm close signature verification failed");
  }
  return { zone, close: frame.close, closeDigest: createHash("sha256").update(canonical(closeBody)).digest("hex") };
}

export function verifyReceiptArtifactManifests(receipt) {
  if (!receipt || typeof receipt !== "object" || Array.isArray(receipt)) throw new Error("receipt artifact manifest count mismatch");
  if (receipt.artifact_manifests === undefined) return;
  if (!Array.isArray(receipt.artifact_refs) || !Array.isArray(receipt.artifact_manifests)) {
    throw new Error("receipt artifact manifest count mismatch");
  }
  if (receipt.artifact_refs.length !== receipt.artifact_manifests.length) {
    throw new Error("receipt artifact manifest count mismatch");
  }
  for (const [index, manifest] of receipt.artifact_manifests.entries()) {
    if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) throw new Error("artifact manifest missing");
    if (manifest.uri !== receipt.artifact_refs[index]) throw new Error("artifact manifest uri mismatch");
    for (const field of ["sha256", "media_type", "manifest_hash"]) {
      if (typeof manifest[field] !== "string" || manifest[field] === "") throw new Error(`artifact manifest ${field} missing`);
    }
    if (manifest.afp !== undefined && manifest.afp !== `afp:sha256:${manifest.sha256}`) {
      throw new Error("artifact manifest afp mismatch");
    }
    if (typeof manifest.size !== "number") throw new Error("artifact manifest size missing");
    const { manifest_hash, ...body } = manifest;
    if (manifest_hash !== createHash("sha256").update(canonical(body)).digest("hex")) {
      throw new Error("artifact manifest hash mismatch");
    }
  }
}

export function verifyZoneBinding(entry, descriptor, alias) {
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) throw new Error("zone binding context missing");
  if (!descriptor || typeof descriptor !== "object" || Array.isArray(descriptor)) throw new Error("zone binding descriptor missing");
  if (!entry.zone) throw new Error(`zone descriptor missing for ${alias}`);
  if (!entry.zone_binding) throw new Error(`zone binding missing for ${alias}`);
  const { publicKey: zonePublicKey } = verifyZoneDescriptor(entry.zone);
  const expectedBinding = { zone: entry.zone.zid, alias: descriptor.alias, aid: descriptor.aid };
  if (
    entry.zone_binding.zone !== expectedBinding.zone ||
    entry.zone_binding.alias !== expectedBinding.alias ||
    entry.zone_binding.aid !== expectedBinding.aid
  ) {
    throw new Error(`zone binding mismatch for ${alias}`);
  }
  if (!verifyObject(zonePublicKey, expectedBinding, entry.zone_binding.signature)) {
    throw new Error(`zone binding signature verification failed for ${alias}`);
  }
}

export function verifyZoneRevocation(revocation, zoneDescriptor) {
  if (!revocation || typeof revocation !== "object" || Array.isArray(revocation)) return false;
  let zonePublicKey;
  try {
    ({ publicKey: zonePublicKey } = verifyZoneDescriptor(zoneDescriptor));
  } catch {
    return false;
  }
  const body = { zone: revocation.zone, subject: revocation.subject, reason: revocation.reason };
  return revocation.zone === zoneDescriptor.zid && verifyObject(zonePublicKey, body, revocation.signature);
}

export function verifyNotRevoked(entry, descriptor, alias) {
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) throw new Error("zone revocation context missing");
  if (!descriptor || typeof descriptor !== "object" || Array.isArray(descriptor)) throw new Error("zone revocation descriptor missing");
  if (!Array.isArray(entry.revocations)) throw new Error("zone revocations missing");
  for (const revocation of entry.revocations) {
    if (!verifyZoneRevocation(revocation, entry.zone)) {
      throw new Error(`zone revocation signature verification failed for ${alias}`);
    }
    if (revocation.subject === descriptor.aid || revocation.subject === alias) {
      throw new Error(`agent revoked: ${revocation.subject}`);
    }
  }
}

export function aliasRebindingBody(zoneDescriptor, previousDescriptor, nextDescriptor) {
  if (previousDescriptor.alias !== nextDescriptor.alias) {
    throw new Error("alias rebinding requires matching aliases");
  }
  return {
    zone: zoneDescriptor.zid,
    alias: previousDescriptor.alias,
    previous_aid: previousDescriptor.aid,
    next_aid: nextDescriptor.aid,
  };
}

export function aliasRebindingProof(zone, previousDescriptor, nextDescriptor, agent_rotation_proof) {
  const body = aliasRebindingBody(zone.descriptor, previousDescriptor, nextDescriptor);
  return {
    ...body,
    agent_rotation_proof,
    zone_signature: signObject(zone.privateKey, body),
  };
}

export function rotationBody(previousDescriptor, nextDescriptor) {
  return {
    previous_aid: previousDescriptor.aid,
    next_aid: nextDescriptor.aid,
  };
}

export function rotationProof(previousAgent, nextAgent) {
  const body = rotationBody(previousAgent.descriptor, nextAgent.descriptor);
  return {
    ...body,
    previous_signature: signObject(previousAgent.privateKey, body),
    next_signature: signObject(nextAgent.privateKey, body),
  };
}

export function verifyRotationProof(proof, previousDescriptor, nextDescriptor) {
  if (!proof || typeof proof !== "object" || Array.isArray(proof)) return false;
  if (!previousDescriptor || typeof previousDescriptor !== "object" || Array.isArray(previousDescriptor)) return false;
  if (!nextDescriptor || typeof nextDescriptor !== "object" || Array.isArray(nextDescriptor)) return false;
  try {
    const previousPublicKey = publicKeyFromDescriptor(previousDescriptor);
    const nextPublicKey = publicKeyFromDescriptor(nextDescriptor);
    if (computeAid(previousPublicKey) !== previousDescriptor.aid) return false;
    if (computeAid(nextPublicKey) !== nextDescriptor.aid) return false;
    if (!verifyObject(previousPublicKey, descriptorBody(previousDescriptor), previousDescriptor.descriptor_signature)) {
      return false;
    }
    if (!verifyObject(nextPublicKey, descriptorBody(nextDescriptor), nextDescriptor.descriptor_signature)) {
      return false;
    }
    const body = rotationBody(previousDescriptor, nextDescriptor);
    if (proof.previous_aid !== body.previous_aid || proof.next_aid !== body.next_aid) return false;
    return (
      verifyObject(previousPublicKey, body, proof.previous_signature) &&
      verifyObject(nextPublicKey, body, proof.next_signature)
    );
  } catch {
    return false;
  }
}

export function verifyAliasRebindingProof(proof, zoneDescriptor, previousDescriptor, nextDescriptor) {
  if (!proof || typeof proof !== "object" || Array.isArray(proof)) return false;
  if (!previousDescriptor || typeof previousDescriptor !== "object" || Array.isArray(previousDescriptor)) return false;
  if (!nextDescriptor || typeof nextDescriptor !== "object" || Array.isArray(nextDescriptor)) return false;
  try {
    const { publicKey: zonePublicKey } = verifyZoneDescriptor(zoneDescriptor);
    const body = aliasRebindingBody(zoneDescriptor, previousDescriptor, nextDescriptor);
    if (
      proof.zone !== body.zone ||
      proof.alias !== body.alias ||
      proof.previous_aid !== body.previous_aid ||
      proof.next_aid !== body.next_aid
    ) {
      return false;
    }
    return (
      verifyRotationProof(proof.agent_rotation_proof, previousDescriptor, nextDescriptor) &&
      verifyObject(zonePublicKey, body, proof.zone_signature)
    );
  } catch {
    return false;
  }
}

export function capabilityCredential(authorityZone, subjectDescriptor, capability, claims = {}) {
  const body = {
    issuer: authorityZone.zid,
    subject: subjectDescriptor.aid,
    capability,
    claims,
  };
  return { ...body, signature: signObject(authorityZone.privateKey, body) };
}

export function verifyCapabilityCredential(credential, authorityDescriptor, subjectDescriptor) {
  if (!credential || typeof credential !== "object" || Array.isArray(credential)) return false;
  try {
    const { publicKey: authorityPublicKey } = verifyZoneDescriptor(authorityDescriptor);
    const subjectPublicKey = publicKeyFromDescriptor(subjectDescriptor);
    if (computeAid(subjectPublicKey) !== subjectDescriptor.aid) return false;
    if (!verifyObject(subjectPublicKey, descriptorBody(subjectDescriptor), subjectDescriptor.descriptor_signature)) return false;
    if (!subjectDescriptor.capabilities.includes(credential.capability)) return false;
    const body = {
      issuer: credential.issuer,
      subject: credential.subject,
      capability: credential.capability,
      claims: credential.claims,
    };
    return (
      credential.issuer === authorityDescriptor.zid &&
      credential.subject === subjectDescriptor.aid &&
      verifyObject(authorityPublicKey, body, credential.signature)
    );
  } catch {
    return false;
  }
}

export function capabilityCredentialId(credential) {
  if (!credential || typeof credential !== "object" || Array.isArray(credential)) throw new Error("credential missing");
  const body = {
    issuer: credential.issuer,
    subject: credential.subject,
    capability: credential.capability,
    claims: credential.claims,
  };
  return `credential:sha256:${createHash("sha256").update(Buffer.from(canonical(body))).digest("hex")}`;
}

export function verifyCredentialStatus(status, credential, authorityDescriptor) {
  if (!status || typeof status !== "object" || Array.isArray(status)) return false;
  if (!credential || typeof credential !== "object" || Array.isArray(credential)) return false;
  try {
    const { publicKey: authorityPublicKey } = verifyZoneDescriptor(authorityDescriptor);
    const body = {
      issuer: status.issuer,
      credential_id: status.credential_id,
      subject: status.subject,
      status: status.status,
    };
    return (
      status.issuer === authorityDescriptor.zid &&
      status.credential_id === capabilityCredentialId(credential) &&
      status.subject === credential.subject &&
      verifyObject(authorityPublicKey, body, status.status_signature)
    );
  } catch {
    return false;
  }
}

export function enforcePolicy(descriptor, task) {
  const policy = descriptor.policy ?? {};
  const scope = task.scope ?? {};
  if (scope.network && policy.allow_network !== true) {
    throw new Error("policy denied network access");
  }
  for (const target of scope.write ?? []) {
    const allowed = (policy.write_prefixes ?? []).some((prefix) => target.startsWith(prefix));
    if (!allowed) throw new Error(`policy denied write scope: ${target}`);
  }
}

export function approvalReasons(descriptor, task) {
  const required = descriptor.policy?.approval_required ?? [];
  const scope = task.scope ?? {};
  return required.filter((item) => item === "write" && (scope.write ?? []).length > 0);
}

function localArtifactPath(uri) {
  const prefix = "artifact://local/";
  if (typeof uri !== "string" || !uri.startsWith(prefix)) throw new Error("artifact uri invalid");
  const localPath = uri.slice(prefix.length);
  if (!localPath || localPath.includes("\\") || localPath.split("/").some((part) => !part || part === "." || part === "..")) {
    throw new Error("artifact uri invalid");
  }
  return `artifacts/${localPath}`;
}

export async function writeArtifact(uri, text) {
  const file = localArtifactPath(uri);
  await mkdir(dirname(file), { recursive: true });
  await writeFile(file, text);
  const data = Buffer.from(text);
  const manifest = {
    uri,
    sha256: createHash("sha256").update(data).digest("hex"),
    size: data.length,
    media_type: "text/markdown; charset=utf-8",
  };
  manifest.afp = `afp:sha256:${manifest.sha256}`;
  manifest.manifest_hash = createHash("sha256").update(canonical(manifest)).digest("hex");
  await writeFile(`${file}.manifest.json`, `${JSON.stringify(manifest, null, 2)}\n`);
  return { path: file, manifest };
}

export async function verifyLocalArtifact(manifest) {
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) throw new Error("artifact manifest missing");
  const file = localArtifactPath(manifest.uri);
  verifyReceiptArtifactManifests({ artifact_refs: [manifest.uri], artifact_manifests: [manifest] });
  const sidecar = JSON.parse(await readFile(`${file}.manifest.json`, "utf8"));
  if (JSON.stringify(sidecar) !== JSON.stringify(manifest)) throw new Error("artifact manifest sidecar mismatch");
  const data = await readFile(file);
  if (data.length !== manifest.size) throw new Error("artifact bytes size mismatch");
  if (createHash("sha256").update(data).digest("hex") !== manifest.sha256) {
    throw new Error("artifact bytes digest mismatch");
  }
  return manifest;
}
