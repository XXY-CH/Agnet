import { appendFile, chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from "node:crypto";

const AGENT_DOMAIN = Buffer.from("asp-agent-id-v1\0");
const ZONE_DOMAIN = Buffer.from("asp-zone-id-v1\0");

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

export function computeZid(publicKey) {
  const digest = createHash("sha256").update(ZONE_DOMAIN).update(publicKeyDer(publicKey)).digest();
  return `zid:ed25519:${b64url(digest)}`;
}

export function publicKeyFromDescriptor(descriptor) {
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
  return verify(null, Buffer.from(canonical(payload)), publicKey, Buffer.from(signature, "base64url"));
}

export function descriptorBody(descriptor) {
  const { descriptor_signature, ...body } = descriptor;
  return body;
}

export function zoneDescriptorBody(descriptor) {
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
  return new Map(
    trustStore.zones.map((zoneDescriptor) => {
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

export async function appendAudit(record) {
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
  if (Array.isArray(registry)) return new Map(registry.map((descriptor) => [descriptor.alias, { descriptor }]));
  return new Map(
    registry.agents.map((entry) => [
      entry.descriptor.alias,
      {
        descriptor: entry.descriptor,
        zone: registry.zone,
        zone_binding: entry.zone_binding,
        revocations: registry.revocations ?? [],
      },
    ]),
  );
}

export function resolveAgent(registry, alias) {
  const entry = registry.get(alias);
  if (!entry) throw new Error(`agent alias not found: ${alias}`);
  const descriptor = entry.descriptor ?? entry;
  const publicKey = publicKeyFromDescriptor(descriptor);
  const computedAid = computeAid(publicKey);
  if (computedAid !== descriptor.aid) throw new Error(`descriptor aid mismatch for ${alias}`);
  if (!descriptor.descriptor_signature) throw new Error(`descriptor signature missing for ${alias}`);
  if (!verifyObject(publicKey, descriptorBody(descriptor), descriptor.descriptor_signature)) {
    throw new Error(`descriptor signature verification failed for ${alias}`);
  }
  if (entry.zone || entry.zone_binding) verifyZoneBinding(entry, descriptor, alias);
  if (entry.revocations?.length) verifyNotRevoked(entry, descriptor, alias);
  return { descriptor, publicKey, zone: entry.zone, zoneBinding: entry.zone_binding };
}

export function verifyZoneBinding(entry, descriptor, alias) {
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
}

export function verifyAliasRebindingProof(proof, zoneDescriptor, previousDescriptor, nextDescriptor) {
  let zonePublicKey;
  try {
    ({ publicKey: zonePublicKey } = verifyZoneDescriptor(zoneDescriptor));
  } catch {
    return false;
  }
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
}

export function capabilityCredentialId(credential) {
  const body = {
    issuer: credential.issuer,
    subject: credential.subject,
    capability: credential.capability,
    claims: credential.claims,
  };
  return `credential:sha256:${createHash("sha256").update(Buffer.from(canonical(body))).digest("hex")}`;
}

export function verifyCredentialStatus(status, credential, authorityDescriptor) {
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

export async function writeArtifact(uri, text) {
  const file = uri.replace("artifact://local/", "artifacts/");
  await mkdir(dirname(file), { recursive: true });
  await writeFile(file, text);
  return file;
}
