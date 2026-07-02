import { appendFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { createHash, createPublicKey, generateKeyPairSync, sign, verify } from "node:crypto";

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

export function createAgent(alias, policy = {}, transports = ["asp+local://demo"]) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const aid = computeAid(publicKey);
  const descriptor = {
    alias,
    aid,
    public_key_spki: b64url(publicKeyDer(publicKey)),
    transports,
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

export function zoneBinding(zone, descriptor) {
  const body = { zone: zone.zid, alias: descriptor.alias, aid: descriptor.aid };
  return { ...body, signature: signObject(zone.privateKey, body) };
}

export async function writeRegistry(file, zone, descriptors) {
  await writeJson(file, {
    zone: zone.descriptor,
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
      { descriptor: entry.descriptor, zone: registry.zone, zone_binding: entry.zone_binding },
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
  return { descriptor, publicKey, zone: entry.zone, zoneBinding: entry.zone_binding };
}

export function verifyZoneBinding(entry, descriptor, alias) {
  if (!entry.zone) throw new Error(`zone descriptor missing for ${alias}`);
  if (!entry.zone_binding) throw new Error(`zone binding missing for ${alias}`);
  const zonePublicKey = publicKeyFromDescriptor({ public_key_spki: entry.zone.public_key_spki });
  const zid = computeZid(zonePublicKey);
  if (zid !== entry.zone.zid) throw new Error(`zone id mismatch for ${alias}`);
  if (!verifyObject(zonePublicKey, zoneDescriptorBody(entry.zone), entry.zone.zone_signature)) {
    throw new Error(`zone signature verification failed for ${alias}`);
  }
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
