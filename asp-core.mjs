import { appendFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { createHash, createPublicKey, generateKeyPairSync, sign, verify } from "node:crypto";

const DOMAIN = Buffer.from("asp-agent-id-v1\0");

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
  const digest = createHash("sha256").update(DOMAIN).update(publicKeyDer(publicKey)).digest();
  return `aid:ed25519:${b64url(digest)}`;
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

export function createAgent(alias, policy = {}, transports = ["asp+local://demo"]) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const aid = computeAid(publicKey);
  return {
    alias,
    aid,
    descriptor: {
      alias,
      aid,
      public_key_spki: b64url(publicKeyDer(publicKey)),
      transports,
      policy,
    },
    privateKey,
    publicKey,
  };
}

export async function writeJson(file, value) {
  await mkdir(dirname(file), { recursive: true });
  await writeFile(file, `${JSON.stringify(value, null, 2)}\n`);
}

export async function appendAudit(record) {
  await mkdir("state", { recursive: true });
  await appendFile("state/audit.log", `${JSON.stringify(record)}\n`);
}

export async function loadRegistry(file) {
  const entries = JSON.parse(await readFile(file, "utf8"));
  return new Map(entries.map((descriptor) => [descriptor.alias, descriptor]));
}

export function resolveAgent(registry, alias) {
  const descriptor = registry.get(alias);
  if (!descriptor) throw new Error(`agent alias not found: ${alias}`);
  const publicKey = publicKeyFromDescriptor(descriptor);
  const computedAid = computeAid(publicKey);
  if (computedAid !== descriptor.aid) throw new Error(`descriptor aid mismatch for ${alias}`);
  return { descriptor, publicKey };
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
