import { createHash } from "node:crypto";

import {
  assertCanonicalStringDomain,
  canonical,
  decodeBase64UrlExact,
  resolveAgent,
  verifyZoneBinding,
  verifyZoneDescriptor,
  verifyZoneRevocation,
} from "./asp-core.mjs";
import { safeOpenOwnedJson } from "./secure-input.mjs";

const ALLOWLIST_FORMAT = "asp-swarm-output-verifier-allowlist/v1";
const TRUSTED_ZONES_FORMAT = "asp-swarm-output-trusted-zones/v1";
const REVOCATIONS_FORMAT = "asp-swarm-output-revocations/v1";
const VERIFY_AUTHORIZATION = "swarm.output.verify";

const ALLOWLIST_FIELDS = ["format", "verifiers"];
const VERIFIER_FIELDS = ["authorizations", "descriptor", "zone_binding"];
const AGENT_DESCRIPTOR_FIELDS = [
  "aid",
  "alias",
  "capabilities",
  "descriptor_signature",
  "did_key",
  "policy",
  "public_key_spki",
  "transports",
];
const POLICY_FIELDS = new Set(["allow_network", "approval_required", "write_prefixes"]);
const ZONE_BINDING_FIELDS = ["aid", "alias", "signature", "zone"];
const TRUSTED_ZONES_FIELDS = ["format", "zones"];
const ZONE_DESCRIPTOR_FIELDS = ["name", "public_key_spki", "zid", "zone_signature"];
const REVOCATIONS_FIELDS = ["format", "revocations"];
const REVOCATION_FIELDS = ["reason", "signature", "subject", "zone"];

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function requireExactFields(value, fields, label) {
  if (!isObject(value)) throw new Error(`${label} exact schema invalid`);
  const actual = Object.keys(value).sort();
  const expected = [...fields].sort();
  if (actual.length !== expected.length || actual.some((field, index) => field !== expected[index])) {
    throw new Error(`${label} exact schema has unknown or missing fields`);
  }
}

function requireString(value, label) {
  if (typeof value !== "string" || value.length === 0 || value.includes("\0")) throw new Error(`${label} invalid`);
  return assertCanonicalStringDomain(value, `${label} canonical string domain`);
}

function requireBase64UrlString(value, label) {
  const text = requireString(value, label);
  decodeBase64UrlExact(text, label);
  return text;
}

function requireStringList(value, label, { allowEmpty = true } = {}) {
  if (!Array.isArray(value) || (!allowEmpty && value.length === 0)) throw new Error(`${label} invalid`);
  const seen = new Set();
  return value.map((item) => {
    const text = requireString(item, label);
    if (seen.has(text)) throw new Error(`${label} duplicate value`);
    seen.add(text);
    return text;
  });
}

function normalizePolicy(policy) {
  if (!isObject(policy)) throw new Error("verifier policy exact schema invalid");
  for (const field of Object.keys(policy)) {
    if (!POLICY_FIELDS.has(field)) throw new Error("verifier policy exact schema has unknown fields");
  }
  const normalized = {};
  if (Object.hasOwn(policy, "allow_network")) {
    if (typeof policy.allow_network !== "boolean") throw new Error("verifier policy allow_network invalid");
    normalized.allow_network = policy.allow_network;
  }
  for (const field of ["approval_required", "write_prefixes"]) {
    if (Object.hasOwn(policy, field)) normalized[field] = requireStringList(policy[field], `verifier policy ${field}`);
  }
  return normalized;
}

function normalizeAgentDescriptor(descriptor) {
  requireExactFields(descriptor, AGENT_DESCRIPTOR_FIELDS, "verifier descriptor");
  return {
    alias: requireString(descriptor.alias, "verifier alias"),
    aid: requireString(descriptor.aid, "verifier aid"),
    did_key: requireString(descriptor.did_key, "verifier did_key"),
    public_key_spki: requireBase64UrlString(descriptor.public_key_spki, "verifier public_key_spki"),
    transports: requireStringList(descriptor.transports, "verifier transports"),
    capabilities: requireStringList(descriptor.capabilities, "verifier capabilities"),
    policy: normalizePolicy(descriptor.policy),
    descriptor_signature: requireBase64UrlString(descriptor.descriptor_signature, "verifier descriptor signature"),
  };
}

function normalizeZoneBinding(binding) {
  requireExactFields(binding, ZONE_BINDING_FIELDS, "verifier zone binding");
  return {
    zone: requireString(binding.zone, "verifier zone binding zone"),
    alias: requireString(binding.alias, "verifier zone binding alias"),
    aid: requireString(binding.aid, "verifier zone binding aid"),
    signature: requireBase64UrlString(binding.signature, "verifier zone binding signature"),
  };
}

function normalizeZoneDescriptor(zone) {
  requireExactFields(zone, ZONE_DESCRIPTOR_FIELDS, "trusted zone descriptor");
  return {
    name: requireString(zone.name, "trusted zone name"),
    zid: requireString(zone.zid, "trusted zone zid"),
    public_key_spki: requireBase64UrlString(zone.public_key_spki, "trusted zone public_key_spki"),
    zone_signature: requireBase64UrlString(zone.zone_signature, "trusted zone signature"),
  };
}

function normalizeRevocation(revocation) {
  requireExactFields(revocation, REVOCATION_FIELDS, "revocation entry");
  return {
    zone: requireString(revocation.zone, "revocation zone"),
    subject: requireString(revocation.subject, "revocation subject"),
    reason: requireString(revocation.reason, "revocation reason"),
    signature: requireBase64UrlString(revocation.signature, "revocation signature"),
  };
}

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left), Buffer.from(right));
}

function normalizeTrustedZones(input) {
  requireExactFields(input, TRUSTED_ZONES_FIELDS, "trusted zones");
  if (input.format !== TRUSTED_ZONES_FORMAT) throw new Error("trusted zones format invalid");
  if (!Array.isArray(input.zones) || input.zones.length === 0) throw new Error("trusted zones list invalid");
  const seen = new Set();
  const zones = input.zones.map((zone) => {
    const normalized = normalizeZoneDescriptor(zone);
    if (seen.has(normalized.zid)) throw new Error(`duplicate trusted zone: ${normalized.zid}`);
    seen.add(normalized.zid);
    try {
      verifyZoneDescriptor(normalized);
    } catch (error) {
      throw new Error(`zone signature verification failed: ${error.message}`);
    }
    return normalized;
  });
  zones.sort((left, right) => compareUtf8(left.zid, right.zid));
  return { format: TRUSTED_ZONES_FORMAT, zones };
}

function normalizeAllowlist(input, trustedZones) {
  requireExactFields(input, ALLOWLIST_FIELDS, "allowlist");
  if (input.format !== ALLOWLIST_FORMAT) throw new Error("allowlist format invalid");
  if (!Array.isArray(input.verifiers) || input.verifiers.length === 0) throw new Error("allowlist verifier list invalid");
  const trustedByZid = new Map(trustedZones.zones.map((zone) => [zone.zid, zone]));
  const identityOwners = new Map();
  const tuples = new Set();
  const verifiers = input.verifiers.map((entry) => {
    requireExactFields(entry, VERIFIER_FIELDS, "allowlist verifier");
    const descriptor = normalizeAgentDescriptor(entry.descriptor);
    const zoneBinding = normalizeZoneBinding(entry.zone_binding);
    const authorizations = requireStringList(entry.authorizations, "verifier authorizations", { allowEmpty: false });
    if (!authorizations.includes(VERIFY_AUTHORIZATION)) throw new Error("verifier missing exact swarm.output.verify authorization");
    for (const identity of [descriptor.aid, descriptor.alias]) {
      if (identityOwners.has(identity)) throw new Error(`duplicate verifier identity: ${identity}`);
      identityOwners.set(identity, descriptor.aid);
    }
    for (const authorization of authorizations) {
      const tuple = `${descriptor.aid}\0${zoneBinding.zone}\0${authorization}`;
      if (tuples.has(tuple)) throw new Error(`duplicate verifier authorization tuple: ${descriptor.aid}`);
      tuples.add(tuple);
    }
    try {
      resolveAgent(new Map([[descriptor.alias, descriptor]]), descriptor.alias);
    } catch (error) {
      throw new Error(`verifier descriptor signature verification failed: ${error.message}`);
    }
    const zone = trustedByZid.get(zoneBinding.zone);
    if (!zone) throw new Error(`untrusted verifier zone: ${zoneBinding.zone}`);
    try {
      verifyZoneBinding({ zone, zone_binding: zoneBinding }, descriptor, descriptor.alias);
    } catch (error) {
      throw new Error(`zone binding signature verification failed: ${error.message}`);
    }
    return { descriptor, zone_binding: zoneBinding, authorizations };
  });
  verifiers.sort((left, right) => compareUtf8(left.descriptor.aid, right.descriptor.aid));
  return { format: ALLOWLIST_FORMAT, verifiers };
}

function normalizeRevocations(input, trustedZones, allowlist) {
  requireExactFields(input, REVOCATIONS_FIELDS, "revocations");
  if (input.format !== REVOCATIONS_FORMAT) throw new Error("revocations format invalid");
  if (!Array.isArray(input.revocations)) throw new Error("revocations list invalid");
  const trustedByZid = new Map(trustedZones.zones.map((zone) => [zone.zid, zone]));
  const verifierZoneByIdentity = new Map();
  for (const verifier of allowlist.verifiers) {
    verifierZoneByIdentity.set(verifier.descriptor.aid, verifier.zone_binding.zone);
    verifierZoneByIdentity.set(verifier.descriptor.alias, verifier.zone_binding.zone);
  }
  const seen = new Set();
  const revokedByZone = new Map();
  const revocations = input.revocations.map((entry) => {
    const revocation = normalizeRevocation(entry);
    const tuple = `${revocation.zone}\0${revocation.subject}`;
    if (seen.has(tuple)) throw new Error(`duplicate revocation identity: ${revocation.zone}/${revocation.subject}`);
    seen.add(tuple);
    const zone = trustedByZid.get(revocation.zone);
    if (!zone) throw new Error(`untrusted revocation zone: ${revocation.zone}`);
    try {
      if (!verifyZoneRevocation(revocation, zone)) throw new Error("signature verification failed");
    } catch (error) {
      throw new Error(`revocation signature verification failed: ${error.message}`);
    }
    const verifierZone = verifierZoneByIdentity.get(revocation.subject);
    if (verifierZone !== undefined && verifierZone !== revocation.zone) {
      throw new Error(`out-of-scope verifier revocation: ${revocation.zone}/${revocation.subject}`);
    }
    if (trustedByZid.has(revocation.subject) && revocation.subject !== revocation.zone) {
      throw new Error(`out-of-scope Zone revocation: ${revocation.zone}/${revocation.subject}`);
    }
    if (!revokedByZone.has(revocation.zone)) revokedByZone.set(revocation.zone, new Set());
    revokedByZone.get(revocation.zone).add(revocation.subject);
    return revocation;
  });
  for (const zone of trustedZones.zones) {
    if (revokedByZone.get(zone.zid)?.has(zone.zid)) throw new Error(`trusted zone revoked: ${zone.zid}`);
  }
  for (const verifier of allowlist.verifiers) {
    const scoped = revokedByZone.get(verifier.zone_binding.zone);
    if (scoped?.has(verifier.descriptor.aid) || scoped?.has(verifier.descriptor.alias)) {
      throw new Error(`verifier revoked: ${verifier.descriptor.aid}`);
    }
  }
  revocations.sort((left, right) => compareUtf8(`${left.zone}\0${left.subject}`, `${right.zone}\0${right.subject}`));
  return { format: REVOCATIONS_FORMAT, revocations };
}

function digest(value) {
  return createHash("sha256").update(canonical(value)).digest("hex");
}

function deepFreeze(value) {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const item of Object.values(value)) deepFreeze(item);
  return Object.freeze(value);
}

function buildTrustInputs(allowlistInput, trustedZonesInput, revocationsInput, evidence = null) {
  const trusted_zones = normalizeTrustedZones(trustedZonesInput);
  const allowlist = normalizeAllowlist(allowlistInput, trusted_zones);
  const revocations = normalizeRevocations(revocationsInput, trusted_zones, allowlist);
  const trust_inputs_digest = digest({ allowlist, trusted_zones, revocations });
  const snapshotEvidence = evidence === null ? undefined : {
    allowlist: { ...evidence.allowlist, schema_format: allowlist.format, snapshot_digest: digest(allowlist) },
    trusted_zones: { ...evidence.trusted_zones, schema_format: trusted_zones.format, snapshot_digest: digest(trusted_zones) },
    revocations: { ...evidence.revocations, schema_format: revocations.format, snapshot_digest: digest(revocations) },
  };
  return deepFreeze({
    allowlist,
    trusted_zones,
    revocations,
    trust_inputs_digest,
    ...(snapshotEvidence === undefined ? {} : { evidence: snapshotEvidence }),
  });
}

export function createSwarmOutputTrustInputsForTest(allowlist, trustedZones, revocations) {
  return buildTrustInputs(allowlist, trustedZones, revocations);
}

export async function loadSwarmOutputTrustInputs(paths) {
  requireExactFields(paths, ["allowlist", "revocations", "trustedZones"], "trust input paths");
  for (const [name, path] of Object.entries(paths)) {
    if (typeof path !== "string" || path.length === 0) throw new Error(`trust input ${name} path invalid`);
  }
  const [allowlistFile, trustedZonesFile, revocationsFile] = await Promise.all([
    safeOpenOwnedJson(paths.allowlist),
    safeOpenOwnedJson(paths.trustedZones),
    safeOpenOwnedJson(paths.revocations),
  ]);
  return buildTrustInputs(
    allowlistFile.value,
    trustedZonesFile.value,
    revocationsFile.value,
    {
      allowlist: allowlistFile.evidence,
      trusted_zones: trustedZonesFile.evidence,
      revocations: revocationsFile.evidence,
    },
  );
}
