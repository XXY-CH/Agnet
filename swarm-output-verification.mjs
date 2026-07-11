import { createHash, randomUUID } from "node:crypto";

import {
  assertCanonicalStringDomain,
  canonical,
  decodeBase64UrlExact,
  deriveSwarmFinalOutput,
  publicKeyFromDescriptor,
  resolveAgent,
  signObject,
  signedReceiptDigest,
  verifyFederatedReceipt,
  verifyObject,
  verifyResultArtifact,
  verifySwarmClose,
  verifySwarmExecutionBinding,
  verifySwarmPlan,
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
const OUTPUT_VERIFICATION_FORMAT = "asp-swarm-output-verification/v1";
const OUTPUT_VERIFICATION_FRAME_FIELDS = ["proof", "type", "verifier", "verifier_zone", "verifier_zone_binding"];
const OUTPUT_VERIFICATION_BODY_FIELDS = [
  "close_digest",
  "execution_graph_digest",
  "final_output",
  "format",
  "plan_digest",
  "proof_signature",
  "swarm_id",
  "trust_inputs_digest",
  "verification_id",
  "verified_at",
  "verifier_aid",
  "verifier_zone",
];
const FUTURE_SKEW_MS = 5 * 60 * 1000;
const UTC_TIMESTAMP_PATTERN = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?Z$/;

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
  if (value === null || typeof value !== "object" || Object.isFrozen(value) || ArrayBuffer.isView(value)) return value;
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

function requireHexDigest(value, label) {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) throw new Error(`${label} invalid`);
  return value;
}

function canonicalEqual(left, right) {
  return canonical(left) === canonical(right);
}

function trustedZonesMapFromEvidence(evidence) {
  const trustedZones = evidence?.trustedZones;
  if (trustedZones instanceof Map) return trustedZones;
  if (trustedZones && typeof trustedZones === "object" && !Array.isArray(trustedZones)) return new Map(Object.entries(trustedZones));
  throw new Error("swarm output trusted zones missing");
}

function validateUTCNotFuture(value, now) {
  const match = typeof value === "string" ? UTC_TIMESTAMP_PATTERN.exec(value) : null;
  if (!match) throw new Error("verified_at invalid");
  const [, year, month, day, hour, minute, second, ms = "0"] = match;
  const millis = Number(ms.padEnd(3, "0"));
  const parsed = Date.UTC(Number(year), Number(month) - 1, Number(day), Number(hour), Number(minute), Number(second), millis);
  const date = new Date(parsed);
  if (
    date.getUTCFullYear() !== Number(year) ||
    date.getUTCMonth() !== Number(month) - 1 ||
    date.getUTCDate() !== Number(day) ||
    date.getUTCHours() !== Number(hour) ||
    date.getUTCMinutes() !== Number(minute) ||
    date.getUTCSeconds() !== Number(second) ||
    date.getUTCMilliseconds() !== millis
  ) throw new Error("verified_at invalid");
  const nowMs = now instanceof Date ? now.getTime() : new Date(now).getTime();
  if (!Number.isFinite(nowMs)) throw new Error("verification clock invalid");
  if (parsed - nowMs > FUTURE_SKEW_MS) throw new Error("verified_at future skew invalid");
}

function findPinnedVerifier(frame, trustInputs) {
  if (!trustInputs || !Array.isArray(trustInputs.allowlist?.verifiers) || !Array.isArray(trustInputs.trusted_zones?.zones)) throw new Error("trust inputs missing");
  requireExactFields(frame, OUTPUT_VERIFICATION_FRAME_FIELDS, "swarm output verification frame");
  if (frame.type !== "FED_SWARM_OUTPUT_VERIFICATION") throw new Error("expected FED_SWARM_OUTPUT_VERIFICATION frame");
  const verifier = normalizeAgentDescriptor(frame.verifier);
  const verifierZone = normalizeZoneDescriptor(frame.verifier_zone);
  const verifierZoneBinding = normalizeZoneBinding(frame.verifier_zone_binding);
  const allowed = trustInputs.allowlist.verifiers.find((entry) => entry.descriptor.aid === verifier.aid && entry.zone_binding.zone === verifierZone.zid && entry.authorizations.includes(VERIFY_AUTHORIZATION));
  if (!allowed) throw new Error("verifier allowlist tuple missing");
  if (!canonicalEqual(allowed.descriptor, verifier)) throw new Error("verifier descriptor mismatch");
  if (!canonicalEqual(allowed.zone_binding, verifierZoneBinding)) throw new Error("verifier zone binding mismatch");
  const trustedZone = trustInputs.trusted_zones.zones.find((zone) => zone.zid === verifierZone.zid);
  if (!trustedZone || !canonicalEqual(trustedZone, verifierZone)) throw new Error("verifier trusted Zone mismatch");
  return { verifier, verifierZone, verifierZoneBinding };
}

async function verifyArtifactBytes(finalOutput, terminalReceipt, loadArtifactBytes) {
  if (typeof loadArtifactBytes !== "function") throw new Error("artifact byte loader missing");
  const artifact = finalOutput.artifact;
  const manifests = terminalReceipt.artifact_manifests ?? [];
  const manifest = manifests.find((item) => item.uri === artifact.uri && item.sha256 === artifact.sha256 && item.manifest_hash === artifact.manifest_hash);
  if (!manifest) throw new Error("result artifact manifest mismatch");
  const bytes = await loadArtifactBytes(artifact, manifest);
  if (!(bytes instanceof Uint8Array) && !Buffer.isBuffer(bytes)) throw new Error("artifact bytes missing");
  const buffer = Buffer.from(bytes);
  if (buffer.length !== manifest.size) throw new Error("artifact bytes size mismatch");
  if (createHash("sha256").update(buffer).digest("hex") !== artifact.sha256) throw new Error("artifact bytes digest mismatch");
}

async function recomputeSwarmOutput(evidence, trustInputs) {
  if (!isObject(evidence)) throw new Error("swarm output evidence missing");
  const trustedZones = trustedZonesMapFromEvidence(evidence);
  const verifiedPlan = verifySwarmPlan(evidence.planFrame, trustedZones);
  const verifiedBinding = verifySwarmExecutionBinding(evidence.executionBinding, verifiedPlan, evidence.executableSteps, evidence.resolvedWorkers);
  const closeVerified = verifySwarmClose(evidence.closeFrame, trustedZones);
  if (closeVerified.legacy || closeVerified.format !== "asp-swarm-close/v2") throw new Error("swarm output requires v2 close");
  if (closeVerified.close.swarm_id !== verifiedBinding.swarmId) throw new Error("close swarm_id mismatch");
  if (closeVerified.close.plan_digest !== verifiedBinding.planDigest) throw new Error("close plan digest mismatch");
  if (closeVerified.close.execution_graph_digest !== verifiedBinding.executionGraphDigest) throw new Error("close execution graph digest mismatch");
  if (!Array.isArray(evidence.receiptFrames) || evidence.receiptFrames.length !== verifiedBinding.steps.length) throw new Error("signed receipt count mismatch");
  const signedReceiptsByStep = new Map();
  for (const receiptFrame of evidence.receiptFrames) {
    const stepID = receiptFrame?.receipt?.swarm?.step_id;
    const executableStep = evidence.executableSteps.find((step) => step.step_id === stepID);
    const verifiedReceipt = verifyFederatedReceipt(receiptFrame, trustedZones, executableStep?.task);
    const receiptStepID = verifiedReceipt.receipt.swarm?.step_id;
    if (signedReceiptsByStep.has(receiptStepID)) throw new Error("duplicate signed receipt step");
    signedReceiptsByStep.set(receiptStepID, verifiedReceipt.signedReceipt);
  }
  const finalOutput = deriveSwarmFinalOutput(verifiedBinding, signedReceiptsByStep);
  if (!canonicalEqual(finalOutput, closeVerified.close.final_output)) throw new Error("final output mismatch");
  const closeSteps = new Map(closeVerified.close.step_receipts.map((step) => [step.step_id, step]));
  if (closeSteps.size !== signedReceiptsByStep.size) throw new Error("close signed receipt count mismatch");
  for (const stepID of closeSteps.keys()) {
    if (!signedReceiptsByStep.has(stepID)) throw new Error(`close signed receipt missing: ${stepID}`);
  }
  for (const [stepID, signedReceipt] of signedReceiptsByStep) {
    const closeStep = closeSteps.get(stepID);
    if (!closeStep) throw new Error(`close signed receipt missing: ${stepID}`);
    if (closeStep.task_id !== signedReceipt.task_id) throw new Error("close receipt task mismatch");
    if (closeStep.signed_receipt_digest !== signedReceiptDigest(signedReceipt)) throw new Error("close signed receipt digest mismatch");
  }
  const terminalReceipt = signedReceiptsByStep.get(finalOutput.step_id);
  const resultArtifact = verifyResultArtifact(terminalReceipt);
  if (!canonicalEqual(resultArtifact, finalOutput.artifact)) throw new Error("final output artifact mismatch");
  await verifyArtifactBytes(finalOutput, terminalReceipt, evidence.loadArtifactBytes);
  return { closeVerified, finalOutput };
}

function snapshotProofFrame(proofFrame) {
  return structuredClone(proofFrame);
}

function proofBodyFromFrame(proofFrame, trustInputs, now) {
  const { verifier } = findPinnedVerifier(proofFrame, trustInputs);
  requireExactFields(proofFrame.proof, OUTPUT_VERIFICATION_BODY_FIELDS, "swarm output verification proof");
  const { proof_signature: signature, ...body } = proofFrame.proof;
  if (body.format !== OUTPUT_VERIFICATION_FORMAT) throw new Error("swarm output verification format invalid");
  requireString(body.verification_id, "verification_id");
  validateUTCNotFuture(body.verified_at, now);
  requireString(body.swarm_id, "swarm_id");
  requireHexDigest(body.plan_digest, "plan_digest");
  requireHexDigest(body.execution_graph_digest, "execution_graph_digest");
  requireHexDigest(body.close_digest, "close_digest");
  requireHexDigest(body.trust_inputs_digest, "trust_inputs_digest");
  if (!isObject(body.final_output)) throw new Error("final_output invalid");
  if (body.verifier_aid !== verifier.aid) throw new Error("verifier aid mismatch");
  if (body.verifier_zone !== proofFrame.verifier_zone.zid) throw new Error("verifier Zone mismatch");
  if (typeof signature !== "string" || signature.length === 0) throw new Error("proof signature missing");
  if (!verifyObject(publicKeyFromDescriptor(verifier), body, signature)) throw new Error("proof signature verification failed");
  return body;
}

function buildResult(proofSnapshot, proofBody, closeVerified, finalOutput, trustInputs) {
  const closeBytes = Buffer.from(canonical(closeVerified.close));
  const proofBytes = Buffer.from(canonical(proofSnapshot.proof));
  const proofDigest = createHash("sha256").update(proofBytes).digest("hex");
  return deepFreeze({
    proof: proofSnapshot,
    verificationID: proofBody.verification_id,
    verifiedAt: proofBody.verified_at,
    verifierAID: proofBody.verifier_aid,
    verifierZone: proofBody.verifier_zone,
    proofDigest,
    closeDigest: closeVerified.closeDigest,
    trustInputsDigest: trustInputs.trust_inputs_digest,
    CloseBytes: closeBytes,
    ProofBytes: proofBytes,
    finalOutput,
  });
}

export async function createSwarmOutputVerification(evidence, trustInputs, verifier, options = {}) {
  if (!isObject(verifier) || !verifier.privateKey) throw new Error("verifier signing key missing");
  const { finalOutput, closeVerified } = await recomputeSwarmOutput(evidence, trustInputs);
  const proofBody = {
    format: OUTPUT_VERIFICATION_FORMAT,
    verification_id: requireString(options.verificationId ?? `verification:${randomUUID()}`, "verification_id"),
    verified_at: options.verifiedAt ?? new Date(options.now ?? Date.now()).toISOString().replace(".000Z", "Z"),
    swarm_id: closeVerified.close.swarm_id,
    plan_digest: closeVerified.close.plan_digest,
    execution_graph_digest: closeVerified.close.execution_graph_digest,
    close_digest: closeVerified.closeDigest,
    final_output: finalOutput,
    verifier_aid: verifier.descriptor?.aid,
    verifier_zone: verifier.zone?.zid,
    trust_inputs_digest: trustInputs.trust_inputs_digest,
  };
  validateUTCNotFuture(proofBody.verified_at, options.now ?? new Date());
  const proof = {
    type: "FED_SWARM_OUTPUT_VERIFICATION",
    verifier: verifier.descriptor,
    verifier_zone: verifier.zone,
    verifier_zone_binding: verifier.zone_binding,
    proof: { ...proofBody, proof_signature: signObject(verifier.privateKey, proofBody) },
  };
  const proofSnapshot = snapshotProofFrame(proof);
  const proofBodySnapshot = proofBodyFromFrame(proofSnapshot, trustInputs, options.now ?? new Date());
  return buildResult(proofSnapshot, proofBodySnapshot, closeVerified, finalOutput, trustInputs);
}

export async function verifySwarmOutputVerification(proof, evidence, trustInputs, options = {}) {
  const proofSnapshot = snapshotProofFrame(proof);
  const body = proofBodyFromFrame(proofSnapshot, trustInputs, options.now ?? new Date());
  const { finalOutput, closeVerified } = await recomputeSwarmOutput(evidence, trustInputs);
  if (body.trust_inputs_digest !== trustInputs.trust_inputs_digest) throw new Error("trust inputs digest mismatch");
  if (body.swarm_id !== closeVerified.close.swarm_id) throw new Error("proof swarm_id mismatch");
  if (body.plan_digest !== closeVerified.close.plan_digest) throw new Error("proof plan digest mismatch");
  if (body.execution_graph_digest !== closeVerified.close.execution_graph_digest) throw new Error("proof execution graph digest mismatch");
  if (body.close_digest !== closeVerified.closeDigest) throw new Error("proof close digest mismatch");
  if (!canonicalEqual(body.final_output, finalOutput)) throw new Error("proof final output mismatch");
  return buildResult(proofSnapshot, body, closeVerified, finalOutput, trustInputs);
}

function cloneReplayJSON(value) {
  return structuredClone(value);
}

function proofReplayRecordFromVerification(verified) {
  const canonicalProofText = Buffer.from(verified.ProofBytes).toString("utf8");
  const canonicalCloseText = Buffer.from(verified.CloseBytes).toString("utf8");
  return deepFreeze({
    verification_id: verified.verificationID,
    canonical_proof_sha256: createHash("sha256").update(canonicalProofText, "utf8").digest("hex"),
    canonical_close_sha256: createHash("sha256").update(canonicalCloseText, "utf8").digest("hex"),
    canonical_proof_bytes: canonicalProofText,
    canonical_close_bytes: canonicalCloseText,
    proof_close_digest: verified.closeDigest,
    stored_close_digest: verified.closeDigest,
    proof_digest: verified.proofDigest,
    trust_inputs_digest: verified.trustInputsDigest,
    final_output: cloneReplayJSON(verified.finalOutput),
    verified_at: verified.verifiedAt,
    verifier_aid: verified.verifierAID,
    verifier_zone: verified.verifierZone,
  });
}

function replayBytesEqual(left, right) {
  if (Buffer.isBuffer(right)) return left.equals(right);
  if (right instanceof Uint8Array) return left.equals(Buffer.from(right));
  if (Array.isArray(right)) return left.equals(Buffer.from(right));
  if (typeof right === "string") return left.equals(Buffer.from(right));
  return false;
}

function classifyReplay(existing, record) {
  if (!existing) return "accepted";
  return existing.canonical_proof_sha256 === record.canonical_proof_sha256
    && existing.canonical_close_sha256 === record.canonical_close_sha256
    && existing.stored_close_digest === record.stored_close_digest
    && existing.stored_close_digest === record.proof_close_digest
    && existing.proof_close_digest === record.proof_close_digest
    && existing.proof_digest === record.proof_digest
    && existing.trust_inputs_digest === record.trust_inputs_digest
    && replayBytesEqual(Buffer.from(record.canonical_proof_bytes, "utf8"), existing.canonical_proof_bytes)
    && replayBytesEqual(Buffer.from(record.canonical_close_bytes, "utf8"), existing.canonical_close_bytes)
    && canonicalEqual(existing.final_output, record.final_output)
    ? "idempotent"
    : "conflict";
}

function buildSchedulerCompletion(verified, record, replayDecision, storeMutated, storedRecord = record) {
  const storedCloseDigest = storedRecord.stored_close_digest;
  const gateDecision = replayDecision === "accepted" || replayDecision === "idempotent";
  return deepFreeze({
    verification_id: record.verification_id,
    canonical_proof_sha256: record.canonical_proof_sha256,
    canonical_close_sha256: record.canonical_close_sha256,
    replay_decision: replayDecision,
    stored_close_digest: storedCloseDigest,
    proof_close_digest: record.proof_close_digest,
    store_mutated: storeMutated,
    closeDigest: verified.closeDigest,
    proofDigest: verified.proofDigest,
    trustInputsDigest: verified.trustInputsDigest,
    CloseBytes: Buffer.from(verified.CloseBytes),
    ProofBytes: Buffer.from(verified.ProofBytes),
    finalOutput: cloneReplayJSON(verified.finalOutput),
    completion_gate: gateDecision && storedCloseDigest === verified.closeDigest,
  });
}

function replayPut(store) {
  return store.putVerificationReplayIfAbsent ?? store.putIfAbsent;
}

export async function applySwarmOutputVerificationReplay(proof, evidence, trustInputs, store, options = {}) {
  const putIfAbsent = replayPut(store);
  if (!store || typeof putIfAbsent !== "function") {
    throw new Error("verification replay store invalid");
  }
  const verified = await verifySwarmOutputVerification(proof, evidence, trustInputs, options);
  if (options.expectedCloseDigest !== undefined) {
    requireHexDigest(options.expectedCloseDigest, "expected close digest");
    if (options.expectedCloseDigest !== verified.closeDigest) throw new Error("verification replay close digest mismatch");
  }
  const record = proofReplayRecordFromVerification(verified);
  const putResult = await putIfAbsent.call(store, record);
  const inserted = putResult === true || putResult?.inserted === true;
  const storedRecord = putResult?.record ?? putResult?.existing ?? (inserted ? record : undefined);
  if (!inserted && !storedRecord) throw new Error("verification replay store did not return existing record");
  const replayDecision = inserted ? "accepted" : classifyReplay(storedRecord, record);
  return buildSchedulerCompletion(verified, record, replayDecision, inserted, storedRecord ?? record);
}
