import { appendFile, chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { createHash, createPublicKey, generateKeyPairSync, randomUUID, sign, verify } from "node:crypto";

const AGENT_DOMAIN = Buffer.from("asp-agent-id-v1\0");
const ZONE_DOMAIN = Buffer.from("asp-zone-id-v1\0");
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const ED25519_MULTIKEY_PREFIX = Buffer.from([0xed, 0x01]);
const BASE58BTC = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const TASK_ID_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;
export const CREDENTIAL_VALID_UNTIL_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;

export function b64url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

export function assertCanonicalStringDomain(value, label = "canonical string domain") {
  if (typeof value !== "string") throw new Error(`${label} invalid`);
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code === 0x2028 || code === 0x2029) throw new Error(`${label} excludes U+2028/U+2029`);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!Number.isInteger(next) || next < 0xdc00 || next > 0xdfff) throw new Error(`${label} requires Unicode scalar values`);
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new Error(`${label} requires Unicode scalar values`);
    }
  }
  return value;
}

export function decodeBase64UrlExact(value, label = "base64url value") {
  if (typeof value !== "string" || value.length === 0 || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error(`${label} must use exact unpadded base64url`);
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.toString("base64url") !== value) throw new Error(`${label} must use exact unpadded base64url`);
  return decoded;
}

export function canonical(value) {
  if (typeof value === "string") return JSON.stringify(assertCanonicalStringDomain(value));
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  const keys = Object.keys(value)
    .map((key) => ({ key: assertCanonicalStringDomain(key), bytes: Buffer.from(key) }))
    .sort((left, right) => Buffer.compare(left.bytes, right.bytes));
  return `{${keys.map(({ key }) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
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
  let der;
  try {
    der = decodeBase64UrlExact(publicKeySPKI, "ed25519 public_key_spki");
  } catch {
    throw new Error("expected ed25519 public_key_spki");
  }
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
    key: decodeBase64UrlExact(descriptor.public_key_spki, "descriptor public_key_spki"),
    type: "spki",
    format: "der",
  });
}

export function signObject(privateKey, payload) {
  return b64url(sign(null, Buffer.from(canonical(payload)), privateKey));
}

export function verifyObject(publicKey, payload, signature) {
  if (typeof signature !== "string" || signature === "") return false;
  try {
    return verify(null, Buffer.from(canonical(payload)), publicKey, decodeBase64UrlExact(signature, "signature"));
  } catch {
    return false;
  }
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

function assertTrustedZoneDescriptor(zone, trustedZones, label) {
  assertTrustedZones(trustedZones);
  const trusted = trustedZones.get(zone.zid);
  if (!trusted || trusted.public_key_spki !== zone.public_key_spki) {
    throw new Error(`untrusted zone: ${zone.zid}`);
  }
  return zone;
}

function validateSwarmPlanSteps(steps) {
  if (!Array.isArray(steps) || steps.length === 0) throw new Error("swarm plan steps missing");
  for (const step of steps) {
    if (!step || typeof step !== "object" || Array.isArray(step)) throw new Error("swarm plan step invalid");
    if (typeof step.step_id !== "string" || step.step_id === "" || step.step_id.includes("\0")) throw new Error("swarm plan step invalid");
    if (typeof step.capability !== "string" || step.capability === "") throw new Error("swarm plan step capability invalid");
    if (step.constraint !== undefined && (!step.constraint || typeof step.constraint !== "object" || Array.isArray(step.constraint))) {
      throw new Error("swarm plan step constraint invalid");
    }
    if (step.depends_on !== undefined) {
      if (!Array.isArray(step.depends_on)) throw new Error("swarm plan step depends_on invalid");
      for (const dependency of step.depends_on) {
        if (typeof dependency !== "string" || dependency === "" || dependency.includes("\0")) throw new Error("swarm plan step depends_on invalid");
      }
    }
  }
}

function sha256Canonical(value) {
  return createHash("sha256").update(canonical(value)).digest("hex");
}

function knowledgeQueryDigest(intent, sources, policyDigest, queryId) {
  return sha256Canonical({ intent, sources, policy_digest: policyDigest, query_id: queryId });
}

function validateKnowledgeSources(sources) {
  if (!Array.isArray(sources) || sources.length === 0) throw new Error("knowledge query sources missing");
  for (const source of sources) {
    if (typeof source !== "string" || source === "") throw new Error("knowledge query source invalid");
  }
}

function validateKnowledgeResults(results) {
  if (!Array.isArray(results)) throw new Error("knowledge response results missing");
  for (const result of results) {
    if (!result || typeof result !== "object" || Array.isArray(result)) throw new Error("knowledge response result invalid");
    for (const field of ["source", "title", "summary", "freshness_at", "license"]) {
      if (typeof result[field] !== "string" || result[field] === "") throw new Error(`knowledge response result ${field} invalid`);
    }
  }
}

function knowledgeResultDigest(queryId, queryDigest, results) {
  return sha256Canonical({ query_id: queryId, query_digest: queryDigest, results });
}

function swarmPlanDigest(intent, steps) {
  return sha256Canonical({ intent, steps });
}

export function knowledgeQuery(requesterZone, intent, sources, policyDigest) {
  if (!requesterZone || !requesterZone.descriptor || !requesterZone.privateKey) throw new Error("knowledge query zone missing");
  if (typeof intent !== "string" || intent === "") throw new Error("knowledge query intent invalid");
  validateKnowledgeSources(sources);
  if (typeof policyDigest !== "string" || !/^[0-9a-f]{64}$/.test(policyDigest)) throw new Error("knowledge query policy digest invalid");
  const query_id = `knowledge-query:${randomUUID()}`;
  const query_digest = knowledgeQueryDigest(intent, sources, policyDigest, query_id);
  const queryBody = { intent, sources, policy_digest: policyDigest, query_id, query_digest };
  return {
    type: "FED_KNOWLEDGE_QUERY",
    zone: requesterZone.descriptor,
    query: { ...queryBody, query_signature: signObject(requesterZone.privateKey, queryBody) },
  };
}

export function verifyKnowledgeQuery(frame, trustedZones) {
  if (!frame || typeof frame !== "object" || Array.isArray(frame) || frame.type !== "FED_KNOWLEDGE_QUERY") throw new Error("expected FED_KNOWLEDGE_QUERY frame");
  if (!frame.zone || typeof frame.zone !== "object" || Array.isArray(frame.zone)) throw new Error("knowledge query zone missing");
  const zone = assertTrustedZoneDescriptor(verifyZoneDescriptor(frame.zone).descriptor, trustedZones, "knowledge query");
  if (!frame.query || typeof frame.query !== "object" || Array.isArray(frame.query)) throw new Error("knowledge query body missing");
  const { query_signature, ...queryBody } = frame.query;
  if (typeof queryBody.intent !== "string" || queryBody.intent === "") throw new Error("knowledge query intent invalid");
  validateKnowledgeSources(queryBody.sources);
  if (typeof queryBody.policy_digest !== "string" || !/^[0-9a-f]{64}$/.test(queryBody.policy_digest)) throw new Error("knowledge query policy digest invalid");
  if (typeof queryBody.query_id !== "string" || queryBody.query_id === "" || queryBody.query_id.includes("\0")) throw new Error("knowledge query id invalid");
  if (typeof queryBody.query_digest !== "string" || queryBody.query_digest !== knowledgeQueryDigest(queryBody.intent, queryBody.sources, queryBody.policy_digest, queryBody.query_id)) throw new Error("knowledge query digest invalid");
  if (typeof query_signature !== "string" || query_signature === "") throw new Error("knowledge query signature missing");
  if (!verifyObject(publicKeyFromDescriptor(zone), queryBody, query_signature)) {
    throw new Error("knowledge query signature verification failed");
  }
  return { zone, query: frame.query };
}

export function knowledgeResponse(gatewayZone, queryId, results, queryDigest) {
  if (!gatewayZone || !gatewayZone.descriptor || !gatewayZone.privateKey) throw new Error("knowledge response zone missing");
  if (typeof queryId !== "string" || queryId === "" || queryId.includes("\0")) throw new Error("knowledge response query_id invalid");
  if (typeof queryDigest !== "string" || !/^[0-9a-f]{64}$/.test(queryDigest)) throw new Error("knowledge response query_digest invalid");
  validateKnowledgeResults(results);
  const result_digest = knowledgeResultDigest(queryId, queryDigest, results);
  const responseBody = { query_id: queryId, query_digest: queryDigest, results, result_digest };
  return {
    type: "FED_KNOWLEDGE_RESPONSE",
    zone: gatewayZone.descriptor,
    response: { ...responseBody, response_signature: signObject(gatewayZone.privateKey, responseBody) },
  };
}

export function verifyKnowledgeResponse(frame, trustedZones, queryFrame) {
  if (!frame || typeof frame !== "object" || Array.isArray(frame) || frame.type !== "FED_KNOWLEDGE_RESPONSE") throw new Error("expected FED_KNOWLEDGE_RESPONSE frame");
  if (!frame.zone || typeof frame.zone !== "object" || Array.isArray(frame.zone)) throw new Error("knowledge response zone missing");
  const zone = assertTrustedZoneDescriptor(verifyZoneDescriptor(frame.zone).descriptor, trustedZones, "knowledge response");
  if (!frame.response || typeof frame.response !== "object" || Array.isArray(frame.response)) throw new Error("knowledge response body missing");
  const verifiedQuery = verifyKnowledgeQuery(queryFrame, trustedZones);
  const { response_signature, ...responseBody } = frame.response;
  if (typeof responseBody.query_id !== "string" || responseBody.query_id === "" || responseBody.query_id.includes("\0")) throw new Error("knowledge response query_id invalid");
  if (responseBody.query_id !== verifiedQuery.query.query_id) throw new Error("knowledge response query_id mismatch");
  if (responseBody.query_digest !== verifiedQuery.query.query_digest) throw new Error("knowledge response query_digest mismatch");
  validateKnowledgeResults(responseBody.results);
  if (typeof responseBody.result_digest !== "string" || responseBody.result_digest !== knowledgeResultDigest(responseBody.query_id, responseBody.query_digest, responseBody.results)) throw new Error("knowledge response result digest invalid");
  if (typeof response_signature !== "string" || response_signature === "") throw new Error("knowledge response signature missing");
  if (!verifyObject(publicKeyFromDescriptor(zone), responseBody, response_signature)) {
    throw new Error("knowledge response signature verification failed");
  }
  return { zone, response: frame.response };
}

export function swarmPlan(zone, swarmId, intent, steps, policyDigest) {
  if (!zone || !zone.descriptor || !zone.privateKey) throw new Error("swarm plan zone missing");
  if (typeof swarmId !== "string" || swarmId === "" || swarmId.includes("\0")) throw new Error("swarm plan swarm_id invalid");
  if (typeof intent !== "string" || intent === "") throw new Error("swarm plan intent invalid");
  validateSwarmPlanSteps(steps);
  if (typeof policyDigest !== "string" || !/^[0-9a-f]{64}$/.test(policyDigest)) throw new Error("swarm plan policy digest invalid");
  const plan_digest = swarmPlanDigest(intent, steps);
  const planBody = { swarm_id: swarmId, intent, steps, policy_digest: policyDigest, plan_digest };
  return {
    type: "FED_SWARM_PLAN",
    zone: zone.descriptor,
    plan: { ...planBody, plan_signature: signObject(zone.privateKey, planBody) },
  };
}

export function verifySwarmPlan(frame, trustedZones) {
  if (!frame || typeof frame !== "object" || Array.isArray(frame) || frame.type !== "FED_SWARM_PLAN") throw new Error("expected FED_SWARM_PLAN frame");
  if (!frame.zone || typeof frame.zone !== "object" || Array.isArray(frame.zone)) throw new Error("swarm plan zone missing");
  const zone = assertTrustedZoneDescriptor(verifyZoneDescriptor(frame.zone).descriptor, trustedZones, "swarm plan");
  if (!frame.plan || typeof frame.plan !== "object" || Array.isArray(frame.plan)) throw new Error("swarm plan body missing");
  const { plan_signature, ...planBody } = frame.plan;
  if (typeof planBody.swarm_id !== "string" || planBody.swarm_id === "" || planBody.swarm_id.includes("\0")) throw new Error("swarm plan swarm_id invalid");
  if (typeof planBody.intent !== "string" || planBody.intent === "") throw new Error("swarm plan intent invalid");
  validateSwarmPlanSteps(planBody.steps);
  if (typeof planBody.policy_digest !== "string" || !/^[0-9a-f]{64}$/.test(planBody.policy_digest)) throw new Error("swarm plan policy digest invalid");
  if (typeof planBody.plan_digest !== "string" || planBody.plan_digest !== swarmPlanDigest(planBody.intent, planBody.steps)) throw new Error("swarm plan digest invalid");
  if (typeof plan_signature !== "string" || plan_signature === "") throw new Error("swarm plan signature missing");
  if (!verifyObject(publicKeyFromDescriptor(zone), planBody, plan_signature)) {
    throw new Error("swarm plan signature verification failed");
  }
  return { zone, plan: frame.plan };
}

const SWARM_EXECUTION_BINDING_FIELDS = ["binding_signature", "execution_graph_digest", "format", "plan_digest", "steps", "swarm_id"];
const SWARM_EXECUTION_BINDING_STEP_FIELDS = ["capability", "depends_on", "step_id", "task_digest"];

function hasExactFields(value, expected) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const fields = Object.keys(value).sort();
  return fields.length === expected.length && fields.every((field, index) => field === expected[index]);
}

function executionBindingDependencies(value) {
  if (!Array.isArray(value)) throw new Error("execution binding step depends_on invalid");
  const seen = new Set();
  for (const dependency of value) {
    if (typeof dependency !== "string" || dependency === "" || dependency.includes("\0")) {
      throw new Error("execution binding step depends_on invalid");
    }
    if (seen.has(dependency)) throw new Error("execution binding duplicate dependency");
    seen.add(dependency);
  }
  return value;
}

function validateSwarmExecutionBinding(binding) {
  if (!hasExactFields(binding, SWARM_EXECUTION_BINDING_FIELDS)) throw new Error("execution binding fields invalid");
  if (binding.format !== "asp-swarm-execution-binding/v1") throw new Error("execution binding format invalid");
  if (typeof binding.swarm_id !== "string" || binding.swarm_id === "" || binding.swarm_id.includes("\0")) {
    throw new Error("execution binding swarm_id invalid");
  }
  if (typeof binding.plan_digest !== "string" || !/^[0-9a-f]{64}$/.test(binding.plan_digest)) {
    throw new Error("execution binding plan_digest invalid");
  }
  if (!Array.isArray(binding.steps) || binding.steps.length === 0) throw new Error("execution binding steps missing");
  const stepIds = new Set();
  for (const step of binding.steps) {
    if (!hasExactFields(step, SWARM_EXECUTION_BINDING_STEP_FIELDS)) throw new Error("execution binding step fields invalid");
    if (typeof step.step_id !== "string" || step.step_id === "" || step.step_id.includes("\0")) {
      throw new Error("execution binding step_id invalid");
    }
    if (stepIds.has(step.step_id)) throw new Error("execution binding duplicate step_id");
    stepIds.add(step.step_id);
    executionBindingDependencies(step.depends_on);
    if (typeof step.capability !== "string" || step.capability === "" || step.capability.includes("\0")) {
      throw new Error("execution binding step capability invalid");
    }
    if (typeof step.task_digest !== "string" || !/^[0-9a-f]{64}$/.test(step.task_digest)) {
      throw new Error("execution binding step task_digest invalid");
    }
  }
  if (typeof binding.execution_graph_digest !== "string" || !/^[0-9a-f]{64}$/.test(binding.execution_graph_digest)) {
    throw new Error("execution binding graph digest invalid");
  }
  if (typeof binding.binding_signature !== "string" || binding.binding_signature === "") {
    throw new Error("execution binding signature missing");
  }
}

function executionBindingPlan(verifiedPlan) {
  if (!verifiedPlan || typeof verifiedPlan !== "object" || Array.isArray(verifiedPlan)) throw new Error("verified swarm plan missing");
  if (!verifiedPlan.zone || !verifiedPlan.plan) throw new Error("verified swarm plan missing");
  const verified = verifySwarmPlan(
    { type: "FED_SWARM_PLAN", zone: verifiedPlan.zone, plan: verifiedPlan.plan },
    new Map([[verifiedPlan.zone.zid, verifiedPlan.zone]]),
  );
  const stepIds = new Set();
  const steps = verified.plan.steps.map((step) => {
    if (stepIds.has(step.step_id)) throw new Error("execution binding duplicate plan step_id");
    stepIds.add(step.step_id);
    const depends_on = executionBindingDependencies(step.depends_on ?? []);
    return { step_id: step.step_id, depends_on, capability: step.capability };
  });
  return { zone: verified.zone, plan: verified.plan, steps };
}

function executableBindingStep(step) {
  if (!step || typeof step !== "object" || Array.isArray(step)) throw new Error("execution binding executable step invalid");
  if (typeof step.step_id !== "string" || step.step_id === "" || step.step_id.includes("\0")) {
    throw new Error("execution binding executable step invalid");
  }
  const depends_on = executionBindingDependencies(step.depends_on);
  if (!step.task || typeof step.task !== "object" || Array.isArray(step.task) || typeof step.task.signature !== "string" || step.task.signature === "") {
    throw new Error("execution binding signed task missing");
  }
  return { step_id: step.step_id, depends_on, task: step.task };
}

function sameExecutionDependencies(left, right) {
  return left.length === right.length && left.every((dependency, index) => dependency === right[index]);
}

function executionBindingCapabilities(value) {
  if (!Array.isArray(value) || value.length === 0) throw new Error("execution binding worker capabilities invalid");
  const seen = new Set();
  for (const capability of value) {
    if (typeof capability !== "string" || capability === "" || capability.includes("\0")) {
      throw new Error("execution binding worker capabilities invalid");
    }
    if (seen.has(capability)) throw new Error("execution binding worker capability duplicate");
    seen.add(capability);
  }
  return value;
}

export function signedReceiptDigest(signedReceipt) {
  if (!signedReceipt || typeof signedReceipt !== "object" || Array.isArray(signedReceipt)) throw new Error("signed receipt missing");
  if (typeof signedReceipt.signature !== "string" || signedReceipt.signature === "") throw new Error("signed receipt signature missing");
  return sha256Canonical(signedReceipt);
}

export function swarmExecutionBinding(coordinatorZone, planFrame, executableSteps) {
  if (!coordinatorZone || !coordinatorZone.descriptor || !coordinatorZone.privateKey) throw new Error("execution binding coordinator zone missing");
  const verifiedPlan = verifySwarmPlan(planFrame, new Map([[coordinatorZone.descriptor.zid, coordinatorZone.descriptor]]));
  const plan = executionBindingPlan(verifiedPlan);
  if (!Array.isArray(executableSteps) || executableSteps.length !== plan.steps.length) {
    throw new Error("execution binding executable step count mismatch");
  }
  const steps = plan.steps.map((planStep, index) => {
    const executableStep = executableBindingStep(executableSteps[index]);
    if (executableStep.step_id !== planStep.step_id) throw new Error("execution binding executable step order mismatch");
    if (!sameExecutionDependencies(executableStep.depends_on, planStep.depends_on)) {
      throw new Error("execution binding executable depends_on mismatch");
    }
    return {
      step_id: planStep.step_id,
      depends_on: [...planStep.depends_on],
      capability: planStep.capability,
      task_digest: sha256Canonical(executableStep.task),
    };
  });
  const digestPreimage = { swarm_id: plan.plan.swarm_id, plan_digest: plan.plan.plan_digest, steps };
  const execution_graph_digest = sha256Canonical(digestPreimage);
  const body = {
    format: "asp-swarm-execution-binding/v1",
    swarm_id: plan.plan.swarm_id,
    plan_digest: plan.plan.plan_digest,
    steps,
    execution_graph_digest,
  };
  const binding = { ...body, binding_signature: signObject(coordinatorZone.privateKey, body) };
  validateSwarmExecutionBinding(binding);
  return binding;
}

export function verifySwarmExecutionBinding(binding, verifiedPlan, executableSteps, resolvedWorkers) {
  validateSwarmExecutionBinding(binding);
  const plan = executionBindingPlan(verifiedPlan);
  if (binding.swarm_id !== plan.plan.swarm_id) throw new Error("execution binding swarm_id mismatch");
  if (binding.plan_digest !== plan.plan.plan_digest) throw new Error("execution binding plan_digest mismatch");
  if (!Array.isArray(executableSteps) || !Array.isArray(resolvedWorkers) || binding.steps.length !== plan.steps.length || executableSteps.length !== plan.steps.length || resolvedWorkers.length !== plan.steps.length) {
    throw new Error("execution binding step count mismatch");
  }

  for (let index = 0; index < plan.steps.length; index += 1) {
    const boundStep = binding.steps[index];
    const planStep = plan.steps[index];
    const executableStep = executableBindingStep(executableSteps[index]);
    if (boundStep.step_id !== planStep.step_id) throw new Error("execution binding step order mismatch");
    if (executableStep.step_id !== planStep.step_id) throw new Error("execution binding executable step order mismatch");
    if (!sameExecutionDependencies(boundStep.depends_on, planStep.depends_on)) throw new Error("execution binding step depends_on mismatch");
    if (!sameExecutionDependencies(executableStep.depends_on, planStep.depends_on)) throw new Error("execution binding executable depends_on mismatch");
    if (boundStep.capability !== planStep.capability) throw new Error("execution binding step capability mismatch");
    if (boundStep.task_digest !== sha256Canonical(executableStep.task)) throw new Error("execution binding task_digest mismatch");
  }

  const digestPreimage = { swarm_id: binding.swarm_id, plan_digest: binding.plan_digest, steps: binding.steps };
  if (binding.execution_graph_digest !== sha256Canonical(digestPreimage)) throw new Error("execution binding graph digest mismatch");
  const { binding_signature, ...bindingBody } = binding;
  let validSignature = false;
  try {
    validSignature = verifyObject(publicKeyFromDescriptor(plan.zone), bindingBody, binding_signature);
  } catch {
    validSignature = false;
  }
  if (!validSignature) throw new Error("execution binding signature verification failed");

  for (let index = 0; index < plan.steps.length; index += 1) {
    const workerEntry = resolvedWorkers[index];
    const descriptor = workerEntry?.descriptor ?? workerEntry;
    let worker;
    try {
      worker = resolveAgent(new Map([[descriptor?.alias, workerEntry]]), descriptor?.alias).descriptor;
    } catch (error) {
      throw new Error(`execution binding worker invalid: ${error.message}`);
    }
    const capabilities = executionBindingCapabilities(worker.capabilities);
    if (!capabilities.includes(plan.steps[index].capability)) {
      throw new Error(`execution binding worker capability missing: ${plan.steps[index].step_id}`);
    }
  }

  const immutableSteps = Object.freeze(binding.steps.map((step) => Object.freeze({
    step_id: step.step_id,
    depends_on: Object.freeze([...step.depends_on]),
    capability: step.capability,
    task_digest: step.task_digest,
  })));
  return Object.freeze({
    swarmId: binding.swarm_id,
    planDigest: binding.plan_digest,
    steps: immutableSteps,
    executionGraphDigest: binding.execution_graph_digest,
  });
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


function zoneTrustDelegationBody(delegation) {
  if (!delegation || typeof delegation !== "object" || Array.isArray(delegation)) throw new Error("zone trust delegation missing");
  const { signature, ...body } = delegation;
  return body;
}

export function zoneTrustDelegation(authorityZone, delegateZoneDescriptor, capabilities) {
  if (!authorityZone?.descriptor || !authorityZone?.privateKey) throw new Error("authority zone missing");
  verifyZoneDescriptor(authorityZone.descriptor);
  const delegate = verifyZoneDescriptor(delegateZoneDescriptor).descriptor;
  if (!Array.isArray(capabilities)) throw new Error("zone trust delegation capabilities missing");
  const body = {
    delegator: authorityZone.zid,
    delegate: delegate.zid,
    capabilities: [...capabilities],
    delegator_descriptor: authorityZone.descriptor,
  };
  return { ...body, signature: signObject(authorityZone.privateKey, body) };
}

export function verifyZoneTrustDelegation(delegation, trustedAuthorityDescriptor) {
  if (!delegation || typeof delegation !== "object" || Array.isArray(delegation)) return false;
  if (!Array.isArray(delegation.capabilities)) return false;
  try {
    const { descriptor, publicKey } = verifyZoneDescriptor(trustedAuthorityDescriptor);
    if (delegation.delegator !== descriptor.zid) return false;
    if (delegation.delegator_descriptor?.zid !== descriptor.zid) return false;
    if (delegation.delegator_descriptor?.public_key_spki !== descriptor.public_key_spki) return false;
    return verifyObject(publicKey, zoneTrustDelegationBody(delegation), delegation.signature);
  } catch {
    return false;
  }
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

const SWARM_JOURNAL_FORMAT = "agnet-local-swarm-journal/v1";
const SWARM_JOURNAL_ZERO_HASH = "0".repeat(64);
const SWARM_TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;
const SWARM_JOURNAL_FIELDS = ["format", "hash", "kind", "payload", "prev_hash", "prior_state_version", "sequence", "state_version", "timestamp"];

function durableHex(value, label) {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) throw new Error(`${label} invalid`);
  return value;
}

function durableSafeInteger(value, label, minimum = 0) {
  if (!Number.isSafeInteger(value) || value < minimum) throw new Error(`${label} must be a safe integer`);
  return value;
}

function durableTimestamp(value, label) {
  if (typeof value !== "string" || !SWARM_TIMESTAMP_PATTERN.test(value) || Number.isNaN(Date.parse(value))) throw new Error(`${label} invalid`);
  return value;
}

const DURABLE_LEASE_CLAIM_FIELDS = ["attempt", "candidate", "candidate_index", "capability", "deadline", "fence", "owner", "step_id"];

function durableLeaseTimestamp(value, label) {
  durableTimestamp(value, label);
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$/.exec(value);
  if (!match || match[7]?.endsWith("0")) throw new Error(`${label} invalid`);
  const parsed = new Date(value);
  if (parsed.getUTCFullYear() !== Number(match[1]) || parsed.getUTCMonth() + 1 !== Number(match[2]) || parsed.getUTCDate() !== Number(match[3]) || parsed.getUTCHours() !== Number(match[4]) || parsed.getUTCMinutes() !== Number(match[5]) || parsed.getUTCSeconds() !== Number(match[6])) throw new Error(`${label} invalid`);
  return value;
}

function durableLeaseClaim(claim, label) {
  if (!hasExactFields(claim, DURABLE_LEASE_CLAIM_FIELDS) || typeof claim.step_id !== "string" || claim.step_id === "" || typeof claim.owner !== "string" || claim.owner === "" || !Number.isSafeInteger(claim.fence) || claim.fence < 1 || !Number.isSafeInteger(claim.attempt) || claim.attempt < 1 || !Number.isSafeInteger(claim.candidate_index) || claim.candidate_index < 0 || typeof claim.capability !== "string" || !durablePlainObject(claim.candidate, label)) throw new Error(`${label} invalid`);
  durableLeaseTimestamp(claim.deadline, `${label} deadline`);
  return claim;
}

function durableLeaseIdentityEqual(left, right) {
  return left.step_id === right.step_id && left.owner === right.owner && left.fence === right.fence && left.attempt === right.attempt && left.candidate_index === right.candidate_index && left.capability === right.capability && canonical(left.candidate) === canonical(right.candidate);
}

function durableDerivedSwarmStatus(steps) {
  if (steps.some((step) => step.status === "failed")) return "failed";
  if (steps.some((step) => step.status === "running")) return "running";
  if (steps.every((step) => step.status === "completed")) return "completed";
  if (steps.every((step) => step.status === "cancelled")) return "cancelled";
  return "open";
}

function durablePlainObject(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} invalid`);
  return value;
}

function durableFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const item of Object.values(value)) durableFreeze(item);
  return Object.freeze(value);
}

function swarmJournalHash(entry) {
  const { hash, ...preimage } = entry;
  return createHash("sha256").update(canonical(preimage)).digest("hex");
}

function durableEntryFields(entry, constructing = false) {
  const value = durablePlainObject(entry, "swarm journal entry");
  const fields = Object.keys(value).sort();
  const expected = constructing ? SWARM_JOURNAL_FIELDS.filter((field) => field !== "hash") : SWARM_JOURNAL_FIELDS;
  if (fields.length !== expected.length || !fields.every((field, index) => field === expected[index])) throw new Error("swarm journal entry fields invalid");
  if (value.format !== SWARM_JOURNAL_FORMAT) throw new Error("swarm journal format invalid");
  durableSafeInteger(value.sequence, "swarm journal sequence", 1);
  durableSafeInteger(value.prior_state_version, "swarm journal prior state version");
  durableSafeInteger(value.state_version, "swarm journal state version", 1);
  if (value.prior_state_version >= Number.MAX_SAFE_INTEGER || value.state_version !== value.prior_state_version + 1) throw new Error("swarm journal state versions are not contiguous");
  if (typeof value.kind !== "string" || value.kind === "" || value.kind.includes("\0")) throw new Error("swarm journal kind invalid");
  durablePlainObject(value.payload, "swarm journal payload");
  durableTimestamp(value.timestamp, "swarm journal timestamp");
  durableHex(value.prev_hash, "swarm journal previous hash");
  if (!constructing) durableHex(value.hash, "swarm journal hash");
}

/** Construct one immutable, canonical journal entry. This pure helper performs no I/O. */
export function swarmJournalEntry(entry) {
  durableEntryFields(entry, true);
  const result = { ...entry, payload: structuredClone(entry.payload) };
  result.hash = swarmJournalHash(result);
  return durableFreeze(result);
}

const DURABLE_GENERATION_PIN_FIELDS = ["passphrase_file", "record_digest", "store_path"];
const DURABLE_SPEC_REQUIRED_FIELDS = ["authority_generation_pin", "binding", "plan", "request", "schema_version", "steps", "swarm_id"];
const DURABLE_SPEC_OPTIONAL_FIELDS = ["local_authority"];
const DURABLE_STEP_REQUIRED_FIELDS = ["attempt_policy", "candidates", "step_id"];
const DURABLE_STEP_OPTIONAL_FIELDS = ["capability", "depends_on", "task_digest", "task_id"];
const DURABLE_CANDIDATE_REQUIRED_FIELDS = ["aid", "alias", "descriptor_digest", "generation_pin", "public_key_spki"];
const DURABLE_CANDIDATE_OPTIONAL_FIELDS = ["descriptor", "runtime", "runtime_kind", "zone_binding"];

function durableGenerationPin(value, label, required) {
  if (!hasExactFields(value, DURABLE_GENERATION_PIN_FIELDS)) throw new Error(`${label} invalid`);
  for (const field of ["store_path", "passphrase_file"]) {
    if (typeof value[field] !== "string" || (required && value[field] === "")) throw new Error(`${label} invalid`);
  }
  if (typeof value.record_digest !== "string" || (required && !/^[0-9a-f]{64}$/.test(value.record_digest)) || (!required && value.record_digest !== "" && !/^[0-9a-f]{64}$/.test(value.record_digest))) throw new Error(`${label} invalid`);
}

function durableFrozenJson(value, label) {
  if (typeof value !== "string" || value === "") throw new Error(`${label} invalid`);
  return durableCanonicalJson(Buffer.from(value), label);
}

function durableFrozenCandidate(candidate, authority, frozen) {
  if (!hasRequiredAllowedFields(candidate, DURABLE_CANDIDATE_REQUIRED_FIELDS, DURABLE_CANDIDATE_OPTIONAL_FIELDS)) throw new Error("swarm durable worker verification pin invalid");
  if (typeof candidate.alias !== "string" || candidate.alias === "" || candidate.alias.includes("\0") || typeof candidate.aid !== "string" || candidate.aid === "" || candidate.aid.includes("\0") || !/^[0-9a-f]{64}$/.test(candidate.descriptor_digest)) throw new Error("swarm durable worker verification pin invalid");
  durableGenerationPin(candidate.generation_pin, "swarm durable worker verification pin", true);
  let publicKey;
  try { publicKey = publicKeyFromDescriptor({ public_key_spki: candidate.public_key_spki }); } catch { throw new Error("swarm durable worker verification pin invalid"); }
  if (computeAid(publicKey) !== candidate.aid) throw new Error("swarm durable worker verification pin invalid");
  if (candidate.runtime !== undefined && (!durablePlainObject(candidate.runtime, "swarm durable worker runtime") || (candidate.runtime_kind !== undefined && candidate.runtime_kind !== "docker" && candidate.runtime_kind !== "apple-container"))) throw new Error("swarm durable worker runtime invalid");
  if (!frozen) return;
  if (typeof candidate.descriptor !== "string" || typeof candidate.zone_binding !== "string") throw new Error("swarm durable worker descriptor pin invalid");
  const descriptor = durableFrozenJson(candidate.descriptor, "swarm durable worker descriptor");
  const zoneBinding = durableFrozenJson(candidate.zone_binding, "swarm durable worker zone binding");
  if (!durablePlainObject(descriptor, "swarm durable worker descriptor") || createHash("sha256").update(canonical(descriptor)).digest("hex") !== candidate.descriptor_digest || descriptor.aid !== candidate.aid || descriptor.public_key_spki !== candidate.public_key_spki) throw new Error("swarm durable worker descriptor pin invalid");
  try { resolveAgent(new Map([[candidate.alias, { descriptor, zone: authority, zone_binding: zoneBinding }]]), candidate.alias); } catch { throw new Error("swarm durable worker descriptor pin invalid"); }
}

function durableSpecSteps(payload) {
  if (!hasExactFields(payload, ["schema_version", "spec"]) || payload.schema_version !== 1 || !hasRequiredAllowedFields(payload.spec, DURABLE_SPEC_REQUIRED_FIELDS, DURABLE_SPEC_OPTIONAL_FIELDS) || payload.spec.schema_version !== 1) throw new Error("swarm opened payload invalid");
  const { swarm_id: swarmId, steps } = payload.spec;
  if (typeof swarmId !== "string" || swarmId === "" || swarmId.includes("\0") || !Array.isArray(steps) || steps.length === 0) throw new Error("swarm opened payload invalid");
  for (const field of ["plan", "binding", "request"]) durableCanonicalJson(durableBase64(payload.spec[field], `swarm durable ${field}`), `swarm durable ${field}`);
  const frozen = payload.spec.local_authority !== undefined;
  let authority;
  if (frozen) {
    durableGenerationPin(payload.spec.authority_generation_pin, "swarm durable local authority pin", true);
    try { authority = verifyZoneDescriptor(payload.spec.local_authority).descriptor; } catch { throw new Error("swarm durable local authority pin invalid"); }
  } else {
    durableGenerationPin(payload.spec.authority_generation_pin, "swarm durable local authority pin", false);
  }
  const ids = new Set();
  return steps.map((step) => {
    if (!hasRequiredAllowedFields(step, DURABLE_STEP_REQUIRED_FIELDS, DURABLE_STEP_OPTIONAL_FIELDS) || typeof step.step_id !== "string" || step.step_id === "" || step.step_id.includes("\0") || ids.has(step.step_id) || !hasExactFields(step.attempt_policy, ["max_attempts"]) || !Number.isSafeInteger(step.attempt_policy.max_attempts) || step.attempt_policy.max_attempts < 1 || !Array.isArray(step.candidates) || step.candidates.length === 0) throw new Error("swarm durable step invalid");
    if (frozen && (typeof step.task_id !== "string" || step.task_id === "" || step.task_id.includes("\0") || !/^[0-9a-f]{64}$/.test(step.task_digest))) throw new Error("swarm durable signed task identity invalid");
    const dependencies = step.depends_on ?? [];
    if (!Array.isArray(dependencies) || new Set(dependencies).size !== dependencies.length || dependencies.some((dependency) => typeof dependency !== "string" || !ids.has(dependency))) throw new Error("swarm durable step dependency invalid");
    for (const candidate of step.candidates) durableFrozenCandidate(candidate, authority, frozen);
    ids.add(step.step_id);
    return { step_id: step.step_id, depends_on: [...dependencies], status: "pending", attempts: 0, observations: [] };
  });
}

function durableWave(payload, label, payloadFields = ["schema_version", "wave"]) {
  if (!hasExactFields(payload, payloadFields) || payload.schema_version !== 1 || !hasExactFields(payload.wave, ["recorded_at", "step_ids"]) || !Array.isArray(payload.wave.step_ids) || payload.wave.step_ids.length === 0 || payload.wave.step_ids.some((stepId) => typeof stepId !== "string" || stepId === "")) throw new Error(`${label} wave invalid`);
  if (new Set(payload.wave.step_ids).size !== payload.wave.step_ids.length) throw new Error(`${label} wave duplicate step`);
  durableTimestamp(payload.wave.recorded_at, `${label} recorded_at`);
  return payload.wave;
}

function durableBase64(value, label) {
  if (typeof value !== "string" || value === "" || value.includes("=") || !/^[A-Za-z0-9_-]+$/.test(value)) throw new Error(`${label} invalid`);
  let decoded;
  try { decoded = Buffer.from(value, "base64url"); } catch { throw new Error(`${label} invalid`); }
  if (decoded.toString("base64url") !== value) throw new Error(`${label} invalid`);
  return decoded;
}

function durableCanonicalJson(bytes, label) {
  let value;
  try { value = JSON.parse(bytes.toString("utf8")); } catch { throw new Error(`${label} invalid`); }
  if (canonical(value) !== bytes.toString("utf8")) throw new Error(`${label} noncanonical`);
  return value;
}

function durableAuthority(state) {
  const authority = state.spec?.local_authority;
  if (!authority || typeof authority !== "object") throw new Error("swarm frozen local authority missing");
  return authority;
}

function durableClaimEqual(left, right) {
  return canonical(left) === canonical(right);
}

function durableCloseReplayEvidence(state) {
  const binding = durableCanonicalJson(durableBase64(state.spec.binding, "swarm durable binding"), "swarm durable binding");
  if (!durablePlainObject(binding, "swarm close binding") || binding.format !== "asp-swarm-execution-binding/v1" || binding.swarm_id !== state.spec.swarm_id || !/^[0-9a-f]{64}$/.test(binding.plan_digest) || !/^[0-9a-f]{64}$/.test(binding.execution_graph_digest)) throw new Error("swarm close binding invalid");
  const receipts = state.spec.steps.map((specStep) => {
    const step = state.steps.find((item) => item.step_id === specStep.step_id);
    const receipt = state.receipts?.[specStep.step_id];
    if (!step || step.status !== "completed" || !receipt || typeof specStep.task_id !== "string" || specStep.task_id === "" || !/^[0-9a-f]{64}$/.test(receipt.digest)) throw new Error("swarm close receipt missing");
    return {
      step_id: specStep.step_id,
      task_id: specStep.task_id,
      signed_receipt_digest: receipt.digest,
      observations: step.observations.map(({ claim, outcome, observed_at }) => ({ attempt: claim.attempt, candidate: claim.candidate, owner: claim.owner, fence: claim.fence, outcome, observed_at })),
    };
  });
  const referenced = new Set(state.spec.steps.flatMap((step) => step.depends_on ?? []));
  const terminal = state.spec.steps.filter((step) => !referenced.has(step.step_id));
  if (terminal.length !== 1) throw new Error("single terminal step required");
  const terminalIndex = state.spec.steps.findIndex((step) => step.step_id === terminal[0].step_id);
  const result = state.receipts?.[terminal[0].step_id]?.result;
  if (!durablePlainObject(result, "terminal result artifact")) throw new Error("terminal result artifact missing");
  return {
    format: "asp-swarm-close/v2",
    swarm_id: state.spec.swarm_id,
    plan_digest: binding.plan_digest,
    execution_graph_digest: binding.execution_graph_digest,
    step_receipts: receipts,
    final_output: { step_id: terminal[0].step_id, task_id: terminal[0].task_id, signed_receipt_digest: receipts[terminalIndex].signed_receipt_digest, artifact: result, selection_rule: "single-terminal-result" },
    scheduler: { mode: "parallel-ready-dag", ready_waves: state.ready_waves ?? [], dispatch_waves: state.dispatch_waves ?? [] },
  };
}

function verifyDurableCloseReplay(close, state) {
  const expected = durableCloseReplayEvidence(state);
  if (!hasExactFields(close, [...Object.keys(expected), "close_signature"].sort())) throw new Error("swarm close replay fields invalid");
  for (const [field, value] of Object.entries(expected)) {
    if (canonical(close[field]) !== canonical(value)) throw new Error(`swarm close ${field} evidence mismatch`);
  }
}

function durableArtifactTriple(value, label) {
  if (!hasExactFields(value, ["manifest_hash", "sha256", "uri"]) || !/^[0-9a-f]{64}$/.test(value.sha256) || value.manifest_hash !== value.sha256 || value.uri !== `artifact://local/sha256/${value.sha256}`) throw new Error(`${label} invalid`);
  return value;
}

function durableReceiptMatchesCommit(state, specStep, claim, payload, receipt) {
  const requiredReceipt = ["attempt", "auxiliary", "capability", "fence", "format", "graph_digest", "result", "signature", "step_id", "swarm_id", "task_digest", "worker_aid", "worker_generation_pin"];
  const bindingBytes = durableBase64(state.spec.binding, "swarm durable binding");
  if (!hasExactFields(payload, ["auxiliary", "claim", "receipt", "receipt_digest", "result", "schema_version"]) || !hasRequiredAllowedFields(receipt, requiredReceipt, ["dependencies", "task_id"]) || !Array.isArray(payload.auxiliary) || !Array.isArray(receipt.auxiliary)) return false;
  try {
    durableArtifactTriple(payload.result, "swarm receipt result");
    for (const artifact of payload.auxiliary) durableArtifactTriple(artifact, "swarm receipt auxiliary");
    durableArtifactTriple(receipt.result, "swarm receipt result");
    for (const artifact of receipt.auxiliary) durableArtifactTriple(artifact, "swarm receipt auxiliary");
  } catch { return false; }
  if (receipt.format !== "agnet-receipt/v2" || receipt.swarm_id !== state.spec.swarm_id || receipt.step_id !== claim.step_id || receipt.task_digest !== specStep.task_digest || receipt.graph_digest !== createHash("sha256").update(bindingBytes).digest("hex") || receipt.capability !== (specStep.capability ?? "") || receipt.worker_aid !== claim.candidate?.aid || receipt.attempt !== claim.attempt || receipt.fence !== claim.fence || canonical(receipt.worker_generation_pin) !== canonical(claim.candidate?.generation_pin) || canonical(receipt.result) !== canonical(payload.result) || canonical(receipt.auxiliary) !== canonical(payload.auxiliary)) return false;
  if (specStep.task_id && receipt.task_id !== specStep.task_id) return false;
  const expectedDependencies = specStep.depends_on ?? [];
  const receiptDependencies = receipt.dependencies ?? [];
  if (!Array.isArray(receiptDependencies) || receiptDependencies.length !== expectedDependencies.length) return false;
  for (const dependency of receiptDependencies) {
    if (!hasExactFields(dependency, ["artifact", "step_id"]) || typeof dependency.step_id !== "string" || dependency.step_id === "") return false;
    try { durableArtifactTriple(dependency.artifact, "swarm receipt dependency"); } catch { return false; }
  }
  const dependencies = new Map(receiptDependencies.map((dependency) => [dependency.step_id, dependency.artifact]));
  return dependencies.size === expectedDependencies.length && expectedDependencies.every((stepId) => canonical(dependencies.get(stepId)) === canonical(state.receipts?.[stepId]?.result));
}

function durableOutputVerifiedPayload(payload) {
  for (const field of ["canonical_proof_digest", "close_digest", "proof_digest", "submission_digest", "trust_inputs_digest"]) durableHex(payload[field], `output ${field}`);
  for (const field of ["swarm_id", "verification_id", "verified_at", "verifier_aid", "verifier_zone"]) {
    if (typeof payload[field] !== "string" || payload[field] === "" || payload[field].includes("\0")) throw new Error(`output ${field} invalid`);
  }
  if (payload.verification_id.length > 256 || payload.prior_status !== "closing" || payload.next_status !== "completed" || payload.replay_decision !== "accepted" || !durablePlainObject(payload.final_output, "output final output")) throw new Error("output verification invalid");
  durableTimestamp(payload.completed_at, "output completed_at");
  const signature = durableBase64(payload.completion_signature, "output completion signature");
  if (signature.length !== 64) throw new Error("output completion signature invalid");
}

function reduceDurableEntry(prior, entry) {
  if (entry.prior_state_version !== prior.version) throw new Error("swarm journal state versions are not contiguous");
  if (prior.status === "disbanded") throw new Error("swarm is terminal");
  if (prior.status === "failed" && entry.kind !== "lease.expired") throw new Error("swarm is failed");
  if (entry.kind.startsWith("future.")) return { ...prior, version: entry.state_version };
  const next = structuredClone(prior);
  if (entry.kind === "swarm.opened") {
    if (prior.version !== 0) throw new Error("swarm already opened");
    next.spec = structuredClone(entry.payload.spec);
    next.steps = durableSpecSteps(entry.payload);
    next.ready_waves = [];
    next.dispatch_waves = [];
    next.status = "open";
  } else if (entry.kind === "wave.ready") {
    if (prior.version === 0 || prior.status === "closing" || prior.status === "completed" || prior.ready_wave || prior.steps.some((step) => step.status === "running")) throw new Error("swarm ready wave does not match Kahn layer");
    const wave = durableWave(entry.payload, "swarm ready");
    durableLeaseTimestamp(entry.timestamp, "swarm ready timestamp");
    durableLeaseTimestamp(wave.recorded_at, "swarm ready recorded_at");
    const expectedStepIds = prior.steps.filter((step) => step.status === "pending" && step.depends_on.every((dependency) => prior.steps.find((item) => item.step_id === dependency)?.status === "completed")).map((step) => step.step_id);
    if (wave.recorded_at !== entry.timestamp || canonical(wave.step_ids) !== canonical(expectedStepIds)) throw new Error("swarm ready wave does not match Kahn layer");
    next.ready_wave = structuredClone(wave);
    next.ready_waves.push(structuredClone(wave));
  } else if (entry.kind === "wave.dispatched") {
    if (prior.version === 0 || !prior.ready_wave || prior.status === "closing" || prior.status === "completed") throw new Error("swarm dispatch requires ready wave");
    const wave = durableWave(entry.payload, "swarm dispatch", ["claims", "schema_version", "wave"]);
    durableLeaseTimestamp(entry.timestamp, "swarm dispatch timestamp");
    if (!hasExactFields(entry.payload, ["claims", "schema_version", "wave"]) || canonical(wave) !== canonical(prior.ready_wave) || !Array.isArray(entry.payload.claims) || entry.payload.claims.length !== wave.step_ids.length || (prior.leases ?? []).length !== 0) throw new Error("swarm dispatch readiness invalid");
    const claims = [];
    for (const [index, claim] of entry.payload.claims.entries()) {
      durableLeaseClaim(claim, "swarm dispatch claim");
      const step = next.steps.find((item) => item.step_id === claim.step_id);
      const specStep = prior.spec.steps.find((item) => item.step_id === claim.step_id);
      if (claim.step_id !== wave.step_ids[index] || claim.fence !== prior.last_fence + index + 1 || claim.attempt !== step?.attempts + 1 || claim.attempt > specStep?.attempt_policy.max_attempts || claim.candidate_index !== claim.attempt - 1 || claim.candidate_index >= specStep?.candidates.length || claim.capability !== (specStep?.capability ?? "") || canonical(claim.candidate) !== canonical(specStep?.candidates[claim.candidate_index]) || claim.deadline <= entry.timestamp) throw new Error("swarm dispatch readiness invalid");
      step.status = "running";
      step.attempts = claim.attempt;
      next.last_fence = claim.fence;
      step.observations.push({ claim: structuredClone(claim), outcome: "dispatched", observed_at: entry.timestamp });
      claims.push(structuredClone(claim));
    }
    next.leases = claims;
    delete next.ready_wave;
    next.dispatch_waves.push({ wave: structuredClone(wave), attempts: structuredClone(claims) });
    next.status = "running";
  } else if (entry.kind === "lease.renewed") {
    if (prior.version === 0 || !hasExactFields(entry.payload, ["claim", "schema_version"]) || entry.payload.schema_version !== 1) throw new Error("lease renewal payload invalid");
    const claim = durableLeaseClaim(entry.payload.claim, "lease renewal claim");
    durableLeaseTimestamp(entry.timestamp, "lease renewal timestamp");
    const leaseIndex = (prior.leases ?? []).findIndex((item) => item.step_id === claim.step_id);
    const lease = prior.leases?.[leaseIndex];
    if (!lease || !durableLeaseIdentityEqual(lease, claim) || entry.timestamp > lease.deadline || claim.deadline <= entry.timestamp || claim.deadline <= lease.deadline) throw new Error("lease renewal does not match live lease");
    next.leases[leaseIndex] = structuredClone(claim);
  } else if (entry.kind === "lease.observed") {
    if (prior.version === 0 || !hasExactFields(entry.payload, ["claim", "outcome", "schema_version"]) || entry.payload.schema_version !== 1 || typeof entry.payload.outcome !== "string" || entry.payload.outcome === "") throw new Error("swarm observation invalid");
    const claim = durableLeaseClaim(entry.payload.claim, "swarm observation claim");
    durableLeaseTimestamp(entry.timestamp, "swarm observation timestamp");
    const lease = (prior.leases ?? []).find((item) => item.step_id === claim.step_id);
    if (!lease || !durableClaimEqual(lease, claim) || entry.timestamp >= claim.deadline) throw new Error("swarm observation does not match live lease");
    const step = next.steps.find((item) => item.step_id === claim.step_id);
    if (!step || step.status !== "running" || step.attempts !== claim.attempt) throw new Error("swarm observation step state invalid");
    step.observations.push({ claim: structuredClone(claim), outcome: entry.payload.outcome, observed_at: entry.timestamp });
  } else if (entry.kind === "lease.expired") {
    if (prior.version === 0 || !hasExactFields(entry.payload, ["claims", "now", "schema_version"]) || entry.payload.schema_version !== 1 || entry.payload.now !== entry.timestamp || !Array.isArray(entry.payload.claims) || entry.payload.claims.length === 0) throw new Error("lease expiry payload invalid");
    durableLeaseTimestamp(entry.timestamp, "lease expiry timestamp");
    durableLeaseTimestamp(entry.payload.now, "lease expiry now");
    for (const claim of entry.payload.claims) {
      durableLeaseClaim(claim, "lease expiry claim");
      const leaseIndex = next.leases.findIndex((item) => item.step_id === claim.step_id);
      const lease = next.leases[leaseIndex];
      if (!lease || !durableClaimEqual(lease, claim) || claim.deadline > entry.payload.now) throw new Error("lease expiry does not match live lease");
      const step = next.steps.find((item) => item.step_id === claim.step_id);
      const specStep = prior.spec.steps.find((item) => item.step_id === claim.step_id);
      if (!step || !specStep || step.status !== "running" || step.attempts !== claim.attempt) throw new Error("lease expiry step state invalid");
      step.observations.push({ claim: structuredClone(claim), outcome: "expired", observed_at: entry.payload.now });
      step.status = step.attempts >= specStep.attempt_policy.max_attempts ? "failed" : "pending";
      next.leases.splice(leaseIndex, 1);
    }
    delete next.ready_wave;
  } else if (entry.kind === "receipt.committed") {
    if (prior.status !== "running" || !hasExactFields(entry.payload, ["auxiliary", "claim", "receipt", "receipt_digest", "result", "schema_version"]) || entry.payload.schema_version !== 1) throw new Error("swarm receipt invalid");
    const claim = durableLeaseClaim(entry.payload.claim, "swarm receipt claim");
    durableLeaseTimestamp(entry.timestamp, "swarm receipt timestamp");
    const step = next.steps.find((item) => item.step_id === claim.step_id);
    const lease = (prior.leases ?? []).find((item) => item.step_id === claim.step_id);
    const receiptBytes = durableBase64(entry.payload.receipt, "swarm receipt");
    if (!step || step.status !== "running" || step.attempts !== claim.attempt || !lease || !durableClaimEqual(lease, claim) || entry.timestamp >= claim.deadline || durableHex(entry.payload.receipt_digest, "swarm receipt digest") !== createHash("sha256").update(receiptBytes).digest("hex")) throw new Error("swarm receipt does not match live lease");
    const receipt = durableCanonicalJson(receiptBytes, "swarm receipt");
    const specStep = prior.spec.steps.find((item) => item.step_id === claim.step_id);
    if (!specStep || !durableReceiptMatchesCommit(prior, specStep, claim, entry.payload, receipt) || !verifyObject(publicKeyFromDescriptor({ public_key_spki: claim.candidate?.public_key_spki }), (() => { const { signature, ...body } = receipt; return body; })(), receipt.signature)) throw new Error("swarm receipt signature invalid");
    step.status = "completed";
    next.leases = (prior.leases ?? []).filter((item) => item.step_id !== claim.step_id);
    step.observations.push({ claim: structuredClone(claim), outcome: "receipt.committed", observed_at: entry.timestamp });
    next.receipts ??= {};
    next.receipts[claim.step_id] = { digest: entry.payload.receipt_digest, result: structuredClone(entry.payload.result) };
  } else if (entry.kind === "close.stored") {
    if (prior.status !== "completed" || (prior.leases ?? []).length !== 0 || !hasExactFields(entry.payload, ["close", "digest", "schema_version"]) || entry.payload.schema_version !== 1) throw new Error("illegal swarm close");
    const closeBytes = durableBase64(entry.payload.close, "swarm close");
    if (durableHex(entry.payload.digest, "swarm close digest") !== createHash("sha256").update(closeBytes).digest("hex")) throw new Error("swarm close digest invalid");
    const close = durableCanonicalJson(closeBytes, "swarm close");
    const authority = durableAuthority(prior);
    verifySwarmCloseV2({ type: "FED_SWARM_CLOSE", swarm_id: prior.spec.swarm_id, zone: authority, close }, new Map([[authority.zid, authority]]));
    next.stored_close = { bytes: closeBytes.toString("base64url"), digest: entry.payload.digest, close };
    verifyDurableCloseReplay(close, prior);
    next.status = "closing";
  } else if (entry.kind === "output.verification_failed") {
    if (prior.status !== "closing" || !hasExactFields(entry.payload, ["error_code", "schema_version", "submission_digest"]) || entry.payload.schema_version !== 1 || !/^[0-9a-f]{64}$/.test(entry.payload.submission_digest) || entry.payload.error_code !== "output_proof_rejected") throw new Error("output verification failure invalid");
  } else if (entry.kind === "output.verified") {
    if (prior.status !== "closing" || !prior.stored_close || !hasExactFields(entry.payload, ["canonical_proof_digest", "close", "close_digest", "completed_at", "completion_signature", "final_output", "next_status", "prior_status", "proof", "proof_digest", "replay_decision", "schema_version", "submission_digest", "swarm_id", "trust_inputs_digest", "verification_id", "verified_at", "verifier_aid", "verifier_zone"]) || entry.payload.schema_version !== 1) throw new Error("output verification invalid");
    const payload = entry.payload;
    durableOutputVerifiedPayload(payload);
    const proofBytes = durableBase64(payload.proof, "output proof");
    const closeBytes = durableBase64(payload.close, "output close");
    if (durableHex(payload.canonical_proof_digest, "output proof digest") !== createHash("sha256").update(proofBytes).digest("hex") || durableHex(payload.close_digest, "output close digest") !== prior.stored_close.digest || closeBytes.toString("base64url") !== prior.stored_close.bytes || payload.swarm_id !== prior.spec.swarm_id || payload.prior_status !== "closing" || payload.next_status !== "completed" || payload.completed_at !== entry.timestamp || !/^[0-9a-f]{64}$/.test(payload.trust_inputs_digest)) throw new Error("output verification binding invalid");
    const proof = durableCanonicalJson(proofBytes, "output proof");
    const finalOutput = durableCanonicalJson(Buffer.from(canonical(payload.final_output)), "output final output");
    if (canonical(finalOutput) !== canonical(prior.stored_close.close.final_output)) throw new Error("output verification evidence mismatch");
    const { completion_signature, ...body } = payload;
    if (typeof completion_signature !== "string" || !verifyObject(publicKeyFromDescriptor(durableAuthority(prior)), body, completion_signature)) throw new Error("output verification signature invalid");
    next.output_verification = { close_digest: payload.close_digest, trust_inputs_digest: payload.trust_inputs_digest, digest: createHash("sha256").update(canonical(payload)).digest("hex"), completed_at: payload.completed_at, proof: proofBytes.toString("base64url") };
    next.status = "completed";
  } else if (entry.kind === "swarm.disbanded") {
    if (prior.status !== "completed" || !prior.output_verification || entry.timestamp !== prior.output_verification.completed_at || !hasExactFields(entry.payload, ["digest", "disband", "schema_version"]) || entry.payload.schema_version !== 1) throw new Error("swarm disband invalid");
    const disbandBytes = durableBase64(entry.payload.disband, "swarm disband");
    if (durableHex(entry.payload.digest, "swarm disband digest") !== createHash("sha256").update(disbandBytes).digest("hex")) throw new Error("swarm disband digest invalid");
    const disband = durableCanonicalJson(disbandBytes, "swarm disband");
    const close = prior.stored_close.close;
    verifySwarmDisband(disband, durableAuthority(prior), { swarm_id: prior.spec.swarm_id, plan_digest: close.plan_digest, execution_graph_digest: close.execution_graph_digest, close_digest: prior.stored_close.digest, output_verification_digest: prior.output_verification.digest, completed_at: prior.output_verification.completed_at });
    next.disband = { bytes: disbandBytes.toString("base64url"), digest: entry.payload.digest, disband };
    next.status = "disbanded";
  } else {
    throw new Error("swarm journal transition kind invalid");
  }
  if (["wave.ready", "wave.dispatched", "lease.renewed", "lease.observed", "lease.expired", "receipt.committed"].includes(entry.kind)) next.status = durableDerivedSwarmStatus(next.steps);
  next.version = entry.state_version;
  return next;
}

/** Verify exact journal preimages and replay the recognized immutable state machine without I/O. */
export function verifySwarmJournal(entries) {
  if (!Array.isArray(entries)) throw new Error("swarm journal entries invalid");
  let previousHash = SWARM_JOURNAL_ZERO_HASH;
  let previousVersion = 0;
  let state = { version: 0, status: "", steps: [], leases: [], last_fence: 0 };
  for (const [index, entry] of entries.entries()) {
    durableEntryFields(entry);
    if (entry.sequence !== index + 1) throw new Error("swarm journal sequence invalid");
    if (entry.prior_state_version !== previousVersion || entry.prev_hash !== previousHash) throw new Error("swarm journal chain invalid");
    if (entry.hash !== swarmJournalHash(entry)) throw new Error("swarm journal hash invalid");
    state = reduceDurableEntry(state, entry);
    previousHash = entry.hash;
    previousVersion = entry.state_version;
  }
  return durableFreeze({ entries: entries.map((entry) => durableFreeze(structuredClone(entry))), head: previousHash, state });
}

const SWARM_DISBAND_FIELDS = ["close_digest", "disband_signature", "disbanded_at", "execution_graph_digest", "format", "output_verification_digest", "plan_digest", "swarm_id"];

function swarmDisbandBody(value) {
  const { disband_signature, ...body } = value;
  return body;
}

function validateSwarmDisbandBinding(binding) {
  durablePlainObject(binding, "swarm disband binding");
  for (const field of ["swarm_id", "plan_digest", "execution_graph_digest", "close_digest", "output_verification_digest"]) {
    if (typeof binding[field] !== "string" || binding[field] === "") throw new Error("swarm disband binding invalid");
  }
  for (const field of ["plan_digest", "execution_graph_digest", "close_digest", "output_verification_digest"]) durableHex(binding[field], `swarm disband ${field}`);
  durableTimestamp(binding.completed_at, "swarm disband timestamp");
}

/** Create a signed immutable disband record from completed verified output only. */
export function swarmDisband(authorityZone, completedOutput) {
  if (!authorityZone?.privateKey || !authorityZone?.descriptor) throw new Error("swarm disband authority missing");
  validateSwarmDisbandBinding(completedOutput);
  const body = { format: "asp-swarm-disband/v1", swarm_id: completedOutput.swarm_id, plan_digest: completedOutput.plan_digest, execution_graph_digest: completedOutput.execution_graph_digest, close_digest: completedOutput.close_digest, output_verification_digest: completedOutput.output_verification_digest, disbanded_at: completedOutput.completed_at };
  return durableFreeze({ ...body, disband_signature: signObject(authorityZone.privateKey, body) });
}

/** Verify a canonical signed disband record against frozen completed-output bindings. */
export function verifySwarmDisband(disband, authorityDescriptor, completedOutput) {
  if (!hasExactFields(disband, SWARM_DISBAND_FIELDS) || disband.format !== "asp-swarm-disband/v1") throw new Error("swarm disband fields invalid");
  validateSwarmDisbandBinding({ ...completedOutput, completed_at: completedOutput?.completed_at });
  for (const field of ["swarm_id", "plan_digest", "execution_graph_digest", "close_digest", "output_verification_digest"]) {
    if (disband[field] !== completedOutput[field]) throw new Error("swarm disband binding mismatch");
  }
  if (disband.disbanded_at !== completedOutput.completed_at) throw new Error("swarm disband timestamp mismatch");
  durableTimestamp(disband.disbanded_at, "swarm disband timestamp");
  if (typeof disband.disband_signature !== "string" || disband.disband_signature === "" || !verifyObject(publicKeyFromDescriptor(authorityDescriptor), swarmDisbandBody(disband), disband.disband_signature)) throw new Error("swarm disband signature invalid");
  return durableFreeze({ disband: structuredClone(disband), digest: createHash("sha256").update(canonical(disband)).digest("hex") });
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

function receiptCheckpointRefs(value) {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string" || item === "")) throw new Error("checkpoint ref invalid");
  return value;
}

function receiptCheckpoints(value) {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.some((item) => !item || typeof item !== "object" || Array.isArray(item))) throw new Error("checkpoint invalid");
  return value;
}

function verifyReceiptCheckpoints(publicKey, receipt) {
  const refs = receiptCheckpointRefs(receipt.checkpoint_refs);
  const checkpoints = receiptCheckpoints(receipt.checkpoints);
  if (refs.length !== checkpoints.length) throw new Error("receipt checkpoint ref count mismatch");
  let parent = Object.prototype.hasOwnProperty.call(receipt, "resumed_from") ? receipt.resumed_from : null;
  for (let index = 0; index < checkpoints.length; index += 1) {
    const checkpoint = checkpoints[index];
    if (checkpoint.task_id !== receipt.task_id) throw new Error("checkpoint task mismatch");
    if (checkpoint.checkpoint_id !== refs[index]) throw new Error("checkpoint ref mismatch");
    if (checkpoint.parent_checkpoint !== parent) throw new Error("checkpoint parent mismatch");
    const { checkpoint_signature: signature, ...body } = checkpoint;
    if (!verifyObject(publicKey, body, signature)) throw new Error("checkpoint signature verification failed");
    parent = checkpoint.checkpoint_id;
  }
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
  validateTaskId(receipt.task_id);
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
  verifyResultArtifactPointer(receipt);
  verifyReceiptCheckpoints(resolved.publicKey, receipt);
  return { zone, worker: resolved.descriptor, receipt, signedReceipt: frame.receipt };
}


function verifySwarmMicroContracts(closeBody, stepById) {
  if (closeBody.micro_contracts === undefined) return;
  if (!Array.isArray(closeBody.micro_contracts) || closeBody.micro_contracts.length !== stepById.size) throw new Error("swarm close micro-contracts missing");
  const contractStepIds = new Set();
  for (const contract of closeBody.micro_contracts) {
    if (!contract || typeof contract !== "object" || Array.isArray(contract)) throw new Error("swarm close micro-contract missing");
    const { contract_digest, signature, ...contractBody } = contract;
    if (contractBody.micro_contract !== "ok") throw new Error("swarm close micro-contract status invalid");
    if (contractBody.swarm_id !== closeBody.swarm_id) throw new Error("swarm close micro-contract swarm mismatch");
    if (typeof contractBody.step_id !== "string" || contractBody.step_id === "" || contractBody.step_id.includes("\0")) throw new Error("swarm close micro-contract step invalid");
    if (contractStepIds.has(contractBody.step_id)) throw new Error("swarm close duplicate micro-contract");
    contractStepIds.add(contractBody.step_id);
    const step = stepById.get(contractBody.step_id);
    if (!step) throw new Error("swarm close micro-contract step missing");
    if (!step.worker || typeof step.worker !== "object" || Array.isArray(step.worker)) throw new Error("swarm close step worker missing");
    if (!contractBody.worker || typeof contractBody.worker !== "object" || Array.isArray(contractBody.worker)) throw new Error("swarm close micro-contract worker missing");
    if (canonical(contractBody.worker) !== canonical(step.worker)) throw new Error("swarm close micro-contract worker mismatch");
    if (!contractBody.cost_estimate || typeof contractBody.cost_estimate !== "object" || Array.isArray(contractBody.cost_estimate)) throw new Error("swarm close micro-contract cost missing");
    for (const field of ["tokens", "seconds"]) {
      if (typeof contractBody.cost_estimate[field] !== "number" || !Number.isSafeInteger(contractBody.cost_estimate[field]) || contractBody.cost_estimate[field] < 0) {
        throw new Error("swarm close micro-contract cost invalid");
      }
    }
    if (typeof contractBody.capability_proof !== "string" || contractBody.capability_proof === "") throw new Error("swarm close micro-contract capability missing");
    if (typeof contractBody.policy_digest !== "string" || !/^[0-9a-f]{64}$/.test(contractBody.policy_digest)) throw new Error("swarm close micro-contract policy invalid");
    if (typeof contract_digest !== "string" || contract_digest !== createHash("sha256").update(canonical(contractBody)).digest("hex")) throw new Error("swarm close micro-contract digest invalid");
    if (typeof signature !== "string" || signature === "") throw new Error("swarm close micro-contract signature missing");
    if (!verifyObject(publicKeyFromDescriptor(step.worker), contractBody, signature)) throw new Error("micro-contract signature verification failed");
  }
}


function verifySwarmConflictResolutions(closeBody, stepById, zone) {
  if (closeBody.conflict_resolutions === undefined) return;
  if (!Array.isArray(closeBody.conflict_resolutions)) throw new Error("swarm close conflict_resolutions invalid");
  const zonePublicKey = publicKeyFromDescriptor(zone);
  for (const resolution of closeBody.conflict_resolutions) {
    if (!resolution || typeof resolution !== "object" || Array.isArray(resolution)) throw new Error("swarm close conflict resolution invalid");
    const { resolution_digest, signature, ...resolutionBody } = resolution;
    if (resolutionBody.swarm_id !== closeBody.swarm_id) throw new Error("swarm close conflict resolution swarm mismatch");
    if (typeof resolutionBody.artifact_ref !== "string" || resolutionBody.artifact_ref === "") throw new Error("swarm close conflict resolution artifact_ref missing");
    if (!Array.isArray(resolutionBody.candidate_step_ids) || resolutionBody.candidate_step_ids.length < 2) throw new Error("swarm close conflict resolution candidates missing");
    const candidateStepIds = new Set();
    for (const stepId of resolutionBody.candidate_step_ids) {
      if (typeof stepId !== "string" || stepId === "" || stepId.includes("\0")) throw new Error("swarm close conflict resolution candidate invalid");
      if (candidateStepIds.has(stepId)) throw new Error("swarm close conflict resolution candidate duplicate");
      candidateStepIds.add(stepId);
      if (!stepById.has(stepId)) throw new Error("swarm close conflict resolution candidate missing");
    }
    if (candidateStepIds.size < 2) throw new Error("swarm close conflict resolution candidates missing");
    if (typeof resolutionBody.chosen_step_id !== "string" || resolutionBody.chosen_step_id === "" || resolutionBody.chosen_step_id.includes("\0")) throw new Error("swarm close conflict resolution chosen step invalid");
    if (!candidateStepIds.has(resolutionBody.chosen_step_id)) throw new Error("swarm close conflict resolution chosen step missing");
    const chosenStep = stepById.get(resolutionBody.chosen_step_id);
    if (!resolutionBody.chosen_worker || typeof resolutionBody.chosen_worker !== "object" || Array.isArray(resolutionBody.chosen_worker)) throw new Error("swarm close conflict resolution worker missing");
    if (!chosenStep?.worker || typeof chosenStep.worker !== "object" || Array.isArray(chosenStep.worker)) throw new Error("swarm close step worker missing");
    if (canonical(resolutionBody.chosen_worker) !== canonical(chosenStep.worker)) throw new Error("swarm close conflict resolution worker mismatch");
    if (typeof resolutionBody.reason !== "string" || resolutionBody.reason === "") throw new Error("swarm close conflict resolution reason missing");
    if (typeof resolution_digest !== "string" || resolution_digest !== createHash("sha256").update(canonical(resolutionBody)).digest("hex")) throw new Error("swarm close conflict resolution digest invalid");
    if (typeof signature !== "string" || signature === "") throw new Error("swarm close conflict resolution signature missing");
    if (!verifyObject(zonePublicKey, resolutionBody, signature)) throw new Error("conflict resolution signature verification failed");
  }
}

function verifySwarmMigrationLog(closeBody, stepById) {
  if (closeBody.migration_log === undefined) return;
  if (!Array.isArray(closeBody.migration_log)) throw new Error("swarm close migration_log invalid");
  for (const entry of closeBody.migration_log) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) throw new Error("swarm close migration entry invalid");
    if (typeof entry.step_id !== "string" || entry.step_id === "" || entry.step_id.includes("\0")) throw new Error("swarm close migration step invalid");
    if (!stepById.has(entry.step_id)) throw new Error("swarm close migration step missing");
    if (typeof entry.original_worker_aid !== "string" || entry.original_worker_aid === "") throw new Error("swarm close migration original worker missing");
    if (typeof entry.migrated_to_worker_aid !== "string" || entry.migrated_to_worker_aid === "") throw new Error("swarm close migration target worker missing");
    if (typeof entry.reason !== "string" || entry.reason === "") throw new Error("swarm close migration reason missing");
    if (typeof entry.migration_at !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(entry.migration_at)) {
      throw new Error("swarm close migration_at invalid");
    }
  }
}

function verifySwarmScheduler(closeBody, stepById, requireReceiptOrder) {
  if (closeBody.scheduler === undefined) return;
  const scheduler = closeBody.scheduler;
  if (!hasExactFields(scheduler, ["mode", "step_order"])) throw new Error("swarm close scheduler invalid");
  if (scheduler.mode !== "ready-dag") throw new Error("swarm close scheduler mode invalid");
  if (!Array.isArray(scheduler.step_order)) throw new Error("swarm close scheduler step order invalid");
  if (scheduler.step_order.length !== stepById.size) throw new Error("swarm close scheduler step order mismatch");
  const scheduled = new Set();
  for (const [index, stepId] of scheduler.step_order.entries()) {
    if (typeof stepId !== "string" || stepId === "" || stepId.includes("\0")) throw new Error("swarm close scheduler step invalid");
    if (scheduled.has(stepId)) throw new Error("swarm close scheduler step duplicate");
    if (!stepById.has(stepId)) throw new Error("swarm close scheduler step missing");
    if (requireReceiptOrder && stepId !== closeBody.step_receipts[index].step_id) throw new Error("swarm close scheduler step_order mismatch");
    scheduled.add(stepId);
  }
}

function verifyParallelReadyDagScheduler(closeBody, stepById) {
  const scheduler = closeBody.scheduler;
  if (!hasExactFields(scheduler, ["dispatch_waves", "mode", "ready_waves"]) || scheduler.mode !== "parallel-ready-dag" || !Array.isArray(scheduler.ready_waves) || !Array.isArray(scheduler.dispatch_waves) || scheduler.ready_waves.length !== scheduler.dispatch_waves.length || scheduler.ready_waves.length === 0) throw new Error("swarm close parallel scheduler invalid");
  const validateWave = (wave, label) => {
    if (!hasExactFields(wave, ["recorded_at", "step_ids"]) || !Array.isArray(wave.step_ids) || wave.step_ids.length === 0 || new Set(wave.step_ids).size !== wave.step_ids.length || wave.step_ids.some((stepId) => typeof stepId !== "string" || !stepById.has(stepId))) throw new Error(`swarm close ${label} wave invalid`);
    durableTimestamp(wave.recorded_at, `swarm close ${label} recorded_at`);
  };
  const attempts = [];
  for (const [index, ready] of scheduler.ready_waves.entries()) {
    validateWave(ready, "ready");
    const dispatched = scheduler.dispatch_waves[index];
    if (!hasExactFields(dispatched, ["attempts", "wave"]) || !Array.isArray(dispatched.attempts) || dispatched.attempts.length !== ready.step_ids.length) throw new Error("swarm close dispatch wave invalid");
    validateWave(dispatched.wave, "dispatch");
    if (canonical(dispatched.wave) !== canonical(ready)) throw new Error("swarm close dispatch wave order mismatch");
    const fences = new Set();
    for (const [attemptIndex, attempt] of dispatched.attempts.entries()) {
      if (!durablePlainObject(attempt, "swarm close dispatch attempt") || attempt.step_id !== ready.step_ids[attemptIndex] || typeof attempt.owner !== "string" || attempt.owner === "" || !Number.isSafeInteger(attempt.fence) || attempt.fence < 1 || fences.has(attempt.fence) || !Number.isSafeInteger(attempt.attempt) || attempt.attempt < 1 || !Number.isSafeInteger(attempt.candidate_index) || attempt.candidate_index < 0 || typeof attempt.capability !== "string" || attempt.capability === "" || !durablePlainObject(attempt.candidate, "swarm close dispatch candidate")) throw new Error("swarm close dispatch attempt invalid");
      fences.add(attempt.fence);
      durableTimestamp(attempt.deadline, "swarm close dispatch deadline");
      attempts.push(attempt);
    }
  }
  for (const [stepId, step] of stepById) {
    if (step.observations === undefined) continue;
    if (!Array.isArray(step.observations)) throw new Error("swarm close observations invalid");
    for (const observation of step.observations) {
      if (!hasExactFields(observation, ["attempt", "candidate", "fence", "observed_at", "outcome", "owner"]) || !Number.isSafeInteger(observation.attempt) || observation.attempt < 1 || !Number.isSafeInteger(observation.fence) || observation.fence < 1 || typeof observation.owner !== "string" || observation.owner === "" || typeof observation.outcome !== "string" || observation.outcome === "" || !durablePlainObject(observation.candidate, "swarm close observation candidate")) throw new Error("swarm close observation invalid");
      durableTimestamp(observation.observed_at, "swarm close observation timestamp");
      if (!attempts.some((attempt) => attempt.step_id === stepId && attempt.owner === observation.owner && attempt.fence === observation.fence && attempt.attempt === observation.attempt && canonical(attempt.candidate) === canonical(observation.candidate))) throw new Error("swarm close observation binding invalid");
    }
  }
}

const SWARM_CLOSE_V1_REQUIRED_FIELDS = ["close_signature", "format", "step_receipts", "swarm_id"];
const SWARM_CLOSE_V1_OPTIONAL_FIELDS = ["conflict_resolutions", "execution_graph_digest", "micro_contracts", "migration_log", "plan_digest", "scheduler"];
const SWARM_CLOSE_V2_REQUIRED_FIELDS = ["close_signature", "execution_graph_digest", "final_output", "format", "plan_digest", "step_receipts", "swarm_id"];
const SWARM_CLOSE_V2_OPTIONAL_FIELDS = ["conflict_resolutions", "micro_contracts", "migration_log", "scheduler"];
const SWARM_CLOSE_FINAL_OUTPUT_FIELDS = ["artifact", "selection_rule", "signed_receipt_digest", "step_id", "task_id"];
const RESULT_ARTIFACT_FIELDS = ["manifest_hash", "sha256", "uri"];

function hasRequiredAllowedFields(value, required, optional = []) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const allowed = new Set([...required, ...optional]);
  return required.every((field) => Object.prototype.hasOwnProperty.call(value, field)) && Object.keys(value).every((field) => allowed.has(field));
}

function verifiedSwarmCloseEnvelope(frame, trustedZones) {
  if (!frame || typeof frame !== "object" || Array.isArray(frame) || frame.type !== "FED_SWARM_CLOSE") throw new Error("expected FED_SWARM_CLOSE frame");
  if (!frame.zone || typeof frame.zone !== "object" || Array.isArray(frame.zone)) throw new Error("swarm close zone missing");
  const zone = verifyZoneDescriptor(frame.zone).descriptor;
  assertTrustedZones(trustedZones);
  const trusted = trustedZones.get(zone.zid);
  if (!trusted || trusted.public_key_spki !== zone.public_key_spki) throw new Error(`untrusted zone: ${zone.zid}`);
  if (!frame.close || typeof frame.close !== "object" || Array.isArray(frame.close)) throw new Error("swarm close proof missing");
  return zone;
}

function verifySwarmCloseIdentity(frame, closeBody) {
  if (typeof closeBody.swarm_id !== "string" || closeBody.swarm_id === "") throw new Error("swarm close identity missing");
  if (closeBody.swarm_id.includes("\0")) throw new Error("swarm close identity contains NUL");
  if (frame.swarm_id !== closeBody.swarm_id) throw new Error("swarm close frame id mismatch");
}

function verifySwarmCloseStepReceipts(closeBody, digestField, fieldsError, allowObservations = false) {
  if (!Array.isArray(closeBody.step_receipts) || closeBody.step_receipts.length === 0) throw new Error("swarm close step receipts missing");
  const requiredFields = [digestField, "step_id", "task_id"].sort();
  const stepIds = new Set();
  const stepById = new Map();
  for (const step of closeBody.step_receipts) {
    if (!hasRequiredAllowedFields(step, requiredFields, allowObservations ? ["observations", "worker"] : ["worker"])) throw new Error(fieldsError);
    if (typeof step.step_id !== "string" || step.step_id === "") throw new Error("swarm close step identity missing");
    if (step.step_id.includes("\0")) throw new Error("swarm close identity contains NUL");
    if (stepIds.has(step.step_id)) throw new Error("swarm close duplicate step receipt");
    stepIds.add(step.step_id);
    stepById.set(step.step_id, step);
    if (typeof step.task_id !== "string" || step.task_id === "") throw new Error("swarm close task missing");
    if (!TASK_ID_PATTERN.test(step.task_id)) throw new Error("swarm close task invalid");
    if (typeof step[digestField] !== "string" || !/^[0-9a-f]{64}$/.test(step[digestField])) throw new Error(`swarm close ${digestField.replaceAll("_", " ")} invalid`);
    if (step.worker !== undefined && (!step.worker || typeof step.worker !== "object" || Array.isArray(step.worker))) throw new Error("swarm close step worker missing");
  }
  return stepById;
}

function verifySwarmCloseAuxiliaryEvidence(closeBody, stepById, zone, requireSchedulerReceiptOrder) {
  verifySwarmMigrationLog(closeBody, stepById);
  verifySwarmMicroContracts(closeBody, stepById);
  verifySwarmConflictResolutions(closeBody, stepById, zone);
  if (closeBody.scheduler?.mode === "parallel-ready-dag") verifyParallelReadyDagScheduler(closeBody, stepById);
  else verifySwarmScheduler(closeBody, stepById, requireSchedulerReceiptOrder);
}

function verifySwarmCloseSignature(zone, closeBody, closeSignature) {
  if (typeof closeSignature !== "string" || closeSignature === "") throw new Error("swarm close signature missing");
  if (!verifyObject(publicKeyFromDescriptor(zone), closeBody, closeSignature)) throw new Error("swarm close signature verification failed");
}

function verifySwarmCloseFinalOutput(closeBody, stepById) {
  const finalOutput = closeBody.final_output;
  if (!hasExactFields(finalOutput, SWARM_CLOSE_FINAL_OUTPUT_FIELDS)) throw new Error("swarm close final output fields invalid");
  if (typeof finalOutput.step_id !== "string" || finalOutput.step_id === "" || finalOutput.step_id.includes("\0")) throw new Error("swarm close final output step invalid");
  if (typeof finalOutput.task_id !== "string" || !TASK_ID_PATTERN.test(finalOutput.task_id)) throw new Error("swarm close final output task invalid");
  if (typeof finalOutput.signed_receipt_digest !== "string" || !/^[0-9a-f]{64}$/.test(finalOutput.signed_receipt_digest)) throw new Error("swarm close final output receipt digest invalid");
  if (finalOutput.selection_rule !== "single-terminal-result") throw new Error("swarm close final output selection rule invalid");
  if (!hasExactFields(finalOutput.artifact, RESULT_ARTIFACT_FIELDS)) throw new Error("swarm close final output artifact fields invalid");
  if (typeof finalOutput.artifact.uri !== "string" || finalOutput.artifact.uri === "") throw new Error("swarm close final output artifact uri invalid");
  for (const field of ["sha256", "manifest_hash"]) {
    if (typeof finalOutput.artifact[field] !== "string" || !/^[0-9a-f]{64}$/.test(finalOutput.artifact[field])) throw new Error(`swarm close final output artifact ${field} invalid`);
  }
  const linkedStep = stepById.get(finalOutput.step_id);
  if (!linkedStep) throw new Error("swarm close final output step mismatch");
  if (linkedStep.task_id !== finalOutput.task_id) throw new Error("swarm close final output task mismatch");
  if (linkedStep.signed_receipt_digest !== finalOutput.signed_receipt_digest) throw new Error("swarm close final output receipt digest mismatch");
}

export function verifySwarmCloseV1(frame, trustedZones) {
  const zone = verifiedSwarmCloseEnvelope(frame, trustedZones);
  if (!hasRequiredAllowedFields(frame.close, SWARM_CLOSE_V1_REQUIRED_FIELDS, SWARM_CLOSE_V1_OPTIONAL_FIELDS)) throw new Error("swarm close v1 fields invalid");
  if (frame.close.format !== "asp-swarm-close/v1") throw new Error("swarm close v1 format invalid");
  const { close_signature, ...closeBody } = frame.close;
  verifySwarmCloseIdentity(frame, closeBody);
  for (const field of ["plan_digest", "execution_graph_digest"]) {
    if (closeBody[field] !== undefined && (typeof closeBody[field] !== "string" || !/^[0-9a-f]{64}$/.test(closeBody[field]))) throw new Error(`swarm close ${field.replaceAll("_", " ")} invalid`);
  }
  const stepById = verifySwarmCloseStepReceipts(closeBody, "receipt_digest", "swarm close v1 step fields invalid");
  verifySwarmCloseAuxiliaryEvidence(closeBody, stepById, zone, true);
  verifySwarmCloseSignature(zone, closeBody, close_signature);
  return { zone, close: frame.close, closeDigest: sha256Canonical(closeBody), format: frame.close.format, legacy: true };
}

export function verifySwarmCloseV2(frame, trustedZones) {
  const zone = verifiedSwarmCloseEnvelope(frame, trustedZones);
  if (!hasRequiredAllowedFields(frame.close, SWARM_CLOSE_V2_REQUIRED_FIELDS, SWARM_CLOSE_V2_OPTIONAL_FIELDS)) throw new Error("swarm close v2 fields invalid");
  if (frame.close.format !== "asp-swarm-close/v2") throw new Error("swarm close v2 format invalid");
  const { close_signature, ...closeBody } = frame.close;
  verifySwarmCloseIdentity(frame, closeBody);
  if (typeof closeBody.plan_digest !== "string" || !/^[0-9a-f]{64}$/.test(closeBody.plan_digest)) throw new Error("swarm close plan digest invalid");
  if (typeof closeBody.execution_graph_digest !== "string" || !/^[0-9a-f]{64}$/.test(closeBody.execution_graph_digest)) throw new Error("swarm close execution graph digest invalid");
  const stepById = verifySwarmCloseStepReceipts(closeBody, "signed_receipt_digest", "swarm close v2 step fields invalid", true);
  verifySwarmCloseFinalOutput(closeBody, stepById);
  verifySwarmCloseAuxiliaryEvidence(closeBody, stepById, zone, false);
  verifySwarmCloseSignature(zone, closeBody, close_signature);
  return { zone, close: frame.close, closeDigest: sha256Canonical(frame.close), format: frame.close.format, legacy: false };
}

export function verifySwarmClose(frame, trustedZones) {
  if (!frame || typeof frame !== "object" || Array.isArray(frame) || frame.type !== "FED_SWARM_CLOSE") throw new Error("expected FED_SWARM_CLOSE frame");
  if (!frame.close || typeof frame.close !== "object" || Array.isArray(frame.close)) throw new Error("swarm close proof missing");
  if (!Object.prototype.hasOwnProperty.call(frame.close, "format")) throw new Error("swarm close format missing");
  if (frame.close.format === "asp-swarm-close/v1") return verifySwarmCloseV1(frame, trustedZones);
  if (frame.close.format === "asp-swarm-close/v2") return verifySwarmCloseV2(frame, trustedZones);
  throw new Error("unsupported swarm close format");
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
    if (typeof manifest.uri !== "string" || manifest.uri === "") throw new Error("artifact manifest uri invalid");
    if (typeof receipt.artifact_refs[index] !== "string" || receipt.artifact_refs[index] === "") throw new Error("artifact refs invalid");
    if (manifest.uri !== receipt.artifact_refs[index]) throw new Error("artifact manifest uri mismatch");
    for (const field of ["sha256", "media_type", "manifest_hash"]) {
      if (typeof manifest[field] !== "string" || manifest[field] === "") throw new Error(`artifact manifest ${field} missing`);
    }
    if (!/^[0-9a-f]{64}$/.test(manifest.sha256)) throw new Error("artifact manifest sha256 invalid");
    if (manifest.afp !== undefined && manifest.afp !== `afp:sha256:${manifest.sha256}`) {
      throw new Error("artifact manifest afp mismatch");
    }
    if (typeof manifest.size !== "number") throw new Error("artifact manifest size missing");
    if (!Number.isSafeInteger(manifest.size) || manifest.size < 0) throw new Error("artifact manifest size invalid");
    const { manifest_hash, ...body } = manifest;
    if (manifest_hash !== createHash("sha256").update(canonical(body)).digest("hex")) {
      throw new Error("artifact manifest hash mismatch");
    }
  }
}

function verifyResultArtifactPointer(receipt) {
  if (!receipt || typeof receipt !== "object" || Array.isArray(receipt)) throw new Error("result artifact receipt invalid");
  if (!Object.prototype.hasOwnProperty.call(receipt, "result_artifact")) return null;
  const pointer = receipt.result_artifact;
  if (!pointer || typeof pointer !== "object" || Array.isArray(pointer)) throw new Error("result artifact invalid");
  if (!hasExactFields(pointer, RESULT_ARTIFACT_FIELDS)) throw new Error("result artifact fields invalid");
  if (typeof pointer.uri !== "string" || pointer.uri === "") throw new Error("result artifact uri invalid");
  for (const field of ["sha256", "manifest_hash"]) {
    if (typeof pointer[field] !== "string" || !/^[0-9a-f]{64}$/.test(pointer[field])) throw new Error(`result artifact ${field} invalid`);
  }
  const manifests = Array.isArray(receipt.artifact_manifests) ? receipt.artifact_manifests : [];
  const matches = manifests.filter((manifest) => manifest.uri === pointer.uri && manifest.sha256 === pointer.sha256 && manifest.manifest_hash === pointer.manifest_hash);
  if (matches.length !== 1) throw new Error("result artifact manifest mismatch");
  return Object.freeze({ uri: pointer.uri, sha256: pointer.sha256, manifest_hash: pointer.manifest_hash });
}

export function verifyResultArtifact(receipt) {
  verifyReceiptArtifactManifests(receipt);
  return verifyResultArtifactPointer(receipt);
}

export function deriveSwarmFinalOutput(binding, completedReceipts) {
  if (!hasExactFields(binding, ["executionGraphDigest", "planDigest", "steps", "swarmId"])) throw new Error("verified execution binding invalid");
  if (typeof binding.swarmId !== "string" || binding.swarmId === "" || binding.swarmId.includes("\0")) throw new Error("verified execution binding swarm_id invalid");
  if (typeof binding.planDigest !== "string" || !/^[0-9a-f]{64}$/.test(binding.planDigest)) throw new Error("verified execution binding plan digest invalid");
  if (typeof binding.executionGraphDigest !== "string" || !/^[0-9a-f]{64}$/.test(binding.executionGraphDigest)) throw new Error("verified execution binding graph digest invalid");
  if (!Array.isArray(binding.steps) || binding.steps.length === 0) throw new Error("verified execution binding steps missing");
  if (!(completedReceipts instanceof Map)) throw new Error("completed receipts invalid");

  const stepById = new Map();
  for (const step of binding.steps) {
    if (!hasExactFields(step, SWARM_EXECUTION_BINDING_STEP_FIELDS)) throw new Error("verified execution binding step fields invalid");
    if (typeof step.step_id !== "string" || step.step_id === "" || step.step_id.includes("\0")) throw new Error("verified execution binding step invalid");
    if (stepById.has(step.step_id)) throw new Error("verified execution binding duplicate step");
    executionBindingDependencies(step.depends_on);
    if (typeof step.capability !== "string" || step.capability === "" || step.capability.includes("\0")) throw new Error("verified execution binding capability invalid");
    if (typeof step.task_digest !== "string" || !/^[0-9a-f]{64}$/.test(step.task_digest)) throw new Error("verified execution binding task digest invalid");
    stepById.set(step.step_id, step);
  }
  for (const step of binding.steps) {
    if (!completedReceipts.has(step.step_id)) throw new Error(`completed receipt missing: ${step.step_id}`);
  }
  if (completedReceipts.size !== binding.steps.length) throw new Error("completed receipt count mismatch");
  const referenced = new Set();
  for (const step of binding.steps) {
    for (const dependency of step.depends_on) {
      if (!stepById.has(dependency)) throw new Error("verified execution binding dependency missing");
      referenced.add(dependency);
    }
  }
  const terminalStepIds = binding.steps.map((step) => step.step_id).filter((stepId) => !referenced.has(stepId));
  if (terminalStepIds.length !== 1) throw new Error("single terminal step required");

  const selectedByStep = new Map();
  for (const step of binding.steps) {
    const receipt = completedReceipts.get(step.step_id);
    if (!receipt || typeof receipt !== "object" || Array.isArray(receipt)) throw new Error(`completed receipt missing: ${step.step_id}`);
    signedReceiptDigest(receipt);
    if (typeof receipt.task_id !== "string" || !TASK_ID_PATTERN.test(receipt.task_id)) throw new Error("receipt task id invalid");
    if (receipt.task_digest !== step.task_digest) throw new Error("receipt task digest mismatch");
    const swarm = receipt.swarm;
    if (!swarm || typeof swarm !== "object" || Array.isArray(swarm)) throw new Error("receipt swarm binding missing");
    if (swarm.swarm_id !== binding.swarmId) throw new Error("receipt swarm_id mismatch");
    if (swarm.step_id !== step.step_id) throw new Error("receipt step mismatch");
    if (!sameExecutionDependencies(swarm.after, step.depends_on)) throw new Error("receipt dependency mismatch");
    if (swarm.plan_digest !== binding.planDigest) throw new Error("receipt plan digest mismatch");
    if (swarm.execution_graph_digest !== binding.executionGraphDigest) throw new Error("receipt execution graph digest mismatch");
    if (swarm.capability !== step.capability) throw new Error("receipt capability mismatch");
    if (swarm.task_digest !== step.task_digest) throw new Error("receipt swarm task digest mismatch");
    verifyReceiptArtifactManifests(receipt);
    selectedByStep.set(step.step_id, verifyResultArtifactPointer(receipt));
  }

  const terminalStepId = terminalStepIds[0];
  const terminalReceipt = completedReceipts.get(terminalStepId);
  const artifact = selectedByStep.get(terminalStepId);
  if (artifact === null) throw new Error("terminal result artifact missing");
  return Object.freeze({
    step_id: terminalStepId,
    task_id: terminalReceipt.task_id,
    signed_receipt_digest: signedReceiptDigest(terminalReceipt),
    artifact,
    selection_rule: "single-terminal-result",
  });
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
    const valid = credential.issuer === authorityDescriptor.zid && credential.subject === subjectDescriptor.aid && verifyObject(authorityPublicKey, body, credential.signature);
    if (!valid) return false;
    const validUntil = credential.claims?.valid_until;
    if (validUntil !== undefined) {
      if (typeof validUntil !== "string" || !CREDENTIAL_VALID_UNTIL_PATTERN.test(validUntil)) return false;
      const validUntilMs = Date.parse(validUntil);
      if (!Number.isFinite(validUntilMs) || Date.now() > validUntilMs) return false;
    }
    return true;

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
