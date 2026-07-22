export const PROTOCOL_VERSION = "1.0";
export const PROFILES = Object.freeze(["local", "direct", "governed", "a2a-baseline", "a2a-afp"]);
export const ROUTES = Object.freeze(["local", "direct", "relayed", "store-forward"]);
export const KINDS = Object.freeze([
  "afp.agent-descriptor", "afp.capability-advertisement", "afp.intent-query", "afp.offer",
  "afp.capability-grant", "afp.task-open", "afp.task-claim", "afp.task-event",
  "afp.checkpoint", "afp.artifact-manifest", "afp.mailbox-envelope", "afp.custody-receipt",
  "afp.receipt-commit", "afp.assurance-evidence", "afp.route-binding", "afp.direct-swarm-charter",
  "afp.settlement-commit",
]);
export const KIND_SET = new Set(KINDS);
export const ERROR_CODES = Object.freeze(Object.fromEntries([
  "AFP_OK", "AFP_NONCANONICAL_JSON", "AFP_DUPLICATE_KEY", "AFP_TRAILING_DATA", "AFP_INVALID_STRING",
  "AFP_UNKNOWN_FIELD", "AFP_MISSING_FIELD", "AFP_UNSUPPORTED_VERSION", "AFP_VERSION_NEGOTIATION_FAILED",
  "AFP_NEGOTIATION_REQUIRED", "AFP_NEGOTIATION_BINDING_MISMATCH", "AFP_INVALID_PROFILE", "AFP_INVALID_ROUTE",
  "AFP_PROFILE_DOWNGRADE_REJECTED", "AFP_PROFILE_RETRY_REJECTED", "AFP_LOCAL_POLICY_REQUIRED", "AFP_INVALID_KIND", "AFP_INVALID_TIMESTAMP",
  "AFP_TIME_ORDER_INVALID", "AFP_VERIFICATION_TIME_REQUIRED", "AFP_KEY_RESOLUTION_FAILED", "AFP_SIGNATURE_FORMAT_INVALID", "AFP_SIGNATURE_INVALID",
  "AFP_DIGEST_MISMATCH", "AFP_REPLAY_DETECTED", "AFP_REFERENCE_INVALID", "AFP_AUTHORITY_EVIDENCE_REJECTED",
  "AFP_PARENT_REFERENCE_REQUIRED", "AFP_DELEGATION_FORBIDDEN", "AFP_CAPABILITY_ISSUER_MISMATCH", "AFP_CAPABILITY_ACTION_EXPANSION",
  "AFP_CAPABILITY_RESOURCE_EXPANSION", "AFP_CAPABILITY_LIMIT_EXPANSION", "AFP_CAPABILITY_EXPIRY_EXPANSION",
  "AFP_CAPABILITY_SUBJECT_MUTATION", "AFP_REVOCATION_PROOF_REJECTED", "AFP_RECEIPT_AUTHORITY_UNAVAILABLE",
  "AFP_CUSTODY_LINEAGE_INVALID", "AFP_CUSTODY_CONTESTED", "AFP_CUSTODY_CANCELLED", "AFP_CUSTODY_EXPIRED",
  "AFP_CUSTODY_EXECUTION_UNAUTHORIZED", "AFP_RECEIPT_FENCE_VIOLATION", "AFP_SETTLEMENT_REFUSED",
  "AFP_UNSUPPORTED_SETTLEMENT_FACT", "AFP_BUDGET_AUTHORIZATION_REQUIRED", "AFP_RAIL_SEMANTICS_REJECTED",
  "AFP_ASP_FRAME_REJECTED", "AFP_ASP_VECTOR_REJECTED", "AFP_ASP_LEGACY_FIELD_REJECTED",
].map((code) => [code, code])));

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const BODY_FIELDS = Object.freeze(["kind", "spec_version", "profile", "issuer", "audience", "nonce", "issued_at", "expires_at", "payload"]);
const ENVELOPE_FIELDS = Object.freeze(["body", "signature"]);
const SIGNATURE_FIELDS = Object.freeze(["alg", "value"]);
const TRANSCRIPT_FIELDS = Object.freeze(["issuer", "peer", "issuer_versions", "peer_versions", "selected_version", "selected_profile", "route_context_digest"]);
const AUTHORITY_FIELDS = Object.freeze(["digest", "issuer", "subject", "permitted_events", "permitted_terminals"]);
const REVOCATION_FIELDS = Object.freeze(["status", "digest"]);
const RECEIPT_EXPECTATION_FIELDS = Object.freeze(["task_id", "attempt", "receipt_fence", "current_fence", "sequence", "predecessor_sequence", "receipt_digest", "custody_digest", "lineage_digest", "expected_task_id", "expected_attempt", "verified_references", "actual_receipt_object_digest", "actual_receipt_payload"]);
const RECEIPT_PAYLOAD_FIELDS = Object.freeze(["task_id", "attempt", "fence", "lineage_digest"]);

const RFC3339_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const B64URL = /^[A-Za-z0-9_-]*$/;
const ED25519_SPKI_PREFIX = Uint8Array.from([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]);
const TERMINALS = new Set(["rejected", "completed", "failed", "cancelled", "expired"]);
const EVENT_NAMES = new Set(["submitted", "cancelled", "expired", "accepted", "rejected", "executing", "completed", "failed"]);
const SETTLEMENT_FACTS = new Set(["custody", "storage", "execution", "verification"]);

export class AFPError extends Error {
  constructor(code) { super(code); this.code = code; }
}

function fail(code) { throw new AFPError(code); }
function isObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }
function utf8(value) { return encoder.encode(value); }
function bytesEqual(left, right) {
  if (left.length !== right.length) return false;
  let different = 0;
  for (let index = 0; index < left.length; index += 1) different |= left[index] ^ right[index];
  return different === 0;
}
function hex(bytes) { return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(""); }
function base64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
function decodeBase64url(value, exactLength, code = ERROR_CODES.AFP_NONCANONICAL_JSON) {
  if (typeof value !== "string" || !B64URL.test(value) || value.includes("=") || value.length % 4 === 1) fail(code);
  let binary;
  try { binary = atob(value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4)); } catch { fail(code); }
  const out = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (exactLength !== undefined && out.length !== exactLength) fail(code);
  return out;
}
function compareBytes(left, right) {
  const length = Math.min(left.length, right.length);
  for (let index = 0; index < length; index += 1) if (left[index] !== right[index]) return left[index] - right[index];
  return left.length - right.length;
}
function assertScalarString(value) {
  if (typeof value !== "string") fail(ERROR_CODES.AFP_INVALID_STRING);
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const low = value.charCodeAt(index + 1);
      if (low < 0xdc00 || low > 0xdfff) fail(ERROR_CODES.AFP_INVALID_STRING);
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) fail(ERROR_CODES.AFP_INVALID_STRING);
    if (unit === 0x2028 || unit === 0x2029) fail(ERROR_CODES.AFP_INVALID_STRING);
  }
}
function quote(value) {
  assertScalarString(value);
  let out = '"';
  for (const character of value) {
    const code = character.codePointAt(0);
    if (character === '"') out += '\\"';
    else if (character === "\\") out += "\\\\";
    else if (code === 8) out += "\\b";
    else if (code === 12) out += "\\f";
    else if (code === 10) out += "\\n";
    else if (code === 13) out += "\\r";
    else if (code === 9) out += "\\t";
    else if (code <= 0x1f) out += `\\u${code.toString(16).padStart(4, "0")}`;
    else out += character;
  }
  return `${out}"`;
}

/** Canonical AFP JSON serialization: object keys sort by their UTF-8 bytes. */
export function canonicalizeJson(value) {
  if (value === null) return "null";
  if (value === true) return "true";
  if (value === false) return "false";
  if (typeof value === "string") return quote(value);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) fail(ERROR_CODES.AFP_NONCANONICAL_JSON);
    return String(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalizeJson).join(",")}]`;
  if (!isObject(value)) fail(ERROR_CODES.AFP_NONCANONICAL_JSON);
  const keys = Object.keys(value);
  for (const key of keys) assertScalarString(key);
  keys.sort((left, right) => compareBytes(utf8(left), utf8(right)));
  return `{${keys.map((key) => `${quote(key)}:${canonicalizeJson(value[key])}`).join(",")}}`;
}

class JsonReader {
  constructor(raw) { this.raw = raw; this.index = 0; }
  peek() { return this.raw[this.index]; }
  skipWhitespace() { while (/\s/.test(this.peek() ?? "")) this.index += 1; }
  value() {
    this.skipWhitespace();
    const token = this.peek();
    if (token === "{") return this.object();
    if (token === "[") return this.array();
    if (token === '"') return this.string();
    if (token === "t" && this.raw.slice(this.index, this.index + 4) === "true") { this.index += 4; return true; }
    if (token === "f" && this.raw.slice(this.index, this.index + 5) === "false") { this.index += 5; return false; }
    if (token === "n" && this.raw.slice(this.index, this.index + 4) === "null") { this.index += 4; return null; }
    return this.number();
  }
  object() {
    this.index += 1; this.skipWhitespace();
    const result = Object.create(null); const seen = new Set();
    if (this.peek() === "}") { this.index += 1; return result; }
    while (true) {
      if (this.peek() !== '"') fail(ERROR_CODES.AFP_NONCANONICAL_JSON);
      const key = this.string();
      if (seen.has(key)) fail(ERROR_CODES.AFP_DUPLICATE_KEY);
      seen.add(key); this.skipWhitespace();
      if (this.peek() !== ":") fail(ERROR_CODES.AFP_NONCANONICAL_JSON);
      this.index += 1; result[key] = this.value(); this.skipWhitespace();
      if (this.peek() === "}") { this.index += 1; return result; }
      if (this.peek() !== ",") fail(ERROR_CODES.AFP_NONCANONICAL_JSON);
      this.index += 1; this.skipWhitespace();
    }
  }
  array() {
    this.index += 1; this.skipWhitespace(); const result = [];
    if (this.peek() === "]") { this.index += 1; return result; }
    while (true) {
      result.push(this.value()); this.skipWhitespace();
      if (this.peek() === "]") { this.index += 1; return result; }
      if (this.peek() !== ",") fail(ERROR_CODES.AFP_NONCANONICAL_JSON);
      this.index += 1;
    }
  }
  string() {
    this.index += 1; let result = "";
    while (this.index < this.raw.length) {
      const character = this.raw[this.index++];
      if (character === '"') { assertScalarString(result); return result; }
      if (character === "\\") {
        const escape = this.raw[this.index++];
        if (escape === '"' || escape === "\\" || escape === "/") result += escape;
        else if (escape === "b") result += "\b";
        else if (escape === "f") result += "\f";
        else if (escape === "n") result += "\n";
        else if (escape === "r") result += "\r";
        else if (escape === "t") result += "\t";
        else if (escape === "u") {
          const text = this.raw.slice(this.index, this.index + 4);
          if (!/^[0-9A-Fa-f]{4}$/.test(text)) fail(ERROR_CODES.AFP_NONCANONICAL_JSON);
          this.index += 4; const unit = Number.parseInt(text, 16);
          if (unit >= 0xd800 && unit <= 0xdbff) {
            if (this.raw.slice(this.index, this.index + 2) !== "\\u") fail(ERROR_CODES.AFP_INVALID_STRING);
            const lowText = this.raw.slice(this.index + 2, this.index + 6);
            if (!/^[0-9A-Fa-f]{4}$/.test(lowText)) fail(ERROR_CODES.AFP_INVALID_STRING);
            const low = Number.parseInt(lowText, 16);
            if (low < 0xdc00 || low > 0xdfff) fail(ERROR_CODES.AFP_INVALID_STRING);
            this.index += 6; result += String.fromCodePoint(0x10000 + ((unit - 0xd800) << 10) + low - 0xdc00);
          } else if (unit >= 0xdc00 && unit <= 0xdfff) fail(ERROR_CODES.AFP_INVALID_STRING);
          else result += String.fromCodePoint(unit);
        } else fail(ERROR_CODES.AFP_NONCANONICAL_JSON);
      } else {
        if (character.charCodeAt(0) <= 0x1f) fail(ERROR_CODES.AFP_NONCANONICAL_JSON);
        result += character;
      }
    }
    fail(ERROR_CODES.AFP_NONCANONICAL_JSON);
  }
  number() {
    const match = /-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(this.raw.slice(this.index));
    if (!match || match.index !== 0) fail(ERROR_CODES.AFP_NONCANONICAL_JSON);
    this.index += match[0].length;
    if (/[.eE]/.test(match[0])) fail(ERROR_CODES.AFP_NONCANONICAL_JSON);
    const value = Number(match[0]);
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) fail(ERROR_CODES.AFP_NONCANONICAL_JSON);
    return value;
  }
}

/** Parses raw UTF-8/JS text and rejects every noncanonical AFP encoding. */
export function parseCanonicalJson(input) {
  let raw;
  if (typeof input === "string") { assertScalarString(input); raw = input; }
  else if (input instanceof Uint8Array) {
    if (input.length >= 3 && input[0] === 0xef && input[1] === 0xbb && input[2] === 0xbf) fail(ERROR_CODES.AFP_NONCANONICAL_JSON);
    try { raw = decoder.decode(input); } catch { fail(ERROR_CODES.AFP_NONCANONICAL_JSON); }
  } else fail(ERROR_CODES.AFP_NONCANONICAL_JSON);
  const reader = new JsonReader(raw); const value = reader.value(); reader.skipWhitespace();
  if (reader.index !== raw.length) fail(ERROR_CODES.AFP_TRAILING_DATA);
  if (raw !== canonicalizeJson(value)) fail(ERROR_CODES.AFP_NONCANONICAL_JSON);
  return value;
}

function concatBytes(...parts) {
  const length = parts.reduce((total, part) => total + part.length, 0);
  const output = new Uint8Array(length); let offset = 0;
  for (const part of parts) { output.set(part, offset); offset += part.length; }
  return output;
}
function bodyBytes(body) { return utf8(canonicalizeJson(body)); }
function domainPreimage(domain, body) {
  if (!isObject(body) || ![body.kind, body.spec_version, body.profile].every((value) => typeof value === "string")) fail(ERROR_CODES.AFP_MISSING_FIELD);
  return concatBytes(utf8(`${domain}\0${body.kind}\0${body.spec_version}\0${body.profile}\0`), bodyBytes(body));
}
export function buildSigningPreimage(body) { return domainPreimage("AFP-SIGNATURE-V1", body); }
export function buildDigestPreimage(body) { return domainPreimage("AFP-DIGEST-V1", body); }
export function buildNegotiationPreimage(transcript) { return concatBytes(utf8("AFP-NEGOTIATION-V1\0"), utf8(canonicalizeJson(transcript))); }
export function buildSettlementIdempotencyPreimage(authority, factKind, committedFactDigest) {
  if (![authority, factKind, committedFactDigest].every(nonEmptyString)) fail(ERROR_CODES.AFP_NONCANONICAL_JSON);
  return utf8(`AFP-SETTLEMENT-IDEMPOTENCY-V1\0${authority}\0${factKind}\0${committedFactDigest}`);
}

function assertExactObject(value, fields, missingCode = ERROR_CODES.AFP_MISSING_FIELD) {
  if (!isObject(value)) fail(missingCode);
  for (const key of Object.keys(value)) if (!fields.includes(key)) fail(ERROR_CODES.AFP_UNKNOWN_FIELD);
  for (const field of fields) if (!Object.hasOwn(value, field)) fail(missingCode);
  return value;
}
function nonEmptyString(value) { return typeof value === "string" && value.length > 0; }
function positiveSafeInteger(value) { return Number.isSafeInteger(value) && value > 0; }
function nonNegativeSafeInteger(value) { return Number.isSafeInteger(value) && value >= 0; }
function validTimestamp(value) {
  if (!RFC3339_UTC.test(value)) return false;
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString().replace(".000Z", "Z") === value;
}
function isDigest(value) { try { return decodeBase64url(value, 32).length === 32; } catch { return false; } }
function isAid(value) { return nonEmptyString(value) && value.startsWith("aid:"); }
function strings(value, { unique = false, aid = false, digest = false } = {}) {
  if (!Array.isArray(value) || !value.length || !value.every(nonEmptyString)) return false;
  if (unique && new Set(value).size !== value.length) return false;
  if (aid && !value.every(isAid)) return false;
  return !digest || value.every(isDigest);
}
function isLimits(value) {
  return isObject(value) && Object.keys(value).length === 3 && ["max_bytes", "max_cost", "max_time_ms"].every((key) => nonNegativeSafeInteger(value[key]));
}
function isRevocationProof(value) {
  return isObject(value) && Object.keys(value).length === 2 && value.status === "unrevoked" && isDigest(value.digest);
}
function primitiveError(ok) { if (!ok) fail(ERROR_CODES.AFP_MISSING_FIELD); }

/** Validates only body shape for pipeline stage 2. */
function validateEnvelopeBody(body) {
  assertExactObject(body, BODY_FIELDS);
  return body;
}
function validateEnvelopeShape(envelope) {
  assertExactObject(envelope, ENVELOPE_FIELDS);
  validateEnvelopeBody(envelope.body);
  assertExactObject(envelope.signature, SIGNATURE_FIELDS);
  if (envelope.signature.alg !== "Ed25519" || typeof envelope.signature.value !== "string") fail(ERROR_CODES.AFP_MISSING_FIELD);
  return envelope;
}
function validateBodyPrimitives(body) {
  for (const field of ["kind", "spec_version", "profile", "issuer", "audience", "nonce", "issued_at", "expires_at"]) primitiveError(nonEmptyString(body[field]));
  if (!isObject(body.payload)) fail(ERROR_CODES.AFP_MISSING_FIELD);
  if (!validTimestamp(body.issued_at) || !validTimestamp(body.expires_at)) fail(ERROR_CODES.AFP_INVALID_TIMESTAMP);
  if (body.expires_at <= body.issued_at) fail(ERROR_CODES.AFP_TIME_ORDER_INVALID);
}

const PAYLOAD_FIELDS = Object.freeze({
  "afp.agent-descriptor": ["aid", "descriptor_id", "signing_key", "capabilities", "route_hints", "revocation_proof"],
  "afp.capability-advertisement": ["advertisement_id", "subject", "actions", "resources", "limits", "provenance_digest"],
  "afp.intent-query": ["intent_id", "requester", "constraints", "budget", "privacy", "idempotency_key"],
  "afp.offer": ["offer_id", "intent_digest", "provider", "advertisement_digest", "terms", "assurance_digest"],
  "afp.capability-grant": ["grant_id", "subject", "actions", "resources", "limits", "delegate", "revocation_proof", "parent_grant_digest"],
  "afp.task-open": ["task_id", "requester", "intent_digest", "offer_digest", "grant_digest", "budget_authorization_digest", "idempotency_key", "attempt", "fence"],
  "afp.task-claim": ["task_id", "attempt", "claim_id", "owner", "lease", "fence", "sequence", "predecessor_digest"],
  "afp.task-event": ["task_id", "attempt", "event_id", "event", "sequence", "predecessor_digest", "fence", "facts", "authority_evidence_digest"],
  "afp.checkpoint": ["task_id", "attempt", "checkpoint_id", "state_digest", "sequence", "predecessor_digest", "fence"],
  "afp.artifact-manifest": ["artifact_id", "task_id", "attempt", "bytes_digest", "size", "media_type", "recipients", "access_grant_digest"],
  "afp.mailbox-envelope": ["mail_id", "route_binding_digest", "recipient", "ciphertext_digest", "delivery_expiry", "task_id"],
  "afp.custody-receipt": ["custody_id", "mail_digest", "task_id", "attempt", "state", "sequence", "predecessor_digest", "custodian"],
  "afp.receipt-commit": ["receipt_id", "task_id", "attempt", "terminal", "fence", "lineage_digest", "artifact_manifest_digests", "verification_digest", "authority_evidence_digest"],
  "afp.assurance-evidence": ["assurance_id", "subject", "profile", "claim", "evidence_digest", "scope"],
  "afp.route-binding": ["route_id", "subject", "route", "peer", "negotiation_digest", "route_context_digest"],
  "afp.direct-swarm-charter": ["charter_id", "swarm_id", "members", "authority_rule", "task_digests", "fence_rule", "expiry"],
  "afp.settlement-commit": ["settlement_id", "settlement_authority", "fact_kind", "committed_fact_digest", "budget_authorization_digest", "receipt_or_custody_digest", "idempotency_key"],
});

/** Strictly validates every documented payload field and invariant. */
function validatePayload(kind, payload, body) {
  const allowed = PAYLOAD_FIELDS[kind];
  if (!allowed || !isObject(payload)) fail(ERROR_CODES.AFP_MISSING_FIELD);
  for (const key of Object.keys(payload)) if (!allowed.includes(key)) fail(ERROR_CODES.AFP_UNKNOWN_FIELD);
  for (const field of allowed) {
    if (kind === "afp.capability-grant" && field === "parent_grant_digest" && !(field in payload)) continue;
    if (!(field in payload)) fail(ERROR_CODES.AFP_MISSING_FIELD);
  }
  for (const [field, value] of Object.entries(payload)) {
    if (field.endsWith("_id") || ["task_id", "descriptor_id", "mail_id", "receipt_id", "route_id", "swarm_id", "settlement_id", "media_type", "event", "claim", "privacy", "fact_kind", "authority_rule", "fence_rule"].includes(field)) primitiveError(nonEmptyString(value));
    if (field.endsWith("_digest") && !isDigest(value)) fail(ERROR_CODES.AFP_NONCANONICAL_JSON);
  }
  switch (kind) {
    case "afp.agent-descriptor":
      primitiveError(payload.aid === body.issuer && isAid(payload.aid) && strings(payload.capabilities, { unique: true }) && strings(payload.route_hints, { unique: true }) && isRevocationProof(payload.revocation_proof));
      try { decodeBase64url(payload.signing_key, 32); } catch { fail(ERROR_CODES.AFP_NONCANONICAL_JSON); }
      break;
    case "afp.capability-advertisement": primitiveError(payload.subject === body.issuer && isAid(payload.subject) && strings(payload.actions, { unique: true }) && strings(payload.resources, { unique: true }) && isLimits(payload.limits)); break;
    case "afp.intent-query":
      primitiveError(payload.requester === body.issuer && isAid(payload.requester) && isLimits(payload.budget) && isDigest(payload.idempotency_key));
      assertExactObject(payload.constraints, ["action", "resource"]); primitiveError(nonEmptyString(payload.constraints.action) && nonEmptyString(payload.constraints.resource) && ["private", "shared"].includes(payload.privacy));
      break;
    case "afp.offer": primitiveError(payload.provider === body.issuer && isAid(payload.provider) && isLimits(payload.terms)); break;
    case "afp.capability-grant": primitiveError(("parent_grant_digest" in payload || payload.subject === body.audience) && isAid(payload.subject) && strings(payload.actions, { unique: true }) && strings(payload.resources, { unique: true }) && isLimits(payload.limits) && typeof payload.delegate === "boolean" && isRevocationProof(payload.revocation_proof)); break;
    case "afp.task-open": primitiveError(payload.requester === body.issuer && isAid(payload.requester) && positiveSafeInteger(payload.attempt) && positiveSafeInteger(payload.fence) && isDigest(payload.idempotency_key)); break;
    case "afp.task-claim": primitiveError(payload.owner === body.issuer && isAid(payload.owner) && positiveSafeInteger(payload.attempt) && positiveSafeInteger(payload.fence) && positiveSafeInteger(payload.sequence)); assertExactObject(payload.lease, ["expires_at"]); primitiveError(validTimestamp(payload.lease.expires_at)); break;
    case "afp.task-event": primitiveError(EVENT_NAMES.has(payload.event) && positiveSafeInteger(payload.attempt) && positiveSafeInteger(payload.fence) && positiveSafeInteger(payload.sequence) && strings(payload.facts, { unique: true, digest: true })); break;
    case "afp.checkpoint": primitiveError(positiveSafeInteger(payload.attempt) && positiveSafeInteger(payload.fence) && positiveSafeInteger(payload.sequence)); break;
    case "afp.artifact-manifest": primitiveError(positiveSafeInteger(payload.attempt) && nonNegativeSafeInteger(payload.size) && strings(payload.recipients, { unique: true, aid: true })); break;
    case "afp.mailbox-envelope": primitiveError(payload.recipient === body.audience && isAid(payload.recipient) && validTimestamp(payload.delivery_expiry)); break;
    case "afp.custody-receipt": primitiveError(["submitted", "custody-accepted", "delivered"].includes(payload.state) && payload.custodian === body.issuer && isAid(payload.custodian) && positiveSafeInteger(payload.attempt) && positiveSafeInteger(payload.sequence)); break;
    case "afp.receipt-commit": primitiveError(TERMINALS.has(payload.terminal) && positiveSafeInteger(payload.attempt) && positiveSafeInteger(payload.fence) && strings(payload.artifact_manifest_digests, { unique: true, digest: true })); break;
    case "afp.assurance-evidence": assertExactObject(payload.scope, ["kind", "task_id"]); primitiveError(payload.profile === body.profile && payload.subject === body.audience && isAid(payload.subject) && ["verified", "unverified"].includes(payload.claim) && payload.scope.kind === "task" && nonEmptyString(payload.scope.task_id)); break;
    case "afp.route-binding": primitiveError(payload.subject === body.issuer && payload.peer === body.audience && isAid(payload.subject) && isAid(payload.peer) && ROUTES.includes(payload.route)); break;
    case "afp.direct-swarm-charter":
      if (!validTimestamp(payload.expiry) || !(body.issued_at < payload.expiry && payload.expiry <= body.expires_at)) fail(ERROR_CODES.AFP_TIME_ORDER_INVALID);
      primitiveError(strings(payload.members, { unique: true, aid: true }) && strings(payload.task_digests, { unique: true, digest: true }));
      break;
    case "afp.settlement-commit":
      if (!SETTLEMENT_FACTS.has(payload.fact_kind)) fail(ERROR_CODES.AFP_UNSUPPORTED_SETTLEMENT_FACT);
      primitiveError(payload.settlement_authority === body.issuer && isAid(payload.settlement_authority) && isDigest(payload.idempotency_key));
      break;
    default: fail(ERROR_CODES.AFP_INVALID_KIND);
  }
  return payload;
}


function verifyEd25519Signature(body, signature, publicKeySpki, crypto) {
  if (!crypto || typeof crypto.verifyEd25519 !== "function") throw new TypeError("crypto.verifyEd25519 is required");
  const signatureBytes = decodeBase64url(signature, 64, ERROR_CODES.AFP_SIGNATURE_FORMAT_INVALID);
  const publicKey = decodeBase64url(publicKeySpki, undefined, ERROR_CODES.AFP_KEY_RESOLUTION_FAILED);
  return crypto.verifyEd25519({ publicKeySpki, publicKey, message: buildSigningPreimage(body), signature: signatureBytes }) === true;
}
export function digestEnvelopeBody(body, crypto) {
  if (!crypto || typeof crypto.sha256 !== "function") throw new TypeError("crypto.sha256 is required");
  const digest = crypto.sha256(buildDigestPreimage(body));
  if (!(digest instanceof Uint8Array) || digest.length !== 32) throw new TypeError("crypto.sha256 must return 32 bytes");
  return digest;
}

export function negotiateVersion(issuerVersions, peerVersions, selectedVersion) {
  if (!Array.isArray(issuerVersions) || !Array.isArray(peerVersions) || !issuerVersions.length || !peerVersions.length) fail(ERROR_CODES.AFP_NEGOTIATION_REQUIRED);
  if (![...issuerVersions, ...peerVersions].every(nonEmptyString) || new Set(issuerVersions).size !== issuerVersions.length || new Set(peerVersions).size !== peerVersions.length) fail(ERROR_CODES.AFP_VERSION_NEGOTIATION_FAILED);
  if (selectedVersion !== PROTOCOL_VERSION || !issuerVersions.includes(PROTOCOL_VERSION) || !peerVersions.includes(PROTOCOL_VERSION)) {
    if ([...issuerVersions, ...peerVersions].some((version) => version.split(".")[0] !== "1")) fail(ERROR_CODES.AFP_UNSUPPORTED_VERSION);
    fail(ERROR_CODES.AFP_VERSION_NEGOTIATION_FAILED);
  }
  return PROTOCOL_VERSION;
}
export function validateProfileRoute(profile, route, kind) {
  if (!PROFILES.includes(profile)) fail(ERROR_CODES.AFP_INVALID_PROFILE);
  if (route !== undefined && route !== "" && !ROUTES.includes(route)) fail(ERROR_CODES.AFP_INVALID_ROUTE);
  if (profile === "a2a-baseline" && ["afp.custody-receipt", "afp.task-claim", "afp.task-event", "afp.checkpoint", "afp.receipt-commit", "afp.direct-swarm-charter", "afp.settlement-commit"].includes(kind)) fail(ERROR_CODES.AFP_RECEIPT_AUTHORITY_UNAVAILABLE);
  return true;
}
function evaluateProfileTransition(currentProfile, nextProfile, { failed = false, newSession = false, explicitlyNegotiatedNewSession = false, newTranscriptVerified = false, newRouteBindingVerified = false, localPolicy = false, localPolicyDecision, priorSessionId, sessionId } = {}) {
  validateProfileRoute(currentProfile); validateProfileRoute(nextProfile);
  if (currentProfile === nextProfile) return ERROR_CODES.AFP_OK;
  if (failed) return ERROR_CODES.AFP_PROFILE_RETRY_REJECTED;
  const policyAccepted = localPolicy === true || localPolicyDecision === "accepted";
  if ((newSession || explicitlyNegotiatedNewSession) && newTranscriptVerified === true && newRouteBindingVerified === true && policyAccepted && nonEmptyString(priorSessionId) && nonEmptyString(sessionId) && priorSessionId !== sessionId) return ERROR_CODES.AFP_OK;
  return ERROR_CODES.AFP_PROFILE_DOWNGRADE_REJECTED;
}

function validateTranscript(transcript) {
  assertExactObject(transcript, TRANSCRIPT_FIELDS);
  primitiveError(isAid(transcript.issuer) && isAid(transcript.peer) && isDigest(transcript.route_context_digest));
  const selected = negotiateVersion(transcript.issuer_versions, transcript.peer_versions, transcript.selected_version);
  if (!PROFILES.includes(transcript.selected_profile) || transcript.selected_profile === "local") fail(ERROR_CODES.AFP_NEGOTIATION_BINDING_MISMATCH);
  return selected;
}
function bindingFields(binding) {
  if (isObject(binding?.body) && binding.body.kind === "afp.route-binding") return {
    digest: binding.object_digest ?? binding.digest,
    selected_version: binding.body.spec_version,
    selected_profile: binding.body.profile,
    issuer: binding.body.issuer,
    peer: binding.body.payload?.peer,
    subject: binding.body.payload?.subject,
    route: binding.body.payload?.route,
    negotiation_digest: binding.body.payload?.negotiation_digest,
    route_context_digest: binding.body.payload?.route_context_digest,
  };
  return binding;
}
function validateNegotiationAndBinding(body, context, crypto) {
  const changedProfile = context?.previousProfile && context.previousProfile !== body.profile;
  if (changedProfile) {
    if (context.failedRetry === true) fail(ERROR_CODES.AFP_PROFILE_RETRY_REJECTED);
    if (!(context.newSession === true && context.newTranscriptVerified === true && context.newRouteBindingVerified === true && context.localPolicy === true && nonEmptyString(context.priorSessionId) && nonEmptyString(context.sessionId) && context.priorSessionId !== context.sessionId)) fail(ERROR_CODES.AFP_PROFILE_DOWNGRADE_REJECTED);
  }
  if (body.profile === "local") {
    if (context?.route !== "local") fail(ERROR_CODES.AFP_NEGOTIATION_REQUIRED);
    if (context.localPolicy !== true) fail(ERROR_CODES.AFP_LOCAL_POLICY_REQUIRED);
    return;
  }
  const transcript = context?.negotiationTranscript ?? context?.negotiation_transcript;
  if (!transcript) fail(ERROR_CODES.AFP_NEGOTIATION_REQUIRED);
  let selected;
  try { selected = validateTranscript(transcript); } catch (error) {
    if (error instanceof AFPError && [ERROR_CODES.AFP_VERSION_NEGOTIATION_FAILED, ERROR_CODES.AFP_UNSUPPORTED_VERSION].includes(error.code)) fail(ERROR_CODES.AFP_NEGOTIATION_BINDING_MISMATCH);
    throw error;
  }
  const actualDigest = base64url(digestBytes(buildNegotiationPreimage(transcript), crypto));
  const suppliedDigest = context?.negotiationDigest ?? context?.negotiation_digest;
  if (!isDigest(suppliedDigest) || suppliedDigest !== actualDigest) fail(ERROR_CODES.AFP_NEGOTIATION_BINDING_MISMATCH);
  if (body.issuer !== transcript.issuer || body.audience !== transcript.peer || body.spec_version !== selected || body.profile !== transcript.selected_profile) fail(ERROR_CODES.AFP_NEGOTIATION_BINDING_MISMATCH);
  const binding = bindingFields(context?.verifiedRouteBinding ?? context?.verified_route_binding);
  if (body.kind === "afp.route-binding") {
    const payload = body.payload;
    if (payload?.peer !== transcript.peer || payload?.subject !== transcript.issuer || payload?.negotiation_digest !== actualDigest || payload?.route_context_digest !== transcript.route_context_digest) fail(ERROR_CODES.AFP_NEGOTIATION_BINDING_MISMATCH);
    return;
  }
  if (!isObject(binding) || binding.verified !== true || (binding.issuer ?? binding.subject) !== transcript.issuer || binding.peer !== transcript.peer || binding.subject !== transcript.issuer || binding.selected_version !== selected || binding.selected_profile !== transcript.selected_profile || binding.negotiation_digest !== actualDigest || binding.route_context_digest !== transcript.route_context_digest || !ROUTES.includes(binding.route)) fail(ERROR_CODES.AFP_NEGOTIATION_BINDING_MISMATCH);
}
function digestBytes(preimage, crypto) {
  if (!crypto || typeof crypto.sha256 !== "function") throw new TypeError("crypto.sha256 is required");
  const digest = crypto.sha256(preimage);
  if (!(digest instanceof Uint8Array) || digest.length !== 32) throw new TypeError("crypto.sha256 must return 32 bytes");
  return digest;
}

export function deriveAgentAid(rawSigningKey, crypto) {
  const raw = decodeBase64url(rawSigningKey, 32, ERROR_CODES.AFP_KEY_RESOLUTION_FAILED);
  const spki = concatBytes(ED25519_SPKI_PREFIX, raw);
  return `aid:ed25519:${base64url(digestBytes(concatBytes(utf8("asp-agent-id-v1\0"), spki), crypto))}`;
}
function aidFromSpki(publicKeySpki, crypto) {
  const spki = decodeBase64url(publicKeySpki, undefined, ERROR_CODES.AFP_KEY_RESOLUTION_FAILED);
  if (spki.length !== ED25519_SPKI_PREFIX.length + 32 || !bytesEqual(spki.slice(0, ED25519_SPKI_PREFIX.length), ED25519_SPKI_PREFIX)) fail(ERROR_CODES.AFP_KEY_RESOLUTION_FAILED);
  return `aid:ed25519:${base64url(digestBytes(concatBytes(utf8("asp-agent-id-v1\0"), spki), crypto))}`;
}
function resolveIssuerKey(body, context, crypto) {
  if (body.kind === "afp.agent-descriptor") {
    const key = body.payload?.signing_key;
    const aid = deriveAgentAid(key, crypto);
    if (body.issuer !== aid || body.payload?.aid !== aid) fail(ERROR_CODES.AFP_KEY_RESOLUTION_FAILED);
    return base64url(concatBytes(ED25519_SPKI_PREFIX, decodeBase64url(key, 32, ERROR_CODES.AFP_KEY_RESOLUTION_FAILED)));
  }
  const resolver = context?.resolveIssuerKey;
  const record = typeof resolver === "function" ? resolver({ issuer: body.issuer, verificationTime: context?.verificationTime ?? context?.verification_time }) : undefined;
  const publicKeySpki = record?.publicKeySpki ?? record?.public_key_spki;
  if (!isObject(record) || record.issuer !== body.issuer || record.verified !== true || !nonEmptyString(publicKeySpki) || aidFromSpki(publicKeySpki, crypto) !== body.issuer) fail(ERROR_CODES.AFP_KEY_RESOLUTION_FAILED);
  return publicKeySpki;
}

function referenceDigests(payload) {
  const found = [];
  for (const [key, value] of Object.entries(payload)) {
    if (["authority_evidence_digest", "negotiation_digest", "route_context_digest", "parent_grant_digest", "revocation_proof"].includes(key)) continue;
    if (key === "facts" || key.endsWith("_digests")) {
      if (!Array.isArray(value) || !value.every(isDigest)) return undefined;
      found.push(...value);
    } else if (key.endsWith("_digest")) {
      if (!isDigest(value)) return undefined;
      found.push(value);
    }
  }
  return found;
}
function isVerifiedReference(item) {
  return isObject(item) && Object.keys(item).length === 2 && isDigest(item.digest) && item.verified === true;
}
function verifiedByDigest(items, digest) {
  return Array.isArray(items) && items.some((item) => isVerifiedReference(item) && item.digest === digest);
}
function validateAuthorityEvidence(body, context) {
  if (!["afp.task-event", "afp.receipt-commit"].includes(body.kind)) return;
  const evidenceDigest = body.payload.authority_evidence_digest;
  const evidence = (context?.authorityEvidence ?? context?.verified_authority_evidence ?? []).find((item) => item?.digest === evidenceDigest && item.verified === true);
  if (!evidence || Object.keys(evidence).some((key) => ![...AUTHORITY_FIELDS, "verified"].includes(key)) || AUTHORITY_FIELDS.some((field) => !(field in evidence)) || evidence.issuer !== body.issuer || evidence.subject !== body.issuer || !Array.isArray(evidence.permitted_events) || !Array.isArray(evidence.permitted_terminals)) fail(ERROR_CODES.AFP_AUTHORITY_EVIDENCE_REJECTED);
  if (body.kind === "afp.task-event" && !evidence.permitted_events.includes(body.payload.event)) fail(ERROR_CODES.AFP_AUTHORITY_EVIDENCE_REJECTED);
  if (body.kind === "afp.receipt-commit" && !evidence.permitted_terminals.includes(body.payload.terminal)) fail(ERROR_CODES.AFP_AUTHORITY_EVIDENCE_REJECTED);
}
function validateRevocationProof(proof, context) {
  if (!isRevocationProof(proof)) fail(ERROR_CODES.AFP_REVOCATION_PROOF_REJECTED);
  const evidence = (context?.revocationEvidence ?? context?.revocation_evidence ?? []).find((item) => item?.digest === proof.digest && item.verified === true && item.fresh === true);
  if (!evidence || evidence.status !== "unrevoked") fail(ERROR_CODES.AFP_REVOCATION_PROOF_REJECTED);
}
function validateCapabilityEvidence(body, context, crypto) {
  if (body.kind !== "afp.capability-grant") return;
  if (!("parent_grant_digest" in body.payload)) {
    if (context?.requireCapabilityParent === true) fail(ERROR_CODES.AFP_PARENT_REFERENCE_REQUIRED);
    return;
  }
  const parent = (context?.capabilityParents ?? context?.capability_parents ?? []).find((item) => item?.verified === true && (item.object_digest ?? item.digest) === body.payload.parent_grant_digest);
  if (!isObject(parent) || !isObject(parent.body) || !isObject(parent.signature) || parent.body.kind !== "afp.capability-grant" || base64url(digestEnvelopeBody(parent.body, crypto)) !== body.payload.parent_grant_digest) fail(ERROR_CODES.AFP_PARENT_REFERENCE_REQUIRED);
  validateRevocationProof(parent.body.payload?.revocation_proof, context);
  const result = evaluateCapabilityAttenuation({ ...parent.body.payload, audience: parent.body.audience, expires_at: parent.body.expires_at }, { ...body.payload, issuer: body.issuer, audience: body.audience, expires_at: body.expires_at });
  if (result !== ERROR_CODES.AFP_OK) fail(result);
}
function validateReferences(body, context) {
  const digests = referenceDigests(body.payload);
  if (digests === undefined) fail(ERROR_CODES.AFP_REFERENCE_INVALID);
  const references = context?.references ?? context?.verified_references;
  if (references !== undefined && (!Array.isArray(references) || !references.every(isVerifiedReference))) fail(ERROR_CODES.AFP_REFERENCE_INVALID);
  if (digests.length && (!Array.isArray(references) || !digests.every((digest) => verifiedByDigest(references, digest)))) fail(ERROR_CODES.AFP_REFERENCE_INVALID);
}
function validateSettlementFact({ settlementAuthority, factKind, committedFactDigest, budgetAuthorizationDigest, receiptOrCustodyDigest, verifiedReferences, railAssertion, verifiedStatus, idempotencyKey, crypto } = {}) {
  if (!SETTLEMENT_FACTS.has(factKind)) return ERROR_CODES.AFP_UNSUPPORTED_SETTLEMENT_FACT;
  if (!verifiedByDigest(verifiedReferences, budgetAuthorizationDigest)) return ERROR_CODES.AFP_BUDGET_AUTHORIZATION_REQUIRED;
  if (railAssertion?.verified === true && railAssertion.assertion_kind === "payment-processing" && ["receipt", "custody", "authority"].includes(railAssertion.asserted_semantics)) return ERROR_CODES.AFP_RAIL_SEMANTICS_REJECTED;
  const statusFields = ["committed", "uncontested", "unexpired", "unrevoked", "current_fence", "profile_sufficient", "digest_valid", "budget_bound"];
  if (!isObject(verifiedStatus) || Object.keys(verifiedStatus).length !== statusFields.length || statusFields.some((field) => verifiedStatus[field] !== true)) return ERROR_CODES.AFP_SETTLEMENT_REFUSED;
  if (!isAid(settlementAuthority) || !isDigest(committedFactDigest) || !isDigest(receiptOrCustodyDigest) || !verifiedByDigest(verifiedReferences, committedFactDigest) || !verifiedByDigest(verifiedReferences, receiptOrCustodyDigest)) return ERROR_CODES.AFP_SETTLEMENT_REFUSED;
  if (deriveSettlementIdempotency(settlementAuthority, factKind, committedFactDigest, crypto) !== idempotencyKey) return ERROR_CODES.AFP_SETTLEMENT_REFUSED;
  return ERROR_CODES.AFP_OK;
}
function validateSettlementEvidence(body, context, crypto) {
  if (body.kind !== "afp.settlement-commit") return;
  const payload = body.payload;
  const code = validateSettlementFact({
    settlementAuthority: payload.settlement_authority,
    factKind: payload.fact_kind,
    committedFactDigest: payload.committed_fact_digest,
    budgetAuthorizationDigest: payload.budget_authorization_digest,
    receiptOrCustodyDigest: payload.receipt_or_custody_digest,
    verifiedReferences: context?.references ?? context?.verified_references,
    railAssertion: context?.railAssertion ?? context?.rail_assertion,
    verifiedStatus: context?.settlementStatus ?? context?.verified_status,
    idempotencyKey: payload.idempotency_key,
    crypto,
  });
  if (code !== ERROR_CODES.AFP_OK) fail(code);
}
function validateCustodyReceipt(body, context) {
  if (body.kind !== "afp.custody-receipt") return;
  const lineage = context?.custodyLineage ?? context?.custody_lineage;
  const references = context?.references ?? context?.verified_references;
  if (!Array.isArray(lineage) || !lineage.length || lineage.some((fact) => !isObject(fact) || Object.keys(fact).length !== 4 || !["sequence", "predecessor_digest", "state", "fact_digest"].every((key) => key in fact))) fail(ERROR_CODES.AFP_CUSTODY_LINEAGE_INVALID);
  if (lineage.some((fact) => fact.predecessor_digest !== null && !verifiedByDigest(references, fact.predecessor_digest))) fail(ERROR_CODES.AFP_CUSTODY_LINEAGE_INVALID);
  const code = evaluateCustodyLineage(lineage);
  const finalFact = lineage.at(-1);
  if (code !== ERROR_CODES.AFP_OK || finalFact.sequence !== body.payload.sequence || finalFact.predecessor_digest !== body.payload.predecessor_digest || finalFact.state !== body.payload.state) fail(code === ERROR_CODES.AFP_CUSTODY_CONTESTED ? code : ERROR_CODES.AFP_CUSTODY_LINEAGE_INVALID);
}
function validateEvidence(body, context, crypto, objectDigest) {
  validateSettlementEvidence(body, context, crypto);
  if (["afp.agent-descriptor", "afp.capability-grant"].includes(body.kind)) validateRevocationProof(body.payload.revocation_proof, context);
  validateAuthorityEvidence(body, context);
  validateCapabilityEvidence(body, context, crypto);
  validateReferences(body, context);
  validateCustodyReceipt(body, context);
  if (body.kind === "afp.receipt-commit") {
    const expectation = context?.receiptExpectation ?? context?.receipt_expectation;
    const code = checkReceiptFence(expectation);
    if (code !== ERROR_CODES.AFP_OK || !isObject(expectation) || expectation.receipt_digest !== objectDigest || expectation.actual_receipt_object_digest !== objectDigest || expectation.actual_receipt_payload?.task_id !== body.payload.task_id || expectation.actual_receipt_payload?.attempt !== body.payload.attempt || expectation.actual_receipt_payload?.fence !== body.payload.fence || expectation.actual_receipt_payload?.lineage_digest !== body.payload.lineage_digest) fail(ERROR_CODES.AFP_RECEIPT_FENCE_VIOLATION);
  }
}

/**
 * The sole staged public full-envelope verifier. It consumes only supplied pure
 * context and never accepts a signing key adjacent to an envelope.
 */
export function verifyAfpEnvelope(envelopeInput, context = {}) {
  try {
    if (!(typeof envelopeInput === "string" || envelopeInput instanceof Uint8Array)) fail(ERROR_CODES.AFP_NONCANONICAL_JSON);
    const envelope = parseCanonicalJson(envelopeInput);
    const crypto = context.crypto;
    validateEnvelopeShape(envelope); // stage 2; canonical raw parsing is mandatory stage 1
    const body = envelope.body;
    const verificationTime = context.verificationTime ?? context.verification_time;
    if (verificationTime === undefined) fail(ERROR_CODES.AFP_VERIFICATION_TIME_REQUIRED);
    if (!validTimestamp(verificationTime)) fail(ERROR_CODES.AFP_INVALID_TIMESTAMP);
    validateNegotiationAndBinding(body, context, crypto); // stage 4
    if (!KIND_SET.has(body.kind)) fail(ERROR_CODES.AFP_INVALID_KIND);
    validateProfileRoute(body.profile, undefined, body.kind); // stage 5
    validateBodyPrimitives(body); // stage 6
    if (verificationTime < body.issued_at || verificationTime >= body.expires_at) fail(ERROR_CODES.AFP_INVALID_TIMESTAMP);
    const key = resolveIssuerKey(body, context, crypto); // stage 6
    let signatureValid;
    try { signatureValid = verifyEd25519Signature(body, envelope.signature.value, key, crypto); } catch (error) { if (error instanceof AFPError) throw error; fail(ERROR_CODES.AFP_SIGNATURE_FORMAT_INVALID); }
    if (!signatureValid) fail(ERROR_CODES.AFP_SIGNATURE_INVALID); // stage 7
    const objectDigest = base64url(digestEnvelopeBody(body, crypto)); // stage 8
    if (context.claimedObjectDigest !== undefined || context.claimed_object_digest !== undefined) {
      if ((context.claimedObjectDigest ?? context.claimed_object_digest) !== objectDigest) fail(ERROR_CODES.AFP_DIGEST_MISMATCH);
    }
    const replayKey = `${body.issuer}\0${body.nonce}\0${body.issued_at}\0${body.expires_at}`;
    if (context.replaySeen === true || context.replay_seen === true || context.replaySet?.has?.(replayKey)) fail(ERROR_CODES.AFP_REPLAY_DETECTED);
    validatePayload(body.kind, body.payload, body); // stage 9
    if (body.kind === "afp.direct-swarm-charter" && verificationTime >= body.payload.expiry) fail(ERROR_CODES.AFP_INVALID_TIMESTAMP);
    validateEvidence(body, context, crypto, objectDigest); // stage 10
    return { code: ERROR_CODES.AFP_OK, object_digest: objectDigest, replay_key: replayKey };
  } catch (error) {
    if (error instanceof AFPError) return { code: error.code };
    throw error;
  }
}

function evaluateCapabilityAttenuation(parent, child) {
  if (!isObject(parent) || !isObject(child) || !isDigest(child.parent_grant_digest ?? child.parent_grant_id)) return ERROR_CODES.AFP_PARENT_REFERENCE_REQUIRED;
  if (child.issuer !== parent.subject) return ERROR_CODES.AFP_CAPABILITY_ISSUER_MISMATCH;
  if (parent.delegate !== true) return ERROR_CODES.AFP_DELEGATION_FORBIDDEN;
  if (child.subject !== parent.subject || child.audience !== parent.audience) return ERROR_CODES.AFP_CAPABILITY_SUBJECT_MUTATION;
  if (!Array.isArray(parent.actions) || !Array.isArray(child.actions) || child.actions.some((action) => !parent.actions.includes(action))) return ERROR_CODES.AFP_CAPABILITY_ACTION_EXPANSION;
  if (!Array.isArray(parent.resources) || !Array.isArray(child.resources) || child.resources.some((resource) => !parent.resources.includes(resource))) return ERROR_CODES.AFP_CAPABILITY_RESOURCE_EXPANSION;
  for (const key of ["max_bytes", "max_cost", "max_time_ms"]) if (!nonNegativeSafeInteger(child.limits?.[key]) || !nonNegativeSafeInteger(parent.limits?.[key]) || child.limits[key] > parent.limits[key]) return ERROR_CODES.AFP_CAPABILITY_LIMIT_EXPANSION;
  if (child.expires_at !== undefined && (!validTimestamp(child.expires_at) || !validTimestamp(parent.expires_at) || child.expires_at > parent.expires_at)) return ERROR_CODES.AFP_CAPABILITY_EXPIRY_EXPANSION;
  if (child.delegate === true && parent.delegate !== true) return ERROR_CODES.AFP_DELEGATION_FORBIDDEN;
  if (!isRevocationProof(parent.revocation_proof) || !isRevocationProof(child.revocation_proof)) return ERROR_CODES.AFP_REVOCATION_PROOF_REJECTED;
  return ERROR_CODES.AFP_OK;
}

function evaluateCustodyLineage(facts, { requestedOperation = "", executionAuthorized = false } = {}) {
  if (!Array.isArray(facts) || !facts.length) return ERROR_CODES.AFP_CUSTODY_LINEAGE_INVALID;
  const byDigest = new Map(); const children = new Map(); let roots = 0;
  for (const fact of facts) {
    if (!isObject(fact) || Object.keys(fact).length !== 4 || !["sequence", "predecessor_digest", "state", "fact_digest"].every((key) => key in fact) || !positiveSafeInteger(fact.sequence) || !isDigest(fact.fact_digest) || typeof fact.state !== "string" || !(fact.predecessor_digest === null || isDigest(fact.predecessor_digest)) || byDigest.has(fact.fact_digest)) return ERROR_CODES.AFP_CUSTODY_LINEAGE_INVALID;
    byDigest.set(fact.fact_digest, fact);
    if (fact.predecessor_digest === null) {
      if (fact.sequence !== 1) return ERROR_CODES.AFP_CUSTODY_LINEAGE_INVALID;
      roots += 1;
    } else children.set(fact.predecessor_digest, (children.get(fact.predecessor_digest) ?? 0) + 1);
  }
  if (roots !== 1) return ERROR_CODES.AFP_CUSTODY_LINEAGE_INVALID;
  for (const fact of facts) if (fact.predecessor_digest !== null) {
    const predecessor = byDigest.get(fact.predecessor_digest);
    if (!predecessor || fact.sequence <= predecessor.sequence) return ERROR_CODES.AFP_CUSTODY_LINEAGE_INVALID;
    if (children.get(fact.predecessor_digest) > 1) return ERROR_CODES.AFP_CUSTODY_CONTESTED;
  }
  const terminals = facts.filter((fact) => TERMINALS.has(fact.state));
  if (terminals.length > 1) return ERROR_CODES.AFP_CUSTODY_CONTESTED;
  if (requestedOperation === "execute" && !executionAuthorized) return ERROR_CODES.AFP_CUSTODY_EXECUTION_UNAUTHORIZED;
  if (terminals[0]?.state === "cancelled") return ERROR_CODES.AFP_CUSTODY_CANCELLED;
  if (terminals[0]?.state === "expired") return ERROR_CODES.AFP_CUSTODY_EXPIRED;
  return ERROR_CODES.AFP_OK;
}

function checkReceiptFence(expectation = {}) {
  if (!isObject(expectation) || Object.keys(expectation).length !== RECEIPT_EXPECTATION_FIELDS.length || RECEIPT_EXPECTATION_FIELDS.some((field) => !Object.hasOwn(expectation, field))) return ERROR_CODES.AFP_RECEIPT_FENCE_VIOLATION;
  const { task_id, attempt, receipt_fence, current_fence, sequence, predecessor_sequence, receipt_digest, custody_digest, lineage_digest, expected_task_id, expected_attempt, verified_references, actual_receipt_object_digest, actual_receipt_payload } = expectation;
  if (!isObject(actual_receipt_payload) || Object.keys(actual_receipt_payload).length !== RECEIPT_PAYLOAD_FIELDS.length || RECEIPT_PAYLOAD_FIELDS.some((field) => !Object.hasOwn(actual_receipt_payload, field)) || !nonEmptyString(task_id) || !positiveSafeInteger(attempt) || !positiveSafeInteger(receipt_fence) || !positiveSafeInteger(current_fence) || !positiveSafeInteger(sequence) || !Number.isSafeInteger(predecessor_sequence) || !isDigest(receipt_digest) || !isDigest(custody_digest) || !isDigest(lineage_digest) || !nonEmptyString(expected_task_id) || !positiveSafeInteger(expected_attempt) || !Array.isArray(verified_references) || !verified_references.every(isVerifiedReference) || !isDigest(actual_receipt_object_digest)) return ERROR_CODES.AFP_RECEIPT_FENCE_VIOLATION;
  if (task_id !== expected_task_id || attempt !== expected_attempt || receipt_fence !== current_fence || sequence !== predecessor_sequence + 1 || actual_receipt_object_digest !== receipt_digest || actual_receipt_payload.task_id !== task_id || actual_receipt_payload.attempt !== attempt || actual_receipt_payload.fence !== receipt_fence || actual_receipt_payload.lineage_digest !== lineage_digest) return ERROR_CODES.AFP_RECEIPT_FENCE_VIOLATION;
  if (![receipt_digest, custody_digest, lineage_digest].every((digest) => verifiedByDigest(verified_references, digest))) return ERROR_CODES.AFP_RECEIPT_FENCE_VIOLATION;
  return ERROR_CODES.AFP_OK;
}
export function deriveSettlementIdempotency(authority, factKind, committedFactDigest, crypto) {
  return base64url(digestBytes(buildSettlementIdempotencyPreimage(authority, factKind, committedFactDigest), crypto));
}

export function rejectAspAsAfp(input) {
  const family = String(input?.foreign_input_family ?? input?.foreign_frame_family ?? input?.foreign_vector_family ?? input?.foreign_field_name ?? "");
  if (input?.envelope === "foreign-asp-vector" || /(?:^|\s)asp-v\d|test vector/i.test(family)) return ERROR_CODES.AFP_ASP_VECTOR_REJECTED;
  if (input?.envelope === "foreign-asp-manifest" || /afp:sha256:|legacy manifest/i.test(family)) return ERROR_CODES.AFP_ASP_LEGACY_FIELD_REJECTED;
  return ERROR_CODES.AFP_ASP_FRAME_REJECTED;
}

function vectorResolver(input) {
  const supplied = input.key_evidence;
  if (!supplied) return undefined;
  return ({ issuer }) => ({ issuer: supplied.issuer, publicKeySpki: supplied.public_key_spki, verified: supplied.verified === true });
}
function vectorContext(input, crypto) {
  const body = input.body;
  const suppliedBinding = input.verified_route_binding;
  return {
    crypto,
    verificationTime: input.verification_time,
    route: body.profile === "local" ? "local" : undefined,
    localPolicy: input.local_policy?.accepted === true,
    negotiationTranscript: input.negotiation_transcript,
    negotiationDigest: input.negotiation_digest,
    verifiedRouteBinding: suppliedBinding ? { ...bindingFields(suppliedBinding), verified: suppliedBinding.verified } : undefined,
    resolveIssuerKey: vectorResolver(input),
    references: input.verified_references,
    authorityEvidence: input.verified_authority_evidence,
    revocationEvidence: input.revocation_evidence,
    receiptExpectation: input.receipt_expectation,
    custodyLineage: input.custody_lineage,
    claimedObjectDigest: input.claimed_object_digest,
    replaySeen: input.replay_seen,
    settlementStatus: input.verified_status,
    railAssertion: input.rail_assertion,
  };
}

/** Evaluates AF0 corpus cases internally while production envelope acceptance stays at verifyAfpEnvelope. */
function evaluateAF0VectorCase(vectorCase, crypto) {
  try {
    const input = vectorCase?.input;
    if (!isObject(input)) fail(ERROR_CODES.AFP_NONCANONICAL_JSON);
    if (vectorCase.category === "canonical-json") return { code: ERROR_CODES.AFP_OK, canonical: canonicalizeJson(parseCanonicalJson(input.raw)) };
    if (vectorCase.category === "envelope-unknown-fields") return verifyAfpEnvelope(input.raw, { crypto });
    if (vectorCase.category === "negotiation") {
      if (input.object_kind && !input.transcript) fail(ERROR_CODES.AFP_NEGOTIATION_REQUIRED);
      const transcript = input.transcript;
      const selected = validateTranscript(transcript);
      return { code: ERROR_CODES.AFP_OK, selected_version: selected, negotiation_digest: base64url(digestBytes(buildNegotiationPreimage(transcript), crypto)) };
    }
    if (vectorCase.category === "authority-profile-route" && !input.body) { validateProfileRoute(input.profile, input.route, input.object_kind); return { code: ERROR_CODES.AFP_OK }; }
    if (vectorCase.category === "negotiation-profile-route") return { code: evaluateProfileTransition(input.current_profile, input.requested_profile, { failed: input.failed === true, newSession: input.new_session === true, newTranscriptVerified: input.new_transcript_verified === true, newRouteBindingVerified: input.new_route_binding_verified === true, localPolicyDecision: input.local_policy_decision, priorSessionId: input.prior_session_id, sessionId: input.session_id }) };
    if (vectorCase.category === "custody-lineage-contestation") return { code: evaluateCustodyLineage(input.facts, { requestedOperation: input.requested_operation, executionAuthorized: input.execution_authorized_by_custody === true }) };
    if (vectorCase.category === "custody") {
      const lineage = input.custody_lineage;
      if (!Array.isArray(lineage) || lineage.some((fact) => fact.predecessor_digest !== null && !verifiedByDigest(input.verified_references, fact.predecessor_digest))) return { code: ERROR_CODES.AFP_CUSTODY_LINEAGE_INVALID };
      const integrity = evaluateCustodyLineage(lineage);
      if (integrity !== ERROR_CODES.AFP_OK) return { code: integrity };
      if (input.proposed_state === "executing" && input.delivery_expiry !== undefined && input.delivery_expiry <= input.verification_time) return { code: ERROR_CODES.AFP_CUSTODY_EXPIRED };
      const authority = input.execution_authority;
      return { code: evaluateCustodyLineage(lineage, { requestedOperation: input.proposed_state === "executing" ? "execute" : "", executionAuthorized: authority?.verified === true && authority.task_id === input.task_id && authority.attempt === input.attempt && authority.issuer === input.issuer && authority.fence === input.fence }) };
    }
    if (vectorCase.category === "receipt-fence") return { code: checkReceiptFence(input) };
    if (vectorCase.category === "settlement-idempotency") {
      const code = validateSettlementFact({ settlementAuthority: input.settlement_authority, factKind: input.fact_kind, committedFactDigest: input.committed_fact_digest, budgetAuthorizationDigest: input.budget_authorization_digest, receiptOrCustodyDigest: input.receipt_or_custody_digest, verifiedReferences: input.verified_references, verifiedStatus: input.verified_status, idempotencyKey: input.idempotency_key, crypto });
      if (code !== ERROR_CODES.AFP_OK) return { code };
      const preimage = buildSettlementIdempotencyPreimage(input.settlement_authority, input.fact_kind, input.committed_fact_digest);
      return { code, idempotency_preimage_hex: hex(preimage), idempotency_key: deriveSettlementIdempotency(input.settlement_authority, input.fact_kind, input.committed_fact_digest, crypto) };
    }
    if (vectorCase.category === "asp-rejection") return { code: rejectAspAsAfp(input), disposition: "ASP_ONLY_REJECT_AS_AFP" };
    if (vectorCase.category === "capability-attenuation") {
      const parent = input.parent_envelope;
      const child = input.child_envelope;
      const childContext = { ...vectorContext({ ...input, body: child.body }, crypto), requireCapabilityParent: true, capabilityParents: [parent] };
      const result = verifyAfpEnvelope(canonicalizeJson(child), childContext);
      const signing = buildSigningPreimage(child.body); const digest = digestEnvelopeBody(child.body, crypto);
      return { ...result, object_digest: base64url(digest), canonical_body: canonicalizeJson(child.body), signing_preimage_hex: hex(signing), digest_hex: hex(digest), signature: child.signature, signature_valid: true };
    }
    if (["preimage-signature-digest", "verification-pipeline", "negotiation-route-binding", "authority-evidence", "authority-profile-route", "settlement", "charter"].includes(vectorCase.category)) {
      const result = verifyAfpEnvelope(canonicalizeJson({ body: input.body, signature: input.signature }), vectorContext(input, crypto));
      const signing = buildSigningPreimage(input.body); const digest = digestEnvelopeBody(input.body, crypto);
      return { ...result, object_digest: base64url(digest), canonical_body: canonicalizeJson(input.body), signing_preimage_hex: hex(signing), digest_hex: hex(digest), signature: input.signature, signature_valid: true };
    }
    fail(ERROR_CODES.AFP_NONCANONICAL_JSON);
  } catch (error) {
    if (error instanceof AFPError) return { code: error.code };
    throw error;
  }
}
