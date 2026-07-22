import assert from "node:assert/strict";
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from "node:crypto";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import * as afp from "../afp-contract.mjs";
const { ERROR_CODES, KIND_SET, PROFILES, PROTOCOL_VERSION, ROUTES, buildNegotiationPreimage, buildSigningPreimage, canonicalizeJson, deriveAgentAid, verifyAfpEnvelope } = afp;

const [vectorsText, afpSource] = await Promise.all([
  readFile(new URL("../test-vectors/afp-v1-af0.json", import.meta.url), "utf8"),
  readFile(new URL("../afp-contract.mjs", import.meta.url), "utf8"),
]);
const vectors = JSON.parse(vectorsText);
const testOnlyAfp = await import(`data:text/javascript;base64,${Buffer.from(afpSource.replace(/(?:export )?function evaluateAF0VectorCase/, "export function evaluateAF0VectorCase")).toString("base64")}`);
const crypto = Object.freeze({
  publicKeySpki: vectors.crypto.public_key_spki,
  sha256(bytes) { return createHash("sha256").update(bytes).digest(); },
  verifyEd25519({ publicKeySpki, message, signature }) {
    return verify(null, message, createPublicKey({ key: Buffer.from(publicKeySpki, "base64url"), format: "der", type: "spki" }), signature);
  },
});
const byId = new Map(vectors.cases.map((vectorCase) => [vectorCase.id, vectorCase]));
function binding(input) {
  const source = input.verified_route_binding;
  if (!source) return undefined;
  const body = source.body;
  const payload = body?.payload;
  return {
    selected_version: body?.spec_version ?? source.selected_version,
    selected_profile: body?.profile ?? source.selected_profile,
    issuer: body?.issuer ?? source.subject,
    subject: payload?.subject ?? source.subject,
    peer: payload?.peer ?? source.peer,
    route: payload?.route ?? source.route,
    negotiation_digest: payload?.negotiation_digest ?? source.negotiation_digest,
    route_context_digest: payload?.route_context_digest ?? source.route_context_digest,
    verified: true,
  };
}
function context(input, extra = {}) {
  return {
    crypto,
    verificationTime: input.verification_time,
    route: input.body.profile === "local" ? "local" : undefined,
    localPolicy: input.local_policy?.accepted === true,
    negotiationTranscript: input.negotiation_transcript,
    negotiationDigest: input.negotiation_digest,
    verifiedRouteBinding: binding(input),
    resolveIssuerKey: ({ issuer }) => ({ issuer: input.key_evidence?.issuer, publicKeySpki: input.key_evidence?.public_key_spki, verified: input.key_evidence?.verified === true }),
    references: input.verified_references,
    authorityEvidence: input.verified_authority_evidence,
    revocationEvidence: input.revocation_evidence,
    receiptExpectation: input.receipt_expectation,
    custodyLineage: input.custody_lineage,
    settlementStatus: input.verified_status,
    railAssertion: input.rail_assertion,
    ...extra,
  };
}
function envelope(body, privateKey) { return { body, signature: { alg: "Ed25519", value: sign(null, buildSigningPreimage(body), privateKey).toString("base64url") } }; }
function vectorPrivateKey() {
  const der = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(vectors.crypto.seed_hex, "hex")]);
  return createPrivateKey({ key: der, format: "der", type: "pkcs8" });
}

test("AF0 corpus schema 1.1 inventory and public constants are complete", () => {
  assert.equal(vectors.format, "afp-af0-v1");
  assert.equal(vectors.schema_version, "afp-v1-af0-test-vectors/1.1");
  assert.equal(vectors.protocol_version, PROTOCOL_VERSION);
  assert.equal(vectors.cases.length, 121);
  assert.equal(vectors.inventory.total_cases, 121);
  assert.equal(vectors.inventory.signed_positive_envelopes, 17);
  assert.deepEqual(vectors.inventory.category_counts, { "asp-rejection": 13, "authority-evidence": 3, "authority-profile-route": 6, "canonical-json": 11, "capability-attenuation": 12, charter: 2, custody: 3, "custody-lineage-contestation": 5, "envelope-unknown-fields": 2, negotiation: 4, "negotiation-profile-route": 3, "negotiation-route-binding": 6, "preimage-signature-digest": 21, "receipt-fence": 6, settlement: 1, "settlement-idempotency": 9, "verification-pipeline": 14 });
  assert.equal(Object.values(vectors.inventory.category_counts).reduce((total, count) => total + count, 0), vectors.inventory.total_cases);
  assert.deepEqual(vectors.inventory.expected_code_counts, Object.fromEntries([...vectors.cases.reduce((counts, vectorCase) => counts.set(vectorCase.expect.code, (counts.get(vectorCase.expect.code) ?? 0) + 1), new Map()).entries()].sort(([left], [right]) => left.localeCompare(right))));
  assert.deepEqual(PROFILES, ["local", "direct", "governed", "a2a-baseline", "a2a-afp"]);
  assert.deepEqual(ROUTES, ["local", "direct", "relayed", "store-forward"]);
  assert.equal(KIND_SET.size, 17);
  for (const code of ["AFP_NEGOTIATION_BINDING_MISMATCH", "AFP_INVALID_KIND", "AFP_INVALID_TIMESTAMP", "AFP_TIME_ORDER_INVALID", "AFP_VERIFICATION_TIME_REQUIRED", "AFP_LOCAL_POLICY_REQUIRED", "AFP_KEY_RESOLUTION_FAILED", "AFP_SIGNATURE_FORMAT_INVALID", "AFP_SIGNATURE_INVALID", "AFP_DIGEST_MISMATCH", "AFP_REPLAY_DETECTED", "AFP_REFERENCE_INVALID", "AFP_AUTHORITY_EVIDENCE_REJECTED", "AFP_SETTLEMENT_REFUSED"]) assert.equal(ERROR_CODES[code], code);
});

test("full verifier rejects unknown nested payload fields", () => {
  const { input } = byId.get("afp.task-open.positive");
  const body = structuredClone(input.body); body.payload.unexpected = true;
  assert.equal(verifyAfpEnvelope(canonicalizeJson(envelope(body, vectorPrivateKey())), context(input)).code, ERROR_CODES.AFP_UNKNOWN_FIELD);
});

for (const vectorCase of vectors.cases) test(`AF0 vector ${vectorCase.id}`, () => {
  const result = testOnlyAfp.evaluateAF0VectorCase(vectorCase, crypto);
  assert.equal(result.code, vectorCase.expect.code);
  for (const [field, expected] of Object.entries(vectorCase.expect)) if (field !== "code") assert.deepEqual(result[field], expected, `${vectorCase.id}: ${field}`);
});

test("AF0 evaluator fails closed when corpus evidence is absent", () => {
  const cases = [
    ["afp.task-open.positive", "verified_references", ERROR_CODES.AFP_REFERENCE_INVALID],
    ["afp.agent-descriptor.positive", "revocation_evidence", ERROR_CODES.AFP_REVOCATION_PROOF_REJECTED],
    ["afp.task-event.positive", "verified_authority_evidence", ERROR_CODES.AFP_AUTHORITY_EVIDENCE_REJECTED],
    ["afp.receipt-commit.positive", "receipt_expectation", ERROR_CODES.AFP_RECEIPT_FENCE_VIOLATION],
    ["afp.settlement-commit.positive", "verified_status", ERROR_CODES.AFP_SETTLEMENT_REFUSED],
  ];
  for (const [id, field, code] of cases) {
    const vectorCase = structuredClone(byId.get(id));
    delete vectorCase.input[field];
    assert.equal(testOnlyAfp.evaluateAF0VectorCase(vectorCase, crypto).code, code, `${id} without ${field}`);
  }
});

test("public full verifier requires canonical bytes and a verified non-local route", () => {
  const { input } = byId.get("afp.task-open.positive");
  assert.equal(verifyAfpEnvelope(canonicalizeJson({ body: input.body, signature: input.signature }), context(input)).code, ERROR_CODES.AFP_OK);
  assert.equal(verifyAfpEnvelope(JSON.stringify({ body: input.body, signature: input.signature }), context(input)).code, ERROR_CODES.AFP_NONCANONICAL_JSON);
  assert.equal(verifyAfpEnvelope(canonicalizeJson({ body: input.body, signature: input.signature }), context(input, { verifiedRouteBinding: undefined })).code, ERROR_CODES.AFP_NEGOTIATION_BINDING_MISMATCH);
});

test("public full verifier accepts a valid cross-key issuer only through the resolver", () => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const spki = publicKey.export({ format: "der", type: "spki" });
  const issuer = deriveAgentAid(Buffer.from(spki).subarray(12).toString("base64url"), crypto);
  const { input } = byId.get("afp.task-open.positive");
  const body = structuredClone(input.body); body.issuer = issuer; body.payload.requester = issuer;
  const transcript = structuredClone(input.negotiation_transcript); transcript.issuer = issuer;
  const negotiationDigest = createHash("sha256").update(buildNegotiationPreimage(transcript)).digest("base64url");
  const route = binding(input); route.issuer = issuer; route.subject = issuer; route.negotiation_digest = negotiationDigest;
  const result = verifyAfpEnvelope(canonicalizeJson(envelope(body, privateKey)), context(input, { negotiationTranscript: transcript, negotiationDigest, verifiedRouteBinding: route, resolveIssuerKey: ({ issuer: requested }) => ({ issuer: requested, publicKeySpki: Buffer.from(spki).toString("base64url"), verified: true }) }));
  assert.equal(result.code, ERROR_CODES.AFP_OK);
});

test("full verifier enforces custody finality", () => {
  const custody = byId.get("afp.custody-receipt.positive").input;
  assert.equal(verifyAfpEnvelope(canonicalizeJson({ body: custody.body, signature: custody.signature }), context(custody, { custodyLineage: undefined })).code, ERROR_CODES.AFP_CUSTODY_LINEAGE_INVALID);
});

test("full verifier rejects a signed direct-swarm charter at its exact payload expiry", () => {
  const { input } = byId.get("afp.direct-swarm-charter.positive");
  const result = verifyAfpEnvelope(canonicalizeJson({ body: input.body, signature: input.signature }), context(input, { verificationTime: input.body.payload.expiry }));
  assert.equal(result.code, ERROR_CODES.AFP_INVALID_TIMESTAMP);
});
test("full verifier rejects a signed direct-swarm charter under a2a-baseline", () => {
  const charter = structuredClone(byId.get("afp.direct-swarm-charter.positive").input);
  charter.body.profile = "a2a-baseline";
  charter.negotiation_transcript.selected_profile = "a2a-baseline";
  charter.negotiation_digest = createHash("sha256").update(buildNegotiationPreimage(charter.negotiation_transcript)).digest("base64url");
  charter.verified_route_binding.body.profile = "a2a-baseline";
  charter.verified_route_binding.body.payload.negotiation_digest = charter.negotiation_digest;
  assert.equal(verifyAfpEnvelope(canonicalizeJson(envelope(charter.body, vectorPrivateKey())), context(charter)).code, ERROR_CODES.AFP_RECEIPT_AUTHORITY_UNAVAILABLE);
});

test("full verifier requires exact complete receipt-expectation schemas", () => {
  const receipt = byId.get("afp.receipt-commit.positive").input;
  for (const mutateExpectation of [
    (expectation) => { expectation.unexpected = true; },
    (expectation) => { expectation.actual_receipt_payload.unexpected = true; },
  ]) {
    const malformed = structuredClone(receipt);
    mutateExpectation(malformed.receipt_expectation);
    assert.equal(verifyAfpEnvelope(canonicalizeJson({ body: malformed.body, signature: malformed.signature }), context(malformed)).code, ERROR_CODES.AFP_RECEIPT_FENCE_VIOLATION);
  }
});


test("public API exposes only safe helpers and the sole AFP acceptance verifier", () => {
  assert.equal(Object.hasOwn(afp, "evaluateProfileTransition"), false, "evaluateProfileTransition must not authorize AFP transitions outside verifyAfpEnvelope");
  assert.deepEqual(Object.keys(afp).sort(), ["AFPError", "ERROR_CODES", "KINDS", "KIND_SET", "PROFILES", "PROTOCOL_VERSION", "ROUTES", "buildDigestPreimage", "buildNegotiationPreimage", "buildSettlementIdempotencyPreimage", "buildSigningPreimage", "canonicalizeJson", "deriveAgentAid", "deriveSettlementIdempotency", "digestEnvelopeBody", "negotiateVersion", "parseCanonicalJson", "rejectAspAsAfp", "validateProfileRoute", "verifyAfpEnvelope"].sort());
  for (const name of ["validateEnvelopeBody", "validatePayload", "validateSignedEnvelope", "verifySignedEnvelope", "verifyEd25519Signature", "evaluateCapabilityAttenuation", "evaluateCustodyLineage", "checkReceiptFence", "validateSettlementFact", "evaluateAF0VectorCase"]) assert.equal(Object.hasOwn(afp, name), false, `${name} must not accept AFP authority, custody, or envelopes outside verifyAfpEnvelope`);
});

test("full verifier has no alternate acceptance path and enforces final AFP evidence", () => {
  assert.equal("verifySignedEnvelope" in afp, false);
  assert.equal("validateSettlementFact" in afp, false);

  const descriptor = byId.get("afp.agent-descriptor.positive").input;
  assert.equal(verifyAfpEnvelope(canonicalizeJson({ body: descriptor.body, signature: descriptor.signature }), context(descriptor, { resolveIssuerKey: undefined })).code, ERROR_CODES.AFP_OK);
  assert.equal(verifyAfpEnvelope(canonicalizeJson({ body: descriptor.body, signature: descriptor.signature }), context(descriptor, { localPolicy: false, resolveIssuerKey: undefined })).code, ERROR_CODES.AFP_LOCAL_POLICY_REQUIRED);

  const custody = byId.get("afp.custody-receipt.positive").input;
  const missingPredecessor = structuredClone(custody); missingPredecessor.verified_references = missingPredecessor.verified_references.filter((reference) => reference.digest !== custody.body.payload.predecessor_digest);
  assert.equal(verifyAfpEnvelope(canonicalizeJson({ body: missingPredecessor.body, signature: missingPredecessor.signature }), context(missingPredecessor)).code, ERROR_CODES.AFP_REFERENCE_INVALID);
  for (const [id, code] of [["transition.direct-to-governed-new-session", ERROR_CODES.AFP_OK], ["transition.failed-strong-to-weaker-with-new-evidence", ERROR_CODES.AFP_PROFILE_RETRY_REJECTED], ["capability.signed-expiry-expansion", ERROR_CODES.AFP_CAPABILITY_EXPIRY_EXPANSION], ["capability.signed-issuer-mismatch", ERROR_CODES.AFP_CAPABILITY_ISSUER_MISMATCH], ["profile.a2a-baseline-forbidden-signed-receipt", ERROR_CODES.AFP_RECEIPT_AUTHORITY_UNAVAILABLE], ["settlement.signed-unsupported-fact", ERROR_CODES.AFP_UNSUPPORTED_SETTLEMENT_FACT], ["charter.expiry-before-issued-at", ERROR_CODES.AFP_TIME_ORDER_INVALID]]) assert.equal(testOnlyAfp.evaluateAF0VectorCase(byId.get(id), crypto).code, code, id);
  assert.equal(verifyAfpEnvelope(canonicalizeJson({ body: custody.body, signature: custody.signature }), context(custody, { custodyLineage: undefined })).code, ERROR_CODES.AFP_CUSTODY_LINEAGE_INVALID);

});
