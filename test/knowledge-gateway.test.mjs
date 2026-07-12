import assert from "node:assert/strict";
import { test } from "node:test";
import { createZone,
knowledgeQuery,
knowledgeResponse,
verifyKnowledgeQuery,
verifyKnowledgeResponse, } from "../asp-core.mjs"

const POLICY_DIGEST = "a".repeat(64);
const WRONG_QUERY_DIGEST = "b".repeat(64);

function trustedZones(...zones) {
  return new Map(zones.map((zone) => [zone.zid, zone.descriptor]));
}

function sampleKnowledgeRequest() {
  return {
    intent: "Summarize memory safety guidance for gateway operators.",
    sources: ["kg://security-handbook", "kg://incident-retrospectives"],
  };
}

function sampleKnowledgeResults() {
  return [
    {
      source: "kg://security-handbook",
      title: "Gateway operator checklist",
      summary: "Pin trust roots before cross-zone retrieval.",
      freshness_at: "2026-07-08T00:00:00Z",
      license: "CC-BY-4.0",
    },
  ];
}

test("knowledge query frames verify for a trusted requester Zone", () => {
  const requester = createZone("zone://knowledge-requester");
  const { intent, sources } = sampleKnowledgeRequest();

  const frame = knowledgeQuery(requester, intent, sources, POLICY_DIGEST);
  const verified = verifyKnowledgeQuery(frame, trustedZones(requester));

  assert.equal(frame.type, "FED_KNOWLEDGE_QUERY");
  assert.equal(verified.zone.zid, requester.zid);
  assert.equal(verified.query.intent, intent);
  assert.deepEqual(verified.query.sources, sources);
  assert.equal(verified.query.policy_digest, POLICY_DIGEST);
  assert.equal(verified.query.query_digest, frame.query.query_digest);
});

test("knowledge response frames verify and bind to the originating query digest", () => {
  const requester = createZone("zone://knowledge-requester");
  const gateway = createZone("zone://knowledge-gateway");
  const { intent, sources } = sampleKnowledgeRequest();
  const queryFrame = knowledgeQuery(requester, intent, sources, POLICY_DIGEST);
  const verifiedQuery = verifyKnowledgeQuery(queryFrame, trustedZones(requester, gateway));
  const results = sampleKnowledgeResults();

  const responseFrame = knowledgeResponse(gateway, verifiedQuery.query.query_id, results, verifiedQuery.query.query_digest);
  const verifiedResponse = verifyKnowledgeResponse(responseFrame, trustedZones(requester, gateway), queryFrame);

  assert.equal(responseFrame.type, "FED_KNOWLEDGE_RESPONSE");
  assert.equal(verifiedResponse.zone.zid, gateway.zid);
  assert.equal(verifiedResponse.response.query_id, verifiedQuery.query.query_id);
  assert.equal(verifiedResponse.response.query_digest, verifiedQuery.query.query_digest);
  assert.deepEqual(verifiedResponse.response.results, results);
});

test("knowledge query verification rejects a tampered query signature", () => {
  const requester = createZone("zone://knowledge-requester");
  const { intent, sources } = sampleKnowledgeRequest();
  const frame = knowledgeQuery(requester, intent, sources, POLICY_DIGEST);
  const tampered = structuredClone(frame);
  tampered.query.query_signature = "tampered";

  assert.throws(
    () => verifyKnowledgeQuery(tampered, trustedZones(requester)),
    /knowledge query signature verification failed/,
  );
});

test("knowledge response verification rejects a tampered response signature", () => {
  const requester = createZone("zone://knowledge-requester");
  const gateway = createZone("zone://knowledge-gateway");
  const { intent, sources } = sampleKnowledgeRequest();
  const queryFrame = knowledgeQuery(requester, intent, sources, POLICY_DIGEST);
  const verifiedQuery = verifyKnowledgeQuery(queryFrame, trustedZones(requester, gateway));
  const frame = knowledgeResponse(gateway, verifiedQuery.query.query_id, sampleKnowledgeResults(), verifiedQuery.query.query_digest);
  const tampered = structuredClone(frame);
  tampered.response.response_signature = "tampered";

  assert.throws(
    () => verifyKnowledgeResponse(tampered, trustedZones(requester, gateway), queryFrame),
    /knowledge response signature verification failed/,
  );
});

test("knowledge response verification rejects a response bound to the wrong query digest", () => {
  const requester = createZone("zone://knowledge-requester");
  const gateway = createZone("zone://knowledge-gateway");
  const { intent, sources } = sampleKnowledgeRequest();
  const queryFrame = knowledgeQuery(requester, intent, sources, POLICY_DIGEST);
  const verifiedQuery = verifyKnowledgeQuery(queryFrame, trustedZones(requester, gateway));

  const wrongDigestResponse = knowledgeResponse(gateway, verifiedQuery.query.query_id, sampleKnowledgeResults(), WRONG_QUERY_DIGEST);

  assert.throws(
    () => verifyKnowledgeResponse(wrongDigestResponse, trustedZones(requester, gateway), queryFrame),
    /knowledge response query_digest mismatch/,
  );
});

test("knowledge query verification rejects an untrusted requester Zone", () => {
  const requester = createZone("zone://knowledge-requester");
  const unrelated = createZone("zone://unrelated-trust-root");
  const { intent, sources } = sampleKnowledgeRequest();
  const frame = knowledgeQuery(requester, intent, sources, POLICY_DIGEST);

  assert.throws(
    () => verifyKnowledgeQuery(frame, trustedZones(unrelated)),
    /untrusted zone:/,
  );
});
