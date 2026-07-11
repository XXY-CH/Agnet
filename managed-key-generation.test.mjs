import assert from "node:assert/strict";
import { createPrivateKey } from "node:crypto";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

import {
  agentFromPrivateKey,
  aliasRebindingProof,
  descriptorBody,
  canonical,
  rotationProof,
  signObject,
  zoneFromPrivateKey,
} from "./asp-core.mjs";
import {
  createRotationGenerationRecord,
  createSignedGenerationRecord,
  generationBody,
  parseGenerationRecord,
  recordDigest,
  verifyGenerationChain,
  verifyGenerationRebinding,
  verifyGenerationRecord,
} from "./managed-key.mjs";
import { sealKeyEnvelope } from "./managed-key.mjs";

const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const ZERO_DIGEST = "0".repeat(64);
const PASSPHRASE = Buffer.from("u9 generation passphrase\n");

function seed(start) {
  return Buffer.from(Array.from({ length: 32 }, (_, index) => (start + index) & 0xff));
}

function privateKey(start) {
  return createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, seed(start)]), format: "der", type: "pkcs8" });
}

function envelopeFor(agent, plaintext, iterations = 100000) {
  return sealKeyEnvelope({ keyType: "ed25519-pkcs8", plaintext, identity: { kind: "aid", value: agent.aid }, passphrase: PASSPHRASE, iterations });
}

function buildChain() {
  const previous = agentFromPrivateKey("agent://u9/worker", privateKey(0));
  const next = agentFromPrivateKey("agent://u9/worker", privateKey(64));
  const zone = zoneFromPrivateKey("zone://u9", privateKey(128));
  const previousPlaintext = Buffer.concat([PKCS8_PREFIX, seed(0)]);
  const nextPlaintext = Buffer.concat([PKCS8_PREFIX, seed(64)]);
  const envelope1 = envelopeFor(previous, previousPlaintext);
  const body1 = generationBody({ identity: { kind: "aid", value: previous.aid }, generation: 1, operation: "migrate", envelopeBytes: envelope1, descriptor: previous.descriptor });
  const record1 = createSignedGenerationRecord({ body: body1, privateKey: previous.privateKey });
  const envelope2 = envelopeFor(previous, previousPlaintext, 100001);
  const body2 = generationBody({ identity: { kind: "aid", value: previous.aid }, generation: 2, operation: "rewrap", envelopeBytes: envelope2, descriptor: previous.descriptor, previousRecord: record1 });
  const record2 = createSignedGenerationRecord({ body: body2, privateKey: previous.privateKey });
  const envelope3 = envelopeFor(next, nextPlaintext);
  const body3 = generationBody({ identity: { kind: "aid", value: next.aid }, generation: 3, operation: "rotate", envelopeBytes: envelope3, descriptor: next.descriptor, previousRecord: record2 });
  const record3 = createRotationGenerationRecord({ body: body3, previousAgent: previous, nextAgent: next, zone });
  return { previous, next, zone, envelopes: [envelope1, envelope2, envelope3], records: [record1, record2, record3] };
}

function contextFor(chain, index) {
  const record = chain.records[index];
  return {
    envelopeBytes: chain.envelopes[index],
    descriptor: index === 2 ? chain.next.descriptor : chain.previous.descriptor,
    previousRecord: index === 0 ? undefined : chain.records[index - 1],
    previousDescriptor: index === 2 ? chain.previous.descriptor : undefined,
    zoneDescriptor: index === 2 ? chain.zone.descriptor : undefined,
    activePointer: { generation: record.body.generation, record_digest: record.record_digest },
  };
}

test("managed key generation authenticates migrate, rewrap, and rotate chain", () => {
  const chain = buildChain();
  for (let index = 0; index < chain.records.length; index += 1) {
    const record = chain.records[index];
    assert.equal(record.record_digest, recordDigest(record.body));
    const verified = verifyGenerationRecord(record, contextFor(chain, index));
    assert.equal(verified.record_digest, record.record_digest);
  }
  assert.deepEqual(verifyGenerationChain(chain.records, chain.envelopes, {
    descriptors: [chain.previous.descriptor, chain.previous.descriptor, chain.next.descriptor],
    previousDescriptors: [undefined, undefined, chain.previous.descriptor],
    zoneDescriptors: [undefined, undefined, chain.zone.descriptor],
    activePointer: { generation: 3, record_digest: chain.records[2].record_digest },
  }).map((record) => record.body.generation), [1, 2, 3]);
  assert.equal(verifyGenerationRebinding(chain.records[2].generation_rebinding, {
    zoneDescriptor: chain.zone.descriptor,
    previousDescriptor: chain.previous.descriptor,
    nextDescriptor: chain.next.descriptor,
    generation: 3,
    recordDigest: chain.records[2].record_digest,
  }), true);
});

test("generation parser rejects duplicate and unknown fields", () => {
  const chain = buildChain();
  const canonicalRecord = Buffer.from(canonical(chain.records[0]));
  const text = canonicalRecord.toString("utf8");
  assert.throws(() => parseGenerationRecord(Buffer.from(text.replace('"record_digest":', `"record_digest":"${ZERO_DIGEST}","record_digest":`))), /duplicate JSON key: record_digest/);
  assert.throws(() => parseGenerationRecord(Buffer.from(JSON.stringify({ ...chain.records[0], extra: true }))), /generation record fields invalid/);
  assert.throws(() => parseGenerationRecord(Buffer.from(JSON.stringify({ ...chain.records[0], body: { ...chain.records[0].body, extra: true } }))), /generation body fields invalid/);
});

test("generation verification rejects chain, identity, pointer, and authorization substitutions", () => {
  const chain = buildChain();
  const [record1, record2, record3] = chain.records;
  for (const generation of [0, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => verifyGenerationRecord({ ...record1, body: { ...record1.body, generation } }, contextFor(chain, 0)), /generation invalid|record digest mismatch/);
  }
  assert.throws(() => verifyGenerationRecord(record2, { ...contextFor(chain, 1), previousRecord: { ...record1, record_digest: ZERO_DIGEST } }), /previous record digest mismatch/);
  assert.throws(() => verifyGenerationRecord(record2, { ...contextFor(chain, 1), activePointer: { generation: 1, record_digest: record1.record_digest } }), /active pointer mismatch/);
  assert.throws(() => verifyGenerationRecord(record2, { ...contextFor(chain, 1), descriptor: chain.next.descriptor }), /descriptor digest mismatch|descriptor identity mismatch|identity drift/);
  const driftBody = { ...record2.body, identity_value: chain.next.aid };
  assert.throws(() => verifyGenerationRecord({ ...record2, body: driftBody, record_digest: recordDigest(driftBody) }, contextFor(chain, 1)), /identity drift|envelope identity mismatch|generation signature/);
  assert.throws(() => verifyGenerationChain([record1, record2, record2], [chain.envelopes[0], chain.envelopes[1], chain.envelopes[1]], {
    descriptors: [chain.previous.descriptor, chain.previous.descriptor, chain.previous.descriptor],
  }), /generation must be contiguous|replay|previous/);
  assert.throws(() => verifyGenerationChain([record1, record3], [chain.envelopes[0], chain.envelopes[2]], {
    descriptors: [chain.previous.descriptor, chain.next.descriptor],
    previousDescriptors: [undefined, chain.previous.descriptor],
    zoneDescriptors: [undefined, chain.zone.descriptor],
  }), /generation must be contiguous/);
  const missingSignature = structuredClone(record1);
  delete missingSignature.identity_signature;
  assert.throws(() => verifyGenerationRecord(missingSignature, contextFor(chain, 0)), /generation record fields invalid|identity signature/);

  const swapped = structuredClone(record3);
  swapped.previous_descriptor = chain.next.descriptor;
  swapped.next_descriptor = chain.previous.descriptor;
  assert.throws(() => verifyGenerationRecord(swapped, contextFor(chain, 2)), /descriptor|rotation|previous|next/);

  const substitutedPreviousDescriptor = {
    ...descriptorBody(chain.previous.descriptor),
    policy: "substituted",
  };
  substitutedPreviousDescriptor.descriptor_signature = signObject(chain.previous.privateKey, substitutedPreviousDescriptor);
  const substitutedRotation = structuredClone(record3);
  substitutedRotation.previous_descriptor = substitutedPreviousDescriptor;
  assert.throws(() => verifyGenerationRecord(substitutedRotation, {
    ...contextFor(chain, 2),
    previousDescriptor: substitutedPreviousDescriptor,
  }), /previous descriptor digest mismatch/);

  for (const [name, mutate] of [
    ["zone", (proof) => { proof.zone = "zid:ed25519:bad"; }],
    ["alias", (proof) => { proof.alias = "agent://u9/other"; }],
    ["generation", (proof) => { proof.generation = 2; }],
    ["record digest", (proof) => { proof.record_digest = ZERO_DIGEST; }],
  ]) {
    const proof = structuredClone(record3.generation_rebinding);
    mutate(proof);
    assert.equal(verifyGenerationRebinding(proof, {
      zoneDescriptor: chain.zone.descriptor,
      previousDescriptor: chain.previous.descriptor,
      nextDescriptor: chain.next.descriptor,
      generation: 3,
      recordDigest: record3.record_digest,
    }), false, name);
  }
  const legacy = aliasRebindingProof(chain.zone, chain.previous.descriptor, chain.next.descriptor, rotationProof(chain.previous, chain.next));
  assert.equal(verifyGenerationRebinding(legacy, {
    zoneDescriptor: chain.zone.descriptor,
    previousDescriptor: chain.previous.descriptor,
    nextDescriptor: chain.next.descriptor,
    generation: 3,
    recordDigest: record3.record_digest,
  }), false);
});

test("Node verifies frozen Node-created and Go-created generation vectors", async () => {
  const vector = JSON.parse(await readFile("test-vectors/agnet-key-generation-v1.json", "utf8"));
  assert.equal(vector.format, "agnet-key-generation-test-v1");
  assert.deepEqual(vector.cases.map((item) => item.origin), ["node-created", "go-created"]);
  for (const item of vector.cases) {
    const records = item.records.map((record) => parseGenerationRecord(Buffer.from(record.canonical, "utf8")));
    const envelopes = item.records.map((record) => Buffer.from(record.envelope, "base64url"));
    const descriptors = item.records.map((record) => record.descriptor);
    const previousDescriptors = item.records.map((record) => record.previous_descriptor);
    const zoneDescriptors = item.records.map((record) => record.zone_descriptor);
    const verified = verifyGenerationChain(records, envelopes, {
      descriptors,
      previousDescriptors,
      zoneDescriptors,
      activePointer: item.active_pointer,
    });
    assert.equal(verified.at(-1).record_digest, item.active_pointer.record_digest);
  }
});
