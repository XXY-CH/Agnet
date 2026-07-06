import assert from "node:assert/strict";
import { test } from "node:test";
import { createAgent, rotationProof, verifyRotationProof } from "./asp-core.mjs";

test("key rotation proof links previous and next agent identities", () => {
  const previous = createAgent("agent://local/summarizer");
  const next = createAgent("agent://local/summarizer");
  const proof = rotationProof(previous, next);

  assert.notEqual(previous.aid, next.aid);
  assert.equal(verifyRotationProof(proof, previous.descriptor, next.descriptor), true);
  assert.equal(
    verifyRotationProof({ ...proof, next_aid: previous.aid }, previous.descriptor, next.descriptor),
    false,
  );
  assert.equal(verifyRotationProof(null, previous.descriptor, next.descriptor), false);
  assert.equal(verifyRotationProof(proof, null, next.descriptor), false);
  assert.equal(verifyRotationProof(proof, previous.descriptor, null), false);
});
