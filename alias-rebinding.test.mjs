import assert from "node:assert/strict";
import { test } from "node:test";
import {
  aliasRebindingProof,
  createAgent,
  createZone,
  rotationProof,
  verifyAliasRebindingProof,
} from "./asp-core.mjs";

test("zone can approve alias rebinding after agent key rotation", () => {
  const zone = createZone("zone://local");
  const previous = createAgent("agent://local/summarizer");
  const next = createAgent("agent://local/summarizer");
  const agentRotation = rotationProof(previous, next);
  const rebinding = aliasRebindingProof(zone, previous.descriptor, next.descriptor, agentRotation);

  assert.equal(verifyAliasRebindingProof(rebinding, zone.descriptor, previous.descriptor, next.descriptor), true);
  assert.equal(
    verifyAliasRebindingProof(
      { ...rebinding, next_aid: previous.aid },
      zone.descriptor,
      previous.descriptor,
      next.descriptor,
    ),
    false,
  );
});
