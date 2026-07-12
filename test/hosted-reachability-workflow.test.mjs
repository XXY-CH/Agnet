import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

test("hosted reachability workflow runs external-host observer and verifier", async () => {
  const workflow = await readFile(".github/workflows/hosted-reachability-observer.yml", "utf8");

  for (const input of ["bundle_b64", "receipt_frame_b64", "trusted_zones_b64", "swarm_close_frame_b64", "swarm_close_trusted_zones_b64", "observer_seed_hex"]) {
    assert.match(workflow, new RegExp(`${input}:`));
  }
  assert.match(workflow, /AGNET_REACHABILITY_OBSERVER_SEED_HEX/);
  assert.match(workflow, /external-reachability-observer\.mjs[\s\S]*external-host/);
  assert.match(workflow, /asp-verify\.mjs proof-bundle/);
  assert.match(workflow, /verification\.json/);
});
