import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { loadOrCreateAgent, loadOrCreateZone } from "./asp-core.mjs";

test("agent and zone identities survive key reload", async () => {
  const dir = await mkdtemp(join(tmpdir(), "agnet-keys-"));
  const agentKey = join(dir, "agent.pkcs8");
  const zoneKey = join(dir, "zone.pkcs8");

  const firstAgent = await loadOrCreateAgent("agent://local/summarizer", agentKey);
  const secondAgent = await loadOrCreateAgent("agent://local/summarizer", agentKey);
  const firstZone = await loadOrCreateZone("zone://local", zoneKey);
  const secondZone = await loadOrCreateZone("zone://local", zoneKey);

  assert.equal(secondAgent.aid, firstAgent.aid);
  assert.equal(secondAgent.descriptor.public_key_spki, firstAgent.descriptor.public_key_spki);
  assert.equal(secondZone.zid, firstZone.zid);
  assert.equal(secondZone.descriptor.public_key_spki, firstZone.descriptor.public_key_spki);
});
