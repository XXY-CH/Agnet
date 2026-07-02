import assert from "node:assert/strict";
import { test } from "node:test";
import { createAgent, createZone, loadRegistry, resolveAgent, writeRegistry, zoneRevocation } from "./asp-core.mjs";

test("zone revocation rejects revoked aid", async () => {
  const zone = createZone("zone://local");
  const agent = createAgent("agent://local/summarizer");
  const revocation = zoneRevocation(zone, agent.aid, "compromised");

  await writeRegistry("state/revocation-test.json", zone, [agent.descriptor], [revocation]);
  const registry = await loadRegistry("state/revocation-test.json");

  assert.throws(() => resolveAgent(registry, agent.alias), /agent revoked/);
});

test("tampered zone revocation is rejected", async () => {
  const zone = createZone("zone://local");
  const agent = createAgent("agent://local/summarizer");
  const revocation = { ...zoneRevocation(zone, "aid:ed25519:other", "compromised"), subject: agent.aid };

  await writeRegistry("state/revocation-tamper-test.json", zone, [agent.descriptor], [revocation]);
  const registry = await loadRegistry("state/revocation-tamper-test.json");

  assert.throws(() => resolveAgent(registry, agent.alias), /zone revocation signature verification failed/);
});
