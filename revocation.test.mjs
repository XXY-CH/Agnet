import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createAgent,
  createZone,
  loadRegistry,
  resolveAgent,
  verifyNotRevoked,
  verifyZoneRevocation,
  writeRegistry,
  zoneRevocation,
} from "./asp-core.mjs";

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

test("zone revocation verification rejects missing context objects", () => {
  const zone = createZone("zone://local");
  const agent = createAgent("agent://local/summarizer");
  const entry = {
    zone: zone.descriptor,
    revocations: [zoneRevocation(zone, "aid:ed25519:other", "compromised")],
  };

  assert.equal(verifyZoneRevocation(null, zone.descriptor), false);
  assert.equal(verifyZoneRevocation([], zone.descriptor), false);
  assert.throws(() => verifyNotRevoked(null, agent.descriptor, agent.alias), /zone revocation context missing/);
  assert.throws(() => verifyNotRevoked([], agent.descriptor, agent.alias), /zone revocation context missing/);
  assert.throws(() => verifyNotRevoked({ zone: zone.descriptor }, agent.descriptor, agent.alias), /zone revocations missing/);
  assert.throws(() => verifyNotRevoked(entry, null, agent.alias), /zone revocation descriptor missing/);
  assert.throws(() => verifyNotRevoked(entry, [], agent.alias), /zone revocation descriptor missing/);
});
