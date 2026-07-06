import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import { test } from "node:test";
import { createAgent, createZone, loadRegistry, resolveAgent, writeRegistry } from "./asp-core.mjs";

test("zone-signed registry binding resolves agent alias", async () => {
  const zone = createZone("zone://local");
  const agent = createAgent("agent://local/summarizer");
  await writeRegistry("state/zone-registry-test.json", zone, [agent.descriptor]);

  const registry = await loadRegistry("state/zone-registry-test.json");
  const resolved = resolveAgent(registry, agent.alias);

  assert.equal(resolved.descriptor.aid, agent.aid);
  assert.equal(resolved.zone.zid, zone.zid);
});

test("zone binding tampering is rejected", async () => {
  const zone = createZone("zone://local");
  const agent = createAgent("agent://local/summarizer");
  const entry = {
    descriptor: agent.descriptor,
    zone: zone.descriptor,
    zone_binding: {
      zone: zone.zid,
      alias: agent.alias,
      aid: "aid:ed25519:wrong",
      signature: "bad",
    },
  };

  assert.throws(
    () => resolveAgent(new Map([[agent.alias, entry]]), agent.alias),
    /zone binding mismatch/,
  );
});

test("registry loading rejects missing agent entries", async () => {
  const zone = createZone("zone://local");

  await writeFile("state/zone-registry-missing-agents-test.json", `${JSON.stringify({ zone: zone.descriptor })}\n`);
  await assert.rejects(
    () => loadRegistry("state/zone-registry-missing-agents-test.json"),
    /registry agents missing/,
  );

  await writeFile("state/zone-registry-missing-entry-test.json", `${JSON.stringify({ zone: zone.descriptor, agents: [null] })}\n`);
  await assert.rejects(
    () => loadRegistry("state/zone-registry-missing-entry-test.json"),
    /registry entry missing/,
  );

  await writeFile("state/zone-registry-missing-descriptor-test.json", `${JSON.stringify({ zone: zone.descriptor, agents: [{}] })}\n`);
  await assert.rejects(
    () => loadRegistry("state/zone-registry-missing-descriptor-test.json"),
    /registry descriptor missing/,
  );
});
