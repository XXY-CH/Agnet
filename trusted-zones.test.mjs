import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import { test } from "node:test";
import {
  createAgent,
  createZone,
  loadTrustedZones,
  verifyZoneDescriptor,
  verifyZoneBinding,
  writeTrustedZones,
  zoneBinding,
} from "./asp-core.mjs";

test("trusted Zone store loads verified Zone descriptors", async () => {
  const zone = createZone("zone://remote-b");
  await writeTrustedZones("state/trusted-zones-test.json", [zone]);

  const trustedZones = await loadTrustedZones("state/trusted-zones-test.json");

  assert.equal(trustedZones.get(zone.zid).name, zone.name);
  assert.equal(verifyZoneDescriptor(zone.descriptor).descriptor.zid, zone.zid);
});

test("trusted Zone store rejects tampered Zone descriptors", async () => {
  const zone = createZone("zone://remote-b");
  await writeTrustedZones("state/trusted-zones-tamper-test.json", [
    { ...zone.descriptor, name: "zone://evil" },
  ]);

  await assert.rejects(
    () => loadTrustedZones("state/trusted-zones-tamper-test.json"),
    /zone signature verification failed/,
  );
});

test("trusted Zone store rejects missing Zone descriptor objects", async () => {
  await writeFile("state/trusted-zones-missing-descriptor-test.json", '{"zones":[null]}\n');

  await assert.rejects(
    () => loadTrustedZones("state/trusted-zones-missing-descriptor-test.json"),
    /zone descriptor missing/,
  );

  assert.throws(() => verifyZoneDescriptor(null), /zone descriptor missing/);
  assert.throws(() => verifyZoneDescriptor([]), /zone descriptor missing/);
});

test("trusted Zone store rejects missing zone lists", async () => {
  await writeFile("state/trusted-zones-missing-zones-test.json", "{}\n");

  await assert.rejects(
    () => loadTrustedZones("state/trusted-zones-missing-zones-test.json"),
    /trusted zone list missing/,
  );
});

test("trusted Zone store loads raw Zone descriptor arrays", async () => {
  const zone = createZone("zone://remote-b");
  await writeFile("state/trusted-zones-raw-array-test.json", `${JSON.stringify([zone.descriptor])}\n`);

  const trustedZones = await loadTrustedZones("state/trusted-zones-raw-array-test.json");

  assert.equal(trustedZones.get(zone.zid).name, zone.name);
});

test("zone binding verification rejects missing context objects", () => {
  const zone = createZone("zone://local");
  const agent = createAgent("agent://local/summarizer");
  const entry = {
    descriptor: agent.descriptor,
    zone: zone.descriptor,
    zone_binding: zoneBinding(zone, agent.descriptor),
  };

  assert.throws(() => verifyZoneBinding(null, agent.descriptor, agent.alias), /zone binding context missing/);
  assert.throws(() => verifyZoneBinding([], agent.descriptor, agent.alias), /zone binding context missing/);
  assert.throws(() => verifyZoneBinding(entry, null, agent.alias), /zone binding descriptor missing/);
  assert.throws(() => verifyZoneBinding(entry, [], agent.alias), /zone binding descriptor missing/);
});
