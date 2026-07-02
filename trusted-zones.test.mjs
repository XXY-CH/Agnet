import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createZone,
  loadTrustedZones,
  verifyZoneDescriptor,
  writeTrustedZones,
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
