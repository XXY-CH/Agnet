import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { test } from "node:test";
import { promisify } from "node:util";
import { loadOrCreateZone, writeTrustedZones } from "./asp-core.mjs";

const execFileAsync = promisify(execFile);

function waitForGateway(child) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("gateway did not start")), 3000);
    child.stdout.on("data", (chunk) => {
      const line = chunk.toString().split("\n").find((item) => item.trim().startsWith("{"));
      if (!line) return;
      clearTimeout(timer);
      resolve(JSON.parse(line));
    });
    child.once("error", reject);
    child.once("exit", (code) => {
      if (code !== null && code !== 0) reject(new Error(`gateway exited early: ${code}`));
    });
  });
}

test("Federation Gateway completes a cross-Zone task", async () => {
  const port = 8991;
  const zoneA = await loadOrCreateZone("zone://a", "state/keys/fed-zone-a.pkcs8");
  const zoneB = await loadOrCreateZone("zone://b", "state/keys/fed-zone-b.pkcs8");
  await writeTrustedZones("state/zone-a-trust.json", [zoneB]);
  await writeTrustedZones("state/zone-b-trust.json", [zoneA]);

  const gateway = spawn(process.execPath, ["federation-gateway.mjs", "serve", String(port), "state/zone-b-trust.json"], {
    cwd: process.cwd(),
    stdio: ["ignore", "pipe", "pipe"],
  });

  try {
    const started = await waitForGateway(gateway);
    assert.equal(started.zone, zoneB.zid);

    const { stdout } = await execFileAsync(process.execPath, [
      "federation-gateway.mjs",
      "request",
      String(port),
      "state/zone-a-trust.json",
    ]);
    const result = JSON.parse(stdout);

    assert.equal(result.zone, zoneA.zid);
    assert.equal(result.receipt.origin_zone, zoneA.zid);
    assert.equal(result.receipt.executing_zone, zoneB.zid);
    assert.equal(result.events.at(-1).type, "task.completed");
    assert.equal(result.receipt.event_count, result.events.length);
  } finally {
    gateway.kill("SIGINT");
  }
});

test("Federation Gateway rejects an untrusted origin Zone", async () => {
  const port = 8992;
  const zoneB = await loadOrCreateZone("zone://b", "state/keys/fed-zone-b.pkcs8");
  await writeTrustedZones("state/zone-a-trust-untrusted-test.json", [zoneB]);
  await writeTrustedZones("state/zone-b-empty-trust.json", []);

  const gateway = spawn(process.execPath, ["federation-gateway.mjs", "serve", String(port), "state/zone-b-empty-trust.json"], {
    cwd: process.cwd(),
    stdio: ["ignore", "pipe", "pipe"],
  });

  try {
    await waitForGateway(gateway);

    await assert.rejects(
      () =>
        execFileAsync(process.execPath, [
          "federation-gateway.mjs",
          "request",
          String(port),
          "state/zone-a-trust-untrusted-test.json",
        ]),
      (error) => error.stderr.includes("untrusted zone"),
    );
  } finally {
    gateway.kill("SIGINT");
  }
});
