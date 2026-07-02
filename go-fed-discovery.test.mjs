import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import { test } from "node:test";
import { promisify } from "node:util";
import { loadOrCreateZone, writeTrustedZones } from "./asp-core.mjs";

const execFileAsync = promisify(execFile);

function waitForGoGateway(child) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("go gateway did not start")), 5000);
    child.stdout.on("data", (chunk) => {
      const line = chunk.toString().split("\n").find((item) => item.trim().startsWith("{"));
      if (!line) return;
      clearTimeout(timer);
      resolve(JSON.parse(line));
    });
    child.once("error", reject);
    child.once("exit", (code) => {
      if (code !== null && code !== 0) reject(new Error(`go gateway exited early: ${code}`));
    });
  });
}

test("Go discovery gateway serves FED_RESOLVE and FED_QUERY to Node client", async () => {
  const port = 9091;
  const zoneA = await loadOrCreateZone("zone://a", "state/keys/fed-zone-a.pkcs8");
  const fixture = JSON.parse(await readFile("test-vectors/asp-v1.5-capability-credential.json", "utf8"));
  const goFixture = JSON.parse(JSON.stringify(fixture));
  delete goFixture.authority_seed_hex;
  delete goFixture.worker_seed_hex;
  delete goFixture.worker;
  delete goFixture.zone_binding;
  await writeFile("state/go-fed-discovery-dynamic-worker.json", `${JSON.stringify(goFixture, null, 2)}\n`);
  await writeFile("state/go-fed-discovery-authority.seed", `${fixture.authority_seed_hex}\n`);
  await writeFile("state/go-fed-discovery-worker.seed", `${fixture.worker_seed_hex}\n`);
  await writeTrustedZones("state/go-fed-discovery-trusted-origin.json", [zoneA]);
  await writeFile("state/node-trusts-go-discovery.json", `${JSON.stringify({ zones: [fixture.authority] }, null, 2)}\n`);
  await execFileAsync("go", ["build", "-o", "state/go-fed-discovery-test", "./cmd/go-fed-discovery"]);

  const gateway = spawn("./state/go-fed-discovery-test", [
    "--port",
    String(port),
    "--trusted",
    "state/go-fed-discovery-trusted-origin.json",
    "--fixture",
    "state/go-fed-discovery-dynamic-worker.json",
    "--authority-key",
    "state/go-fed-discovery-authority.seed",
    "--worker-key",
    "state/go-fed-discovery-worker.seed",
  ], {
    cwd: process.cwd(),
    stdio: ["ignore", "pipe", "pipe"],
  });

  try {
    await waitForGoGateway(gateway);

    const resolved = await execFileAsync(process.execPath, [
      "federation-gateway.mjs",
      "resolve",
      String(port),
      "state/node-trusts-go-discovery.json",
      "agent://zone-b/summarizer",
    ]);
    const resolvedResult = JSON.parse(resolved.stdout);
    assert.equal(resolvedResult.zone, fixture.authority.zid);
    assert.equal(resolvedResult.aid, fixture.worker.aid);

    const queried = await execFileAsync(process.execPath, [
      "federation-gateway.mjs",
      "query",
      String(port),
      "state/node-trusts-go-discovery.json",
      "summarize.text",
    ]);
    const queriedResult = JSON.parse(queried.stdout);
    assert.equal(queriedResult.matches.length, 1);
    assert.equal(queriedResult.matches[0].aid, fixture.worker.aid);
    assert.equal(queriedResult.matches[0].credentials[0].issuer, fixture.authority.zid);
    assert.equal(queriedResult.matches[0].credentials[0].subject, fixture.worker.aid);
  } finally {
    gateway.kill("SIGINT");
  }
});
