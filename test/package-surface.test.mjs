import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const packageJSON = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));

test("Agnet publishes a versioned client and daemon dependency surface", () => {
  assert.equal(packageJSON.name, "agnet");
  assert.equal(packageJSON.version, "0.1.0-dev.3");
  assert.equal(packageJSON.engines.node, ">=22.0.0");
  assert.equal(packageJSON.exports["./client"].import, "./agnet-client.mjs");
  assert.equal(packageJSON.exports["./client"].types, "./agnet-client.d.mts");
  assert.equal(packageJSON.bin["agnet-daemon"], "./agnet-daemon.mjs");
  for (const required of ["agnet-client.mjs", "agnet-client.d.mts", "agnet-daemon.mjs", "swarm-output-verification.mjs"]) {
    assert.ok(packageJSON.files.includes(required), `package files omit ${required}`);
  }
});

test("Agnet core delegates native execution to platform packages", () => {
  assert.ok(!packageJSON.files.includes("dist/bin/agnet-daemon"));
  const expected = [
    "@agnet-ai/daemon-darwin-arm64",
    "@agnet-ai/daemon-darwin-x64",
    "@agnet-ai/daemon-linux-arm64",
    "@agnet-ai/daemon-linux-x64",
  ];
  assert.deepEqual(Object.keys(packageJSON.optionalDependencies).sort(), expected);
  for (const dependency of expected) assert.equal(packageJSON.optionalDependencies[dependency], packageJSON.version);
});

test("Agnet package excludes runtime state and private journal data", () => {
  for (const excluded of ["state", "artifacts", ".compound-engineering", "cmd", "internal", "test-vectors"]) {
    assert.ok(!packageJSON.files.includes(excluded), `package files expose ${excluded}`);
  }
});

test("JavaScript package bins carry Node shebangs", async () => {
  for (const relativePath of Object.values(packageJSON.bin)) {
    if (!relativePath.endsWith(".mjs")) continue;
    const source = await readFile(new URL(`..${relativePath.slice(1)}`, import.meta.url), "utf8");
    assert.ok(source.startsWith("#!/usr/bin/env node\n"), `${relativePath} is not directly executable`);
  }
});
