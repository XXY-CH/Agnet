import { access, readFile } from "node:fs/promises";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { canonical } from "./asp-core.mjs";

const execFileAsync = promisify(execFile);

test("MVP demo produces registry, artifact, and signed receipt", async () => {
  const { stdout } = await execFileAsync("node", ["mvp-demo.mjs"]);
  const result = JSON.parse(stdout);

  assert.match(result.requester, /^aid:ed25519:/);
  assert.match(result.worker, /^aid:ed25519:/);
  assert.equal(result.deniedTask, "policy denied network access");
  assert.equal(result.events.some((event) => event.type === "approval.required"), true);
  assert.equal(result.events.some((event) => event.type === "approval.granted"), true);
  assert.equal(result.events.at(-1).type, "task.completed");
  assert.equal(result.receipt.artifact_refs[0], "artifact://local/task_001/summary.md");
  const artifactEvent = result.events.find((event) => event.type === "artifact.created");
  assert.ok(artifactEvent.manifest);
  assert.deepEqual(result.receipt.artifact_manifests, [artifactEvent.manifest]);
  assert.match(result.receipt.signature, /^[A-Za-z0-9_-]+$/);

  await access(result.registry);
  await access(result.artifactPath);
  const artifactText = await readFile(result.artifactPath, "utf8");
  const manifest = result.receipt.artifact_manifests[0];
  assert.equal(manifest.sha256, createHash("sha256").update(artifactText).digest("hex"));
  assert.equal(manifest.size, Buffer.byteLength(artifactText));
  const { manifest_hash, ...manifestBody } = manifest;
  assert.equal(manifest_hash, createHash("sha256").update(canonical(manifestBody)).digest("hex"));
  assert.deepEqual(JSON.parse(await readFile(`${result.artifactPath}.manifest.json`, "utf8")), manifest);
  await access(result.auditLog);
});
