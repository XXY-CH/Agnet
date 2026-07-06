import { access, readFile, writeFile } from "node:fs/promises";
import assert from "node:assert/strict";
import { test } from "node:test";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { verifyLocalArtifact } from "./asp-core.mjs";

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
  const manifest = result.receipt.artifact_manifests[0];
  assert.deepEqual(await verifyLocalArtifact(manifest), manifest);
  await writeFile(`${result.artifactPath}.manifest.json`, "{}\n");
  await assert.rejects(() => verifyLocalArtifact(manifest), /artifact manifest sidecar mismatch/);
  await writeFile(`${result.artifactPath}.manifest.json`, `${JSON.stringify(manifest, null, 2)}\n`);
  await writeFile(result.artifactPath, "tampered\n");
  await assert.rejects(() => verifyLocalArtifact(manifest), /artifact bytes (size|digest) mismatch/);
  await access(result.auditLog);
});
