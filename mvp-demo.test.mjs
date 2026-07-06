import { access, readFile, writeFile } from "node:fs/promises";
import assert from "node:assert/strict";
import { test } from "node:test";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { promisify } from "node:util";
import { canonical, verifyLocalArtifact } from "./asp-core.mjs";

const execFileAsync = promisify(execFile);

function testManifest(uri) {
  const manifest = {
    uri,
    sha256: createHash("sha256").update("").digest("hex"),
    size: 0,
    media_type: "text/plain",
  };
  manifest.afp = `afp:sha256:${manifest.sha256}`;
  manifest.manifest_hash = createHash("sha256").update(canonical(manifest)).digest("hex");
  return manifest;
}

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
  const manifestPath = `${result.artifactPath}.manifest.json`;
  assert.equal(manifest.afp, `afp:sha256:${manifest.sha256}`);
  assert.deepEqual(JSON.parse((await execFileAsync("node", ["asp-verify.mjs", "artifact", manifestPath])).stdout), {
    artifact_verify: "ok",
    uri: manifest.uri,
  });
  await assert.rejects(() => verifyLocalArtifact(null), /artifact manifest missing/);
  await assert.rejects(() => verifyLocalArtifact(testManifest(undefined)), /artifact uri invalid/);
  await assert.rejects(() => verifyLocalArtifact(testManifest("file:///tmp/evil")), /artifact uri invalid/);
  assert.deepEqual(await verifyLocalArtifact(manifest), manifest);
  await writeFile(manifestPath, "{}\n");
  await assert.rejects(() => verifyLocalArtifact(manifest), /artifact manifest sidecar mismatch/);
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  await writeFile(result.artifactPath, "tampered\n");
  await assert.rejects(
    () => execFileAsync("node", ["asp-verify.mjs", "artifact", manifestPath]),
    (error) => /artifact bytes (size|digest) mismatch/.test(error.stderr),
  );
  await assert.rejects(() => verifyLocalArtifact(manifest), /artifact bytes (size|digest) mismatch/);
  await access(result.auditLog);
});
