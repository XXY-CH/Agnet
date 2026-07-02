import { access } from "node:fs/promises";
import assert from "node:assert/strict";
import { test } from "node:test";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

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
  assert.match(result.receipt.signature, /^[A-Za-z0-9_-]+$/);

  await access(result.registry);
  await access(result.artifactPath);
  await access(result.auditLog);
});
