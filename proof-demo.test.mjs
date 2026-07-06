import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { test } from "node:test";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

test("proof demo runs the local MVP and verifies its artifact", async () => {
  const { stdout } = await execFileAsync("bash", ["scripts/proof-demo.sh"]);
  const result = JSON.parse(stdout);

  assert.equal(result.proof_demo, "ok");
  assert.equal(result.artifact_verify, "ok");
  assert.equal(result.task_id, "task_001");
  assert.match(result.receipt_signature, /^[A-Za-z0-9_-]+$/);
});
