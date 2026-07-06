import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { access } from "node:fs/promises";
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

test("proof demo emits verifier-ready receipt closure files", async () => {
  const { stdout } = await execFileAsync("bash", ["scripts/proof-demo.sh"]);
  const result = JSON.parse(stdout);

  assert.equal(result.fed_receipt_artifacts_verify, "ok");
  assert.match(result.receipt_frame, /^state\/proof-demo-fed-receipt\.json$/);
  assert.match(result.trusted_zones, /^state\/proof-demo-trusted-zones\.json$/);
  await access(result.receipt_frame);
  await access(result.trusted_zones);

  const verified = JSON.parse((await execFileAsync("node", [
    "asp-verify.mjs",
    "fed-receipt-artifacts",
    result.receipt_frame,
    result.trusted_zones,
  ])).stdout);

  assert.deepEqual(verified, {
    fed_receipt_artifacts_verify: "ok",
    task_id: "task_001",
    artifact_count: 1,
  });
});
