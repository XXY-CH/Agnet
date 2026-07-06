import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { promisify } from "node:util";
import { canonical } from "./asp-core.mjs";

const execFileAsync = promisify(execFile);

test("public node proof starts a public-listen gateway", async () => {
  const { stdout } = await execFileAsync("bash", ["scripts/public-node-proof.sh"]);
  const result = JSON.parse(stdout);

  assert.equal(result.public_node_proof, "ok");
  assert.equal(result.listen_host, "0.0.0.0");
  assert.equal(result.public_transport, true);
  assert.equal(result.transport, "fed+tcp");
  assert.equal(result.resolve_alias, "agent://zone-b/summarizer");
  assert.equal(result.resolve_close, true);
  assert.equal(result.query_capability, "summarize.text");
  assert.equal(result.query_match_count, 1);
  assert.equal(result.query_status, "active");
  assert.equal(result.task_id, "public_node_probe_task");
  assert.equal(result.task_receipt, true);
  assert.equal(result.task_close, true);
  assert.equal(result.audit_task_id, "public_node_probe_task");
  assert.equal(result.audit_receipt, true);
  assert.equal(result.audit_close, true);
  assert.equal(result.receipt_frame, "state/public-node-proof-fed-receipt.json");
  assert.equal(result.trusted_zones, "state/public-node-proof-trusted-zones.json");
  assert.equal(result.artifact_file, "artifacts/public_node_probe_task/go-summary.md");
  assert.equal(result.fed_receipt_artifacts_verify, "ok");
  assert.equal(result.artifact_reject, true);
  assert.match(result.artifact_reject_error, /receipt artifact not found/);
  assert.equal(result.artifact_tamper_reject, true);
  assert.match(result.artifact_tamper_error, /artifact bytes digest mismatch/);
  assert.equal(result.swarm_id, "swarm://public-node-proof/two-step");
  assert.equal(result.swarm_step_count, 2);
  assert.deepEqual(result.swarm_step_ids, ["summary", "dependent"]);
  assert.equal(result.swarm_close_signature, true);
  assert.equal(result.swarm_close_receipts, true);
  assert.match(result.swarm_close_digest, /^[a-f0-9]{64}$/);
  assert.equal(result.swarm_close_frame, "state/public-node-proof-swarm-close.json");
  assert.equal(result.swarm_close_trusted_zones, "state/public-node-proof-swarm-close-trusted-zones.json");

  const closeFrame = JSON.parse(await readFile(result.swarm_close_frame, "utf8"));
  const closeTrustedZones = JSON.parse(await readFile(result.swarm_close_trusted_zones, "utf8"));
  assert.equal(closeFrame.type, "FED_SWARM_CLOSE");
  assert.equal(closeFrame.swarm_id, result.swarm_id);
  assert.equal(closeFrame.close.swarm_id, result.swarm_id);
  assert.equal(closeTrustedZones.zones[0].zid, closeFrame.zone.zid);

  const audit = await readFile("state/public-node-proof-audit.log", "utf8");
  const closeRecord = audit
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line))
    .findLast((entry) => entry.record?.kind === "go_swarm_close")?.record;
  const { close_signature, ...closeBody } = closeRecord.close;
  assert.equal(result.swarm_close_digest, createHash("sha256").update(canonical(closeBody)).digest("hex"));
  const { close_signature: frameCloseSignature, ...frameCloseBody } = closeFrame.close;
  assert.equal(result.swarm_close_digest, createHash("sha256").update(canonical(frameCloseBody)).digest("hex"));

  const verified = await execFileAsync(process.execPath, ["asp-verify.mjs", "fed-receipt", result.receipt_frame, result.trusted_zones]);
  assert.deepEqual(JSON.parse(verified.stdout), { fed_receipt_verify: "ok", task_id: "public_node_probe_task" });
  const verifiedArtifacts = await execFileAsync(process.execPath, ["asp-verify.mjs", "fed-receipt-artifacts", result.receipt_frame, result.trusted_zones]);
  assert.deepEqual(JSON.parse(verifiedArtifacts.stdout), { fed_receipt_artifacts_verify: "ok", task_id: "public_node_probe_task", artifact_count: 1 });
});
