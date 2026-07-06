import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { test } from "node:test";
import { promisify } from "node:util";

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
});
