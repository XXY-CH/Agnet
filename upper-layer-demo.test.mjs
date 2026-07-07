import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { promisify } from "node:util";
import { canonical, loadRegistry, resolveAgent, verifyObject } from "./asp-core.mjs";

const execFileAsync = promisify(execFile);

test("upper layer demo signs a 10-agent plan with a master agent", async () => {
  const { stdout } = await execFileAsync("node", ["upper-layer-demo.mjs"]);
  const result = JSON.parse(stdout);
  const plan = JSON.parse(await readFile(result.plan, "utf8"));
  const registry = await loadRegistry(result.registry);
  const master = resolveAgent(registry, plan.master_agent);
  const { signature, ...planBody } = plan;

  assert.equal(result.upper_layer_demo, "ok");
  assert.equal(result.master_agent, "agent://upper/master");
  assert.equal(result.worker_count, 10);
  assert.equal(result.assignment_count, 10);
  assert.equal(plan.master_aid, master.descriptor.aid);
  assert.equal(verifyObject(master.publicKey, planBody, signature), true);
  assert.equal(result.plan_digest, createHash("sha256").update(canonical(plan)).digest("hex"));
  assert.equal(new Set(plan.assignments.map((assignment) => assignment.agent)).size, 10);
  for (const assignment of plan.assignments) {
    const resolved = resolveAgent(registry, assignment.agent);
    assert.equal(resolved.descriptor.capabilities.includes(assignment.capability), true);
  }
});
