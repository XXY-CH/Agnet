import { createHash } from "node:crypto";
import {
  canonical,
  createAgent,
  createZone,
  loadRegistry,
  resolveAgent,
  signObject,
  verifyObject,
  writeJson,
  writeRegistry,
} from "./asp-core.mjs";

const capabilities = [
  "research.map",
  "requirements.extract",
  "architecture.review",
  "protocol.verify",
  "security.audit",
  "artifact.inspect",
  "test.write",
  "docs.summarize",
  "release.check",
  "operator.brief",
];

function digestHex(value) {
  return createHash("sha256").update(canonical(value)).digest("hex");
}

async function run() {
  const zone = createZone("zone://upper-demo");
  const master = createAgent("agent://upper/master", {}, ["asp+local://upper-demo"], ["orchestrate.demo"]);
  const workers = capabilities.map((capability, index) => createAgent(
    `agent://upper/specialist-${String(index + 1).padStart(2, "0")}`,
    {},
    ["asp+local://upper-demo"],
    [capability],
  ));
  const registryPath = "state/upper-layer-demo-registry.json";
  const planPath = "state/upper-layer-demo-plan.json";
  await writeRegistry(registryPath, zone, [master.descriptor, ...workers.map((worker) => worker.descriptor)]);

  const registry = await loadRegistry(registryPath);
  const assignments = workers.map((worker, index) => ({
    step_id: `step-${String(index + 1).padStart(2, "0")}`,
    agent: worker.alias,
    capability: capabilities[index],
  }));
  for (const assignment of assignments) {
    const resolved = resolveAgent(registry, assignment.agent);
    if (!resolved.descriptor.capabilities.includes(assignment.capability)) {
      throw new Error(`assignment capability mismatch: ${assignment.agent}`);
    }
  }
  const plan = {
    plan_id: "upper-demo-10-agent-orchestration",
    master_agent: master.alias,
    master_aid: master.aid,
    worker_count: workers.length,
    assignments,
  };
  const signedPlan = { ...plan, signature: signObject(master.privateKey, plan) };
  const resolvedMaster = resolveAgent(registry, master.alias);
  if (!verifyObject(resolvedMaster.publicKey, plan, signedPlan.signature)) {
    throw new Error("master plan signature verification failed");
  }
  await writeJson(planPath, signedPlan);
  console.log(JSON.stringify({
    upper_layer_demo: "ok",
    registry: registryPath,
    plan: planPath,
    zone: zone.zid,
    master_agent: master.alias,
    master_aid: master.aid,
    worker_count: workers.length,
    assignment_count: assignments.length,
    plan_digest: digestHex(signedPlan),
  }, null, 2));
}

run().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
