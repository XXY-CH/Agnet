import {
  appendAudit,
  approvalReasons,
  createAgent,
  createZone,
  enforcePolicy,
  loadRegistry,
  resolveAgent,
  signObject,
  verifyObject,
  writeArtifact,
  writeRegistry,
} from "./asp-core.mjs";

async function run() {
  const requester = createAgent("agent://local/requester");
  const worker = createAgent("agent://local/summarizer", {
    allow_network: false,
    approval_required: ["write"],
    write_prefixes: ["artifact://local/"],
  });
  const zone = createZone("zone://local");
  await writeRegistry("state/registry.json", zone, [requester.descriptor, worker.descriptor]);
  const registry = await loadRegistry("state/registry.json");

  const task = {
    task_id: "task_001",
    from: requester.aid,
    to: worker.alias,
    intent: "Summarize the supplied text as a tiny MVP artifact.",
    scope: { network: false, write: ["artifact://local/task_001/"] },
    budget: { time_seconds: 30 },
  };
  const signedTask = { ...task, signature: signObject(requester.privateKey, task) };

  const resolvedRequester = resolveAgent(registry, requester.alias);
  if (!verifyObject(resolvedRequester.publicKey, task, signedTask.signature)) {
    throw new Error("task signature verification failed");
  }
  const resolvedWorker = resolveAgent(registry, worker.alias);
  enforcePolicy(resolvedWorker.descriptor, task);

  let deniedTask;
  try {
    enforcePolicy(resolvedWorker.descriptor, { ...task, task_id: "task_denied", scope: { network: true } });
  } catch (error) {
    deniedTask = error.message;
  }
  if (!deniedTask) throw new Error("policy denial self-check failed");

  const events = [{ type: "task.accepted", task_id: task.task_id, by: worker.aid }];
  const approvals = approvalReasons(resolvedWorker.descriptor, task);
  if (approvals.length > 0) {
    events.push({ type: "approval.required", task_id: task.task_id, reasons: approvals });
    events.push({ type: "approval.granted", task_id: task.task_id, by: "human://local/operator", reasons: approvals });
  }
  events.push({ type: "task.started", task_id: task.task_id, by: worker.aid });
  events.push({ type: "task.progress", task_id: task.task_id, progress: 0.5 });

  const artifactUri = "artifact://local/task_001/summary.md";
  const artifactPath = await writeArtifact(
    artifactUri,
    "# MVP Summary\n\nAgent Space MVP proved identity, signed task, events, artifact, and receipt.\n",
  );
  events.push({ type: "artifact.created", task_id: task.task_id, uri: artifactUri });
  events.push({ type: "task.completed", task_id: task.task_id, by: worker.aid });
  for (const event of events) await appendAudit({ kind: "event", ...event });

  const receipt = {
    task_id: task.task_id,
    from: requester.aid,
    to: worker.aid,
    artifact_refs: [artifactUri],
    event_count: events.length,
    approvals,
  };
  const signedReceipt = { ...receipt, signature: signObject(worker.privateKey, receipt) };
  await appendAudit({ kind: "receipt", ...signedReceipt });

  if (!verifyObject(resolvedWorker.publicKey, receipt, signedReceipt.signature)) {
    throw new Error("receipt signature verification failed");
  }

  console.log(JSON.stringify({
    registry: "state/registry.json",
    requester: requester.aid,
    worker: worker.aid,
    deniedTask,
    events,
    artifactPath,
    auditLog: "state/audit.log",
    receipt: signedReceipt,
  }, null, 2));
}

run().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
