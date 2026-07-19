import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import http from "node:http";
import test from "node:test";

import { AgnetAPIError, AgnetClient, agnetTaskId } from "../agnet-client.mjs";
import { agentFromPrivateKey, canonical, signObject, zoneBinding, zoneFromPrivateKey } from "../asp-core.mjs";

async function withServer(handler, run) {
  const server = http.createServer(handler);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  try {
    await run(`http://127.0.0.1:${address.port}`);
  } finally {
    await new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
  }
}

async function readJSON(request) {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  return chunks.length === 0 ? {} : JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function json(response, status, payload, headers = {}) {
  response.writeHead(status, { "content-type": "application/json", ...headers });
  response.end(JSON.stringify(payload));
}

test("AgnetClient maps the stable product contract without exposing journal paths", async () => {
  const requests = [];
  await withServer(async (request, response) => {
    const body = await readJSON(request);
    requests.push({ method: request.method, url: request.url, authorization: request.headers.authorization, body });
    if (request.method === "POST" && request.url === "/api/v1/tasks") {
      json(response, 201, { data: { task_id: body.task_id, status: "queued", correlation: body.correlation } });
      return;
    }
    if (request.method === "POST" && request.url === "/api/v1/tasks/pi%3Atask/execute") {
      json(response, 202, { data: { task_id: "pi:task", status: "claimed" } });
      return;
    }
    if (request.method === "GET" && request.url === "/api/v1/tasks/pi%3Atask") {
      json(response, 200, { data: { task_id: "pi:task", status: "completed" } });
      return;
    }
    if (request.method === "POST" && request.url === "/api/approvals/actions") {
      json(response, 200, { ok: true, approval: { task_id: body.task_id, status: body.action === "approve" ? "approved" : "denied" } });
      return;
    }
    if (request.method === "POST" && request.url === "/api/v1/tasks/pi%3Atask/cancel") {
      json(response, 200, { data: { task_id: "pi:task", status: "cancelled" } });
      return;
    }
    if (request.method === "POST" && request.url === "/api/v1/tasks/pi%3Atask/retry") {
      json(response, 201, { data: { task_id: body.task_id, retry_of: "pi:task", status: "queued" } });
      return;
    }
    if (request.method === "GET" && request.url === "/api/v1/tasks/pi%3Atask/receipt") {
      json(response, 200, { data: { task_id: "pi:task", status: "completed", committed: true, receipt_digest: "abc", receipt: { artifact_refs: ["artifact://local/pi:task/result"] } } });
      return;
    }
    response.writeHead(404).end();
  }, async (baseURL) => {
    const client = new AgnetClient({ baseURL, token: "secret" });
    const intent = client.createIntent({ workspaceId: "workspace-1", conversationId: "conversation-1", text: "inspect" });
    assert.match(intent.intentId, /^intent:sha256:[0-9a-f]{64}$/);
    const task = await client.createTask({
      taskId: "pi:task",
      to: "agent://worker",
      intent: intent.text,
      scope: { network: false, write: [], data_domains: ["workspace"] },
      correlation: { workspace_id: "workspace-1", conversation_id: "conversation-1", session_id: "session-1", run_id: "run-1", tool_call_id: "call-1", task_id: "pi:task", payload_digest: `sha256:${"a".repeat(64)}` },
    });
    assert.equal(task.status, "queued");
    assert.equal((await client.execute("pi:task")).status, "claimed");
    assert.equal((await client.getTask("pi:task")).status, "completed");
    assert.equal((await client.approve({ taskId: "pi:task", actor: "human://local" })).status, "approved");
    assert.equal((await client.deny({ taskId: "pi:task", actor: "human://local" })).status, "denied");
    assert.equal((await client.cancel("pi:task", "user cancelled")).status, "cancelled");
    assert.equal((await client.retry("pi:task", { taskId: "pi:task:attempt:2" })).retry_of, "pi:task");
    const receipt = await client.getReceipt("pi:task");
    assert.equal(receipt.committed, true);
  });

  assert.equal(requests[0].authorization, "Bearer secret");
  assert.deepEqual(requests[0].body.correlation, {
    workspace_id: "workspace-1",
    conversation_id: "conversation-1",
    session_id: "session-1",
    run_id: "run-1",
    tool_call_id: "call-1",
    task_id: "pi:task",
    payload_digest: `sha256:${"a".repeat(64)}`,
  });
  assert.ok(requests.every((request) => !JSON.stringify(request).includes("journal")));
});

test("AgnetClient subscription resumes by cursor and stops at a terminal receipt", async () => {
  const cursors = [];
  await withServer((request, response) => {
    const url = new URL(request.url, "http://local");
    if (url.pathname !== "/api/v1/tasks/pi%3Astream/events") {
      response.writeHead(404).end();
      return;
    }
    const after = url.searchParams.get("after") ?? "0";
    cursors.push(after);
    if (after === "0") {
      json(response, 200, { data: [{ cursor: 2, type: "task.started", verified: false, payload: { task_id: "pi:stream" } }], next_cursor: "2" });
      return;
    }
    json(response, 200, { data: [{ cursor: 4, type: "receipt.committed", verified: false, payload: { task_id: "pi:stream" } }], next_cursor: "4" });
  }, async (baseURL) => {
    const client = new AgnetClient({ baseURL, pollIntervalMs: 1 });
    const seen = [];
    await new Promise((resolve, reject) => {
      client.subscribe("pi:stream", (event) => {
        seen.push(event.type);
        if (event.type === "receipt.committed") resolve();
      }, { onError: reject });
    });
    assert.deepEqual(seen, ["task.started", "receipt.committed"]);
    await new Promise((resolve) => setTimeout(resolve, 10));
  });
  assert.deepEqual(cursors, ["0", "2"]);
});

test("AgnetClient rejects malformed replay batches before delivery", async (t) => {
  const valid = { cursor: 5, type: "task.started", verified: false, payload: { task_id: "pi:replay-invalid" } };
  const cases = [
    ["non-array data", { data: {}, next_cursor: "5" }],
    ["unsafe cursor", { data: [{ ...valid, cursor: Number.MAX_SAFE_INTEGER + 1 }], next_cursor: String(Number.MAX_SAFE_INTEGER + 1) }],
    ["duplicate cursor", { data: [valid, { ...valid }], next_cursor: "6" }],
    ["decreasing cursor", { data: [{ ...valid, cursor: 6 }, valid], next_cursor: "6" }],
    ["cursor at or before after", { data: [{ ...valid, cursor: 4 }], next_cursor: "5" }],
    ["cursor beyond next bound", { data: [{ ...valid, cursor: 6 }], next_cursor: "5" }],
    ["nonprogressing next cursor", { data: [valid], next_cursor: "4" }],
    ["regressing empty next cursor", { data: [], next_cursor: "3" }],
    ["cross-task payload", { data: [{ ...valid, payload: { task_id: "pi:other-task" } }], next_cursor: "5" }],
    ["malformed event", { data: [{ ...valid, type: "" }], next_cursor: "5" }],
  ];
  for (const [name, payload] of cases) {
    await t.test(name, async () => {
      await withServer((_request, response) => json(response, 200, payload), async (baseURL) => {
        const client = new AgnetClient({ baseURL });
        await assert.rejects(client.replay("pi:replay-invalid", 4), (error) => error instanceof AgnetAPIError && error.code === "invalid_response");
      });
    });
  }
});

test("AgnetClient subscription stops on its first invalid replay batch and preserves the typed cause", async () => {
  let requests = 0;
  let deliveries = 0;
  await withServer((_request, response) => {
    requests += 1;
    json(response, 200, { data: [{ cursor: 1, type: "task.started", verified: false, payload: { task_id: "pi:wrong-task" } }], next_cursor: "1" });
  }, async (baseURL) => {
    const client = new AgnetClient({ baseURL, pollIntervalMs: 1 });
    const error = await new Promise((resolve) => {
      client.subscribe("pi:subscription-task", () => { deliveries += 1; }, { onError: resolve });
    });
    assert.ok(error instanceof AgnetAPIError);
    assert.equal(error.code, "invalid_response");
    await new Promise((resolve) => setTimeout(resolve, 10));
  });
  assert.equal(deliveries, 0);
  assert.equal(requests, 1);
});

test("AgnetClient subscription rejects a regressing empty cursor without polling again", async () => {
  const cursors = [];
  let deliveries = 0;
  let errors = 0;
  await withServer((request, response) => {
    const url = new URL(request.url, "http://local");
    cursors.push(url.searchParams.get("after"));
    json(response, 200, { data: [], next_cursor: "3" });
  }, async (baseURL) => {
    const client = new AgnetClient({ baseURL, pollIntervalMs: 1 });
    let resolveError;
    const error = new Promise((resolve) => { resolveError = resolve; });
    const stop = client.subscribe("pi:subscription-regressing-empty", () => { deliveries += 1; }, {
      after: "4",
      onError: (cause) => {
        errors += 1;
        resolveError(cause);
      },
    });
    const outcome = await Promise.race([
      error,
      new Promise((resolve) => setTimeout(() => resolve(null), 25)),
    ]);
    stop();
    assert.ok(outcome instanceof AgnetAPIError);
    assert.equal(outcome.code, "invalid_response");
  });
  assert.equal(errors, 1);
  assert.equal(deliveries, 0);
  assert.deepEqual(cursors, ["4"]);
});

test("AgnetClient subscription reports transport AbortError not caused by stop", async () => {
  const transportAbort = new Error("transport aborted independently");
  transportAbort.name = "AbortError";
  const client = new AgnetClient({
    baseURL: "http://127.0.0.1:1",
    fetch: async () => { throw transportAbort; },
  });
  const observed = await new Promise((resolve) => {
    client.subscribe("pi:stream-abort", () => {}, { onError: resolve });
  });
  assert.equal(observed, transportAbort);
});

test("AgnetClient preserves typed API failures", async () => {
  await withServer((_request, response) => {
    json(response, 409, { error: { code: "idempotency_conflict", message: "task already exists" } });
  }, async (baseURL) => {
    const client = new AgnetClient({ baseURL });
    await assert.rejects(
      client.createTask({ taskId: "agent:duplicate", to: "agent://worker", intent: "x", scope: {}, correlation: { workspace_id: "w", conversation_id: "c", session_id: "s", run_id: "r", tool_call_id: "t", task_id: "agent:duplicate", payload_digest: `sha256:${"a".repeat(64)}` } }),
      (error) => error instanceof AgnetAPIError && error.status === 409 && error.code === "idempotency_conflict",
    );
  });
});

test("agnetTaskId is deterministic and separates session/tool pairs", () => {
  assert.equal(agnetTaskId("session-a", "call-a"), agnetTaskId("session-a", "call-a"));
  assert.notEqual(agnetTaskId("session-a", "call-a"), agnetTaskId("session-b", "call-a"));
  assert.match(agnetTaskId("session-a", "call-a"), /^agent:[0-9a-f]{64}$/);
});

test("AgnetClient requires the exact authenticated capability contract and replays a cursor batch", async () => {
  const requests = [];
  await withServer((request, response) => {
    requests.push({ url: request.url, authorization: request.headers.authorization });
    if (request.url === "/api/v1/capabilities") {
      json(response, 200, { data: { package_name: "agnet", package_version: "0.1.0-dev.6", product_api: "agnet.product-api/v1", capabilities: ["task.create", "task.execute", "task.cancel", "receipt.get", "receipt.verify", "evidence.replay", "evidence.subscribe"] } });
      return;
    }
    if (request.url === "/api/v1/tasks/pi%3Areplay/events?after=4") {
      json(response, 200, { data: [{ cursor: 5, type: "task.started", verified: false, payload: { task_id: "pi:replay" } }], next_cursor: "5" });
      return;
    }
    response.writeHead(404).end();
  }, async (baseURL) => {
    const client = new AgnetClient({ baseURL, token: "secret" });
    await client.handshake({ packageVersion: "0.1.0-dev.6", productApi: "agnet.product-api/v1", capabilities: ["task.create", "task.execute", "task.cancel", "receipt.get", "receipt.verify", "evidence.replay", "evidence.subscribe"] });
    const replay = await client.replay("pi:replay", 4);
    assert.deepEqual(replay, { events: [{ cursor: 5, type: "task.started", verified: false, payload: { task_id: "pi:replay" } }], nextCursor: 5 });
  });
  assert.deepEqual(requests.map((request) => request.authorization), ["Bearer secret", "Bearer secret"]);
});

test("AgnetClient rejects a receipt whose signed task and receipt disagree on full correlation", async () => {
  const originKey = generateKeyPairSync("ed25519").privateKey;
  const workerZoneKey = generateKeyPairSync("ed25519").privateKey;
  const workerKey = generateKeyPairSync("ed25519").privateKey;
  const origin = zoneFromPrivateKey("zone://origin-correlation", originKey);
  const workerZone = zoneFromPrivateKey("zone://worker-correlation", workerZoneKey);
  const worker = agentFromPrivateKey("agent://worker/correlation", workerKey, { allow_network: false }, ["asp+local://worker"], ["workspace.read"]);
  const correlation = { workspace_id: "workspace", conversation_id: "conversation", session_id: "session", run_id: "run", tool_call_id: "tool", task_id: "pi:correlation", payload_digest: `sha256:${"a".repeat(64)}` };
  const signedTask = { task_id: "pi:correlation", from: "aid:requester", to: worker.alias, intent: "read", correlation, signature: "request-signature" };
  const receiptBody = { task_id: signedTask.task_id, task_digest: createHash("sha256").update(canonical(signedTask)).digest("hex"), from: signedTask.from, origin_zone: origin.zid, executing_zone: workerZone.zid, to: worker.aid, status: "cancelled", correlation: { ...correlation, run_id: "other-run" }, artifact_refs: [], artifact_manifests: [], event_count: 0, approvals: [], checkpoint_refs: [], checkpoints: [] };
  const signedReceipt = { ...receiptBody, signature: signObject(worker.privateKey, receiptBody) };
  const committed = { committed: true, task_id: signedTask.task_id, status: "cancelled", receipt_digest: createHash("sha256").update(canonical(signedReceipt)).digest("hex"), audit_hash: "audit-hash", zone: workerZone.descriptor, worker: worker.descriptor, zone_binding: zoneBinding(workerZone, worker.descriptor), signed_task: signedTask, receipt: signedReceipt };
  const client = new AgnetClient({ baseURL: "http://127.0.0.1:1", trustedZones: [origin.descriptor, workerZone.descriptor] });
  await assert.rejects(client.verifyReceipt(committed), (error) => error instanceof AgnetAPIError && error.code === "verification_failed");
});

test("AgnetClient verifies receipt trust, signature, task binding, and artifact bytes locally", async (t) => {
  const originKey = generateKeyPairSync("ed25519").privateKey;
  const workerZoneKey = generateKeyPairSync("ed25519").privateKey;
  const workerKey = generateKeyPairSync("ed25519").privateKey;
  const origin = zoneFromPrivateKey("zone://origin", originKey);
  const workerZone = zoneFromPrivateKey("zone://worker", workerZoneKey);
  const worker = agentFromPrivateKey("agent://worker/tool", workerKey, { allow_network: false }, ["asp+local://worker"], ["workspace.read"]);
  const signedTask = { task_id: "pi:local-verify", from: "aid:requester", to: worker.alias, intent: "read", correlation: { workspace_id: "workspace", conversation_id: "conversation", session_id: "session", run_id: "run", tool_call_id: "tool", task_id: "pi:local-verify", payload_digest: `sha256:${"a".repeat(64)}` }, signature: "request-signature" };
  const artifactBytes = Buffer.from("locally verified artifact", "utf8");
  const artifactURI = "artifact://local/pi:local-verify/result.txt";
  const manifestBody = {
    uri: artifactURI,
    sha256: createHash("sha256").update(artifactBytes).digest("hex"),
    size: artifactBytes.length,
    media_type: "text/plain; charset=utf-8",
    afp: `afp:sha256:${createHash("sha256").update(artifactBytes).digest("hex")}`,
  };
  const manifest = { ...manifestBody, manifest_hash: createHash("sha256").update(canonical(manifestBody)).digest("hex") };
  const receiptBody = {
    task_id: signedTask.task_id,
    task_digest: createHash("sha256").update(canonical(signedTask)).digest("hex"),
    from: signedTask.from,
    origin_zone: origin.zid,
    executing_zone: workerZone.zid,
    to: worker.aid,
    status: "completed",
    artifact_refs: [artifactURI],
    artifact_manifests: [manifest],
    result_artifact: { uri: artifactURI, sha256: manifest.sha256, manifest_hash: manifest.manifest_hash },
    event_count: 1,
    approvals: [],
    checkpoint_refs: [],
    checkpoints: [],
    correlation: signedTask.correlation,
  };
  const signedReceipt = { ...receiptBody, signature: signObject(worker.privateKey, receiptBody) };
  const committed = {
    committed: true,
    task_id: signedTask.task_id,
    status: "completed",
    receipt_digest: createHash("sha256").update(canonical(signedReceipt)).digest("hex"),
    audit_hash: "audit-hash",
    zone: workerZone.descriptor,
    worker: worker.descriptor,
    zone_binding: zoneBinding(workerZone, worker.descriptor),
    signed_task: signedTask,
    receipt: signedReceipt,
  };
  let artifactReads = 0;
  await withServer((request, response) => {
    const url = new URL(request.url, "http://local");
    if (url.pathname === "/api/artifacts/read") {
      artifactReads += 1;
      response.writeHead(200, { "content-type": manifest.media_type });
      response.end(artifactBytes);
      return;
    }
    response.writeHead(404).end();
  }, async (baseURL) => {
    const client = new AgnetClient({ baseURL, trustedZones: [origin.descriptor, workerZone.descriptor] });
    const verified = await client.verifyReceipt(committed);
    assert.equal(verified.verified, true);
    assert.equal(verified.verification.mode, "local");
    assert.equal(verified.verification.artifact_count, 1);

    await t.test("rejects a relabeled wrapper task_id before fetching artifacts", async () => {
      const relabeled = structuredClone(committed);
      relabeled.task_id = "pi:relabeled";
      const readsBeforeVerification = artifactReads;
      await assert.rejects(client.verifyReceipt(relabeled), (error) => error instanceof AgnetAPIError && error.code === "verification_failed");
      assert.equal(artifactReads, readsBeforeVerification);
    });

    await t.test("rejects a missing signed_task before fetching artifacts", async () => {
      const missingSignedTask = structuredClone(committed);
      delete missingSignedTask.signed_task;
      const readsBeforeVerification = artifactReads;
      await assert.rejects(client.verifyReceipt(missingSignedTask), (error) => error instanceof AgnetAPIError && error.code === "verification_failed");
      assert.equal(artifactReads, readsBeforeVerification);
    });

    await t.test("rejects a signed receipt without terminal status before fetching artifacts", async () => {
      const missingStatus = structuredClone(committed);
      const { signature: _signature, status: _status, ...unsignedReceipt } = missingStatus.receipt;
      missingStatus.receipt = { ...unsignedReceipt, signature: signObject(worker.privateKey, unsignedReceipt) };
      missingStatus.receipt_digest = createHash("sha256").update(canonical(missingStatus.receipt)).digest("hex");
      const readsBeforeVerification = artifactReads;
      await assert.rejects(client.verifyReceipt(missingStatus), (error) => error instanceof AgnetAPIError && error.code === "verification_failed");
      assert.equal(artifactReads, readsBeforeVerification);
    });

    await t.test("rejects a relabeled wrapper status before fetching artifacts", async () => {
      const relabeled = structuredClone(committed);
      relabeled.status = "failed";
      const readsBeforeVerification = artifactReads;
      await assert.rejects(client.verifyReceipt(relabeled), (error) => error instanceof AgnetAPIError && error.code === "verification_failed");
      assert.equal(artifactReads, readsBeforeVerification);
    });

    const tampered = structuredClone(committed);
    tampered.receipt.signature = `${tampered.receipt.signature}tampered`;
    await assert.rejects(client.verifyReceipt(tampered), (error) => error instanceof AgnetAPIError && error.code === "verification_failed");

    await t.test("rejects signed artifact refs without manifests before fetching artifacts", async () => {
      const missingManifests = structuredClone(committed);
      const { signature: _signature, artifact_manifests: _manifests, result_artifact: _resultArtifact, ...unsignedReceipt } = missingManifests.receipt;
      const unsignedCancelledReceipt = { ...unsignedReceipt, status: "cancelled" };
      missingManifests.status = "cancelled";
      missingManifests.receipt = { ...unsignedCancelledReceipt, signature: signObject(worker.privateKey, unsignedCancelledReceipt) };
      missingManifests.receipt_digest = createHash("sha256").update(canonical(missingManifests.receipt)).digest("hex");
      const readsBeforeVerification = artifactReads;
      await assert.rejects(client.verifyReceipt(missingManifests), (error) => error instanceof AgnetAPIError && error.code === "verification_failed");
      assert.equal(artifactReads, readsBeforeVerification);
    });

    await t.test("rejects signed receipt artifact manifest cardinality mismatches before fetching artifacts", async () => {
      const extraManifests = structuredClone(committed);
      const { signature: _signature, ...unsignedReceipt } = extraManifests.receipt;
      extraManifests.receipt = { ...unsignedReceipt, artifact_manifests: [manifest, manifest], signature: signObject(worker.privateKey, { ...unsignedReceipt, artifact_manifests: [manifest, manifest] }) };
      extraManifests.receipt_digest = createHash("sha256").update(canonical(extraManifests.receipt)).digest("hex");
      const readsBeforeVerification = artifactReads;
      await assert.rejects(client.verifyReceipt(extraManifests), (error) => error instanceof AgnetAPIError && error.code === "verification_failed");
      assert.equal(artifactReads, readsBeforeVerification);
    });
  });
});

