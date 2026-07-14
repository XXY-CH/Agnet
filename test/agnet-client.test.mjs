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
      correlation: { workspace_id: "workspace-1", conversation_id: "conversation-1", pi_session_id: "session-1", tool_call_id: "call-1" },
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
    pi_session_id: "session-1",
    tool_call_id: "call-1",
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
      client.createTask({ taskId: "pi:duplicate", to: "agent://worker", intent: "x", scope: {}, correlation: { workspace_id: "w", conversation_id: "c", pi_session_id: "s", tool_call_id: "t" } }),
      (error) => error instanceof AgnetAPIError && error.status === 409 && error.code === "idempotency_conflict",
    );
  });
});

test("agnetTaskId is deterministic and separates session/tool pairs", () => {
  assert.equal(agnetTaskId("session-a", "call-a"), agnetTaskId("session-a", "call-a"));
  assert.notEqual(agnetTaskId("session-a", "call-a"), agnetTaskId("session-b", "call-a"));
  assert.match(agnetTaskId("session-a", "call-a"), /^pi:[0-9a-f]{64}$/);
});

test("AgnetClient verifies receipt trust, signature, task binding, and artifact bytes locally", async (t) => {
  const originKey = generateKeyPairSync("ed25519").privateKey;
  const workerZoneKey = generateKeyPairSync("ed25519").privateKey;
  const workerKey = generateKeyPairSync("ed25519").privateKey;
  const origin = zoneFromPrivateKey("zone://origin", originKey);
  const workerZone = zoneFromPrivateKey("zone://worker", workerZoneKey);
  const worker = agentFromPrivateKey("agent://worker/tool", workerKey, { allow_network: false }, ["asp+local://worker"], ["workspace.read"]);
  const signedTask = { task_id: "pi:local-verify", from: "aid:requester", to: worker.alias, intent: "read", signature: "request-signature" };
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
  });
});

