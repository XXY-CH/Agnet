import { createHash } from "node:crypto";
import { canonical, verifyFederatedReceipt } from "./asp-core.mjs";

const TERMINAL_EVENT_TYPE = "receipt.committed";

export class AgnetAPIError extends Error {
  constructor(message, { status = 0, code = "request_failed", details, cause } = {}) {
    super(message, { cause });
    this.name = "AgnetAPIError";
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

export function agnetTaskId(sessionId, toolCallId) {
  requireNonEmptyString(sessionId, "sessionId");
  requireNonEmptyString(toolCallId, "toolCallId");
  return `agent:${sha256(`${sessionId}\0${toolCallId}`)}`;
}

export function createToolCorrelation({ workspaceId, conversationId, sessionId, runId, toolCallId, taskId = agnetTaskId(sessionId, toolCallId), payloadDigest, operationDigest }) {
  for (const [name, value] of Object.entries({ workspaceId, conversationId, sessionId, runId, toolCallId, taskId, payloadDigest, operationDigest })) {
    requireNonEmptyString(value, name);
  }
  if (!/^sha256:[a-f0-9]{64}$/.test(payloadDigest)) throw new TypeError("payloadDigest must be a sha256 digest");
  if (!/^sha256:[a-f0-9]{64}$/.test(operationDigest)) throw new TypeError("operationDigest must be a sha256 digest");
  return Object.freeze({
    workspace_id: workspaceId,
    conversation_id: conversationId,
    session_id: sessionId,
    run_id: runId,
    tool_call_id: toolCallId,
    task_id: taskId,
    payload_digest: payloadDigest,
    operation_digest: operationDigest,
  });
}

export class AgnetClient {
  #baseURL;
  #token;
  #fetch;
  #pollIntervalMs;
  #trustedZones;
  #maxArtifactBytes;

  constructor({ baseURL, token, trustedZones = [], maxArtifactBytes = 64 * 1024 * 1024, fetch: fetchImplementation = globalThis.fetch, pollIntervalMs = 250, allowInsecureRemote = false }) {
    if (typeof fetchImplementation !== "function") throw new TypeError("fetch implementation is required");
    const parsed = new URL(baseURL);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") throw new TypeError("Agnet baseURL must use http or https");
    if (parsed.protocol === "http:" && !allowInsecureRemote && !isLoopbackHost(parsed.hostname)) {
      throw new TypeError("Plain HTTP Agnet endpoints must be loopback-only");
    }
    if (!Number.isFinite(pollIntervalMs) || pollIntervalMs < 0) throw new TypeError("pollIntervalMs must be non-negative");
    if (!Number.isSafeInteger(maxArtifactBytes) || maxArtifactBytes <= 0) throw new TypeError("maxArtifactBytes must be a positive safe integer");
    this.#baseURL = parsed.toString().replace(/\/$/, "");
    this.#token = token;
    this.#fetch = fetchImplementation;
    this.#pollIntervalMs = pollIntervalMs;
    this.#trustedZones = normalizeTrustedZones(trustedZones);
    this.#maxArtifactBytes = maxArtifactBytes;
  }

  createIntent({ workspaceId, conversationId, text }) {
    requireNonEmptyString(workspaceId, "workspaceId");
    requireNonEmptyString(conversationId, "conversationId");
    requireNonEmptyString(text, "text");
    return {
      intentId: `intent:sha256:${sha256(`${workspaceId}\0${conversationId}\0${text}`)}`,
      workspaceId,
      conversationId,
      text,
    };
  }

  async handshake({ packageVersion, productApi, capabilities }) {
    requireNonEmptyString(packageVersion, "packageVersion");
    requireNonEmptyString(productApi, "productApi");
    if (!Array.isArray(capabilities) || capabilities.some((capability) => typeof capability !== "string" || capability.length === 0)) {
      throw new TypeError("capabilities must be a non-empty string array");
    }
    const advertised = this.#data(await this.#request("/api/v1/capabilities"));
    if (!isRecord(advertised) || advertised.package_name !== "agnet" || advertised.package_version !== packageVersion || advertised.product_api !== productApi || !sameStringList(advertised.capabilities, capabilities)) {
      throw new AgnetAPIError("Agnet capability handshake does not match the required contract", { status: 409, code: "capability_mismatch", details: advertised });
    }
    return Object.freeze({ packageName: advertised.package_name, packageVersion: advertised.package_version, productApi: advertised.product_api, capabilities: Object.freeze([...advertised.capabilities]) });
  }

  async createTask(input) {
    const correlation = normalizeCorrelation(input.correlation);
    if (correlation.task_id !== input.taskId) throw new TypeError("correlation.task_id must match taskId");
    const payload = {
      task_id: input.taskId,
      to: input.to,
      intent: input.intent,
      scope: input.scope,
      correlation,
    };
    if (input.budget !== undefined) payload.budget = input.budget;
    if (input.artifactRef !== undefined) payload.artifact_ref = input.artifactRef;
    if (input.approvalExpiresAt !== undefined) payload.approval_expires_at = input.approvalExpiresAt;
    return this.#data(await this.#request("/api/v1/tasks", { method: "POST", body: payload }));
  }

  async execute(taskId, correlation) {
    const expected = normalizeCorrelation(correlation);
    if (expected.task_id !== taskId) throw new TypeError("correlation.task_id must match taskId");
    return this.#data(await this.#request(`/api/v1/tasks/${encodeURIComponent(taskId)}/execute`, { method: "POST", body: { correlation: expected } }));
  }

  async cancel(taskId, reason = "", correlation) {
    const expected = normalizeCorrelation(correlation);
    if (expected.task_id !== taskId) throw new TypeError("correlation.task_id must match taskId");
    return this.#data(await this.#request(`/api/v1/tasks/${encodeURIComponent(taskId)}/cancel`, { method: "POST", body: { reason, correlation: expected } }));
  }

  async retry(taskId, { taskId: attemptTaskId }) {
    return this.#data(await this.#request(`/api/v1/tasks/${encodeURIComponent(taskId)}/retry`, { method: "POST", body: { task_id: attemptTaskId } }));
  }

  async approve({ taskId, actor = "human://local" }) {
    const payload = await this.#request("/api/approvals/actions", { method: "POST", body: { action: "approve", task_id: taskId, actor } });
    return payload.approval;
  }

  async deny({ taskId, actor = "human://local" }) {
    const payload = await this.#request("/api/approvals/actions", { method: "POST", body: { action: "deny", task_id: taskId, actor } });
    return payload.approval;
  }

  async getTask(taskId) {
    return this.#data(await this.#request(`/api/v1/tasks/${encodeURIComponent(taskId)}`));
  }

  async getReceipt(taskId) {
    return this.#data(await this.#request(`/api/v1/tasks/${encodeURIComponent(taskId)}/receipt`));
  }

  async replay(taskId, after = 0) {
    requireNonEmptyString(taskId, "taskId");
    if (!Number.isSafeInteger(after) || after < 0) throw new TypeError("replay cursor must be a non-negative safe integer");
    return this.#replayBatch(taskId, String(after));
  }

  async verifyReceipt(committed) {
    if (!isRecord(committed) || committed.committed !== true || typeof committed.task_id !== "string" || typeof committed.receipt_digest !== "string") {
      throw new AgnetAPIError("Receipt is not an Agnet committed receipt", { status: 409, code: "verification_failed" });
    }
    if (this.#trustedZones.size === 0) {
      throw new AgnetAPIError("Local receipt verification requires trustedZones", { status: 409, code: "trust_store_required" });
    }
    if (!isRecord(committed.zone) || !isRecord(committed.worker) || !isRecord(committed.zone_binding) || !isRecord(committed.signed_task) || !isRecord(committed.receipt)) {
      throw new AgnetAPIError("Committed receipt evidence is incomplete", { status: 409, code: "verification_failed" });
    }
    const signedTask = committed.signed_task;
    const taskId = committed.task_id;
    if (committed.receipt.task_id !== taskId || signedTask.task_id !== taskId) {
      throw new AgnetAPIError("Committed receipt task identity mismatch", { status: 409, code: "verification_failed" });
    }
    const signedStatus = committed.receipt.status;
    if ((signedStatus !== "completed" && signedStatus !== "failed" && signedStatus !== "cancelled") || committed.status !== signedStatus) {
      throw new AgnetAPIError("Committed receipt terminal status mismatch", { status: 409, code: "verification_failed" });
    }
    assertReceiptCorrelation(committed);
    const artifacts = receiptArtifactPairs(committed.receipt);
    try {
      verifyFederatedReceipt({
        type: "FED_RECEIPT",
        zone: committed.zone,
        worker: committed.worker,
        zone_binding: committed.zone_binding,
        receipt: committed.receipt,
      }, this.#trustedZones, signedTask);
    } catch (cause) {
      throw new AgnetAPIError("Local receipt signature or trust verification failed", { status: 409, code: "verification_failed", cause });
    }
    const localDigest = sha256(canonical(committed.receipt));
    if (localDigest !== committed.receipt_digest) {
      throw new AgnetAPIError("Local receipt digest mismatch", { status: 409, code: "verification_failed" });
    }
    for (const { reference, manifest } of artifacts) {
      const stream = await this.getArtifact(taskId, reference);
      const observed = await hashArtifactStream(stream, this.#maxArtifactBytes);
      if (observed.sha256 !== manifest.sha256 || observed.size !== manifest.size) {
        throw new AgnetAPIError("Local artifact verification failed", { status: 409, code: "verification_failed" });
      }
    }
    return {
      ...committed,
      verified: true,
      verification: {
        mode: "local",
        receipt_digest: localDigest,
        artifact_count: artifacts.length,
      },
    };
  }

  async getArtifact(taskId, reference, { signal } = {}) {
    const uri = typeof reference === "string" ? reference : reference?.uri;
    requireNonEmptyString(uri, "artifact reference");
    const path = `/api/artifacts/read?task_id=${encodeURIComponent(taskId)}&uri=${encodeURIComponent(uri)}`;
    const response = await this.#rawRequest(path, { signal });
    if (!response.body) throw new AgnetAPIError("Artifact response has no body", { status: 502, code: "empty_artifact" });
    return response.body;
  }

  async #replayBatch(taskId, after, signal) {
    const afterCursor = replayCursor(after, "replay cursor");
    const payload = await this.#request(`/api/v1/tasks/${encodeURIComponent(taskId)}/events?after=${encodeURIComponent(afterCursor)}`, { signal });
    if (!isRecord(payload) || !Array.isArray(payload.data)) throw invalidReplayResponse("Agnet returned replay data that is not an array");
    const nextCursor = replayCursor(payload.next_cursor ?? afterCursor, "next replay cursor");
    let previousCursor = afterCursor;
    let terminalSeen = false;
    for (const [index, event] of payload.data.entries()) {
      if (!isRecord(event) || !Number.isSafeInteger(event.cursor) || event.cursor <= previousCursor || event.cursor > nextCursor || typeof event.type !== "string" || event.type.length === 0 || typeof event.verified !== "boolean" || !isRecord(event.payload) || event.payload.task_id !== taskId) {
        throw invalidReplayResponse("Agnet returned an invalid replay event");
      }
      if (event.type === TERMINAL_EVENT_TYPE) {
        if (terminalSeen || index !== payload.data.length - 1) throw invalidReplayResponse("Agnet returned events after a terminal receipt");
        terminalSeen = true;
      }
      previousCursor = event.cursor;
    }
    if (nextCursor < afterCursor || payload.data.length > 0 && nextCursor === afterCursor) throw invalidReplayResponse("Agnet returned a nonprogressing replay cursor");
    return Object.freeze({ events: Object.freeze([...payload.data]), nextCursor });
  }

  subscribe(taskId, listener, { after = "0", signal, onError } = {}) {
    requireNonEmptyString(taskId, "taskId");
    if (typeof listener !== "function") throw new TypeError("listener must be a function");
    const controller = new AbortController();
    let stopped = false;
    const stop = () => {
      if (stopped) return;
      stopped = true;
      controller.abort();
      signal?.removeEventListener("abort", stop);
    };
    if (signal) {
      if (signal.aborted) stop();
      else signal.addEventListener("abort", stop, { once: true });
    }
    void (async () => {
      let cursor = String(after);
      try {
        while (!stopped) {
          const batch = await this.#replayBatch(taskId, cursor, controller.signal);
          for (const event of batch.events) {
            if (stopped) break;
            await listener(event);
            if (event.type === TERMINAL_EVENT_TYPE) {
              stop();
              break;
            }
          }
          cursor = String(batch.nextCursor);
          if (!stopped && batch.events.length === 0) await delay(this.#pollIntervalMs, controller.signal);
        }
      } catch (error) {
        if (!stopped) {
          stop();
          if (typeof onError === "function") onError(error);
          else queueMicrotask(() => { throw error; });
        }
      }
    })();
    return stop;
  }

  async #request(path, { method = "GET", body, signal } = {}) {
    const response = await this.#rawRequest(path, { method, body, signal });
    if (response.status === 204) return {};
    try {
      return await response.json();
    } catch (cause) {
      throw new AgnetAPIError("Agnet returned invalid JSON", { status: response.status, code: "invalid_response", cause });
    }
  }

  async #rawRequest(path, { method = "GET", body, signal } = {}) {
    const headers = { accept: "application/json" };
    if (body !== undefined) headers["content-type"] = "application/json";
    if (this.#token) headers.authorization = `Bearer ${this.#token}`;
    let response;
    try {
      response = await this.#fetch(`${this.#baseURL}${path}`, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        signal,
      });
    } catch (cause) {
      if (cause?.name === "AbortError") throw cause;
      throw new AgnetAPIError("Unable to reach Agnet", { code: "transport_error", cause });
    }
    if (response.ok) return response;
    let payload;
    try {
      payload = await response.json();
    } catch {
      payload = undefined;
    }
    const error = payload?.error;
    throw new AgnetAPIError(error?.message ?? `Agnet request failed with HTTP ${response.status}`, {
      status: response.status,
      code: error?.code ?? "request_failed",
      details: error?.details,
    });
  }

  #data(payload) {
    if (!payload || typeof payload !== "object" || !("data" in payload)) {
      throw new AgnetAPIError("Agnet response omitted data", { status: 502, code: "invalid_response" });
    }
    return payload.data;
  }
}

function normalizeTrustedZones(value) {
  const descriptors = value instanceof Map ? [...value.values()] : value;
  if (!Array.isArray(descriptors)) throw new TypeError("trustedZones must be an array or Map");
  const trusted = new Map();
  for (const descriptor of descriptors) {
    if (!isRecord(descriptor) || typeof descriptor.zid !== "string" || descriptor.zid.length === 0) {
      throw new TypeError("trusted zone descriptor is invalid");
    }
    trusted.set(descriptor.zid, descriptor);
  }
  return trusted;
}

async function hashArtifactStream(stream, maxBytes) {
  const reader = stream.getReader();
  const hash = createHash("sha256");
  let size = 0;
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      size += chunk.value.byteLength;
      if (size > maxBytes) {
        await reader.cancel("artifact exceeds maxArtifactBytes");
        throw new AgnetAPIError("Artifact exceeds maxArtifactBytes", { status: 409, code: "verification_failed" });
      }
      hash.update(chunk.value);
    }
    return { sha256: hash.digest("hex"), size };
  } finally {

    reader.releaseLock();
  }
}

function replayCursor(value, label) {
  const cursor = typeof value === "string" || typeof value === "number" ? Number(value) : Number.NaN;
  if (!Number.isSafeInteger(cursor) || cursor < 0) throw invalidReplayResponse(`${label} must be a non-negative safe integer`);
  return cursor;
}

function invalidReplayResponse(message) {
  return new AgnetAPIError(message, { status: 502, code: "invalid_response" });
}

function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function normalizeCorrelation(correlation) {
  if (!correlation || typeof correlation !== "object") throw new TypeError("correlation is required");
  if ("workspace_id" in correlation) return validateCorrelation(correlation);
  return createToolCorrelation({
    workspaceId: correlation.workspaceId,
    conversationId: correlation.conversationId,
    sessionId: correlation.sessionId,
    runId: correlation.runId,
    toolCallId: correlation.toolCallId,
    taskId: correlation.taskId,
    payloadDigest: correlation.payloadDigest,
    operationDigest: correlation.operationDigest,
  });
}

function validateCorrelation(correlation) {
  for (const field of ["workspace_id", "conversation_id", "session_id", "run_id", "tool_call_id", "task_id", "payload_digest", "operation_digest"]) {
    requireNonEmptyString(correlation[field], `correlation.${field}`);
  }
  if (!/^sha256:[a-f0-9]{64}$/.test(correlation.payload_digest)) throw new TypeError("correlation.payload_digest must be a sha256 digest");
  if (!/^sha256:[a-f0-9]{64}$/.test(correlation.operation_digest)) throw new TypeError("correlation.operation_digest must be a sha256 digest");
  return Object.freeze({ workspace_id: correlation.workspace_id, conversation_id: correlation.conversation_id, session_id: correlation.session_id, run_id: correlation.run_id, tool_call_id: correlation.tool_call_id, task_id: correlation.task_id, payload_digest: correlation.payload_digest, operation_digest: correlation.operation_digest });
}

function sameStringList(actual, expected) {
  return Array.isArray(actual) && actual.length === expected.length && actual.every((value, index) => value === expected[index]);
}

function assertReceiptCorrelation(committed) {
  try {
    const taskCorrelation = validateCorrelation(committed.signed_task.correlation);
    const receiptCorrelation = validateCorrelation(committed.receipt.correlation);
    if (taskCorrelation.task_id !== committed.task_id || receiptCorrelation.task_id !== committed.task_id || !sameStringList(Object.values(taskCorrelation), Object.values(receiptCorrelation))) {
      throw new Error("receipt correlation does not match the signed task");
    }
    const signedTask = committed.signed_task;
    requireNonEmptyString(signedTask.to, "signed_task.to");
    requireNonEmptyString(signedTask.intent, "signed_task.intent");
    if (!isRecord(signedTask.scope)) throw new TypeError("signed_task.scope must be an object");
    const expectedOperationDigest = `sha256:${sha256(canonical({
      target: signedTask.to,
      intent: signedTask.intent,
      scope: signedTask.scope,
      payload_digest: taskCorrelation.payload_digest,
    }))}`;
    if (taskCorrelation.operation_digest !== expectedOperationDigest) {
      throw new Error("signed task operation digest does not bind target, intent, scope, and payload");
    }
  } catch (cause) {
    throw new AgnetAPIError("Committed receipt correlation binding mismatch", { status: 409, code: "verification_failed", cause });
  }
}

function receiptArtifactPairs(receipt) {
  const references = receipt.artifact_refs;
  const manifests = receipt.artifact_manifests;
  if (references === undefined && manifests === undefined) return [];
  if (!Array.isArray(references) || !Array.isArray(manifests) || references.length !== manifests.length) {
    throw new AgnetAPIError("Receipt artifact refs and manifests must be equal-length arrays", { status: 409, code: "verification_failed" });
  }
  return references.map((reference, index) => {
    const manifest = manifests[index];
    if (typeof reference !== "string" || reference.length === 0 || !isRecord(manifest) || manifest.uri !== reference || typeof manifest.sha256 !== "string" || !Number.isSafeInteger(manifest.size) || manifest.size < 0) {
      throw new AgnetAPIError("Receipt artifact manifest is invalid", { status: 409, code: "verification_failed" });
    }
    return Object.freeze({ reference, manifest: Object.freeze({ uri: manifest.uri, sha256: manifest.sha256, size: manifest.size }) });
  });
}

function isLoopbackHost(hostname) {
  const normalized = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  return normalized === "localhost" || normalized === "127.0.0.1" || normalized === "::1";
}

function requireNonEmptyString(value, name) {
  if (typeof value !== "string" || value.length === 0) throw new TypeError(`${name} must be a non-empty string`);
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function delay(milliseconds, signal) {
  if (milliseconds === 0) return Promise.resolve();
  if (signal?.aborted) {
    const error = new Error("Aborted");
    error.name = "AbortError";
    return Promise.reject(error);
  }
  const settled = Promise.withResolvers();
  const handleAbort = () => {
    clearTimeout(timer);
    const error = new Error("Aborted");
    error.name = "AbortError";
    settled.reject(error);
  };
  const timer = setTimeout(() => {
    signal?.removeEventListener("abort", handleAbort);
    settled.resolve();
  }, milliseconds);
  signal?.addEventListener("abort", handleAbort, { once: true });
  return settled.promise;
}
