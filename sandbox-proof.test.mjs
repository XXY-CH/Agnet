import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { test } from "node:test";
import { promisify } from "node:util";
import { canonical, createAgent, createZone, signObject, zoneBinding } from "./asp-core.mjs";

const execFileAsync = promisify(execFile);

async function writeSandboxReceipt(prefix, mutate = (value) => value, mutateBeforeReceiptSignature = () => {}) {
  const authority = createZone("sandbox-authority");
  const origin = createZone("sandbox-origin");
  const worker = createAgent("agent://sandbox/worker");
  const taskId = `${prefix}_task`;
  const sandbox = {
    mode: "local-temp-dir",
    isolation_level: "local-process",
    runtime: "go-fed-discovery",
    cwd: "state/sandbox-proof",
    network: "not_granted",
    mounts: [{ path: "state/sandbox-proof", access: "rw" }],
    tool_command_digest: "1".repeat(64),
    tool_binary_digest: "2".repeat(64),
    tool_transcript_digest: "3".repeat(64),
  };
  const receiptBody = mutate({
    task_id: taskId,
    task_digest: createHash("sha256").update(`${prefix}:task`).digest("hex"),
    origin_zone: origin.zid,
    executing_zone: authority.zid,
    to: worker.aid,
    status: "completed",
    policy_digest: "4".repeat(64),
    sandbox_claim: "local-temp-dir",
    sandbox,
  });
  const proofBody = {
    proof_type: "local.sandbox.v1",
    task_id: taskId,
    authority: authority.zid,
    worker: worker.aid,
    policy_digest: receiptBody.policy_digest,
    sandbox_claim: receiptBody.sandbox_claim,
    sandbox,
  };
  const frame = {
    type: "FED_RECEIPT",
    zone: authority.descriptor,
    worker: worker.descriptor,
    zone_binding: zoneBinding(authority, worker.descriptor),
    receipt: {
      ...receiptBody,
      sandbox_proof: { ...proofBody, sandbox_signature: signObject(authority.privateKey, proofBody) },
    },
  };
  mutateBeforeReceiptSignature(frame);
  frame.receipt.signature = signObject(worker.privateKey, frame.receipt);
  const dir = "state/sandbox-proof-test";
  await mkdir(dir, { recursive: true });
  const framePath = `${dir}/${prefix}-receipt.json`;
  const trustedPath = `${dir}/${prefix}-trusted-zones.json`;
  await writeFile(framePath, `${JSON.stringify(frame, null, 2)}\n`);
  await writeFile(trustedPath, `${JSON.stringify({ zones: [authority.descriptor, origin.descriptor] }, null, 2)}\n`);
  return { framePath, trustedPath, taskId };
}

test("sandbox proof verifier accepts signed local-process proof without upgrading it", async () => {
  const { framePath, trustedPath, taskId } = await writeSandboxReceipt("local");

  const { stdout } = await execFileAsync(process.execPath, ["asp-verify.mjs", "sandbox-proof", framePath, trustedPath]);
  const verified = JSON.parse(stdout);

  assert.equal(verified.sandbox_proof_verify, "ok");
  assert.equal(verified.task_id, taskId);
  assert.equal(verified.sandbox_claim, "local-temp-dir");
  assert.equal(verified.sandbox_class, "local-process");
  assert.equal(verified.remote_attestation, false);
  assert.match(verified.receipt_digest, /^[0-9a-f]{64}$/);
});

test("sandbox proof verifier refuses required remote attestation without signed attestation evidence", async () => {
  const { framePath, trustedPath } = await writeSandboxReceipt("remote");

  await assert.rejects(
    execFileAsync(process.execPath, ["asp-verify.mjs", "sandbox-proof", framePath, trustedPath, "remote-attestation"]),
    /sandbox class unavailable: remote-attestation/,
  );
});

test("sandbox proof verifier rejects proof not bound to receipt sandbox claim", async () => {
  const { framePath, trustedPath } = await writeSandboxReceipt("claimmismatch", (receipt) => receipt, (frame) => {
    frame.receipt.sandbox_claim = "container-namespace";
  });

  await assert.rejects(
    execFileAsync(process.execPath, ["asp-verify.mjs", "sandbox-proof", framePath, trustedPath]),
    /sandbox claim mismatch/,
  );
});

test("sandbox proof verifier rejects local proof without command and transcript digests", async () => {
  const { framePath, trustedPath } = await writeSandboxReceipt("missingdigest", (receipt) => {
    delete receipt.sandbox.tool_transcript_digest;
    return receipt;
  });

  await assert.rejects(
    execFileAsync(process.execPath, ["asp-verify.mjs", "sandbox-proof", framePath, trustedPath]),
    /sandbox evidence transcript digest missing/,
  );
});
