import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { test } from "node:test";
import { promisify } from "node:util";
import { canonical, createAgent, createZone, signObject, zoneBinding } from "./asp-core.mjs";

const execFileAsync = promisify(execFile);

function receiptDigest(receipt) {
  const { signature, ...body } = receipt;
  return createHash("sha256").update(canonical(body)).digest("hex");
}

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
  return { frame, framePath, trustedPath, taskId };
}

async function writeSandboxAttestation(prefix, frame, mutate = (value) => value, trustedAttestor = null) {
  const attestor = trustedAttestor ?? createAgent("agent://sandbox/attestor", {}, ["asp+local://sandbox-attestation"], ["sandbox.attest"]);
  const body = mutate({
    attestation: "ok",
    format: "asp-sandbox-attestation/v1",
    receipt_digest: receiptDigest(frame.receipt),
    task_id: frame.receipt.task_id,
    sandbox_class: "remote-attestation",
    sandbox_digest: createHash("sha256").update(canonical(frame.receipt.sandbox)).digest("hex"),
    sandbox_claim: frame.receipt.sandbox_claim,
    policy_digest: frame.receipt.policy_digest,
    runtime_identity: "test-attested-runtime",
    observed_at: new Date().toISOString(),
    attestor: attestor.descriptor,
  });
  const evidence = {
    ...body,
    attestation_digest: createHash("sha256").update(canonical(body)).digest("hex"),
    signature: signObject(attestor.privateKey, body),
  };
  const dir = "state/sandbox-proof-test";
  await mkdir(dir, { recursive: true });
  const attestationPath = `${dir}/${prefix}-attestation.json`;
  const trustedAttestorsPath = `${dir}/${prefix}-trusted-attestors.json`;
  await writeFile(attestationPath, `${JSON.stringify(evidence, null, 2)}\n`);
  await writeFile(trustedAttestorsPath, `${JSON.stringify({ signers: [attestor.descriptor] }, null, 2)}\n`);
  return { attestationPath, trustedAttestorsPath, attestor };
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

test("sandbox attestation verifier accepts trusted signed evidence bound to receipt and sandbox", async () => {
  const { frame, framePath, trustedPath, taskId } = await writeSandboxReceipt("attested");
  const { attestationPath, trustedAttestorsPath, attestor } = await writeSandboxAttestation("attested", frame);

  const { stdout } = await execFileAsync(process.execPath, ["asp-verify.mjs", "sandbox-attestation", framePath, trustedPath, attestationPath, trustedAttestorsPath]);
  const verified = JSON.parse(stdout);

  assert.equal(verified.sandbox_attestation_verify, "ok");
  assert.equal(verified.task_id, taskId);
  assert.equal(verified.sandbox_class, "remote-attestation");
  assert.equal(verified.attestor_aid, attestor.aid);
  assert.equal(verified.hardware_attestation, false);
  assert.match(verified.attestation_digest, /^[0-9a-f]{64}$/);
});

test("sandbox attestation verifier rejects mismatched receipt digests", async () => {
  const { frame, framePath, trustedPath } = await writeSandboxReceipt("attestationmismatch");
  const { attestationPath, trustedAttestorsPath } = await writeSandboxAttestation("attestationmismatch", frame, (body) => ({
    ...body,
    receipt_digest: "0".repeat(64),
  }));

  await assert.rejects(
    execFileAsync(process.execPath, ["asp-verify.mjs", "sandbox-attestation", framePath, trustedPath, attestationPath, trustedAttestorsPath]),
    /sandbox attestation receipt_digest mismatch/,
  );
});

test("sandbox attestation verifier rejects mismatched sandbox digests", async () => {
  const { frame, framePath, trustedPath } = await writeSandboxReceipt("attestationsandboxmismatch");
  const { attestationPath, trustedAttestorsPath } = await writeSandboxAttestation("attestationsandboxmismatch", frame, (body) => ({
    ...body,
    sandbox_digest: "9".repeat(64),
  }));

  await assert.rejects(
    execFileAsync(process.execPath, ["asp-verify.mjs", "sandbox-attestation", framePath, trustedPath, attestationPath, trustedAttestorsPath]),
    /sandbox attestation sandbox_digest mismatch/,
  );
});

test("sandbox attestation verifier rejects untrusted attestors", async () => {
  const { frame, framePath, trustedPath } = await writeSandboxReceipt("attestoruntrusted");
  const { attestationPath, trustedAttestorsPath } = await writeSandboxAttestation("attestoruntrusted", frame);
  const other = createAgent("agent://sandbox/other-attestor", {}, ["asp+local://sandbox-attestation"], ["sandbox.attest"]);
  await writeFile(trustedAttestorsPath, `${JSON.stringify({ signers: [other.descriptor] }, null, 2)}\n`);

  await assert.rejects(
    execFileAsync(process.execPath, ["asp-verify.mjs", "sandbox-attestation", framePath, trustedPath, attestationPath, trustedAttestorsPath]),
    /sandbox attestation signer untrusted/,
  );
});

test("sandbox attestation verifier rejects attestors without sandbox attest capability", async () => {
  const { frame, framePath, trustedPath } = await writeSandboxReceipt("attestormissingcapability");
  const attestor = createAgent("agent://sandbox/no-cap-attestor", {}, ["asp+local://sandbox-attestation"], []);
  const { attestationPath, trustedAttestorsPath } = await writeSandboxAttestation("attestormissingcapability", frame, (body) => body, attestor);

  await assert.rejects(
    execFileAsync(process.execPath, ["asp-verify.mjs", "sandbox-attestation", framePath, trustedPath, attestationPath, trustedAttestorsPath]),
    /sandbox attestation signer capability missing/,
  );
});

test("sandbox attestation verifier rejects stale evidence", async () => {
  const { frame, framePath, trustedPath } = await writeSandboxReceipt("attestationstale");
  const { attestationPath, trustedAttestorsPath } = await writeSandboxAttestation("attestationstale", frame, (body) => ({
    ...body,
    observed_at: "2000-01-01T00:00:00Z",
  }));

  await assert.rejects(
    execFileAsync(process.execPath, ["asp-verify.mjs", "sandbox-attestation", framePath, trustedPath, attestationPath, trustedAttestorsPath]),
    /sandbox attestation stale/,
  );
});

test("sandbox attestation verifier rejects future-dated evidence", async () => {
  const { frame, framePath, trustedPath } = await writeSandboxReceipt("attestationfuture");
  const { attestationPath, trustedAttestorsPath } = await writeSandboxAttestation("attestationfuture", frame, (body) => ({
    ...body,
    observed_at: "2999-01-01T00:00:00Z",
  }));

  await assert.rejects(
    execFileAsync(process.execPath, ["asp-verify.mjs", "sandbox-attestation", framePath, trustedPath, attestationPath, trustedAttestorsPath]),
    /sandbox attestation observed_at invalid/,
  );
});

test("sandbox attestation verifier rejects invalid embedded sandbox proofs first", async () => {
  const { frame, framePath, trustedPath } = await writeSandboxReceipt("attestationbadproof", (receipt) => receipt, (draftFrame) => {
    draftFrame.receipt.sandbox_proof.task_id = "different_task";
  });
  const { attestationPath, trustedAttestorsPath } = await writeSandboxAttestation("attestationbadproof", frame);

  await assert.rejects(
    execFileAsync(process.execPath, ["asp-verify.mjs", "sandbox-attestation", framePath, trustedPath, attestationPath, trustedAttestorsPath]),
    /bundle sandbox task_id mismatch/,
  );
});
