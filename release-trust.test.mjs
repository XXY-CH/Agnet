import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile, rm, writeFile } from "node:fs/promises";
import { test } from "node:test";
import { promisify } from "node:util";
import { canonical, loadOrCreateAgent, signObject } from "./asp-core.mjs";

const execFileAsync = promisify(execFile);
const releaseTrustPath = "state/package-proof/release-trust.json";
let releaseTrustPromise;

function produceReleaseTrustOnce() {
  releaseTrustPromise ??= (async () => {
    await rm("state/package-proof", { recursive: true, force: true });
    await execFileAsync(process.execPath, ["scripts/package-proof.mjs"]);
    const { stdout } = await execFileAsync(process.execPath, ["scripts/release-trust.mjs"]);
    return JSON.parse(stdout);
  })();
  return releaseTrustPromise;
}

async function readReleaseTrust() {
  await produceReleaseTrustOnce();
  return JSON.parse(await readFile(releaseTrustPath, "utf8"));
}

async function writeMutatedReleaseTrust(path, proof, patch) {
  const proofBody = { ...proof, ...patch };
  await writeFile(path, `${JSON.stringify(await signReleaseTrustBody(proofBody), null, 2)}\n`);
}

async function signReleaseTrustBody(proofBody) {
  const signer = await loadOrCreateAgent("agent://release-trust/signer", "state/keys/release-trust-signer.pkcs8", {}, ["asp+local://release-trust"], ["release.trust.sign"]);
  return signReleaseTrustBodyWithSigner(proofBody, signer);
}

function signReleaseTrustBodyWithSigner(proofBody, signer) {
  const { trust_digest, signature, ...body } = proofBody;
  const signedBody = { ...body, signer: signer.descriptor };
  return {
    ...signedBody,
    trust_digest: createHash("sha256").update(canonical(signedBody)).digest("hex"),
    signature: signObject(signer.privateKey, signedBody),
  };
}

function rejectsWithMessage(args, message) {
  return assert.rejects(
    () => execFileAsync(process.execPath, args),
    (error) => error.stderr.includes(message),
  );
}

test("release trust producer creates and verifier accepts bound release evidence", async () => {
  const proof = await produceReleaseTrustOnce();
  const manifest = JSON.parse(await readFile(releaseTrustPath, "utf8"));
  const verified = JSON.parse((await execFileAsync(process.execPath, ["asp-verify.mjs", "release-trust", releaseTrustPath])).stdout);

  assert.equal(proof.release_trust, "ok");
  assert.equal(proof.format, "asp-release-trust/v1");
  assert.equal(proof.name, "agnet");
  assert.equal(proof.version, "0.0.0");
  assert.equal(proof.filename, "agnet-0.0.0.tgz");
  assert.equal(proof.tarball, "agnet-0.0.0.tgz");
  assert.equal(proof.package_proof, "package-proof.json");
  assert.match(proof.package_proof_digest, /^[a-f0-9]{64}$/);
  assert.match(proof.trust_digest, /^[a-f0-9]{64}$/);
  assert.equal(proof.signer.alias, "agent://release-trust/signer");
  assert.equal(proof.signer.capabilities.includes("release.trust.sign"), true);
  assert.deepEqual(manifest, proof);
  assert.equal(verified.release_trust_verify, "ok");
  assert.equal(verified.name, proof.name);
  assert.equal(verified.version, proof.version);
  assert.equal(verified.filename, proof.filename);
  assert.equal(verified.tarball, proof.tarball);
  assert.equal(verified.size, proof.size);
  assert.equal(verified.sha256, proof.sha256);
  assert.equal(verified.package_proof, proof.package_proof);
  assert.equal(verified.package_proof_digest, proof.package_proof_digest);
  assert.equal(verified.trust_digest, proof.trust_digest);
  assert.equal(verified.released_at, proof.released_at);
  assert.equal(verified.signer_aid, proof.signer.aid);
});

test("release trust verifier accepts pinned trusted release signers", async () => {
  const proof = await readReleaseTrust();
  await writeFile("state/package-proof/trusted-release-signers.json", `${JSON.stringify({ signers: [proof.signer] }, null, 2)}\n`);

  const verified = JSON.parse((await execFileAsync(process.execPath, ["asp-verify.mjs", "release-trust", releaseTrustPath, "state/package-proof/trusted-release-signers.json"])).stdout);

  assert.equal(verified.release_trust_verify, "ok");
  assert.equal(verified.signer_aid, proof.signer.aid);
  assert.equal(verified.signer_trusted, true);
});

test("release trust verifier rejects non-object manifests", async () => {
  await writeFile("state/release-trust-null.json", "null\n");
  await writeFile("state/release-trust-array.json", "[]\n");

  await rejectsWithMessage(["asp-verify.mjs", "release-trust", "state/release-trust-null.json"], "release trust manifest invalid");
  await rejectsWithMessage(["asp-verify.mjs", "release-trust", "state/release-trust-array.json"], "release trust manifest invalid");
});

test("release trust verifier rejects release_trust and format mismatches", async () => {
  const proof = await readReleaseTrust();
  await writeMutatedReleaseTrust("state/package-proof/release-trust-marker-mismatch.json", proof, { release_trust: "no" });
  await writeMutatedReleaseTrust("state/package-proof/release-trust-format-mismatch.json", proof, { format: "spdx" });

  await rejectsWithMessage(["asp-verify.mjs", "release-trust", "state/package-proof/release-trust-marker-mismatch.json"], "bundle release_trust mismatch");
  await rejectsWithMessage(["asp-verify.mjs", "release-trust", "state/package-proof/release-trust-format-mismatch.json"], "bundle format mismatch");
});

test("release trust verifier rejects unsafe package proof and tarball paths", async () => {
  const proof = await readReleaseTrust();
  await writeMutatedReleaseTrust("state/package-proof/release-trust-package-proof-escape.json", proof, { package_proof: "../x.json" });
  await writeMutatedReleaseTrust("state/package-proof/release-trust-tarball-escape.json", proof, { tarball: "../x.tgz" });

  await rejectsWithMessage(["asp-verify.mjs", "release-trust", "state/package-proof/release-trust-package-proof-escape.json"], "release trust package_proof path invalid");
  await rejectsWithMessage(["asp-verify.mjs", "release-trust", "state/package-proof/release-trust-tarball-escape.json"], "release trust tarball path invalid");
});

test("release trust verifier rejects stale package proof evidence", async () => {
  const proof = await readReleaseTrust();
  await writeMutatedReleaseTrust("state/package-proof/release-trust-stale.json", proof, { package_proof_digest: "0".repeat(64) });

  await rejectsWithMessage(["asp-verify.mjs", "release-trust", "state/package-proof/release-trust-stale.json"], "release trust evidence stale");
});

test("release trust verifier rejects package proof binding mismatches", async () => {
  const proof = await readReleaseTrust();
  await writeMutatedReleaseTrust("state/package-proof/release-trust-name-mismatch.json", proof, { name: "not-agnet" });
  await writeMutatedReleaseTrust("state/package-proof/release-trust-version-mismatch.json", proof, { version: "9.9.9" });
  await writeMutatedReleaseTrust("state/package-proof/release-trust-files-mismatch.json", proof, { files: proof.files.slice(1) });
  await writeMutatedReleaseTrust("state/package-proof/release-trust-sha256-mismatch.json", proof, { sha256: "0".repeat(64) });

  await rejectsWithMessage(["asp-verify.mjs", "release-trust", "state/package-proof/release-trust-name-mismatch.json"], "bundle name mismatch");
  await rejectsWithMessage(["asp-verify.mjs", "release-trust", "state/package-proof/release-trust-version-mismatch.json"], "bundle version mismatch");
  await rejectsWithMessage(["asp-verify.mjs", "release-trust", "state/package-proof/release-trust-files-mismatch.json"], "bundle files mismatch");
  await rejectsWithMessage(["asp-verify.mjs", "release-trust", "state/package-proof/release-trust-sha256-mismatch.json"], "bundle sha256 mismatch");
});

test("release trust verifier rejects invalid released_at timestamps", async () => {
  const proof = await readReleaseTrust();
  const { released_at, ...missingReleasedAt } = proof;
  await writeMutatedReleaseTrust("state/package-proof/release-trust-future-released-at.json", proof, { released_at: new Date(Date.now() + 6 * 60 * 1000).toISOString() });
  await writeMutatedReleaseTrust("state/package-proof/release-trust-rfc2822-released-at.json", proof, { released_at: new Date().toUTCString() });
  await writeFile("state/package-proof/release-trust-missing-released-at.json", `${JSON.stringify(await signReleaseTrustBody(missingReleasedAt), null, 2)}\n`);

  await rejectsWithMessage(["asp-verify.mjs", "release-trust", "state/package-proof/release-trust-future-released-at.json"], "release trust released_at invalid");
  await rejectsWithMessage(["asp-verify.mjs", "release-trust", "state/package-proof/release-trust-rfc2822-released-at.json"], "release trust released_at invalid");
  await rejectsWithMessage(["asp-verify.mjs", "release-trust", "state/package-proof/release-trust-missing-released-at.json"], "release trust released_at invalid");
});

test("release trust verifier rejects invalid ASP signatures", async () => {
  const proof = await readReleaseTrust();
  const missing = await signReleaseTrustBody(proof);
  delete missing.signature;
  await writeFile("state/package-proof/release-trust-signature-missing.json", `${JSON.stringify(missing, null, 2)}\n`);
  const invalid = await signReleaseTrustBody(proof);
  invalid.signature = "bad";
  await writeFile("state/package-proof/release-trust-signature-invalid.json", `${JSON.stringify(invalid, null, 2)}\n`);

  await rejectsWithMessage(["asp-verify.mjs", "release-trust", "state/package-proof/release-trust-signature-missing.json"], "release trust signature missing");
  await rejectsWithMessage(["asp-verify.mjs", "release-trust", "state/package-proof/release-trust-signature-invalid.json"], "release trust signature invalid");
});

test("release trust verifier rejects signers without release trust capability", async () => {
  const proof = await readReleaseTrust();
  const signer = await loadOrCreateAgent("agent://release-trust/no-capability", "state/keys/release-trust-no-capability.pkcs8", {}, ["asp+local://release-trust"], []);
  const noCapabilityProof = signReleaseTrustBodyWithSigner(proof, signer);
  await writeFile("state/package-proof/release-trust-signer-capability-missing.json", `${JSON.stringify(noCapabilityProof, null, 2)}\n`);

  await rejectsWithMessage(["asp-verify.mjs", "release-trust", "state/package-proof/release-trust-signer-capability-missing.json"], "release trust signer capability missing");
});

test("release trust verifier rejects untrusted release signers", async () => {
  const proof = await readReleaseTrust();
  const other = await loadOrCreateAgent("agent://release-trust/other-signer", "state/keys/release-trust-other-signer.pkcs8", {}, ["asp+local://release-trust"], ["release.trust.sign"]);
  await writeFile("state/package-proof/untrusted-release-signers.json", `${JSON.stringify({ signers: [other.descriptor] }, null, 2)}\n`);

  await rejectsWithMessage(["asp-verify.mjs", "release-trust", releaseTrustPath, "state/package-proof/untrusted-release-signers.json"], "release trust signer untrusted");
});

test("release trust verifier rejects null trusted release signer lists", async () => {
  await readReleaseTrust();
  await writeFile("state/package-proof/null-trusted-release-signers.json", "null\n");

  await rejectsWithMessage(["asp-verify.mjs", "release-trust", releaseTrustPath, "state/package-proof/null-trusted-release-signers.json"], "trusted release signer list missing");
});

test("release trust verifier rejects extra positional arguments", async () => {
  await readReleaseTrust();

  await rejectsWithMessage(["asp-verify.mjs", "release-trust", releaseTrustPath, "state/package-proof/trusted-release-signers.json", "extra"], "usage: node asp-verify.mjs");
});
