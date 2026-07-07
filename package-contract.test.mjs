import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { test } from "node:test";
import { promisify } from "node:util";
import { canonical, loadOrCreateAgent, publicKeyFromDescriptor, signObject, verifyObject } from "./asp-core.mjs";

const execFileAsync = promisify(execFile);

async function writeMutatedPackageProof(path, proof, patch) {
  const proofBody = { ...proof, ...patch, manifest: path.split("/").at(-1) };
  await writeFile(path, `${JSON.stringify(await signPackageProofBody(proofBody), null, 2)}\n`);
}

async function signPackageProofBody(proofBody) {
  const signer = await loadOrCreateAgent("agent://package-proof/signer", "state/keys/package-proof-signer.pkcs8", {}, ["asp+local://package-proof"], ["package.proof.sign"]);
  const { proof_digest, signature, ...body } = proofBody;
  const signedBody = { ...body, signer: signer.descriptor };
  return {
    ...signedBody,
    proof_digest: createHash("sha256").update(canonical(signedBody)).digest("hex"),
    signature: signObject(signer.privateKey, signedBody),
  };
}

test("npm package exposes the existing verifier CLI and core exports", async () => {
  const pkg = JSON.parse(await readFile("package.json", "utf8"));
  assert.equal(pkg.name, "agnet");
  assert.equal(pkg.type, "module");
  assert.equal(pkg.license, "UNLICENSED");
  assert.equal(pkg.bin["asp-verify"], "./asp-verify.mjs");
  assert.equal(pkg.exports["."], "./asp-core.mjs");
  assert.deepEqual(pkg.files, ["asp-core.mjs", "asp-verify.mjs", "README.md"]);

  const vector = JSON.parse(await readFile("test-vectors/asp-v9.25-fed-receipt.json", "utf8"));
  const framePath = "state/npm-fed-receipt-frame.json";
  const trustedPath = "state/npm-fed-receipt-trusted.json";
  await writeFile(framePath, `${JSON.stringify(vector.frame, null, 2)}\n`);
  await writeFile(trustedPath, `${JSON.stringify({ zones: vector.trusted_zones }, null, 2)}\n`);

  const { stdout } = await execFileAsync("npm", ["exec", "--package", ".", "--", "asp-verify", "fed-receipt", framePath, trustedPath]);
  const { signature, ...receipt } = vector.frame.receipt;
  assert.deepEqual(JSON.parse(stdout), {
    fed_receipt_verify: "ok",
    task_id: vector.expected.task_id,
    receipt_digest: createHash("sha256").update(canonical(receipt)).digest("hex"),
  });
});

test("package proof creates an npm tarball artifact", async () => {
  await rm("state/package-proof", { recursive: true, force: true });
  const { stdout } = await execFileAsync(process.execPath, ["scripts/package-proof.mjs"]);
  const proof = JSON.parse(stdout);
  const tarballPath = `state/package-proof/${proof.tarball}`;
  const manifestPath = `state/package-proof/${proof.manifest}`;
  const tarball = await stat(tarballPath);

  assert.equal(proof.package_proof, "ok");
  assert.equal(proof.name, "agnet");
  assert.equal(proof.version, "0.0.0");
  assert.equal(proof.filename, "agnet-0.0.0.tgz");
  assert.equal(proof.tarball, "agnet-0.0.0.tgz");
  assert.equal(proof.manifest, "package-proof.json");
  assert.match(proof.shasum, /^[a-f0-9]{40}$/);
  assert.match(proof.integrity, /^sha512-/);
  assert.match(proof.sha256, /^[a-f0-9]{64}$/);
  assert.equal(proof.sha256, createHash("sha256").update(await readFile(tarballPath)).digest("hex"));
  assert.match(proof.proof_digest, /^[a-f0-9]{64}$/);
  assert.equal(proof.signer.alias, "agent://package-proof/signer");
  assert.equal(proof.signer.capabilities.includes("package.proof.sign"), true);
  assert.match(proof.signature, /^[A-Za-z0-9_-]+$/);
  const { proof_digest, signature, ...proofBody } = proof;
  assert.equal(proof_digest, createHash("sha256").update(canonical(proofBody)).digest("hex"));
  assert.equal(verifyObject(publicKeyFromDescriptor(proof.signer), proofBody, signature), true);
  assert.equal(tarball.size, proof.size);
  assert.deepEqual(proof.files, ["README.md", "asp-core.mjs", "asp-verify.mjs", "package.json"]);
  assert.deepEqual(JSON.parse(await readFile(manifestPath, "utf8")), proof);

  const verified = JSON.parse((await execFileAsync(process.execPath, ["asp-verify.mjs", "package-proof", manifestPath])).stdout);
  assert.deepEqual(verified, {
    package_proof_verify: "ok",
    name: proof.name,
    version: proof.version,
    filename: proof.filename,
    tarball: proof.tarball,
    size: proof.size,
    shasum: proof.shasum,
    integrity: proof.integrity,
    sha256: proof.sha256,
    proof_digest: proof.proof_digest,
    signer_aid: proof.signer.aid,
  });
});

test("package proof verifier rejects non-object manifests", async () => {
  await writeFile("state/package-proof-null.json", "null\n");
  await writeFile("state/package-proof-array.json", "[]\n");

  await assert.rejects(
    () => execFileAsync(process.execPath, ["asp-verify.mjs", "package-proof", "state/package-proof-null.json"]),
    (error) => error.stderr.includes("package proof manifest invalid"),
  );
  await assert.rejects(
    () => execFileAsync(process.execPath, ["asp-verify.mjs", "package-proof", "state/package-proof-array.json"]),
    (error) => error.stderr.includes("package proof manifest invalid"),
  );
});

test("package proof verifier rejects unsafe tarball paths", async () => {
  await writeFile("state/package-proof-absolute.json", JSON.stringify({ package_proof: "ok", tarball: "/tmp/agnet.tgz" }));
  await writeFile("state/package-proof-escape.json", JSON.stringify({ package_proof: "ok", tarball: "../agnet.tgz" }));

  await assert.rejects(
    () => execFileAsync(process.execPath, ["asp-verify.mjs", "package-proof", "state/package-proof-absolute.json"]),
    (error) => error.stderr.includes("package proof tarball path invalid"),
  );
  await assert.rejects(
    () => execFileAsync(process.execPath, ["asp-verify.mjs", "package-proof", "state/package-proof-escape.json"]),
    (error) => error.stderr.includes("package proof tarball path invalid"),
  );
});

test("package proof verifier resolves tarball relative to manifest", async () => {
  await mkdir("state/package-proof-relative", { recursive: true });
  const tarball = "agnet-0.0.0.tgz";
  const tarballBytes = Buffer.from("package bytes\n");
  await writeFile(`state/package-proof-relative/${tarball}`, tarballBytes);
  const proofBody = {
    package_proof: "ok",
    name: "agnet",
    version: "0.0.0",
    filename: tarball,
    tarball,
    manifest: "package-proof.json",
    size: tarballBytes.length,
    shasum: createHash("sha1").update(tarballBytes).digest("hex"),
    integrity: `sha512-${createHash("sha512").update(tarballBytes).digest("base64")}`,
    sha256: createHash("sha256").update(tarballBytes).digest("hex"),
    files: ["README.md"],
  };
  const proof = await signPackageProofBody(proofBody);
  await writeFile("state/package-proof-relative/package-proof.json", `${JSON.stringify(proof, null, 2)}\n`);

  const verified = JSON.parse((await execFileAsync(process.execPath, ["asp-verify.mjs", "package-proof", "state/package-proof-relative/package-proof.json"])).stdout);
  assert.equal(verified.package_proof_verify, "ok");
  assert.equal(verified.tarball, tarball);
});

test("package proof verifier rejects invalid ASP signatures", async () => {
  await rm("state/package-proof", { recursive: true, force: true });
  await execFileAsync(process.execPath, ["scripts/package-proof.mjs"]);
  const proof = JSON.parse(await readFile("state/package-proof/package-proof.json", "utf8"));
  const missing = await signPackageProofBody({ ...proof, manifest: "signature-missing.json" });
  delete missing.signature;
  await writeFile("state/package-proof/signature-missing.json", `${JSON.stringify(missing, null, 2)}\n`);
  await writeMutatedPackageProof("state/package-proof/signature-invalid.json", proof, {});
  const invalid = JSON.parse(await readFile("state/package-proof/signature-invalid.json", "utf8"));
  invalid.signature = "invalid";
  await writeFile("state/package-proof/signature-invalid.json", `${JSON.stringify(invalid, null, 2)}\n`);

  await assert.rejects(
    () => execFileAsync(process.execPath, ["asp-verify.mjs", "package-proof", "state/package-proof/signature-missing.json"]),
    (error) => error.stderr.includes("package proof signature missing"),
  );
  await assert.rejects(
    () => execFileAsync(process.execPath, ["asp-verify.mjs", "package-proof", "state/package-proof/signature-invalid.json"]),
    (error) => error.stderr.includes("package proof signature invalid"),
  );
});

test("package proof verifier accepts trusted package signers", async () => {
  await rm("state/package-proof", { recursive: true, force: true });
  await execFileAsync(process.execPath, ["scripts/package-proof.mjs"]);
  const proof = JSON.parse(await readFile("state/package-proof/package-proof.json", "utf8"));
  await writeFile("state/package-proof/trusted-signers.json", `${JSON.stringify({ signers: [proof.signer] }, null, 2)}\n`);

  const verified = JSON.parse((await execFileAsync(process.execPath, ["asp-verify.mjs", "package-proof", "state/package-proof/package-proof.json", "state/package-proof/trusted-signers.json"])).stdout);

  assert.equal(verified.package_proof_verify, "ok");
  assert.equal(verified.signer_aid, proof.signer.aid);
  assert.equal(verified.signer_trusted, true);

  await writeFile("state/package-proof/trusted-signers-array.json", `${JSON.stringify([proof.signer], null, 2)}\n`);
  const rawArrayVerified = JSON.parse((await execFileAsync(process.execPath, ["asp-verify.mjs", "package-proof", "state/package-proof/package-proof.json", "state/package-proof/trusted-signers-array.json"])).stdout);
  assert.equal(rawArrayVerified.signer_trusted, true);
});

test("package proof verifier rejects untrusted package signers", async () => {
  await rm("state/package-proof", { recursive: true, force: true });
  await execFileAsync(process.execPath, ["scripts/package-proof.mjs"]);
  const other = await loadOrCreateAgent("agent://package-proof/other-signer", "state/keys/package-proof-other-signer.pkcs8", {}, ["asp+local://package-proof"], ["package.proof.sign"]);
  await writeFile("state/package-proof/untrusted-signers.json", `${JSON.stringify({ signers: [other.descriptor] }, null, 2)}\n`);

  await assert.rejects(
    () => execFileAsync(process.execPath, ["asp-verify.mjs", "package-proof", "state/package-proof/package-proof.json", "state/package-proof/untrusted-signers.json"]),
    (error) => error.stderr.includes("package proof signer untrusted"),
  );
});

test("package proof verifier rejects null trusted package signer lists", async () => {
  await rm("state/package-proof", { recursive: true, force: true });
  await execFileAsync(process.execPath, ["scripts/package-proof.mjs"]);
  await writeFile("state/package-proof/null-trusted-signers.json", "null\n");

  await assert.rejects(
    () => execFileAsync(process.execPath, ["asp-verify.mjs", "package-proof", "state/package-proof/package-proof.json", "state/package-proof/null-trusted-signers.json"]),
    (error) => error.stderr.includes("trusted package signer list missing"),
  );
});

test("package proof verifier rejects npm digest mismatches", async () => {
  await rm("state/package-proof", { recursive: true, force: true });
  await execFileAsync(process.execPath, ["scripts/package-proof.mjs"]);
  const proof = JSON.parse(await readFile("state/package-proof/package-proof.json", "utf8"));
  await writeMutatedPackageProof("state/package-proof/shasum-mismatch.json", proof, { shasum: "0".repeat(40) });
  await writeMutatedPackageProof("state/package-proof/integrity-mismatch.json", proof, { integrity: "sha512-invalid" });

  await assert.rejects(
    () => execFileAsync(process.execPath, ["asp-verify.mjs", "package-proof", "state/package-proof/shasum-mismatch.json"]),
    (error) => error.stderr.includes("bundle shasum mismatch"),
  );
  await assert.rejects(
    () => execFileAsync(process.execPath, ["asp-verify.mjs", "package-proof", "state/package-proof/integrity-mismatch.json"]),
    (error) => error.stderr.includes("bundle integrity mismatch"),
  );
});

test("package proof verifier rejects filename and tarball mismatch", async () => {
  await rm("state/package-proof", { recursive: true, force: true });
  await execFileAsync(process.execPath, ["scripts/package-proof.mjs"]);
  const proof = JSON.parse(await readFile("state/package-proof/package-proof.json", "utf8"));
  await writeMutatedPackageProof("state/package-proof/filename-mismatch.json", proof, { filename: "not-the-tarball.tgz" });

  await assert.rejects(
    () => execFileAsync(process.execPath, ["asp-verify.mjs", "package-proof", "state/package-proof/filename-mismatch.json"]),
    (error) => error.stderr.includes("bundle filename mismatch"),
  );
});

test("package proof verifier rejects malformed packaged file lists", async () => {
  await rm("state/package-proof", { recursive: true, force: true });
  await execFileAsync(process.execPath, ["scripts/package-proof.mjs"]);
  const proof = JSON.parse(await readFile("state/package-proof/package-proof.json", "utf8"));
  await writeMutatedPackageProof("state/package-proof/files-not-array.json", proof, { files: "README.md" });
  await writeMutatedPackageProof("state/package-proof/files-escape.json", proof, { files: ["../README.md"] });

  await assert.rejects(
    () => execFileAsync(process.execPath, ["asp-verify.mjs", "package-proof", "state/package-proof/files-not-array.json"]),
    (error) => error.stderr.includes("package proof files invalid"),
  );
  await assert.rejects(
    () => execFileAsync(process.execPath, ["asp-verify.mjs", "package-proof", "state/package-proof/files-escape.json"]),
    (error) => error.stderr.includes("package proof files invalid"),
  );
});

test("package proof verifier rejects malformed file lists before tarball reads", async () => {
  await rm("state/package-proof", { recursive: true, force: true });
  await execFileAsync(process.execPath, ["scripts/package-proof.mjs"]);
  const proof = JSON.parse(await readFile("state/package-proof/package-proof.json", "utf8"));
  await writeMutatedPackageProof("state/package-proof/files-invalid-missing-tarball.json", proof, { files: ["../README.md"] });
  await rm(`state/package-proof/${proof.tarball}`);

  await assert.rejects(
    () => execFileAsync(process.execPath, ["asp-verify.mjs", "package-proof", "state/package-proof/files-invalid-missing-tarball.json"]),
    (error) => error.stderr.includes("package proof files invalid"),
  );
});

test("package proof verifier rejects manifest filename mismatches", async () => {
  await rm("state/package-proof", { recursive: true, force: true });
  await execFileAsync(process.execPath, ["scripts/package-proof.mjs"]);
  const proof = JSON.parse(await readFile("state/package-proof/package-proof.json", "utf8"));
  await writeFile("state/package-proof/manifest-mismatch.json", `${JSON.stringify(await signPackageProofBody({ ...proof, manifest: "not-this-file.json" }), null, 2)}\n`);

  await assert.rejects(
    () => execFileAsync(process.execPath, ["asp-verify.mjs", "package-proof", "state/package-proof/manifest-mismatch.json"]),
    (error) => error.stderr.includes("bundle manifest mismatch"),
  );
});

test("package proof verifier rejects package identity and filename mismatches", async () => {
  await rm("state/package-proof", { recursive: true, force: true });
  await execFileAsync(process.execPath, ["scripts/package-proof.mjs"]);
  const proof = JSON.parse(await readFile("state/package-proof/package-proof.json", "utf8"));
  await writeMutatedPackageProof("state/package-proof/package-identity-mismatch.json", proof, { name: "not-agnet" });

  await assert.rejects(
    () => execFileAsync(process.execPath, ["asp-verify.mjs", "package-proof", "state/package-proof/package-identity-mismatch.json"]),
    (error) => error.stderr.includes("bundle package identity mismatch"),
  );
});
