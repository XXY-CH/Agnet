import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { test } from "node:test";
import { promisify } from "node:util";
import { canonical } from "./asp-core.mjs";

const execFileAsync = promisify(execFile);

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
  const { proof_digest, ...proofBody } = proof;
  assert.equal(proof_digest, createHash("sha256").update(canonical(proofBody)).digest("hex"));
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
  const tarball = "agnet-relative.tgz";
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
  };
  const proof = {
    ...proofBody,
    proof_digest: createHash("sha256").update(canonical(proofBody)).digest("hex"),
  };
  await writeFile("state/package-proof-relative/package-proof.json", `${JSON.stringify(proof, null, 2)}\n`);

  const verified = JSON.parse((await execFileAsync(process.execPath, ["asp-verify.mjs", "package-proof", "state/package-proof-relative/package-proof.json"])).stdout);
  assert.equal(verified.package_proof_verify, "ok");
  assert.equal(verified.tarball, tarball);
});

test("package proof verifier rejects npm digest mismatches", async () => {
  await rm("state/package-proof", { recursive: true, force: true });
  await execFileAsync(process.execPath, ["scripts/package-proof.mjs"]);
  const proof = JSON.parse(await readFile("state/package-proof/package-proof.json", "utf8"));
  const writeMutatedProof = async (path, patch) => {
    const proofBody = { ...proof, ...patch };
    delete proofBody.proof_digest;
    await writeFile(path, `${JSON.stringify({ ...proofBody, proof_digest: createHash("sha256").update(canonical(proofBody)).digest("hex") }, null, 2)}\n`);
  };
  await writeMutatedProof("state/package-proof/shasum-mismatch.json", { shasum: "0".repeat(40) });
  await writeMutatedProof("state/package-proof/integrity-mismatch.json", { integrity: "sha512-invalid" });

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
  const proofBody = { ...proof, filename: "not-the-tarball.tgz" };
  delete proofBody.proof_digest;
  await writeFile("state/package-proof/filename-mismatch.json", `${JSON.stringify({ ...proofBody, proof_digest: createHash("sha256").update(canonical(proofBody)).digest("hex") }, null, 2)}\n`);

  await assert.rejects(
    () => execFileAsync(process.execPath, ["asp-verify.mjs", "package-proof", "state/package-proof/filename-mismatch.json"]),
    (error) => error.stderr.includes("bundle filename mismatch"),
  );
});
