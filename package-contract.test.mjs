import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile, rm, stat, writeFile } from "node:fs/promises";
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
  const tarball = await stat(proof.tarball);

  assert.equal(proof.package_proof, "ok");
  assert.equal(proof.name, "agnet");
  assert.equal(proof.version, "0.0.0");
  assert.equal(proof.filename, "agnet-0.0.0.tgz");
  assert.equal(proof.tarball, "state/package-proof/agnet-0.0.0.tgz");
  assert.match(proof.shasum, /^[a-f0-9]{40}$/);
  assert.match(proof.integrity, /^sha512-/);
  assert.match(proof.sha256, /^[a-f0-9]{64}$/);
  assert.equal(proof.sha256, createHash("sha256").update(await readFile(proof.tarball)).digest("hex"));
  assert.equal(tarball.size, proof.size);
  assert.deepEqual(proof.files, ["README.md", "asp-core.mjs", "asp-verify.mjs", "package.json"]);
});
