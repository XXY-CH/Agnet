#!/usr/bin/env node
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { basename, join } from "node:path";
import { promisify } from "node:util";
import { canonical, loadOrCreateAgent, signObject } from "../asp-core.mjs";

const execFileAsync = promisify(execFile);
const outDir = "state/package-proof";
const packageProofPath = join(outDir, "package-proof.json");
const manifestPath = join(outDir, "release-trust.json");

try {
  await readFile(packageProofPath, "utf8");
} catch (error) {
  if (error && error.code === "ENOENT") throw new Error("package proof missing; run scripts/package-proof.mjs first");
  throw error;
}

await execFileAsync("node", ["asp-verify.mjs", "package-proof", packageProofPath]);
const packageProof = JSON.parse(await readFile(packageProofPath, "utf8"));
const signer = await loadOrCreateAgent("agent://release-trust/signer", "state/keys/release-trust-signer.pkcs8", {}, ["asp+local://release-trust"], ["release.trust.sign"]);

const trustBody = {
  release_trust: "ok",
  format: "asp-release-trust/v1",
  signer: signer.descriptor,
  name: packageProof.name,
  version: packageProof.version,
  filename: packageProof.filename,
  tarball: packageProof.tarball,
  package_proof: basename(packageProofPath),
  package_proof_digest: packageProof.proof_digest,
  sha256: packageProof.sha256,
  size: packageProof.size,
  files: packageProof.files,
  released_at: new Date().toISOString(),
};
const trust = {
  ...trustBody,
  trust_digest: createHash("sha256").update(canonical(trustBody)).digest("hex"),
  signature: signObject(signer.privateKey, trustBody),
};

await writeFile(manifestPath, `${JSON.stringify(trust, null, 2)}\n`);
console.log(JSON.stringify(trust));
