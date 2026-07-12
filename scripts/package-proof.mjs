#!/usr/bin/env node
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";
import { canonical, signObject } from "../asp-core.mjs";
import { loadManagedAgent } from "../managed-key-runtime.mjs";

const execFileAsync = promisify(execFile);
const outDir = "state/package-proof";

async function loadConfiguredSigner() {
  const configPath = process.env.AGNET_PACKAGE_PROOF_SIGNER_CONFIG;
  if (typeof configPath !== "string" || configPath.length === 0 || configPath.includes("\0")) throw new Error("package proof managed signer config missing");
  let config;
  try {
    config = JSON.parse(await readFile(configPath, "utf8"));
  } catch (error) {
    if (error instanceof SyntaxError) throw new Error("package proof managed signer config invalid");
    throw error;
  }
  if (config === null || typeof config !== "object" || Array.isArray(config)) throw new Error("package proof managed signer config invalid");
  return loadManagedAgent(config);
}
const signer = await loadConfiguredSigner();

await mkdir(outDir, { recursive: true });
const { stdout } = await execFileAsync("npm", ["pack", "--json", "--pack-destination", outDir]);
const [packed] = JSON.parse(stdout);
const tarballPath = join(outDir, packed.filename);
const manifestPath = join(outDir, "package-proof.json");

const proofBody = {
  package_proof: "ok",
  signer: signer.descriptor,
  name: packed.name,
  version: packed.version,
  filename: packed.filename,
  tarball: packed.filename,
  manifest: "package-proof.json",
  size: packed.size,
  unpacked_size: packed.unpackedSize,
  shasum: packed.shasum,
  integrity: packed.integrity,
  sha256: createHash("sha256").update(await readFile(tarballPath)).digest("hex"),
  files: packed.files.map(({ path }) => path),
};
const proof = {
  ...proofBody,
  proof_digest: createHash("sha256").update(canonical(proofBody)).digest("hex"),
  signature: signObject(signer.privateKey, proofBody),
};

await writeFile(manifestPath, `${JSON.stringify(proof, null, 2)}\n`);
console.log(JSON.stringify(proof));
