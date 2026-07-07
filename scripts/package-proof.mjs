#!/usr/bin/env node
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";
import { canonical, loadOrCreateAgent, signObject } from "../asp-core.mjs";

const execFileAsync = promisify(execFile);
const outDir = "state/package-proof";

await mkdir(outDir, { recursive: true });
const { stdout } = await execFileAsync("npm", ["pack", "--json", "--pack-destination", outDir]);
const [packed] = JSON.parse(stdout);
const tarballPath = join(outDir, packed.filename);
const manifestPath = join(outDir, "package-proof.json");
const signer = await loadOrCreateAgent("agent://package-proof/signer", "state/keys/package-proof-signer.pkcs8", {}, ["asp+local://package-proof"], ["package.proof.sign"]);

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
