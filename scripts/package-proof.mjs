#!/usr/bin/env node
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const outDir = "state/package-proof";

await mkdir(outDir, { recursive: true });
const { stdout } = await execFileAsync("npm", ["pack", "--json", "--pack-destination", outDir]);
const [packed] = JSON.parse(stdout);
const tarball = join(outDir, packed.filename);
const manifest = join(outDir, "package-proof.json");

const proof = {
  package_proof: "ok",
  name: packed.name,
  version: packed.version,
  filename: packed.filename,
  tarball,
  manifest,
  size: packed.size,
  unpacked_size: packed.unpackedSize,
  shasum: packed.shasum,
  integrity: packed.integrity,
  sha256: createHash("sha256").update(await readFile(tarball)).digest("hex"),
  files: packed.files.map(({ path }) => path),
};

await writeFile(manifest, `${JSON.stringify(proof, null, 2)}\n`);
console.log(JSON.stringify(proof));
