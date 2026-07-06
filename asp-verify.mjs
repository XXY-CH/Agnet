import { readFile } from "node:fs/promises";
import { verifyLocalArtifact } from "./asp-core.mjs";

const [command, file] = process.argv.slice(2);

try {
  if (command !== "artifact" || !file) {
    throw new Error("usage: node asp-verify.mjs artifact <manifest.json>");
  }
  const manifest = JSON.parse(await readFile(file, "utf8"));
  await verifyLocalArtifact(manifest);
  console.log(JSON.stringify({ artifact_verify: "ok", uri: manifest.uri }));
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
