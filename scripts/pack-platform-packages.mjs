import { mkdir, readFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const packageJSON = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
const output = fileURLToPath(new URL("../dist/packages", import.meta.url));
const targets = ["darwin-arm64", "darwin-x64", "linux-arm64", "linux-x64"];
await mkdir(output, { recursive: true });
for (const target of targets) {
  const directory = fileURLToPath(new URL(`../dist/platform/${target}`, import.meta.url));
  await run("npm", ["pack", directory, "--pack-destination", output, "--json"]);
}
console.log(`Packed Agnet ${packageJSON.version} platform packages in ${output}`);

function run(command, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: "inherit" });
    child.once("error", reject);
    child.once("exit", (code, signal) => {
      if (code === 0) resolve();
      else reject(new Error(`${command} failed with ${signal ?? `exit ${code}`}`));
    });
  });
}
