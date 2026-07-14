import { chmod, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const dist = fileURLToPath(new URL("../dist", import.meta.url));
const packageJSON = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
const targets = [
  { os: "darwin", goos: "darwin", cpu: "arm64", goarch: "arm64", executable: "agnet-daemon" },
  { os: "darwin", goos: "darwin", cpu: "x64", goarch: "amd64", executable: "agnet-daemon" },
  { os: "linux", goos: "linux", cpu: "arm64", goarch: "arm64", executable: "agnet-daemon" },
  { os: "linux", goos: "linux", cpu: "x64", goarch: "amd64", executable: "agnet-daemon" },
];

await rm(dist, { recursive: true, force: true });
await Promise.all(targets.map(async (target) => {
  const directory = fileURLToPath(new URL(`../dist/platform/${target.os}-${target.cpu}/`, import.meta.url));
  const binDirectory = fileURLToPath(new URL(`../dist/platform/${target.os}-${target.cpu}/bin/`, import.meta.url));
  const output = fileURLToPath(new URL(`../dist/platform/${target.os}-${target.cpu}/bin/${target.executable}`, import.meta.url));
  await mkdir(binDirectory, { recursive: true });
  await run("go", ["build", "-trimpath", "-o", output, "./cmd/go-fed-discovery"], root, {
    ...process.env,
    CGO_ENABLED: "0",
    GOOS: target.goos,
    GOARCH: target.goarch,
  });
  await chmod(output, 0o755);
  const manifest = {
    name: `@agnet-ai/daemon-${target.os}-${target.cpu}`,
    version: packageJSON.version,
    description: `Agnet daemon binary for ${target.os}-${target.cpu}`,
    license: packageJSON.license,
    os: [target.os],
    cpu: [target.cpu],
    files: [`bin/${target.executable}`],
  };
  await writeFile(`${directory}/package.json`, `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600 });
}));
await chmod(fileURLToPath(new URL("../agnet-daemon.mjs", import.meta.url)), 0o755);

function run(command, args, cwd, env) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd, env, stdio: "inherit" });
    child.once("error", reject);
    child.once("exit", (code, signal) => {
      if (code === 0) resolve();
      else reject(new Error(`${command} failed with ${signal ?? `exit ${code}`}`));
    });
  });
}
