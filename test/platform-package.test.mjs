import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { access, chmod, mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

const root = new URL("../", import.meta.url);
const targets = [
  { os: "darwin", cpu: "arm64", executable: "agnet-daemon" },
  { os: "darwin", cpu: "x64", executable: "agnet-daemon" },
  { os: "linux", cpu: "arm64", executable: "agnet-daemon" },
  { os: "linux", cpu: "x64", executable: "agnet-daemon" },
];

test("platform builds produce isolated npm packages", async () => {
  for (const target of targets) {
    const directory = new URL(`dist/platform/${target.os}-${target.cpu}/`, root);
    const manifest = JSON.parse(await readFile(new URL("package.json", directory), "utf8"));
    assert.equal(manifest.name, `@agnet-ai/daemon-${target.os}-${target.cpu}`);
    assert.deepEqual(manifest.os, [target.os]);
    assert.deepEqual(manifest.cpu, [target.cpu]);
    assert.deepEqual(manifest.files, [`bin/${target.executable}`]);
    const executableURL = new URL(`bin/${target.executable}`, directory);
    await access(executableURL);
    const metadata = await stat(executableURL);
    assert.ok(metadata.size > 1_000_000, `${path.basename(executableURL.pathname)} is not a compiled daemon`);
  }
});

test("daemon wrapper exits with the packaged daemon signal", async (t) => {
  const target = targets.find(({ os, cpu }) => os === process.platform && cpu === process.arch);
  assert.ok(target, `test host ${process.platform}-${process.arch} is unsupported`);
  const directory = await mkdtemp(path.join(tmpdir(), "agnet-daemon-signal-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const wrapperDirectory = path.join(directory, "node_modules", "agnet");
  const platformDirectory = path.join(directory, "node_modules", "@agnet-ai", `daemon-${target.os}-${target.cpu}`);
  await mkdir(wrapperDirectory, { recursive: true });
  await mkdir(path.join(platformDirectory, "bin"), { recursive: true });
  await writeFile(path.join(wrapperDirectory, "agnet-daemon.mjs"), await readFile(new URL("../agnet-daemon.mjs", import.meta.url), "utf8"));
  await writeFile(path.join(platformDirectory, "package.json"), JSON.stringify({ name: `@agnet-ai/daemon-${target.os}-${target.cpu}`, version: "0.0.0" }));
  const fakeDaemon = path.join(platformDirectory, "bin", "agnet-daemon");
  await writeFile(fakeDaemon, "#!/usr/bin/env node\nconsole.log('ready');\nsetInterval(() => {}, 1000);\n");
  await chmod(fakeDaemon, 0o755);

  const wrapper = spawn(process.execPath, [path.join(wrapperDirectory, "agnet-daemon.mjs")], { stdio: ["ignore", "pipe", "pipe"] });
  const ready = new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("fake daemon did not start")), 3000);
    wrapper.stdout.once("data", (chunk) => {
      clearTimeout(timer);
      assert.match(String(chunk), /ready/);
      resolve();
    });
  });
  await ready;
  wrapper.kill("SIGTERM");
  let exitTimer;
  const timeout = new Promise((_, reject) => {
    exitTimer = setTimeout(() => reject(new Error("wrapper did not propagate terminal signal")), 3000);
  });
  const [code, signal] = await Promise.race([once(wrapper, "exit"), timeout]).finally(() => clearTimeout(exitTimer));
  assert.equal(code, null);
  assert.equal(signal, "SIGTERM");
});
