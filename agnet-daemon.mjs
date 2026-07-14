#!/usr/bin/env node
import { spawn } from "node:child_process";
import { createRequire } from "node:module";

const platformKey = `${process.platform}-${process.arch}`;
const platformPackages = {
  "darwin-arm64": ["@agnet-ai/daemon-darwin-arm64", "agnet-daemon"],
  "darwin-x64": ["@agnet-ai/daemon-darwin-x64", "agnet-daemon"],
  "linux-arm64": ["@agnet-ai/daemon-linux-arm64", "agnet-daemon"],
  "linux-x64": ["@agnet-ai/daemon-linux-x64", "agnet-daemon"],
};
const selection = platformPackages[platformKey];
if (!selection) {
  console.error(`Agnet does not publish a daemon for ${platformKey}.`);
  process.exit(1);
}
const [packageName, executable] = selection;
const require = createRequire(import.meta.url);
let binary;
try {
  binary = require.resolve(`${packageName}/bin/${executable}`);
} catch {
  console.error(`Missing optional Agnet platform package ${packageName}. Reinstall Agnet on this machine.`);
  process.exit(1);
}
const child = spawn(binary, process.argv.slice(2), { stdio: "inherit" });

for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  process.on(signal, () => {
    if (!child.killed) child.kill(signal);
  });
}

child.once("error", (error) => {
  console.error(`Unable to start packaged Agnet daemon: ${error.message}`);
  process.exitCode = 1;
});

child.once("exit", (code, signal) => {
  if (signal) {
    process.removeAllListeners(signal);
    process.kill(process.pid, signal);
    return;
  }
  process.exitCode = code ?? 1;
});
