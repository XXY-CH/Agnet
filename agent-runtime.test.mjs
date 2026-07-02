import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { test } from "node:test";
import { promisify } from "node:util";
import { spawn } from "node:child_process";

const execFileAsync = promisify(execFile);

function waitForWorker(child) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("worker did not start")), 3000);
    child.stdout.on("data", (chunk) => {
      const text = chunk.toString();
      const line = text.split("\n").find((item) => item.trim().startsWith("{"));
      if (!line) return;
      clearTimeout(timer);
      resolve(JSON.parse(line));
    });
    child.once("error", reject);
    child.once("exit", (code) => {
      if (code !== null && code !== 0) reject(new Error(`worker exited early: ${code}`));
    });
  });
}

test("local ASP runtime connects two processes", async () => {
  const port = 8890;
  const worker = spawn(process.execPath, ["agent-runtime.mjs", "worker", String(port)], {
    cwd: process.cwd(),
    stdio: ["ignore", "pipe", "pipe"],
  });

  try {
    const started = await waitForWorker(worker);
    assert.equal(started.listening, port);

    const { stdout } = await execFileAsync(process.execPath, [
      "agent-runtime.mjs",
      "request",
      "agent://local/summarizer",
    ]);
    const result = JSON.parse(stdout);

    assert.match(result.requester, /^aid:ed25519:/);
    assert.match(result.worker, /^aid:ed25519:/);
    assert.equal(result.events.some((event) => event.type === "approval.required"), true);
    assert.equal(result.events.at(-1).type, "task.completed");
    assert.equal(result.receipt.event_count, result.events.length);
    assert.equal(result.receipt.approvals[0], "write");
  } finally {
    worker.kill("SIGINT");
  }
});

test("worker aid survives runtime restart", async () => {
  const first = spawn(process.execPath, ["agent-runtime.mjs", "worker", "8891"], {
    cwd: process.cwd(),
    stdio: ["ignore", "pipe", "pipe"],
  });
  const firstStarted = await waitForWorker(first);
  first.kill("SIGINT");

  const second = spawn(process.execPath, ["agent-runtime.mjs", "worker", "8892"], {
    cwd: process.cwd(),
    stdio: ["ignore", "pipe", "pipe"],
  });
  try {
    const secondStarted = await waitForWorker(second);
    assert.equal(secondStarted.worker, firstStarted.worker);
  } finally {
    second.kill("SIGINT");
  }
});
