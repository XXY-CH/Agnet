import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { test } from "node:test";
import { promisify } from "node:util";
import { spawn } from "node:child_process";
import { createPrivateKey } from "node:crypto";
import net from "node:net";
import { chmod, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { agentFromPrivateKey, canonical, zoneFromPrivateKey } from "../asp-core.mjs"
import { migrateKey } from "../agnet-key.mjs"

const execFileAsync = promisify(execFile);

const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const PASSPHRASE = Buffer.from("u13 runtime fixture passphrase\n");

function privateKey(start) {
  return createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, Buffer.from(Array.from({ length: 32 }, (_, index) => (start + index) & 0xff))]), format: "der", type: "pkcs8" });
}

async function restricted(path, bytes) {
  await writeFile(path, bytes, { mode: 0o600 });
  await chmod(path, 0o600);
}

async function managedIdentity(root, identity, kind) {
  const path = join(root, kind, identity.aid ?? identity.zid);
  await (await import("node:fs/promises")).mkdir(path, { recursive: true, mode: 0o700 });
  await chmod(path, 0o700);
  const keyPath = join(path, "key.pkcs8");
  const descriptorPath = join(path, "descriptor.json");
  const passphrasePath = join(path, "passphrase");
  const storePath = join(path, "store");
  await restricted(keyPath, Buffer.from(identity.privateKey.export({ format: "der", type: "pkcs8" })));
  await restricted(descriptorPath, Buffer.from(canonical(identity.descriptor)));
  await restricted(passphrasePath, PASSPHRASE);
  await migrateKey({ storePath, keyPath, keyType: "ed25519-pkcs8", identityKind: kind, descriptorPath, passphrasePath, iterations: 100000 });
  return { storePath, passphraseFile: passphrasePath };
}

async function runtimeConfig() {
  const root = await mkdtemp(join(tmpdir(), "agnet-u13-agent-runtime-"));
  await chmod(root, 0o700);
  const worker = agentFromPrivateKey("agent://local/summarizer", privateKey(1), { allow_network: false, approval_required: ["write"], write_prefixes: ["artifact://local/"] }, ["asp+tcp://127.0.0.1:8890"], ["summarize.text"]);
  const requester = agentFromPrivateKey("agent://local/requester", privateKey(33));
  const zone = zoneFromPrivateKey("zone://local", privateKey(65));
  const workerManaged = await managedIdentity(root, worker, "aid");
  const requesterManaged = await managedIdentity(root, requester, "aid");
  const zoneManaged = await managedIdentity(root, zone, "zid");
  const config = {
    worker: { ...workerManaged, alias: worker.alias, policy: worker.descriptor.policy, transports: worker.descriptor.transports, capabilities: worker.descriptor.capabilities },
    requester: { ...requesterManaged, alias: requester.alias, policy: requester.descriptor.policy, transports: requester.descriptor.transports, capabilities: requester.descriptor.capabilities },
    zone: { ...zoneManaged, name: zone.name },
    registryPath: join(root, "registry.json"),
  };
  const configPath = join(root, "managed-runtime.json");
  await restricted(configPath, Buffer.from(JSON.stringify(config)));
  return { configPath, worker: worker.aid };
}

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

test("runtime rejects a missing managed config before opening its listener", async () => {
  const port = 9141;
  const worker = spawn(process.execPath, ["agent-runtime.mjs", "worker", String(port), "/definitely/not/a/managed-runtime.json"], {
    cwd: process.cwd(),
    stdio: ["ignore", "pipe", "pipe"],
  });
  const [code] = await new Promise((resolve) => worker.once("exit", (...args) => resolve(args)));
  assert.equal(code, 1);
  await assert.rejects(new Promise((resolve, reject) => {
    const socket = net.createConnection(port, "127.0.0.1");
    socket.once("connect", () => { socket.end(); resolve(); });
    socket.once("error", reject);
  }));
});

test("local ASP runtime connects two managed-key processes", async () => {
  const config = await runtimeConfig();
  const port = 8890;
  const worker = spawn(process.execPath, ["agent-runtime.mjs", "worker", String(port), config.configPath], {
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
      config.configPath,
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

test("managed worker aid survives runtime restart", async () => {
  const config = await runtimeConfig();
  const first = spawn(process.execPath, ["agent-runtime.mjs", "worker", "8891", config.configPath], {
    cwd: process.cwd(),
    stdio: ["ignore", "pipe", "pipe"],
  });
  const firstStarted = await waitForWorker(first);
  first.kill("SIGINT");

  const second = spawn(process.execPath, ["agent-runtime.mjs", "worker", "8892", config.configPath], {
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
