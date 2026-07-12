import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import { appendFile, chmod, mkdir, mkdtemp, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { publishOwnedFileAtomically, safeOpenOwnedBytes, safeOpenOwnedJson } from "../secure-input.mjs"

const MAX_INPUT_BYTES = 1024 * 1024;

async function workspace(t, name = "agnet-secure-input-node-") {
  const dir = await mkdtemp(join(tmpdir(), name));
  await chmod(dir, 0o700);
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

async function writeSecureJson(path, value, raw = null) {
  await writeFile(path, raw ?? `${JSON.stringify(value)}\n`, { mode: 0o600 });
  await chmod(path, 0o600);
}

test("safeOpenOwnedJson opens the final component relative to the verified parent handle", async (t) => {
  const dir = await workspace(t);
  const outer = join(dir, "outer");
  const inner = join(outer, "inner");
  const moved = join(dir, "verified-outer");
  await mkdir(inner, { recursive: true, mode: 0o700 });
  await chmod(outer, 0o700);
  await chmod(inner, 0o700);
  const path = join(inner, "input.json");
  await writeSecureJson(path, { source: "verified-parent" });
  let hookCalled = false;

  const opened = await safeOpenOwnedJson(path, {
    afterParentVerified: async () => {
      hookCalled = true;
      await rename(outer, moved);
      await mkdir(inner, { recursive: true, mode: 0o700 });
      await chmod(outer, 0o700);
      await chmod(inner, 0o700);
      await writeSecureJson(path, { source: "rebound-path" });
    },
  });

  assert.equal(hookCalled, true);
  assert.deepEqual(opened.value, { source: "verified-parent" });
});

test("safeOpenOwnedJson bounds descriptor reads when a file grows after fstat", async (t) => {
  const dir = await workspace(t);
  const path = join(dir, "growing.json");
  await writeSecureJson(path, { value: "small" });
  let hookCalled = false;

  await assert.rejects(
    () => safeOpenOwnedJson(path, {
      afterInitialStat: async () => {
        hookCalled = true;
        await appendFile(path, "x".repeat(MAX_INPUT_BYTES + 1));
      },
    }),
    /size limit/i,
  );
  assert.equal(hookCalled, true);
});

test("safeOpenOwnedJson rejects an after-read mutation", async (t) => {
  const dir = await workspace(t, "agnet-secure-after-read-");
  const path = join(dir, "input.json");
  await writeSecureJson(path, { value: "stable" });
  await assert.rejects(
    () => safeOpenOwnedJson(path, {
      afterRead: async () => appendFile(path, " "),
    }),
    /changed during read/i,
  );
});

test("safeOpenOwnedJson reports validation errors for parser nesting and entry limits", async (t) => {
  const dir = await workspace(t);
  const tooMany = join(dir, "too-many.json");
  await writeSecureJson(tooMany, null, `{"values":[${"0,".repeat(100_000)}0]}`);
  await assert.rejects(() => safeOpenOwnedJson(tooMany), /entry limit/i);

  const tooDeep = join(dir, "too-deep.json");
  await writeSecureJson(tooDeep, null, `{"value":${"[".repeat(512)}0${"]".repeat(512)}}`);
  await assert.rejects(
    () => safeOpenOwnedJson(tooDeep),
    (error) => !(error instanceof RangeError) && /nesting limit/i.test(error.message),
  );
});

test("safeOpenOwnedJson scans many numeric tokens without suffix-copy blowup", async (t) => {
  const dir = await workspace(t);
  const path = join(dir, "many-numbers.json");
  await writeSecureJson(path, null, `{"values":[${"1,".repeat(49_999)}1]}`);
  const started = performance.now();
  const opened = await safeOpenOwnedJson(path);
  const elapsed = performance.now() - started;

  assert.equal(opened.value.values.length, 50_000);
  assert.ok(elapsed < 5_000, `many-number parse took ${elapsed}ms`);
});

test("publishOwnedFileAtomically exclusively publishes a synced leaf without hard links", async (t) => {
  const dir = await workspace(t, "agnet-secure-publish-");
  const temp = join(dir, ".target.1.1.a.tmp");
  const canonical = join(dir, "target");
  await writeFile(temp, "published", { mode: 0o600 });

  await publishOwnedFileAtomically(temp, canonical, { exclusive: true });

  assert.equal(await readFile(canonical, "utf8"), "published");
  assert.equal((await stat(canonical)).nlink, 1);
  await assert.rejects(stat(temp), { code: "ENOENT" });
});

test("publishOwnedFileAtomically retains collision and swap predecessors", async (t) => {
  const dir = await workspace(t, "agnet-secure-publish-collision-");
  const canonical = join(dir, "active.json");
  const collisionTemp = join(dir, ".active.json.1.1.a.tmp");
  const swapTemp = join(dir, ".active.json.1.2.a.tmp");
  await writeFile(canonical, "old", { mode: 0o600 });
  await writeFile(collisionTemp, "other", { mode: 0o600 });

  await assert.rejects(() => publishOwnedFileAtomically(collisionTemp, canonical, { exclusive: true }), /already exists/i);
  assert.equal(await readFile(canonical, "utf8"), "old");
  assert.equal(await readFile(collisionTemp, "utf8"), "other");

  await writeFile(swapTemp, "new", { mode: 0o600 });
  await publishOwnedFileAtomically(swapTemp, canonical);
  assert.equal(await readFile(canonical, "utf8"), "new");
  assert.equal(await readFile(swapTemp, "utf8"), "old");
  assert.equal((await stat(canonical)).nlink, 1);
  assert.equal((await stat(swapTemp)).nlink, 1);
});

test("helper rejects substituted expected parent before authoritative reads and publication", async (t) => {
  const dir = await workspace(t, "agnet-secure-parent-pin-");
  const expected = await stat(dir);
  const source = join(dir, "source.json");
  await writeSecureJson(source, { authority: "original" });
  const retained = `${dir}-retained`;
  await rename(dir, retained);
  await mkdir(dir, { mode: 0o700 });
  await chmod(dir, 0o700);
  await writeSecureJson(source, { authority: "replay" });
  await assert.rejects(
    () => safeOpenOwnedBytes(source, { expectedParent: expected }),
    /parent identity changed/i,
  );
  const temp = join(dir, ".active.1.1.a.tmp");
  const canonical = join(dir, "active.json");
  await writeFile(temp, "new", { mode: 0o600 });
  await assert.rejects(
    () => publishOwnedFileAtomically(temp, canonical, { expectedParent: expected }),
    /parent identity changed/i,
  );
  await assert.rejects(stat(canonical), { code: "ENOENT" });
});

test("beforePublish runs inside exclusive and swap atomic windows", async (t) => {
  const dir = await workspace(t, "agnet-secure-before-publish-");
  const exclusiveTemp = join(dir, ".exclusive.1.1.a.tmp");
  const exclusiveCanonical = join(dir, "exclusive.json");
  await writeFile(exclusiveTemp, "new-exclusive", { mode: 0o600 });
  await assert.rejects(
    () => publishOwnedFileAtomically(exclusiveTemp, exclusiveCanonical, {
      exclusive: true,
      testHooks: { beforePublish: () => { throw new Error("fault:exclusive-before-publish"); } },
    }),
    /fault:exclusive-before-publish/,
  );
  await assert.rejects(stat(exclusiveCanonical), { code: "ENOENT" });
  assert.equal(await readFile(exclusiveTemp, "utf8"), "new-exclusive");

  const swapTemp = join(dir, ".swap.1.1.a.tmp");
  const swapCanonical = join(dir, "swap.json");
  await writeFile(swapCanonical, "old", { mode: 0o600 });
  await writeFile(swapTemp, "new-swap", { mode: 0o600 });
  await assert.rejects(
    () => publishOwnedFileAtomically(swapTemp, swapCanonical, {
      testHooks: { beforePublish: () => { throw new Error("fault:swap-before-publish"); } },
    }),
    /fault:swap-before-publish/,
  );
  assert.equal(await readFile(swapCanonical, "utf8"), "old");
  assert.equal(await readFile(swapTemp, "utf8"), "new-swap");
});

test("forced unsupported atomic rename fails closed only through explicit test hooks", async (t) => {
  const dir = await workspace(t, "agnet-secure-unsupported-atomic-");
  const active = join(dir, "active.json");
  const exclusiveTemp = join(dir, ".exclusive.1.1.a.tmp");
  const exclusiveCanonical = join(dir, "exclusive.json");
  const swapTemp = join(dir, ".active.1.2.a.tmp");
  const activeBefore = Buffer.from("old-authority");
  await writeFile(active, activeBefore, { mode: 0o600 });
  await writeFile(exclusiveTemp, "exclusive-source", { mode: 0o600 });

  await publishOwnedFileAtomically(exclusiveTemp, exclusiveCanonical, { exclusive: true, forceUnsupportedAtomicRename: true });
  assert.equal(await readFile(exclusiveCanonical, "utf8"), "exclusive-source");
  assert.deepEqual(await readFile(active), activeBefore);

  await writeFile(swapTemp, "swap-source", { mode: 0o600 });
  await assert.rejects(
    () => publishOwnedFileAtomically(swapTemp, active, { testHooks: { forceUnsupportedAtomicRename: true } }),
    /^Error: atomic rename primitive unsupported by test hook$/,
  );
  assert.equal(await readFile(swapTemp, "utf8"), "swap-source");
  assert.deepEqual(await readFile(active), activeBefore);

  const forcedExclusiveTemp = join(dir, ".exclusive.1.3.a.tmp");
  const forcedExclusiveCanonical = join(dir, "forced-exclusive.json");
  await writeFile(forcedExclusiveTemp, "forced-exclusive-source", { mode: 0o600 });
  await assert.rejects(
    () => publishOwnedFileAtomically(forcedExclusiveTemp, forcedExclusiveCanonical, { exclusive: true, testHooks: { forceUnsupportedAtomicRename: true } }),
    /^Error: atomic rename primitive unsupported by test hook$/,
  );
  assert.equal(await readFile(forcedExclusiveTemp, "utf8"), "forced-exclusive-source");
  await assert.rejects(stat(forcedExclusiveCanonical), { code: "ENOENT" });
  assert.deepEqual(await readFile(active), activeBefore);
});

test("generation lock is reacquirable after the holder dies abruptly", async (t) => {
  const { holdOwnedGenerationLock } = await import("../secure-input.mjs");
  const dir = await workspace(t, "agnet-secure-lock-death-");
  const lock = join(dir, "0000000000000001.install.lock");
  const helper = fileURLToPath(new URL("../secure-input-openat.py", import.meta.url));
  const holder = spawn("/usr/bin/python3", ["-I", helper, "--hold-generation-lock", lock, String(process.getuid()), "-", "-"], {
    stdio: ["pipe", "pipe", "pipe"],
  });
  await new Promise((resolveReady, rejectReady) => {
    let output = "";
    holder.stdout.on("data", (chunk) => {
      output += chunk.toString("utf8");
      if (output.includes("READY\n")) resolveReady();
    });
    holder.once("error", rejectReady);
    holder.once("close", (code) => rejectReady(new Error(`lock holder exited before ready (${code})`)));
  });
  holder.kill("SIGKILL");
  await new Promise((resolveClose) => holder.once("close", resolveClose));
  const release = await holdOwnedGenerationLock(lock);
  await release();
});

test("held generation lock is permanent and permits retry after release", async (t) => {
  const { holdOwnedGenerationLock } = await import("../secure-input.mjs");
  const dir = await workspace(t, "agnet-secure-lock-");
  const lock = join(dir, "0000000000000001.install.lock");
  const release = await holdOwnedGenerationLock(lock);
  await assert.rejects(() => holdOwnedGenerationLock(lock), /already in progress/i);
  await release();
  const retryRelease = await holdOwnedGenerationLock(lock);
  assert.equal((await stat(lock)).mode & 0o777, 0o600);
  assert.equal((await stat(lock)).nlink, 1);
  await retryRelease();
});
