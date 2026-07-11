import assert from "node:assert/strict";
import { appendFile, chmod, mkdir, mkdtemp, rename, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { safeOpenOwnedJson } from "./secure-input.mjs";

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
