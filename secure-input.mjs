import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { assertCanonicalStringDomain } from "./asp-core.mjs";

const MAX_OWNED_JSON_BYTES = 1024 * 1024;
const MAX_HELPER_OUTPUT_BYTES = 2 * 1024 * 1024;
// The helper performs the openat-style parent walk. It rejects parent symlinks
// except for its fixed platform allowlist of root-owned system links (for
// example Darwin /tmp -> private/tmp), and restarts traversal from / after a
// permitted link instead of trusting a second pathname validation pass.
const SECURE_OPEN_HELPER = fileURLToPath(new URL("./secure-input-openat.py", import.meta.url));
const SYSTEM_PYTHON = process.platform === "darwin" || process.platform === "linux" ? "/usr/bin/python3" : null;

function expectedParentArguments(expectedParent) {
  if (expectedParent === undefined) return ["-", "-"];
  if (!Number.isSafeInteger(expectedParent.dev) || expectedParent.dev < 0 || !Number.isSafeInteger(expectedParent.ino) || expectedParent.ino < 0) {
    throw new Error("owned JSON expected parent identity invalid");
  }
  return [String(expectedParent.dev), String(expectedParent.ino)];
}

function allowedNlinksArgument(allowedNlinks) {
  if (allowedNlinks === undefined) return "1";
  if (!Array.isArray(allowedNlinks) || allowedNlinks.length === 0 || allowedNlinks.some((value) => !Number.isSafeInteger(value) || value < 1 || value > 3)) {
    throw new Error("owned JSON allowed link counts invalid");
  }
  return [...new Set(allowedNlinks)].sort((left, right) => left - right).join(",");
}

async function readOwnedJsonWithOpenAt(path, expectedUID, maxBytes, testHooks, expectedParent = undefined, allowedNlinks = undefined) {
  if (SYSTEM_PYTHON === null) throw new Error(`owned JSON secure open unsupported on ${process.platform}`);
  const hooks = Object.fromEntries(
    Object.entries(testHooks ?? {}).filter(([name, callback]) =>
      ["afterParentVerified", "afterInitialStat", "afterRead"].includes(name) && typeof callback === "function"),
  );
  const child = spawn(SYSTEM_PYTHON, ["-I", SECURE_OPEN_HELPER, path, String(expectedUID), String(maxBytes), ...expectedParentArguments(expectedParent), allowedNlinksArgument(allowedNlinks)], {
    env: { AGNET_SECURE_OPEN_HOOKS: Object.keys(hooks).join(",") },
    stdio: ["pipe", "pipe", "pipe"],
  });
  const stdout = [];
  let stdoutBytes = 0;
  let stderr = "";
  let hookBuffer = "";
  let hookChain = Promise.resolve();
  let hookError;
  child.stdout.on("data", (chunk) => {
    stdoutBytes += chunk.length;
    if (stdoutBytes > MAX_HELPER_OUTPUT_BYTES) {
      child.kill();
      hookError = new Error("owned JSON secure-open helper output limit exceeded");
      return;
    }
    stdout.push(chunk);
  });
  child.stderr.on("data", (chunk) => {
    const text = chunk.toString("utf8");
    stderr += text;
    hookBuffer += text;
    for (;;) {
      const newline = hookBuffer.indexOf("\n");
      if (newline < 0) break;
      const line = hookBuffer.slice(0, newline);
      hookBuffer = hookBuffer.slice(newline + 1);
      if (!line.startsWith("HOOK ")) continue;
      const name = line.slice("HOOK ".length);
      hookChain = hookChain.then(async () => {
        try {
          await hooks[name]();
          child.stdin.write("1");
        } catch (error) {
          hookError = error;
          child.kill();
        }
      });
    }
  });
  const exit = await new Promise((accept, reject) => {
    child.once("error", reject);
    child.once("close", (code, signal) => accept({ code, signal }));
  });
  await hookChain;
  if (hookError) throw hookError;
  if (exit.code !== 0) {
    const message = stderr.split("\n").findLast((line) => line.startsWith("ERROR "))?.slice("ERROR ".length)
      ?? `owned JSON secure-open helper failed${exit.signal ? ` (${exit.signal})` : ""}`;
    throw new Error(message);
  }
  let result;
  try {
    result = JSON.parse(Buffer.concat(stdout).toString("utf8"));
  } catch {
    throw new Error("owned JSON secure-open helper response invalid");
  }
  return result;
}
async function runAtomicHelper(args, testHooks = undefined, hookNames = []) {
  if (SYSTEM_PYTHON === null) throw new Error(`owned JSON atomic helper unsupported on ${process.platform}`);
  const hooks = Object.fromEntries(
    Object.entries(testHooks ?? {}).filter(([name, callback]) => hookNames.includes(name) && typeof callback === "function"),
  );
  const forceUnsupportedAtomicRename = testHooks !== undefined && testHooks?.forceUnsupportedAtomicRename === true;
  const child = spawn(SYSTEM_PYTHON, ["-I", SECURE_OPEN_HELPER, ...args], {
    env: {
      AGNET_SECURE_OPEN_HOOKS: Object.keys(hooks).join(","),
      AGNET_SECURE_OPEN_FORCE_UNSUPPORTED_ATOMIC_RENAME: forceUnsupportedAtomicRename ? "1" : "0",
    },
    stdio: ["pipe", "ignore", "pipe"],
  });
  let stderr = "";
  let hookBuffer = "";
  let hookChain = Promise.resolve();
  let hookError;
  child.stderr.on("data", (chunk) => {
    const text = chunk.toString("utf8");
    stderr += text;
    hookBuffer += text;
    for (;;) {
      const newline = hookBuffer.indexOf("\n");
      if (newline < 0) break;
      const line = hookBuffer.slice(0, newline);
      hookBuffer = hookBuffer.slice(newline + 1);
      if (!line.startsWith("HOOK ")) continue;
      const name = line.slice("HOOK ".length);
      hookChain = hookChain.then(async () => {
        try {
          await hooks[name]();
          child.stdin.write("1");
        } catch (error) {
          hookError = error;
          child.kill();
        }
      });
    }
  });
  const exit = await new Promise((accept, reject) => {
    child.once("error", reject);
    child.once("close", (code, signal) => accept({ code, signal }));
  });
  await hookChain;
  if (hookError) throw hookError;
  if (exit.code !== 0) {
    const message = stderr.split("\n").findLast((line) => line.startsWith("ERROR "))?.slice("ERROR ".length)
      ?? `owned JSON atomic helper failed${exit.signal ? ` (${exit.signal})` : ""}`;
    throw new Error(message);
  }
}


const MAX_JSON_NESTING_DEPTH = 128;
const MAX_JSON_ENTRIES = 100_000;

class DuplicateSafeJsonParser {
  constructor(text) {
    this.text = text;
    this.index = 0;
    this.depth = 0;
    this.entries = 0;
  }

  parse() {
    const value = this.parseValue();
    this.skipWhitespace();
    if (this.index !== this.text.length) throw new Error(`invalid JSON at byte ${this.index}`);
    return value;
  }

  skipWhitespace() {
    while (this.index < this.text.length) {
      const char = this.text[this.index];
      if (char !== " " && char !== "\t" && char !== "\n" && char !== "\r") return;
      this.index += 1;
    }
  }

  enterContainer() {
    this.depth += 1;
    if (this.depth > MAX_JSON_NESTING_DEPTH) throw new Error(`JSON nesting limit exceeded at byte ${this.index}`);
  }

  leaveContainer() {
    this.depth -= 1;
  }

  recordEntry() {
    this.entries += 1;
    if (this.entries > MAX_JSON_ENTRIES) throw new Error(`JSON entry limit exceeded at byte ${this.index}`);
  }

  parseValue() {
    this.skipWhitespace();
    const char = this.text[this.index];
    if (char === "{") return this.parseObject();
    if (char === "[") return this.parseArray();
    if (char === '"') return this.parseString();
    if (char === "t") return this.parseKeyword("true", true);
    if (char === "f") return this.parseKeyword("false", false);
    if (char === "n") return this.parseKeyword("null", null);
    return this.parseNumber();
  }

  parseObject() {
    this.enterContainer();
    this.index += 1;
    const value = {};
    const keys = new Set();
    this.skipWhitespace();
    if (this.text[this.index] === "}") {
      this.index += 1;
      this.leaveContainer();
      return value;
    }
    for (;;) {
      this.skipWhitespace();
      if (this.text[this.index] !== '"') throw new Error(`invalid JSON object key at byte ${this.index}`);
      const key = this.parseString();
      if (keys.has(key)) throw new Error(`duplicate JSON key: ${key}`);
      keys.add(key);
      this.recordEntry();
      this.skipWhitespace();
      if (this.text[this.index] !== ":") throw new Error(`invalid JSON object separator at byte ${this.index}`);
      this.index += 1;
      const item = this.parseValue();
      Object.defineProperty(value, key, {
        value: item,
        enumerable: true,
        configurable: true,
        writable: true,
      });
      this.skipWhitespace();
      const separator = this.text[this.index];
      if (separator === "}") {
        this.index += 1;
        this.leaveContainer();
        return value;
      }
      if (separator !== ",") throw new Error(`invalid JSON object at byte ${this.index}`);
      this.index += 1;
    }
  }

  parseArray() {
    this.enterContainer();
    this.index += 1;
    const value = [];
    this.skipWhitespace();
    if (this.text[this.index] === "]") {
      this.index += 1;
      this.leaveContainer();
      return value;
    }
    for (;;) {
      this.recordEntry();
      value.push(this.parseValue());
      this.skipWhitespace();
      const separator = this.text[this.index];
      if (separator === "]") {
        this.index += 1;
        this.leaveContainer();
        return value;
      }
      if (separator !== ",") throw new Error(`invalid JSON array at byte ${this.index}`);
      this.index += 1;
    }
  }

  parseString() {
    const start = this.index;
    this.index += 1;
    let escaped = false;
    while (this.index < this.text.length) {
      const char = this.text[this.index];
      if (!escaped && char === '"') {
        this.index += 1;
        return assertCanonicalStringDomain(JSON.parse(this.text.slice(start, this.index)));
      }
      if (!escaped && char.charCodeAt(0) < 0x20) throw new Error(`invalid JSON string at byte ${this.index}`);
      if (!escaped && char === "\\") escaped = true;
      else escaped = false;
      this.index += 1;
    }
    throw new Error(`unterminated JSON string at byte ${start}`);
  }

  parseKeyword(keyword, value) {
    for (let offset = 0; offset < keyword.length; offset += 1) {
      if (this.text[this.index + offset] !== keyword[offset]) throw new Error(`invalid JSON token at byte ${this.index}`);
    }
    this.index += keyword.length;
    return value;
  }

  parseNumber() {
    const start = this.index;
    if (this.text[this.index] === "-") this.index += 1;
    if (this.text[this.index] === "0") {
      this.index += 1;
    } else {
      if (this.text[this.index] < "1" || this.text[this.index] > "9") throw new Error(`invalid JSON token at byte ${start}`);
      while (this.text[this.index] >= "0" && this.text[this.index] <= "9") this.index += 1;
    }
    if (this.text[this.index] === ".") {
      this.index += 1;
      const fractionStart = this.index;
      while (this.text[this.index] >= "0" && this.text[this.index] <= "9") this.index += 1;
      if (this.index === fractionStart) throw new Error(`invalid JSON number at byte ${start}`);
    }
    if (this.text[this.index] === "e" || this.text[this.index] === "E") {
      this.index += 1;
      if (this.text[this.index] === "+" || this.text[this.index] === "-") this.index += 1;
      const exponentStart = this.index;
      while (this.text[this.index] >= "0" && this.text[this.index] <= "9") this.index += 1;
      if (this.index === exponentStart) throw new Error(`invalid JSON number at byte ${start}`);
    }
    const value = Number(this.text.slice(start, this.index));
    if (!Number.isFinite(value)) throw new Error(`JSON number out of range at byte ${start}`);
    return value;
  }
}

export function parseDuplicateSafeJson(text) {
  return new DuplicateSafeJsonParser(text).parse();
}

export async function safeOpenOwnedBytes(path, options = {}) {
  if (typeof path !== "string" || path.length === 0 || path.includes("\0")) throw new Error("owned JSON path invalid");
  if (typeof process.getuid !== "function") throw new Error("owned JSON current UID unavailable");
  const maxBytes = options.maxBytes ?? MAX_OWNED_JSON_BYTES;
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0 || maxBytes > MAX_OWNED_JSON_BYTES) throw new Error("owned JSON maxBytes invalid");
  const absolutePath = resolve(path);
  const opened = await readOwnedJsonWithOpenAt(absolutePath, process.getuid(), maxBytes, options.testHooks, options.expectedParent, options.allowedNlinks);
  return Object.freeze({ bytes: Buffer.from(opened.data, "base64url"), evidence: Object.freeze(opened.evidence) });
}
export async function publishOwnedFileAtomically(tempPath, canonicalPath, { exclusive = false, testHooks = undefined, expectedParent = undefined } = {}) {
  if (typeof tempPath !== "string" || tempPath.length === 0 || tempPath.includes("\0")) throw new Error("atomic temp path invalid");
  if (typeof canonicalPath !== "string" || canonicalPath.length === 0 || canonicalPath.includes("\0")) throw new Error("atomic canonical path invalid");
  if (typeof process.getuid !== "function") throw new Error("owned JSON current UID unavailable");
  const tempAbsolutePath = resolve(tempPath);
  const canonicalAbsolutePath = resolve(canonicalPath);
  if (dirname(tempAbsolutePath) !== dirname(canonicalAbsolutePath)) throw new Error("atomic paths must share a directory");
  await runAtomicHelper([exclusive ? "--publish-exclusive" : "--publish-swap", tempAbsolutePath, canonicalAbsolutePath, String(process.getuid()), ...expectedParentArguments(expectedParent)], testHooks, ["beforePublish"]);
}

export async function repairOwnedLegacyHardLink(canonicalPath, candidatePath, { maxBytes = MAX_OWNED_JSON_BYTES, testHooks = undefined, expectedParent = undefined } = {}) {
  if (typeof canonicalPath !== "string" || canonicalPath.length === 0 || canonicalPath.includes("\0")) throw new Error("canonical recovery path invalid");
  if (typeof candidatePath !== "string" || candidatePath.length === 0 || candidatePath.includes("\0")) throw new Error("recovery candidate path invalid");
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0 || maxBytes > MAX_OWNED_JSON_BYTES) throw new Error("owned JSON maxBytes invalid");
  if (typeof process.getuid !== "function") throw new Error("owned JSON current UID unavailable");
  const canonicalAbsolutePath = resolve(canonicalPath);
  const candidateAbsolutePath = resolve(candidatePath);
  if (dirname(canonicalAbsolutePath) !== dirname(candidateAbsolutePath)) throw new Error("recovery paths must share a directory");
  await runAtomicHelper(["--repair-legacy", canonicalAbsolutePath, candidateAbsolutePath, String(process.getuid()), String(maxBytes), ...expectedParentArguments(expectedParent)], testHooks, ["afterRecoveryInitialStat", "beforeRecoverySwap"]);
}

export async function holdOwnedGenerationLock(lockPath, { expectedParent = undefined } = {}) {
  if (typeof lockPath !== "string" || lockPath.length === 0 || lockPath.includes("\0")) throw new Error("generation lock path invalid");
  if (typeof process.getuid !== "function") throw new Error("owned JSON current UID unavailable");
  const absolutePath = resolve(lockPath);
  if (SYSTEM_PYTHON === null) throw new Error(`owned JSON atomic helper unsupported on ${process.platform}`);
  const child = spawn(SYSTEM_PYTHON, ["-I", SECURE_OPEN_HELPER, "--hold-generation-lock", absolutePath, String(process.getuid()), ...expectedParentArguments(expectedParent)], { stdio: ["pipe", "pipe", "pipe"] });
  let stderr = "";
  child.stderr.on("data", (chunk) => { stderr += chunk.toString("utf8"); });
  const ready = await new Promise((accept, reject) => {
    let stdout = "";
    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString("utf8");
      if (stdout.includes("READY\n")) accept();
    });
    child.once("error", reject);
    child.once("close", (code, signal) => reject(new Error(stderr.split("\n").findLast((line) => line.startsWith("ERROR "))?.slice("ERROR ".length) ?? `generation lock helper failed${signal ? ` (${signal})` : ` (${code})`}`)));
  });
  await ready;
  let released = false;
  return async () => {
    if (released) return;
    released = true;
    child.stdin.end();
    await new Promise((accept, reject) => child.once("close", (code) => code === 0 ? accept() : reject(new Error(`generation lock helper failed (${code})`))));
  };
}


export async function safeOpenOwnedJson(path, testHooks = undefined) {
  const opened = await safeOpenOwnedBytes(path, { maxBytes: MAX_OWNED_JSON_BYTES, testHooks });
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(opened.bytes);
  } catch {
    throw new Error("owned JSON must be valid UTF-8");
  }
  const value = parseDuplicateSafeJson(text);
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("owned JSON root must be an object");
  return Object.freeze({ value, evidence: opened.evidence });
}
