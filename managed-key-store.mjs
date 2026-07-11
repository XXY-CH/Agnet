import { createHash } from "node:crypto";
import { constants } from "node:fs";
import {
  chmod,
  lstat,
  mkdir,
  open,
  readdir,
} from "node:fs/promises";
import { basename, dirname, join } from "node:path";

import { canonical } from "./asp-core.mjs";
import {
  openKeyEnvelope,
  parseGenerationRecord,
  verifyGenerationChain,
} from "./managed-key.mjs";
import {
  holdOwnedGenerationLock,
  parseDuplicateSafeJson,
  publishOwnedFileAtomically,
  repairOwnedLegacyHardLink,
  safeOpenOwnedBytes,
} from "./secure-input.mjs";


export const ERR_KEY_RECOVERY_REQUIRED = "ERR_KEY_RECOVERY_REQUIRED";
export const ACTIVE_POINTER_FORMAT = "agnet-managed-key-active/v1";
export const GENERATION_COMMIT_FORMAT = "agnet-managed-key-generation-commit/v1";
export const INSTALL_LOCK_SUFFIX = "install.lock";

const GENERATION_SUFFIXES = ["envelope", "record", "descriptor"];
const DIGEST_RE = /^[a-f0-9]{64}$/;

class KeyRecoveryRequiredError extends Error {
  constructor(message) {
    super(message);
    this.name = "KeyRecoveryRequiredError";
    this.code = ERR_KEY_RECOVERY_REQUIRED;
  }
}

function sha256Hex(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function generationPrefix(generation) {
  if (!Number.isSafeInteger(generation) || generation < 1) throw new Error("generation invalid");
  return String(generation).padStart(16, "0");
}

function generationPath(root, generation, suffix) {
  return join(root, "generations", `${generationPrefix(generation)}.${suffix}.json`);
}

async function maybeFault(testHooks, point) {
  if (typeof testHooks?.fault === "function") await testHooks.fault(point);
}

async function syncDirectory(path, { testHooks = undefined, pointPrefix = undefined } = {}) {
  const handle = await open(path, "r");
  try {
    await handle.sync();
    if (pointPrefix !== undefined) await maybeFault(testHooks, `${pointPrefix}-after-dir-sync`);
  } finally {
    await handle.close();
  }
}

async function durableWriteFile(path, data, { mode = 0o600, pointPrefix, testHooks, exclusive = false, allowExisting = true, parentIdentity } = {}) {
  const dir = dirname(path);
  const leaf = basename(path);
  const temp = join(dir, `.${leaf}.${process.pid}.${Date.now()}.${Math.random().toString(16).slice(2)}.tmp`);
  const handle = await open(temp, "wx", mode);
  try {
    await handle.writeFile(data);
    await handle.chmod(mode);
    await maybeFault(testHooks, `${pointPrefix}-after-temp-write`);
    await handle.sync();
    await maybeFault(testHooks, `${pointPrefix}-file-sync`);
  } finally {
    await handle.close();
  }
  await maybeFault(testHooks, `${pointPrefix}-before-rename`);
  try {
    await publishOwnedFileAtomically(temp, path, {
      exclusive,
      expectedParent: parentIdentity,
      testHooks: { beforePublish: () => maybeFault(testHooks, `${pointPrefix}-before-publish`) },
    });
  } catch (error) {
    if (!exclusive || !/File exists|EEXIST|already exists/i.test(error.message)) throw error;
    const existing = await readPrivateFile(path, `${pointPrefix} file`, { recoverExclusive: true, testHooks, parentIdentity });
    if (allowExisting && Buffer.from(existing).equals(Buffer.from(data))) return;
    throw new Error(`${pointPrefix} already exists`);
  }
  await maybeFault(testHooks, `${pointPrefix}-after-rename`);
  await maybeFault(testHooks, `${pointPrefix}-after-dir-sync`);
}

function parseJsonBytes(bytes, label) {
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new Error(`${label} must be valid UTF-8`);
  }
  const value = parseDuplicateSafeJson(text);
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} invalid`);
  return value;
}

function parseActivePointer(bytes) {
  const pointer = parseJsonBytes(bytes, "active pointer");
  const keys = Object.keys(pointer).sort();
  if (canonical(keys) !== canonical(["format", "generation", "record_digest"])) throw new Error("active pointer fields invalid");
  if (pointer.format !== ACTIVE_POINTER_FORMAT) throw new Error("active pointer format invalid");
  if (!Number.isSafeInteger(pointer.generation) || pointer.generation < 1) throw new Error("active pointer generation invalid");
  if (typeof pointer.record_digest !== "string" || !DIGEST_RE.test(pointer.record_digest)) throw new Error("active pointer record digest invalid");
  return Object.freeze({ format: ACTIVE_POINTER_FORMAT, generation: pointer.generation, record_digest: pointer.record_digest });
}

function parseGenerationCommit(bytes, generation, recordDigest) {
  const marker = parseJsonBytes(bytes, "generation commit");
  const keys = Object.keys(marker).sort();
  if (canonical(keys) !== canonical(["format", "generation", "record_digest"])) throw new Error("generation commit fields invalid");
  if (marker.format !== GENERATION_COMMIT_FORMAT) throw new Error("generation commit format invalid");
  if (marker.generation !== generation || marker.record_digest !== recordDigest) throw new Error("generation commit mismatch");
}

function generationLockPath(root, generation) {
  return join(root, "generations", `${generationPrefix(generation)}.${INSTALL_LOCK_SUFFIX}`);
}

function publicGenerationMetadata(record) {
  return Object.freeze({
    identity_kind: record.body.identity_kind,
    identity_value: record.body.identity_value,
    generation: record.body.generation,
    record_digest: record.record_digest,
    envelope_sha256: record.body.envelope_sha256,
    descriptor_digest: record.body.descriptor_digest,
  });
}

function recoveryRequired(message) {
  return new KeyRecoveryRequiredError(message);
}

function expectedUID() {
  return typeof process.getuid === "function" ? process.getuid() : undefined;
}

function validateOwnedMode(info, label, mode, kind) {
  if (kind === "directory" && !info.isDirectory()) throw new Error(`${label} must be directory`);
  if (kind === "file" && !info.isFile()) throw new Error(`${label} must be regular file`);
  if ((info.mode & 0o777) !== mode) throw new Error(`${label} mode must be ${mode.toString(8).padStart(4, "0")}`);
  const uid = expectedUID();
  if (uid !== undefined && info.uid !== uid) throw new Error(`${label} owner must be current uid`);
}

async function ensureExactPrivateDir(path, label, testHooks = undefined) {
  let info;
  let created = false;
  try {
    const linkInfo = await lstat(path);
    if (linkInfo.isSymbolicLink()) throw new Error(`${label} symbolic link rejected`);
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
    try {
      await mkdir(path, { mode: 0o700 });
      created = true;
    } catch (mkdirError) {
      if (mkdirError?.code !== "EEXIST") throw mkdirError;
    }
    if (created) {
      await chmod(path, 0o700);
      await syncDirectory(dirname(path), { testHooks, pointPrefix: `${label} parent` });
    }
  }
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    info = await handle.stat();
  } finally {
    await handle.close();
  }
  validateOwnedMode(info, label, 0o700, "directory");
  if (created) await syncDirectory(path, { testHooks, pointPrefix: label });
  return Object.freeze({ dev: info.dev, ino: info.ino });
}

async function assertPinnedDirectory(path, label, expectedIdentity) {
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const info = await handle.stat();
    validateOwnedMode(info, label, 0o700, "directory");
    if (!sameInode(info, expectedIdentity)) throw new Error(`${label} identity changed`);
  } catch (error) {
    if (error?.code === "ELOOP") throw new Error(`${label} symbolic link rejected`);
    throw error;
  } finally {
    if (handle !== undefined) await handle.close();
  }
}

async function readPrivateFile(path, label, { recoverExclusive = false, testHooks = undefined, parentIdentity = undefined } = {}) {
  if (recoverExclusive) await recoverExclusivePublication(path, label, testHooks, parentIdentity);
  try {
    return (await safeOpenOwnedBytes(path, { testHooks, expectedParent: parentIdentity })).bytes;
  } catch (error) {
    if (error?.code === "ENOENT") throw error;
    if (/owned JSON mode must be 0600/.test(error.message)) throw new Error(`${label} mode must be 0600`);
    if (/owned JSON link count must be 1/.test(error.message)) throw new Error(`${label} link count must be 1`);
    throw error;
  }
}

function exactTempNamePattern(leaf) {
  const escapedLeaf = leaf.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`^\\.${escapedLeaf}\\.[0-9]+\\.[0-9]+\\.[0-9a-f]+\\.tmp$`);
}

function exactQuarantineNamePattern(leaf) {
  const escapedLeaf = leaf.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`^\\.${escapedLeaf}\\.[0-9]+\\.[0-9]+\\.[0-9a-f]+\\.tmp\\.recover$`);
}

function malformedQuarantineNamePattern(leaf) {
  const escapedLeaf = leaf.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`^\\.${escapedLeaf}\\..*\\.tmp\\.recover.*$`);
}

function sameInode(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

async function inspectPrivateFile(path, label, parentIdentity) {
  try {
    const { evidence } = await safeOpenOwnedBytes(path, { expectedParent: parentIdentity, allowedNlinks: [1, 2, 3] });
    return Object.freeze({ dev: evidence.device, ino: evidence.inode, nlink: evidence.nlink });
  } catch (error) {
    if (/owned JSON mode must be 0600/.test(error.message)) throw new Error(`${label} mode must be 0600`);
    throw error;
  }
}

async function recoverExclusivePublication(path, label, testHooks = undefined, parentIdentity = undefined) {
  const canonicalInfo = await inspectPrivateFile(path, label, parentIdentity);
  if (canonicalInfo.nlink === 1) return;
  if (canonicalInfo.nlink !== 2 && canonicalInfo.nlink !== 3) throw new Error(`${label} link count must be 1`);

  const dir = dirname(path);
  const tempPattern = exactTempNamePattern(basename(path));
  const quarantinePattern = exactQuarantineNamePattern(basename(path));
  const malformedQuarantinePattern = malformedQuarantineNamePattern(basename(path));
  const matchingCandidates = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const tempCandidate = tempPattern.test(entry.name);
    const quarantineCandidate = quarantinePattern.test(entry.name);
    if (!tempCandidate && !quarantineCandidate && !malformedQuarantinePattern.test(entry.name)) continue;
    const candidatePath = join(dir, entry.name);
    const candidateInfo = await inspectPrivateFile(candidatePath, `${label} recovery temp`, parentIdentity);
    if (!sameInode(canonicalInfo, candidateInfo)) continue;
    if (!tempCandidate && !quarantineCandidate) throw new Error(`${label} recovery quarantine name malformed`);
    matchingCandidates.push({ path: candidatePath, name: entry.name, type: tempCandidate ? "temp" : "quarantine" });
  }

  let recoveryTemp;
  if (canonicalInfo.nlink === 2) {
    if (matchingCandidates.length !== 1) throw new Error(`${label} link count must be 1`);
    recoveryTemp = matchingCandidates[0].path;
  } else {
    if (matchingCandidates.length !== 2) throw new Error(`${label} link count must be 1`);
    const temp = matchingCandidates.find((candidate) => candidate.type === "temp");
    const quarantine = matchingCandidates.find((candidate) => candidate.type === "quarantine");
    if (temp === undefined || quarantine === undefined || quarantine.name !== `${temp.name}.recover`) {
      throw new Error(`${label} link count must be 1`);
    }
    recoveryTemp = temp.path;
  }

  await repairOwnedLegacyHardLink(path, recoveryTemp, {
    maxBytes: 1024 * 1024,
    expectedParent: parentIdentity,
    testHooks: {
      afterRecoveryInitialStat: () => maybeFault(testHooks, "exclusive-recovery-after-initial-stat"),
      beforeRecoverySwap: () => maybeFault(testHooks, "exclusive-recovery-before-swap"),
    },
  });
  const restoredInfo = await inspectPrivateFile(path, label, parentIdentity);
  if (restoredInfo.nlink !== 1) throw new Error(`${label} link count must be 1`);
}

export class ManagedKeyStore {
  static async open(path, { testHooks = undefined } = {}) {
    if (typeof path !== "string" || path.length === 0) throw new Error("store path invalid");
    const rootIdentity = await ensureExactPrivateDir(path, "managed key store", testHooks);
    const generations = join(path, "generations");
    const generationsIdentity = await ensureExactPrivateDir(generations, "managed key generations directory", testHooks);
    return new ManagedKeyStore(path, testHooks, rootIdentity, generationsIdentity);
  }

  constructor(path, testHooks, rootIdentity, generationsIdentity) {
    this.path = path;
    this.testHooks = testHooks;
    this.rootIdentity = rootIdentity;
    this.generationsIdentity = generationsIdentity;
  }

  async loadActive(passphrase) {
    const scan = await this.#scanCompleteGenerations();
    const activePointer = await this.#readActivePointer();
    if (activePointer === undefined) {
      if (scan.verified.length > 0) throw recoveryRequired("active pointer recovery required");
      throw new Error("active pointer missing");
    }
    const active = scan.verified[activePointer.generation - 1];
    if (active === undefined || active.record.record_digest !== activePointer.record_digest) throw new Error("active pointer mismatch");
    const highest = scan.verified.at(-1);
    if (highest !== undefined && highest.record.body.generation > activePointer.generation) throw recoveryRequired("higher complete generation requires recovery");
    return this.#loadVerified(active, passphrase);
  }

  async loadRecordDigest(recordDigest, passphrase) {
    if (typeof recordDigest !== "string" || !DIGEST_RE.test(recordDigest)) throw new Error("record digest invalid");
    const scan = await this.#scanCompleteGenerations();
    const pinned = scan.verified.find((item) => item.record.record_digest === recordDigest);
    if (pinned === undefined) throw new Error("requested record digest not found");
    return this.#loadVerified(pinned, passphrase);
  }

  async installGeneration({ envelopeBytes, record, descriptor, previousDescriptor = undefined, zoneDescriptor = undefined, zoneRecord = undefined, expectedIdentity = undefined, passphrase }) {
    const normalizedRecord = parseGenerationRecord(Buffer.from(canonical(record)));
    const generation = normalizedRecord.body.generation;
    const releaseLock = await this.#acquireGenerationLock(generation);
    try {
      const activePointer = await this.#readActivePointer();
      const scan = await this.#scanCompleteGenerations();
      if (activePointer !== undefined) {
        const highest = scan.verified.at(-1);
        if (highest === undefined || highest.record.body.generation !== activePointer.generation || highest.record.record_digest !== activePointer.record_digest) throw recoveryRequired("active pointer is not highest verified generation");
        if (generation !== activePointer.generation + 1) throw new Error("generation install is not next active generation");
      } else if (scan.verified.length !== 0 || generation !== 1) {
        throw recoveryRequired("store requires recovery before install");
      }
      const bundle = this.#normalizeInstallBundle({ envelopeBytes, record: normalizedRecord, descriptor, previousDescriptor, zoneDescriptor, zoneRecord });
      const verified = this.#verifyChain([...scan.raw, bundle], undefined).at(-1);
      openKeyEnvelope({ envelopeBytes: bundle.envelopeBytes, passphrase });
      for (const [suffix, bytes] of Object.entries(bundle.files)) {
        await durableWriteFile(generationPath(this.path, generation, suffix), bytes, {
          mode: 0o600,
          pointPrefix: suffix === "previous-descriptor" ? "previous-descriptor" : suffix === "zone-descriptor" ? "zone-descriptor" : suffix,
          testHooks: this.testHooks,
          exclusive: true,
          parentIdentity: this.generationsIdentity,
        });
      }
      const commitBytes = Buffer.from(canonical({ format: GENERATION_COMMIT_FORMAT, generation, record_digest: verified.record.record_digest }));
      await durableWriteFile(generationPath(this.path, generation, "commit"), commitBytes, {
        mode: 0o600,
        pointPrefix: "commit",
        testHooks: this.testHooks,
        exclusive: true,
        parentIdentity: this.generationsIdentity,
      });
      const reloaded = await this.#scanCompleteGenerations();
      const candidate = reloaded.verified.find((item) => item.record.body.generation === generation && item.record.record_digest === verified.record.record_digest);
      if (candidate === undefined) throw new Error("installed generation did not reload");
      if (expectedIdentity !== undefined) {
        if (typeof expectedIdentity !== "object" || expectedIdentity === null || (expectedIdentity.kind !== "aid" && expectedIdentity.kind !== "zid") || typeof expectedIdentity.value !== "string" || expectedIdentity.value === "") throw new Error("expected identity invalid");
        const candidateLoaded = this.#loadVerified(candidate, passphrase);
        try {
          if (candidateLoaded.identity.kind !== expectedIdentity.kind || candidateLoaded.identity.value !== expectedIdentity.value) throw new Error("installed generation identity mismatch");
        } finally {
          candidateLoaded.plaintext.fill(0);
        }
      }
      await this.#writeActivePointer({ generation, record_digest: verified.record.record_digest });
      return this.loadActive(passphrase);
    } finally {
      await releaseLock();
    }
  }

  async recover(passphrase) {
    const scan = await this.#scanCompleteGenerations();
    if (scan.verified.length === 0) throw new Error("no complete generation to recover");
    const highest = scan.verified.at(-1);
    const loaded = this.#loadVerified(highest, passphrase);
    await this.#writeActivePointer({ generation: highest.record.body.generation, record_digest: highest.record.record_digest });
    return loaded;
  }

  #normalizeInstallBundle({ envelopeBytes, record, descriptor, previousDescriptor, zoneDescriptor, zoneRecord }) {
    const envelopeBuffer = Buffer.from(envelopeBytes);
    const recordBytes = Buffer.from(canonical(record));
    const descriptorBytes = Buffer.from(canonical(descriptor));
    const files = { envelope: envelopeBuffer, record: recordBytes, descriptor: descriptorBytes };
    if (record.body.operation === "rotate") {
      const requiresZoneRecord = Object.hasOwn(record.generation_rebinding, "zone_generation");
      if (previousDescriptor === undefined || zoneDescriptor === undefined || (requiresZoneRecord && zoneRecord === undefined)) throw new Error("rotate generation requires descriptor trust material");
      files["previous-descriptor"] = Buffer.from(canonical(previousDescriptor));
      files["zone-descriptor"] = Buffer.from(canonical(zoneDescriptor));
      if (requiresZoneRecord) files["zone-record"] = Buffer.from(canonical(zoneRecord));
    }
    return {
      generation: record.body.generation,
      envelopeBytes: envelopeBuffer,
      record,
      descriptor: parseJsonBytes(descriptorBytes, "descriptor"),
      previousDescriptor: previousDescriptor === undefined ? undefined : parseJsonBytes(files["previous-descriptor"], "previous descriptor"),
      zoneDescriptor: zoneDescriptor === undefined ? undefined : parseJsonBytes(files["zone-descriptor"], "zone descriptor"),
      zoneRecord: zoneRecord === undefined ? undefined : parseGenerationRecord(files["zone-record"]),
      files,
    };
  }

  async #readActivePointer() {
    try {
      return parseActivePointer(await readPrivateFile(join(this.path, "active.json"), "active pointer file", { parentIdentity: this.rootIdentity }));
    } catch (error) {
      if (error?.code === "ENOENT" || /No such file or directory/.test(error?.message)) return undefined;
      throw error;
    }
  }

  async #writeActivePointer(pointer) {
    const bytes = Buffer.from(canonical({ format: ACTIVE_POINTER_FORMAT, generation: pointer.generation, record_digest: pointer.record_digest }));
    await durableWriteFile(join(this.path, "active.json"), bytes, {
      mode: 0o600,
      pointPrefix: "active",
      testHooks: this.testHooks,
      exclusive: false,
      parentIdentity: this.rootIdentity,
    });
  }

  async #acquireGenerationLock(generation) {
    return holdOwnedGenerationLock(generationLockPath(this.path, generation), { expectedParent: this.generationsIdentity });
  }

  async #scanCompleteGenerations() {
    const dir = join(this.path, "generations");
    await assertPinnedDirectory(dir, "managed key generations directory", this.generationsIdentity);
    const entries = await readdir(dir, { withFileTypes: true });
    const groups = new Map();
    for (const entry of entries) {
      const match = /^(\d{16})\.(envelope|record|descriptor|previous-descriptor|zone-descriptor|zone-record|commit|claim)\.json$/.exec(entry.name);
      if (match === null || match[2] === "claim") continue;
      if (entry.isSymbolicLink()) throw new Error(`generation file ${entry.name} symbolic link rejected`);
      if (!entry.isFile()) throw new Error(`generation file ${entry.name} must be regular file`);
      const generation = Number(match[1]);
      if (!Number.isSafeInteger(generation) || generation < 1) throw new Error("generation filename invalid");
      const group = groups.get(generation) ?? { generation, files: {} };
      group.files[match[2]] = join(dir, entry.name);
      groups.set(generation, group);
    }
    const raw = [];
    const readGenerationFile = (path, label) => readPrivateFile(path, label, {
      recoverExclusive: true,
      testHooks: this.testHooks,
      parentIdentity: this.generationsIdentity,
    });
    for (const generation of [...groups.keys()].sort((a, b) => a - b)) {
      const group = groups.get(generation);
      if (!GENERATION_SUFFIXES.every((suffix) => group.files[suffix] !== undefined) || group.files.commit === undefined) continue;
      try {
        const envelopeBytes = await readGenerationFile(group.files.envelope, "generation envelope file");
        const record = parseGenerationRecord(await readGenerationFile(group.files.record, "generation record file"));
        if (record.body.generation !== generation) throw new Error("generation filename mismatch");
        parseGenerationCommit(await readGenerationFile(group.files.commit, "generation commit file"), generation, record.record_digest);
        const descriptor = parseJsonBytes(await readGenerationFile(group.files.descriptor, "generation descriptor file"), "descriptor");
        const item = { generation, envelopeBytes, record, descriptor, previousDescriptor: undefined, zoneDescriptor: undefined, zoneRecord: undefined };
        if (record.body.operation === "rotate") {
          const requiresZoneRecord = Object.hasOwn(record.generation_rebinding, "zone_generation");
          if (group.files["previous-descriptor"] === undefined || group.files["zone-descriptor"] === undefined || (requiresZoneRecord && group.files["zone-record"] === undefined)) throw new Error("rotate generation trust material incomplete");
          item.previousDescriptor = parseJsonBytes(await readGenerationFile(group.files["previous-descriptor"], "previous descriptor file"), "previous descriptor");
          item.zoneDescriptor = parseJsonBytes(await readGenerationFile(group.files["zone-descriptor"], "zone descriptor file"), "zone descriptor");
          if (requiresZoneRecord) item.zoneRecord = parseGenerationRecord(await readGenerationFile(group.files["zone-record"], "zone record file"));
        }
        raw.push(item);
      } catch (error) {
        throw new Error(`malformed complete generation ${generation}: ${error.message}`);
      }
    }
    if (raw.length === 0) return { raw, verified: [] };
    return { raw, verified: this.#verifyChain(raw, undefined) };
  }

  #verifyChain(raw, activePointer) {
    const verifiedRecords = verifyGenerationChain(raw.map((item) => item.record), raw.map((item) => item.envelopeBytes), {
      descriptors: raw.map((item) => item.descriptor),
      previousDescriptors: raw.map((item) => item.previousDescriptor),
      zoneDescriptors: raw.map((item) => item.zoneDescriptor),
      zoneRecords: raw.map((item) => item.zoneRecord),
      activePointer,
    });
    return verifiedRecords.map((record, index) => ({ ...raw[index], record }));
  }

  #loadVerified(item, passphrase) {
    const opened = openKeyEnvelope({ envelopeBytes: item.envelopeBytes, passphrase });
    if (opened.identity.kind !== item.record.body.identity_kind || opened.identity.value !== item.record.body.identity_value) throw new Error("loaded identity mismatch");
    return Object.freeze({
      keyType: opened.keyType,
      identity: opened.identity,
      plaintext: opened.plaintext,
      privateKey: opened.privateKey,
      record: item.record,
      descriptor: structuredClone(item.descriptor),
      keyGeneration: publicGenerationMetadata(item.record),
    });
  }
}
