import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createPrivateKey } from "node:crypto";
import { appendFile, chmod, copyFile, link, mkdir, mkdtemp, readFile, readdir, rename, stat, symlink, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import { agentFromPrivateKey,
canonical,
zoneFromPrivateKey, } from "../asp-core.mjs"
import { createRotationGenerationRecord,
createSignedGenerationRecord,
generationBody,
sealKeyEnvelope, } from "../managed-key.mjs"
import { ERR_KEY_RECOVERY_REQUIRED, ManagedKeyStore } from "../managed-key-store.mjs"

const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const PASSPHRASE = Buffer.from("u10 managed store passphrase\n");
const ZERO_DIGEST = "0".repeat(64);

function seed(start) {
  return Buffer.from(Array.from({ length: 32 }, (_, index) => (start + index) & 0xff));
}

function pkcs8(start) {
  return Buffer.concat([PKCS8_PREFIX, seed(start)]);
}

function privateKey(start) {
  return createPrivateKey({ key: pkcs8(start), format: "der", type: "pkcs8" });
}

function envelopeFor(agent, plaintext, iterations = 100000) {
  return sealKeyEnvelope({ keyType: "ed25519-pkcs8", plaintext, identity: { kind: "aid", value: agent.aid }, passphrase: PASSPHRASE, iterations });
}

function buildStoreChain(iterations = 100000) {
  const previous = agentFromPrivateKey("agent://u10/worker", privateKey(0));
  const next = agentFromPrivateKey("agent://u10/worker", privateKey(64));
  const zone = zoneFromPrivateKey("zone://u10", privateKey(128));
  const envelope1 = envelopeFor(previous, pkcs8(0), iterations);
  const body1 = generationBody({ identity: { kind: "aid", value: previous.aid }, generation: 1, operation: "migrate", envelopeBytes: envelope1, descriptor: previous.descriptor });
  const record1 = createSignedGenerationRecord({ body: body1, privateKey: previous.privateKey });
  const envelope2 = envelopeFor(previous, pkcs8(0), iterations + 1);
  const body2 = generationBody({ identity: { kind: "aid", value: previous.aid }, generation: 2, operation: "rewrap", envelopeBytes: envelope2, descriptor: previous.descriptor, previousRecord: record1 });
  const record2 = createSignedGenerationRecord({ body: body2, privateKey: previous.privateKey });
  const envelope3 = envelopeFor(next, pkcs8(64), iterations + 2);
  const body3 = generationBody({ identity: { kind: "aid", value: next.aid }, generation: 3, operation: "rotate", envelopeBytes: envelope3, descriptor: next.descriptor, previousRecord: record2 });
  const record3 = createRotationGenerationRecord({ body: body3, previousAgent: previous, nextAgent: next, zone });
  return {
    previous,
    next,
    zone,
    items: [
      { envelopeBytes: envelope1, record: record1, descriptor: previous.descriptor },
      { envelopeBytes: envelope2, record: record2, descriptor: previous.descriptor },
      { envelopeBytes: envelope3, record: record3, descriptor: next.descriptor, previousDescriptor: previous.descriptor, zoneDescriptor: zone.descriptor },
    ],
  };
}


function competingSecondGeneration(chain, iterations = 100002) {
  const envelopeBytes = envelopeFor(chain.previous, pkcs8(0), iterations);
  const body = generationBody({
    identity: { kind: "aid", value: chain.previous.aid },
    generation: 2,
    operation: "rewrap",
    envelopeBytes,
    descriptor: chain.previous.descriptor,
    previousRecord: chain.items[0].record,
  });
  const record = createSignedGenerationRecord({ body, privateKey: chain.previous.privateKey });
  return { envelopeBytes, record, descriptor: chain.previous.descriptor };
}
async function newStorePath(name) {
  const root = await mkdtemp(join(tmpdir(), `agnet-${name}-`));
  await chmod(root, 0o700);
  return root;
}

function generationName(generation, suffix) {
  return join("generations", `${String(generation).padStart(16, "0")}.${suffix}.json`);
}

async function install(store, item) {
  return store.installGeneration({ ...item, passphrase: PASSPHRASE });
}

async function writeRawGeneration(root, item) {
  const generation = item.record.body.generation;
  const files = {
    envelope: item.envelopeBytes,
    record: Buffer.from(canonical(item.record)),
    descriptor: Buffer.from(canonical(item.descriptor)),
  };
  if (item.previousDescriptor !== undefined) files["previous-descriptor"] = Buffer.from(canonical(item.previousDescriptor));
  if (item.zoneDescriptor !== undefined) files["zone-descriptor"] = Buffer.from(canonical(item.zoneDescriptor));
  files.commit = Buffer.from(canonical({ format: "agnet-managed-key-generation-commit/v1", generation, record_digest: item.record.record_digest }));
  for (const [suffix, bytes] of Object.entries(files)) {
    await writeFile(join(root, generationName(generation, suffix)), bytes, { mode: 0o600 });
  }
}

async function prepareActivationMatrixStore(root, chain) {
  await ManagedKeyStore.open(root);
  await writeRawGeneration(root, chain.items[0]);
  await writeRawGeneration(root, chain.items[1]);
  await writeFile(join(root, "active.json"), Buffer.from(canonical({
    format: "agnet-managed-key-active/v1",
    generation: 2,
    record_digest: chain.items[1].record.record_digest,
  })), { mode: 0o600 });
}

async function assertActive(store, generation, recordDigest) {
  const loaded = await store.loadActive(PASSPHRASE);
  assert.equal(loaded.keyGeneration.generation, generation);
  assert.equal(loaded.keyGeneration.record_digest, recordDigest);
  assert.equal(loaded.keyGeneration.envelope_sha256.length, 64);
  assert.equal(loaded.identity.value, loaded.keyGeneration.identity_value);
  return loaded;
}

async function assertRecoveryRequired(store) {
  await assert.rejects(store.loadActive(PASSPHRASE), (error) => error?.code === ERR_KEY_RECOVERY_REQUIRED);
}

test("managed key store activates generations durably and exposes exact layout", async () => {
  const root = await newStorePath("u10-layout");
  const unsafeRoot = await newStorePath("u10-unsafe-mode");
  await chmod(unsafeRoot, 0o755);
  await assert.rejects(ManagedKeyStore.open(unsafeRoot), /managed key store mode must be 0700/);
  const symlinkTarget = await newStorePath("u10-root-symlink-target");
  const rootLink = `${symlinkTarget}-link`;
  await symlink(symlinkTarget, rootLink);
  await assert.rejects(ManagedKeyStore.open(rootLink), /symbolic link|symlink/);
  const symlinkGenerationsRoot = await newStorePath("u10-generations-symlink");
  const generationsTarget = await newStorePath("u10-generations-target");
  await symlink(generationsTarget, join(symlinkGenerationsRoot, "generations"));
  await assert.rejects(ManagedKeyStore.open(symlinkGenerationsRoot), /symbolic link|symlink/);
  const chain = buildStoreChain();
  const store = await ManagedKeyStore.open(root);
  const loaded = await install(store, chain.items[0]);
  assert.equal(loaded.keyGeneration.generation, 1);
  assert.equal(loaded.keyGeneration.record_digest, chain.items[0].record.record_digest);
  assert.equal(loaded.keyGeneration.descriptor_digest, chain.items[0].record.body.descriptor_digest);
  assert.equal(loaded.privateKey.asymmetricKeyType, "ed25519");
  assert.equal((await stat(root)).mode & 0o777, 0o700);
  for (const suffix of ["envelope", "record", "descriptor"]) {
    assert.equal((await stat(join(root, generationName(1, suffix)))).mode & 0o777, 0o600);
  }
  const pointer = JSON.parse(await readFile(join(root, "active.json"), "utf8"));
  assert.deepEqual(pointer, { format: "agnet-managed-key-active/v1", generation: 1, record_digest: chain.items[0].record.record_digest });
  await assertActive(await ManagedKeyStore.open(root), 1, chain.items[0].record.record_digest);
});
test("open durably links a newly created store root through its parent", async () => {
  const parent = await newStorePath("u10-new-root-parent-sync");
  const root = join(parent, "store");
  const syncedDirectories = [];
  const opened = await ManagedKeyStore.open(root, {
    testHooks: {
      fault(point) {
        if (point.endsWith("-after-dir-sync")) syncedDirectories.push(point);
      },
    },
  });
  assert.equal(opened.path, root);
  assert.deepEqual(syncedDirectories, ["managed key store parent-after-dir-sync", "managed key store-after-dir-sync", "managed key generations directory parent-after-dir-sync", "managed key generations directory-after-dir-sync"]);

  const failedRoot = join(parent, "failed-store");
  await assert.rejects(
    ManagedKeyStore.open(failedRoot, {
      testHooks: {
        fault(point) {
          if (point === "managed key store parent-after-dir-sync") throw new Error("fault:parent-sync");
        },
      },
    }),
    /fault:parent-sync/,
  );
  assert.equal((await stat(failedRoot)).mode & 0o777, 0o700);
});


test("activation crash matrix preserves authority at every durable leaf stage", async () => {
  const stages = ["after-temp-write", "file-sync", "before-rename", "before-publish", "after-rename", "after-dir-sync"];
  const leaves = ["envelope", "record", "descriptor", "previous-descriptor", "zone-descriptor", "commit", "active"];
  const cases = leaves.flatMap((leaf) => stages.map((stage) => ({ leaf, stage, point: `${leaf}-${stage}` })));
  assert.equal(cases.length, 42);
  const chain = buildStoreChain();
  const oldPointer = Buffer.from(canonical({ format: "agnet-managed-key-active/v1", generation: 2, record_digest: chain.items[1].record.record_digest }));
  const newPointer = Buffer.from(canonical({ format: "agnet-managed-key-active/v1", generation: 3, record_digest: chain.items[2].record.record_digest }));
  const expectedBytes = {
    envelope: chain.items[2].envelopeBytes,
    record: Buffer.from(canonical(chain.items[2].record)),
    descriptor: Buffer.from(canonical(chain.items[2].descriptor)),
    "previous-descriptor": Buffer.from(canonical(chain.items[2].previousDescriptor)),
    "zone-descriptor": Buffer.from(canonical(chain.items[2].zoneDescriptor)),
    commit: Buffer.from(canonical({ format: "agnet-managed-key-generation-commit/v1", generation: 3, record_digest: chain.items[2].record.record_digest })),
    active: newPointer,
  };

  for (const { leaf, stage, point } of cases) {
    const root = await newStorePath(`u10-crash-matrix-${leaf}-${stage}`);
    await prepareActivationMatrixStore(root, chain);
    const crashing = await ManagedKeyStore.open(root, { testHooks: { fault(faultPoint) { if (faultPoint === point) throw new Error(`fault:${point}`); } } });
    await assert.rejects(install(crashing, chain.items[2]), new RegExp(`fault:${point}`));
    const reopened = await ManagedKeyStore.open(root);
    const targetPath = leaf === "active" ? join(root, "active.json") : join(root, generationName(3, leaf));
    const postPublication = stage === "after-rename" || stage === "after-dir-sync";

    if (leaf === "active") {
      if (postPublication) {
        assert.deepEqual(await readFile(targetPath), expectedBytes.active);
        await assertActive(reopened, 3, chain.items[2].record.record_digest);
      } else {
        assert.deepEqual(await readFile(targetPath), oldPointer);
        await assertRecoveryRequired(reopened);
      }
      continue;
    }

    if (!postPublication) {
      await assert.rejects(stat(targetPath), { code: "ENOENT" });
      await assertActive(reopened, 2, chain.items[1].record.record_digest);
      continue;
    }

    assert.deepEqual(await readFile(targetPath), expectedBytes[leaf]);
    if (leaf === "commit") {
      assert.deepEqual(await readFile(join(root, "active.json")), oldPointer);
      await assertRecoveryRequired(reopened);
    } else {
      await assertActive(reopened, 2, chain.items[1].record.record_digest);
    }
  }
});

test("same-generation contenders continue safely after a killed lock holder", async () => {
  const root = await newStorePath("u10-killed-holder-continuation");
  const chain = buildStoreChain();
  const alternate = competingSecondGeneration(chain);
  await install(await ManagedKeyStore.open(root), chain.items[0]);
  const generations = join(root, "generations");
  const generationLock = join(generations, "0000000000000002.install.lock");
  const generationsIdentity = await stat(generations);
  const helper = fileURLToPath(new URL("../secure-input-openat.py", import.meta.url));
  const holder = spawn("/usr/bin/python3", ["-I", helper, "--hold-generation-lock", generationLock, String(process.getuid()), String(generationsIdentity.dev), String(generationsIdentity.ino)], { stdio: ["pipe", "pipe", "pipe"] });
  await new Promise((resolveReady, rejectReady) => {
    let output = "";
    holder.stdout.on("data", (chunk) => {
      output += chunk.toString("utf8");
      if (output.includes("READY\n")) resolveReady();
    });
    holder.once("error", rejectReady);
    holder.once("close", (code) => rejectReady(new Error(`lock holder exited before ready (${code})`)));
  });

  await assert.rejects(install(await ManagedKeyStore.open(root), alternate), /generation install already in progress/);
  holder.kill("SIGKILL");
  await new Promise((resolveClose) => holder.once("close", resolveClose));

  const [primary, contender] = await Promise.allSettled([
    install(await ManagedKeyStore.open(root), chain.items[1]),
    install(await ManagedKeyStore.open(root), alternate),
  ]);
  const outcomes = [primary, contender];
  assert.equal(outcomes.filter((outcome) => outcome.status === "fulfilled").length, 1);
  assert.equal(outcomes.filter((outcome) => outcome.status === "rejected").length, 1);
  const winner = outcomes.find((outcome) => outcome.status === "fulfilled").value;
  const loserDigest = winner.keyGeneration.record_digest === chain.items[1].record.record_digest
    ? alternate.record.record_digest
    : chain.items[1].record.record_digest;
  const pointer = JSON.parse(await readFile(join(root, "active.json"), "utf8"));
  assert.equal(pointer.generation, 2);
  assert.equal(pointer.record_digest, winner.keyGeneration.record_digest);
  assert.notEqual(pointer.record_digest, loserDigest);
  assert.equal((await assertActive(await ManagedKeyStore.open(root), 2, winner.keyGeneration.record_digest)).keyGeneration.record_digest, winner.keyGeneration.record_digest);
  const winnerRecord = winner.keyGeneration.record_digest === chain.items[1].record.record_digest ? chain.items[1].record : alternate.record;
  assert.deepEqual(await readFile(join(root, generationName(2, "record"))), Buffer.from(canonical(winnerRecord)));
});

test("store recovery ignores temps, rejects malformed complete generations, and picks highest authorized", async () => {
  const root = await newStorePath("u10-recover");
  const chain = buildStoreChain();
  const store = await ManagedKeyStore.open(root);
  await install(store, chain.items[0]);
  await writeFile(join(root, "generations", "0000000000000002.record.json.tmp"), Buffer.from("ignored"), { mode: 0o600 });
  await assertActive(await ManagedKeyStore.open(root), 1, chain.items[0].record.record_digest);

  await writeRawGeneration(root, chain.items[1]);
  await assertRecoveryRequired(await ManagedKeyStore.open(root));
  await writeRawGeneration(root, chain.items[2]);
  const recovered = await (await ManagedKeyStore.open(root)).recover(PASSPHRASE);
  assert.equal(recovered.keyGeneration.generation, 3);
  assert.equal(recovered.keyGeneration.record_digest, chain.items[2].record.record_digest);

  const malformedRoot = await newStorePath("u10-malformed");
  const malformedStore = await ManagedKeyStore.open(malformedRoot);
  await install(malformedStore, chain.items[0]);
  await writeRawGeneration(malformedRoot, { ...chain.items[1], record: { ...chain.items[1].record, record_digest: ZERO_DIGEST } });
  await assert.rejects(ManagedKeyStore.open(malformedRoot).then((opened) => opened.loadActive(PASSPHRASE)), /record digest mismatch|malformed complete generation/);
});

test("recovery authenticates the highest generation before changing active authority", async () => {
  const root = await newStorePath("u10-recover-authenticate-first");
  const chain = buildStoreChain();
  const store = await ManagedKeyStore.open(root);
  await install(store, chain.items[0]);
  await writeRawGeneration(root, chain.items[1]);
  const pointerPath = join(root, "active.json");
  const before = await readFile(pointerPath);

  await assert.rejects((await ManagedKeyStore.open(root)).recover(Buffer.from("wrong recovery passphrase")));
  assert.deepEqual(await readFile(pointerPath), before);
  await assertRecoveryRequired(await ManagedKeyStore.open(root));
});

test("legacy L2, L3, and L2Q hard-link recovery copy-swaps authority and retains garbage", async () => {
  for (const state of ["L2", "L3", "L2Q"]) {
    const root = await newStorePath(`u10-legacy-${state}`);
    const chain = buildStoreChain();
    await install(await ManagedKeyStore.open(root), chain.items[0]);
    await writeRawGeneration(root, chain.items[1]);
    const generations = join(root, "generations");
    const canonicalPath = join(root, generationName(2, "commit"));
    const temp = join(generations, `.${basename(canonicalPath)}.1.2.a.tmp`);
    const quarantine = `${temp}.recover`;
    if (state === "L2" || state === "L3") await link(canonicalPath, temp);
    if (state === "L3" || state === "L2Q") await link(canonicalPath, quarantine);

    const reopened = await ManagedKeyStore.open(root);
    const recovered = await reopened.recover(PASSPHRASE);

    assert.equal(recovered.keyGeneration.generation, 2);
    assert.equal((await stat(canonicalPath)).nlink, 1);
    assert.equal((await stat(state === "L2Q" ? quarantine : temp)).nlink, state === "L3" ? 3 : 2);
    await assertActive(await ManagedKeyStore.open(root), 2, chain.items[1].record.record_digest);
  }
});

test("legacy repair failure before swap preserves authority for later recovery", async () => {
  const root = await newStorePath("u10-legacy-fault");
  const chain = buildStoreChain();
  await install(await ManagedKeyStore.open(root), chain.items[0]);

  await writeRawGeneration(root, chain.items[1]);
  const canonicalPath = join(root, generationName(2, "commit"));
  const temp = join(root, "generations", `.${basename(canonicalPath)}.1.2.a.tmp`);
  await link(canonicalPath, temp);
  const pointerBefore = await readFile(join(root, "active.json"));
  const faulting = await ManagedKeyStore.open(root, {
    testHooks: { fault(point) { if (point === "exclusive-recovery-before-swap") throw new Error("fault:legacy-before-swap"); } },
  });

  await assert.rejects(faulting.recover(PASSPHRASE), /fault:legacy-before-swap/);
  assert.deepEqual(await readFile(join(root, "active.json")), pointerBefore);
  const recovered = await (await ManagedKeyStore.open(root)).recover(PASSPHRASE);
  assert.equal(recovered.keyGeneration.generation, 2);
  await assertActive(await ManagedKeyStore.open(root), 2, chain.items[1].record.record_digest);
});

test("legacy repair rejects source growth after Node preflight without promoting authority", async () => {
  const root = await newStorePath("u10-legacy-growth-after-preflight");
  const chain = buildStoreChain();
  await install(await ManagedKeyStore.open(root), chain.items[0]);
  await writeRawGeneration(root, chain.items[1]);
  const canonicalPath = join(root, generationName(2, "commit"));
  const temp = join(root, "generations", `.${basename(canonicalPath)}.1.2.a.tmp`);
  await link(canonicalPath, temp);
  const pointerBefore = await readFile(join(root, "active.json"));
  const faulting = await ManagedKeyStore.open(root, {
    testHooks: {
      async fault(point) {
        if (point === "exclusive-recovery-after-initial-stat") await appendFile(canonicalPath, Buffer.alloc(1024 * 1024 + 1));
      },
    },
  });

  await assert.rejects(faulting.recover(PASSPHRASE), /size limit exceeded/i);
  assert.deepEqual(await readFile(join(root, "active.json")), pointerBefore);
  assert.equal((await stat(canonicalPath)).nlink, 2);
});

test("legacy repair does not delete a raced replacement at the old temp name", async () => {
  const root = await newStorePath("u10-legacy-race");
  const chain = buildStoreChain();
  await install(await ManagedKeyStore.open(root), chain.items[0]);
  await writeRawGeneration(root, chain.items[1]);
  const canonicalPath = join(root, generationName(2, "commit"));
  const temp = join(root, "generations", `.${basename(canonicalPath)}.1.2.a.tmp`);
  await link(canonicalPath, temp);
  const sentinel = Buffer.from("raced replacement survives");
  const recovered = await ManagedKeyStore.open(root, {
    testHooks: {
      async fault(point) {
        if (point === "exclusive-recovery-before-swap") {
          await rename(temp, `${temp}.old`);
          await writeFile(temp, sentinel, { mode: 0o600 });
        }
      },
    },
  });

  await recovered.recover(PASSPHRASE);
  assert.deepEqual(await readFile(temp), sentinel);
  assert.equal((await stat(canonicalPath)).nlink, 1);
});

test("store rejects rollback, replay, pointer substitution, sync failure, and same-generation races", async () => {
  const chain = buildStoreChain();
  const root = await newStorePath("u10-adversarial");
  const store = await ManagedKeyStore.open(root);
  await install(store, chain.items[0]);
  const syncFail = await ManagedKeyStore.open(root, { testHooks: { fault(point) { if (point === "record-file-sync") throw new Error("fault:record-file-sync"); } } });
  await assert.rejects(install(syncFail, chain.items[1]), /fault:record-file-sync/);
  await assertActive(await ManagedKeyStore.open(root), 1, chain.items[0].record.record_digest);
  const unsafeFileRoot = await newStorePath("u10-unsafe-file");
  const unsafeFileStore = await ManagedKeyStore.open(unsafeFileRoot);
  await install(unsafeFileStore, chain.items[0]);
  await chmod(join(unsafeFileRoot, "active.json"), 0o644);
  await assert.rejects(ManagedKeyStore.open(unsafeFileRoot).then((opened) => opened.loadActive(PASSPHRASE)), /active pointer file mode must be 0600/);
  const symlinkPointerRoot = await newStorePath("u10-active-pointer-symlink");
  const symlinkPointerStore = await ManagedKeyStore.open(symlinkPointerRoot);
  await install(symlinkPointerStore, chain.items[0]);
  await unlink(join(symlinkPointerRoot, "active.json"));
  await symlink(join(symlinkPointerRoot, generationName(1, "descriptor")), join(symlinkPointerRoot, "active.json"));
  await assert.rejects(ManagedKeyStore.open(symlinkPointerRoot).then((opened) => opened.loadActive(PASSPHRASE)), /symbolic link|symlink/);
  const hardLinkedPointerRoot = await newStorePath("u10-active-pointer-hard-link");
  const hardLinkedPointerStore = await ManagedKeyStore.open(hardLinkedPointerRoot);
  await install(hardLinkedPointerStore, chain.items[0]);
  await unlink(join(hardLinkedPointerRoot, "active.json"));
  await link(join(hardLinkedPointerRoot, generationName(1, "descriptor")), join(hardLinkedPointerRoot, "active.json"));
  await assert.rejects(ManagedKeyStore.open(hardLinkedPointerRoot).then((opened) => opened.loadActive(PASSPHRASE)), /link count must be 1/);
  const symlinkFileRoot = await newStorePath("u10-file-symlink");
  const symlinkFileStore = await ManagedKeyStore.open(symlinkFileRoot);
  await install(symlinkFileStore, chain.items[0]);
  await unlink(join(symlinkFileRoot, generationName(1, "envelope")));
  await symlink(join(symlinkFileRoot, generationName(1, "descriptor")), join(symlinkFileRoot, generationName(1, "envelope")));
  await assert.rejects(ManagedKeyStore.open(symlinkFileRoot).then((opened) => opened.loadActive(PASSPHRASE)), /symbolic link|symlink/);

  const staleClaimRoot = await newStorePath("u10-stale-claim");
  const staleClaimStore = await ManagedKeyStore.open(staleClaimRoot);
  await install(staleClaimStore, chain.items[0]);
  await writeFile(join(staleClaimRoot, "generations", "0000000000000002.claim.json"), Buffer.from(canonical({ format: "agnet-managed-key-install-claim/v1", generation: 2, pid: -1 })), { mode: 0o600 });
  await assertActive(await ManagedKeyStore.open(staleClaimRoot).then((opened) => opened.installGeneration({ ...chain.items[1], passphrase: PASSPHRASE }).then(() => opened)), 2, chain.items[1].record.record_digest);

  const rotatePartialRoot = await newStorePath("u10-rotate-partial");
  const rotatePartialStore = await ManagedKeyStore.open(rotatePartialRoot);
  await install(rotatePartialStore, chain.items[0]);
  await install(rotatePartialStore, chain.items[1]);
  for (const suffix of ["envelope", "record", "descriptor"]) {
    const bytes = suffix === "envelope" ? chain.items[2].envelopeBytes : Buffer.from(canonical(suffix === "record" ? chain.items[2].record : chain.items[2].descriptor));
    await writeFile(join(rotatePartialRoot, generationName(3, suffix)), bytes, { mode: 0o600 });
  }
  await assertActive(await ManagedKeyStore.open(rotatePartialRoot), 2, chain.items[1].record.record_digest);
  await writeFile(join(rotatePartialRoot, generationName(3, "commit")), Buffer.from(canonical({ format: "agnet-managed-key-generation-commit/v1", generation: 3, record_digest: chain.items[2].record.record_digest })), { mode: 0o600 });
  await assert.rejects(ManagedKeyStore.open(rotatePartialRoot).then((opened) => opened.loadActive(PASSPHRASE)), /trust material incomplete|malformed complete generation/);


  const racerA = await ManagedKeyStore.open(root);
  const racerB = await ManagedKeyStore.open(root);
  const outcomes = await Promise.allSettled([install(racerA, chain.items[1]), install(racerB, chain.items[1])]);
  assert.equal(outcomes.filter((outcome) => outcome.status === "fulfilled").length, 1, outcomes.map((outcome) => outcome.status === "rejected" ? outcome.reason?.stack : "fulfilled").join(" | "));
  assert.equal(outcomes.filter((outcome) => outcome.status === "rejected").length, 1);
  await assertActive(await ManagedKeyStore.open(root), 2, chain.items[1].record.record_digest);

  await writeFile(join(root, "active.json"), Buffer.from(canonical({ format: "agnet-managed-key-active/v1", generation: 1, record_digest: chain.items[0].record.record_digest })), { mode: 0o600 });
  await assertRecoveryRequired(await ManagedKeyStore.open(root));
  await writeFile(join(root, "active.json"), Buffer.from(canonical({ format: "agnet-managed-key-active/v1", generation: 2, record_digest: ZERO_DIGEST })), { mode: 0o600 });
  await assert.rejects(ManagedKeyStore.open(root).then((opened) => opened.loadActive(PASSPHRASE)), /active pointer mismatch|record digest/);

  const replayRoot = await newStorePath("u10-replay");
  const replayStore = await ManagedKeyStore.open(replayRoot);
  await install(replayStore, chain.items[0]);
  await writeRawGeneration(replayRoot, chain.items[1]);
  for (const suffix of ["envelope", "record", "descriptor", "commit"]) {
    await copyFile(join(replayRoot, generationName(2, suffix)), join(replayRoot, generationName(3, suffix)));
  }
  await assert.rejects(ManagedKeyStore.open(replayRoot).then((opened) => opened.recover(PASSPHRASE)), /generation filename mismatch|contiguous|replay/);
});

test("opened store rejects replay-tree substitution of pinned root and generations directories", async () => {
  const root = await newStorePath("u10-directory-pins");
  const chain = buildStoreChain();
  const rootPinned = await ManagedKeyStore.open(root);
  await install(rootPinned, chain.items[0]);

  const retainedRoot = `${root}-retained`;
  await rename(root, retainedRoot);
  await mkdir(root, { mode: 0o700 });
  await chmod(root, 0o700);
  await mkdir(join(root, "generations"), { mode: 0o700 });
  await chmod(join(root, "generations"), 0o700);
  await assert.rejects(rootPinned.loadActive(PASSPHRASE), /parent identity changed|directory identity changed/);

  const generationsRoot = await newStorePath("u10-generations-directory-pin");
  const generationsPinned = await ManagedKeyStore.open(generationsRoot);
  await install(generationsPinned, chain.items[0]);
  const retainedGenerations = join(generationsRoot, "generations-retained");
  await rename(join(generationsRoot, "generations"), retainedGenerations);
  await mkdir(join(generationsRoot, "generations"), { mode: 0o700 });
  await chmod(join(generationsRoot, "generations"), 0o700);
  await assert.rejects(generationsPinned.loadActive(PASSPHRASE), /parent identity changed|directory identity changed/);
});
