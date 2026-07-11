import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { appendFile, chmod, link, mkdir, mkdtemp, rename, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { promisify } from "node:util";

import { canonical, createAgent, createZone, decodeBase64UrlExact, deriveSwarmFinalOutput, signObject, signedReceiptDigest, swarmExecutionBinding, swarmPlan, verifySwarmExecutionBinding, verifySwarmPlan, zoneBinding, zoneRevocation } from "./asp-core.mjs";
import { safeOpenOwnedJson } from "./secure-input.mjs";
import { applySwarmOutputVerificationReplay, createSwarmOutputTrustInputsForTest, createSwarmOutputVerification, loadSwarmOutputTrustInputs, verifySwarmOutputVerification } from "./swarm-output-verification.mjs";

const MAX_INPUT_BYTES = 1024 * 1024;
const execFileAsync = promisify(execFile);

function reverseKeys(value) {
  if (Array.isArray(value)) return value.map(reverseKeys);
  if (value === null || typeof value !== "object") return value;
  return Object.fromEntries(Object.entries(value).reverse().map(([key, item]) => [key, reverseKeys(item)]));
}

function fixture() {
  const zone = createZone("zone://output-verifiers");
  const verifier = createAgent(
    "agent://local/output-verifier",
    { allow_network: false, write_prefixes: ["artifact://local/"] },
    ["asp+local://output-verifier"],
    ["self.declared.only"],
  );
  const binding = zoneBinding(zone, verifier.descriptor);
  const revocation = zoneRevocation(zone, "aid:ed25519:retired-output-verifier", "retired");
  return {
    zone,
    verifier,
    allowlist: {
      format: "asp-swarm-output-verifier-allowlist/v1",
      verifiers: [{ descriptor: verifier.descriptor, zone_binding: binding, authorizations: ["swarm.output.verify"] }],
    },
    trustedZones: {
      format: "asp-swarm-output-trusted-zones/v1",
      zones: [zone.descriptor],
    },
    revocations: {
      format: "asp-swarm-output-revocations/v1",
      revocations: [revocation],
    },
  };
}

async function workspace(t, name = "agnet-u4-node-") {
  const dir = await mkdtemp(join(tmpdir(), name));
  await chmod(dir, 0o700);
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

async function writeSecureJson(path, value, raw = null) {
  await writeFile(path, raw ?? `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  await chmod(path, 0o600);
}

async function writeFixture(t, values = fixture()) {
  const dir = await workspace(t);
  const paths = {
    allowlist: join(dir, "allowlist.json"),
    trustedZones: join(dir, "trusted-zones.json"),
    revocations: join(dir, "revocations.json"),
  };
  await Promise.all([
    writeSecureJson(paths.allowlist, values.allowlist),
    writeSecureJson(paths.trustedZones, values.trustedZones),
    writeSecureJson(paths.revocations, values.revocations),
  ]);
  return { dir, paths, values };
}

function clone(value) {
  return structuredClone(value);
}

function injectDuplicate(raw, key) {
  const needle = `${JSON.stringify(key)}:`;
  const index = raw.indexOf(needle);
  assert.notEqual(index, -1, `missing key ${key}`);
  const valueStart = index + needle.length;
  let cursor = valueStart;
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (; cursor < raw.length; cursor += 1) {
    const char = raw[cursor];
    if (inString) {
      if (escaped) escaped = false;
      else if (char === "\\") escaped = true;
      else if (char === '"') inString = false;
      continue;
    }
    if (char === '"') inString = true;
    else if (char === "{" || char === "[") depth += 1;
    else if (char === "}" || char === "]") {
      if (depth === 0) break;
      depth -= 1;
    } else if (char === "," && depth === 0) break;
  }
  const encodedValue = raw.slice(valueStart, cursor).trim();
  return `${raw.slice(0, index)}${JSON.stringify(key)}:${encodedValue},${raw.slice(index)}`;
}

test("loadSwarmOutputTrustInputs safely verifies and freezes exact trust snapshots", async (t) => {
  const { paths, values } = await writeFixture(t);
  const trust = await loadSwarmOutputTrustInputs(paths);

  assert.equal(trust.allowlist.format, values.allowlist.format);
  assert.equal(trust.trusted_zones.format, values.trustedZones.format);
  assert.equal(trust.revocations.format, values.revocations.format);
  assert.match(trust.trust_inputs_digest, /^[0-9a-f]{64}$/);
  assert.equal(
    trust.trust_inputs_digest,
    (await createSwarmOutputTrustInputsForTest(values.allowlist, values.trustedZones, values.revocations)).trust_inputs_digest,
  );
  assert.equal(Object.isFrozen(trust), true);
  assert.equal(Object.isFrozen(trust.allowlist.verifiers[0].descriptor.policy.write_prefixes), true);
  assert.throws(() => trust.allowlist.verifiers.push({}), TypeError);

  for (const [name, evidence] of Object.entries(trust.evidence)) {
    assert.equal(evidence.path, paths[name === "trusted_zones" ? "trustedZones" : name]);
    assert.equal(typeof evidence.device, "number");
    assert.equal(typeof evidence.inode, "number");
    assert.equal(evidence.uid, process.getuid());
    assert.equal(evidence.mode, 0o600);
    assert.equal(evidence.nlink, 1);
    assert.equal(evidence.schema_format, trust[name].format);
    assert.match(evidence.snapshot_digest, /^[0-9a-f]{64}$/);
  }
});

test("safeOpenOwnedJson rejects unsafe filesystem inputs and oversized JSON", async (t) => {
  const dir = await workspace(t);
  const safe = join(dir, "safe.json");
  await writeSecureJson(safe, { ok: true });
  const opened = await safeOpenOwnedJson(safe);
  assert.deepEqual(opened.value, { ok: true });
  assert.equal(opened.evidence.nlink, 1);

  const symlinkPath = join(dir, "symlink.json");
  await symlink(safe, symlinkPath);
  await assert.rejects(() => safeOpenOwnedJson(symlinkPath), /no-follow|symbolic link/i);

  const symlinkTarget = join(dir, "symlink-target");
  await mkdir(symlinkTarget, { mode: 0o700 });
  await chmod(symlinkTarget, 0o700);
  const symlinkTargetFile = join(symlinkTarget, "input.json");
  await writeSecureJson(symlinkTargetFile, { ok: true });
  const symlinkParent = join(dir, "symlink-parent");
  await symlink(symlinkTarget, symlinkParent);
  await assert.rejects(() => safeOpenOwnedJson(join(symlinkParent, "input.json")), /unsafe parent symbolic link/i);

  const hardlinkPath = join(dir, "hardlink.json");
  await link(safe, hardlinkPath);
  await assert.rejects(() => safeOpenOwnedJson(safe), /link count/i);
  await rm(hardlinkPath);

  await assert.rejects(() => safeOpenOwnedJson(dir), /regular file/i);
  await assert.rejects(() => safeOpenOwnedJson("/dev/null"), /regular file/i);

  const nonObject = join(dir, "non-object.json");
  await writeSecureJson(nonObject, [], "[]");
  await assert.rejects(() => safeOpenOwnedJson(nonObject), /root must be an object/i);

  await chmod(safe, 0o644);
  await assert.rejects(() => safeOpenOwnedJson(safe), /mode.*0600/i);
  await chmod(safe, 0o600);

  const unsafeParent = join(dir, "unsafe-parent");
  await mkdir(unsafeParent, { mode: 0o777 });
  await chmod(unsafeParent, 0o777);
  const unsafeChild = join(unsafeParent, "input.json");
  await writeSecureJson(unsafeChild, { ok: true });
  await assert.rejects(() => safeOpenOwnedJson(unsafeChild), /unsafe parent/i);

  const oversized = join(dir, "oversized.json");
  await writeFile(oversized, `{"value":"${"x".repeat(MAX_INPUT_BYTES)}"}`, { mode: 0o600 });
  await chmod(oversized, 0o600);
  await assert.rejects(() => safeOpenOwnedJson(oversized), /size limit/i);
});

test("safeOpenOwnedJson binds the final open to a verified parent handle", async (t) => {
  const dir = await workspace(t);
  const parent = join(dir, "parent");
  const moved = join(dir, "verified-parent");
  await mkdir(parent, { mode: 0o700 });
  await chmod(parent, 0o700);
  const path = join(parent, "input.json");
  await writeSecureJson(path, { source: "verified-parent" });
  let hookCalled = false;

  const opened = await safeOpenOwnedJson(path, {
    afterParentVerified: async () => {
      hookCalled = true;
      await rename(parent, moved);
      await mkdir(parent, { mode: 0o700 });
      await chmod(parent, 0o700);
      await writeSecureJson(path, { source: "rebound-path" });
    },
  });

  assert.equal(hookCalled, true);
  assert.deepEqual(opened.value, { source: "verified-parent" });
});

test("safeOpenOwnedJson re-fstats the final handle after reading", async (t) => {
  const dir = await workspace(t);
  const path = join(dir, "input.json");
  await writeSecureJson(path, { ok: true });
  let hookCalled = false;

  await assert.rejects(
    () => safeOpenOwnedJson(path, {
      afterRead: async () => {
        hookCalled = true;
        await chmod(path, 0o644);
      },
    }),
    /changed during read/i,
  );
  assert.equal(hookCalled, true);
});

test("safeOpenOwnedJson bounds a file that grows after the initial fstat", async (t) => {
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

test("safeOpenOwnedJson enforces normal parser nesting and entry errors", async (t) => {
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

test("safeOpenOwnedJson scans many numbers in linear time", async (t) => {
  const dir = await workspace(t);
  const path = join(dir, "many-numbers.json");
  await writeSecureJson(path, null, `{"values":[${"1,".repeat(49_999)}1]}`);
  const started = performance.now();
  const opened = await safeOpenOwnedJson(path);
  const elapsed = performance.now() - started;
  assert.equal(opened.value.values.length, 50_000);
  assert.ok(elapsed < 5_000, `many-number parse took ${elapsed}ms`);
});

test("safeOpenOwnedJson rejects owner mismatch through the current-UID seam", async (t) => {
  const dir = await workspace(t);
  const path = join(dir, "owner.json");
  await writeSecureJson(path, { ok: true });
  const actualUID = process.getuid();
  t.mock.method(process, "getuid", () => actualUID + 1);
  await assert.rejects(() => safeOpenOwnedJson(path), /owner mismatch/i);
});

test("duplicate JSON keys are rejected before object construction at every schema nesting", async (t) => {
  const base = fixture();
  const cases = [
    ["allowlist top", "allowlist", "format"],
    ["allowlist verifier", "allowlist", "authorizations"],
    ["verifier descriptor", "allowlist", "aid"],
    ["verifier policy", "allowlist", "allow_network"],
    ["zone binding", "allowlist", "zone"],
    ["trusted zones top", "trustedZones", "format"],
    ["zone descriptor", "trustedZones", "zid"],
    ["revocations top", "revocations", "format"],
    ["revocation entry", "revocations", "subject"],
  ];
  for (const [name, target, key] of cases) {
    await t.test(name, async (subtest) => {
      const { paths, values } = await writeFixture(subtest, fixture());
      const raw = JSON.stringify(values[target]);
      await writeSecureJson(paths[target], values[target], injectDuplicate(raw, key));
      await assert.rejects(() => loadSwarmOutputTrustInputs(paths), /duplicate JSON key/i);
    });
  }
  assert.equal(base.allowlist.format, "asp-swarm-output-verifier-allowlist/v1");
});

test("unknown JSON keys are rejected at every schema nesting", async (t) => {
  const mutations = [
    ["allowlist top", (v) => { v.allowlist.unknown = true; }],
    ["allowlist verifier", (v) => { v.allowlist.verifiers[0].unknown = true; }],
    ["verifier descriptor", (v) => { v.allowlist.verifiers[0].descriptor.unknown = true; }],
    ["verifier policy", (v) => { v.allowlist.verifiers[0].descriptor.policy.unknown = true; }],
    ["zone binding", (v) => { v.allowlist.verifiers[0].zone_binding.unknown = true; }],
    ["trusted zones top", (v) => { v.trustedZones.unknown = true; }],
    ["zone descriptor", (v) => { v.trustedZones.zones[0].unknown = true; }],
    ["revocations top", (v) => { v.revocations.unknown = true; }],
    ["revocation entry", (v) => { v.revocations.revocations[0].unknown = true; }],
  ];
  for (const [name, mutate] of mutations) {
    await t.test(name, async (subtest) => {
      const values = fixture();
      mutate(values);
      const { paths } = await writeFixture(subtest, values);
      await assert.rejects(() => loadSwarmOutputTrustInputs(paths), /unknown|exact schema/i);
    });
  }
});

test("wrong formats, duplicate identities, and missing exact authorization fail closed", async (t) => {
  const mutations = [
    ["allowlist format", (v) => { v.allowlist.format = "wrong"; }, /allowlist format/i],
    ["trusted zones format", (v) => { v.trustedZones.format = "wrong"; }, /trusted zones format/i],
    ["revocations format", (v) => { v.revocations.format = "wrong"; }, /revocations format/i],
    ["duplicate verifier", (v) => { v.allowlist.verifiers.push(clone(v.allowlist.verifiers[0])); }, /duplicate verifier/i],
    ["duplicate zone", (v) => { v.trustedZones.zones.push(clone(v.trustedZones.zones[0])); }, /duplicate trusted zone/i],
    ["duplicate revocation", (v) => { v.revocations.revocations.push(clone(v.revocations.revocations[0])); }, /duplicate revocation/i],
    ["missing authorization", (v) => { v.allowlist.verifiers[0].authorizations = ["swarm.output.read"]; }, /swarm\.output\.verify authorization/i],
    ["revoked verifier", (v) => { v.revocations.revocations = [zoneRevocation(v.zone, v.verifier.aid, "revoked")]; }, /verifier revoked/i],
    ["revoked trusted Zone", (v) => { v.revocations.revocations = [zoneRevocation(v.zone, v.zone.zid, "revoked")]; }, /trusted zone revoked/i],
  ];
  for (const [name, mutate, message] of mutations) {
    await t.test(name, async (subtest) => {
      const values = fixture();
      mutate(values);
      const { paths } = await writeFixture(subtest, values);
      await assert.rejects(() => loadSwarmOutputTrustInputs(paths), message);
    });
  }
});

test("revocations are authorized only within their issuer Zone", () => {
  const zoneA = createZone("zone://a");
  const zoneB = createZone("zone://b");
  const verifierB = createAgent("agent://zone-b/verifier", {}, ["asp+local://zone-b/verifier"], []);
  const allowlist = {
    format: "asp-swarm-output-verifier-allowlist/v1",
    verifiers: [{
      descriptor: verifierB.descriptor,
      zone_binding: zoneBinding(zoneB, verifierB.descriptor),
      authorizations: ["swarm.output.verify"],
    }],
  };
  const trustedZones = {
    format: "asp-swarm-output-trusted-zones/v1",
    zones: [zoneA.descriptor, zoneB.descriptor],
  };
  const revocations = (entries) => ({ format: "asp-swarm-output-revocations/v1", revocations: entries });

  assert.throws(
    () => createSwarmOutputTrustInputsForTest(
      allowlist,
      trustedZones,
      revocations([zoneRevocation(zoneA, verifierB.aid, "cross-zone aid")]),
    ),
    /out-of-scope.*revocation/i,
  );
  assert.throws(
    () => createSwarmOutputTrustInputsForTest(
      allowlist,
      trustedZones,
      revocations([zoneRevocation(zoneA, verifierB.alias, "cross-zone alias")]),
    ),
    /out-of-scope.*revocation/i,
  );
  assert.throws(
    () => createSwarmOutputTrustInputsForTest(
      allowlist,
      trustedZones,
      revocations([zoneRevocation(zoneA, zoneB.zid, "cross-zone Zone")]),
    ),
    /out-of-scope.*revocation/i,
  );
  assert.throws(
    () => createSwarmOutputTrustInputsForTest(
      allowlist,
      trustedZones,
      revocations([zoneRevocation(zoneB, verifierB.aid, "same-zone aid")]),
    ),
    /verifier revoked/i,
  );
  assert.throws(
    () => createSwarmOutputTrustInputsForTest(
      allowlist,
      trustedZones,
      revocations([zoneRevocation(zoneB, verifierB.alias, "same-zone alias")]),
    ),
    /verifier revoked/i,
  );
  assert.throws(
    () => createSwarmOutputTrustInputsForTest(
      allowlist,
      trustedZones,
      revocations([zoneRevocation(zoneB, zoneB.zid, "self-revocation")]),
    ),
    /trusted zone revoked/i,
  );
});

test("invalid verifier, Zone, binding, and revocation signatures fail closed", async (t) => {
  const mutations = [
    ["verifier descriptor", (v) => { v.allowlist.verifiers[0].descriptor.descriptor_signature = "bad"; }, /descriptor signature/i],
    ["Zone descriptor", (v) => { v.trustedZones.zones[0].zone_signature = "bad"; }, /zone signature/i],
    ["Zone binding", (v) => { v.allowlist.verifiers[0].zone_binding.signature = "bad"; }, /zone binding signature/i],
    ["revocation", (v) => { v.revocations.revocations[0].signature = "bad"; }, /revocation signature/i],
  ];
  for (const [name, mutate, message] of mutations) {
    await t.test(name, async (subtest) => {
      const values = fixture();
      mutate(values);
      const { paths } = await writeFixture(subtest, values);
      await assert.rejects(() => loadSwarmOutputTrustInputs(paths), message);
    });
  }
});
test("one identity ownership map rejects AID and alias collisions", () => {
  const zone = createZone("zone://identity-owner");
  const build = (descriptors) => createSwarmOutputTrustInputsForTest(
    {
      format: "asp-swarm-output-verifier-allowlist/v1",
      verifiers: descriptors.map((descriptor) => ({
        descriptor,
        zone_binding: zoneBinding(zone, descriptor),
        authorizations: ["swarm.output.verify"],
      })),
    },
    { format: "asp-swarm-output-trusted-zones/v1", zones: [zone.descriptor] },
    { format: "asp-swarm-output-revocations/v1", revocations: [] },
  );

  const first = createAgent("agent://identity/first");
  const aliasEqualsAid = createAgent(first.aid);
  assert.throws(() => build([first.descriptor, aliasEqualsAid.descriptor]), /duplicate verifier identity/i);

  const second = createAgent("agent://identity/second");
  const aidEqualsAlias = createAgent(second.aid);
  assert.throws(() => build([aidEqualsAlias.descriptor, second.descriptor]), /duplicate verifier identity/i);

  const self = createAgent("agent://identity/self");
  const selfBody = { ...self.descriptor, alias: self.aid };
  delete selfBody.descriptor_signature;
  const selfDescriptor = { ...selfBody, descriptor_signature: signObject(self.privateKey, selfBody) };
  assert.throws(() => build([selfDescriptor]), /duplicate verifier identity/i);
});

test("fixed U4 base64url vectors match the cross-language domain", () => {
  assert.deepEqual([...decodeBase64UrlExact("AA")], [0]);
  for (const invalid of ["AB", "AA==", "AA\n", "AA+/"]) {
    assert.throws(() => decodeBase64UrlExact(invalid), /exact unpadded base64url/i);
  }
});

test("fixed U4 canonical key ordering uses UTF-8 bytes", () => {
  assert.equal(canonical({ "\u{10000}": 1, "\ue000": 2 }), "{\"\":2,\"𐀀\":1}");
});

function nonCanonicalTrailingBits(encoded) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const last = alphabet.indexOf(encoded.at(-1));
  assert.notEqual(last, -1);
  return `${encoded.slice(0, -1)}${alphabet[(last & 0b111100) | 0b000001]}`;
}

test("trust inputs reject non-scalar canonical strings", async (t) => {
  const mutations = [
    ["unpaired surrogate alias", (v) => { v.allowlist.verifiers[0].descriptor.alias = "agent://bad/\ud800"; }],
    ["U+2028 verifier aid", (v) => { v.allowlist.verifiers[0].descriptor.aid += "\u2028bad"; }],
    ["U+2029 verifier did_key", (v) => { v.allowlist.verifiers[0].descriptor.did_key += "\u2029bad"; }],
    ["U+2028 verifier public_key_spki", (v) => { v.allowlist.verifiers[0].descriptor.public_key_spki += "\u2028bad"; }],
    ["U+2029 verifier descriptor_signature", (v) => { v.allowlist.verifiers[0].descriptor.descriptor_signature += "\u2029bad"; }],
    ["U+2028 zone name", (v) => { v.trustedZones.zones[0].name += "\u2028bad"; }],
    ["U+2028 zone zid", (v) => { v.trustedZones.zones[0].zid += "\u2028bad"; }],
    ["U+2029 zone public_key_spki", (v) => { v.trustedZones.zones[0].public_key_spki += "\u2029bad"; }],
    ["U+2028 zone signature", (v) => { v.trustedZones.zones[0].zone_signature += "\u2028bad"; }],
    ["U+2029 binding alias", (v) => { v.allowlist.verifiers[0].zone_binding.alias += "\u2029bad"; }],
    ["U+2028 binding zone", (v) => { v.allowlist.verifiers[0].zone_binding.zone += "\u2028bad"; }],
    ["U+2029 binding aid", (v) => { v.allowlist.verifiers[0].zone_binding.aid += "\u2029bad"; }],
    ["U+2028 binding signature", (v) => { v.allowlist.verifiers[0].zone_binding.signature += "\u2028bad"; }],
    ["U+2028 transport", (v) => { v.allowlist.verifiers[0].descriptor.transports = ["asp+local://bad\u2028transport"]; }],
    ["U+2029 capability", (v) => { v.allowlist.verifiers[0].descriptor.capabilities = ["bad\u2029capability"]; }],
    ["U+2028 policy prefix", (v) => { v.allowlist.verifiers[0].descriptor.policy.write_prefixes = ["artifact://bad\u2028"]; }],
    ["U+2029 authorization", (v) => { v.allowlist.verifiers[0].authorizations = ["swarm.output.verify", "bad\u2029authorization"]; }],
    ["U+2028 revocation reason", (v) => { v.revocations.revocations[0].reason += "\u2028bad"; }],
    ["U+2029 revocation zone", (v) => { v.revocations.revocations[0].zone += "\u2029bad"; }],
    ["U+2028 revocation subject", (v) => { v.revocations.revocations[0].subject += "\u2028bad"; }],
    ["U+2029 revocation signature", (v) => { v.revocations.revocations[0].signature += "\u2029bad"; }],
  ];
  for (const [name, mutate] of mutations) {
    await t.test(name, () => {
      const values = fixture();
      mutate(values);
      assert.throws(
        () => createSwarmOutputTrustInputsForTest(values.allowlist, values.trustedZones, values.revocations),
        /canonical string domain|unicode scalar/i,
      );
    });
  }

  const dir = await workspace(t);
  const path = join(dir, "unpaired.json");
  await writeSecureJson(path, null, String.raw`{"value":"\ud800"}`);
  await assert.rejects(() => safeOpenOwnedJson(path), /canonical string domain|unicode scalar/i);
});

test("trust signatures and SPKI require exact unpadded base64url", () => {
  const paddedSignature = fixture();
  paddedSignature.trustedZones.zones[0].zone_signature += "=";
  assert.throws(
    () => createSwarmOutputTrustInputsForTest(paddedSignature.allowlist, paddedSignature.trustedZones, paddedSignature.revocations),
    /exact unpadded base64url/i,
  );

  const whitespaceSignature = fixture();
  whitespaceSignature.trustedZones.zones[0].zone_signature += "\n";
  assert.throws(
    () => createSwarmOutputTrustInputsForTest(whitespaceSignature.allowlist, whitespaceSignature.trustedZones, whitespaceSignature.revocations),
    /exact unpadded base64url/i,
  );

  const trailingBitsSignature = fixture();
  trailingBitsSignature.trustedZones.zones[0].zone_signature = nonCanonicalTrailingBits(
    trailingBitsSignature.trustedZones.zones[0].zone_signature,
  );
  assert.throws(
    () => createSwarmOutputTrustInputsForTest(trailingBitsSignature.allowlist, trailingBitsSignature.trustedZones, trailingBitsSignature.revocations),
    /exact unpadded base64url/i,
  );

  const paddedDescriptorSignature = fixture();
  paddedDescriptorSignature.allowlist.verifiers[0].descriptor.descriptor_signature += "=";
  assert.throws(
    () => createSwarmOutputTrustInputsForTest(paddedDescriptorSignature.allowlist, paddedDescriptorSignature.trustedZones, paddedDescriptorSignature.revocations),
    /exact unpadded base64url/i,
  );

  const paddedBindingSignature = fixture();
  paddedBindingSignature.allowlist.verifiers[0].zone_binding.signature += "=";
  assert.throws(
    () => createSwarmOutputTrustInputsForTest(paddedBindingSignature.allowlist, paddedBindingSignature.trustedZones, paddedBindingSignature.revocations),
    /exact unpadded base64url/i,
  );

  const paddedRevocationSignature = fixture();
  paddedRevocationSignature.revocations.revocations[0].signature += "=";
  assert.throws(
    () => createSwarmOutputTrustInputsForTest(paddedRevocationSignature.allowlist, paddedRevocationSignature.trustedZones, paddedRevocationSignature.revocations),
    /exact unpadded base64url/i,
  );

  const paddedSPKI = fixture();
  const descriptor = paddedSPKI.trustedZones.zones[0];
  descriptor.public_key_spki += "=";
  const { zone_signature: _signature, ...body } = descriptor;
  descriptor.zone_signature = signObject(paddedSPKI.zone.privateKey, body);
  assert.throws(
    () => createSwarmOutputTrustInputsForTest(paddedSPKI.allowlist, paddedSPKI.trustedZones, paddedSPKI.revocations),
    /exact unpadded base64url/i,
  );
});


test("canonical trust digest ignores input formatting and object key order", async (t) => {
  const first = await writeFixture(t, fixture());
  const second = await writeFixture(t, fixture());
  second.values = first.values;
  await Promise.all([
    writeSecureJson(second.paths.allowlist, first.values.allowlist, JSON.stringify(reverseKeys(first.values.allowlist))),
    writeSecureJson(second.paths.trustedZones, first.values.trustedZones, JSON.stringify(reverseKeys(first.values.trustedZones), null, 4)),
    writeSecureJson(second.paths.revocations, first.values.revocations, `\n${JSON.stringify(reverseKeys(first.values.revocations))}\n`),
  ]);
  const [left, right] = await Promise.all([
    loadSwarmOutputTrustInputs(first.paths),
    loadSwarmOutputTrustInputs(second.paths),
  ]);
  assert.equal(left.trust_inputs_digest, right.trust_inputs_digest);
  assert.equal(
    left.trust_inputs_digest,
    (await createSwarmOutputTrustInputsForTest(first.values.allowlist, first.values.trustedZones, first.values.revocations)).trust_inputs_digest,
  );
  assert.equal(canonical(left.allowlist), canonical(right.allowlist));
});

function u5Digest(value) {
  return createHash("sha256").update(canonical(value)).digest("hex");
}

function u5Manifest(uri, bytes) {
  const body = {
    uri,
    sha256: createHash("sha256").update(bytes).digest("hex"),
    size: bytes.length,
    media_type: "text/plain",
    afp: `afp:sha256:${createHash("sha256").update(bytes).digest("hex")}`,
  };
  return { ...body, manifest_hash: u5Digest(body) };
}

function signCloseForU5(zone, closeBody) {
  return { type: "FED_SWARM_CLOSE", swarm_id: closeBody.swarm_id, zone: zone.descriptor, close: { ...closeBody, close_signature: signObject(zone.privateKey, closeBody) } };
}

async function u5Fixture({ twoTerminals = false, dependencyChain = false } = {}) {
  const trustValues = fixture();
  const trust = await createSwarmOutputTrustInputsForTest(trustValues.allowlist, trustValues.trustedZones, trustValues.revocations);
  const fixtureKind = dependencyChain ? "dependency" : (twoTerminals ? "two" : "single");
  const coordinator = createZone(`zone://u5-output/coordinator-${fixtureKind}`);
  const worker = createAgent(`agent://u5-output/worker-${fixtureKind}`, {}, ["asp+local://u5"], ["summarize.text"]);
  const planSteps = dependencyChain
    ? [{ step_id: "draft", capability: "summarize.text", depends_on: [] }, { step_id: "final", capability: "summarize.text", depends_on: ["draft"] }]
    : (twoTerminals
      ? [{ step_id: "summary", capability: "summarize.text", depends_on: [] }, { step_id: "appendix", capability: "summarize.text", depends_on: [] }]
      : [{ step_id: "summary", capability: "summarize.text", depends_on: [] }]);
  const planFrame = swarmPlan(coordinator, `swarm://u5-output/${fixtureKind}`, "Produce a final Swarm result.", planSteps, "a".repeat(64));
  const verifiedPlan = verifySwarmPlan(planFrame, new Map([[coordinator.zid, coordinator.descriptor]]));
  const executableSteps = planSteps.map((step) => {
    const taskBody = { task_id: `u5_${step.step_id}`, from: worker.aid, to: worker.alias, intent: `Complete ${step.step_id}.` };
    return { step_id: step.step_id, depends_on: step.depends_on, task: { ...taskBody, signature: signObject(worker.privateKey, taskBody) } };
  });
  const executionBinding = swarmExecutionBinding(coordinator, planFrame, executableSteps);
  const verifiedBinding = verifySwarmExecutionBinding(executionBinding, verifiedPlan, executableSteps, executableSteps.map(() => worker.descriptor));
  const trustedZones = new Map([[coordinator.zid, coordinator.descriptor]]);
  const artifactBytesByUri = new Map();
  const receiptFrames = [];
  for (const [index, step] of planSteps.entries()) {
    const bytes = Buffer.from(`u5 result bytes ${step.step_id}\n`);
    const manifest = u5Manifest(`artifact://local/u5-output/${step.step_id}.txt`, bytes);
    artifactBytesByUri.set(manifest.uri, bytes);
    const resultArtifact = { uri: manifest.uri, sha256: manifest.sha256, manifest_hash: manifest.manifest_hash };
    const inputArtifacts = step.depends_on.map((dependency) => {
      const dependencyReceipt = receiptFrames.find((frame) => frame.receipt.swarm.step_id === dependency)?.receipt;
      assert.ok(dependencyReceipt, `dependency receipt missing in fixture: ${dependency}`);
      return {
        step_id: dependency,
        uri: dependencyReceipt.result_artifact.uri,
        sha256: dependencyReceipt.result_artifact.sha256,
        manifest_hash: dependencyReceipt.result_artifact.manifest_hash,
        signed_receipt_digest: signedReceiptDigest(dependencyReceipt),
      };
    });
    const receiptBody = {
      task_id: executableSteps[index].task.task_id,
      task_digest: u5Digest(executableSteps[index].task),
      origin_zone: coordinator.zid,
      executing_zone: coordinator.zid,
      to: worker.aid,
      artifact_refs: [manifest.uri],
      artifact_manifests: [manifest],
      result_artifact: resultArtifact,
      swarm: {
        swarm_id: planFrame.plan.swarm_id,
        step_id: step.step_id,
        after: step.depends_on,
        ...(inputArtifacts.length > 0 ? { input_artifacts: inputArtifacts } : {}),
        plan_digest: verifiedBinding.planDigest,
        execution_graph_digest: verifiedBinding.executionGraphDigest,
        capability: step.capability,
        task_digest: u5Digest(executableSteps[index].task),
      },
    };
    receiptFrames.push({ type: "FED_RECEIPT", zone: coordinator.descriptor, worker: worker.descriptor, zone_binding: zoneBinding(coordinator, worker.descriptor), receipt: { ...receiptBody, signature: signObject(worker.privateKey, receiptBody) } });
  }
  const completed = new Map(receiptFrames.map((frame) => [frame.receipt.swarm.step_id, frame.receipt]));
  const finalOutput = deriveSwarmFinalOutput(verifiedBinding, completed);
  const closeBody = {
    format: "asp-swarm-close/v2",
    swarm_id: planFrame.plan.swarm_id,
    plan_digest: verifiedBinding.planDigest,
    execution_graph_digest: verifiedBinding.executionGraphDigest,
    step_receipts: receiptFrames.map((frame) => ({ step_id: frame.receipt.swarm.step_id, task_id: frame.receipt.task_id, signed_receipt_digest: signedReceiptDigest(frame.receipt) })),
    final_output: finalOutput,
  };
  const closeFrame = signCloseForU5(coordinator, closeBody);
  const evidence = {
    planFrame,
    executionBinding,
    executableSteps,
    resolvedWorkers: executableSteps.map(() => worker.descriptor),
    closeFrame,
    receiptFrames,
    trustedZones,
    loadArtifactBytes: async ({ uri }) => artifactBytesByUri.get(uri),
  };
  const verifier = {
    descriptor: trustValues.verifier.descriptor,
    zone: trustValues.zone.descriptor,
    zone_binding: trustValues.allowlist.verifiers[0].zone_binding,
    privateKey: trustValues.verifier.privateKey,
  };
  return { trustValues, trust, coordinator, worker, evidence, verifier, artifactBytesByUri };
}

function resignU5Proof(proof, privateKey, mutate) {
  const next = structuredClone(proof);
  const { proof_signature: _signature, ...body } = next.proof;
  mutate(body, next);
  next.proof = { ...body, proof_signature: signObject(privateKey, body) };
  return next;
}

function resignU5Receipt(frame, privateKey) {
  const { signature: _signature, ...body } = frame.receipt;
  frame.receipt = { ...body, signature: signObject(privateKey, body) };
}

function resignU5CloseAndProof(fixtureValue, proof, mutateClose) {
  const { close_signature: _closeSignature, ...closeBody } = structuredClone(fixtureValue.evidence.closeFrame.close);
  mutateClose(closeBody);
  fixtureValue.evidence.closeFrame = signCloseForU5(fixtureValue.coordinator, closeBody);
  return resignU5Proof(proof, fixtureValue.verifier.privateKey, (body) => {
    body.close_digest = u5Digest(fixtureValue.evidence.closeFrame.close);
    body.final_output = fixtureValue.evidence.closeFrame.close.final_output;
  });
}

test("FED_SWARM_OUTPUT_VERIFICATION rejects non-exact close step_receipts with Node/Go parity cases", async (t) => {
  const now = new Date("2026-07-11T12:00:00Z");
  const cases = [
    ["extra phantom close receipt", (closeBody) => {
      closeBody.step_receipts.push({ step_id: "phantom", task_id: "u5_phantom", signed_receipt_digest: "0".repeat(64) });
    }, /close signed receipt (count mismatch|missing)|phantom/i],
    ["omitted dependency close receipt", (closeBody) => {
      closeBody.step_receipts = closeBody.step_receipts.filter((step) => step.step_id !== "draft");
    }, /close signed receipt (count mismatch|missing)|draft/i],
  ];
  for (const [name, mutateClose, message] of cases) {
    await t.test(name, async () => {
      const fresh = await u5Fixture({ dependencyChain: true });
      const result = await createSwarmOutputVerification(fresh.evidence, fresh.trust, fresh.verifier, { verificationId: `u5-close-${name.replaceAll(/[^a-z0-9]+/gi, "-")}`, verifiedAt: "2026-07-11T11:59:00Z", now });
      const proof = resignU5CloseAndProof(fresh, result.proof, mutateClose);
      await assert.rejects(() => verifySwarmOutputVerification(proof, fresh.evidence, fresh.trust, { now }), message);
    });
  }
});

test("FED_SWARM_OUTPUT_VERIFICATION verified_at grammar is strict uppercase UTC with 0-3 fractional digits", async (t) => {
  const now = new Date("2026-07-11T12:00:00Z");
  const accepted = ["2026-07-11T11:59:00Z", "2026-07-11T11:59:00.1Z", "2026-07-11T11:59:00.12Z", "2026-07-11T11:59:00.123Z"];
  for (const verifiedAt of accepted) {
    await t.test(`accepts ${verifiedAt}`, async () => {
      const fresh = await u5Fixture();
      const result = await createSwarmOutputVerification(fresh.evidence, fresh.trust, fresh.verifier, { verificationId: `u5-time-${verifiedAt.replaceAll(/[^0-9]+/g, "-")}`, verifiedAt, now });
      assert.equal((await verifySwarmOutputVerification(result.proof, fresh.evidence, fresh.trust, { now })).proof.proof.verified_at, verifiedAt);
    });
  }
  const rejected = ["2026-07-11T11:59:00+00:00", "2026-07-11T11:59:00z", "2026-07-11T11:59:00.1234Z", "2026-07-11T12:05:01Z"];
  for (const verifiedAt of rejected) {
    await t.test(`rejects ${verifiedAt}`, async () => {
      const fresh = await u5Fixture();
      const result = await createSwarmOutputVerification(fresh.evidence, fresh.trust, fresh.verifier, { verificationId: `u5-time-reject-${verifiedAt.replaceAll(/[^0-9]+/g, "-")}`, verifiedAt: "2026-07-11T11:59:00Z", now });
      const proof = resignU5Proof(result.proof, fresh.verifier.privateKey, (body) => { body.verified_at = verifiedAt; });
      await assert.rejects(() => verifySwarmOutputVerification(proof, fresh.evidence, fresh.trust, { now }), /verified_at invalid|future/i);
    });
  }
});

test("FED_SWARM_OUTPUT_VERIFICATION recomputes final output proof and rejects mismatch matrix", async (t) => {
  const base = await u5Fixture();
  const now = new Date("2026-07-11T12:00:00Z");
  const created = await createSwarmOutputVerification(base.evidence, base.trust, base.verifier, { verificationId: "u5-proof-positive", verifiedAt: "2026-07-11T11:59:00Z", now });
  assert.equal(created.proof.type, "FED_SWARM_OUTPUT_VERIFICATION");
  assert.equal(created.proof.proof.format, "asp-swarm-output-verification/v1");
  assert.equal(created.finalOutput.signed_receipt_digest, signedReceiptDigest(base.evidence.receiptFrames[0].receipt));
  assert.equal(created.closeDigest, u5Digest(base.evidence.closeFrame.close));
  assert.equal(created.trustInputsDigest, base.trust.trust_inputs_digest);
  assert.match(created.proofDigest, /^[0-9a-f]{64}$/);
  assert.deepEqual(
    await verifySwarmOutputVerification(created.proof, base.evidence, base.trust, { now }),
    created,
  );
  assert.equal((await verifySwarmOutputVerification(resignU5Proof(created.proof, base.verifier.privateKey, (body) => { body.verified_at = "2020-01-01T00:00:00Z"; }), base.evidence, base.trust, { now })).proof.proof.verified_at, "2020-01-01T00:00:00Z");

  const assertRejectsMutation = async (name, mutateEvidence, message, mutateProof = (proof) => proof) => {
    await t.test(name, async () => {
      const fresh = await u5Fixture();
      const result = await createSwarmOutputVerification(fresh.evidence, fresh.trust, fresh.verifier, { verificationId: `u5-${name.replaceAll(/[^a-z0-9]+/gi, "-").toLowerCase()}`, verifiedAt: "2026-07-11T11:59:00Z", now });
      await mutateEvidence(fresh);
      await assert.rejects(
        () => verifySwarmOutputVerification(mutateProof(result.proof, fresh), fresh.evidence, fresh.trust, { now }),
        message,
      );
    });
  };

  await assertRejectsMutation("plan mismatch", (f) => { f.evidence.planFrame.plan.intent = "tampered"; }, /swarm plan signature verification failed|plan/i);
  await assertRejectsMutation("binding mismatch", (f) => { f.evidence.executionBinding.steps[0].task_digest = "b".repeat(64); }, /execution binding task_digest mismatch|signature/i);
  await assertRejectsMutation("graph mismatch", (f) => { f.evidence.executionBinding.execution_graph_digest = "c".repeat(64); }, /execution binding graph digest mismatch|signature/i);
  await assertRejectsMutation("close mismatch", (f) => {
    const { close_signature: _sig, ...body } = f.evidence.closeFrame.close;
    f.evidence.closeFrame = signCloseForU5(f.coordinator, { ...body, plan_digest: "d".repeat(64) });
  }, /proof close digest mismatch|close plan digest mismatch|plan digest mismatch/i);
  await assertRejectsMutation("receipt mismatch", (f) => { f.evidence.receiptFrames[0].receipt.signature = "bad"; }, /receipt signature|base64url/i);
  await assertRejectsMutation("result uri mismatch", (f) => {
    const receipt = f.evidence.receiptFrames[0].receipt;
    receipt.result_artifact = { ...receipt.result_artifact, uri: "artifact://local/u5-output/missing.txt" };
    resignU5Receipt(f.evidence.receiptFrames[0], f.worker.privateKey);
  }, /result artifact manifest mismatch|final output mismatch/i);
  await assertRejectsMutation("result sha mismatch", (f) => {
    const receipt = f.evidence.receiptFrames[0].receipt;
    receipt.result_artifact = { ...receipt.result_artifact, sha256: "e".repeat(64) };
    resignU5Receipt(f.evidence.receiptFrames[0], f.worker.privateKey);
  }, /result artifact manifest mismatch|final output mismatch/i);
  await assertRejectsMutation("manifest mismatch", (f) => {
    f.evidence.receiptFrames[0].receipt.artifact_manifests[0].manifest_hash = "f".repeat(64);
    resignU5Receipt(f.evidence.receiptFrames[0], f.worker.privateKey);
  }, /artifact manifest hash mismatch/i);
  await assertRejectsMutation("bytes mismatch", (f) => {
    const original = f.artifactBytesByUri.get(f.evidence.closeFrame.close.final_output.artifact.uri);
    f.evidence.loadArtifactBytes = async () => Buffer.alloc(original.length, 0x61);
  }, /artifact bytes digest mismatch/i);
  await assertRejectsMutation("trust digest mismatch", () => {}, /trust inputs digest mismatch/i, (proof, f) => resignU5Proof(proof, f.verifier.privateKey, (body) => { body.trust_inputs_digest = "1".repeat(64); }));
  await assertRejectsMutation("proof over another close", async (f) => {
    const other = await u5Fixture();
    f.evidence.closeFrame = other.evidence.closeFrame;
    f.evidence.trustedZones = new Map([...f.evidence.trustedZones, ...other.evidence.trustedZones]);
  }, /proof close digest mismatch|close swarm_id mismatch|close execution graph digest mismatch/i);
  await assertRejectsMutation("bad proof signature", () => {}, /proof signature verification failed|base64url/i, (proof) => ({ ...proof, proof: { ...proof.proof, proof_signature: "bad" } }));
  await assertRejectsMutation("future proof timestamp", () => {}, /verified_at invalid|future/i, (proof, f) => resignU5Proof(proof, f.verifier.privateKey, (body) => { body.verified_at = "2026-07-11T12:06:01Z"; }));
  await assertRejectsMutation("unknown proof field", () => {}, /exact schema/i, (proof, f) => resignU5Proof(proof, f.verifier.privateKey, (body) => { body.unexpected = true; }));

  assert.throws(
    () => deriveSwarmFinalOutput(
      { swarmId: "swarm://u5-output/wrong-terminal", planDigest: "a".repeat(64), executionGraphDigest: "b".repeat(64), steps: [{ step_id: "one", depends_on: [], capability: "summarize.text", task_digest: "c".repeat(64) }, { step_id: "two", depends_on: [], capability: "summarize.text", task_digest: "d".repeat(64) }] },
      new Map([["one", {}], ["two", {}]]),
    ),
    /single terminal step required/,
  );

  const wrongAllowlist = fixture();
  wrongAllowlist.allowlist.verifiers[0].authorizations = ["swarm.output.read"];
  assert.throws(() => createSwarmOutputTrustInputsForTest(wrongAllowlist.allowlist, wrongAllowlist.trustedZones, wrongAllowlist.revocations), /swarm.output.verify authorization/);
  const revokedVerifier = fixture();
  revokedVerifier.revocations.revocations = [zoneRevocation(revokedVerifier.zone, revokedVerifier.verifier.aid, "revoked")];
  assert.throws(() => createSwarmOutputTrustInputsForTest(revokedVerifier.allowlist, revokedVerifier.trustedZones, revokedVerifier.revocations), /verifier revoked/);
  const revokedZone = fixture();
  revokedZone.revocations.revocations = [zoneRevocation(revokedZone.zone, revokedZone.zone.zid, "revoked")];
  assert.throws(() => createSwarmOutputTrustInputsForTest(revokedZone.allowlist, revokedZone.trustedZones, revokedZone.revocations), /trusted zone revoked/);

  const rogue = createAgent("agent://u5-output/rogue", {}, ["asp+local://rogue"], ["swarm.output.verify"]);
  const rogueProof = resignU5Proof(created.proof, rogue.privateKey, (body) => { body.verifier_aid = rogue.aid; });
  rogueProof.verifier = rogue.descriptor;
  await assert.rejects(() => verifySwarmOutputVerification(rogueProof, base.evidence, base.trust, { now }), /allowlist|verifier/i);
  const wrongBinding = structuredClone(created.proof);
  wrongBinding.verifier_zone_binding = zoneBinding(createZone("zone://u5-output/wrong-zone"), base.verifier.descriptor);
  await assert.rejects(() => verifySwarmOutputVerification(wrongBinding, base.evidence, base.trust, { now }), /zone binding/i);
});

test("FED_SWARM_OUTPUT_VERIFICATION CLI verifies proof and rejects byte tamper and wrong arity", async (t) => {
  const base = await u5Fixture();
  const now = new Date("2026-07-11T12:00:00Z");
  const created = await createSwarmOutputVerification(base.evidence, base.trust, base.verifier, { verificationId: "u5-cli-positive", verifiedAt: "2026-07-11T11:59:00Z", now });
  const dir = await workspace(t, "agnet-u5-cli-");
  const artifactPath = join(dir, "result.txt");
  await writeFile(artifactPath, base.artifactBytesByUri.get(created.finalOutput.artifact.uri));
  const files = {
    bundle: join(dir, "bundle.json"),
    proof: join(dir, "proof.json"),
    plan: join(dir, "plan.json"),
    binding: join(dir, "binding.json"),
    steps: join(dir, "steps.json"),
    workers: join(dir, "workers.json"),
    close: join(dir, "close.json"),
    receipts: join(dir, "receipts.json"),
    zones: join(dir, "trusted-zones.json"),
    allowlist: join(dir, "allowlist.json"),
    verifierZones: join(dir, "verifier-zones.json"),
    revocations: join(dir, "revocations.json"),
  };
  await Promise.all([
    writeSecureJson(files.proof, created.proof),
    writeSecureJson(files.plan, base.evidence.planFrame),
    writeSecureJson(files.binding, base.evidence.executionBinding),
    writeSecureJson(files.steps, base.evidence.executableSteps),
    writeSecureJson(files.workers, base.evidence.resolvedWorkers),
    writeSecureJson(files.close, base.evidence.closeFrame),
    writeSecureJson(files.receipts, base.evidence.receiptFrames),
    writeSecureJson(files.zones, { zones: [...base.evidence.trustedZones.values()] }),
    writeSecureJson(files.allowlist, base.trustValues.allowlist),
    writeSecureJson(files.verifierZones, base.trustValues.trustedZones),
    writeSecureJson(files.revocations, base.trustValues.revocations),
  ]);
  await writeSecureJson(files.bundle, {
    format: "asp-swarm-output-verification-cli/v1",
    proof: "proof.json",
    plan: "plan.json",
    execution_binding: "binding.json",
    executable_steps: "steps.json",
    resolved_workers: "workers.json",
    close: "close.json",
    receipts: "receipts.json",
    trusted_zones: "trusted-zones.json",
    trust_inputs: { allowlist: "allowlist.json", trustedZones: "verifier-zones.json", revocations: "revocations.json" },
    artifacts: [{ uri: created.finalOutput.artifact.uri, path: "result.txt" }],
  });
  const ok = JSON.parse((await execFileAsync("node", ["asp-verify.mjs", "swarm-output", files.bundle], { env: { ...process.env, ASP_VERIFY_NOW: now.toISOString() } })).stdout);
  assert.equal(ok.swarm_output_verify, "ok");
  assert.equal(ok.proof_digest, created.proofDigest);
  assert.equal(ok.close_digest, created.closeDigest);
  assert.equal(ok.artifact_sha256, created.finalOutput.artifact.sha256);
  assert.equal(ok.manifest_hash, created.finalOutput.artifact.manifest_hash);
  await writeFile(artifactPath, Buffer.alloc(base.artifactBytesByUri.get(created.finalOutput.artifact.uri).length, 0x61));
  await assert.rejects(
    () => execFileAsync("node", ["asp-verify.mjs", "swarm-output", files.bundle], { env: { ...process.env, ASP_VERIFY_NOW: now.toISOString() } }),
    (error) => /artifact bytes digest mismatch/.test(error.stderr),
  );
  await assert.rejects(
    () => execFileAsync("node", ["asp-verify.mjs", "swarm-output", files.bundle, "extra.json"], { env: { ...process.env, ASP_VERIFY_NOW: now.toISOString() } }),
    (error) => /usage: node asp-verify.mjs/.test(error.stderr),
  );
});

test("replay is idempotent and conflicts by bytes", async () => {
  const now = new Date("2026-07-11T12:00:00Z");
  const makeStore = () => {
    const records = new Map();
    return {
      records,
      async lookup(verificationId) {
        return records.get(verificationId) ?? null;
      },
      async putIfAbsent(record) {
        const existing = records.get(record.verification_id);
        if (existing) return { inserted: false, record: existing };
        records.set(record.verification_id, record);
        return { inserted: true, record };
      },
    };
  };
  const base = await u5Fixture();
  const created = await createSwarmOutputVerification(base.evidence, base.trust, base.verifier, { verificationId: "u6-node-replay", verifiedAt: "2026-07-11T11:59:00Z", now });
  const store = makeStore();

  const accepted = await applySwarmOutputVerificationReplay(created.proof, base.evidence, base.trust, store, { now, expectedCloseDigest: created.closeDigest });
  assert.equal(accepted.replay_decision, "accepted");
  assert.equal(accepted.store_mutated, true);
  assert.equal(accepted.verification_id, "u6-node-replay");
  assert.equal(accepted.canonical_proof_sha256, createHash("sha256").update(canonical(created.proof.proof)).digest("hex"));
  assert.equal(accepted.stored_close_digest, created.closeDigest);
  assert.equal(accepted.proof_close_digest, created.closeDigest);
  assert.equal(accepted.closeDigest, created.closeDigest);
  assert.equal(accepted.proofDigest, created.proofDigest);
  assert.equal(accepted.trustInputsDigest, created.trustInputsDigest);
  assert.deepEqual(accepted.CloseBytes, Buffer.from(canonical(base.evidence.closeFrame.close)));
  assert.deepEqual(accepted.ProofBytes, Buffer.from(canonical(created.proof.proof)));
  assert.deepEqual(accepted.finalOutput, created.finalOutput);
  assert.equal(accepted.completion_gate, true);

  const formattingOnly = JSON.parse(JSON.stringify(reverseKeys(created.proof)));
  const idempotent = await applySwarmOutputVerificationReplay(formattingOnly, base.evidence, base.trust, store, { now, expectedCloseDigest: created.closeDigest });
  assert.equal(idempotent.replay_decision, "idempotent");
  assert.equal(idempotent.store_mutated, false);
  assert.equal(idempotent.canonical_proof_sha256, accepted.canonical_proof_sha256);
  assert.equal(idempotent.completion_gate, true);

  const changedSignedBytes = resignU5Proof(created.proof, base.verifier.privateKey, (body) => { body.verified_at = "2026-07-11T11:58:59Z"; });
  const conflict = await applySwarmOutputVerificationReplay(changedSignedBytes, base.evidence, base.trust, store, { now, expectedCloseDigest: created.closeDigest });
  assert.equal(conflict.replay_decision, "conflict");
  assert.equal(conflict.store_mutated, false);
  assert.equal(conflict.completion_gate, false);
  assert.equal(store.records.size, 1);

  for (const storedCloseDigest of ["", "0".repeat(64)]) {
    const corruptStore = makeStore();
    await applySwarmOutputVerificationReplay(created.proof, base.evidence, base.trust, corruptStore, { now, expectedCloseDigest: created.closeDigest });
    corruptStore.records.set(created.proof.proof.verification_id, { ...corruptStore.records.get(created.proof.proof.verification_id), stored_close_digest: storedCloseDigest });
    const corrupt = await applySwarmOutputVerificationReplay(created.proof, base.evidence, base.trust, corruptStore, { now, expectedCloseDigest: created.closeDigest });
    assert.equal(corrupt.replay_decision, "conflict");
    assert.equal(corrupt.store_mutated, false);
    assert.equal(corrupt.completion_gate, false);
  }

  const aliasStore = makeStore();
  const aliasAccepted = await applySwarmOutputVerificationReplay(created.proof, base.evidence, base.trust, aliasStore, { now, expectedCloseDigest: created.closeDigest });
  const storedAlias = aliasStore.records.get(created.proof.proof.verification_id);
  if (Buffer.isBuffer(storedAlias.canonical_proof_bytes)) storedAlias.canonical_proof_bytes[0] ^= 0xff;
  if (Buffer.isBuffer(storedAlias.canonical_close_bytes)) storedAlias.canonical_close_bytes[0] ^= 0xff;
  aliasAccepted.CloseBytes[0] ^= 0xff;
  aliasAccepted.ProofBytes[0] ^= 0xff;
  assert.throws(() => { aliasAccepted.finalOutput.artifact.uri = "artifact://local/mutated-return.txt"; }, /read only|Cannot assign/);
  const aliasIdempotent = await applySwarmOutputVerificationReplay(created.proof, base.evidence, base.trust, aliasStore, { now, expectedCloseDigest: created.closeDigest });
  assert.equal(aliasIdempotent.replay_decision, "idempotent");
  assert.equal(aliasIdempotent.completion_gate, true);
  assert.deepEqual(aliasIdempotent.finalOutput, created.finalOutput);

  const mismatchStore = makeStore();
  await assert.rejects(
    () => applySwarmOutputVerificationReplay(created.proof, base.evidence, base.trust, mismatchStore, { now, expectedCloseDigest: "f".repeat(64) }),
    /close digest mismatch/i,
  );
  assert.equal(mismatchStore.records.size, 0);
  const otherClose = await u5Fixture({ dependencyChain: true });
  const otherCreated = await createSwarmOutputVerification(otherClose.evidence, otherClose.trust, otherClose.verifier, { verificationId: "u6-node-other-close", verifiedAt: "2026-07-11T11:59:00Z", now });
  const otherCloseStore = makeStore();
  await assert.rejects(
    () => applySwarmOutputVerificationReplay(created.proof, base.evidence, base.trust, otherCloseStore, { now, expectedCloseDigest: otherCreated.closeDigest }),
    /close digest mismatch/i,
  );
  assert.equal(otherCloseStore.records.size, 0);


  const invalidStore = makeStore();
  const invalid = structuredClone(created.proof);
  invalid.proof.proof_signature = "bad";
  await assert.rejects(
    () => applySwarmOutputVerificationReplay(invalid, base.evidence, base.trust, invalidStore, { now, expectedCloseDigest: created.closeDigest }),
    /proof signature/i,
  );
  assert.equal(invalidStore.records.size, 0);

  const raceStore = {
    records: new Map(),
    async lookup() { return null; },
    async putIfAbsent(record) {
      const existing = { ...record, canonical_proof_sha256: "0".repeat(64), canonical_proof_bytes: Buffer.from("different"), proof_close_digest: record.proof_close_digest };
      this.records.set(record.verification_id, existing);
      return { inserted: false, record: existing };
    },
  };
  const race = await applySwarmOutputVerificationReplay(created.proof, base.evidence, base.trust, raceStore, { now, expectedCloseDigest: created.closeDigest });
  assert.equal(race.replay_decision, "conflict");
  assert.equal(race.store_mutated, false);
});

test("replay records use immutable verified proof snapshot across artifact await", async () => {
  const now = new Date("2026-07-11T12:00:00Z");
  const base = await u5Fixture();
  const created = await createSwarmOutputVerification(base.evidence, base.trust, base.verifier, { verificationId: "u6-node-snapshot-original", verifiedAt: "2026-07-11T11:59:00Z", now });
  const proof = structuredClone(created.proof);
  const originalProofBytes = Buffer.from(canonical(proof.proof));
  const originalProofDigest = createHash("sha256").update(canonical(proof.proof)).digest("hex");
  const originalSignature = proof.proof.proof_signature;
  const originalVerifiedAt = proof.proof.verified_at;
  const originalVerifierAID = proof.proof.verifier_aid;
  const originalVerifierZone = proof.proof.verifier_zone;
  const storeRecords = new Map();
  const store = {
    async putIfAbsent(record) {
      storeRecords.set(record.verification_id, record);
      return { inserted: true, record };
    },
  };
  base.evidence.loadArtifactBytes = async ({ uri }) => {
    await Promise.resolve();
    proof.proof.verification_id = "u6-node-snapshot-mutated";
    proof.proof.verified_at = "2020-01-01T00:00:00Z";
    proof.proof.verifier_aid = "aid:ed25519:mutated";
    proof.proof.verifier_zone = "zid:mutated";
    proof.proof.proof_signature = "mutated-signature";
    return base.artifactBytesByUri.get(uri);
  };

  const accepted = await applySwarmOutputVerificationReplay(proof, base.evidence, base.trust, store, { now, expectedCloseDigest: created.closeDigest });

  assert.equal(accepted.verification_id, "u6-node-snapshot-original");
  assert.equal(accepted.proofDigest, originalProofDigest);
  assert.deepEqual(accepted.ProofBytes, originalProofBytes);
  assert.equal(storeRecords.has("u6-node-snapshot-original"), true);
  assert.equal(storeRecords.has("u6-node-snapshot-mutated"), false);
  const record = storeRecords.get("u6-node-snapshot-original");
  assert.equal(record.verification_id, "u6-node-snapshot-original");
  assert.equal(record.canonical_proof_sha256, originalProofDigest);
  assert.deepEqual(record.canonical_proof_bytes, originalProofBytes.toString("utf8"));
  assert.equal(record.proof_digest, originalProofDigest);
  assert.equal(record.verified_at, originalVerifiedAt);
  assert.equal(record.verifier_aid, originalVerifierAID);
  assert.equal(record.verifier_zone, originalVerifierZone);
  assert.notEqual(record.canonical_proof_bytes.includes("mutated-signature"), true);
  assert.equal(proof.proof.proof_signature, "mutated-signature");
  assert.equal(originalSignature.length > 0, true);
});

test("FED_SWARM_OUTPUT_VERIFICATION CLI rejects duplicate artifact bindings before verification", async (t) => {
  const base = await u5Fixture();
  const now = new Date("2026-07-11T12:00:00Z");
  const created = await createSwarmOutputVerification(base.evidence, base.trust, base.verifier, { verificationId: "u6-cli-duplicate-artifact", verifiedAt: "2026-07-11T11:59:00Z", now });
  const dir = await workspace(t, "agnet-u6-cli-duplicate-");
  await writeFile(join(dir, "result.txt"), base.artifactBytesByUri.get(created.finalOutput.artifact.uri));
  await writeFile(join(dir, "other.txt"), Buffer.from("other bytes\n"));
  const files = {
    bundle: join(dir, "bundle.json"),
    proof: join(dir, "proof.json"),
    plan: join(dir, "plan.json"),
    binding: join(dir, "binding.json"),
    steps: join(dir, "steps.json"),
    workers: join(dir, "workers.json"),
    close: join(dir, "close.json"),
    receipts: join(dir, "receipts.json"),
    zones: join(dir, "trusted-zones.json"),
    allowlist: join(dir, "allowlist.json"),
    verifierZones: join(dir, "verifier-zones.json"),
    revocations: join(dir, "revocations.json"),
  };
  await Promise.all([
    writeSecureJson(files.proof, created.proof),
    writeSecureJson(files.plan, base.evidence.planFrame),
    writeSecureJson(files.binding, base.evidence.executionBinding),
    writeSecureJson(files.steps, base.evidence.executableSteps),
    writeSecureJson(files.workers, base.evidence.resolvedWorkers),
    writeSecureJson(files.close, base.evidence.closeFrame),
    writeSecureJson(files.receipts, base.evidence.receiptFrames),
    writeSecureJson(files.zones, { zones: [...base.evidence.trustedZones.values()] }),
    writeSecureJson(files.allowlist, base.trustValues.allowlist),
    writeSecureJson(files.verifierZones, base.trustValues.trustedZones),
    writeSecureJson(files.revocations, base.trustValues.revocations),
  ]);
  await writeSecureJson(files.bundle, {
    format: "asp-swarm-output-verification-cli/v1",
    proof: "proof.json",
    plan: "plan.json",
    execution_binding: "binding.json",
    executable_steps: "steps.json",
    resolved_workers: "workers.json",
    close: "close.json",
    receipts: "receipts.json",
    trusted_zones: "trusted-zones.json",
    trust_inputs: { allowlist: "allowlist.json", trustedZones: "verifier-zones.json", revocations: "revocations.json" },
    artifacts: [{ uri: created.finalOutput.artifact.uri, path: "result.txt" }, { uri: created.finalOutput.artifact.uri, path: "other.txt" }],
  });
  await assert.rejects(
    () => execFileAsync("node", ["asp-verify.mjs", "swarm-output", files.bundle], { env: { ...process.env, ASP_VERIFY_NOW: now.toISOString() } }),
    (error) => /duplicate artifact uri/i.test(error.stderr),
  );
});

