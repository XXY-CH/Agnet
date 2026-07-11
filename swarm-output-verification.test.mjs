import assert from "node:assert/strict";
import { appendFile, chmod, link, mkdir, mkdtemp, rename, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { canonical, createAgent, createZone, decodeBase64UrlExact, signObject, zoneBinding, zoneRevocation } from "./asp-core.mjs";
import { safeOpenOwnedJson } from "./secure-input.mjs";
import { createSwarmOutputTrustInputsForTest, loadSwarmOutputTrustInputs } from "./swarm-output-verification.mjs";

const MAX_INPUT_BYTES = 1024 * 1024;

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

