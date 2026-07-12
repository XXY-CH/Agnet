import assert from "node:assert/strict";
import { test } from "node:test";
import { CREDENTIAL_VALID_UNTIL_PATTERN, capabilityCredential, capabilityCredentialId, createAgent, createZone, signObject, verifyCapabilityCredential, verifyCredentialStatus } from "../asp-core.mjs"

test("Zone-signed capability credential verifies against subject descriptor", () => {
  const authority = createZone("zone://security-authority");
  const agent = createAgent("agent://local/summarizer", {}, ["asp+local://demo"], ["summarize.text"]);
  const credential = capabilityCredential(authority, agent.descriptor, "summarize.text", {
    level: "L1",
    evidence: ["local-demo"],
  });

  assert.equal(verifyCapabilityCredential(credential, authority.descriptor, agent.descriptor), true);
  assert.equal(
    verifyCapabilityCredential({ ...credential, capability: "translate.text" }, authority.descriptor, agent.descriptor),
    false,
  );
});

test("capability credential valid_until accepts future ISO UTC expiry", () => {
  const authority = createZone("zone://security-authority");
  const agent = createAgent("agent://local/summarizer", {}, ["asp+local://demo"], ["summarize.text"]);
  const validUntil = new Date(Date.now() + 60 * 60 * 1000).toISOString();
  const credential = capabilityCredential(authority, agent.descriptor, "summarize.text", {
    valid_until: validUntil,
  });

  assert.equal(CREDENTIAL_VALID_UNTIL_PATTERN.test(validUntil), true);
  assert.equal(verifyCapabilityCredential(credential, authority.descriptor, agent.descriptor), true);
});

test("capability credential valid_until rejects past ISO UTC expiry", () => {
  const authority = createZone("zone://security-authority");
  const agent = createAgent("agent://local/summarizer", {}, ["asp+local://demo"], ["summarize.text"]);
  const credential = capabilityCredential(authority, agent.descriptor, "summarize.text", {
    valid_until: new Date(Date.now() - 60 * 60 * 1000).toISOString(),
  });

  assert.equal(verifyCapabilityCredential(credential, authority.descriptor, agent.descriptor), false);
});

test("capability credential valid_until rejects invalid expiry values", () => {
  const authority = createZone("zone://security-authority");
  const agent = createAgent("agent://local/summarizer", {}, ["asp+local://demo"], ["summarize.text"]);
  const invalidStringCredential = capabilityCredential(authority, agent.descriptor, "summarize.text", {
    valid_until: "tomorrow",
  });
  const invalidTypeCredential = capabilityCredential(authority, agent.descriptor, "summarize.text", {
    valid_until: 123,
  });

  assert.equal(CREDENTIAL_VALID_UNTIL_PATTERN.test("tomorrow"), false);
  assert.equal(verifyCapabilityCredential(invalidStringCredential, authority.descriptor, agent.descriptor), false);
  assert.equal(verifyCapabilityCredential(invalidTypeCredential, authority.descriptor, agent.descriptor), false);
});


test("capability credential helpers reject missing objects", () => {
  const authority = createZone("zone://security-authority");
  const agent = createAgent("agent://local/summarizer", {}, ["asp+local://demo"], ["summarize.text"]);
  const credential = capabilityCredential(authority, agent.descriptor, "summarize.text", {
    level: "L1",
  });
  const statusBody = {
    issuer: authority.zid,
    credential_id: capabilityCredentialId(credential),
    subject: agent.aid,
    status: "active",
  };
  const status = { ...statusBody, signature: signObject(authority.privateKey, statusBody) };

  assert.equal(verifyCapabilityCredential(null, authority.descriptor, agent.descriptor), false);
  assert.equal(verifyCapabilityCredential(credential, null, agent.descriptor), false);
  assert.equal(verifyCapabilityCredential(credential, authority.descriptor, null), false);
  assert.equal(verifyCapabilityCredential(credential, authority.descriptor, {}), false);
  assert.throws(() => capabilityCredentialId(null), /credential missing/);
  assert.equal(verifyCredentialStatus(null, credential, authority.descriptor), false);
  assert.equal(verifyCredentialStatus(status, null, authority.descriptor), false);
  assert.equal(verifyCredentialStatus(status, credential, null), false);
});
