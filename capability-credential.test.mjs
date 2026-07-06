import assert from "node:assert/strict";
import { test } from "node:test";
import { capabilityCredential, capabilityCredentialId, createAgent, createZone, signObject, verifyCapabilityCredential, verifyCredentialStatus } from "./asp-core.mjs";

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
  assert.throws(() => capabilityCredentialId(null), /credential missing/);
  assert.equal(verifyCredentialStatus(null, credential, authority.descriptor), false);
  assert.equal(verifyCredentialStatus(status, null, authority.descriptor), false);
});
