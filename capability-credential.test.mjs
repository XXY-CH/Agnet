import assert from "node:assert/strict";
import { test } from "node:test";
import { capabilityCredential, createAgent, createZone, verifyCapabilityCredential } from "./asp-core.mjs";

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
