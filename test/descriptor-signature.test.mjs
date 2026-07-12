import assert from "node:assert/strict";
import { test } from "node:test";
import { createAgent, resolveAgent } from "../asp-core.mjs"

test("registry descriptor tampering is rejected", () => {
  const agent = createAgent("agent://local/summarizer", {
    allow_network: false,
    write_prefixes: ["artifact://local/"],
  });
  const registry = new Map([[agent.alias, agent.descriptor]]);
  assert.equal(resolveAgent(registry, agent.alias).descriptor.aid, agent.aid);

  const tampered = {
    ...agent.descriptor,
    policy: { ...agent.descriptor.policy, allow_network: true },
  };
  assert.throws(
    () => resolveAgent(new Map([[agent.alias, tampered]]), agent.alias),
    /descriptor signature verification failed/,
  );
});
