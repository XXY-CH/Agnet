import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

test("ASP Core draft documents the narrow implemented proof layer", async () => {
  const text = await readFile("docs/asp-core-draft.md", "utf8");

  for (const phrase of [
    "# ASP Core Draft",
    "aid: is the canonical Agent identifier.",
    "did:key is an Ed25519 bridge field, not canonical identity.",
    "FED_TASK_OPEN",
    "FED_RECEIPT",
    "artifact_manifests",
    "audit hash chain",
    "A2A compatibility is out of scope for this draft.",
  ]) {
    assert.match(text, new RegExp(phrase.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  }
});
