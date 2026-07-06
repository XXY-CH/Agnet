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

test("v10 public docs agree that the proof milestone is closed", async () => {
  const [readme, roadmap, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v10-roadmap.md", "utf8"),
    readFile("docs/v10.47-boundary.md", "utf8"),
  ]);

  assert.match(readme, /`docs\/v10-roadmap\.md` - closed v10 roadmap\./);
  assert.match(readme, /v9 and v10 are closed\./);
  assert.match(roadmap, /状态：closed/);
  assert.match(roadmap, /## v10\.47: V10 Closeout Alignment/);
  assert.match(boundary, /状态：complete/);
  assert.match(boundary, /v10 到此收尾/);
});

test("v11 public docs start with receipt origin-zone trust validation", async () => {
  const [readme, roadmap, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/v11.0-boundary.md", "utf8"),
  ]);

  assert.match(readme, /`docs\/v11-roadmap\.md` - active v11 roadmap\./);
  assert.match(roadmap, /## v11\.0: Receipt Origin Zone Trust Validation/);
  assert.match(boundary, /untrusted signed receipt `origin_zone`/);
});

test("v11 public docs include requester Zone binding for FED_TASK_OPEN", async () => {
  const [roadmap, draft, boundary] = await Promise.all([
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/v11.1-boundary.md", "utf8"),
  ]);

  assert.match(roadmap, /## v11\.1: FED_TASK_OPEN Requester Zone Binding/);
  assert.match(draft, /requester_zone_binding/);
  assert.match(boundary, /requester Zone binding/);
});

test("v11 public docs include Swarm close structural validation", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.2-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v11 active at `v11\.2-protocol`/);
  assert.match(readme, /fail-closed checks for empty Swarm close proofs/);
  assert.match(roadmap, /## v11\.2: FED_SWARM_CLOSE Structural Close Proof Validation/);
  assert.match(draft, /requires at least one step receipt/);
  assert.match(status, /状态：v11\.2 active/);
  assert.match(boundary, /structurally empty close proofs/);
});
