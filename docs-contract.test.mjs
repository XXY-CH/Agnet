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
  const [roadmap, draft, boundary] = await Promise.all([
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/v11.2-boundary.md", "utf8"),
  ]);

  assert.match(roadmap, /## v11\.2: FED_SWARM_CLOSE Structural Close Proof Validation/);
  assert.match(draft, /requires at least one step receipt/);
  assert.match(boundary, /structurally empty close proofs/);
});

test("v11 public docs include task id token validation", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.3-boundary.md", "utf8"),
  ]);

  assert.match(readme, /`docs\/v11\.3-boundary\.md` - task id token validation boundary\./);
  assert.match(readme, /task ids now fail closed unless they are safe protocol tokens/);
  assert.match(roadmap, /## v11\.3: Task ID Token Validation/);
  assert.match(draft, /task_id` is currently constrained/);
  assert.match(status, /`task_id` token validation/);
  assert.match(boundary, /task identifiers fail closed/);
});

test("v11 public docs include receipt task digest binding", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.4-boundary.md", "utf8"),
  ]);

  assert.match(readme, /`docs\/v11\.4-boundary\.md` - receipt task digest binding boundary\./);
  assert.match(readme, /receipts now carry `task_digest`/);
  assert.match(roadmap, /## v11\.4: Receipt Task Digest Binding/);
  assert.match(draft, /`task_digest` is the SHA-256 digest/);
  assert.match(status, /receipt `task_digest` binding requirement/);
  assert.match(boundary, /Bind signed receipts to the signed task object/);
});

test("v11 public docs include optional receipt task evidence verification", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.5-boundary.md", "utf8"),
  ]);

  assert.match(readme, /`docs\/v11\.5-boundary\.md` - optional receipt task evidence verification boundary\./);
  assert.match(readme, /supplied task evidence whose digest does not match/);
  assert.match(roadmap, /## v11\.5: Optional Receipt Task Evidence Verification/);
  assert.match(draft, /When signed task evidence is supplied/);
  assert.match(status, /optional supplied-task `task_digest` verification/);
  assert.match(boundary, /supplied signed task evidence/);
});

test("v11 public docs include artifact closure task evidence parity", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.6-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v11 active at `v11\.6-protocol`/);
  assert.match(readme, /Node receipt\/artifact verifiers can reject supplied task evidence/);
  assert.match(roadmap, /## v11\.6: Artifact Closure Task Evidence Parity/);
  assert.match(draft, /fed-receipt-artifacts <frame\.json> <trusted-zones\.json> \[task\.json\]/);
  assert.match(status, /状态：v11\.6 active/);
  assert.match(boundary, /receipt-plus-artifact verifier CLIs aligned/);
});
