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
  assert.match(readme, /supplied or in-memory task evidence whose digest does not match/);
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

  assert.match(readme, /`docs\/v11\.6-boundary\.md` - artifact closure task evidence parity boundary\./);
  assert.match(readme, /`docs\/v11\.6-boundary\.md` - artifact closure task evidence parity boundary\./);
  assert.match(roadmap, /## v11\.6: Artifact Closure Task Evidence Parity/);
  assert.match(draft, /fed-receipt-artifacts <frame\.json> <trusted-zones\.json> \[task\.json\]/);
  assert.match(status, /optional supplied-task `task_digest` verification across Node receipt\/artifact CLIs/);
  assert.match(boundary, /receipt-plus-artifact verifier CLIs aligned/);
});

test("v11 public docs include Go receipt CLI task evidence verification", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.7-boundary.md", "utf8"),
  ]);

  assert.match(readme, /`docs\/v11\.7-boundary\.md` - Go receipt CLI task evidence boundary\./);
  assert.match(roadmap, /## v11\.7: Go Receipt CLI Task Evidence/);
  assert.match(draft, /--verify-receipt <receipt\.json> \[--verify-task <task\.json>\]/);
  assert.match(status, /Go receipt CLI/);
  assert.match(boundary, /Go receipt verifier CLI/);
});

test("v11 public docs include Go-to-Node interop receipt task binding", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.8-boundary.md", "utf8"),
  ]);

  assert.match(readme, /`docs\/v11\.8-boundary\.md` - Go-to-Node interop receipt task binding boundary\./);
  assert.match(roadmap, /## v11\.8: Go-to-Node Interop Receipt Task Binding/);
  assert.match(draft, /fed-receipt <frame\.json> <trusted-zones\.json> \[task\.json\]/);
  assert.match(status, /Go-to-Node interop receipt verification/);
  assert.match(boundary, /signed task sent by the Go client/);
});

test("v11 public docs include Node-to-Go interop receipt task binding", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.9-boundary.md", "utf8"),
  ]);

  assert.match(readme, /`docs\/v11\.9-boundary\.md` - Node-to-Go interop receipt task binding boundary\./);
  assert.match(roadmap, /## v11\.9: Node-to-Go Interop Receipt Task Binding/);
  assert.match(draft, /fed-receipt <frame\.json> <trusted-zones\.json> \[task\.json\]/);
  assert.match(status, /Node-to-Go interop receipt verification/);
  assert.match(boundary, /signed task sent by the Node client/);
});

test("v11 public docs include FED_RECEIPT frame type validation", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.10-boundary.md", "utf8"),
  ]);

  assert.match(readme, /`docs\/v11\.10-boundary\.md` - FED_RECEIPT frame type validation boundary\./);
  assert.match(roadmap, /## v11\.10: FED_RECEIPT Frame Type Validation/);
  assert.match(draft, /`frame\.type` is `FED_RECEIPT`/);
  assert.match(status, /FED_RECEIPT verifier requires frame\.type FED_RECEIPT/);
  assert.match(boundary, /wrong protocol type/);
});

test("v11 public docs include FED_TASK_OPEN frame type validation", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.11-boundary.md", "utf8"),
  ]);

  assert.match(readme, /`docs\/v11\.11-boundary\.md` - FED_TASK_OPEN frame type validation boundary\./);
  assert.match(readme, /task and receipt verifiers require the correct `FED_TASK_OPEN` \/ `FED_RECEIPT` frame types/);
  assert.match(roadmap, /## v11\.11: FED_TASK_OPEN Frame Type Validation/);
  assert.match(draft, /`frame\.type` is `FED_TASK_OPEN`/);
  assert.match(status, /FED_TASK_OPEN` and `FED_RECEIPT` frame type validation/);
  assert.match(boundary, /wrong protocol type/);
});

test("v11 public docs include FED_SWARM_CLOSE duplicate step validation", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.12-boundary.md", "utf8"),
  ]);

  assert.match(readme, /`docs\/v11\.12-boundary\.md` - FED_SWARM_CLOSE duplicate step validation boundary\./);
  assert.match(roadmap, /## v11\.12: FED_SWARM_CLOSE Duplicate Step Validation/);
  assert.match(draft, /rejects duplicate or NUL-bearing Swarm identities/);
  assert.match(status, /structural close-frame\/close-zone\/close-proof\/close-signature\/step-receipt object\/identity\/task-id\/uniqueness\/NUL checks/);
  assert.match(boundary, /duplicate step receipts/);
});

test("v11 public docs include FED_SWARM_CLOSE Swarm identity presence", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.13-boundary.md", "utf8"),
  ]);

  assert.match(readme, /`docs\/v11\.13-boundary\.md` - FED_SWARM_CLOSE Swarm identity presence boundary\./);
  assert.match(roadmap, /## v11\.13: FED_SWARM_CLOSE Swarm Identity Presence/);
  assert.match(draft, /checks the close frame object and type, signing Zone object and descriptor, close proof object, close signature presence and verification/);
  assert.match(status, /structural close-frame\/close-zone\/close-proof\/close-signature\/step-receipt object\/identity\/task-id\/uniqueness\/NUL checks/);
  assert.match(boundary, /without a signed Swarm id/);
});

test("v11 public docs include FED_SWARM_CLOSE NUL identity validation", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.14-boundary.md", "utf8"),
  ]);

  assert.match(readme, /`docs\/v11\.14-boundary\.md` - FED_SWARM_CLOSE NUL identity validation boundary\./);
  assert.match(roadmap, /## v11\.14: FED_SWARM_CLOSE NUL Identity Validation/);
  assert.match(draft, /rejects duplicate or NUL-bearing Swarm identities/);
  assert.match(boundary, /NUL-bearing Swarm identities/);
});

test("v11 public docs include FED_SWARM_CLOSE step task id validation", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.15-boundary.md", "utf8"),
  ]);

  assert.match(readme, /`docs\/v11\.15-boundary\.md` - FED_SWARM_CLOSE step task id validation boundary\./);
  assert.match(roadmap, /## v11\.15: FED_SWARM_CLOSE Step Task ID Validation/);
  assert.match(draft, /safe `task_id` token/);
  assert.match(boundary, /unsafe close step task ids/);
});

test("v11 public docs include FED_SWARM_CLOSE close signature presence", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.16-boundary.md", "utf8"),
  ]);

  assert.match(readme, /`docs\/v11\.16-boundary\.md` - FED_SWARM_CLOSE close signature presence boundary\./);
  assert.match(roadmap, /## v11\.16: FED_SWARM_CLOSE Close Signature Presence/);
  assert.match(draft, /close signature presence and verification/);
  assert.match(boundary, /missing close signatures/);
});

test("v11 public docs include FED_SWARM_CLOSE close proof presence", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.17-boundary.md", "utf8"),
  ]);

  assert.match(readme, /`docs\/v11\.17-boundary\.md` - FED_SWARM_CLOSE close proof presence boundary\./);
  assert.match(roadmap, /## v11\.17: FED_SWARM_CLOSE Close Proof Presence/);
  assert.match(draft, /checks the close frame object and type, signing Zone object and descriptor, close proof object, close signature presence and verification/);
  assert.match(boundary, /missing close proof objects/);
});

test("v11 public docs include FED_SWARM_CLOSE signing Zone presence", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.18-boundary.md", "utf8"),
  ]);

  assert.match(readme, /`docs\/v11\.18-boundary\.md` - FED_SWARM_CLOSE signing Zone presence boundary\./);
  assert.match(roadmap, /## v11\.18: FED_SWARM_CLOSE Signing Zone Presence/);
  assert.match(draft, /signing Zone object and descriptor/);
  assert.match(status, /structural close-frame\/close-zone\/close-proof\/close-signature\/step-receipt object\/identity\/task-id\/uniqueness\/NUL checks/);
  assert.match(boundary, /missing signing Zones/);
});

test("v11 public docs include FED_SWARM_CLOSE step receipt object presence", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.19-boundary.md", "utf8"),
  ]);

  assert.match(readme, /`docs\/v11\.19-boundary\.md` - FED_SWARM_CLOSE step receipt object presence boundary\./);
  assert.match(roadmap, /## v11\.19: FED_SWARM_CLOSE Step Receipt Object Presence/);
  assert.match(draft, /requires each step receipt to be an object/);
  assert.match(status, /structural close-frame\/close-zone\/close-proof\/close-signature\/step-receipt object\/identity\/task-id\/uniqueness\/NUL checks/);
  assert.match(boundary, /malformed step receipt entries/);
});

test("v11 public docs include FED_SWARM_CLOSE frame object presence", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.20-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v11 active at `v11\.20-protocol`/);
  assert.match(readme, /missing-frame, missing-zone, missing-proof, missing-signature, missing-identity, malformed-step, unsafe-task-id, NUL-bearing, structurally empty, or duplicate-step close proofs/);
  assert.match(roadmap, /## v11\.20: FED_SWARM_CLOSE Frame Object Presence/);
  assert.match(draft, /checks the close frame object and type/);
  assert.match(status, /状态：v11\.20 active/);
  assert.match(status, /structural close-frame\/close-zone\/close-proof\/close-signature\/step-receipt object\/identity\/task-id\/uniqueness\/NUL checks/);
  assert.match(boundary, /missing frame objects/);
});
