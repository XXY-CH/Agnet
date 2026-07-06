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
  assert.match(draft, /frame is an object whose `frame\.type` is `FED_RECEIPT`/);
  assert.match(status, /FED_RECEIPT verifier requires frame object\/type FED_RECEIPT/);
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
  assert.match(readme, /task and receipt verifiers require valid `FED_TASK_OPEN` \/ `FED_RECEIPT` frame objects, correct frame types, required Zone descriptor objects, required payload objects, and a trusted Zone store/);
  assert.match(roadmap, /## v11\.11: FED_TASK_OPEN Frame Type Validation/);
  assert.match(draft, /frame is an object whose `frame\.type` is `FED_TASK_OPEN`/);
  assert.match(status, /Node `FED_TASK_OPEN` and `FED_RECEIPT` frame object\/type.*validation/);
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
  assert.match(draft, /checks the close frame object and type, .*signing Zone object and descriptor, close proof object, close signature presence and verification/);
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
  assert.match(draft, /checks the close frame object and type, .*signing Zone object and descriptor, close proof object, close signature presence and verification/);
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

  assert.match(readme, /`docs\/v11\.20-boundary\.md` - FED_SWARM_CLOSE frame object presence boundary\./);
  assert.match(readme, /missing-frame, missing-zone, missing-proof, missing-signature, missing-identity, malformed-step, unsafe-task-id, NUL-bearing, structurally empty, or duplicate-step close proofs/);
  assert.match(roadmap, /## v11\.20: FED_SWARM_CLOSE Frame Object Presence/);
  assert.match(draft, /checks the close frame object and type/);
  assert.match(status, /structural close-frame\/close-zone\/close-proof\/close-signature\/step-receipt object\/identity\/task-id\/uniqueness\/NUL checks/);
  assert.match(boundary, /missing frame objects/);
});

test("v11 public docs include task and receipt frame object presence", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.21-boundary.md", "utf8"),
  ]);

  assert.match(readme, /`docs\/v11\.21-boundary\.md` - FED_TASK_OPEN and FED_RECEIPT frame object presence boundary\./);
  assert.match(readme, /task and receipt verifiers require valid `FED_TASK_OPEN` \/ `FED_RECEIPT` frame objects, correct frame types, required Zone descriptor objects, required payload objects, and a trusted Zone store/);
  assert.match(roadmap, /## v11\.21: FED_TASK_OPEN and FED_RECEIPT Frame Object Presence/);
  assert.match(draft, /frame is an object whose `frame\.type` is `FED_TASK_OPEN`/);
  assert.match(draft, /frame is an object whose `frame\.type` is `FED_RECEIPT`/);
  assert.match(status, /Node `FED_TASK_OPEN` and `FED_RECEIPT` frame object\/type.*validation/);
  assert.match(boundary, /missing frame objects/);
});

test("v11 public docs include task and receipt Zone descriptor presence", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.22-boundary.md", "utf8"),
  ]);

  assert.match(readme, /`docs\/v11\.22-boundary\.md` - FED_TASK_OPEN and FED_RECEIPT Zone descriptor presence boundary\./);
  assert.match(readme, /task and receipt verifiers require valid `FED_TASK_OPEN` \/ `FED_RECEIPT` frame objects, correct frame types, required Zone descriptor objects, required payload objects, and a trusted Zone store/);
  assert.match(roadmap, /## v11\.22: FED_TASK_OPEN and FED_RECEIPT Zone Descriptor Presence/);
  assert.match(draft, /origin Zone descriptor is present as an object and verifies/);
  assert.match(draft, /signing Zone descriptor is present as an object and trusted/);
  assert.match(status, /Node `FED_TASK_OPEN` and `FED_RECEIPT` frame object\/type.*Zone descriptor presence.*validation/);
  assert.match(boundary, /missing Zone descriptor objects/);
});

test("v11 public docs include task and receipt payload object presence", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.23-boundary.md", "utf8"),
  ]);

  assert.match(readme, /`docs\/v11\.23-boundary\.md` - FED_TASK_OPEN and FED_RECEIPT payload object presence boundary\./);
  assert.match(readme, /task and receipt verifiers require valid `FED_TASK_OPEN` \/ `FED_RECEIPT` frame objects, correct frame types, required Zone descriptor objects, required payload objects, and a trusted Zone store/);
  assert.match(roadmap, /## v11\.23: FED_TASK_OPEN and FED_RECEIPT Payload Object Presence/);
  assert.match(draft, /requester descriptor is present as an object/);
  assert.match(draft, /signed task object is present as an object/);
  assert.match(draft, /worker descriptor is present as an object/);
  assert.match(draft, /receipt body is present as an object/);
  assert.match(status, /Node `FED_TASK_OPEN` and `FED_RECEIPT` frame object\/type, Zone descriptor presence, payload object presence, and trusted Zone store presence validation/);
  assert.match(boundary, /missing payload objects/);
});

test("v11 public docs include Node trusted Zone store presence", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.24-boundary.md", "utf8"),
  ]);

  assert.match(readme, /`docs\/v11\.24-boundary\.md` - Node trusted Zone store presence boundary\./);
  assert.match(readme, /Node task, receipt, and Swarm close verifiers reject missing trusted Zone stores/);
  assert.match(roadmap, /## v11\.24: Node Trusted Zone Store Presence/);
  assert.match(draft, /trusted Zone store is present for origin Zone lookup/);
  assert.match(draft, /trusted Zone store is present for signing and origin Zone lookup/);
  assert.match(draft, /trusted Zone store presence, signing Zone object and descriptor/);
  assert.match(status, /trusted Zone store presence validation/);
  assert.match(boundary, /missing trusted Zone stores/);
});

test("v11 public docs include FED_TASK_OPEN worker context presence", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.25-boundary.md", "utf8"),
  ]);

  assert.match(readme, /`docs\/v11\.25-boundary\.md` - FED_TASK_OPEN worker context presence boundary\./);
  assert.match(readme, /local worker descriptor context presence/);
  assert.match(roadmap, /## v11\.25: FED_TASK_OPEN Worker Context Presence/);
  assert.match(draft, /local worker descriptor context is present as an object/);
  assert.match(status, /worker descriptor context presence validation/);
  assert.match(boundary, /task open worker missing/);
});

test("v11 public docs include task and receipt signature presence", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.26-boundary.md", "utf8"),
  ]);

  assert.match(readme, /`docs\/v11\.26-boundary\.md` - FED_TASK_OPEN and FED_RECEIPT signature presence boundary\./);
  assert.match(readme, /signed task\/receipt signatures before crypto verification/);
  assert.match(roadmap, /## v11\.26: FED_TASK_OPEN and FED_RECEIPT Signature Presence/);
  assert.match(draft, /task signature is present as a string/);
  assert.match(draft, /receipt signature is present as a string/);
  assert.match(status, /signed task\/receipt signature presence validation/);
  assert.match(boundary, /task signature missing/);
  assert.match(boundary, /receipt signature missing/);
});

test("v11 public docs include FED_TASK_OPEN worker descriptor identity", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.27-boundary.md", "utf8"),
  ]);

  assert.match(readme, /`docs\/v11\.27-boundary\.md` - FED_TASK_OPEN worker descriptor identity boundary\./);
  assert.match(readme, /valid local worker descriptor identity/);
  assert.match(roadmap, /## v11\.27: FED_TASK_OPEN Worker Descriptor Identity/);
  assert.match(draft, /local worker descriptor identity verifies/);
  assert.match(status, /状态：v11\.36 active/);
  assert.match(status, /worker descriptor context presence validation and worker descriptor identity validation/);
  assert.match(boundary, /task open worker invalid/);
});

test("v11 public docs include FED_RECEIPT worker descriptor identity", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.28-boundary.md", "utf8"),
  ]);

  assert.match(readme, /`docs\/v11\.28-boundary\.md` - FED_RECEIPT worker descriptor identity boundary\./);
  assert.match(readme, /invalid worker descriptor identity/);
  assert.match(roadmap, /## v11\.28: FED_RECEIPT Worker Descriptor Identity/);
  assert.match(draft, /worker descriptor identity verifies before receipt identity and signature checks/);
  assert.match(status, /状态：v11\.36 active/);
  assert.match(status, /Node `FED_RECEIPT` worker descriptor identity validation/);
  assert.match(boundary, /receipt worker invalid/);
});

test("v11 public docs include descriptor public key presence", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.29-boundary.md", "utf8"),
  ]);

  assert.match(readme, /`docs\/v11\.29-boundary\.md` - Node descriptor public key presence boundary\./);
  assert.match(readme, /descriptor public key presence validation/);
  assert.match(roadmap, /## v11\.29: Node Descriptor Public Key Presence/);
  assert.match(draft, /public_key_spki` is missing before handing the descriptor to Node crypto parsing/);
  assert.match(status, /状态：v11\.36 active/);
  assert.match(status, /Node descriptor public key presence validation/);
  assert.match(boundary, /descriptor public key missing/);
});

test("v11 public docs include object signature fail-closed verification", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.30-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v11 active at `v11\.36-protocol`/);
  assert.match(readme, /object signature type validation/);
  assert.match(roadmap, /## v11\.30: Node Object Signature Fail-Closed Verification/);
  assert.match(draft, /object signature verification returns false for missing, empty, or non-string signatures/);
  assert.match(status, /状态：v11\.36 active/);
  assert.match(status, /Node shared object signature fail-closed validation/);
  assert.match(boundary, /verifyObject` returns `false`/);
});

test("v11 public docs include Zone descriptor object presence", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.31-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v11 active at `v11\.36-protocol`/);
  assert.match(readme, /`docs\/v11\.31-boundary\.md` - Node Zone descriptor object presence boundary\./);
  assert.match(readme, /Zone descriptor object presence validation/);
  assert.match(roadmap, /## v11\.31: Node Zone Descriptor Object Presence/);
  assert.match(draft, /Zone descriptor object presence before reading descriptor fields/);
  assert.match(status, /状态：v11\.36 active/);
  assert.match(status, /Node Zone descriptor object presence validation/);
  assert.match(boundary, /zone descriptor missing/);
});

test("v11 public docs include did:key input presence", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.32-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v11 active at `v11\.36-protocol`/);
  assert.match(readme, /`docs\/v11\.32-boundary\.md` - Node did:key input presence boundary\./);
  assert.match(readme, /did:key` bridge fields for descriptors, with missing-input validation/);
  assert.match(roadmap, /## v11\.32: Node did:key Input Presence/);
  assert.match(draft, /did:key` bridge helpers reject missing descriptor\/public-key and DID string inputs/);
  assert.match(status, /状态：v11\.36 active/);
  assert.match(status, /did:key` bridge input presence validation/);
  assert.match(boundary, /expected did:key z-base58btc value/);
});

test("v11 public docs include artifact manifest object presence", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.33-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v11 active at `v11\.36-protocol`/);
  assert.match(readme, /`docs\/v11\.33-boundary\.md` - Node artifact manifest object presence boundary\./);
  assert.match(readme, /artifact manifests, AFP strings, sidecars, local byte verification, CLI verification, object presence validation/);
  assert.match(roadmap, /## v11\.33: Node Artifact Manifest Object Presence/);
  assert.match(draft, /artifact manifest helpers reject missing receipt and manifest objects/);
  assert.match(status, /状态：v11\.36 active/);
  assert.match(status, /Node artifact manifest object presence validation/);
  assert.match(boundary, /artifact manifest missing/);
});

test("v11 public docs include credential object presence", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.34-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v11 active at `v11\.36-protocol`/);
  assert.match(readme, /`docs\/v11\.34-boundary\.md` - Node credential object presence boundary\./);
  assert.match(readme, /capability credential and credential status helpers now reject missing proof objects/);
  assert.match(roadmap, /## v11\.34: Node Credential Object Presence/);
  assert.match(draft, /capability credential helpers reject missing credential and status proof objects/);
  assert.match(status, /状态：v11\.36 active/);
  assert.match(status, /Node capability credential object presence validation/);
  assert.match(boundary, /credential missing/);
});

test("v11 public docs include rotation proof object presence", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.35-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v11 active at `v11\.36-protocol`/);
  assert.match(readme, /`docs\/v11\.35-boundary\.md` - Node rotation proof object presence boundary\./);
  assert.match(readme, /rotation and alias rebinding proof verifiers reject missing proof\/descriptor objects/);
  assert.match(roadmap, /## v11\.35: Node Rotation Proof Object Presence/);
  assert.match(draft, /rotation and alias rebinding proof verifiers reject missing proof and descriptor objects/);
  assert.match(status, /状态：v11\.36 active/);
  assert.match(status, /Node rotation proof object presence validation/);
  assert.match(boundary, /verifyAliasRebindingProof` returns `false`/);
});

test("v11 public docs include Zone binding object presence", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.36-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v11 active at `v11\.36-protocol`/);
  assert.match(readme, /`docs\/v11\.36-boundary\.md` - latest closed boundary\./);
  assert.match(readme, /Zone binding object presence validation/);
  assert.match(roadmap, /## v11\.36: Node Zone Binding Object Presence/);
  assert.match(draft, /Zone binding verifier rejects missing binding context and descriptor objects/);
  assert.match(status, /状态：v11\.36 active/);
  assert.match(status, /Node Zone binding object presence validation/);
  assert.match(boundary, /zone binding context missing/);
});
