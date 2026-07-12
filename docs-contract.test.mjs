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

  assert.match(readme, /`docs\/v11-roadmap\.md` - closed v11 roadmap\./);
  assert.match(roadmap, /状态：closed at v11\.79/);
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
  assert.match(roadmap, /## v11\.27: FED_TASK_OPEN Worker Descriptor Identity/);
  assert.match(draft, /local worker descriptor identity verifies/);
  assert.match(status, /状态：v12 closed at v12\.45/);
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
  assert.match(roadmap, /## v11\.28: FED_RECEIPT Worker Descriptor Identity/);
  assert.match(draft, /worker descriptor identity verifies before receipt identity and signature checks/);
  assert.match(status, /状态：v12 closed at v12\.45/);
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
  assert.match(roadmap, /## v11\.29: Node Descriptor Public Key Presence/);
  assert.match(draft, /public_key_spki` is missing before handing the descriptor to Node crypto parsing/);
  assert.match(status, /状态：v12 closed at v12\.45/);
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

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(roadmap, /## v11\.30: Node Object Signature Fail-Closed Verification/);
  assert.match(draft, /object signature verification returns false for missing, empty, or non-string signatures/);
  assert.match(status, /状态：v12 closed at v12\.45/);
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

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v11\.31-boundary\.md` - Node Zone descriptor object presence boundary\./);
  assert.match(roadmap, /## v11\.31: Node Zone Descriptor Object Presence/);
  assert.match(draft, /Zone descriptor object presence before reading descriptor fields/);
  assert.match(status, /状态：v12 closed at v12\.45/);
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

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v11\.32-boundary\.md` - Node did:key input presence boundary\./);
  assert.match(roadmap, /## v11\.32: Node did:key Input Presence/);
  assert.match(draft, /did:key` bridge helpers reject missing descriptor\/public-key and DID string inputs/);
  assert.match(status, /状态：v12 closed at v12\.45/);
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

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v11\.33-boundary\.md` - Node artifact manifest object presence boundary\./);
  assert.match(roadmap, /## v11\.33: Node Artifact Manifest Object Presence/);
  assert.match(draft, /artifact manifest helpers reject missing receipt and manifest objects/);
  assert.match(status, /状态：v12 closed at v12\.45/);
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

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v11\.34-boundary\.md` - Node credential object presence boundary\./);
  assert.match(roadmap, /## v11\.34: Node Credential Object Presence/);
  assert.match(draft, /capability credential helpers reject missing credential and status proof objects/);
  assert.match(status, /状态：v12 closed at v12\.45/);
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

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v11\.35-boundary\.md` - Node rotation proof object presence boundary\./);
  assert.match(roadmap, /## v11\.35: Node Rotation Proof Object Presence/);
  assert.match(draft, /rotation and alias rebinding proof verifiers reject missing proof and descriptor objects/);
  assert.match(status, /状态：v12 closed at v12\.45/);
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

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v11\.36-boundary\.md` - Node Zone binding object presence boundary\./);
  assert.match(roadmap, /## v11\.36: Node Zone Binding Object Presence/);
  assert.match(draft, /Zone binding verifier rejects missing binding context and descriptor objects/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /Node Zone binding object presence validation/);
  assert.match(boundary, /zone binding context missing/);
});

test("v11 public docs include Zone revocation object presence", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.37-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v11\.37-boundary\.md` - Node Zone revocation object presence boundary\./);
  assert.match(roadmap, /## v11\.37: Node Zone Revocation Object Presence/);
  assert.match(draft, /Zone revocation verifiers reject missing revocation context, descriptor, and revocation-list objects/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /Node Zone revocation object presence validation/);
  assert.match(boundary, /zone revocation context missing/);
});

test("v11 public docs include trusted Zone file shape validation", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.38-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v11\.38-boundary\.md` - Node trusted Zone file shape boundary\./);
  assert.match(roadmap, /## v11\.38: Node Trusted Zone File Shape/);
  assert.match(draft, /Trusted Zone files MUST contain a Zone descriptor list/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /Node trusted Zone file shape validation/);
  assert.match(boundary, /trusted zone list missing/);
});

test("v11 public docs include registry file shape validation", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.39-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v11\.39-boundary\.md` - Node registry file shape boundary\./);
  assert.match(roadmap, /## v11\.39: Node Registry File Shape/);
  assert.match(draft, /Registry files MUST contain agent descriptor entries/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /Node registry file shape validation/);
  assert.match(boundary, /registry agents missing/);
});

test("v11 public docs include resolveAgent registry context validation", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.40-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v11\.40-boundary\.md` - Node resolveAgent registry context boundary\./);
  assert.match(roadmap, /## v11\.40: Node resolveAgent Registry Context/);
  assert.match(draft, /Agent resolution requires registry context/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /Node resolveAgent registry context validation/);
  assert.match(boundary, /registry missing/);
});

test("v11 public docs include descriptor body object presence validation", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.41-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v11\.41-boundary\.md` - Node descriptor body object presence boundary\./);
  assert.match(roadmap, /## v11\.41: Node Descriptor Body Object Presence/);
  assert.match(draft, /Descriptor body helpers MUST receive descriptor objects/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /Node descriptor body object presence validation/);
  assert.match(boundary, /descriptor missing/);
  assert.match(boundary, /zone descriptor missing/);
});

test("v11 public docs include proof verifier malformed descriptor fail-closed validation", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.42-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v11\.42-boundary\.md` - Node proof verifier malformed descriptor fail-closed boundary\./);
  assert.match(roadmap, /## v11\.42: Node Proof Verifier Malformed Descriptor Fail-Closed/);
  assert.match(draft, /boolean proof verifiers return false for malformed descriptor inputs/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /Node proof verifier malformed descriptor fail-closed validation/);
  assert.match(boundary, /descriptor public key missing/);
  assert.match(boundary, /zone descriptor missing/);
});

test("v11 public docs include local artifact URI boundary validation", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.43-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v11\.43-boundary\.md` - Node local artifact URI boundary\./);
  assert.match(roadmap, /## v11\.43: Node Local Artifact URI Boundary/);
  assert.match(draft, /Local artifact byte verification MUST reject missing, non-`artifact:\/\/local\/`, or path-escaping manifest URIs/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /Node local artifact URI boundary validation/);
  assert.match(boundary, /artifact uri invalid/);
});

test("v11 public docs include local artifact path boundary validation", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.44-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v11\.44-boundary\.md` - Node local artifact path boundary\./);
  assert.match(roadmap, /## v11\.44: Node Local Artifact Path Boundary/);
  assert.match(draft, /path-escaping manifest URIs before filesystem reads/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /Node local artifact path boundary validation/);
  assert.match(boundary, /artifact:\/\/local\/\.\.\/evil\.md/);
});

test("v11 public docs include Go artifact digest path boundary validation", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.45-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v11\.45-boundary\.md` - Go artifact digest path boundary\./);
  assert.match(roadmap, /## v11\.45: Go Artifact Digest Path Boundary/);
  assert.match(draft, /reject malformed manifest `sha256` values before constructing digest-addressed sidecar or mirror paths/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /Go artifact manifest SHA-256 path boundary validation/);
  assert.match(boundary, /artifact manifest sha256 invalid/);
});

test("v11 public docs include receipt artifact digest shape validation", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.46-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v11\.46-boundary\.md` - receipt artifact digest shape boundary\./);
  assert.match(roadmap, /## v11\.46: Receipt Artifact Digest Shape Boundary/);
  assert.match(draft, /Receipt artifact manifest verification MUST reject malformed manifest `uri` and `sha256` values/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /receipt artifact manifest SHA-256 shape validation/);
  assert.match(boundary, /sha256: "\.\.\/evil"/);
});

test("v11 public docs include receipt artifact size shape validation", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.47-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v11\.47-boundary\.md` - receipt artifact size shape boundary\./);
  assert.match(roadmap, /## v11\.47: Receipt Artifact Size Shape Boundary/);
  assert.match(draft, /MUST reject negative or non-integer manifest `size` values/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /receipt artifact manifest size shape validation/);
  assert.match(boundary, /size: -1/);
  assert.match(boundary, /size: 1\.5/);
  assert.match(boundary, /artifact manifest size invalid/);
});

test("v11 public docs include Go artifact media type shape validation", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.48-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v11\.48-boundary\.md` - Go artifact media type shape boundary\./);
  assert.match(roadmap, /## v11\.48: Go Receipt Artifact Media Type Shape Boundary/);
  assert.match(draft, /Go receipt and audit artifact manifest verification MUST reject non-string manifest `media_type` values/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /Go artifact manifest media type shape validation/);
  assert.match(boundary, /media_type: \{"type":"text\/plain"\}/);
  assert.match(boundary, /artifact manifest media_type invalid/);
});

test("v11 public docs include Go artifact manifest hash shape validation", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.49-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v11\.49-boundary\.md` - Go artifact manifest hash shape boundary\./);
  assert.match(roadmap, /## v11\.49: Go Receipt Artifact Manifest Hash Shape Boundary/);
  assert.match(draft, /Go receipt and audit artifact manifest verification MUST reject non-string manifest `manifest_hash` values/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /Go artifact manifest hash shape validation/);
  assert.match(boundary, /manifest_hash: \{"hash":"\.\.\."\}/);
  assert.match(boundary, /artifact manifest manifest_hash invalid/);
});

test("v11 public docs include Go artifact list shape validation", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.50-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v11\.50-boundary\.md` - Go artifact list shape boundary\./);
  assert.match(roadmap, /## v11\.50: Go Artifact List Shape Boundary/);
  assert.match(draft, /MUST reject malformed `artifact_refs` and `artifact_manifests` list entries/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /Go artifact list entry shape validation/);
  assert.match(boundary, /artifact refs invalid/);
  assert.match(boundary, /artifact manifest missing/);
});

test("v11 public docs include Go artifact mirror index shape validation", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.51-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v11\.51-boundary\.md` - Go artifact mirror index shape boundary\./);
  assert.match(roadmap, /## v11\.51: Go Artifact Mirror Index Shape Boundary/);
  assert.match(draft, /MUST match index fields against receipt artifact manifest fields without string coercion/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /Go artifact mirror index exact field matching validation/);
  assert.match(boundary, /size: "7"/);
  assert.match(boundary, /numeric `size: 7`/);
});

test("v11 public docs include Go artifact mirror index entry validation", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.52-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v11\.52-boundary\.md` - Go artifact mirror index entry boundary\./);
  assert.match(roadmap, /## v11\.52: Go Artifact Mirror Index Entry Boundary/);
  assert.match(draft, /MUST reject non-object `objects\.ndjson` entries such as `null`/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /Go artifact mirror index entry object validation/);
  assert.match(boundary, /artifact mirror index invalid/);
  assert.match(boundary, /JSON `null` decodes into a nil Go map/);
});

test("v11 public docs include Go artifact mirror index digest validation", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.53-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v11\.53-boundary\.md` - Go artifact mirror index digest boundary\./);
  assert.match(roadmap, /## v11\.53: Go Artifact Mirror Index Digest Boundary/);
  assert.match(draft, /MUST reject index entries whose `sha256` field is missing or not a 64-hex digest/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /Go artifact mirror index SHA-256 path validation/);
  assert.match(boundary, /sha256: "\.\.\/evil"/);
  assert.match(boundary, /path-bearing digest field/);
});

test("v11 public docs include Go artifact mirror index digest presence validation", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.54-boundary.md", "utf8"),
  ]);

  assert.match(readme, /`docs\/v11\.54-boundary\.md` - Go artifact mirror index digest presence boundary\./);
  assert.match(roadmap, /## v11\.54: Go Artifact Mirror Index Digest Presence Boundary/);
  assert.match(draft, /MUST reject index entries whose `sha256` field is missing or not a 64-hex digest/);
  assert.match(status, /Go artifact mirror index SHA-256 presence validation/);
  assert.match(boundary, /missing `sha256` fields/);
  assert.match(boundary, /valid orphan\/index row/);
});

test("v11 public docs include Go artifact mirror index manifest hash validation", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.55-boundary.md", "utf8"),
  ]);

  assert.match(readme, /`docs\/v11\.55-boundary\.md` - Go artifact mirror index manifest hash boundary\./);
  assert.match(roadmap, /## v11\.55: Go Artifact Mirror Index Manifest Hash Boundary/);
  assert.match(draft, /MUST reject present `manifest_hash` values that are not 64-hex digests/);
  assert.match(status, /Go artifact mirror index manifest hash validation/);
  assert.match(boundary, /manifest_hash: "\.\.\/evil"/);
  assert.match(boundary, /does not make it required/);
});

test("v11 public docs include Go artifact mirror index AFP validation", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.56-boundary.md", "utf8"),
  ]);

  assert.match(readme, /`docs\/v11\.56-boundary\.md` - Go artifact mirror index AFP boundary\./);
  assert.match(roadmap, /## v11\.56: Go Artifact Mirror Index AFP Boundary/);
  assert.match(draft, /Present string `afp` values MUST equal `afp:sha256:<sha256>`/);
  assert.match(status, /Go artifact mirror index AFP validation/);
  assert.match(boundary, /valid `sha256` but mismatched AFP/);
  assert.match(boundary, /does not make it required/);
});

test("v11 public docs include Go artifact mirror index size validation", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.57-boundary.md", "utf8"),
  ]);

  assert.match(readme, /`docs\/v11\.57-boundary\.md` - Go artifact mirror index size boundary\./);
  assert.match(roadmap, /## v11\.57: Go Artifact Mirror Index Size Boundary/);
  assert.match(draft, /MUST reject present `size` values that are not non-negative integers/);
  assert.match(status, /Go artifact mirror index size validation/);
  assert.match(boundary, /size: "7"/);
  assert.match(boundary, /size: -1/);
  assert.match(boundary, /size: 1\.5/);
});

test("v11 public docs include Go artifact mirror index media type validation", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.58-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v11\.58-boundary\.md` - Go artifact mirror index media type boundary\./);
  assert.match(roadmap, /## v11\.58: Go Artifact Mirror Index Media Type Boundary/);
  assert.match(draft, /MUST reject present `media_type` values that are not strings/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /Go artifact mirror index media type validation/);
  assert.match(boundary, /media_type: \{"type":"text\/plain"\}/);
  assert.match(boundary, /does not make it required/);
});

test("v11 public docs include Go artifact mirror index URI validation", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.59-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v11\.59-boundary\.md` - Go artifact mirror index URI boundary\./);
  assert.match(roadmap, /## v11\.59: Go Artifact Mirror Index URI Boundary/);
  assert.match(draft, /MUST reject present `uri` values that are not strings/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /Go artifact mirror index URI validation/);
  assert.match(boundary, /uri: \{"path":"artifact:\/\/local\/out\.md"\}/);
  assert.match(boundary, /does not make it required/);
});

test("v11 public docs include Go artifact manifest URI validation", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.60-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v11\.60-boundary\.md` - Go artifact manifest URI boundary\./);
  assert.match(roadmap, /## v11\.60: Go Artifact Manifest URI Boundary/);
  assert.match(draft, /MUST reject non-string manifest `uri` values/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /Go artifact manifest URI validation/);
  assert.match(boundary, /artifact manifest uri invalid/);
  assert.match(boundary, /does not change local URI\/path validation/);
});

test("v11 public docs include Go artifact manifest AFP validation", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.61-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v11\.61-boundary\.md` - Go artifact manifest AFP boundary\./);
  assert.match(roadmap, /## v11\.61: Go Artifact Manifest AFP Boundary/);
  assert.match(draft, /MUST reject present non-string manifest `afp` values/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /Go artifact manifest AFP validation/);
  assert.match(boundary, /artifact manifest afp invalid/);
  assert.match(boundary, /artifact manifest afp mismatch/);
  assert.match(boundary, /does not make it required/);
});

test("v11 public docs include Go artifact mirror index AFP type validation", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.62-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v11\.62-boundary\.md` - Go artifact mirror index AFP type boundary\./);
  assert.match(roadmap, /## v11\.62: Go Artifact Mirror Index AFP Type Boundary/);
  assert.match(draft, /MUST reject present non-string `afp` values before comparing AFP strings/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /Go artifact mirror index AFP type validation/);
  assert.match(boundary, /artifact mirror index afp invalid/);
  assert.match(boundary, /artifact mirror index invalid/);
  assert.match(boundary, /does not make it required/);
});

test("v11 public docs include Go Swarm dependency list shape validation", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.63-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v11\.63-boundary\.md` - Go Swarm dependency list shape boundary\./);
  assert.match(roadmap, /## v11\.63: Go Swarm Dependency List Shape Boundary/);
  assert.match(draft, /MUST reject malformed `after` and `input_artifacts` list entries/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /Go Swarm dependency list shape validation/);
  assert.match(boundary, /swarm after invalid/);
  assert.match(boundary, /swarm input artifact invalid/);
  assert.match(boundary, /does not add generic Swarm schema validation/);
});

test("v11 public docs include Go Swarm close step list shape validation", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.64-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v11\.64-boundary\.md` - Go Swarm close step list shape boundary\./);
  assert.match(roadmap, /## v11\.64: Go Swarm Close Step List Shape Boundary/);
  assert.match(draft, /MUST reject malformed `step_receipts` list entries/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /Go Swarm close step receipt list shape validation/);
  assert.match(boundary, /swarm close step receipt invalid/);
  assert.match(boundary, /does not add generic Swarm close schema validation/);
});

test("v11 public docs include Go receipt approval list shape validation", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.65-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v11\.65-boundary\.md` - Go receipt approval list shape boundary\./);
  assert.match(roadmap, /## v11\.65: Go Receipt Approval List Shape Boundary/);
  assert.match(draft, /rejects malformed `approvals` and `approval_grants` list entries/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /Go receipt approval evidence list shape validation/);
  assert.match(boundary, /receipt approval invalid/);
  assert.match(boundary, /approval grant invalid/);
  assert.match(boundary, /does not add generic receipt schema validation/);
});

test("v11 public docs include Go receipt checkpoint list shape validation", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.66-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v11\.66-boundary\.md` - Go receipt checkpoint list shape boundary\./);
  assert.match(roadmap, /## v11\.66: Go Receipt Checkpoint List Shape Boundary/);
  assert.match(draft, /rejects malformed `checkpoint_refs` and `checkpoints` list entries/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /Go receipt checkpoint evidence list shape validation/);
  assert.match(boundary, /checkpoint ref invalid/);
  assert.match(boundary, /checkpoint invalid/);
  assert.match(boundary, /does not add generic receipt schema validation/);
});

test("v11 public docs include Go runtime checkpoint lookup list shape validation", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.67-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v11\.67-boundary\.md` - Go runtime checkpoint lookup list shape boundary\./);
  assert.match(roadmap, /## v11\.67: Go Runtime Checkpoint Lookup List Shape Boundary/);
  assert.match(draft, /checkpoint lookup for resume rejects malformed receipt `checkpoint_refs` and `checkpoints` list entries/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /Go runtime checkpoint lookup list shape validation/);
  assert.match(boundary, /checkpoint ref invalid/);
  assert.match(boundary, /checkpoint invalid/);
  assert.match(boundary, /does not add generic audit\/schema validation/);
});

test("v11 public docs include Go receipt artifact lookup list shape validation", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.68-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v11\.68-boundary\.md` - Go receipt artifact lookup list shape boundary\./);
  assert.match(roadmap, /## v11\.68: Go Receipt Artifact Lookup List Shape Boundary/);
  assert.match(draft, /receipt artifact lookup rejects malformed `artifact_refs` and `artifact_manifests` list entries/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /Go receipt artifact lookup list shape validation/);
  assert.match(boundary, /artifact refs invalid/);
  assert.match(boundary, /artifact manifest missing/);
  assert.match(boundary, /does not add generic receipt schema validation/);
});

test("v11 public docs include Go FED_SWARM_OPEN after list shape validation", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.69-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v11\.69-boundary\.md` - Go FED_SWARM_OPEN after list shape boundary\./);
  assert.match(roadmap, /## v11\.69: Go FED_SWARM_OPEN After List Shape Boundary/);
  assert.match(draft, /FED_SWARM_OPEN` execution MUST reject malformed step `after` list entries/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /Go FED_SWARM_OPEN after list shape validation/);
  assert.match(boundary, /swarm after invalid/);
  assert.match(boundary, /Missing `after` still serializes as an empty list/);
  assert.match(boundary, /does not add generic Swarm schema validation/);
});

test("v11 public docs include Go queue grant scope list shape validation", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.70-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v11\.70-boundary\.md` - Go queue grant scope list shape boundary\./);
  assert.match(roadmap, /## v11\.70: Go Queue Grant Scope List Shape Boundary/);
  assert.match(draft, /queue action grants reject malformed signed `scope\.actions` list entries/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /signed grant scope action list shape validation/);
  assert.match(boundary, /queue action grant scope invalid/);
  assert.match(boundary, /queue action grant scope mismatch/);
  assert.match(boundary, /does not add roles/);
});

test("v11 public docs include Go task write scope list shape validation", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.71-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v11\.71-boundary\.md` - Go task write scope list shape boundary\./);
  assert.match(roadmap, /## v11\.71: Go Task Write Scope List Shape Boundary/);
  assert.match(draft, /policy enforcement rejects malformed signed task `scope\.write` list entries/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /Go signed task write\/data-domain list shape validation/);
  assert.match(boundary, /policy\.write_invalid/);
  assert.match(boundary, /policy write scope invalid/);
  assert.match(boundary, /does not add generic task schema validation/);
});

test("v11 public docs include Go task data domains list shape validation", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.72-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v11\.72-boundary\.md` - Go task data domains list shape boundary\./);
  assert.match(roadmap, /## v11\.72: Go Task Data Domains List Shape Boundary/);
  assert.match(draft, /policy enforcement rejects malformed signed task `scope\.data_domains` list entries/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /Go signed task write\/data-domain list shape validation/);
  assert.match(boundary, /policy\.data_domains_invalid/);
  assert.match(boundary, /policy data domains invalid/);
  assert.match(boundary, /does not add generic task schema validation/);
});

test("v11 public docs include Go worker approval required list shape validation", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.73-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v11\.73-boundary\.md` - Go worker approval required list shape boundary\./);
  assert.match(roadmap, /## v11\.73: Go Worker Approval Required List Shape Boundary/);
  assert.match(draft, /worker policy `approval_required` list entries before tool approval gates can be skipped/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /worker policy approval-required list shape validation/);
  assert.match(boundary, /policy\.approval_required_invalid/);
  assert.match(boundary, /policy approval required invalid/);
  assert.match(boundary, /does not add roles/);
});

test("v11 public docs include Go receipt policy scope list shape validation", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.74-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v11\.74-boundary\.md` - Go receipt policy scope list shape boundary\./);
  assert.match(roadmap, /## v11\.74: Go Receipt Policy Scope List Shape Boundary/);
  assert.match(draft, /receipt verification rejects malformed `policy_scope` `write`, `tools`, `data_domains`, and `approval_required` list entries/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /receipt policy scope list shape validation/);
  assert.match(boundary, /policy_scope\.write/);
  assert.match(boundary, /policy scope <field> invalid/);
  assert.match(boundary, /does not add generic receipt schema validation/);
});

test("v11 public docs include Go receipt policy scope scalar shape validation", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.75-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v11\.75-boundary\.md` - Go receipt policy scope scalar shape boundary\./);
  assert.match(roadmap, /## v11\.75: Go Receipt Policy Scope Scalar Shape Boundary/);
  assert.match(draft, /receipt verification rejects malformed `policy_scope\.network` and `policy_scope\.expires_at` scalar fields/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /receipt policy scope list shape validation and scalar shape validation/);
  assert.match(boundary, /policy_scope\.network/);
  assert.match(boundary, /policy scope expires_at invalid/);
  assert.match(boundary, /does not add generic receipt schema validation/);
});

test("v11 public docs include Go receipt task id token validation", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.76-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v11\.76-boundary\.md` - Go receipt task id token boundary\./);
  assert.match(roadmap, /## v11\.76: Go Receipt Task ID Token Boundary/);
  assert.match(draft, /Node and Go receipt verification reject unsafe signed receipt `task_id` values/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /FED_RECEIPT verifier rejects unsafe signed receipt task ids/);
  assert.match(boundary, /verifyReceiptRecord` now reuses `validateTaskID`/);
  assert.match(boundary, /task_id invalid/);
  assert.match(boundary, /does not add generic receipt schema validation/);
});

test("v11 public docs include Node receipt task id token validation", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.77-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v11\.77-boundary\.md` - Node receipt task id token boundary\./);
  assert.match(roadmap, /## v11\.77: Node Receipt Task ID Token Boundary/);
  assert.match(draft, /`receipt\.task_id` matches the implemented token format/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /Node unsafe signed receipt `task_id` rejection/);
  assert.match(boundary, /verifyFederatedReceipt` now reuses `validateTaskId`/);
  assert.match(boundary, /task_id invalid/);
  assert.match(boundary, /does not add generic receipt schema validation/);
});

test("v11 public docs include Node receipt artifact URI shape validation", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.78-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v11\.78-boundary\.md` - Node receipt artifact URI\/ref shape boundary\./);
  assert.match(roadmap, /## v11\.78: Node Receipt Artifact URI Shape Boundary/);
  assert.match(draft, /Node and Go receipt artifact manifest verification MUST reject non-string manifest `uri` values/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /Node receipt artifact URI\/ref shape validation/);
  assert.match(boundary, /artifact manifest uri invalid/);
  assert.match(boundary, /artifact refs invalid/);
  assert.match(boundary, /does not add generic receipt schema validation/);
});

test("v11 public docs include public transport receipt proof binding", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v11-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v11.79-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v11\.79-boundary\.md` - public transport receipt proof boundary\./);
  assert.match(roadmap, /## v11\.79: Public Transport Receipt Proof Boundary/);
  assert.match(draft, /Go server-mode task receipts MAY include `transport_proof`/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /Go public-listen signed receipt transport proof/);
  assert.match(boundary, /transport_proof` binds `transport`, `listen_host`, `port`, and `public_transport`/);
  assert.match(boundary, /does not claim hosted public reachability/);
});

test("v12 public docs start with public proof bundle manifests", async () => {
  const [readme, roadmap, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v12-roadmap.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v12.0-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v12-roadmap\.md` - closed v12 roadmap\./);
  assert.match(readme, /`docs\/v12\.0-boundary\.md` - public proof bundle manifest boundary\./);
  assert.match(roadmap, /## v12\.0: Public Proof Bundle Manifest/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /v12.45-closeout-alignment/);
  assert.match(boundary, /state\/public-node-proof-bundle\.json/);
  assert.match(boundary, /not a new verifier or public network deployment/);
});

test("v12 public docs include proof bundle verifier command", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v12-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v12.1-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v12\.1-boundary\.md` - proof bundle verifier command boundary\./);
  assert.match(readme, /asp-verify\.mjs proof-bundle/);
  assert.match(roadmap, /## v12\.1: Proof Bundle Verifier Command/);
  assert.match(draft, /node asp-verify\.mjs proof-bundle <bundle\.json>/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /v12.45-closeout-alignment/);
  assert.match(boundary, /delegates to the existing receipt artifact and Swarm close verifier paths/);
  assert.match(boundary, /does not add batch verification/);
});

test("v12 public docs include public proof summary bundle verification", async () => {
  const [readme, roadmap, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v12-roadmap.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v12.2-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v12\.2-boundary\.md` - public proof summary bundle verification boundary\./);
  assert.match(roadmap, /## v12\.2: Public Proof Summary Bundle Verification/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /v12.45-closeout-alignment/);
  assert.match(boundary, /public proof summary returns `proof_bundle_verify: "ok"`/);
  assert.match(boundary, /does not add external public reachability proof/);
});

test("v12 public docs include bundle-relative proof file paths", async () => {
  const [readme, roadmap, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v12-roadmap.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v12.3-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v12\.3-boundary\.md` - bundle-relative proof file paths boundary\./);
  assert.match(readme, /bundle-relative proof file paths/);
  assert.match(roadmap, /## v12\.3: Bundle-Relative Proof File Paths/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /v12.45-closeout-alignment/);
  assert.match(boundary, /relative to the bundle manifest file/);
  assert.match(boundary, /does not make artifact bytes relocatable/);
});

test("v12 public docs include proof bundle path safety", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v12-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v12.4-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v12\.4-boundary\.md` - proof bundle path safety boundary\./);
  assert.match(roadmap, /## v12\.4: Proof Bundle Path Safety/);
  assert.match(draft, /v12\.45-protocol/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /v12.45-closeout-alignment/);
  assert.match(boundary, /rejects empty, absolute, backslash-bearing, `\.` segment, and `\.\.` segment proof-file paths/);
  assert.match(boundary, /does not make arbitrary bundle file layouts valid/);
});

test("v12 public docs include proof bundle type gate", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v12-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v12.5-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v12\.5-boundary\.md` - proof bundle type gate boundary\./);
  assert.match(roadmap, /## v12\.5: Proof Bundle Type Gate/);
  assert.match(draft, /v12\.45-protocol/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /v12.45-closeout-alignment/);
  assert.match(boundary, /checks `proof === "public-node-proof"` immediately/);
  assert.match(boundary, /does not add support for any other proof type/);
});

test("v12 public docs include proof bundle manifest object validation", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v12-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v12.6-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v12\.6-boundary\.md` - proof bundle manifest object boundary\./);
  assert.match(roadmap, /## v12\.6: Proof Bundle Manifest Object/);
  assert.match(draft, /v12\.45-protocol/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /v12.45-closeout-alignment/);
  assert.match(boundary, /rejects `null` or array bundle manifests/);
  assert.match(boundary, /does not validate every bundle field shape/);
});

test("v12 public docs include proof bundle path preflight", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v12-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v12.7-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v12\.7-boundary\.md` - proof bundle path preflight boundary\./);
  assert.match(roadmap, /## v12\.7: Proof Bundle Path Preflight/);
  assert.match(draft, /v12\.45-protocol/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /v12.45-closeout-alignment/);
  assert.match(boundary, /validates `receipt_frame`, `trusted_zones`, `swarm_close_frame`, and `swarm_close_trusted_zones` before reading any of them/);
  assert.match(boundary, /does not make missing files valid/);
});

test("v12 public docs include proof bundle CLI arity", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v12-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v12.8-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v12\.8-boundary\.md` - proof bundle CLI arity boundary\./);
  assert.match(readme, /proof-bundle <bundle\.json> \[external-trusted-zones\.json\]/);
  assert.match(roadmap, /## v12\.8: Proof Bundle CLI Arity/);
  assert.match(draft, /v12\.45-protocol/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /v12.45-closeout-alignment/);
  assert.match(boundary, /accepts exactly one bundle path argument/);
  assert.match(boundary, /does not make `proof-bundle` a batch command/);
});

test("v12 public docs include proof bundle exact CLI arity", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v12-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v12.9-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v12\.9-boundary\.md` - proof bundle exact CLI arity boundary\./);
  assert.match(readme, /proof-bundle <bundle\.json> \[external-trusted-zones\.json\]/);
  assert.match(roadmap, /## v12\.9: Proof Bundle Exact CLI Arity/);
  assert.match(draft, /v12\.45-protocol/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /v12.45-closeout-alignment/);
  assert.match(boundary, /requires exactly two CLI tokens/);
  assert.match(boundary, /does not add option parsing/);
});

test("v12 public docs include verifier CLI exact arity", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v12-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v12.10-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v12\.10-boundary\.md` - verifier CLI exact arity boundary\./);
  assert.match(roadmap, /## v12\.10: Verifier CLI Exact Arity/);
  assert.match(draft, /The verifier CLI commands reject unsupported extra positional arguments/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /v12.45-closeout-alignment/);
  assert.match(boundary, /Make every `asp-verify\.mjs` command reject extra positional CLI arguments/);
  assert.match(boundary, /does not add option parsing/);
});

test("v12 public docs include proof bundle public transport gate", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v12-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v12.11-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v12\.11-boundary\.md` - proof bundle public transport gate boundary\./);
  assert.match(roadmap, /## v12\.11: Proof Bundle Public Transport Gate/);
  assert.match(draft, /public_transport: true/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /v12.45-closeout-alignment/);
  assert.match(boundary, /reject signed but non-public transport proofs/);
  assert.match(boundary, /does not prove reachability from another host/);
});

test("v12 public docs include proof bundle transport proof shape", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v12-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v12.12-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v12\.12-boundary\.md` - proof bundle transport proof shape boundary\./);
  assert.match(roadmap, /## v12\.12: Proof Bundle Transport Proof Shape/);
  assert.match(draft, /listen_host/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /v12.45-closeout-alignment/);
  assert.match(boundary, /reject incomplete signed transport proofs/);
  assert.match(boundary, /does not prove reachability from another host/);
});

test("v12 public docs include proof bundle federation transport gate", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v12-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v12.13-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v12\.13-boundary\.md` - proof bundle federation transport gate boundary\./);
  assert.match(roadmap, /## v12\.13: Proof Bundle Federation Transport Gate/);
  assert.match(draft, /transport: "fed\+tcp"/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /v12.45-closeout-alignment/);
  assert.match(boundary, /reject non-federation transport proofs/);
  assert.match(boundary, /does not prove reachability from another host/);
});

test("v12 public docs include proof bundle listen host gate", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v12-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v12.14-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v12\.14-boundary\.md` - proof bundle listen host gate boundary\./);
  assert.match(roadmap, /## v12\.14: Proof Bundle Listen Host Gate/);
  assert.match(draft, /non-loopback/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /v12.45-closeout-alignment/);
  assert.match(boundary, /reject loopback public transport proofs/);
  assert.match(boundary, /does not prove reachability from another host/);
});

test("v12 public docs include proof bundle unspecified host gate", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v12-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v12.15-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v12\.15-boundary\.md` - proof bundle unspecified host gate boundary\./);
  assert.match(roadmap, /## v12\.15: Proof Bundle Unspecified Host Gate/);
  assert.match(draft, /non-loopback non-unspecified `listen_host`/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /v12.45-closeout-alignment/);
  assert.match(boundary, /reject unspecified listener hosts/);
  assert.match(boundary, /does not prove reachability from another host/);
});

test("v12 public docs include proof bundle reachability scope", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v12-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v12.16-boundary.md", "utf8"),
  ]);

  assert.match(readme, /`docs\/v12\.16-boundary\.md` - proof bundle reachability scope boundary\./);
  assert.match(roadmap, /## v12\.16: Proof Bundle Reachability Scope/);
  assert.match(draft, /reachability_scope: "local-interface"/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /v12.45-closeout-alignment/);
  assert.match(boundary, /label its current reachability scope/);
  assert.match(boundary, /does not prove reachability from another host/);
});

test("v12 public docs include proof bundle reachability scope ownership", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v12-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v12.17-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v12\.17-boundary\.md` - proof bundle reachability scope ownership boundary\./);
  assert.match(roadmap, /## v12\.17: Proof Bundle Reachability Scope Ownership/);
  assert.match(roadmap, /rejects bundle manifests that include `reachability_scope`/);
  assert.match(draft, /rejects bundle manifests that supply their own `reachability_scope`/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /v12.45-closeout-alignment/);
  assert.match(boundary, /keep reachability scope verifier-owned/);
  assert.match(boundary, /does not prove reachability from another host/);
});

test("v12 public docs include package artifact proof", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v12-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v12.18-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v12\.18-boundary\.md` - package artifact proof boundary\./);
  assert.match(readme, /scripts\/package-proof\.mjs/);
  assert.match(roadmap, /## v12\.18: Package Artifact Proof/);
  assert.match(roadmap, /npm pack --json --pack-destination state\/package-proof/);
  assert.match(draft, /node scripts\/package-proof\.mjs/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /v12.45-closeout-alignment/);
  assert.match(status, /local npm tarball artifact proof manifest metadata/);
  assert.match(boundary, /produce a real local package artifact/);
  assert.match(boundary, /does not sign the tarball or produce an SBOM/);
});

test("v12 public docs include package artifact SHA-256", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v12-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v12.19-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v12\.19-boundary\.md` - package artifact SHA-256 boundary\./);
  assert.match(roadmap, /## v12\.19: Package Artifact SHA-256/);
  assert.match(roadmap, /computes `sha256` over the produced npm tarball/);
  assert.match(draft, /v12\.45-protocol/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /v12.45-closeout-alignment/);
  assert.match(status, /including SHA-256/);
  assert.match(boundary, /same SHA-256 digest shape/);
  assert.match(boundary, /does not sign the tarball or produce an SBOM/);
});

test("v12 public docs include package proof manifest", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v12-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v12.20-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v12\.20-boundary\.md` - package proof manifest boundary\./);
  assert.match(roadmap, /## v12\.20: Package Proof Manifest/);
  assert.match(roadmap, /writes `state\/package-proof\/package-proof\.json`/);
  assert.match(draft, /v12\.45-protocol/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /v12.45-closeout-alignment/);
  assert.match(status, /package-proof\.json manifest/);
  assert.match(boundary, /stable file input/);
  assert.match(boundary, /does not sign the tarball or produce an SBOM/);
});

test("v12 public docs include package proof digest", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v12-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v12.21-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v12\.21-boundary\.md` - package proof digest boundary\./);
  assert.match(roadmap, /## v12\.21: Package Proof Digest/);
  assert.match(roadmap, /computes `proof_digest` as `sha256\(canonical\(proof without proof_digest\)\)`/);
  assert.match(draft, /v12\.45-protocol/);
  assert.match(draft, /package proof manifest includes `proof_digest`/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /v12.45-closeout-alignment/);
  assert.match(status, /canonical package proof digest/);
  assert.match(boundary, /stable digest over the package proof manifest body/);
  assert.match(boundary, /does not sign the tarball or produce an SBOM/);
});

test("v12 public docs include package proof verifier command", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v12-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v12.22-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v12\.22-boundary\.md` - package proof verifier command boundary\./);
  assert.match(readme, /asp-verify\.mjs package-proof/);
  assert.match(roadmap, /## v12\.22: Package Proof Verifier Command/);
  assert.match(roadmap, /verifies `proof_digest`, tarball `sha256`, and tarball size/);
  assert.match(draft, /node asp-verify\.mjs package-proof <manifest\.json>/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /v12.45-closeout-alignment/);
  assert.match(status, /package proof verifier command/);
  assert.match(boundary, /verify the generated package proof manifest and tarball/);
  assert.match(boundary, /does not sign the tarball or produce an SBOM/);
});

test("v12 public docs include package proof manifest object gate", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v12-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v12.23-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v12\.23-boundary\.md` - package proof manifest object boundary\./);
  assert.match(roadmap, /## v12\.23: Package Proof Manifest Object Gate/);
  assert.match(roadmap, /rejects `null` and array package proof manifests/);
  assert.match(draft, /package proof verifier rejects `null` and array manifests/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /v12.45-closeout-alignment/);
  assert.match(status, /package proof manifest object validation/);
  assert.match(boundary, /reject non-object package proof manifests/);
  assert.match(boundary, /does not sign the tarball or produce an SBOM/);
});

test("v12 public docs include package proof tarball path safety", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v12-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v12.24-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v12\.24-boundary\.md` - package proof tarball path safety boundary\./);
  assert.match(readme, /package proof tarball path safety/);
  assert.match(roadmap, /## v12\.24: Package Proof Tarball Path Safety/);
  assert.match(roadmap, /rejects absolute and parent-directory tarball paths/);
  assert.match(draft, /package proof verifier rejects unsafe tarball paths/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /v12.45-closeout-alignment/);
  assert.match(status, /package proof tarball path safety/);
  assert.match(boundary, /reject unsafe package proof tarball paths/);
  assert.match(boundary, /does not make package proofs relocatable/);
});

test("v12 public docs include package proof manifest-relative tarball", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v12-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v12.25-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v12\.25-boundary\.md` - package proof manifest-relative tarball boundary\./);
  assert.match(roadmap, /## v12\.25: Package Proof Manifest-Relative Tarball/);
  assert.match(roadmap, /resolves safe tarball paths relative to the manifest file/);
  assert.match(draft, /package proof verifier resolves safe tarball paths relative to the package proof manifest file/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /v12.45-closeout-alignment/);
  assert.match(status, /manifest-relative package tarball verification/);
  assert.match(boundary, /package proof directory can be copied and verified/);
  assert.match(boundary, /not package signing or SBOM/);
});

test("v12 public docs include package proof npm digest verification", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v12-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v12.26-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v12\.26-boundary\.md` - package proof npm digest verification boundary\./);
  assert.match(roadmap, /## v12\.26: Package Proof npm Digest Verification/);
  assert.match(roadmap, /checks `shasum` as SHA-1/);
  assert.match(roadmap, /checks `integrity` as the npm `sha512-<base64>` string/);
  assert.match(draft, /npm SHA-1 shasum, npm SHA-512 integrity string/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /v12.45-closeout-alignment/);
  assert.match(status, /npm shasum\/integrity verification/);
  assert.match(boundary, /reject npm digest metadata/);
  assert.match(boundary, /not package signatures or SBOM/);
});

test("v12 public docs include package proof verified metadata output", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v12-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v12.27-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v12\.27-boundary\.md` - package proof verified metadata output boundary\./);
  assert.match(roadmap, /## v12\.27: Package Proof Verified Metadata Output/);
  assert.match(roadmap, /returns verified `size`, `shasum`, and `integrity` fields/);
  assert.match(draft, /returns the verified package name, version, filename, tarball path, size, npm shasum, npm integrity, ASP SHA-256, proof digest, and signer Agent ID/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /v12.45-closeout-alignment/);
  assert.match(status, /verified package metadata output/);
  assert.match(boundary, /return the verified npm digest and size metadata/);
  assert.match(boundary, /not package signing or SBOM/);
});

test("v12 public docs include package proof filename binding", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v12-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v12.28-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v12\.28-boundary\.md` - package proof filename binding boundary\./);
  assert.match(roadmap, /## v12\.28: Package Proof Filename Binding/);
  assert.match(roadmap, /requires `filename` to equal the final path segment of `tarball`/);
  assert.match(draft, /requires `filename` to equal the final path segment of `tarball`/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /v12.45-closeout-alignment/);
  assert.match(status, /package filename\/tarball binding/);
  assert.match(boundary, /bind the displayed filename to the tarball path/);
  assert.match(boundary, /not package signing or SBOM/);
});

test("v12 public docs include package proof file list shape", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v12-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v12.29-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v12\.29-boundary\.md` - package proof file list shape boundary\./);
  assert.match(roadmap, /## v12\.29: Package Proof File List Shape/);
  assert.match(roadmap, /requires `files` to be a non-empty array of unique safe relative paths/);
  assert.match(draft, /The `files` field MUST be a non-empty array of unique safe relative paths/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /v12.45-closeout-alignment/);
  assert.match(status, /packaged file list shape/);
  assert.match(boundary, /reject malformed packaged file lists/);
  assert.match(boundary, /not package signing, SBOM, or a tarball member proof/);
});

test("v12 public docs include package proof manifest filename binding", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v12-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v12.30-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v12\.30-boundary\.md` - package proof manifest filename binding boundary\./);
  assert.match(roadmap, /## v12\.30: Package Proof Manifest Filename Binding/);
  assert.match(roadmap, /requires `manifest` to equal the final path segment of the verifier input path/);
  assert.match(draft, /requires `manifest` to equal the final path segment of the verifier input path/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /v12.45-closeout-alignment/);
  assert.match(status, /manifest\/input filename binding/);
  assert.match(boundary, /reject manifests whose `manifest` field does not match/);
  assert.match(boundary, /not package signing, SBOM, or a tarball member proof/);
});

test("v12 public docs include package proof identity filename binding", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v12-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v12.31-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v12\.31-boundary\.md` - package proof identity filename binding boundary\./);
  assert.match(roadmap, /## v12\.31: Package Proof Identity Filename Binding/);
  assert.match(roadmap, /requires `filename` to equal `<name>-<version>\.tgz`/);
  assert.match(draft, /requires `filename` to equal `<name>-<version>\.tgz`/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /v12.45-closeout-alignment/);
  assert.match(status, /package identity filename binding/);
  assert.match(boundary, /reject manifests whose package `name` and `version` metadata do not match/);
  assert.match(boundary, /not package signing, SBOM, or a tarball member proof/);
});

test("v12 public docs include Go canonical JSON HTML escape parity", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v12-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v12.32-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v12\.32-boundary\.md` - Go canonical JSON HTML escape parity boundary\./);
  assert.match(roadmap, /## v12\.32: Go Protocol Canonical JSON HTML-Escape Parity/);
  assert.match(roadmap, /match Node canonical JSON for signed and digested values containing `<`, `>`, and `&`/);
  assert.match(draft, /Go protocol signing, signature verification, and digest paths MUST use canonical JSON without HTML escaping/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /v12.45-closeout-alignment/);
  assert.match(status, /Go protocol canonical JSON no-HTML-escape parity/);
  assert.match(boundary, /Node canonical JSON does not HTML-escape `<`, `>`, or `&`/);
  assert.match(boundary, /protocol canonicalization parity fix/);
});

test("v12 public docs include external reachability evidence gate", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v12-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v12.33-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v12\.33-boundary\.md` - external reachability evidence gate boundary\./);
  assert.match(roadmap, /## v12\.33: External Reachability Evidence Gate/);
  assert.match(roadmap, /proof-bundle <bundle\.json> \[external-trusted-zones\.json\]/);
  assert.match(draft, /MUST fail closed/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /v12.45-closeout-alignment/);
  assert.match(status, /proof-bundle external reachability evidence trust gate/);
  assert.match(boundary, /external-host` requires a separately supplied trusted observer/);
  assert.match(boundary, /not a deployment system/);
});

test("v12 public docs include external reachability observer script", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v12-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v12.34-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v12\.34-boundary\.md` - external reachability observer boundary\./);
  assert.match(readme, /scripts\/external-reachability-observer\.mjs/);
  assert.match(roadmap, /## v12\.34: External Reachability Observer Script/);
  assert.match(roadmap, /TCP-connects to `transport_proof\.listen_host:port`/);
  assert.match(draft, /minimal implemented observer writer/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /v12.45-closeout-alignment/);
  assert.match(status, /external reachability observer TCP proof writer/);
  assert.match(boundary, /This is observer tooling, not deployment proof by itself/);
});

test("v12 public docs include Docker external reachability observer wrapper", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v12-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v12.35-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v12\.35-boundary\.md` - Docker external reachability observer wrapper boundary\./);
  assert.match(readme, /scripts\/docker-external-reachability-observer\.sh/);
  assert.match(roadmap, /## v12\.35: Docker External Reachability Observer Wrapper/);
  assert.match(roadmap, /host\.docker\.internal/);
  assert.match(draft, /docker-external-reachability-observer\.sh/);
  assert.match(draft, /container boundary, not hosted deployment/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /v12.45-closeout-alignment/);
  assert.match(status, /Docker external reachability observer wrapper/);
  assert.match(boundary, /containerized observer runner/);
  assert.match(boundary, /not outside-host deployment proof by itself/);
});

test("v12 public docs keep upper-layer demo outside the core line", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v12-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v12.37-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v12\.37-boundary\.md` - core substrate recenter boundary\./);
  assert.doesNotMatch(readme, /upper-layer-demo\.mjs/);
  assert.match(roadmap, /## v12\.37: Core Substrate Recenter/);
  assert.match(roadmap, /upper-layer demo\/orchestration work parked outside this repository/);
  assert.doesNotMatch(draft, /upper-layer-demo\.mjs/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /v12.45-closeout-alignment/);
  assert.doesNotMatch(status, /Upper-layer demo/);
  assert.match(boundary, /final upper layer will be developed separately/);
  assert.match(boundary, /not a new orchestration runtime/);
});

test("v12 public docs include package proof ASP signature", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v12-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v12.38-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v12\.38-boundary\.md` - package proof ASP signature boundary\./);
  assert.match(roadmap, /## v12\.38: Package Proof ASP Signature/);
  assert.match(roadmap, /state\/keys\/package-proof-signer\.pkcs8/);
  assert.match(draft, /signer Agent descriptor and `signature`/);
  assert.match(draft, /not npm registry signing, release transparency, package publish, or SBOM/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /v12.45-closeout-alignment/);
  assert.match(status, /ASP package proof signature/);
  assert.match(boundary, /Sign the local package proof manifest with an ASP agent identity/);
  assert.match(boundary, /not a full package release trust system/);
});

test("v12 public docs include package proof trusted signer pin", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v12-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v12.39-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v12\.39-boundary\.md` - package proof trusted signer pin boundary\./);
  assert.match(roadmap, /## v12\.39: Package Proof Trusted Signer Pin/);
  assert.match(roadmap, /trusted-signers\.json/);
  assert.match(draft, /package-proof <manifest\.json> \[trusted-signers\.json\]/);
  assert.match(draft, /not npm registry signing, release transparency, package publish, or SBOM/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /v12.45-closeout-alignment/);
  assert.match(status, /trusted package signer pinning/);
  assert.match(boundary, /caller-supplied trusted signer file/);
  assert.match(boundary, /not a full package release trust system/);
});

test("v12 public docs include trusted signer list shape", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v12-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v12.40-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v12\.40-boundary\.md` - trusted signer list shape boundary\./);
  assert.match(roadmap, /## v12\.40: Trusted Signer List Shape/);
  assert.match(roadmap, /trusted package signer list missing/);
  assert.match(draft, /Null files and objects without signer lists fail/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /v12.45-closeout-alignment/);
  assert.match(status, /trusted signer list shape validation/);
  assert.match(boundary, /rejects `null` trusted signer files/);
  assert.match(boundary, /not a full package release trust system/);
});

test("v12 public docs include package proof metadata preflight", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v12-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v12.41-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v12\.41-boundary\.md` - package proof metadata preflight boundary\./);
  assert.match(roadmap, /## v12\.41: Package Proof Metadata Preflight/);
  assert.match(roadmap, /before reading the tarball/);
  assert.match(draft, /rejects malformed packaged file lists before reading tarball bytes/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /v12.45-closeout-alignment/);
  assert.match(status, /package proof metadata preflight/);
  assert.match(boundary, /before reading tarball bytes/);
  assert.match(boundary, /not a generic package release trust system/);
});

test("v12 public docs include package proof identity shape", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v12-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v12.42-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v12\.42-boundary\.md` - package proof identity shape boundary\./);
  assert.match(roadmap, /## v12\.42: Package Proof Identity Shape/);
  assert.match(roadmap, /package proof identity invalid/);
  assert.match(draft, /requires `name`, `version`, and `filename` to be non-empty strings/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /v12.45-closeout-alignment/);
  assert.match(status, /package identity scalar shape/);
  assert.match(boundary, /Reject non-string package identity metadata/);
  assert.match(boundary, /not a generic package release trust system/);
});

test("v12 public docs include package proof byte metadata shape", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v12-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v12.43-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v12\.43-boundary\.md` - package proof byte metadata shape boundary\./);
  assert.match(roadmap, /## v12\.43: Package Proof Byte Metadata Shape/);
  assert.match(roadmap, /package proof byte metadata invalid/);
  assert.match(draft, /requires `shasum`, `integrity`, and `sha256` to be non-empty strings/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /v12.45-closeout-alignment/);
  assert.match(status, /package byte metadata scalar shape/);
  assert.match(boundary, /Reject malformed package byte metadata/);
  assert.match(boundary, /not a generic package release trust system/);
});

test("v12 public docs include package proof signer capability", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v12-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v12.44-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v12\.44-boundary\.md` - package proof signer capability boundary\./);
  assert.match(roadmap, /## v12\.44: Package Proof Signer Capability/);
  assert.match(roadmap, /package proof signer capability missing/);
  assert.match(draft, /signer `package\.proof\.sign` capability/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /v12.45-closeout-alignment/);
  assert.match(status, /package proof signer capability/);
  assert.match(boundary, /Require package proof signers to declare/);
  assert.match(boundary, /not a full package release trust system/);
});

test("v12 public docs agree that the proof-surface milestone is closed", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v12-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v12.45-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v12 closed at `v12\.45-protocol`/);
  assert.match(readme, /`docs\/v12-roadmap\.md` - closed v12 roadmap\./);
  assert.match(readme, /`docs\/v12\.45-boundary\.md` - latest closed boundary\./);
  assert.match(roadmap, /状态：closed at v12\.45/);
  assert.match(roadmap, /## v12\.45: V12 Closeout Alignment/);
  assert.match(roadmap, /v12 到此收尾/);
  assert.match(draft, /local-first prototype at `v12\.45-protocol`/);
  assert.match(status, /状态：v12 closed at v12\.45/);
  assert.match(status, /v12.45-closeout-alignment/);
  assert.match(status, /closed v12 proof surface/);
  assert.match(boundary, /Close v12 as the externally consumable proof-surface milestone/);
  assert.match(boundary, /upper-layer demo\/master-agent orchestration/);
});

test("v13 public docs open the Ultimate-facing protocol milestone without scope drift", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v13-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v13.0-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v14 active at `v14\.10-protocol`/);
  assert.match(readme, /`docs\/v13-roadmap\.md` - closed v13 roadmap\./);
  assert.match(readme, /`docs\/v13\.0-boundary\.md` - v13 opening boundary\./);
  assert.match(roadmap, /状态：active at v13\.15/);
  assert.match(roadmap, /v13 uses larger evidence gates instead of many tiny versions/);
  assert.match(roadmap, /## v13\.1: Hosted Public Reachability Evidence/);
  assert.match(roadmap, /## v13\.2: Release Trust and SBOM/);
  assert.match(roadmap, /## v13\.3: Strong Sandbox and Remote Attestation/);
  assert.match(roadmap, /## v13\.4: Semantic Discovery and Reputation Ranking/);
  assert.match(roadmap, /## v13\.5: Dynamic Swarm Scheduling/);
  assert.match(roadmap, /## v13\.10: Go FED_QUERY Semantic Discovery Parity/);
  assert.match(roadmap, /## v13\.11: Audit-Backed Receipt-Count Reputation/);
  assert.match(roadmap, /## v13\.15: Node Receipt Checkpoint Verification/);
  assert.match(readme, /`docs\/v13\.15-boundary\.md` - v13\.15 Node receipt checkpoint verification boundary\./);
  assert.match(roadmap, /upper-layer demo\/master-agent orchestration stays outside this repository/);
  assert.match(roadmap, /A2A\/ARD compatibility stays parked/);
  assert.match(draft, /local-first prototype at `v14\.10-protocol`/);
  assert.match(status, /状态：v14 active at v14\.11/);
  assert.match(status, /v13.15-node-receipt-checkpoint-verification/);
  assert.match(status, /v13\.1 reachability evidence gates are active: verifier-owned scope classes and observer evidence binding landed with tests; real hosted external-host evidence is still pending/);
  assert.match(boundary, /Open v13 as the Ultimate-facing protocol milestone/);
  assert.match(boundary, /real hosted\/public reachability/);
  assert.match(boundary, /semantic discovery\/reputation ranking/);
  assert.match(boundary, /dynamic Swarm scheduling/);
  assert.match(boundary, /strong sandbox\/remote attestation/);
  assert.match(boundary, /release trust\/SBOM/);
  assert.match(boundary, /no fake public reachability without external-host evidence/);
});

test("v13.1 public docs describe active reachability scope without hosted exit drift", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v13-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v13.1-boundary.md", "utf8"),
  ]);

  assert.match(roadmap, /状态：active at v13\.15/);
  assert.match(roadmap, /状态：active\n目标：把 v12 的 local-interface proof 推进到 verifier-owned reachability scope classes/);
  assert.match(roadmap, /Valid trusted observer evidence returns `reachability_observer_zid` for both `container-observer` and `external-host` scopes/);
  assert.match(roadmap, /hostname listen hosts are out of scope for this slice/);
  assert.match(draft, /reports `reachability_scope: "container-observer"` for `vantage: "container"`/);
  assert.match(draft, /`reachability_scope: "external-host"` for `vantage: "external-host"` only when the signed receipt `listen_host` is a globally routable literal IP/);
  assert.match(draft, /Observer-backed scopes return `reachability_observer_zid`/);
  assert.match(status, /状态：v14 active at v14\.11/);
  assert.match(status, /v13\.1 reachability evidence gates are active: verifier-owned scope classes and observer evidence binding landed with tests; real hosted external-host evidence is still pending as the remaining v13\.1 exit criterion/);
  assert.match(status, /`external-host` requires a globally routable literal-IP listen host; hostname listen hosts are out of scope for this slice/);
  assert.match(boundary, /状态：active/);
  assert.match(boundary, /It is active, not complete: the mechanism and negative gates are in place, but the hosted external-host observer run has not happened yet and remains the remaining v13\.1 exit criterion/);
  assert.match(boundary, /`container-observer` proves a containerized observer boundary only; it is not hosted external-host reachability/);
  assert.match(boundary, /Remaining exit criterion: run the observer from a real hosted external host against a globally routable literal-IP listener/);
  const oldObserverField = new RegExp("external_" + "observer_zid");
  for (const doc of [readme, roadmap, draft, status, boundary]) assert.doesNotMatch(doc, oldObserverField);
});

test("v13.2 public docs describe release trust without supply-chain overclaims", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v13-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v13.2-boundary.md", "utf8"),
  ]);

  const formatNonClaims = /`asp-release-trust\/v1`.*not CycloneDX, not SPDX, not SLSA provenance, not npm registry signing, not package publish, not release transparency,.*not a generic supply-chain platform/s;
  for (const doc of [roadmap, draft, status, boundary]) assert.match(doc, formatNonClaims);
  assert.match(readme, /v14 active at `v14\.10-protocol`/);
  assert.doesNotMatch(readme, /release trust\/SBOM remain pending v13 gates/);
  assert.match(roadmap, /状态：active at v13\.15/);
  assert.match(roadmap, /状态：complete\n目标：把 v12 package proof 推进到 release trust\/SBOM evidence over the produced artifact/);
  assert.match(roadmap, /`asp-verify\.mjs release-trust <release-trust\.json> \[trusted-release-signers\.json\]` verifies package-proof binding, tarball bytes, release signer capability, trusted release signer pins, and manifest signature/);
  assert.match(draft, /local-first prototype at `v14\.10-protocol`/);
  assert.match(draft, /node asp-verify\.mjs release-trust <release-trust\.json> \[trusted-release-signers\.json\]/);
  assert.match(draft, /Release trust staleness means `package_proof_digest` no longer matches the verified referenced package proof/);
  assert.match(draft, /Trusted release signer pinning applies to the release signer only\. It does not pin or replace the embedded package proof signer trust decision/);
  assert.match(status, /状态：v14 active at v14\.11/);
  assert.match(status, /当前代码基线：`v14\.11-apple-private-workspace-proof`/);
  assert.match(status, /asp-verify\.mjs release-trust <release-trust\.json> \[trusted-release-signers\.json\] verifies `asp-release-trust\/v1` release trust manifests/);
  assert.match(status, /scripts\/release-trust\.mjs verifies the existing package proof first/);
  assert.match(boundary, /状态：complete/);
  assert.match(boundary, /Evidence binds name, version, tarball bytes, package proof digest, signer identity, and file list from the verified package proof/);
  assert.match(boundary, /Stale release trust means the referenced package proof drifted from `package_proof_digest`; releases do not expire by elapsed time/);
  assert.match(boundary, /Release trust fails closed when unsigned, signed by a descriptor without `release\.trust\.sign`, signed by the wrong release signer under an optional trust pin, or bound to mismatched package proof fields/);
  assert.match(boundary, /Protocol tag advances to `v13\.2-protocol` as the latest complete slice while the v13\.1 hosted external-host observer run remains pending and visible/);
});

test("v13.4 public docs describe evidence-first semantic discovery without marketplace overclaims", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v13-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v13.4-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v14 active at `v14\.10-protocol`/);
  assert.match(roadmap, /状态：active at v13\.15/);
  assert.match(roadmap, /状态：complete\n目标：在 Node federation gateway 上增加证据优先的 semantic discovery\/reputation ranking primitive/);
  assert.match(roadmap, /No vector database, no global reputation coin, no public marketplace, and no Go query parity in this slice/);
  assert.match(draft, /local-first prototype at `v14\.10-protocol`/);
  assert.match(draft, /`FED_QUERY` may carry an `intent` string for semantic discovery/);
  assert.match(draft, /Ranking is deterministic and evidence-first: exact capability match, trusted capability credential, signed credential claims, audit-backed reputation, zone-chain provenance, verifier-owned routing signals, and semantic token overlap are exposed as inspectable evidence/);
  assert.match(status, /状态：v14 active at v14\.11/);
  assert.match(status, /当前代码基线：`v14\.11-apple-private-workspace-proof`/);
  assert.match(status, /Node federation gateway evidence-first semantic discovery\/reputation ranking/);
  assert.match(boundary, /状态：complete/);
  assert.match(boundary, /Land the first evidence-first semantic discovery\/reputation ranking primitive without adding vector infrastructure/);
  assert.match(boundary, /The semantic-only candidate cannot outrank the exact capability candidate with trusted credential and receipt-count evidence/);
  assert.match(boundary, /not global reputation, not vector-only routing, not public marketplace, and not Go query parity/);
});

test("v13.5 public docs describe scheduler-owned ready-DAG Swarm without orchestration overclaims", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v13-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v13.5-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v14 active at `v14\.10-protocol`/);
  assert.match(roadmap, /状态：active at v13\.15/);
  assert.match(roadmap, /状态：complete\n目标：把 explicit two-step Swarm proof 推进到 scheduler-owned ready-DAG execution primitive/);
  assert.match(roadmap, /No automatic task decomposition, no parallel worker pool, no upper-layer master-agent orchestration, and no economic settlement in this slice/);
  assert.match(draft, /`FED_SWARM_SCHEDULE` accepts a signed Swarm DAG and executes steps in deterministic ready order/);
  assert.match(draft, /The close proof may include signed scheduler evidence with `mode: "ready-dag"` and the executed `step_order`/);
  assert.match(status, /状态：v14 active at v14\.11/);
  assert.match(status, /当前代码基线：`v14\.11-apple-private-workspace-proof`/);
  assert.match(status, /Go `FED_SWARM_SCHEDULE` scheduler-owned ready-DAG execution/);
  assert.match(boundary, /状态：complete/);
  assert.match(boundary, /Land the first scheduler-owned ready-DAG Swarm execution primitive/);
  assert.match(boundary, /Out-of-order input steps execute in dependency-ready order and close proof records `scheduler\.step_order`/);
  assert.match(boundary, /not automatic decomposition, not parallel execution, not upper-layer master-agent orchestration, and not economic settlement/);
});

test("v13.6 public docs describe sandbox proof verification without attestation overclaims", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v13-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v13.6-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v14 active at `v14\.10-protocol`/);
  assert.match(readme, /`asp-verify\.mjs sandbox-proof <frame\.json> <trusted-zones\.json> \[required-sandbox-class\]`/);
  assert.doesNotMatch(readme, /strong sandbox\/remote attestation remain pending v13 gates/);
  assert.match(roadmap, /状态：active at v13\.15/);
  assert.match(roadmap, /状态：active\n目标：把 honest local-process sandbox evidence 推进到 verifier-owned sandbox proof class validation/);
  assert.match(roadmap, /`asp-verify\.mjs sandbox-proof <frame\.json> <trusted-zones\.json> \[required-sandbox-class\]`/);
  assert.match(roadmap, /Hardware remote attestation remains unimplemented and fail-closed/);
  assert.match(draft, /local-first prototype at `v14\.10-protocol`/);
  assert.match(draft, /node asp-verify\.mjs sandbox-proof <frame\.json> <trusted-zones\.json> \[required-sandbox-class\]/);
  assert.match(status, /状态：v14 active at v14\.11/);
  assert.match(status, /当前代码基线：`v14\.11-apple-private-workspace-proof`/);
  assert.match(status, /sandbox-proof <frame\.json> <trusted-zones\.json> \[required-sandbox-class\]/);
  assert.match(boundary, /状态：complete/);
  assert.match(boundary, /It verifies a signed `local\.sandbox\.v1` proof embedded in a verified `FED_RECEIPT` frame/);
  assert.match(boundary, /not hardware remote attestation, not container namespace execution, and not a VM\/TEE claim/);
});

test("v13.7 public docs describe signed sandbox attestation without hardware overclaims", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v13-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v13.7-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v14 active at `v14\.10-protocol`/);
  assert.match(readme, /`asp-verify\.mjs sandbox-attestation <frame\.json> <trusted-zones\.json> <attestation\.json> <trusted-attestors\.json>`/);
  assert.match(roadmap, /状态：active at v13\.15/);
  assert.match(roadmap, /`asp-verify\.mjs sandbox-attestation <frame\.json> <trusted-zones\.json> <attestation\.json> <trusted-attestors\.json>`/);
  assert.match(roadmap, /Signed sandbox attestation evidence is not hardware remote attestation by itself/);
  assert.match(draft, /local-first prototype at `v14\.10-protocol`/);
  assert.match(draft, /node asp-verify\.mjs sandbox-attestation <frame\.json> <trusted-zones\.json> <attestation\.json> <trusted-attestors\.json>/);
  assert.match(status, /状态：v14 active at v14\.11/);
  assert.match(status, /当前代码基线：`v14\.11-apple-private-workspace-proof`/);
  assert.match(status, /sandbox-attestation <frame\.json> <trusted-zones\.json> <attestation\.json> <trusted-attestors\.json>/);
  assert.match(boundary, /状态：complete/);
  assert.match(boundary, /It verifies `asp-sandbox-attestation\/v1` signed evidence/);
  assert.match(boundary, /not hardware remote attestation, not container namespace execution, and not a TEE quote/);
});

test("v13.8 public docs describe pinned external observer identity without hosted overclaim", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v13-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v13.8-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v14 active at `v14\.10-protocol`/);
  assert.match(readme, /`AGNET_REACHABILITY_OBSERVER_SEED_HEX`/);
  assert.match(roadmap, /状态：active at v13\.15/);
  assert.match(roadmap, /Pinned external observer identity/);
  assert.match(draft, /local-first prototype at `v14\.10-protocol`/);
  assert.match(draft, /AGNET_REACHABILITY_OBSERVER_SEED_HEX/);
  assert.match(status, /状态：v14 active at v14\.11/);
  assert.match(status, /当前代码基线：`v14\.11-apple-private-workspace-proof`/);
  assert.match(status, /observer identity can be pinned before a hosted run/);
  assert.match(boundary, /状态：complete/);
  assert.match(boundary, /pre-pinned trusted observer identity/);
  for (const doc of [roadmap, draft, status, boundary]) {
    assert.match(doc, /real hosted external-host observer run (?:is still pending|has not happened yet)/);
  }
});

test("v13.9 public docs describe hosted observer runner without hiding IPv6 blocker", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v13-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v13.9-boundary.md", "utf8"),
  ]);

  assert.match(readme, /v14 active at `v14\.10-protocol`/);
  assert.match(readme, /AGNET_PUBLIC_LISTEN_HOST/);
  assert.match(readme, /AGNET_PUBLIC_PROOF_KEEPALIVE_MS/);
  assert.match(roadmap, /状态：active at v13\.15/);
  assert.match(roadmap, /GitHub hosted observer runner/);
  assert.match(draft, /local-first prototype at `v14\.10-protocol`/);
  assert.match(draft, /AGNET_PUBLIC_LISTEN_HOST/);
  assert.match(status, /状态：v14 active at v14\.11/);
  assert.match(status, /当前代码基线：`v14\.11-apple-private-workspace-proof`/);
  for (const doc of [roadmap, status, boundary]) {
    assert.match(doc, /28916288568/);
    assert.match(doc, /ENETUNREACH/);
    assert.match(doc, /real hosted external-host observer run (?:is still pending|has not happened yet)/);
  }
});

test("v13.10 public docs record Go FED_QUERY semantic parity without overclaims", async () => {
  const [readme, roadmap, draft, status, boundary] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v13-roadmap.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/v13.10-boundary.md", "utf8"),
  ]);

  assert.match(roadmap, /## v13\.10: Go FED_QUERY Semantic Discovery Parity/);
  assert.match(roadmap, /semanticScore/);
  assert.match(boundary, /状态：complete/);
  assert.match(boundary, /No vector database/);
  for (const doc of [readme, roadmap, draft, status, boundary]) {
    assert.doesNotMatch(doc, /v13\.9-protocol/);
  }
});

test("v13.11 public docs record audit-backed receipt-count reputation without oracle overclaims", async () => {
  const [readme, roadmap, boundary, status, draft] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v13-roadmap.md", "utf8"),
    readFile("docs/v13.11-boundary.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
  ]);

  for (const doc of [roadmap, boundary, status, draft]) {
    assert.match(doc, /receipt counts come from the persisted audit log/);
    assert.match(doc, /not a hardcoded demo value, not cross-session (?:ML|learned scoring), (?:and )?not (?:a )?(?:global reputation oracle|third-party reputation service)/);
    assert.doesNotMatch(doc, /ephemeral receipt count/);
  }
  assert.match(readme, /v14 active at `v14\.10-protocol`/);
  assert.match(readme, /`docs\/v13\.11-boundary\.md` - v13\.11 audit-backed receipt-count reputation boundary\./);
  assert.match(roadmap, /状态：active at v13\.15/);
  assert.match(roadmap, /## v13\.11: Audit-Backed Receipt-Count Reputation/);
  assert.match(boundary, /状态：complete/);
  assert.match(status, /状态：v14 active at v14\.11/);
  assert.match(status, /当前代码基线：`v14\.11-apple-private-workspace-proof`/);
  assert.match(draft, /local-first prototype at `v14\.10-protocol`/);
});

test("v13.12 public docs record credential valid_until expiry without credential lifecycle overclaims", async () => {
  const [readme, roadmap, boundary, status, draft] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v13-roadmap.md", "utf8"),
    readFile("docs/v13.12-boundary.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
  ]);

  for (const doc of [roadmap, boundary, status, draft]) {
    assert.match(doc, /Capability credentials may carry a `valid_until` ISO UTC expiry in claims; expired credentials lower discovery score and report `active: false` in discovery evidence\./);
    assert.doesNotMatch(doc, /hardware key management/i);
    assert.doesNotMatch(doc, /cross-zone credential exchange/i);
  }
  assert.match(readme, /v14 active at `v14\.10-protocol`/);
  assert.match(readme, /`docs\/v13\.12-boundary\.md` - v13\.12 credential valid_until expiry boundary\./);
  assert.match(roadmap, /状态：active at v13\.15/);
  assert.match(roadmap, /## v13\.12: Credential Validity Window/);
  assert.match(boundary, /状态：complete/);
  assert.match(status, /状态：v14 active at v14\.11/);
  assert.match(status, /当前代码基线：`v14\.11-apple-private-workspace-proof`/);
  assert.match(draft, /local-first prototype at `v14\.10-protocol`/);
});

test("v13.13 public docs record zone revocation in discovery without oracle overclaims", async () => {
  const [readme, roadmap, boundary, status, draft] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v13-roadmap.md", "utf8"),
    readFile("docs/v13.13-boundary.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
  ]);

  for (const doc of [roadmap, boundary, status, draft]) {
    assert.match(doc, /authority Zone revocation in FED_QUERY discovery/);
    assert.match(doc, /(?:revoked workers lose credential contribution in `agent_score`|Revoked workers get no credential score boost)/);
    assert.doesNotMatch(doc, /global revocation list/i);
    assert.doesNotMatch(doc, /revocation oracle/i);
  }
  assert.match(readme, /v14 active at `v14\.10-protocol`/);
  assert.match(readme, /`docs\/v13\.13-boundary\.md` - v13\.13 authority Zone revocation discovery boundary\./);
  assert.match(roadmap, /状态：active at v13\.15/);
  assert.match(roadmap, /## v13\.13: Zone Revocation in FED_QUERY Discovery/);
  assert.match(boundary, /状态：complete/);
  assert.match(status, /状态：v14 active at v14\.11/);
  assert.match(status, /当前代码基线：`v14\.11-apple-private-workspace-proof`/);
  assert.match(draft, /local-first prototype at `v14\.10-protocol`/);
});

test("v13.14 public docs record multi-signal agent score without oracle or ML overclaims", async () => {
  const [readme, roadmap, boundary, status, draft] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v13-roadmap.md", "utf8"),
    readFile("docs/v13.14-boundary.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
  ]);

  for (const doc of [roadmap, boundary, status, draft]) {
    assert.match(doc, /agent_score/);
    assert.match(doc, /freshness_score/);
    assert.match(doc, /revocation_penalty/);
    assert.doesNotMatch(doc, /global reputation oracle/i);
    assert.doesNotMatch(doc, /machine learning/i);
  }
  assert.match(readme, /v14 active at `v14\.10-protocol`/);
  assert.match(readme, /`docs\/v13\.14-boundary\.md` - v13\.14 multi-signal agent score reputation boundary\./);
  assert.match(roadmap, /状态：active at v13\.15/);
  assert.match(roadmap, /## v13\.14: Multi-Signal Agent Score in Reputation/);
  assert.match(boundary, /状态：complete/);
  assert.match(status, /状态：v14 active at v14\.11/);
  assert.match(status, /当前代码基线：`v14\.11-apple-private-workspace-proof`/);
  assert.match(draft, /local-first prototype at `v14\.10-protocol`/);
});

test("v13.15 public docs record Node receipt checkpoint verification without restore or orchestration overclaims", async () => {
  const [readme, roadmap, boundary, status, draft] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v13-roadmap.md", "utf8"),
    readFile("docs/v13.15-boundary.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
  ]);

  for (const doc of [roadmap, boundary, status, draft]) {
    assert.match(doc, /checkpoint_refs/);
    assert.match(doc, /checkpoints/);
    assert.match(doc, /checkpoint_signature/);
    assert.doesNotMatch(doc, /model KV\/cache restore is complete/i);
    assert.doesNotMatch(doc, /scheduler orchestration is complete/i);
    assert.doesNotMatch(doc, /A2A\/ARD compatibility is implemented/i);
  }
  assert.match(readme, /v14 active at `v14\.10-protocol`/);
  assert.match(readme, /`docs\/v13\.15-boundary\.md` - v13\.15 Node receipt checkpoint verification boundary\./);
  assert.match(roadmap, /状态：active at v13\.15/);
  assert.match(roadmap, /## v13\.15: Node Receipt Checkpoint Verification/);
  assert.match(boundary, /状态：complete/);
  assert.match(boundary, /receipt-carried checkpoint evidence/);
  assert.match(status, /状态：v14 active at v14\.11/);
  assert.match(status, /当前代码基线：`v14\.11-apple-private-workspace-proof`/);
  assert.match(draft, /local-first prototype at `v14\.10-protocol`/);
  assert.match(draft, /Node `FED_RECEIPT` verification requires `checkpoint_refs` and `checkpoints` to have equal length/);
});

test("v14 public docs open the overlay/swarm/routing milestone without terminal overclaims", async () => {
  const [readme, roadmap, boundary, status, draft] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v14-roadmap.md", "utf8"),
    readFile("docs/v14.0-boundary.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
  ]);

  assert.match(readme, /v14 active at `v14\.10-protocol`/);
  assert.match(readme, /`docs\/v14-roadmap\.md` - active v14 roadmap\./);
  assert.match(readme, /`docs\/v14\.0-boundary\.md` - v14 opening boundary\./);
  assert.match(roadmap, /状态：active at v14\.10/);
  assert.match(roadmap, /## v14\.1: Swarm Micro-contracts/);
  assert.match(roadmap, /## v14\.2: Multi-signal FED_QUERY routing/);
  assert.match(roadmap, /## v14\.3: Cross-zone trust chains/);
  assert.match(roadmap, /## v14\.4: Task failure migration/);
  assert.match(roadmap, /candidates sign cost\+latency\+capability micro-contract/);
  assert.match(roadmap, /v14 stays local-first/);
  assert.match(roadmap, /no P2P DHT/);
  assert.match(roadmap, /no token economy/);
  assert.match(boundary, /状态：active/);
  assert.match(boundary, /Overlay Network/);
  assert.match(boundary, /Agent Swarm Layer/);
  assert.match(boundary, /Multi-signal routing/);
  assert.match(status, /状态：v14 active at v14\.11/);
  assert.match(status, /当前代码基线：`v14\.11-apple-private-workspace-proof`/);
  assert.match(draft, /local-first prototype at `v14\.10-protocol`/);
  for (const doc of [readme, roadmap, boundary, status, draft]) {
    assert.doesNotMatch(doc, /P2P DHT is implemented/i);
    assert.doesNotMatch(doc, /token economy is implemented/i);
    assert.doesNotMatch(doc, /production global Agent Net is implemented/i);
  }
});

test("v14.2 public docs record multi-signal FED_QUERY routing evidence", async () => {
  const [readme, roadmap, boundary, status, draft] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v14-roadmap.md", "utf8"),
    readFile("docs/v14.2-boundary.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
  ]);

  assert.match(readme, /`docs\/v14\.2-boundary\.md` - v14\.2 multi-signal FED_QUERY routing boundary\./);
  assert.match(readme, /discovery_evidence\.routing/);
  assert.match(roadmap, /## v14\.2: Multi-signal FED_QUERY routing\n\n状态：complete/);
  assert.match(boundary, /协议标签：`v14\.2-protocol`/);
  for (const doc of [roadmap, boundary, status, draft]) {
    assert.match(doc, /routing/);
    assert.match(doc, /cost_score/);
    assert.match(doc, /availability_score/);
    assert.match(doc, /latency_score/);
  }
});

test("v14.3 public docs record cross-zone trust chains without PKI overclaims", async () => {
  const [readme, roadmap, boundary, status, draft] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v14-roadmap.md", "utf8"),
    readFile("docs/v14.3-boundary.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
  ]);

  assert.match(readme, /v14 active at `v14\.10-protocol`/);
  assert.match(readme, /`docs\/v14\.3-boundary\.md` - v14\.3 cross-zone trust chain boundary\./);
  assert.match(roadmap, /## v14\.3: Cross-zone trust chains\n\n状态：complete/);
  assert.match(roadmap, /zone_trust_chain/);
  assert.match(roadmap, /zoneTrustDelegation/);
  assert.match(boundary, /协议标签：`v14\.3-protocol`/);
  assert.match(boundary, /zone_trust_chain/);
  assert.match(boundary, /zoneTrustDelegation/);
  assert.match(status, /状态：v14 active at v14\.11/);
  assert.match(status, /当前代码基线：`v14\.11-apple-private-workspace-proof`/);
  assert.match(draft, /local-first prototype at `v14\.10-protocol`/);
  assert.match(draft, /zone_trust_chain/);
  assert.match(draft, /zoneTrustDelegation/);
  for (const doc of [readme, roadmap, boundary, status, draft]) {
    assert.doesNotMatch(doc, /global PKI is implemented/i);
    assert.doesNotMatch(doc, /CA hierarchy/i);
  }
});

test("v14.4 public docs record task failure migration evidence", async () => {
  const [readme, roadmap, boundary, status, draft] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v14-roadmap.md", "utf8"),
    readFile("docs/v14.4-boundary.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
  ]);

  assert.match(readme, /v14 active at `v14\.10-protocol`/);
  assert.match(readme, /`docs\/v14\.4-boundary\.md` - v14\.4 task failure migration boundary\./);
  assert.match(roadmap, /## v14\.4: Task failure migration\n\n状态：complete/);
  assert.match(boundary, /协议标签：`v14\.4-protocol`/);
  for (const doc of [roadmap, boundary, status, draft]) {
    assert.match(doc, /migration_log/);
    assert.match(doc, /migrated_to_worker_aid/);
    assert.match(doc, /FED_SWARM_CLOSE/);
  }
  assert.match(draft, /migration_log/);
  assert.match(draft, /migrated_to_worker_aid/);
  assert.doesNotMatch(boundary, /invisible retry loops are implemented/i);
  assert.doesNotMatch(boundary, /distributed worker pool is implemented/i);
});

test("v14.5 public docs record signed Swarm intent decomposition plans", async () => {
  const [roadmap, boundary, status, draft] = await Promise.all([
    readFile("docs/v14-roadmap.md", "utf8"),
    readFile("docs/v14.5-boundary.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
  ]);

  assert.match(roadmap, /## v14\.5: Intent Decomposition/);
  assert.match(boundary, /协议标签：`v14\.5-protocol`/);
  for (const doc of [roadmap, boundary, status, draft]) {
    assert.match(doc, /swarmPlan/);
    assert.match(doc, /FED_SWARM_PLAN/);
    assert.match(doc, /intent/);
    assert.match(doc, /plan_digest/);
  }
  assert.match(status, /v14\.5 Intent Decomposition is complete/);
  assert.match(draft, /FED_SWARM_PLAN/);
  assert.doesNotMatch(boundary, /LLM orchestration is implemented/i);
  assert.doesNotMatch(boundary, /candidate selection is automated/i);
});

test("v14.6 public docs record signed Knowledge Gateway proto", async () => {
  const [roadmap, boundary, status, draft] = await Promise.all([
    readFile("docs/v14-roadmap.md", "utf8"),
    readFile("docs/v14.6-boundary.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
  ]);

  assert.match(roadmap, /## v14\.6: Knowledge Gateway Proto/);
  assert.match(boundary, /协议标签：`v14\.6-protocol`/);
  for (const doc of [roadmap, boundary, status, draft]) {
    assert.match(doc, /Knowledge Gateway/);
    assert.match(doc, /FED_KNOWLEDGE_QUERY/);
    assert.match(doc, /verifyKnowledgeResponse/);
  }
  assert.match(status, /v14\.6 Knowledge Gateway Proto is complete/);
  assert.match(draft, /FED_KNOWLEDGE_RESPONSE/);
  assert.doesNotMatch(boundary, /web crawler is implemented/i);
  assert.doesNotMatch(boundary, /semantic cache is implemented/i);
  assert.doesNotMatch(boundary, /vector store is implemented/i);
  assert.doesNotMatch(boundary, /RAG pipeline is implemented/i);
});

test("v14.7 public docs record policy and risk routing signals", async () => {
  const [readme, roadmap, boundary, status, draft, reputation] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v14-roadmap.md", "utf8"),
    readFile("docs/v14.7-boundary.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/manual/reputation.md", "utf8"),
  ]);

  assert.match(readme, /v14 active at `v14\.10-protocol`/);
  assert.match(roadmap, /状态：active at v14\.10/);
  assert.match(roadmap, /## v14\.7: Policy and risk routing signals/);
  assert.match(boundary, /协议标签：`v14\.7-protocol`/);
  for (const doc of [readme, roadmap, boundary, status, draft, reputation]) {
    assert.match(doc, /policy_match/);
    assert.match(doc, /risk_match/);
  }
  assert.match(status, /状态：v14 active at v14\.11/);
  assert.match(status, /当前代码基线：`v14\.11-apple-private-workspace-proof`/);
  assert.match(draft, /local-first prototype at `v14\.10-protocol`/);
  assert.match(reputation, /Missing cost, latency, availability, policy, or risk evidence stays neutral/);
  assert.doesNotMatch(boundary, /new trust oracle is implemented/i);
  assert.doesNotMatch(boundary, /opaque ML routing is implemented/i);
});

test("v14.8 public docs record deterministic Swarm conflict resolution without merge or settlement overclaims", async () => {
  const [readme, roadmap, boundary, status, draft, v149Boundary, federation] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v14-roadmap.md", "utf8"),
    readFile("docs/v14.8-boundary.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/v14.9-boundary.md", "utf8"),
    readFile("docs/manual/federation.md", "utf8"),
  ]);
  const crossNetnsDocs = [readme, roadmap, v149Boundary, status, draft, federation];

  assert.match(readme, /v14 active at `v14\.10-protocol`/);
  assert.match(readme, /`docs\/v14\.8-boundary\.md` - v14\.8 Swarm conflict resolution boundary\./);
  assert.match(roadmap, /状态：active at v14\.10/);
  assert.match(roadmap, /## v14\.8: Swarm Conflict Resolution/);
  assert.match(boundary, /协议标签：`v14\.8-protocol`/);
  for (const doc of [roadmap, boundary, status, draft]) {
    assert.match(doc, /conflict_resolutions/);
    assert.match(doc, /higher agent_score reputation/);
    assert.match(doc, /alias_tiebreak/);
  }
  assert.match(status, /状态：v14 active at v14\.11/);
  assert.match(status, /当前代码基线：`v14\.11-apple-private-workspace-proof`/);
  assert.match(draft, /local-first prototype at `v14\.10-protocol`/);
  for (const doc of [roadmap, boundary, status, draft]) {
    assert.match(doc, /No voting\/quorum|not voting\/quorum/i);
    assert.match(doc, /No automatic merge of conflicting content|not automatic merge of conflicting content/i);
    assert.match(doc, /No payment\/settlement|not payment\/settlement/i);
  }
  assert.match(readme, /`docs\/v14\.9-boundary\.md` - v14\.9 cross-netns reachability boundary\./);
  assert.match(roadmap, /## v14\.9: Cross-Netns Reachability Evidence/);
  assert.match(v149Boundary, /状态：complete/);
  assert.match(v149Boundary, /协议标签：`v14\.9-protocol`/);
  for (const doc of crossNetnsDocs) {
    assert.match(doc, /cross-netns/);
  }
  for (const doc of [v149Boundary, status, draft]) {
    assert.match(doc, /literal private|private inter-namespace IP|private IP/);
    assert.match(doc, /not public reachability|not public or hosted external-host reachability|not public/i);
    assert.match(doc, /still pending/);
  }
  assert.match(v149Boundary, /192\.168\.64\.6/);
  assert.match(status, /The active protocol tag is `v14\.11-apple-private-workspace-proof`/);
  assert.match(status, /reachability scope classes \(`local-interface`, `container-observer`, `cross-netns`, `external-host`\)/);
  assert.match(draft, /cross-netns.*literal private inter-namespace IP/);
  assert.match(federation, /`cross-netns` for trusted separate-network-namespace evidence over a literal private IP/);
  assert.match(v149Boundary, /`cross-netns` is not public reachability/i);
  assert.match(v149Boundary, /does not complete external-host/i);
});

test("v14.10 public docs record Node ready-DAG parity without orchestration overclaims", async () => {
  const [readme, roadmap, boundary, status, draft, changelog] = await Promise.all([
    readFile("README.md", "utf8"),
    readFile("docs/v14-roadmap.md", "utf8"),
    readFile("docs/v14.10-boundary.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/asp-core-draft.md", "utf8"),
    readFile("docs/CHANGELOG.md", "utf8"),
  ]);

  assert.match(readme, /v14 active at `v14\.10-protocol`/);
  assert.match(readme, /v14\.10 Node ready-DAG parity/);
  assert.match(roadmap, /状态：active at v14\.10/);
  assert.match(roadmap, /## v14\.10: Node FED_SWARM_SCHEDULE ready-DAG parity/);
  assert.match(boundary, /状态：complete/);
  assert.match(boundary, /协议标签：`v14\.10-protocol`/);
  for (const doc of [roadmap, boundary, status, draft, changelog]) {
    assert.match(doc, /FED_SWARM_SCHEDULE/);
    assert.match(doc, /ready-dag/);
    assert.match(doc, /step_order/);
    assert.match(doc, /original input order/);
    assert.match(doc, /missing dependencies/i);
    assert.match(doc, /duplicate step IDs/);
    assert.match(doc, /self-dependencies/);
    assert.match(doc, /cycle|unresolvable graph/);
  }
  assert.match(status, /状态：v14 active at v14\.11/);
  assert.match(status, /当前代码基线：`v14\.11-apple-private-workspace-proof`/);
  assert.match(status, /The active protocol tag is `v14\.11-apple-private-workspace-proof`/);
  assert.match(draft, /local-first prototype at `v14\.10-protocol`/);
  assert.match(draft, /Node and Go gateways accept `FED_SWARM_SCHEDULE`/);
  for (const doc of [readme, roadmap, boundary, status, draft]) {
    assert.match(doc, /No parallel execution|not parallel execution/i);
    assert.match(doc, /No resource scheduling|not resource scheduling/i);
    assert.match(doc, /No economic ranking|not economic ranking/i);
    assert.match(doc, /No LLM scheduling|not LLM scheduling/i);
    assert.match(doc, /No new trust inputs|not new trust inputs/i);
  }
});

test("v14.11 docs state the Apple private-workspace proof and its limits", async () => {
  const [boundary, status, changelog] = await Promise.all([
    readFile("docs/v14.11-boundary.md", "utf8"),
    readFile("docs/implementation-status.md", "utf8"),
    readFile("docs/CHANGELOG.md", "utf8"),
  ]);

  for (const doc of [boundary, status, changelog]) {
    assert.match(doc, /private.*workspace/i);
    assert.match(doc, /read-write.*`\/work`|`\/work`.*read-write/i);
    assert.match(doc, /symlinks.*hardlinks.*devices/i);
    assert.match(doc, /no default route.*DNS|network\/DNS/i);
    assert.match(doc, /not full Docker isolation parity/i);
    assert.match(doc, /tmpfs quota/i);
    assert.match(doc, /PID parity.*nproc|nproc.*PID parity/i);
  }
  assert.match(boundary, /状态：complete/);
  assert.match(boundary, /workspace device, inode, owner UID, and mode/);
  assert.match(boundary, /当前协议基线：`v14\.11-apple-private-workspace-proof`/);
  assert.match(status, /状态：v14 active at v14\.11/);
  assert.match(status, /当前代码基线：`v14\.11-apple-private-workspace-proof`/);
  assert.match(status, /The active protocol tag is `v14\.11-apple-private-workspace-proof`/);
  assert.doesNotMatch(status, /状态：v14 active at v14\.10/);
  assert.doesNotMatch(status, /当前代码基线：`v14\.10-node-ready-dag-parity`/);
  assert.doesNotMatch(status, /The active protocol tag is `v14\.10-protocol`/);
  assert.match(changelog, /\[v14\.11\]/);
});
