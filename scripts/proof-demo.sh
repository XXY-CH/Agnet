#!/usr/bin/env bash
set -euo pipefail

mkdir -p state

demo_json="state/proof-demo.json"
node mvp-demo.mjs > "$demo_json"

manifest_path="$(node -e 'const fs=require("node:fs"); const demo=JSON.parse(fs.readFileSync(process.argv[1],"utf8")); process.stdout.write(`${demo.artifactPath}.manifest.json`);' "$demo_json")"
artifact_json="$(node asp-verify.mjs artifact "$manifest_path")"

receipt_frame="state/proof-demo-fed-receipt.json"
trusted_zones="state/proof-demo-trusted-zones.json"
node -e '
const fs = require("node:fs");
const demo = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
fs.writeFileSync(process.argv[2], `${JSON.stringify(demo.receiptFrame, null, 2)}\n`);
fs.writeFileSync(process.argv[3], `${JSON.stringify(demo.trustedZones, null, 2)}\n`);
' "$demo_json" "$receipt_frame" "$trusted_zones"
fed_artifact_json="$(node asp-verify.mjs fed-receipt-artifacts "$receipt_frame" "$trusted_zones")"

node -e '
const fs = require("node:fs");
const demo = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
const artifact = JSON.parse(process.argv[2]);
const fedArtifact = JSON.parse(process.argv[5]);
console.log(JSON.stringify({
  proof_demo: "ok",
  task_id: demo.receipt.task_id,
  receipt_signature: demo.receipt.signature,
  artifact_verify: artifact.artifact_verify,
  artifact_uri: artifact.uri,
  receipt_frame: process.argv[3],
  trusted_zones: process.argv[4],
  fed_receipt_artifacts_verify: fedArtifact.fed_receipt_artifacts_verify,
  receipt_digest: fedArtifact.receipt_digest
}));
' "$demo_json" "$artifact_json" "$receipt_frame" "$trusted_zones" "$fed_artifact_json"
