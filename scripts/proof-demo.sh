#!/usr/bin/env bash
set -euo pipefail

mkdir -p state

demo_json="state/proof-demo.json"
node mvp-demo.mjs > "$demo_json"

manifest_path="$(node -e 'const fs=require("node:fs"); const demo=JSON.parse(fs.readFileSync(process.argv[1],"utf8")); process.stdout.write(`${demo.artifactPath}.manifest.json`);' "$demo_json")"
artifact_json="$(node asp-verify.mjs artifact "$manifest_path")"

node -e '
const fs = require("node:fs");
const demo = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
const artifact = JSON.parse(process.argv[2]);
console.log(JSON.stringify({
  proof_demo: "ok",
  task_id: demo.receipt.task_id,
  receipt_signature: demo.receipt.signature,
  artifact_verify: artifact.artifact_verify,
  artifact_uri: artifact.uri
}));
' "$demo_json" "$artifact_json"
