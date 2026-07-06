#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { canonical, loadTrustedZones, verifyFederatedReceipt, verifyLocalArtifact, verifySwarmClose } from "./asp-core.mjs";

const [command, file, trustedFile] = process.argv.slice(2);

function receiptDigest(receipt) {
  const { signature, ...body } = receipt;
  return createHash("sha256").update(canonical(body)).digest("hex");
}

try {
  if (command === "artifact" && file) {
    const manifest = JSON.parse(await readFile(file, "utf8"));
    await verifyLocalArtifact(manifest);
    console.log(JSON.stringify({ artifact_verify: "ok", uri: manifest.uri }));
  } else if (command === "fed-receipt" && file && trustedFile) {
    const frame = JSON.parse(await readFile(file, "utf8"));
    const verified = verifyFederatedReceipt(frame, await loadTrustedZones(trustedFile));
    console.log(JSON.stringify({ fed_receipt_verify: "ok", task_id: verified.receipt.task_id, receipt_digest: receiptDigest(verified.signedReceipt) }));
  } else if (command === "fed-receipt-artifacts" && file && trustedFile) {
    const frame = JSON.parse(await readFile(file, "utf8"));
    const verified = verifyFederatedReceipt(frame, await loadTrustedZones(trustedFile));
    const manifests = verified.receipt.artifact_manifests ?? [];
    if ((verified.receipt.artifact_refs?.length ?? 0) > 0 && manifests.length === 0) {
      throw new Error("receipt artifact manifests missing");
    }
    for (const manifest of manifests) await verifyLocalArtifact(manifest);
    console.log(JSON.stringify({ fed_receipt_artifacts_verify: "ok", task_id: verified.receipt.task_id, artifact_count: manifests.length, artifact_uris: manifests.map(({ uri }) => uri), artifact_sha256s: manifests.map(({ sha256 }) => sha256), receipt_digest: receiptDigest(verified.signedReceipt) }));
  } else if (command === "swarm-close" && file && trustedFile) {
    const frame = JSON.parse(await readFile(file, "utf8"));
    const verified = verifySwarmClose(frame, await loadTrustedZones(trustedFile));
    console.log(JSON.stringify({ swarm_close_verify: "ok", swarm_id: verified.close.swarm_id, swarm_close_digest: verified.closeDigest }));
  } else {
    throw new Error("usage: node asp-verify.mjs artifact <manifest.json> | fed-receipt <frame.json> <trusted-zones.json> | fed-receipt-artifacts <frame.json> <trusted-zones.json> | swarm-close <frame.json> <trusted-zones.json>");
  }
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
