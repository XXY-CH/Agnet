import { readFile } from "node:fs/promises";
import { verifyFederatedReceipt, verifyLocalArtifact } from "./asp-core.mjs";

const [command, file, trustedFile] = process.argv.slice(2);

try {
  if (command === "artifact" && file) {
    const manifest = JSON.parse(await readFile(file, "utf8"));
    await verifyLocalArtifact(manifest);
    console.log(JSON.stringify({ artifact_verify: "ok", uri: manifest.uri }));
  } else if (command === "fed-receipt" && file && trustedFile) {
    const frame = JSON.parse(await readFile(file, "utf8"));
    const trusted = JSON.parse(await readFile(trustedFile, "utf8"));
    const zones = trusted.zones ?? trusted;
    const verified = verifyFederatedReceipt(frame, new Map(zones.map((zone) => [zone.zid, zone])));
    console.log(JSON.stringify({ fed_receipt_verify: "ok", task_id: verified.receipt.task_id }));
  } else if (command === "fed-receipt-artifacts" && file && trustedFile) {
    const frame = JSON.parse(await readFile(file, "utf8"));
    const trusted = JSON.parse(await readFile(trustedFile, "utf8"));
    const zones = trusted.zones ?? trusted;
    const verified = verifyFederatedReceipt(frame, new Map(zones.map((zone) => [zone.zid, zone])));
    const manifests = verified.receipt.artifact_manifests ?? [];
    if ((verified.receipt.artifact_refs?.length ?? 0) > 0 && manifests.length === 0) {
      throw new Error("receipt artifact manifests missing");
    }
    for (const manifest of manifests) await verifyLocalArtifact(manifest);
    console.log(JSON.stringify({ fed_receipt_artifacts_verify: "ok", task_id: verified.receipt.task_id, artifact_count: manifests.length }));
  } else {
    throw new Error("usage: node asp-verify.mjs artifact <manifest.json> | fed-receipt <frame.json> <trusted-zones.json> | fed-receipt-artifacts <frame.json> <trusted-zones.json>");
  }
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
