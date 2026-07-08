import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash, createPrivateKey } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import net from "node:net";
import { test } from "node:test";
import { promisify } from "node:util";
import { canonical, createZone, loadTrustedZones, signObject, verifyFederatedReceipt } from "./asp-core.mjs";

const execFileAsync = promisify(execFile);

function privateKeyFromSeed(seedHex) {
  return createPrivateKey({
    key: Buffer.concat([
      Buffer.from("302e020100300506032b657004220420", "hex"),
      Buffer.from(seedHex, "hex"),
    ]),
    format: "der",
    type: "pkcs8",
  });
}

function reachabilityEvidence(observer, transportProof, receiptDigest, overrides = {}) {
  const evidence = {
    proof: "external-reachability",
    observer_zid: observer.zid,
    vantage: "external-host",
    transport_proof: transportProof,
    receipt_digest: receiptDigest,
    observed_host: transportProof.listen_host,
    observed_port: transportProof.port,
    observed_at: new Date().toISOString(),
    reached: true,
  };
  for (const [key, value] of Object.entries(overrides)) {
    if (value === undefined) delete evidence[key];
    else evidence[key] = value;
  }
  return evidence;
}

function signedReachabilityEvidence(observer, evidence) {
  return { ...evidence, signature: signObject(observer.privateKey, evidence) };
}

async function writeReachabilityBundle(file, bundle, evidence) {
  await writeFile(file, `${JSON.stringify({ ...bundle, external_reachability: evidence }, null, 2)}\n`);
}

test("public node proof starts a public-listen gateway", async () => {
  const { stdout } = await execFileAsync("bash", ["scripts/public-node-proof.sh"]);
  const result = JSON.parse(stdout);

  assert.equal(result.public_node_proof, "ok");
  assert.match(result.listen_host, /^(?:\d{1,3}\.){3}\d{1,3}$/);
  assert.notEqual(result.listen_host, "0.0.0.0");
  assert.ok(!result.listen_host.startsWith("127."));
  assert.equal(result.public_transport, true);
  assert.equal(result.transport, "fed+tcp");
  assert.equal(result.resolve_alias, "agent://zone-b/summarizer");
  assert.equal(result.resolve_close, true);
  assert.equal(result.query_capability, "summarize.text");
  assert.equal(result.query_match_count, 1);
  assert.equal(result.query_status, "active");
  assert.equal(result.task_id, "public_node_probe_task");
  assert.equal(result.task_receipt, true);
  assert.equal(result.task_close, true);
  assert.equal(result.audit_task_id, "public_node_probe_task");
  assert.equal(result.audit_receipt, true);
  assert.equal(result.audit_close, true);
  assert.equal(result.receipt_frame, "state/public-node-proof-fed-receipt.json");
  assert.equal(result.trusted_zones, "state/public-node-proof-trusted-zones.json");
  assert.equal(result.bundle_manifest, "state/public-node-proof-bundle.json");
  assert.equal(result.proof_bundle_verify, "ok");
  assert.equal(result.reachability_scope, "local-interface");
  assert.equal(result.artifact_file, "artifacts/public_node_probe_task/go-summary.md");
  assert.equal(result.fed_receipt_artifacts_verify, "ok");
  assert.equal(result.artifact_count, 1);
  assert.deepEqual(result.artifact_uris, ["artifact://local/public_node_probe_task/go-summary.md"]);
  assert.equal(result.artifact_reject, true);
  assert.match(result.artifact_reject_error, /receipt artifact not found/);
  assert.equal(result.artifact_tamper_reject, true);
  assert.match(result.artifact_tamper_error, /artifact bytes digest mismatch/);
  assert.equal(result.swarm_id, "swarm://public-node-proof/two-step");
  assert.equal(result.swarm_step_count, 2);
  assert.deepEqual(result.swarm_step_ids, ["summary", "dependent"]);
  assert.equal(result.swarm_close_signature, true);
  assert.equal(result.swarm_close_receipts, true);
  assert.equal(result.swarm_close_verify, "ok");
  assert.match(result.swarm_close_digest, /^[a-f0-9]{64}$/);
  assert.equal(result.swarm_close_frame, "state/public-node-proof-swarm-close.json");
  assert.equal(result.swarm_close_trusted_zones, "state/public-node-proof-swarm-close-trusted-zones.json");

  const receiptFrame = JSON.parse(await readFile(result.receipt_frame, "utf8"));
  const bundle = JSON.parse(await readFile(result.bundle_manifest, "utf8"));
  const closeFrame = JSON.parse(await readFile(result.swarm_close_frame, "utf8"));
  const closeTrustedZones = JSON.parse(await readFile(result.swarm_close_trusted_zones, "utf8"));
  assert.equal(closeFrame.type, "FED_SWARM_CLOSE");
  assert.equal(closeFrame.swarm_id, result.swarm_id);
  assert.equal(closeFrame.close.swarm_id, result.swarm_id);
  assert.equal(closeTrustedZones.zones[0].zid, closeFrame.zone.zid);

  const audit = await readFile("state/public-node-proof-audit.log", "utf8");
  const closeRecord = audit
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line))
    .findLast((entry) => entry.record?.kind === "go_swarm_close")?.record;
  const { close_signature, ...closeBody } = closeRecord.close;
  assert.equal(result.swarm_close_digest, createHash("sha256").update(canonical(closeBody)).digest("hex"));
  const { close_signature: frameCloseSignature, ...frameCloseBody } = closeFrame.close;
  assert.equal(result.swarm_close_digest, createHash("sha256").update(canonical(frameCloseBody)).digest("hex"));

  const { signature, ...receiptBody } = receiptFrame.receipt;
  const artifactSha256 = receiptFrame.receipt.artifact_manifests[0].sha256;
  const artifactManifestHash = receiptFrame.receipt.artifact_manifests[0].manifest_hash;
  const receiptDigest = createHash("sha256").update(canonical(receiptBody)).digest("hex");
  assert.deepEqual(result.artifact_sha256s, [artifactSha256]);
  assert.deepEqual(result.artifact_manifest_hashes, [artifactManifestHash]);
  assert.equal(result.receipt_digest, receiptDigest);
  assert.deepEqual(receiptFrame.receipt.transport_proof, {
    transport: result.transport,
    listen_host: result.listen_host,
    port: result.port,
    public_transport: result.public_transport,
  });
  assert.deepEqual(bundle, {
    proof: "public-node-proof",
    receipt_frame: "public-node-proof-fed-receipt.json",
    trusted_zones: "public-node-proof-trusted-zones.json",
    receipt_digest: result.receipt_digest,
    artifact_uris: result.artifact_uris,
    artifact_sha256s: result.artifact_sha256s,
    artifact_manifest_hashes: result.artifact_manifest_hashes,
    transport_proof: receiptFrame.receipt.transport_proof,
    swarm_close_frame: "public-node-proof-swarm-close.json",
    swarm_close_trusted_zones: "public-node-proof-swarm-close-trusted-zones.json",
    swarm_close_digest: result.swarm_close_digest,
  });
  const verified = await execFileAsync(process.execPath, ["asp-verify.mjs", "fed-receipt", result.receipt_frame, result.trusted_zones]);
  assert.deepEqual(JSON.parse(verified.stdout), { fed_receipt_verify: "ok", task_id: "public_node_probe_task", receipt_digest: receiptDigest });
  const verifiedArtifacts = await execFileAsync(process.execPath, ["asp-verify.mjs", "fed-receipt-artifacts", result.receipt_frame, result.trusted_zones]);
  assert.deepEqual(JSON.parse(verifiedArtifacts.stdout), { fed_receipt_artifacts_verify: "ok", task_id: "public_node_probe_task", artifact_count: 1, artifact_uris: result.artifact_uris, artifact_sha256s: [artifactSha256], artifact_manifest_hashes: [artifactManifestHash], receipt_digest: receiptDigest });
  const verifiedSwarmClose = await execFileAsync(process.execPath, ["asp-verify.mjs", "swarm-close", result.swarm_close_frame, result.swarm_close_trusted_zones]);
  assert.deepEqual(JSON.parse(verifiedSwarmClose.stdout), { swarm_close_verify: "ok", swarm_id: result.swarm_id, swarm_close_digest: result.swarm_close_digest });
  const verifiedBundle = await execFileAsync(process.execPath, ["asp-verify.mjs", "proof-bundle", result.bundle_manifest]);
  const tamperedBundlePath = "state/public-node-proof-bundle-tampered.json";
  const externalBundlePath = "state/public-node-proof-bundle-external.json";
  const externalTrustedPath = "state/public-node-proof-external-trusted-zones.json";
  const fixture = JSON.parse(await readFile("test-vectors/asp-v1.5-capability-credential.json", "utf8"));
  assert.deepEqual(JSON.parse(verifiedBundle.stdout), {
    proof_bundle_verify: "ok",
    receipt_frame: bundle.receipt_frame,
    trusted_zones: bundle.trusted_zones,
    receipt_digest: receiptDigest,
    artifact_count: 1,
    artifact_uris: result.artifact_uris,
    artifact_sha256s: [artifactSha256],
    artifact_manifest_hashes: [artifactManifestHash],
    transport_proof: receiptFrame.receipt.transport_proof,
    reachability_scope: "local-interface",
    swarm_close_frame: bundle.swarm_close_frame,
    swarm_close_trusted_zones: bundle.swarm_close_trusted_zones,
    swarm_close_digest: result.swarm_close_digest,
  });
  const observer = createZone("zone://external-reachability-observer");
  const untrustedObserver = createZone("zone://untrusted-reachability-observer");
  const untrustedTrustedPath = "state/public-node-proof-untrusted-external-trusted-zones.json";
  const externalReachability = reachabilityEvidence(observer, receiptFrame.receipt.transport_proof, result.receipt_digest);
  await writeFile(externalTrustedPath, `${JSON.stringify({ zones: [observer.descriptor] }, null, 2)}\n`);
  await assert.rejects(
    execFileAsync(process.execPath, ["scripts/external-reachability-observer.mjs", result.bundle_manifest, externalBundlePath, externalTrustedPath, "mars"]),
    /usage: node scripts\/external-reachability-observer\.mjs/,
  );
  await assert.rejects(
    execFileAsync(process.execPath, ["scripts/external-reachability-observer.mjs", result.bundle_manifest, externalBundlePath, externalTrustedPath]),
    /usage: node scripts\/external-reachability-observer\.mjs/,
  );
  await writeFile(untrustedTrustedPath, `${JSON.stringify({ zones: [untrustedObserver.descriptor] }, null, 2)}\n`);
  await writeReachabilityBundle(externalBundlePath, bundle, signedReachabilityEvidence(observer, externalReachability));
  await assert.rejects(
    execFileAsync(process.execPath, ["asp-verify.mjs", "proof-bundle", externalBundlePath]),
    /external reachability trust required/,
  );
  await assert.rejects(
    execFileAsync(process.execPath, ["asp-verify.mjs", "proof-bundle", externalBundlePath, untrustedTrustedPath]),
    /external reachability observer untrusted/,
  );
  await assert.rejects(
    execFileAsync(process.execPath, ["asp-verify.mjs", "proof-bundle", externalBundlePath, externalTrustedPath]),
    /external reachability listen host not globally routable/,
  );
  await writeReachabilityBundle(externalBundlePath, bundle, { ...externalReachability, signature: "bad" });
  await assert.rejects(
    execFileAsync(process.execPath, ["asp-verify.mjs", "proof-bundle", externalBundlePath, externalTrustedPath]),
    /external reachability signature invalid/,
  );
  await writeReachabilityBundle(externalBundlePath, bundle, externalReachability);
  await assert.rejects(
    execFileAsync(process.execPath, ["asp-verify.mjs", "proof-bundle", externalBundlePath, externalTrustedPath]),
    /external reachability signature invalid/,
  );
  const workerPrivateKey = privateKeyFromSeed(fixture.worker_seed_hex);
  const syntheticTransportProof = { ...receiptFrame.receipt.transport_proof, listen_host: "93.184.216.34", port: String(receiptFrame.receipt.transport_proof.port), public_transport: true };
  const syntheticReceipt = {
    ...receiptBody,
    transport_proof: syntheticTransportProof,
  };
  const syntheticReceiptDigest = createHash("sha256").update(canonical(syntheticReceipt)).digest("hex");
  const syntheticReceiptFrame = {
    ...receiptFrame,
    receipt: {
      ...syntheticReceipt,
      signature: signObject(workerPrivateKey, syntheticReceipt),
    },
  };
  const syntheticVerifiedReceipt = verifyFederatedReceipt(syntheticReceiptFrame, await loadTrustedZones(result.trusted_zones));
  assert.equal(syntheticVerifiedReceipt.receipt.transport_proof.listen_host, "93.184.216.34");
  const syntheticReceiptFramePath = "state/public-node-proof-fed-receipt-external-host.json";
  const syntheticBundlePath = "state/public-node-proof-bundle-external-host.json";
  const syntheticBundle = {
    ...bundle,
    receipt_frame: "public-node-proof-fed-receipt-external-host.json",
    receipt_digest: syntheticReceiptDigest,
    transport_proof: syntheticTransportProof,
  };
  await writeFile(syntheticReceiptFramePath, `${JSON.stringify(syntheticReceiptFrame, null, 2)}\n`);
  await writeReachabilityBundle(syntheticBundlePath, syntheticBundle, signedReachabilityEvidence(observer, reachabilityEvidence(observer, syntheticTransportProof, syntheticReceiptDigest)));
  const verifiedExternalBundle = await execFileAsync(process.execPath, ["asp-verify.mjs", "proof-bundle", syntheticBundlePath, externalTrustedPath]);
  const verifiedExternal = JSON.parse(verifiedExternalBundle.stdout);
  assert.equal(verifiedExternal.reachability_scope, "external-host");
  assert.equal(verifiedExternal.reachability_observer_zid, observer.zid);
  assert.ok(!("external_observer_zid" in verifiedExternal));
  await writeReachabilityBundle(externalBundlePath, syntheticBundle, signedReachabilityEvidence(observer, reachabilityEvidence(observer, syntheticTransportProof, syntheticReceiptDigest, { observed_at: new Date().toUTCString() })));
  await assert.rejects(
    execFileAsync(process.execPath, ["asp-verify.mjs", "proof-bundle", externalBundlePath, externalTrustedPath]),
    /external reachability observed_at invalid/,
  );
  const ipv4CompatibleTransportProof = { ...syntheticTransportProof, listen_host: "::10.0.0.1" };
  const ipv4CompatibleReceipt = {
    ...receiptBody,
    transport_proof: ipv4CompatibleTransportProof,
  };
  const ipv4CompatibleReceiptDigest = createHash("sha256").update(canonical(ipv4CompatibleReceipt)).digest("hex");
  const ipv4CompatibleReceiptFrame = {
    ...receiptFrame,
    receipt: {
      ...ipv4CompatibleReceipt,
      signature: signObject(workerPrivateKey, ipv4CompatibleReceipt),
    },
  };
  assert.equal(verifyFederatedReceipt(ipv4CompatibleReceiptFrame, await loadTrustedZones(result.trusted_zones)).receipt.transport_proof.listen_host, "::10.0.0.1");
  const ipv4CompatibleReceiptFramePath = "state/public-node-proof-fed-receipt-ipv4-compatible.json";
  const ipv4CompatibleBundlePath = "state/public-node-proof-bundle-ipv4-compatible.json";
  const ipv4CompatibleBundle = {
    ...bundle,
    receipt_frame: "public-node-proof-fed-receipt-ipv4-compatible.json",
    receipt_digest: ipv4CompatibleReceiptDigest,
    transport_proof: ipv4CompatibleTransportProof,
  };
  await writeFile(ipv4CompatibleReceiptFramePath, `${JSON.stringify(ipv4CompatibleReceiptFrame, null, 2)}\n`);
  await writeReachabilityBundle(ipv4CompatibleBundlePath, ipv4CompatibleBundle, signedReachabilityEvidence(observer, reachabilityEvidence(observer, ipv4CompatibleTransportProof, ipv4CompatibleReceiptDigest)));
  await assert.rejects(
    execFileAsync(process.execPath, ["asp-verify.mjs", "proof-bundle", ipv4CompatibleBundlePath, externalTrustedPath]),
    /external reachability listen host not globally routable/,
  );
  await writeReachabilityBundle(externalBundlePath, syntheticBundle, signedReachabilityEvidence(observer, reachabilityEvidence(observer, syntheticTransportProof, syntheticReceiptDigest, { observed_at: new Date(Date.now() - 61 * 60 * 1000).toISOString() })));
  await assert.rejects(
    execFileAsync(process.execPath, ["asp-verify.mjs", "proof-bundle", externalBundlePath, externalTrustedPath]),
    /external reachability stale/,
  );
  await writeReachabilityBundle(externalBundlePath, syntheticBundle, signedReachabilityEvidence(observer, reachabilityEvidence(observer, syntheticTransportProof, syntheticReceiptDigest, { observed_at: new Date(Date.now() + 6 * 60 * 1000).toISOString() })));
  await assert.rejects(
    execFileAsync(process.execPath, ["asp-verify.mjs", "proof-bundle", externalBundlePath, externalTrustedPath]),
    /external reachability observed_at invalid/,
  );
  await writeReachabilityBundle(externalBundlePath, syntheticBundle, signedReachabilityEvidence(observer, reachabilityEvidence(observer, syntheticTransportProof, syntheticReceiptDigest, { vantage: undefined })));
  await assert.rejects(
    execFileAsync(process.execPath, ["asp-verify.mjs", "proof-bundle", externalBundlePath, externalTrustedPath]),
    /external reachability vantage invalid/,
  );
  await writeReachabilityBundle(externalBundlePath, syntheticBundle, signedReachabilityEvidence(observer, reachabilityEvidence(observer, syntheticTransportProof, syntheticReceiptDigest, { vantage: "mars" })));
  await assert.rejects(
    execFileAsync(process.execPath, ["asp-verify.mjs", "proof-bundle", externalBundlePath, externalTrustedPath]),
    /external reachability vantage invalid/,
  );
  await writeReachabilityBundle(externalBundlePath, syntheticBundle, signedReachabilityEvidence(observer, reachabilityEvidence(observer, syntheticTransportProof, syntheticReceiptDigest, { observed_host: "93.184.216.35" })));
  await assert.rejects(
    execFileAsync(process.execPath, ["asp-verify.mjs", "proof-bundle", externalBundlePath, externalTrustedPath]),
    /external reachability observed_host mismatch/,
  );
  await writeReachabilityBundle(externalBundlePath, syntheticBundle, signedReachabilityEvidence(observer, reachabilityEvidence(observer, syntheticTransportProof, syntheticReceiptDigest, { observed_port: "1" })));
  await assert.rejects(
    execFileAsync(process.execPath, ["asp-verify.mjs", "proof-bundle", externalBundlePath, externalTrustedPath]),
    /external reachability observed_port mismatch/,
  );
  await writeReachabilityBundle(externalBundlePath, syntheticBundle, signedReachabilityEvidence(observer, reachabilityEvidence(observer, syntheticTransportProof, "0".repeat(64))));
  await assert.rejects(
    execFileAsync(process.execPath, ["asp-verify.mjs", "proof-bundle", externalBundlePath, externalTrustedPath]),
    /external reachability receipt_digest mismatch/,
  );
  const observerServer = net.createServer((socket) => socket.end("ok\n"));
  await new Promise((resolve, reject) => {
    observerServer.once("error", reject);
    observerServer.listen(0, result.listen_host, resolve);
  });
  try {
    const observedReceipt = {
      ...receiptBody,
      transport_proof: { ...receiptFrame.receipt.transport_proof, port: String(observerServer.address().port) },
    };
    const observedReceiptFramePath = "state/public-node-proof-fed-receipt-observer-target.json";
    const observedBundleInputPath = "state/public-node-proof-bundle-observer-target.json";
    const observedBundlePath = "state/public-node-proof-bundle-observed.json";
    const observedTrustedPath = "state/public-node-proof-observer-trusted-zones.json";
    await writeFile(observedReceiptFramePath, `${JSON.stringify({
      ...receiptFrame,
      receipt: {
        ...observedReceipt,
        signature: signObject(workerPrivateKey, observedReceipt),
      },
    }, null, 2)}\n`);
    await writeFile(observedBundleInputPath, `${JSON.stringify({
      ...bundle,
      receipt_frame: "public-node-proof-fed-receipt-observer-target.json",
      receipt_digest: createHash("sha256").update(canonical(observedReceipt)).digest("hex"),
      transport_proof: observedReceipt.transport_proof,
    }, null, 2)}\n`);
    const observed = await execFileAsync(process.execPath, ["scripts/external-reachability-observer.mjs", observedBundleInputPath, observedBundlePath, observedTrustedPath, "container"]);
    assert.equal(JSON.parse(observed.stdout).external_reachability_observer, "ok");
    const observedBundle = JSON.parse(await readFile(observedBundlePath, "utf8"));
    assert.equal(observedBundle.external_reachability.vantage, "container");
    assert.equal(observedBundle.external_reachability.observed_host, observedReceipt.transport_proof.listen_host);
    assert.equal(observedBundle.external_reachability.observed_port, observedReceipt.transport_proof.port);
    assert.match(observedBundle.external_reachability.observed_at, /^\d{4}-\d{2}-\d{2}T/);
    const verifiedObserved = await execFileAsync(process.execPath, ["asp-verify.mjs", "proof-bundle", observedBundlePath, observedTrustedPath]);
    const verifiedObservedBody = JSON.parse(verifiedObserved.stdout);
    assert.equal(verifiedObservedBody.reachability_scope, "container-observer");
    assert.equal(verifiedObservedBody.reachability_observer_zid, observedBundle.external_reachability.observer_zid);
  } finally {
    await new Promise((resolve) => observerServer.close(resolve));
  }
  await writeFile(tamperedBundlePath, `${JSON.stringify({ ...bundle, reachability_scope: "external-host" }, null, 2)}\n`);
  await assert.rejects(
    execFileAsync(process.execPath, ["asp-verify.mjs", "proof-bundle", tamperedBundlePath]),
    /bundle reachability_scope is verifier-owned/,
  );
  await assert.rejects(
    execFileAsync(process.execPath, ["asp-verify.mjs", "proof-bundle", result.bundle_manifest, "extra.json"]),
    /external reachability missing/,
  );
  await assert.rejects(
    execFileAsync(process.execPath, ["asp-verify.mjs", "proof-bundle", result.bundle_manifest, ""]),
    /usage: node asp-verify\.mjs/,
  );
  await writeFile(tamperedBundlePath, "null\n");
  await assert.rejects(
    execFileAsync(process.execPath, ["asp-verify.mjs", "proof-bundle", tamperedBundlePath]),
    /bundle manifest invalid/,
  );
  await writeFile(tamperedBundlePath, "[]\n");
  await assert.rejects(
    execFileAsync(process.execPath, ["asp-verify.mjs", "proof-bundle", tamperedBundlePath]),
    /bundle manifest invalid/,
  );
  await writeFile(tamperedBundlePath, `${JSON.stringify({ ...bundle, receipt_digest: "0".repeat(64) }, null, 2)}\n`);
  await assert.rejects(
    execFileAsync(process.execPath, ["asp-verify.mjs", "proof-bundle", tamperedBundlePath]),
    /bundle receipt_digest mismatch/,
  );
  const publicTransportFalseReceipt = {
    ...receiptBody,
    transport_proof: { ...receiptFrame.receipt.transport_proof, public_transport: false },
  };
  const publicTransportFalseFramePath = "state/public-node-proof-fed-receipt-non-public.json";
  await writeFile(publicTransportFalseFramePath, `${JSON.stringify({
    ...receiptFrame,
    receipt: {
      ...publicTransportFalseReceipt,
      signature: signObject(privateKeyFromSeed(fixture.worker_seed_hex), publicTransportFalseReceipt),
    },
  }, null, 2)}\n`);
  await writeFile(tamperedBundlePath, `${JSON.stringify({
    ...bundle,
    receipt_frame: "public-node-proof-fed-receipt-non-public.json",
    receipt_digest: createHash("sha256").update(canonical(publicTransportFalseReceipt)).digest("hex"),
    transport_proof: publicTransportFalseReceipt.transport_proof,
  }, null, 2)}\n`);
  await assert.rejects(
    execFileAsync(process.execPath, ["asp-verify.mjs", "proof-bundle", tamperedBundlePath]),
    /bundle public_transport proof missing/,
  );
  const incompleteTransportReceipt = {
    ...receiptBody,
    transport_proof: { public_transport: true },
  };
  const incompleteTransportFramePath = "state/public-node-proof-fed-receipt-incomplete-transport.json";
  await writeFile(incompleteTransportFramePath, `${JSON.stringify({
    ...receiptFrame,
    receipt: {
      ...incompleteTransportReceipt,
      signature: signObject(privateKeyFromSeed(fixture.worker_seed_hex), incompleteTransportReceipt),
    },
  }, null, 2)}\n`);
  await writeFile(tamperedBundlePath, `${JSON.stringify({
    ...bundle,
    receipt_frame: "public-node-proof-fed-receipt-incomplete-transport.json",
    receipt_digest: createHash("sha256").update(canonical(incompleteTransportReceipt)).digest("hex"),
    transport_proof: incompleteTransportReceipt.transport_proof,
  }, null, 2)}\n`);
  await assert.rejects(
    execFileAsync(process.execPath, ["asp-verify.mjs", "proof-bundle", tamperedBundlePath]),
    /bundle transport_proof invalid/,
  );
  const localTransportReceipt = {
    ...receiptBody,
    transport_proof: { ...receiptFrame.receipt.transport_proof, transport: "asp+local" },
  };
  const localTransportFramePath = "state/public-node-proof-fed-receipt-local-transport.json";
  await writeFile(localTransportFramePath, `${JSON.stringify({
    ...receiptFrame,
    receipt: {
      ...localTransportReceipt,
      signature: signObject(privateKeyFromSeed(fixture.worker_seed_hex), localTransportReceipt),
    },
  }, null, 2)}\n`);
  await writeFile(tamperedBundlePath, `${JSON.stringify({
    ...bundle,
    receipt_frame: "public-node-proof-fed-receipt-local-transport.json",
    receipt_digest: createHash("sha256").update(canonical(localTransportReceipt)).digest("hex"),
    transport_proof: localTransportReceipt.transport_proof,
  }, null, 2)}\n`);
  await assert.rejects(
    execFileAsync(process.execPath, ["asp-verify.mjs", "proof-bundle", tamperedBundlePath]),
    /bundle transport_proof invalid/,
  );
  const loopbackTransportReceipt = {
    ...receiptBody,
    transport_proof: { ...receiptFrame.receipt.transport_proof, listen_host: "127.0.0.1" },
  };
  const loopbackTransportFramePath = "state/public-node-proof-fed-receipt-loopback-transport.json";
  await writeFile(loopbackTransportFramePath, `${JSON.stringify({
    ...receiptFrame,
    receipt: {
      ...loopbackTransportReceipt,
      signature: signObject(privateKeyFromSeed(fixture.worker_seed_hex), loopbackTransportReceipt),
    },
  }, null, 2)}\n`);
  await writeFile(tamperedBundlePath, `${JSON.stringify({
    ...bundle,
    receipt_frame: "public-node-proof-fed-receipt-loopback-transport.json",
    receipt_digest: createHash("sha256").update(canonical(loopbackTransportReceipt)).digest("hex"),
    transport_proof: loopbackTransportReceipt.transport_proof,
  }, null, 2)}\n`);
  await assert.rejects(
    execFileAsync(process.execPath, ["asp-verify.mjs", "proof-bundle", tamperedBundlePath]),
    /bundle transport_proof invalid/,
  );
  const unspecifiedTransportReceipt = {
    ...receiptBody,
    transport_proof: { ...receiptFrame.receipt.transport_proof, listen_host: "0.0.0.0" },
  };
  const unspecifiedTransportFramePath = "state/public-node-proof-fed-receipt-unspecified-transport.json";
  await writeFile(unspecifiedTransportFramePath, `${JSON.stringify({
    ...receiptFrame,
    receipt: {
      ...unspecifiedTransportReceipt,
      signature: signObject(privateKeyFromSeed(fixture.worker_seed_hex), unspecifiedTransportReceipt),
    },
  }, null, 2)}\n`);
  await writeFile(tamperedBundlePath, `${JSON.stringify({
    ...bundle,
    receipt_frame: "public-node-proof-fed-receipt-unspecified-transport.json",
    receipt_digest: createHash("sha256").update(canonical(unspecifiedTransportReceipt)).digest("hex"),
    transport_proof: unspecifiedTransportReceipt.transport_proof,
  }, null, 2)}\n`);
  await assert.rejects(
    execFileAsync(process.execPath, ["asp-verify.mjs", "proof-bundle", tamperedBundlePath]),
    /bundle transport_proof invalid/,
  );
  await writeFile(tamperedBundlePath, `${JSON.stringify({ ...bundle, proof: "other-proof" }, null, 2)}\n`);
  await assert.rejects(
    execFileAsync(process.execPath, ["asp-verify.mjs", "proof-bundle", tamperedBundlePath]),
    /bundle proof mismatch/,
  );
  await writeFile(tamperedBundlePath, `${JSON.stringify({ ...bundle, proof: "other-proof", receipt_frame: "../README.md" }, null, 2)}\n`);
  await assert.rejects(
    execFileAsync(process.execPath, ["asp-verify.mjs", "proof-bundle", tamperedBundlePath]),
    /bundle proof mismatch/,
  );
  await writeFile(tamperedBundlePath, `${JSON.stringify({ ...bundle, receipt_frame: "../README.md" }, null, 2)}\n`);
  await assert.rejects(
    execFileAsync(process.execPath, ["asp-verify.mjs", "proof-bundle", tamperedBundlePath]),
    /bundle receipt_frame path invalid/,
  );
  await writeFile(tamperedBundlePath, `${JSON.stringify({ ...bundle, receipt_frame: "missing-receipt.json", swarm_close_frame: "../README.md" }, null, 2)}\n`);
  await assert.rejects(
    execFileAsync(process.execPath, ["asp-verify.mjs", "proof-bundle", tamperedBundlePath]),
    /bundle swarm_close_frame path invalid/,
  );
  await writeFile(tamperedBundlePath, `${JSON.stringify({ ...bundle, receipt_frame: "/tmp/receipt.json" }, null, 2)}\n`);
  await assert.rejects(
    execFileAsync(process.execPath, ["asp-verify.mjs", "proof-bundle", tamperedBundlePath]),
    /bundle receipt_frame path invalid/,
  );
});
