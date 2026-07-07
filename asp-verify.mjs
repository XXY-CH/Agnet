#!/usr/bin/env node
import { readFile, stat } from "node:fs/promises";
import { createHash } from "node:crypto";
import { isIP } from "node:net";
import { basename, dirname, join } from "node:path";
import { canonical, loadTrustedZones, publicKeyFromDescriptor, resolveAgent, verifyFederatedReceipt, verifyLocalArtifact, verifyObject, verifySwarmClose } from "./asp-core.mjs";

const args = process.argv.slice(2);
const [command, file, trustedFile, taskFile] = args;

function receiptDigest(receipt) {
  const { signature, ...body } = receipt;
  return createHash("sha256").update(canonical(body)).digest("hex");
}

function requireEqual(name, actual, expected) {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`bundle ${name} mismatch`);
  }
}

function bundlePath(baseDir, name, target) {
  if (pathUnsafe(target)) {
    throw new Error(`bundle ${name} path invalid`);
  }
  return join(baseDir, target);
}

function pathUnsafe(target) {
  return typeof target !== "string" || !target || target.includes("\\") || target.split("/").some((part) => !part || part === "." || part === "..") || target.startsWith("/");
}

function isLocalOnlyListenHost(host) {
  return host.toLowerCase() === "localhost" || host === "::1" || host === "::" || host === "0.0.0.0" || (isIP(host) === 4 && host.startsWith("127."));
}

function packageFilesInvalid(files) {
  return !Array.isArray(files) || files.length === 0 || files.some(pathUnsafe) || new Set(files).size !== files.length;
}

async function loadTrustedPackageSigners(file) {
  const trust = JSON.parse(await readFile(file, "utf8"));
  const signers = Array.isArray(trust) ? trust : trust.signers;
  if (!Array.isArray(signers)) throw new Error("trusted package signer list missing");
  return new Map(signers.map((descriptor) => {
    if (!descriptor || typeof descriptor !== "object" || Array.isArray(descriptor)) throw new Error("trusted package signer descriptor missing");
    const signer = resolveAgent(new Map([[descriptor.alias, descriptor]]), descriptor.alias);
    return [signer.descriptor.aid, signer.descriptor];
  }));
}

async function verifyExternalReachability(bundle, transportProof, receiptDigest, trustedFile) {
  if (trustedFile && !bundle.external_reachability) throw new Error("external reachability missing");
  if (!bundle.external_reachability) return null;
  if (!trustedFile) throw new Error("external reachability trust required");
  const evidence = bundle.external_reachability;
  if (!evidence || typeof evidence !== "object" || Array.isArray(evidence)) throw new Error("external reachability invalid");
  const { signature, ...body } = evidence;
  requireEqual("external reachability proof", body.proof, "external-reachability");
  requireEqual("external reachability transport_proof", body.transport_proof, transportProof);
  requireEqual("external reachability receipt_digest", body.receipt_digest, receiptDigest);
  requireEqual("external reachability reached", body.reached, true);
  const trustedZones = await loadTrustedZones(trustedFile);
  const observer = trustedZones.get(body.observer_zid);
  if (!observer) throw new Error("external reachability observer untrusted");
  if (!verifyObject(publicKeyFromDescriptor(observer), body, signature)) throw new Error("external reachability signature invalid");
  return body.observer_zid;
}

try {
  if (command === "artifact" && file && args.length === 2) {
    const manifest = JSON.parse(await readFile(file, "utf8"));
    await verifyLocalArtifact(manifest);
    console.log(JSON.stringify({ artifact_verify: "ok", uri: manifest.uri }));
  } else if (command === "fed-receipt" && file && trustedFile && (args.length === 3 || args.length === 4)) {
    const frame = JSON.parse(await readFile(file, "utf8"));
    const task = taskFile ? JSON.parse(await readFile(taskFile, "utf8")) : undefined;
    const verified = verifyFederatedReceipt(frame, await loadTrustedZones(trustedFile), task);
    console.log(JSON.stringify({ fed_receipt_verify: "ok", task_id: verified.receipt.task_id, receipt_digest: receiptDigest(verified.signedReceipt) }));
  } else if (command === "fed-receipt-artifacts" && file && trustedFile && (args.length === 3 || args.length === 4)) {
    const frame = JSON.parse(await readFile(file, "utf8"));
    const task = taskFile ? JSON.parse(await readFile(taskFile, "utf8")) : undefined;
    const verified = verifyFederatedReceipt(frame, await loadTrustedZones(trustedFile), task);
    const manifests = verified.receipt.artifact_manifests ?? [];
    if ((verified.receipt.artifact_refs?.length ?? 0) > 0 && manifests.length === 0) {
      throw new Error("receipt artifact manifests missing");
    }
    for (const manifest of manifests) await verifyLocalArtifact(manifest);
    console.log(JSON.stringify({ fed_receipt_artifacts_verify: "ok", task_id: verified.receipt.task_id, artifact_count: manifests.length, artifact_uris: manifests.map(({ uri }) => uri), artifact_sha256s: manifests.map(({ sha256 }) => sha256), artifact_manifest_hashes: manifests.map(({ manifest_hash }) => manifest_hash), receipt_digest: receiptDigest(verified.signedReceipt) }));
  } else if (command === "swarm-close" && file && trustedFile && args.length === 3) {
    const frame = JSON.parse(await readFile(file, "utf8"));
    const verified = verifySwarmClose(frame, await loadTrustedZones(trustedFile));
    console.log(JSON.stringify({ swarm_close_verify: "ok", swarm_id: verified.close.swarm_id, swarm_close_digest: verified.closeDigest }));
  } else if (command === "package-proof" && file && (args.length === 2 || (args.length === 3 && trustedFile))) {
    const proof = JSON.parse(await readFile(file, "utf8"));
    if (!proof || typeof proof !== "object" || Array.isArray(proof)) throw new Error("package proof manifest invalid");
    if (pathUnsafe(proof.tarball)) throw new Error("package proof tarball path invalid");
    const tarballPath = join(dirname(file), proof.tarball);
    const { proof_digest: proofDigest, signature, ...proofBody } = proof;
    const tarballBytes = await readFile(tarballPath);
    requireEqual("package_proof", proof.package_proof, "ok");
    requireEqual("proof_digest", proofDigest, createHash("sha256").update(canonical(proofBody)).digest("hex"));
    if (!proof.signer || typeof proof.signer !== "object" || Array.isArray(proof.signer)) throw new Error("package proof signer missing");
    if (typeof signature !== "string" || signature === "") throw new Error("package proof signature missing");
    const signer = resolveAgent(new Map([[proof.signer.alias, proof.signer]]), proof.signer.alias);
    if (!verifyObject(signer.publicKey, proofBody, signature)) throw new Error("package proof signature invalid");
    const trustedSigners = trustedFile ? await loadTrustedPackageSigners(trustedFile) : null;
    if (trustedSigners && !trustedSigners.has(signer.descriptor.aid)) throw new Error("package proof signer untrusted");
    requireEqual("manifest", proof.manifest, basename(file));
    requireEqual("filename", proof.filename, proof.tarball.split("/").at(-1));
    requireEqual("package identity", proof.filename, `${proof.name}-${proof.version}.tgz`);
    if (packageFilesInvalid(proof.files)) throw new Error("package proof files invalid");
    requireEqual("shasum", proof.shasum, createHash("sha1").update(tarballBytes).digest("hex"));
    requireEqual("integrity", proof.integrity, `sha512-${createHash("sha512").update(tarballBytes).digest("base64")}`);
    requireEqual("sha256", proof.sha256, createHash("sha256").update(tarballBytes).digest("hex"));
    requireEqual("size", (await stat(tarballPath)).size, proof.size);
    console.log(JSON.stringify({ package_proof_verify: "ok", name: proof.name, version: proof.version, filename: proof.filename, tarball: proof.tarball, size: proof.size, shasum: proof.shasum, integrity: proof.integrity, sha256: proof.sha256, proof_digest: proof.proof_digest, signer_aid: signer.descriptor.aid, ...(trustedSigners ? { signer_trusted: true } : {}) }));
  } else if (command === "proof-bundle" && file && (args.length === 2 || (args.length === 3 && trustedFile))) {
    const baseDir = dirname(file);
    const bundle = JSON.parse(await readFile(file, "utf8"));
    if (!bundle || typeof bundle !== "object" || Array.isArray(bundle)) throw new Error("bundle manifest invalid");
    requireEqual("proof", bundle.proof, "public-node-proof");
    if (Object.prototype.hasOwnProperty.call(bundle, "reachability_scope")) throw new Error("bundle reachability_scope is verifier-owned");
    const receiptFramePath = bundlePath(baseDir, "receipt_frame", bundle.receipt_frame);
    const trustedZonesPath = bundlePath(baseDir, "trusted_zones", bundle.trusted_zones);
    const swarmCloseFramePath = bundlePath(baseDir, "swarm_close_frame", bundle.swarm_close_frame);
    const swarmCloseTrustedZonesPath = bundlePath(baseDir, "swarm_close_trusted_zones", bundle.swarm_close_trusted_zones);
    const receiptFrame = JSON.parse(await readFile(receiptFramePath, "utf8"));
    const receiptVerified = verifyFederatedReceipt(receiptFrame, await loadTrustedZones(trustedZonesPath));
    const manifests = receiptVerified.receipt.artifact_manifests ?? [];
    if ((receiptVerified.receipt.artifact_refs?.length ?? 0) > 0 && manifests.length === 0) {
      throw new Error("receipt artifact manifests missing");
    }
    for (const manifest of manifests) await verifyLocalArtifact(manifest);
    const closeFrame = JSON.parse(await readFile(swarmCloseFramePath, "utf8"));
    const closeVerified = verifySwarmClose(closeFrame, await loadTrustedZones(swarmCloseTrustedZonesPath));
    requireEqual("receipt_digest", bundle.receipt_digest, receiptDigest(receiptVerified.signedReceipt));
    requireEqual("artifact_uris", bundle.artifact_uris, manifests.map(({ uri }) => uri));
    requireEqual("artifact_sha256s", bundle.artifact_sha256s, manifests.map(({ sha256 }) => sha256));
    requireEqual("artifact_manifest_hashes", bundle.artifact_manifest_hashes, manifests.map(({ manifest_hash }) => manifest_hash));
    requireEqual("transport_proof", bundle.transport_proof, receiptVerified.receipt.transport_proof);
    const transportProof = receiptVerified.receipt.transport_proof;
    if (!transportProof || typeof transportProof !== "object" || Array.isArray(transportProof) || transportProof.transport !== "fed+tcp" || typeof transportProof.listen_host !== "string" || transportProof.listen_host === "" || isLocalOnlyListenHost(transportProof.listen_host) || typeof transportProof.port !== "string" || !/^[1-9][0-9]{0,4}$/.test(transportProof.port)) {
      throw new Error("bundle transport_proof invalid");
    }
    if (transportProof.public_transport !== true) {
      throw new Error("bundle public_transport proof missing");
    }
    const receiptDigestValue = receiptDigest(receiptVerified.signedReceipt);
    const externalObserverZid = await verifyExternalReachability(bundle, transportProof, receiptDigestValue, trustedFile);
    requireEqual("swarm_close_digest", bundle.swarm_close_digest, closeVerified.closeDigest);
    const output = { proof_bundle_verify: "ok", receipt_frame: bundle.receipt_frame, trusted_zones: bundle.trusted_zones, receipt_digest: bundle.receipt_digest, artifact_count: manifests.length, artifact_uris: bundle.artifact_uris, artifact_sha256s: bundle.artifact_sha256s, artifact_manifest_hashes: bundle.artifact_manifest_hashes, transport_proof: bundle.transport_proof, reachability_scope: externalObserverZid ? "external-host" : "local-interface", swarm_close_frame: bundle.swarm_close_frame, swarm_close_trusted_zones: bundle.swarm_close_trusted_zones, swarm_close_digest: bundle.swarm_close_digest };
    if (externalObserverZid) output.external_observer_zid = externalObserverZid;
    console.log(JSON.stringify(output));
  } else {
    throw new Error("usage: node asp-verify.mjs artifact <manifest.json> | fed-receipt <frame.json> <trusted-zones.json> [task.json] | fed-receipt-artifacts <frame.json> <trusted-zones.json> [task.json] | swarm-close <frame.json> <trusted-zones.json> | package-proof <manifest.json> [trusted-signers.json] | proof-bundle <bundle.json> [external-trusted-zones.json]");
  }
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
