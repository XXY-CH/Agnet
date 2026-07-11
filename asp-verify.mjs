#!/usr/bin/env node
import { readFile, stat } from "node:fs/promises";
import { createHash } from "node:crypto";
import { BlockList, isIP } from "node:net";
import { basename, dirname, join } from "node:path";
import { canonical, loadTrustedZones, publicKeyFromDescriptor, resolveAgent, verifyFederatedReceipt, verifyLocalArtifact, verifyObject, verifySwarmClose } from "./asp-core.mjs";
import { loadSwarmOutputTrustInputs, verifySwarmOutputVerification } from "./swarm-output-verification.mjs";

const args = process.argv.slice(2);
const [command, file, trustedFile, taskFile] = args;
const PACKAGE_PROOF_CAPABILITY = "package.proof.sign";
const RELEASE_TRUST_CAPABILITY = "release.trust.sign";
const SANDBOX_ATTEST_CAPABILITY = "sandbox.attest";
const FUTURE_SKEW_MS = 5 * 60 * 1000;
const MAX_AGE_MS = 60 * 60 * 1000;
const UTC_TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;
const NON_GLOBAL_IP_BLOCKS = new BlockList();
NON_GLOBAL_IP_BLOCKS.addSubnet("0.0.0.0", 8, "ipv4");
NON_GLOBAL_IP_BLOCKS.addSubnet("10.0.0.0", 8, "ipv4");
NON_GLOBAL_IP_BLOCKS.addSubnet("100.64.0.0", 10, "ipv4");
NON_GLOBAL_IP_BLOCKS.addSubnet("127.0.0.0", 8, "ipv4");
NON_GLOBAL_IP_BLOCKS.addSubnet("169.254.0.0", 16, "ipv4");
NON_GLOBAL_IP_BLOCKS.addSubnet("172.16.0.0", 12, "ipv4");
NON_GLOBAL_IP_BLOCKS.addSubnet("192.0.0.0", 24, "ipv4");
NON_GLOBAL_IP_BLOCKS.addSubnet("192.0.2.0", 24, "ipv4");
NON_GLOBAL_IP_BLOCKS.addSubnet("192.168.0.0", 16, "ipv4");
NON_GLOBAL_IP_BLOCKS.addSubnet("198.18.0.0", 15, "ipv4");
NON_GLOBAL_IP_BLOCKS.addSubnet("198.51.100.0", 24, "ipv4");
NON_GLOBAL_IP_BLOCKS.addSubnet("203.0.113.0", 24, "ipv4");
NON_GLOBAL_IP_BLOCKS.addSubnet("224.0.0.0", 4, "ipv4");
NON_GLOBAL_IP_BLOCKS.addSubnet("240.0.0.0", 4, "ipv4");
NON_GLOBAL_IP_BLOCKS.addAddress("::", "ipv6");
NON_GLOBAL_IP_BLOCKS.addAddress("::1", "ipv6");
NON_GLOBAL_IP_BLOCKS.addSubnet("::", 96, "ipv6");
NON_GLOBAL_IP_BLOCKS.addSubnet("fc00::", 7, "ipv6");
NON_GLOBAL_IP_BLOCKS.addSubnet("fe80::", 10, "ipv6");
NON_GLOBAL_IP_BLOCKS.addSubnet("ff00::", 8, "ipv6");
NON_GLOBAL_IP_BLOCKS.addSubnet("2001:db8::", 32, "ipv6");

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

function isGloballyRoutableIp(host) {
  const type = isIP(host);
  return type !== 0 && !NON_GLOBAL_IP_BLOCKS.check(host, type === 4 ? "ipv4" : "ipv6");
}

function packageFilesInvalid(files) {
  return !Array.isArray(files) || files.length === 0 || files.some(pathUnsafe) || new Set(files).size !== files.length;
}

function hasCapability(descriptor, capability) {
  return Array.isArray(descriptor.capabilities) && descriptor.capabilities.includes(capability);
}

function hasPackageProofCapability(descriptor) {
  return hasCapability(descriptor, PACKAGE_PROOF_CAPABILITY);
}

function hasReleaseTrustCapability(descriptor) {
  return hasCapability(descriptor, RELEASE_TRUST_CAPABILITY);
}

function hasSandboxAttestCapability(descriptor) {
  return hasCapability(descriptor, SANDBOX_ATTEST_CAPABILITY);
}

async function loadTrustedSigners(file, capability, label) {
  const trust = JSON.parse(await readFile(file, "utf8"));
  if (!trust || typeof trust !== "object") throw new Error(`trusted ${label} signer list missing`);
  const signers = Array.isArray(trust) ? trust : trust.signers;
  if (!Array.isArray(signers)) throw new Error(`trusted ${label} signer list missing`);
  return new Map(signers.map((descriptor) => {
    if (!descriptor || typeof descriptor !== "object" || Array.isArray(descriptor)) throw new Error(`trusted ${label} signer descriptor missing`);
    const signer = resolveAgent(new Map([[descriptor.alias, descriptor]]), descriptor.alias);
    if (!hasCapability(signer.descriptor, capability)) throw new Error(`trusted ${label} signer capability missing`);
    return [signer.descriptor.aid, signer.descriptor];
  }));
}

async function loadTrustedPackageSigners(file) {
  return loadTrustedSigners(file, PACKAGE_PROOF_CAPABILITY, "package");
}

async function loadTrustedReleaseSigners(file) {
  return loadTrustedSigners(file, RELEASE_TRUST_CAPABILITY, "release");
}

async function loadTrustedSandboxAttestors(file) {
  return loadTrustedSigners(file, SANDBOX_ATTEST_CAPABILITY, "sandbox attestation");
}

async function verifyPackageProof(file, trustedFile) {
  const proof = JSON.parse(await readFile(file, "utf8"));
  if (!proof || typeof proof !== "object" || Array.isArray(proof)) throw new Error("package proof manifest invalid");
  if (pathUnsafe(proof.tarball)) throw new Error("package proof tarball path invalid");
  const tarballPath = join(dirname(file), proof.tarball);
  const { proof_digest: proofDigest, signature, ...proofBody } = proof;
  requireEqual("package_proof", proof.package_proof, "ok");
  requireEqual("proof_digest", proofDigest, createHash("sha256").update(canonical(proofBody)).digest("hex"));
  if (!proof.signer || typeof proof.signer !== "object" || Array.isArray(proof.signer)) throw new Error("package proof signer missing");
  if (typeof signature !== "string" || signature === "") throw new Error("package proof signature missing");
  const signer = resolveAgent(new Map([[proof.signer.alias, proof.signer]]), proof.signer.alias);
  if (!hasPackageProofCapability(signer.descriptor)) throw new Error("package proof signer capability missing");
  if (!verifyObject(signer.publicKey, proofBody, signature)) throw new Error("package proof signature invalid");
  const trustedSigners = trustedFile ? await loadTrustedPackageSigners(trustedFile) : null;
  if (trustedSigners && !trustedSigners.has(signer.descriptor.aid)) throw new Error("package proof signer untrusted");
  requireEqual("manifest", proof.manifest, basename(file));
  requireEqual("filename", proof.filename, proof.tarball.split("/").at(-1));
  if (typeof proof.name !== "string" || proof.name === "" || typeof proof.version !== "string" || proof.version === "" || typeof proof.filename !== "string" || proof.filename === "") throw new Error("package proof identity invalid");
  requireEqual("package identity", proof.filename, `${proof.name}-${proof.version}.tgz`);
  if (packageFilesInvalid(proof.files)) throw new Error("package proof files invalid");
  if (typeof proof.shasum !== "string" || proof.shasum === "" || typeof proof.integrity !== "string" || proof.integrity === "" || typeof proof.sha256 !== "string" || proof.sha256 === "" || !Number.isSafeInteger(proof.size) || proof.size < 0) throw new Error("package proof byte metadata invalid");
  const tarballBytes = await readFile(tarballPath);
  requireEqual("shasum", proof.shasum, createHash("sha1").update(tarballBytes).digest("hex"));
  requireEqual("integrity", proof.integrity, `sha512-${createHash("sha512").update(tarballBytes).digest("base64")}`);
  requireEqual("sha256", proof.sha256, createHash("sha256").update(tarballBytes).digest("hex"));
  requireEqual("size", (await stat(tarballPath)).size, proof.size);
  return { proof, signer, trustedSigners };
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
  if (body.vantage !== "container" && body.vantage !== "cross-netns" && body.vantage !== "external-host") throw new Error("external reachability vantage invalid");
  if (body.observed_host !== transportProof.listen_host) throw new Error("external reachability observed_host mismatch");
  if (body.observed_port !== transportProof.port) throw new Error("external reachability observed_port mismatch");
  const observedAt = typeof body.observed_at === "string" && UTC_TIMESTAMP_PATTERN.test(body.observed_at) ? Date.parse(body.observed_at) : NaN;
  const now = Date.now();
  if (Number.isNaN(observedAt) || observedAt - now > FUTURE_SKEW_MS) throw new Error("external reachability observed_at invalid");
  if (now - observedAt > MAX_AGE_MS) throw new Error("external reachability stale");
  if (body.vantage === "external-host" && !isGloballyRoutableIp(transportProof.listen_host)) throw new Error("external reachability listen host not globally routable");
  if (body.vantage === "cross-netns") {
    const host = transportProof.listen_host;
    if (isIP(host) === 0 || isLocalOnlyListenHost(host) || isGloballyRoutableIp(host)) throw new Error("external reachability cross-netns listen host not a private inter-namespace IP");
  }
  const scope = body.vantage === "container" ? "container-observer" : body.vantage === "cross-netns" ? "cross-netns" : "external-host";
  return { reachability_scope: scope, reachability_observer_zid: body.observer_zid };
}

function verifySandboxProof(receiptVerified, requiredClass) {
  const proof = receiptVerified.receipt.sandbox_proof;
  if (!proof || typeof proof !== "object" || Array.isArray(proof)) throw new Error("sandbox proof missing");
  if (typeof proof.sandbox_signature !== "string" || proof.sandbox_signature === "") throw new Error("sandbox proof signature missing");
  requireEqual("sandbox proof_type", proof.proof_type, "local.sandbox.v1");
  requireEqual("sandbox task_id", proof.task_id, receiptVerified.receipt.task_id);
  requireEqual("sandbox authority", proof.authority, receiptVerified.zone.zid);
  requireEqual("sandbox worker", proof.worker, receiptVerified.worker.aid);
  requireEqual("sandbox policy_digest", proof.policy_digest, receiptVerified.receipt.policy_digest);
  requireEqual("sandbox claim", proof.sandbox_claim, receiptVerified.receipt.sandbox_claim);
  requireEqual("sandbox evidence", proof.sandbox, receiptVerified.receipt.sandbox);
  const { sandbox_signature: signature, ...proofBody } = proof;
  if (!verifyObject(publicKeyFromDescriptor(receiptVerified.zone), proofBody, signature)) throw new Error("sandbox proof signature invalid");
  const sandbox = receiptVerified.receipt.sandbox;
  if (!sandbox || typeof sandbox !== "object" || Array.isArray(sandbox)) throw new Error("sandbox evidence missing");
  if (typeof sandbox.mode !== "string" || sandbox.mode === "") throw new Error("sandbox evidence mode missing");
  if (typeof sandbox.isolation_level !== "string" || sandbox.isolation_level === "") throw new Error("sandbox evidence isolation_level missing");
  if (typeof sandbox.network !== "string" || sandbox.network === "") throw new Error("sandbox evidence network missing");
  if (typeof sandbox.tool_command_digest !== "string" || !/^[0-9a-f]{64}$/.test(sandbox.tool_command_digest)) throw new Error("sandbox evidence command digest missing");
  if (typeof sandbox.tool_binary_digest !== "string" || !/^[0-9a-f]{64}$/.test(sandbox.tool_binary_digest)) throw new Error("sandbox evidence binary digest missing");
  if (typeof sandbox.tool_transcript_digest !== "string" || !/^[0-9a-f]{64}$/.test(sandbox.tool_transcript_digest)) throw new Error("sandbox evidence transcript digest missing");
  const sandboxClass = sandbox.isolation_level === "local-process" ? "local-process" : "unknown";
  if (requiredClass && requiredClass !== sandboxClass) throw new Error(`sandbox class unavailable: ${requiredClass}`);
  return { sandboxClass, sandbox };
}

async function verifySandboxAttestation(receiptVerified, sandbox, evidence, trustedFile) {
  if (!evidence || typeof evidence !== "object" || Array.isArray(evidence)) throw new Error("sandbox attestation invalid");
  const { signature, attestation_digest: attestationDigest, ...body } = evidence;
  if (body.attestation !== "ok") throw new Error("sandbox attestation marker invalid");
  if (body.format !== "asp-sandbox-attestation/v1") throw new Error("sandbox attestation format invalid");
  if (attestationDigest !== createHash("sha256").update(canonical(body)).digest("hex")) throw new Error("sandbox attestation digest mismatch");
  if (body.receipt_digest !== receiptDigest(receiptVerified.signedReceipt)) throw new Error("sandbox attestation receipt_digest mismatch");
  if (body.task_id !== receiptVerified.receipt.task_id) throw new Error("sandbox attestation task_id mismatch");
  if (body.sandbox_digest !== createHash("sha256").update(canonical(sandbox)).digest("hex")) throw new Error("sandbox attestation sandbox_digest mismatch");
  if (body.sandbox_claim !== receiptVerified.receipt.sandbox_claim) throw new Error("sandbox attestation sandbox_claim mismatch");
  if (body.policy_digest !== receiptVerified.receipt.policy_digest) throw new Error("sandbox attestation policy_digest mismatch");
  if (typeof body.sandbox_class !== "string" || body.sandbox_class === "") throw new Error("sandbox attestation class missing");
  if (typeof body.runtime_identity !== "string" || body.runtime_identity === "") throw new Error("sandbox attestation runtime identity missing");
  const observedAt = typeof body.observed_at === "string" && UTC_TIMESTAMP_PATTERN.test(body.observed_at) ? Date.parse(body.observed_at) : NaN;
  const now = Date.now();
  if (Number.isNaN(observedAt) || observedAt - now > FUTURE_SKEW_MS) throw new Error("sandbox attestation observed_at invalid");
  if (now - observedAt > MAX_AGE_MS) throw new Error("sandbox attestation stale");
  if (!body.attestor || typeof body.attestor !== "object" || Array.isArray(body.attestor)) throw new Error("sandbox attestation signer missing");
  const signer = resolveAgent(new Map([[body.attestor.alias, body.attestor]]), body.attestor.alias);
  if (!hasSandboxAttestCapability(signer.descriptor)) throw new Error("sandbox attestation signer capability missing");
  if (typeof signature !== "string" || signature === "") throw new Error("sandbox attestation signature missing");
  if (!verifyObject(signer.publicKey, body, signature)) throw new Error("sandbox attestation signature invalid");
  const trustedAttestors = await loadTrustedSandboxAttestors(trustedFile);
  if (!trustedAttestors.has(signer.descriptor.aid)) throw new Error("sandbox attestation signer untrusted");
  return { body, attestationDigest, signer };
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
  } else if (command === "swarm-output" && file && args.length === 2) {
    const baseDir = dirname(file);
    const bundle = JSON.parse(await readFile(file, "utf8"));
    const exact = (value, fields, label) => {
      if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} invalid`);
      const actual = Object.keys(value).sort();
      const expected = [...fields].sort();
      if (actual.length !== expected.length || actual.some((field, index) => field !== expected[index])) throw new Error(`${label} fields invalid`);
    };
    exact(bundle, ["artifacts", "close", "executable_steps", "execution_binding", "format", "plan", "proof", "receipts", "resolved_workers", "trust_inputs", "trusted_zones"], "swarm output bundle");
    if (bundle.format !== "asp-swarm-output-verification-cli/v1") throw new Error("swarm output bundle format invalid");
    exact(bundle.trust_inputs, ["allowlist", "revocations", "trustedZones"], "swarm output trust inputs");
    if (!Array.isArray(bundle.artifacts)) throw new Error("swarm output artifacts invalid");
    const readBundleJSON = async (name, target) => JSON.parse(await readFile(bundlePath(baseDir, name, target), "utf8"));
    const proof = await readBundleJSON("proof", bundle.proof);
    const planFrame = await readBundleJSON("plan", bundle.plan);
    const executionBinding = await readBundleJSON("execution_binding", bundle.execution_binding);
    const executableSteps = await readBundleJSON("executable_steps", bundle.executable_steps);
    const resolvedWorkers = await readBundleJSON("resolved_workers", bundle.resolved_workers);
    const closeFrame = await readBundleJSON("close", bundle.close);
    const receiptFrames = await readBundleJSON("receipts", bundle.receipts);
    const trust = await loadSwarmOutputTrustInputs({
      allowlist: bundlePath(baseDir, "allowlist", bundle.trust_inputs.allowlist),
      trustedZones: bundlePath(baseDir, "trustedZones", bundle.trust_inputs.trustedZones),
      revocations: bundlePath(baseDir, "revocations", bundle.trust_inputs.revocations),
    });
    const trustedZones = await loadTrustedZones(bundlePath(baseDir, "trusted_zones", bundle.trusted_zones));
    const artifactsByURI = new Map();
    const artifactPaths = new Set();
    for (const entry of bundle.artifacts) {
      exact(entry, ["path", "uri"], "swarm output artifact");
      if (typeof entry.uri !== "string" || entry.uri.length === 0) throw new Error("swarm output artifact uri invalid");
      if (typeof entry.path !== "string" || entry.path.length === 0) throw new Error("swarm output artifact path invalid");
      if (artifactsByURI.has(entry.uri)) throw new Error(`duplicate artifact uri: ${entry.uri}`);
      if (artifactPaths.has(entry.path)) throw new Error(`duplicate artifact path: ${entry.path}`);
      artifactsByURI.set(entry.uri, bundlePath(baseDir, "artifact", entry.path));
      artifactPaths.add(entry.path);
    }
    const now = process.env.ASP_VERIFY_NOW ? new Date(process.env.ASP_VERIFY_NOW) : new Date();
    const verified = await verifySwarmOutputVerification(proof, {
      planFrame,
      executionBinding,
      executableSteps,
      resolvedWorkers,
      closeFrame,
      receiptFrames,
      trustedZones,
      loadArtifactBytes: async ({ uri }) => {
        const artifactPath = artifactsByURI.get(uri);
        if (!artifactPath) throw new Error(`artifact path missing: ${uri}`);
        return readFile(artifactPath);
      },
    }, trust, { now });
    console.log(JSON.stringify({ swarm_output_verify: "ok", verification_id: verified.proof.proof.verification_id, verified_at: verified.proof.proof.verified_at, swarm_id: verified.proof.proof.swarm_id, plan_digest: verified.proof.proof.plan_digest, execution_graph_digest: verified.proof.proof.execution_graph_digest, close_digest: verified.closeDigest, signed_receipt_digest: verified.finalOutput.signed_receipt_digest, artifact_sha256: verified.finalOutput.artifact.sha256, manifest_hash: verified.finalOutput.artifact.manifest_hash, trust_inputs_digest: verified.trustInputsDigest, proof_digest: verified.proofDigest }));
  } else if (command === "sandbox-proof" && file && trustedFile && (args.length === 3 || args.length === 4)) {
    const frame = JSON.parse(await readFile(file, "utf8"));
    const verified = verifyFederatedReceipt(frame, await loadTrustedZones(trustedFile));
    const { sandboxClass, sandbox } = verifySandboxProof(verified, taskFile);
    console.log(JSON.stringify({ sandbox_proof_verify: "ok", task_id: verified.receipt.task_id, sandbox_claim: verified.receipt.sandbox_claim, sandbox_class: sandboxClass, remote_attestation: false, runtime_identity: sandbox.runtime ?? sandbox.kind ?? sandbox.mode, network: sandbox.network, receipt_digest: receiptDigest(verified.signedReceipt) }));
  } else if (command === "sandbox-attestation" && file && trustedFile && args[3] && args[4] && args.length === 5) {
    const frame = JSON.parse(await readFile(file, "utf8"));
    const verified = verifyFederatedReceipt(frame, await loadTrustedZones(trustedFile));
    const { sandbox } = verifySandboxProof(verified);
    const evidence = JSON.parse(await readFile(args[3], "utf8"));
    const { body, attestationDigest, signer } = await verifySandboxAttestation(verified, sandbox, evidence, args[4]);
    console.log(JSON.stringify({ sandbox_attestation_verify: "ok", task_id: verified.receipt.task_id, sandbox_class: body.sandbox_class, attestation_digest: attestationDigest, attestor_aid: signer.descriptor.aid, hardware_attestation: false, receipt_digest: receiptDigest(verified.signedReceipt) }));
  } else if (command === "package-proof" && file && (args.length === 2 || (args.length === 3 && trustedFile))) {
    const { proof, signer, trustedSigners } = await verifyPackageProof(file, trustedFile);
    console.log(JSON.stringify({ package_proof_verify: "ok", name: proof.name, version: proof.version, filename: proof.filename, tarball: proof.tarball, size: proof.size, shasum: proof.shasum, integrity: proof.integrity, sha256: proof.sha256, proof_digest: proof.proof_digest, signer_aid: signer.descriptor.aid, ...(trustedSigners ? { signer_trusted: true } : {}) }));
  } else if (command === "release-trust" && file && (args.length === 2 || (args.length === 3 && trustedFile))) {
    const baseDir = dirname(file);
    const proof = JSON.parse(await readFile(file, "utf8"));
    if (!proof || typeof proof !== "object" || Array.isArray(proof)) throw new Error("release trust manifest invalid");
    requireEqual("release_trust", proof.release_trust, "ok");
    requireEqual("format", proof.format, "asp-release-trust/v1");
    if (pathUnsafe(proof.package_proof)) throw new Error("release trust package_proof path invalid");
    const packageProofPath = join(baseDir, proof.package_proof);
    if (pathUnsafe(proof.tarball)) throw new Error("release trust tarball path invalid");
    join(baseDir, proof.tarball);
    const { proof: packageProof } = await verifyPackageProof(packageProofPath, null);
    if (proof.package_proof_digest !== packageProof.proof_digest) throw new Error("release trust evidence stale");
    requireEqual("name", proof.name, packageProof.name);
    requireEqual("version", proof.version, packageProof.version);
    requireEqual("filename", proof.filename, packageProof.filename);
    requireEqual("tarball", proof.tarball, packageProof.tarball);
    requireEqual("sha256", proof.sha256, packageProof.sha256);
    requireEqual("size", proof.size, packageProof.size);
    requireEqual("files", proof.files, packageProof.files);
    const releasedAt = typeof proof.released_at === "string" && UTC_TIMESTAMP_PATTERN.test(proof.released_at) ? Date.parse(proof.released_at) : NaN;
    if (Number.isNaN(releasedAt) || releasedAt - Date.now() > FUTURE_SKEW_MS) throw new Error("release trust released_at invalid");
    const { trust_digest: trustDigest, signature, ...trustBody } = proof;
    requireEqual("trust_digest", trustDigest, createHash("sha256").update(canonical(trustBody)).digest("hex"));
    if (!proof.signer || typeof proof.signer !== "object" || Array.isArray(proof.signer)) throw new Error("release trust signer missing");
    const signer = resolveAgent(new Map([[proof.signer.alias, proof.signer]]), proof.signer.alias);
    if (!hasReleaseTrustCapability(signer.descriptor)) throw new Error("release trust signer capability missing");
    if (typeof signature !== "string" || signature === "") throw new Error("release trust signature missing");
    if (!verifyObject(signer.publicKey, trustBody, signature)) throw new Error("release trust signature invalid");
    const trustedSigners = trustedFile ? await loadTrustedReleaseSigners(trustedFile) : null;
    if (trustedSigners && !trustedSigners.has(signer.descriptor.aid)) throw new Error("release trust signer untrusted");
    console.log(JSON.stringify({ release_trust_verify: "ok", name: proof.name, version: proof.version, filename: proof.filename, tarball: proof.tarball, size: proof.size, sha256: proof.sha256, package_proof: proof.package_proof, package_proof_digest: proof.package_proof_digest, trust_digest: proof.trust_digest, released_at: proof.released_at, signer_aid: signer.descriptor.aid, ...(trustedSigners ? { signer_trusted: true } : {}) }));
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
    const crossNetnsEvidence = bundle.external_reachability?.vantage === "cross-netns";
    if (!transportProof || typeof transportProof !== "object" || Array.isArray(transportProof) || transportProof.transport !== "fed+tcp" || typeof transportProof.listen_host !== "string" || transportProof.listen_host === "" || (!crossNetnsEvidence && isLocalOnlyListenHost(transportProof.listen_host)) || typeof transportProof.port !== "string" || !/^[1-9][0-9]{0,4}$/.test(transportProof.port)) {
      throw new Error("bundle transport_proof invalid");
    }
    if (transportProof.public_transport !== true) {
      throw new Error("bundle public_transport proof missing");
    }
    const receiptDigestValue = receiptDigest(receiptVerified.signedReceipt);
    const reachability = await verifyExternalReachability(bundle, transportProof, receiptDigestValue, trustedFile);
    requireEqual("swarm_close_digest", bundle.swarm_close_digest, closeVerified.closeDigest);
    const output = { proof_bundle_verify: "ok", receipt_frame: bundle.receipt_frame, trusted_zones: bundle.trusted_zones, receipt_digest: bundle.receipt_digest, artifact_count: manifests.length, artifact_uris: bundle.artifact_uris, artifact_sha256s: bundle.artifact_sha256s, artifact_manifest_hashes: bundle.artifact_manifest_hashes, transport_proof: bundle.transport_proof, reachability_scope: reachability ? reachability.reachability_scope : "local-interface", swarm_close_frame: bundle.swarm_close_frame, swarm_close_trusted_zones: bundle.swarm_close_trusted_zones, swarm_close_digest: bundle.swarm_close_digest };
    if (reachability) output.reachability_observer_zid = reachability.reachability_observer_zid;
    console.log(JSON.stringify(output));
  } else {
    throw new Error("usage: node asp-verify.mjs artifact <manifest.json> | fed-receipt <frame.json> <trusted-zones.json> [task.json] | fed-receipt-artifacts <frame.json> <trusted-zones.json> [task.json] | swarm-close <frame.json> <trusted-zones.json> | swarm-output <bundle.json> | sandbox-proof <frame.json> <trusted-zones.json> [required-sandbox-class] | sandbox-attestation <frame.json> <trusted-zones.json> <attestation.json> <trusted-attestors.json> | package-proof <manifest.json> [trusted-signers.json] | release-trust <release-trust.json> [trusted-release-signers.json] | proof-bundle <bundle.json> [external-trusted-zones.json]");
  }
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
