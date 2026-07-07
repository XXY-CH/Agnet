#!/usr/bin/env node
import net from "node:net";
import { readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { createHash } from "node:crypto";
import { canonical, createZone, signObject } from "../asp-core.mjs";

const [bundlePath, observedBundlePath, trustedZonesPath] = process.argv.slice(2);

function usage() {
  throw new Error("usage: node scripts/external-reachability-observer.mjs <bundle.json> <observed-bundle.json> <observer-trusted-zones.json>");
}

function receiptDigest(receipt) {
  const { signature, ...body } = receipt;
  return createHash("sha256").update(canonical(body)).digest("hex");
}

function bundlePathFor(baseDir, target) {
  if (typeof target !== "string" || !target || target.startsWith("/") || target.includes("\\") || target.split("/").some((part) => !part || part === "." || part === "..")) {
    throw new Error("bundle receipt_frame path invalid");
  }
  return join(baseDir, target);
}

function connect(host, port) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host, port: Number(port), timeout: 5000 });
    socket.once("connect", () => {
      socket.end();
      resolve();
    });
    socket.once("timeout", () => {
      socket.destroy();
      reject(new Error("external reachability timeout"));
    });
    socket.once("error", reject);
  });
}

try {
  if (!bundlePath || !observedBundlePath || !trustedZonesPath || process.argv.length !== 5) usage();
  const baseDir = dirname(bundlePath);
  const bundle = JSON.parse(await readFile(bundlePath, "utf8"));
  const receiptFrame = JSON.parse(await readFile(bundlePathFor(baseDir, bundle.receipt_frame), "utf8"));
  const transportProof = receiptFrame.receipt?.transport_proof;
  if (!transportProof || typeof transportProof !== "object" || Array.isArray(transportProof)) throw new Error("transport_proof invalid");
  if (receiptDigest(receiptFrame.receipt) !== bundle.receipt_digest) throw new Error("bundle receipt_digest mismatch");
  if (JSON.stringify(transportProof) !== JSON.stringify(bundle.transport_proof)) throw new Error("bundle transport_proof mismatch");
  await connect(transportProof.listen_host, transportProof.port);
  const observer = createZone("zone://external-reachability-observer");
  const evidence = {
    proof: "external-reachability",
    observer_zid: observer.zid,
    transport_proof: transportProof,
    receipt_digest: bundle.receipt_digest,
    reached: true,
  };
  await writeFile(observedBundlePath, `${JSON.stringify({ ...bundle, external_reachability: { ...evidence, signature: signObject(observer.privateKey, evidence) } }, null, 2)}\n`);
  await writeFile(trustedZonesPath, `${JSON.stringify({ zones: [observer.descriptor] }, null, 2)}\n`);
  console.log(JSON.stringify({ external_reachability_observer: "ok", observer_zid: observer.zid, observed_bundle: observedBundlePath, observer_trusted_zones: trustedZonesPath }));
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
