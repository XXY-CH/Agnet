import { spawn } from "node:child_process";
import net from "node:net";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { createZone, signObject } from "../asp-core.mjs";

await mkdir("state", { recursive: true });
const originZone = createZone("zone://public-node-proof-origin");
await writeFile("state/public-node-proof-trusted.json", `${JSON.stringify({ zones: [originZone.descriptor] }, null, 2)}\n`);
const fixture = JSON.parse(await readFile("test-vectors/asp-v1.5-capability-credential.json", "utf8"));
await writeFile("state/public-node-proof-authority.seed", `${fixture.authority_seed_hex}\n`);
await writeFile("state/public-node-proof-worker.seed", `${fixture.worker_seed_hex}\n`);

const binary = process.argv[2] ?? "state/public-node-proof-go";
const child = spawn(binary, [
  "--listen-host",
  "0.0.0.0",
  "--port",
  "0",
  "--trusted",
  "state/public-node-proof-trusted.json",
  "--authority-key",
  "state/public-node-proof-authority.seed",
  "--worker-key",
  "state/public-node-proof-worker.seed",
  "--audit",
  "state/public-node-proof-audit.log",
], { stdio: ["ignore", "pipe", "inherit"] });

const timer = setTimeout(() => {
  child.kill("SIGKILL");
  console.error("public node proof timeout");
  process.exit(1);
}, 15000);

let output = "";
for await (const chunk of child.stdout) {
  output += chunk;
  const line = output.split("\n").find((item) => item.trim().startsWith("{"));
  if (!line) continue;
  clearTimeout(timer);
  const status = JSON.parse(line);
  if (status.public_transport !== true) throw new Error("public transport proof failed");
  const resolved = await resolveAlias(status.port, originZone, "agent://zone-b/summarizer");
  child.kill("SIGTERM");
  console.log(JSON.stringify({
    public_node_proof: "ok",
    listen_host: status.listen_host,
    port: status.port,
    public_transport: status.public_transport,
    transport: status.transport,
    resolve_alias: resolved.alias,
    resolve_close: resolved.close,
  }));
  process.exit(0);
}

clearTimeout(timer);
process.exitCode = child.exitCode ?? 1;

function authBody(sessionId, challenge, peerZid, remoteZid) {
  return { session_id: sessionId, challenge, peer_zid: peerZid, remote_zid: remoteZid };
}

function resolveAlias(port, zone, alias) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(Number(port), "127.0.0.1");
    let buffer = "";
    let gotResult = false;
    socket.on("error", reject);
    socket.on("connect", () => {
      socket.write(`${JSON.stringify({ type: "HELLO", origin_zone: zone.descriptor })}\n`);
    });
    socket.on("data", (chunk) => {
      buffer += chunk.toString();
      const lines = buffer.split("\n");
      buffer = lines.pop();
      for (const line of lines) {
        if (!line.trim()) continue;
        const frame = JSON.parse(line);
        if (frame.type === "HELLO") {
          const body = authBody(frame.session_id, frame.challenge, zone.descriptor.zid, frame.zone.zid);
          socket.write(`${JSON.stringify({
            type: "AUTH",
            origin_zone: zone.descriptor,
            auth: { ...body, auth_signature: signObject(zone.privateKey, body) },
          })}\n`);
          continue;
        }
        if (frame.type === "AUTH_OK") {
          socket.write(`${JSON.stringify({ type: "FED_RESOLVE", origin_zone: zone.descriptor, alias })}\n`);
          continue;
        }
        if (frame.type === "FED_RESOLVE_RESULT") {
          gotResult = frame.worker?.alias === alias;
          continue;
        }
        if (frame.type === "FED_RESOLVE_CLOSE") {
          socket.end();
          resolve({ alias, close: gotResult && frame.alias === alias });
          return;
        }
        if (frame.type === "FED_TASK_ERROR") {
          reject(new Error(frame.error));
        }
      }
    });
  });
}
