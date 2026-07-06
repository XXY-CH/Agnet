import { spawn } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";

await mkdir("state", { recursive: true });
await writeFile("state/public-node-proof-trusted.json", '{"zones":[]}\n');
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
  child.kill("SIGTERM");
  const status = JSON.parse(line);
  if (status.public_transport !== true) throw new Error("public transport proof failed");
  console.log(JSON.stringify({
    public_node_proof: "ok",
    listen_host: status.listen_host,
    port: status.port,
    public_transport: status.public_transport,
    transport: status.transport,
  }));
  process.exit(0);
}

clearTimeout(timer);
process.exitCode = child.exitCode ?? 1;
