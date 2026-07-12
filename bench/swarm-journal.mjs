import { computeAid, publicKeyFromDescriptor, swarmJournalEntry, verifySwarmJournal } from "../asp-core.mjs";

const ZERO_HASH = "0".repeat(64);
const PUBLIC_KEY_SPKI = "MCowBQYDK2VwAyEA3eO8zsfzpmoRFfRdcg9NwTXDrnxOItyjj9se_WpJX_g";
const ENTRY_COUNTS = [1000, 5000];
const RUNS = 5;
const WARMUP_RUNS = 2;

function parseEntryCounts() {
  const value = process.argv.find((argument) => argument.startsWith("--entries="));
  if (!value) return ENTRY_COUNTS;
  const counts = value.slice("--entries=".length).split(",").map(Number);
  if (counts.length === 0 || counts.some((count) => !Number.isSafeInteger(count) || count < 2)) throw new Error("--entries must be comma-separated safe integers of at least 2");
  return counts;
}

function openedPayload() {
  return {
    schema_version: 1,
    spec: {
      schema_version: 1,
      swarm_id: "swarm://benchmark/deterministic",
      plan: "eyJmb3JtYXQiOiJwbGFuIn0",
      binding: "eyJmb3JtYXQiOiJiaW5kaW5nIn0",
      request: "eyJmb3JtYXQiOiJyZXF1ZXN0In0",
      authority_generation_pin: { store_path: "benchmark", passphrase_file: "benchmark", record_digest: "a".repeat(64) },
      steps: [{
        step_id: "prepare",
        candidates: [{
          alias: "agent://benchmark-worker",
          aid: computeAid(publicKeyFromDescriptor({ public_key_spki: PUBLIC_KEY_SPKI })),
          generation_pin: { store_path: "benchmark", passphrase_file: "benchmark", record_digest: "b".repeat(64) },
          public_key_spki: PUBLIC_KEY_SPKI,
          descriptor_digest: "c".repeat(64),
        }],
        attempt_policy: { max_attempts: 1 },
      }],
    },
  };
}

/** Build a deterministic legal journal: one stateful open followed by non-state future events. */
function buildJournal(entryCount) {
  const journal = [];
  let previousHash = ZERO_HASH;
  for (let index = 0; index < entryCount; index += 1) {
    const sequence = index + 1;
    const entry = swarmJournalEntry({
      format: "agnet-local-swarm-journal/v1",
      sequence,
      prior_state_version: index,
      state_version: sequence,
      kind: index === 0 ? "swarm.opened" : "future.replay",
      payload: index === 0 ? openedPayload() : { ordinal: sequence, schema_version: 1 },
      timestamp: new Date(Date.UTC(2026, 6, 12, 13, 14, 15) + index * 1000).toISOString(),
      prev_hash: previousHash,
    });
    journal.push(entry);
    previousHash = entry.hash;
  }
  return journal;
}

function median(values) {
  const sorted = [...values].sort((left, right) => left - right);
  return sorted[Math.floor(sorted.length / 2)];
}

function measure(journal) {
  for (let run = 0; run < WARMUP_RUNS; run += 1) verifySwarmJournal(journal);
  const measurements = [];
  for (let run = 0; run < RUNS; run += 1) {
    const started = process.hrtime.bigint();
    const verified = verifySwarmJournal(journal);
    const elapsedMilliseconds = Number(process.hrtime.bigint() - started) / 1e6;
    if (verified.entries.length !== journal.length || verified.head !== journal.at(-1).hash || verified.state.version !== journal.length) throw new Error("journal verification returned an unexpected result");
    measurements.push(elapsedMilliseconds);
  }
  return { median_ms: median(measurements), samples_ms: measurements.map((value) => Number(value.toFixed(3))) };
}

for (const entryCount of parseEntryCounts()) {
  const journal = buildJournal(entryCount);
  if (global.gc) global.gc();
  const result = measure(journal);
  console.log(JSON.stringify({ entries: entryCount, runs: RUNS, warmup_runs: WARMUP_RUNS, ...result }));
}
