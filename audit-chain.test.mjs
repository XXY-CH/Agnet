import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile, rm } from "node:fs/promises";
import { appendAudit, AUDIT_ZERO_HASH, auditEntry, verifyAuditEntries } from "./asp-core.mjs";

test("audit hash chain detects tampering", () => {
  const first = auditEntry(AUDIT_ZERO_HASH, { kind: "event", type: "task.started", task_id: "task_1" });
  const second = auditEntry(first.hash, { kind: "receipt", task_id: "task_1", event_count: 1 });

  assert.equal(verifyAuditEntries([first, second]), true);
  assert.equal(
    verifyAuditEntries([
      first,
      { ...second, record: { ...second.record, event_count: 2 } },
    ]),
    false,
  );
});

test("appendAudit serializes concurrent writes", async () => {
  await rm("state/audit.log", { force: true });
  await rm("state/audit.head", { force: true });

  await Promise.all(
    Array.from({ length: 32 }, (_, index) => appendAudit({ kind: "event", type: "concurrent", index })),
  );

  const entries = (await readFile("state/audit.log", "utf8"))
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
  assert.equal(entries.length, 32);
  assert.equal(verifyAuditEntries(entries), true);
});
