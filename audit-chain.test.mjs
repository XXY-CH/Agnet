import assert from "node:assert/strict";
import { test } from "node:test";
import { AUDIT_ZERO_HASH, auditEntry, verifyAuditEntries } from "./asp-core.mjs";

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
