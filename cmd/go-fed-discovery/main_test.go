package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadAuditEntriesAcceptsLargeLines(t *testing.T) {
	record := map[string]any{
		"kind":    "large_audit_record",
		"payload": strings.Repeat("x", 80*1024),
	}
	entry, err := auditEntry(auditZeroHash, record)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	entries, err := readAuditEntries(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
}
