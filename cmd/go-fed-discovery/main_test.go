package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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

func TestApplyApprovalActionSerializesConcurrentApproves(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := Fixture{
		AuthorityPrivateKey: key,
		ApprovalDir:         t.TempDir(),
	}
	taskID := "approval_race"
	if err := f.writeApprovalState(taskID, "pending", []string{"tool"}, "", nil, time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	var successes atomic.Int32
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := f.applyApprovalAction(taskID, "human://operator", "approve"); err == nil {
				successes.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("got %d successful approvals, want 1", successes.Load())
	}
}
