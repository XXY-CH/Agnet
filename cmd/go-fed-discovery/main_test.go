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

func TestWriteJSONStateFileLeavesCompleteStateAndNoTempFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "task.json")
	if err := writeJSONStateFile(path, map[string]any{"task_id": "task_1", "status": "running"}); err != nil {
		t.Fatal(err)
	}
	if err := writeJSONStateFile(path, map[string]any{"task_id": "task_1", "status": "completed", "receipt_digest": "abc"}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var state map[string]any
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	if state["status"] != "completed" {
		t.Fatalf("status = %v, want completed", state["status"])
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".tmp-") {
			t.Fatalf("temporary state file was not cleaned up: %s", entry.Name())
		}
	}
}

func TestTrustedZoneStoreRejectsRevokedZone(t *testing.T) {
	zone, key := testZoneDescriptor(t, "zone://revoked")
	revocation := signBodyWithKey(key, map[string]any{
		"zone":    zone["zid"],
		"subject": zone["zid"],
		"reason":  "compromised",
	}, "signature")
	store := map[string]any{
		"zones":       []any{zone},
		"revocations": []any{revocation},
	}
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "trusted.json")
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	trusted, err := loadTrustedZones(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyTrustedZone(zone, trusted); err == nil || !strings.Contains(err.Error(), "zone revoked") {
		t.Fatalf("got %v, want zone revoked", err)
	}
}

func testZoneDescriptor(t *testing.T, name string) (map[string]any, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, der, err := publicKeySPKI(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{
		"name":            name,
		"zid":             zidFromSPKI(der),
		"public_key_spki": encoded,
	}
	return signBodyWithKey(privateKey, body, "zone_signature"), privateKey
}
