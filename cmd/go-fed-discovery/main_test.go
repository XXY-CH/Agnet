package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
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

func TestAuditAppendRefreshesSharedHead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	first := &AuditLog{Path: path, Head: auditZeroHash}
	second := &AuditLog{Path: path, Head: auditZeroHash}

	if err := first.Append(map[string]any{"kind": "event", "index": float64(1)}); err != nil {
		t.Fatal(err)
	}
	if err := second.Append(map[string]any{"kind": "event", "index": float64(2)}); err != nil {
		t.Fatal(err)
	}
	entries, err := readAuditEntries(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	prev := auditZeroHash
	for _, entry := range entries {
		if err := verifyAuditEntry(entry, prev); err != nil {
			t.Fatal(err)
		}
		prev = entry["hash"].(string)
	}
}

func TestAuditAppendRejectsCorruptSharedAudit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	first := &AuditLog{Path: path, Head: auditZeroHash}
	second := &AuditLog{Path: path, Head: auditZeroHash}

	if err := first.Append(map[string]any{"kind": "event", "index": float64(1)}); err != nil {
		t.Fatal(err)
	}
	entry, err := auditEntry("bad-prev", map[string]any{"kind": "event", "index": float64(2)})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := second.Append(map[string]any{"kind": "event", "index": float64(3)}); err == nil || !strings.Contains(err.Error(), "audit prev_hash mismatch") {
		t.Fatalf("got %v, want audit prev_hash mismatch", err)
	}
}

func TestFederationListenerCanUseTLS(t *testing.T) {
	certPath, keyPath := writeTestTLSCertificate(t)
	listener, transport, err := listenFederation("0", certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if transport != "fed+tls" {
		t.Fatalf("transport = %s, want fed+tls", transport)
	}

	accepted := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			accepted <- err
			return
		}
		defer conn.Close()
		buf := []byte{0}
		_, err = conn.Read(buf)
		accepted <- err
	}()

	conn, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if err := <-accepted; err != nil {
		t.Fatal(err)
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

func writeTestTLSCertificate(t *testing.T) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
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

func TestTrustedZoneStoreRejectsTamperedRevocation(t *testing.T) {
	zone, key := testZoneDescriptor(t, "zone://tampered-revocation")
	revocation := signBodyWithKey(key, map[string]any{
		"zone":    zone["zid"],
		"subject": zone["zid"],
		"reason":  "compromised",
	}, "signature")
	revocation["reason"] = "edited"
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
	if _, err := loadTrustedZones(path); err == nil || !strings.Contains(err.Error(), "zone revocation signature verification failed") {
		t.Fatalf("got %v, want zone revocation signature verification failed", err)
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
