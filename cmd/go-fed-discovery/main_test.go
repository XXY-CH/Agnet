package main

import (
	"agnet/internal/managedkey"
	"agnet/verifier"
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestProtocolCanonicalJSONDoesNotEscapeHTMLCharacters(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"intent": "a<b & c>d", "task_id": "html_chars_task"}
	signed := signBodyWithKey(key, body, "signature")
	signature, err := base64.RawURLEncoding.DecodeString(signed["signature"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(key.Public().(ed25519.PublicKey), testNodeCanonicalJSON(t, body), signature) {
		t.Fatal("signature does not match no-HTML canonical JSON")
	}
	nodeCanonicalSigned := map[string]any{"intent": body["intent"], "task_id": body["task_id"]}
	nodeCanonicalSigned["signature"] = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, testNodeCanonicalJSON(t, body)))
	if err := verifyMapSignature(key.Public().(ed25519.PublicKey), nodeCanonicalSigned, "signature"); err != nil {
		t.Fatalf("verifyMapSignature rejected no-HTML canonical JSON signature: %v", err)
	}
	hash := sha256.Sum256(testNodeCanonicalJSON(t, body))
	if digestHex(body) != hex.EncodeToString(hash[:]) {
		t.Fatalf("digestHex escaped HTML characters")
	}
}

func testNodeCanonicalJSON(t *testing.T, value any) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		t.Fatal(err)
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
}

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

func TestDidKeyBridgeMatchesVector(t *testing.T) {
	spki := "MCowBQYDK2VwAyEAA6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"
	did := "did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd"

	got, err := didKeyFromPublicKeySPKI(spki)
	if err != nil {
		t.Fatal(err)
	}
	if got != did {
		t.Fatalf("did = %s, want %s", got, did)
	}
	roundTrip, err := publicKeySPKIFromDidKey(did)
	if err != nil {
		t.Fatal(err)
	}
	if roundTrip != spki {
		t.Fatalf("spki = %s, want %s", roundTrip, spki)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := agentDescriptor(key, "agent://local/did-key-test")
	if err != nil {
		t.Fatal(err)
	}
	if descriptor["did_key"] == "" {
		t.Fatal("descriptor did_key missing")
	}
}

func TestArtifactManifestAFPMatchesSHA256(t *testing.T) {
	manifest, err := writeArtifact("artifact://local/afp-test/out.md", "# AFP\n", "")
	if err != nil {
		t.Fatal(err)
	}
	sha := fmt.Sprint(manifest["sha256"])
	if manifest["afp"] != "afp:sha256:"+sha {
		t.Fatalf("afp = %v, want afp:sha256:%s", manifest["afp"], sha)
	}

	bad := map[string]any{
		"uri":        manifest["uri"],
		"sha256":     manifest["sha256"],
		"size":       manifest["size"],
		"media_type": manifest["media_type"],
		"afp":        "afp:sha256:" + strings.Repeat("0", 64),
	}
	bad["manifest_hash"] = digestHex(bad)
	sidecar, err := json.MarshalIndent(bad, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	sidecar = append(sidecar, '\n')
	path, err := localArtifactPath(fmt.Sprint(manifest["uri"]))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".manifest.json", sidecar, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("artifacts", "by-sha256", sha)+".manifest.json", sidecar, 0o644); err != nil {
		t.Fatal(err)
	}
	err = verifyArtifactManifests(map[string]any{
		"artifact_refs":      []any{manifest["uri"]},
		"artifact_manifests": []any{bad},
	}, "")
	if err == nil || !strings.Contains(err.Error(), "artifact manifest afp mismatch") {
		t.Fatalf("got %v, want artifact manifest afp mismatch", err)
	}
}

func TestArtifactManifestRejectsUnsafeSHA256BeforeDigestPath(t *testing.T) {
	manifest, err := writeArtifact("artifact://local/sha-boundary-test/out.md", "# SHA\n", "")
	if err != nil {
		t.Fatal(err)
	}
	bad := map[string]any{
		"uri":        manifest["uri"],
		"sha256":     "../evil",
		"size":       manifest["size"],
		"media_type": manifest["media_type"],
		"afp":        "afp:sha256:../evil",
	}
	bad["manifest_hash"] = digestHex(bad)
	sidecar, err := json.MarshalIndent(bad, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path, err := localArtifactPath(fmt.Sprint(manifest["uri"]))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".manifest.json", append(sidecar, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	err = verifyArtifactManifests(map[string]any{
		"artifact_refs":      []any{manifest["uri"]},
		"artifact_manifests": []any{bad},
	}, "")
	if err == nil || !strings.Contains(err.Error(), "artifact manifest sha256 invalid") {
		t.Fatalf("got %v, want artifact manifest sha256 invalid", err)
	}
}

func TestArtifactManifestRejectsMalformedSizeBeforeByteChecks(t *testing.T) {
	manifest, err := writeArtifact("artifact://local/size-boundary-test/out.md", "# Size\n", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []float64{-1, 1.5} {
		bad := map[string]any{
			"uri":        manifest["uri"],
			"sha256":     manifest["sha256"],
			"size":       size,
			"media_type": manifest["media_type"],
			"afp":        manifest["afp"],
		}
		bad["manifest_hash"] = digestHex(bad)
		sidecar, err := json.MarshalIndent(bad, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		path, err := localArtifactPath(fmt.Sprint(manifest["uri"]))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path+".manifest.json", append(sidecar, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		err = verifyArtifactManifests(map[string]any{
			"artifact_refs":      []any{manifest["uri"]},
			"artifact_manifests": []any{bad},
		}, "")
		if err == nil || !strings.Contains(err.Error(), "artifact manifest size invalid") {
			t.Fatalf("size %v: got %v, want artifact manifest size invalid", size, err)
		}
	}
}

func TestArtifactManifestRejectsMalformedMediaTypeBeforeByteChecks(t *testing.T) {
	manifest, err := writeArtifact("artifact://local/media-type-boundary-test/out.md", "# Media\n", "")
	if err != nil {
		t.Fatal(err)
	}
	bad := map[string]any{
		"uri":        manifest["uri"],
		"sha256":     manifest["sha256"],
		"size":       manifest["size"],
		"media_type": map[string]any{"type": "text/plain"},
		"afp":        manifest["afp"],
	}
	bad["manifest_hash"] = digestHex(bad)
	sidecar, err := json.MarshalIndent(bad, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path, err := localArtifactPath(fmt.Sprint(manifest["uri"]))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".manifest.json", append(sidecar, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	err = verifyArtifactManifests(map[string]any{
		"artifact_refs":      []any{manifest["uri"]},
		"artifact_manifests": []any{bad},
	}, "")
	if err == nil || !strings.Contains(err.Error(), "artifact manifest media_type invalid") {
		t.Fatalf("got %v, want artifact manifest media_type invalid", err)
	}
}

func TestArtifactManifestRejectsMalformedManifestHashBeforeByteChecks(t *testing.T) {
	manifest, err := writeArtifact("artifact://local/manifest-hash-boundary-test/out.md", "# Manifest Hash\n", "")
	if err != nil {
		t.Fatal(err)
	}
	bad := map[string]any{
		"uri":           manifest["uri"],
		"sha256":        manifest["sha256"],
		"size":          manifest["size"],
		"media_type":    manifest["media_type"],
		"afp":           manifest["afp"],
		"manifest_hash": map[string]any{"hash": manifest["manifest_hash"]},
	}
	sidecar, err := json.MarshalIndent(bad, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path, err := localArtifactPath(fmt.Sprint(manifest["uri"]))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".manifest.json", append(sidecar, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	err = verifyArtifactManifests(map[string]any{
		"artifact_refs":      []any{manifest["uri"]},
		"artifact_manifests": []any{bad},
	}, "")
	if err == nil || !strings.Contains(err.Error(), "artifact manifest manifest_hash invalid") {
		t.Fatalf("got %v, want artifact manifest manifest_hash invalid", err)
	}
}

func TestArtifactManifestRejectsMalformedURIBeforeByteChecks(t *testing.T) {
	manifest, err := writeArtifact("artifact://local/uri-boundary-test/out.md", "# URI\n", "")
	if err != nil {
		t.Fatal(err)
	}
	bad := map[string]any{
		"uri":        map[string]any{"path": manifest["uri"]},
		"sha256":     manifest["sha256"],
		"size":       manifest["size"],
		"media_type": manifest["media_type"],
		"afp":        manifest["afp"],
	}
	bad["manifest_hash"] = digestHex(bad)
	err = verifyArtifactManifests(map[string]any{
		"artifact_refs":      []any{manifest["uri"]},
		"artifact_manifests": []any{bad},
	}, "")
	if err == nil || !strings.Contains(err.Error(), "artifact manifest uri invalid") {
		t.Fatalf("got %v, want artifact manifest uri invalid", err)
	}
}

func TestArtifactManifestRejectsMalformedAFPBeforeByteChecks(t *testing.T) {
	manifest, err := writeArtifact("artifact://local/afp-shape-boundary-test/out.md", "# AFP\n", "")
	if err != nil {
		t.Fatal(err)
	}
	bad := map[string]any{
		"uri":        manifest["uri"],
		"sha256":     manifest["sha256"],
		"size":       manifest["size"],
		"media_type": manifest["media_type"],
		"afp":        map[string]any{"sha256": manifest["sha256"]},
	}
	bad["manifest_hash"] = digestHex(bad)
	err = verifyArtifactManifests(map[string]any{
		"artifact_refs":      []any{manifest["uri"]},
		"artifact_manifests": []any{bad},
	}, "")
	if err == nil || !strings.Contains(err.Error(), "artifact manifest afp invalid") {
		t.Fatalf("got %v, want artifact manifest afp invalid", err)
	}
}

func TestArtifactManifestRejectsMalformedListEntriesBeforeByteChecks(t *testing.T) {
	manifest, err := writeArtifact("artifact://local/list-shape-boundary-test/out.md", "# List\n", "")
	if err != nil {
		t.Fatal(err)
	}
	err = verifyArtifactManifests(map[string]any{
		"artifact_refs":      []any{manifest["uri"]},
		"artifact_manifests": []any{manifest, nil},
	}, "")
	if err == nil || !strings.Contains(err.Error(), "artifact manifest missing") {
		t.Fatalf("got %v, want artifact manifest missing", err)
	}
}

func TestReceiptArtifactManifestRejectsMalformedLists(t *testing.T) {
	manifest := map[string]any{
		"uri":           "artifact://local/lookup-shape-test/out.md",
		"sha256":        strings.Repeat("1", 64),
		"size":          float64(1),
		"media_type":    "text/plain",
		"manifest_hash": strings.Repeat("2", 64),
	}
	_, err := receiptArtifactManifest(map[string]any{
		"artifact_refs":      []any{manifest["uri"], map[string]any{"uri": manifest["uri"]}},
		"artifact_manifests": []map[string]any{manifest},
	}, fmt.Sprint(manifest["uri"]))
	if err == nil || !strings.Contains(err.Error(), "artifact refs invalid") {
		t.Fatalf("got %v, want artifact refs invalid", err)
	}
	_, err = receiptArtifactManifest(map[string]any{
		"artifact_refs": []string{fmt.Sprint(manifest["uri"])},
		"artifact_manifests": []any{
			manifest,
			"bad-manifest",
		},
	}, fmt.Sprint(manifest["uri"]))
	if err == nil || !strings.Contains(err.Error(), "artifact manifest missing") {
		t.Fatalf("got %v, want artifact manifest missing", err)
	}
}

func TestArtifactStoreIndexRequiresExactManifestFieldTypes(t *testing.T) {
	manifest := map[string]any{
		"uri":           "artifact://local/index-shape-boundary-test/out.md",
		"sha256":        strings.Repeat("1", 64),
		"size":          float64(7),
		"media_type":    "text/markdown",
		"afp":           "afp:sha256:" + strings.Repeat("1", 64),
		"manifest_hash": strings.Repeat("2", 64),
	}
	index := []map[string]any{{
		"uri":           manifest["uri"],
		"sha256":        manifest["sha256"],
		"size":          "7",
		"media_type":    manifest["media_type"],
		"afp":           manifest["afp"],
		"manifest_hash": manifest["manifest_hash"],
	}}
	if artifactStoreIndexContains(index, manifest) {
		t.Fatal("string size index entry matched numeric manifest size")
	}
}

func TestArtifactStoreIndexRejectsNullEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "objects.ndjson")
	if err := os.WriteFile(path, []byte("null\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := readArtifactStoreIndex(path)
	if err == nil || !strings.Contains(err.Error(), "artifact mirror index invalid") {
		t.Fatalf("got %v, want artifact mirror index invalid", err)
	}
}

func TestArtifactStoreIndexRejectsUnsafeSHA256(t *testing.T) {
	path := filepath.Join(t.TempDir(), "objects.ndjson")
	if err := os.WriteFile(path, []byte(`{"sha256":"../evil"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := readArtifactStoreIndex(path)
	if err == nil || !strings.Contains(err.Error(), "artifact mirror index invalid") {
		t.Fatalf("got %v, want artifact mirror index invalid", err)
	}
}

func TestArtifactStoreIndexRejectsMissingSHA256(t *testing.T) {
	path := filepath.Join(t.TempDir(), "objects.ndjson")
	if err := os.WriteFile(path, []byte(`{"uri":"artifact://local/missing-sha"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := readArtifactStoreIndex(path)
	if err == nil || !strings.Contains(err.Error(), "artifact mirror index invalid") {
		t.Fatalf("got %v, want artifact mirror index invalid", err)
	}
}

func TestArtifactStoreIndexRejectsUnsafeManifestHash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "objects.ndjson")
	row := `{"sha256":"` + strings.Repeat("1", 64) + `","manifest_hash":"../evil"}`
	if err := os.WriteFile(path, []byte(row+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := readArtifactStoreIndex(path)
	if err == nil || !strings.Contains(err.Error(), "artifact mirror index invalid") {
		t.Fatalf("got %v, want artifact mirror index invalid", err)
	}
}

func TestArtifactStoreIndexRejectsAFPMismatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "objects.ndjson")
	row := `{"sha256":"` + strings.Repeat("1", 64) + `","afp":"afp:sha256:` + strings.Repeat("2", 64) + `"}`
	if err := os.WriteFile(path, []byte(row+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := readArtifactStoreIndex(path)
	if err == nil || !strings.Contains(err.Error(), "artifact mirror index invalid") {
		t.Fatalf("got %v, want artifact mirror index invalid", err)
	}
}

func TestArtifactStoreIndexRejectsInvalidAFP(t *testing.T) {
	path := filepath.Join(t.TempDir(), "objects.ndjson")
	row := `{"sha256":"` + strings.Repeat("1", 64) + `","afp":{"sha256":"` + strings.Repeat("1", 64) + `"}}`
	if err := os.WriteFile(path, []byte(row+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := readArtifactStoreIndex(path)
	if err == nil || !strings.Contains(err.Error(), "artifact mirror index afp invalid") {
		t.Fatalf("got %v, want artifact mirror index afp invalid", err)
	}
}

func TestArtifactStoreIndexRejectsInvalidSize(t *testing.T) {
	for _, row := range []string{
		`{"sha256":"` + strings.Repeat("1", 64) + `","size":"7"}`,
		`{"sha256":"` + strings.Repeat("1", 64) + `","size":-1}`,
		`{"sha256":"` + strings.Repeat("1", 64) + `","size":1.5}`,
	} {
		path := filepath.Join(t.TempDir(), "objects.ndjson")
		if err := os.WriteFile(path, []byte(row+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := readArtifactStoreIndex(path)
		if err == nil || !strings.Contains(err.Error(), "artifact mirror index invalid") {
			t.Fatalf("row %s: got %v, want artifact mirror index invalid", row, err)
		}
	}
}

func TestArtifactStoreIndexRejectsInvalidMediaType(t *testing.T) {
	path := filepath.Join(t.TempDir(), "objects.ndjson")
	row := `{"sha256":"` + strings.Repeat("1", 64) + `","media_type":{"type":"text/plain"}}`
	if err := os.WriteFile(path, []byte(row+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := readArtifactStoreIndex(path)
	if err == nil || !strings.Contains(err.Error(), "artifact mirror index invalid") {
		t.Fatalf("got %v, want artifact mirror index invalid", err)
	}
}

func TestArtifactStoreIndexRejectsInvalidURI(t *testing.T) {
	path := filepath.Join(t.TempDir(), "objects.ndjson")
	row := `{"sha256":"` + strings.Repeat("1", 64) + `","uri":{"path":"artifact://local/out.md"}}`
	if err := os.WriteFile(path, []byte(row+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := readArtifactStoreIndex(path)
	if err == nil || !strings.Contains(err.Error(), "artifact mirror index invalid") {
		t.Fatalf("got %v, want artifact mirror index invalid", err)
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
	listener, transport, err := listenFederation("127.0.0.1", "0", certPath, keyPath, "")
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

func TestFederationListenerCanBindConfiguredHost(t *testing.T) {
	listener, transport, err := listenFederation("127.0.0.1", "0", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if transport != "fed+tcp" {
		t.Fatalf("transport = %s, want fed+tcp", transport)
	}
	if host, _, _ := net.SplitHostPort(listener.Addr().String()); host != "127.0.0.1" {
		t.Fatalf("host = %s, want 127.0.0.1", host)
	}
}

func TestFedTaskOpenConformanceVectorVerifiesInGo(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "test-vectors", "asp-v9.24-fed-task-open.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		TrustedZones  []map[string]any `json:"trusted_zones"`
		Worker        map[string]any   `json:"worker"`
		Frame         map[string]any   `json:"frame"`
		TaskCanonical string           `json:"task_canonical"`
		Expected      map[string]any   `json:"expected"`
	}
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	trusted := map[string]map[string]any{}
	for _, zone := range vector.TrustedZones {
		trusted[fmt.Sprint(zone["zid"])] = zone
	}
	origin, ok := vector.Frame["origin_zone"].(map[string]any)
	if !ok {
		t.Fatal("origin_zone missing")
	}
	if err := verifyTrustedZone(origin, trusted); err != nil {
		t.Fatal(err)
	}

	fixture := Fixture{Workers: []Worker{{Descriptor: vector.Worker}}}
	wrongTypeFrame := map[string]any{}
	for key, value := range vector.Frame {
		wrongTypeFrame[key] = value
	}
	wrongTypeFrame["type"] = "FED_RECEIPT"
	if _, _, err := fixture.verifyTaskOpen(wrongTypeFrame); err == nil || !strings.Contains(err.Error(), "expected FED_TASK_OPEN frame") {
		t.Fatalf("got %v, want expected FED_TASK_OPEN frame", err)
	}

	unboundFrame := map[string]any{}
	for key, value := range vector.Frame {
		if key != "requester_zone_binding" {
			unboundFrame[key] = value
		}
	}
	if _, _, err := fixture.verifyTaskOpen(unboundFrame); err == nil || !strings.Contains(err.Error(), "requester zone binding missing") {
		t.Fatalf("got %v, want requester zone binding missing", err)
	}

	worker, task, err := fixture.verifyTaskOpen(vector.Frame)
	if err != nil {
		t.Fatal(err)
	}
	taskBody := map[string]any{}
	for key, value := range task {
		if key != "signature" {
			taskBody[key] = value
		}
	}
	canonicalTask, err := json.Marshal(taskBody)
	if err != nil {
		t.Fatal(err)
	}
	if string(canonicalTask) != vector.TaskCanonical {
		t.Fatalf("canonical task = %s, want %s", canonicalTask, vector.TaskCanonical)
	}
	if task["task_id"] != vector.Expected["task_id"] {
		t.Fatalf("task_id = %v, want %v", task["task_id"], vector.Expected["task_id"])
	}
	if worker.Descriptor["alias"] != vector.Expected["worker_alias"] {
		t.Fatalf("worker alias = %v, want %v", worker.Descriptor["alias"], vector.Expected["worker_alias"])
	}
}

func TestFedReceiptConformanceVectorVerifiesInGo(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "test-vectors", "asp-v9.25-fed-receipt.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		TrustedZones     []map[string]any `json:"trusted_zones"`
		Frame            map[string]any   `json:"frame"`
		ReceiptCanonical string           `json:"receipt_canonical"`
		Expected         map[string]any   `json:"expected"`
	}
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	trusted := map[string]map[string]any{}
	for _, zone := range vector.TrustedZones {
		trusted[fmt.Sprint(zone["zid"])] = zone
	}
	if err := verifyInteropReceipt(vector.Frame, trusted); err != nil {
		t.Fatal(err)
	}
	receipt, ok := vector.Frame["receipt"].(map[string]any)
	if !ok {
		t.Fatal("receipt missing")
	}
	receiptBody := map[string]any{}
	for key, value := range receipt {
		if key != "signature" {
			receiptBody[key] = value
		}
	}
	canonicalReceipt, err := json.Marshal(receiptBody)
	if err != nil {
		t.Fatal(err)
	}
	if string(canonicalReceipt) != vector.ReceiptCanonical {
		t.Fatalf("canonical receipt = %s, want %s", canonicalReceipt, vector.ReceiptCanonical)
	}
	if receipt["task_id"] != vector.Expected["task_id"] {
		t.Fatalf("task_id = %v, want %v", receipt["task_id"], vector.Expected["task_id"])
	}
	if receipt["to"] != vector.Expected["worker_aid"] {
		t.Fatalf("receipt worker = %v, want %v", receipt["to"], vector.Expected["worker_aid"])
	}
}

func TestVerifyAuditRejectsSwarmInputArtifactMismatch(t *testing.T) {
	t.Chdir(t.TempDir())
	zone, zoneKey := testZoneDescriptor(t, "zone://swarm")
	_, upstreamKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, downstreamKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	upstreamWorker, err := agentDescriptor(upstreamKey, "agent://zone-b/upstream")
	if err != nil {
		t.Fatal(err)
	}
	downstreamWorker, err := agentDescriptor(downstreamKey, "agent://zone-b/downstream")
	if err != nil {
		t.Fatal(err)
	}
	fixture := Fixture{Authority: zone, AuthorityPrivateKey: zoneKey}
	upstreamManifest, err := writeArtifact("artifact://local/swarm_up/out.md", "# upstream\n", "")
	if err != nil {
		t.Fatal(err)
	}
	otherManifest, err := writeArtifact("artifact://local/swarm_other/out.md", "# other\n", "")
	if err != nil {
		t.Fatal(err)
	}
	downstreamManifest, err := writeArtifact("artifact://local/swarm_down/out.md", "# downstream\n", "")
	if err != nil {
		t.Fatal(err)
	}
	upstreamReceipt := testSignedReceipt(t, zone, zoneKey, upstreamWorker, upstreamKey, "swarm_up", []map[string]any{upstreamManifest}, map[string]any{
		"swarm": map[string]any{
			"swarm_id":        "swarm://test",
			"step_id":         "upstream",
			"after":           []string{},
			"input_artifacts": []map[string]any{},
		},
	})
	nulSwarmReceipt := testSignedReceipt(t, zone, zoneKey, upstreamWorker, upstreamKey, "swarm_nul_swarm", []map[string]any{upstreamManifest}, map[string]any{
		"swarm": map[string]any{
			"swarm_id":        "swarm://test\x00shadow",
			"step_id":         "upstream",
			"after":           []string{},
			"input_artifacts": []map[string]any{},
		},
	})
	nulSwarmLog := &AuditLog{Path: "nul-swarm-id-audit.log", Head: auditZeroHash}
	if err := nulSwarmLog.Append(map[string]any{"kind": "go_fed_receipt", "zone": zone, "worker": upstreamWorker, "zone_binding": fixture.zoneBindingForDescriptor(upstreamWorker), "receipt": nulSwarmReceipt}); err != nil {
		t.Fatal(err)
	}
	err = verifyAuditFile("nul-swarm-id-audit.log", "")
	if err == nil || !strings.Contains(err.Error(), "swarm identity contains NUL") {
		t.Fatalf("got %v, want swarm identity contains NUL", err)
	}
	nulStepReceipt := testSignedReceipt(t, zone, zoneKey, upstreamWorker, upstreamKey, "swarm_nul_step", []map[string]any{upstreamManifest}, map[string]any{
		"swarm": map[string]any{
			"swarm_id":        "swarm://test",
			"step_id":         "upstream\x00shadow",
			"after":           []string{},
			"input_artifacts": []map[string]any{},
		},
	})
	nulStepLog := &AuditLog{Path: "nul-step-id-audit.log", Head: auditZeroHash}
	if err := nulStepLog.Append(map[string]any{"kind": "go_fed_receipt", "zone": zone, "worker": upstreamWorker, "zone_binding": fixture.zoneBindingForDescriptor(upstreamWorker), "receipt": nulStepReceipt}); err != nil {
		t.Fatal(err)
	}
	err = verifyAuditFile("nul-step-id-audit.log", "")
	if err == nil || !strings.Contains(err.Error(), "swarm identity contains NUL") {
		t.Fatalf("got %v, want swarm identity contains NUL", err)
	}
	otherReceipt := testSignedReceipt(t, zone, zoneKey, upstreamWorker, upstreamKey, "swarm_other", []map[string]any{otherManifest}, map[string]any{
		"swarm": map[string]any{
			"swarm_id":        "swarm://test",
			"step_id":         "other",
			"after":           []string{},
			"input_artifacts": []map[string]any{},
		},
	})
	downstreamReceipt := testSignedReceipt(t, zone, zoneKey, downstreamWorker, downstreamKey, "swarm_down", []map[string]any{downstreamManifest}, map[string]any{
		"swarm": map[string]any{
			"swarm_id": "swarm://test",
			"step_id":  "downstream",
			"after":    []string{"upstream"},
			"input_artifacts": []map[string]any{{
				"step_id":               "upstream",
				"uri":                   upstreamManifest["uri"],
				"sha256":                strings.Repeat("0", 64),
				"manifest_hash":         upstreamManifest["manifest_hash"],
				"signed_receipt_digest": digestHex(upstreamReceipt),
			}},
		},
	})
	invalidAfterReceipt := testSignedReceipt(t, zone, zoneKey, downstreamWorker, downstreamKey, "swarm_down_invalid_after", []map[string]any{downstreamManifest}, map[string]any{
		"swarm": map[string]any{
			"swarm_id": "swarm://test",
			"step_id":  "downstream",
			"after":    []any{"upstream", map[string]any{"step_id": "ghost"}},
			"input_artifacts": []map[string]any{{
				"step_id":               "upstream",
				"uri":                   upstreamManifest["uri"],
				"sha256":                upstreamManifest["sha256"],
				"manifest_hash":         upstreamManifest["manifest_hash"],
				"signed_receipt_digest": digestHex(upstreamReceipt),
			}},
		},
	})
	invalidAfterLog := &AuditLog{Path: "invalid-after-audit.log", Head: auditZeroHash}
	if err := invalidAfterLog.Append(map[string]any{"kind": "go_fed_receipt", "zone": zone, "worker": upstreamWorker, "zone_binding": fixture.zoneBindingForDescriptor(upstreamWorker), "receipt": upstreamReceipt}); err != nil {
		t.Fatal(err)
	}
	if err := invalidAfterLog.Append(map[string]any{"kind": "go_fed_receipt", "zone": zone, "worker": downstreamWorker, "zone_binding": fixture.zoneBindingForDescriptor(downstreamWorker), "receipt": invalidAfterReceipt}); err != nil {
		t.Fatal(err)
	}
	err = verifyAuditFile("invalid-after-audit.log", "")
	if err == nil || !strings.Contains(err.Error(), "swarm after invalid") {
		t.Fatalf("got %v, want swarm after invalid", err)
	}
	invalidInputReceipt := testSignedReceipt(t, zone, zoneKey, downstreamWorker, downstreamKey, "swarm_down_invalid_input", []map[string]any{downstreamManifest}, map[string]any{
		"swarm": map[string]any{
			"swarm_id": "swarm://test",
			"step_id":  "downstream",
			"after":    []any{"upstream"},
			"input_artifacts": []any{
				map[string]any{
					"step_id":               "upstream",
					"uri":                   upstreamManifest["uri"],
					"sha256":                upstreamManifest["sha256"],
					"manifest_hash":         upstreamManifest["manifest_hash"],
					"signed_receipt_digest": digestHex(upstreamReceipt),
				},
				"bad-input",
			},
		},
	})
	invalidInputLog := &AuditLog{Path: "invalid-input-audit.log", Head: auditZeroHash}
	if err := invalidInputLog.Append(map[string]any{"kind": "go_fed_receipt", "zone": zone, "worker": upstreamWorker, "zone_binding": fixture.zoneBindingForDescriptor(upstreamWorker), "receipt": upstreamReceipt}); err != nil {
		t.Fatal(err)
	}
	if err := invalidInputLog.Append(map[string]any{"kind": "go_fed_receipt", "zone": zone, "worker": downstreamWorker, "zone_binding": fixture.zoneBindingForDescriptor(downstreamWorker), "receipt": invalidInputReceipt}); err != nil {
		t.Fatal(err)
	}
	err = verifyAuditFile("invalid-input-audit.log", "")
	if err == nil || !strings.Contains(err.Error(), "swarm input artifact invalid") {
		t.Fatalf("got %v, want swarm input artifact invalid", err)
	}
	log := &AuditLog{Path: "audit.log", Head: auditZeroHash}
	if err := log.Append(map[string]any{"kind": "go_fed_receipt", "zone": zone, "worker": upstreamWorker, "zone_binding": fixture.zoneBindingForDescriptor(upstreamWorker), "receipt": upstreamReceipt}); err != nil {
		t.Fatal(err)
	}
	if err := log.Append(map[string]any{"kind": "go_fed_receipt", "zone": zone, "worker": downstreamWorker, "zone_binding": fixture.zoneBindingForDescriptor(downstreamWorker), "receipt": downstreamReceipt}); err != nil {
		t.Fatal(err)
	}

	err = verifyAuditFile("audit.log", "")
	if err == nil || !strings.Contains(err.Error(), "swarm input artifact digest mismatch") {
		t.Fatalf("got %v, want swarm input artifact digest mismatch", err)
	}

	downstreamReceipt["swarm"].(map[string]any)["input_artifacts"].([]map[string]any)[0]["sha256"] = upstreamManifest["sha256"]
	downstreamReceipt["swarm"].(map[string]any)["input_artifacts"].([]map[string]any)[0]["signed_receipt_digest"] = strings.Repeat("1", 64)
	downstreamBadReceiptDigest := signBody(downstreamKey, receiptBodyWithoutSignature(downstreamReceipt))
	badDigestLog := &AuditLog{Path: "bad-digest-audit.log", Head: auditZeroHash}
	if err := badDigestLog.Append(map[string]any{"kind": "go_fed_receipt", "zone": zone, "worker": upstreamWorker, "zone_binding": fixture.zoneBindingForDescriptor(upstreamWorker), "receipt": upstreamReceipt}); err != nil {
		t.Fatal(err)
	}
	if err := badDigestLog.Append(map[string]any{"kind": "go_fed_receipt", "zone": zone, "worker": downstreamWorker, "zone_binding": fixture.zoneBindingForDescriptor(downstreamWorker), "receipt": downstreamBadReceiptDigest}); err != nil {
		t.Fatal(err)
	}
	err = verifyAuditFile("bad-digest-audit.log", "")
	if err == nil || !strings.Contains(err.Error(), "swarm input signed receipt digest mismatch") {
		t.Fatalf("got %v, want swarm input signed receipt digest mismatch", err)
	}

	downstreamStepMismatchReceipt := testSignedReceipt(t, zone, zoneKey, downstreamWorker, downstreamKey, "swarm_down_wrong_step", []map[string]any{downstreamManifest}, map[string]any{
		"swarm": map[string]any{
			"swarm_id": "swarm://test",
			"step_id":  "downstream",
			"after":    []string{"upstream"},
			"input_artifacts": []map[string]any{{
				"step_id":               "other",
				"uri":                   otherManifest["uri"],
				"sha256":                otherManifest["sha256"],
				"manifest_hash":         otherManifest["manifest_hash"],
				"signed_receipt_digest": digestHex(otherReceipt),
			}},
		},
	})
	stepMismatchLog := &AuditLog{Path: "step-mismatch-audit.log", Head: auditZeroHash}
	if err := stepMismatchLog.Append(map[string]any{"kind": "go_fed_receipt", "zone": zone, "worker": upstreamWorker, "zone_binding": fixture.zoneBindingForDescriptor(upstreamWorker), "receipt": upstreamReceipt}); err != nil {
		t.Fatal(err)
	}
	if err := stepMismatchLog.Append(map[string]any{"kind": "go_fed_receipt", "zone": zone, "worker": upstreamWorker, "zone_binding": fixture.zoneBindingForDescriptor(upstreamWorker), "receipt": otherReceipt}); err != nil {
		t.Fatal(err)
	}
	if err := stepMismatchLog.Append(map[string]any{"kind": "go_fed_receipt", "zone": zone, "worker": downstreamWorker, "zone_binding": fixture.zoneBindingForDescriptor(downstreamWorker), "receipt": downstreamStepMismatchReceipt}); err != nil {
		t.Fatal(err)
	}
	err = verifyAuditFile("step-mismatch-audit.log", "")
	if err == nil || !strings.Contains(err.Error(), "swarm input artifact step mismatch") {
		t.Fatalf("got %v, want swarm input artifact step mismatch", err)
	}

	duplicateStepReceipt := testSignedReceipt(t, zone, zoneKey, upstreamWorker, upstreamKey, "swarm_up_duplicate", []map[string]any{otherManifest}, map[string]any{
		"swarm": map[string]any{
			"swarm_id":        "swarm://test",
			"step_id":         "upstream",
			"after":           []string{},
			"input_artifacts": []map[string]any{},
		},
	})
	downstreamDuplicateStepReceipt := testSignedReceipt(t, zone, zoneKey, downstreamWorker, downstreamKey, "swarm_down_duplicate_step", []map[string]any{downstreamManifest}, map[string]any{
		"swarm": map[string]any{
			"swarm_id": "swarm://test",
			"step_id":  "downstream",
			"after":    []string{"upstream"},
			"input_artifacts": []map[string]any{{
				"step_id":               "upstream",
				"uri":                   otherManifest["uri"],
				"sha256":                otherManifest["sha256"],
				"manifest_hash":         otherManifest["manifest_hash"],
				"signed_receipt_digest": digestHex(duplicateStepReceipt),
			}},
		},
	})
	duplicateStepLog := &AuditLog{Path: "duplicate-step-audit.log", Head: auditZeroHash}
	if err := duplicateStepLog.Append(map[string]any{"kind": "go_fed_receipt", "zone": zone, "worker": upstreamWorker, "zone_binding": fixture.zoneBindingForDescriptor(upstreamWorker), "receipt": upstreamReceipt}); err != nil {
		t.Fatal(err)
	}
	if err := duplicateStepLog.Append(map[string]any{"kind": "go_fed_receipt", "zone": zone, "worker": upstreamWorker, "zone_binding": fixture.zoneBindingForDescriptor(upstreamWorker), "receipt": duplicateStepReceipt}); err != nil {
		t.Fatal(err)
	}
	if err := duplicateStepLog.Append(map[string]any{"kind": "go_fed_receipt", "zone": zone, "worker": downstreamWorker, "zone_binding": fixture.zoneBindingForDescriptor(downstreamWorker), "receipt": downstreamDuplicateStepReceipt}); err != nil {
		t.Fatal(err)
	}
	err = verifyAuditFile("duplicate-step-audit.log", "")
	if err == nil || !strings.Contains(err.Error(), "duplicate swarm step receipt") {
		t.Fatalf("got %v, want duplicate swarm step receipt", err)
	}

	noArtifactReceiptBody := receiptBodyWithoutSignature(testSignedReceipt(t, zone, zoneKey, upstreamWorker, upstreamKey, "swarm_no_artifact", []map[string]any{upstreamManifest}, map[string]any{
		"swarm": map[string]any{
			"swarm_id":        "swarm://test",
			"step_id":         "no-artifact",
			"after":           []string{},
			"input_artifacts": []map[string]any{},
		},
	}))
	noArtifactReceiptBody["artifact_refs"] = []string{}
	noArtifactReceiptBody["artifact_manifests"] = []map[string]any{}
	delete(noArtifactReceiptBody, "result_artifact")
	noArtifactReceipt := signBody(upstreamKey, noArtifactReceiptBody)
	duplicateNoArtifactLog := &AuditLog{Path: "duplicate-no-artifact-audit.log", Head: auditZeroHash}
	if err := duplicateNoArtifactLog.Append(map[string]any{"kind": "go_fed_receipt", "zone": zone, "worker": upstreamWorker, "zone_binding": fixture.zoneBindingForDescriptor(upstreamWorker), "receipt": noArtifactReceipt}); err != nil {
		t.Fatal(err)
	}
	if err := duplicateNoArtifactLog.Append(map[string]any{"kind": "go_fed_receipt", "zone": zone, "worker": upstreamWorker, "zone_binding": fixture.zoneBindingForDescriptor(upstreamWorker), "receipt": noArtifactReceipt}); err != nil {
		t.Fatal(err)
	}
	err = verifyAuditFile("duplicate-no-artifact-audit.log", "")
	if err == nil || !strings.Contains(err.Error(), "duplicate swarm step receipt") {
		t.Fatalf("got %v, want duplicate swarm step receipt", err)
	}

	downstreamReceipt["swarm"].(map[string]any)["input_artifacts"].([]map[string]any)[0]["signed_receipt_digest"] = digestHex(upstreamReceipt)
	downstreamRecord := signBody(downstreamKey, receiptBodyWithoutSignature(downstreamReceipt))
	cleanLog := &AuditLog{Path: "clean-audit.log", Head: auditZeroHash}
	if err := cleanLog.Append(map[string]any{"kind": "go_fed_receipt", "zone": zone, "worker": upstreamWorker, "zone_binding": fixture.zoneBindingForDescriptor(upstreamWorker), "receipt": upstreamReceipt}); err != nil {
		t.Fatal(err)
	}
	if err := cleanLog.Append(map[string]any{"kind": "go_fed_receipt", "zone": zone, "worker": downstreamWorker, "zone_binding": fixture.zoneBindingForDescriptor(downstreamWorker), "receipt": downstreamRecord}); err != nil {
		t.Fatal(err)
	}
	cleanClose := signBodyWithKey(zoneKey, map[string]any{
		"format":   "asp-swarm-close/v1",
		"swarm_id": "swarm://test",
		"step_receipts": []map[string]any{
			{"step_id": "upstream", "task_id": "swarm_up", "receipt_digest": digestHex(upstreamReceipt)},
			{"step_id": "downstream", "task_id": "swarm_down", "receipt_digest": digestHex(downstreamRecord)},
		},
	}, "close_signature")
	if err := cleanLog.Append(map[string]any{"kind": "go_swarm_close", "zone": zone, "close": cleanClose}); err != nil {
		t.Fatal(err)
	}
	if err := verifyAuditFile("clean-audit.log", ""); err != nil {
		t.Fatal(err)
	}

	malformedClose := signBodyWithKey(zoneKey, map[string]any{
		"format":   "asp-swarm-close/v1",
		"swarm_id": "swarm://test",
		"step_receipts": []any{
			map[string]any{"step_id": "upstream", "task_id": "swarm_up", "receipt_digest": digestHex(upstreamReceipt)},
			map[string]any{"step_id": "downstream", "task_id": "swarm_down", "receipt_digest": digestHex(downstreamRecord)},
			"bad-step",
		},
	}, "close_signature")
	malformedCloseLog := &AuditLog{Path: "malformed-close-audit.log", Head: auditZeroHash}
	if err := malformedCloseLog.Append(map[string]any{"kind": "go_fed_receipt", "zone": zone, "worker": upstreamWorker, "zone_binding": fixture.zoneBindingForDescriptor(upstreamWorker), "receipt": upstreamReceipt}); err != nil {
		t.Fatal(err)
	}
	if err := malformedCloseLog.Append(map[string]any{"kind": "go_fed_receipt", "zone": zone, "worker": downstreamWorker, "zone_binding": fixture.zoneBindingForDescriptor(downstreamWorker), "receipt": downstreamRecord}); err != nil {
		t.Fatal(err)
	}
	if err := malformedCloseLog.Append(map[string]any{"kind": "go_swarm_close", "zone": zone, "close": malformedClose}); err != nil {
		t.Fatal(err)
	}
	err = verifyAuditFile("malformed-close-audit.log", "")
	if err == nil || !strings.Contains(err.Error(), "swarm close step receipt invalid") {
		t.Fatalf("got %v, want swarm close step receipt invalid", err)
	}

	duplicateCloseRecordLog := &AuditLog{Path: "duplicate-close-record-audit.log", Head: auditZeroHash}
	if err := duplicateCloseRecordLog.Append(map[string]any{"kind": "go_fed_receipt", "zone": zone, "worker": upstreamWorker, "zone_binding": fixture.zoneBindingForDescriptor(upstreamWorker), "receipt": upstreamReceipt}); err != nil {
		t.Fatal(err)
	}
	if err := duplicateCloseRecordLog.Append(map[string]any{"kind": "go_fed_receipt", "zone": zone, "worker": downstreamWorker, "zone_binding": fixture.zoneBindingForDescriptor(downstreamWorker), "receipt": downstreamRecord}); err != nil {
		t.Fatal(err)
	}
	if err := duplicateCloseRecordLog.Append(map[string]any{"kind": "go_swarm_close", "zone": zone, "close": cleanClose}); err != nil {
		t.Fatal(err)
	}
	if err := duplicateCloseRecordLog.Append(map[string]any{"kind": "go_swarm_close", "zone": zone, "close": cleanClose}); err != nil {
		t.Fatal(err)
	}
	err = verifyAuditFile("duplicate-close-record-audit.log", "")
	if err == nil || !strings.Contains(err.Error(), "duplicate swarm close proof") {
		t.Fatalf("got %v, want duplicate swarm close proof", err)
	}

	unknownSwarmClose := signBodyWithKey(zoneKey, map[string]any{
		"format":        "asp-swarm-close/v1",
		"swarm_id":      "swarm://unknown",
		"step_receipts": []map[string]any{},
	}, "close_signature")
	unknownSwarmCloseLog := &AuditLog{Path: "unknown-swarm-close-audit.log", Head: auditZeroHash}
	if err := unknownSwarmCloseLog.Append(map[string]any{"kind": "go_swarm_close", "zone": zone, "close": unknownSwarmClose}); err != nil {
		t.Fatal(err)
	}
	err = verifyAuditFile("unknown-swarm-close-audit.log", "")
	if err == nil || !strings.Contains(err.Error(), "swarm close proof without receipts") {
		t.Fatalf("got %v, want swarm close proof without receipts", err)
	}

	reversedClose := signBodyWithKey(zoneKey, map[string]any{
		"format":   "asp-swarm-close/v1",
		"swarm_id": "swarm://test",
		"step_receipts": []map[string]any{
			{"step_id": "downstream", "task_id": "swarm_down", "receipt_digest": digestHex(downstreamRecord)},
			{"step_id": "upstream", "task_id": "swarm_up", "receipt_digest": digestHex(upstreamReceipt)},
		},
	}, "close_signature")
	reversedCloseLog := &AuditLog{Path: "reversed-close-audit.log", Head: auditZeroHash}
	if err := reversedCloseLog.Append(map[string]any{"kind": "go_fed_receipt", "zone": zone, "worker": upstreamWorker, "zone_binding": fixture.zoneBindingForDescriptor(upstreamWorker), "receipt": upstreamReceipt}); err != nil {
		t.Fatal(err)
	}
	if err := reversedCloseLog.Append(map[string]any{"kind": "go_fed_receipt", "zone": zone, "worker": downstreamWorker, "zone_binding": fixture.zoneBindingForDescriptor(downstreamWorker), "receipt": downstreamRecord}); err != nil {
		t.Fatal(err)
	}
	if err := reversedCloseLog.Append(map[string]any{"kind": "go_swarm_close", "zone": zone, "close": reversedClose}); err != nil {
		t.Fatal(err)
	}
	err = verifyAuditFile("reversed-close-audit.log", "")
	if err == nil || !strings.Contains(err.Error(), "swarm close step order mismatch") {
		t.Fatalf("got %v, want swarm close step order mismatch", err)
	}

	incompleteClose := signBodyWithKey(zoneKey, map[string]any{
		"format":   "asp-swarm-close/v1",
		"swarm_id": "swarm://test",
		"step_receipts": []map[string]any{
			{"step_id": "upstream", "task_id": "swarm_up", "receipt_digest": digestHex(upstreamReceipt)},
		},
	}, "close_signature")
	incompleteCloseLog := &AuditLog{Path: "incomplete-close-audit.log", Head: auditZeroHash}
	if err := incompleteCloseLog.Append(map[string]any{"kind": "go_fed_receipt", "zone": zone, "worker": upstreamWorker, "zone_binding": fixture.zoneBindingForDescriptor(upstreamWorker), "receipt": upstreamReceipt}); err != nil {
		t.Fatal(err)
	}
	if err := incompleteCloseLog.Append(map[string]any{"kind": "go_fed_receipt", "zone": zone, "worker": downstreamWorker, "zone_binding": fixture.zoneBindingForDescriptor(downstreamWorker), "receipt": downstreamRecord}); err != nil {
		t.Fatal(err)
	}
	if err := incompleteCloseLog.Append(map[string]any{"kind": "go_swarm_close", "zone": zone, "close": incompleteClose}); err != nil {
		t.Fatal(err)
	}
	err = verifyAuditFile("incomplete-close-audit.log", "")
	if err == nil || !strings.Contains(err.Error(), "swarm close step count mismatch") {
		t.Fatalf("got %v, want swarm close step count mismatch", err)
	}

	duplicateClose := signBodyWithKey(zoneKey, map[string]any{
		"format":   "asp-swarm-close/v1",
		"swarm_id": "swarm://test",
		"step_receipts": []map[string]any{
			{"step_id": "upstream", "task_id": "swarm_up", "receipt_digest": digestHex(upstreamReceipt)},
			{"step_id": "upstream", "task_id": "swarm_up", "receipt_digest": digestHex(upstreamReceipt)},
		},
	}, "close_signature")
	duplicateCloseLog := &AuditLog{Path: "duplicate-close-audit.log", Head: auditZeroHash}
	if err := duplicateCloseLog.Append(map[string]any{"kind": "go_fed_receipt", "zone": zone, "worker": upstreamWorker, "zone_binding": fixture.zoneBindingForDescriptor(upstreamWorker), "receipt": upstreamReceipt}); err != nil {
		t.Fatal(err)
	}
	if err := duplicateCloseLog.Append(map[string]any{"kind": "go_swarm_close", "zone": zone, "close": duplicateClose}); err != nil {
		t.Fatal(err)
	}
	err = verifyAuditFile("duplicate-close-audit.log", "")
	if err == nil || !strings.Contains(err.Error(), "duplicate swarm close step receipt") {
		t.Fatalf("got %v, want duplicate swarm close step receipt", err)
	}

	badClose := signBodyWithKey(zoneKey, map[string]any{
		"format":   "asp-swarm-close/v1",
		"swarm_id": "swarm://test",
		"step_receipts": []map[string]any{
			{"step_id": "upstream", "task_id": "swarm_up", "receipt_digest": strings.Repeat("2", 64)},
		},
	}, "close_signature")
	badCloseLog := &AuditLog{Path: "bad-close-audit.log", Head: auditZeroHash}
	if err := badCloseLog.Append(map[string]any{"kind": "go_fed_receipt", "zone": zone, "worker": upstreamWorker, "zone_binding": fixture.zoneBindingForDescriptor(upstreamWorker), "receipt": upstreamReceipt}); err != nil {
		t.Fatal(err)
	}
	if err := badCloseLog.Append(map[string]any{"kind": "go_swarm_close", "zone": zone, "close": badClose}); err != nil {
		t.Fatal(err)
	}
	err = verifyAuditFile("bad-close-audit.log", "")
	if err == nil || !strings.Contains(err.Error(), "swarm close receipt digest mismatch") {
		t.Fatalf("got %v, want swarm close receipt digest mismatch", err)
	}
}

func TestPublicListenHostFlag(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1": false,
		"::1":       false,
		"localhost": false,
		"LOCALHOST": false,
		"0.0.0.0":   false,
		"::":        false,
		"fed.local": true,
	}
	for host, want := range cases {
		if got := isPublicListenHost(host); got != want {
			t.Fatalf("isPublicListenHost(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestVerifyApprovalGrantsRejectsMalformedLists(t *testing.T) {
	zonePub, zoneKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	grant := signBodyWithKey(zoneKey, map[string]any{"task_id": "approval_shape"}, "approval_signature")
	err = verifyApprovalGrants(zonePub, map[string]any{
		"task_id":         "approval_shape",
		"approvals":       []any{"approval://ok", map[string]any{"approval": "ghost"}},
		"approval_grants": []map[string]any{grant},
	})
	if err == nil || !strings.Contains(err.Error(), "receipt approval invalid") {
		t.Fatalf("got %v, want receipt approval invalid", err)
	}
	err = verifyApprovalGrants(zonePub, map[string]any{
		"task_id":   "approval_shape",
		"approvals": []string{"approval://ok"},
		"approval_grants": []any{
			grant,
			"bad-grant",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "approval grant invalid") {
		t.Fatalf("got %v, want approval grant invalid", err)
	}
}

func TestVerifyCheckpointsRejectsMalformedLists(t *testing.T) {
	workerPub, workerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := signBodyWithKey(workerKey, map[string]any{
		"task_id":           "checkpoint_shape",
		"checkpoint_id":     "checkpoint://ok",
		"parent_checkpoint": nil,
	}, "checkpoint_signature")
	err = verifyCheckpoints(workerPub, map[string]any{
		"task_id":         "checkpoint_shape",
		"checkpoint_refs": []any{"checkpoint://ok", map[string]any{"checkpoint_id": "ghost"}},
		"checkpoints":     []map[string]any{checkpoint},
	})
	if err == nil || !strings.Contains(err.Error(), "checkpoint ref invalid") {
		t.Fatalf("got %v, want checkpoint ref invalid", err)
	}
	err = verifyCheckpoints(workerPub, map[string]any{
		"task_id":         "checkpoint_shape",
		"checkpoint_refs": []string{"checkpoint://ok"},
		"checkpoints": []any{
			checkpoint,
			"bad-checkpoint",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "checkpoint invalid") {
		t.Fatalf("got %v, want checkpoint invalid", err)
	}
}

func TestVerifyPolicyScopeRejectsMalformedLists(t *testing.T) {
	for _, field := range []string{"write", "tools", "data_domains", "approval_required"} {
		t.Run(field, func(t *testing.T) {
			scope := map[string]any{
				"network":           false,
				"write":             []string{},
				"tools":             []string{},
				"data_domains":      []string{},
				"approval_required": []string{},
				"expires_at":        "",
			}
			scope[field] = []any{"ok", map[string]any{"bad": field}}
			err := verifyPolicyScope(map[string]any{
				"policy_scope":  scope,
				"policy_digest": digestHex(scope),
			})
			want := "policy scope " + field + " invalid"
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("got %v, want %s", err, want)
			}
		})
	}
}

func TestVerifyPolicyScopeRejectsMalformedScalars(t *testing.T) {
	cases := []struct {
		field string
		value any
	}{
		{field: "network", value: "false"},
		{field: "expires_at", value: map[string]any{"at": "2026-07-07T00:00:00Z"}},
	}
	for _, tc := range cases {
		t.Run(tc.field, func(t *testing.T) {
			scope := map[string]any{
				"network":           false,
				"write":             []string{},
				"tools":             []string{},
				"data_domains":      []string{},
				"approval_required": []string{},
				"expires_at":        "",
			}
			scope[tc.field] = tc.value
			err := verifyPolicyScope(map[string]any{
				"policy_scope":  scope,
				"policy_digest": digestHex(scope),
			})
			want := "policy scope " + tc.field + " invalid"
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("got %v, want %s", err, want)
			}
		})
	}
}

func TestVerifyReceiptRecordRejectsUnsafeTaskID(t *testing.T) {
	zone, zoneKey := testZoneDescriptor(t, "zone://receipt-task-id-shape")
	_, workerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := workerDescriptor(WorkerProfile{
		Alias:        "agent://receipt-task-id-shape/worker",
		Transports:   []string{"go-test"},
		Capabilities: []string{"test"},
		Policy:       map[string]any{"network": false},
	}, workerKey)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := writeArtifact("artifact://local/receipt_task_id_shape/out.md", "# Task ID\n", "")
	if err != nil {
		t.Fatal(err)
	}
	fixture := Fixture{Authority: zone, AuthorityPrivateKey: zoneKey}
	receipt := testSignedReceipt(t, zone, zoneKey, worker, workerKey, "../bad/task", []map[string]any{manifest}, nil)
	err = verifyReceiptRecord(map[string]any{
		"kind":         "go_fed_receipt",
		"zone":         zone,
		"worker":       worker,
		"zone_binding": fixture.zoneBindingForDescriptor(worker),
		"receipt":      receipt,
	}, "")
	if err == nil || !strings.Contains(err.Error(), "task_id invalid") {
		t.Fatalf("got %v, want task_id invalid", err)
	}
}

func TestCheckpointByIDRejectsMalformedReceiptCheckpointLists(t *testing.T) {
	zone, zoneKey := testZoneDescriptor(t, "zone://checkpoint-lookup-shape")
	_, workerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := workerDescriptor(WorkerProfile{
		Alias:        "agent://checkpoint-lookup-shape/worker",
		Transports:   []string{"go-test"},
		Capabilities: []string{"test"},
		Policy:       map[string]any{"network": false},
	}, workerKey)
	if err != nil {
		t.Fatal(err)
	}
	manifest := map[string]any{
		"uri":           "artifact://local/checkpoint_lookup_shape/out.txt",
		"sha256":        strings.Repeat("1", 64),
		"size":          float64(1),
		"media_type":    "text/plain",
		"afp":           "afp:sha256:" + strings.Repeat("1", 64),
		"manifest_hash": "",
	}
	manifestBody := map[string]any{}
	for key, value := range manifest {
		if key != "manifest_hash" {
			manifestBody[key] = value
		}
	}
	manifest["manifest_hash"] = digestHex(manifestBody)
	checkpoint := signBodyWithKey(workerKey, map[string]any{
		"task_id":           "checkpoint_lookup_shape",
		"checkpoint_id":     "checkpoint://ok",
		"parent_checkpoint": nil,
	}, "checkpoint_signature")
	cases := []struct {
		name    string
		extra   map[string]any
		wantErr string
	}{
		{
			name: "bad refs",
			extra: map[string]any{
				"checkpoint_refs": []any{"checkpoint://ok", map[string]any{"checkpoint_id": "ghost"}},
				"checkpoints":     []map[string]any{checkpoint},
			},
			wantErr: "checkpoint ref invalid",
		},
		{
			name: "bad checkpoints",
			extra: map[string]any{
				"checkpoint_refs": []string{"checkpoint://ok"},
				"checkpoints":     []any{checkpoint, "bad-checkpoint"},
			},
			wantErr: "checkpoint invalid",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			audit := &AuditLog{Path: filepath.Join(t.TempDir(), "audit.log"), Head: auditZeroHash}
			receipt := testSignedReceipt(t, zone, zoneKey, worker, workerKey, "checkpoint_lookup_shape", []map[string]any{manifest}, tc.extra)
			if err := audit.Append(map[string]any{"kind": "go_fed_receipt", "receipt": receipt}); err != nil {
				t.Fatal(err)
			}
			_, err = (Fixture{Audit: audit}).checkpointByID("checkpoint://ok")
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("got %v, want %s", err, tc.wantErr)
			}
		})
	}
}

func testSignedReceipt(t *testing.T, zone map[string]any, zoneKey ed25519.PrivateKey, worker map[string]any, workerKey ed25519.PrivateKey, taskID string, manifests []map[string]any, extra map[string]any) map[string]any {
	t.Helper()
	refs := make([]string, 0, len(manifests))
	for _, manifest := range manifests {
		refs = append(refs, fmt.Sprint(manifest["uri"]))
	}
	policyScope := map[string]any{
		"network":           false,
		"write":             []string{},
		"tools":             []string{},
		"data_domains":      []string{},
		"approval_required": []string{},
		"expires_at":        "",
	}
	sandbox := map[string]any{"mode": "in-process", "isolation_level": "in-process"}
	policyDigest := digestHex(policyScope)
	proof := signBodyWithKey(zoneKey, map[string]any{
		"proof_type":    "local.sandbox.v1",
		"task_id":       taskID,
		"authority":     zone["zid"],
		"worker":        worker["aid"],
		"sandbox":       sandbox,
		"policy_digest": policyDigest,
	}, "sandbox_signature")
	body := map[string]any{
		"task_id":            taskID,
		"task_digest":        digestHex(map[string]any{"task_id": taskID}),
		"from":               "aid:ed25519:test-requester",
		"origin_zone":        zone["zid"],
		"executing_zone":     zone["zid"],
		"to":                 worker["aid"],
		"artifact_refs":      refs,
		"artifact_manifests": manifests,
		"result_artifact":    map[string]any{"uri": manifests[0]["uri"], "sha256": manifests[0]["sha256"], "manifest_hash": manifests[0]["manifest_hash"]},
		"tool_output_digest": manifests[0]["sha256"],
		"event_count":        float64(1),
		"approvals":          []string{},
		"approval_grants":    []map[string]any{},
		"checkpoint_refs":    []string{},
		"checkpoints":        []map[string]any{},
		"policy_scope":       policyScope,
		"policy_digest":      policyDigest,
		"sandbox":            sandbox,
		"sandbox_proof":      proof,
		"tool":               "test",
	}
	for key, value := range extra {
		body[key] = value
	}
	return signBody(workerKey, body)
}

func receiptBodyWithoutSignature(receipt map[string]any) map[string]any {
	body := map[string]any{}
	for key, value := range receipt {
		if key != "signature" {
			body[key] = value
		}
	}
	return body
}

func TestVerifyReceiptFileRejectsMismatchedTaskEvidence(t *testing.T) {
	zone, zoneKey := testZoneDescriptor(t, "zone://go-verify-receipt")
	_, workerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := workerDescriptor(WorkerProfile{
		Alias:        "agent://go-verify-receipt/worker",
		Transports:   []string{"go-test"},
		Capabilities: []string{"test"},
		Policy:       map[string]any{"network": false},
	}, workerKey)
	if err != nil {
		t.Fatal(err)
	}
	manifest := map[string]any{
		"uri":           "artifact://local/go_verify_receipt_task/out.txt",
		"sha256":        strings.Repeat("1", 64),
		"size":          float64(1),
		"media_type":    "text/plain",
		"afp":           "afp:sha256:" + strings.Repeat("1", 64),
		"manifest_hash": "",
	}
	manifestBody := map[string]any{}
	for key, value := range manifest {
		if key != "manifest_hash" {
			manifestBody[key] = value
		}
	}
	manifest["manifest_hash"] = digestHex(manifestBody)
	record := map[string]any{
		"zone":         zone,
		"worker":       worker,
		"zone_binding": signBodyWithKey(zoneKey, map[string]any{"zone": zone["zid"], "alias": worker["alias"], "aid": worker["aid"]}, "signature"),
		"receipt":      testSignedReceipt(t, zone, zoneKey, worker, workerKey, "go_verify_receipt_task", []map[string]any{manifest}, map[string]any{}),
	}
	dir := t.TempDir()
	receiptPath := filepath.Join(dir, "receipt.json")
	taskPath := filepath.Join(dir, "wrong-task.json")
	if err := writeJSONStateFile(receiptPath, record); err != nil {
		t.Fatal(err)
	}
	if err := writeJSONStateFile(taskPath, map[string]any{"task_id": "go_verify_receipt_task", "intent": "wrong task"}); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyReceiptFile(receiptPath, "", taskPath); err == nil || !strings.Contains(err.Error(), "receipt task_digest mismatch") {
		t.Fatalf("got %v, want receipt task_digest mismatch", err)
	}
}

func TestVerifyInteropReceiptRejectsMismatchedTaskEvidence(t *testing.T) {
	zone, zoneKey := testZoneDescriptor(t, "zone://go-interop-receipt")
	_, workerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := workerDescriptor(WorkerProfile{
		Alias:        "agent://go-interop-receipt/worker",
		Transports:   []string{"go-test"},
		Capabilities: []string{"test"},
		Policy:       map[string]any{"network": false},
	}, workerKey)
	if err != nil {
		t.Fatal(err)
	}
	manifest := map[string]any{
		"uri":           "artifact://local/go_interop_receipt_task/out.txt",
		"sha256":        strings.Repeat("2", 64),
		"size":          float64(1),
		"media_type":    "text/plain",
		"afp":           "afp:sha256:" + strings.Repeat("2", 64),
		"manifest_hash": "",
	}
	manifestBody := map[string]any{}
	for key, value := range manifest {
		if key != "manifest_hash" {
			manifestBody[key] = value
		}
	}
	manifest["manifest_hash"] = digestHex(manifestBody)
	frame := map[string]any{
		"type":         "FED_RECEIPT",
		"zone":         zone,
		"worker":       worker,
		"zone_binding": signBodyWithKey(zoneKey, map[string]any{"zone": zone["zid"], "alias": worker["alias"], "aid": worker["aid"]}, "signature"),
		"receipt":      testSignedReceipt(t, zone, zoneKey, worker, workerKey, "go_interop_receipt_task", []map[string]any{manifest}, map[string]any{}),
	}
	trusted := map[string]map[string]any{fmt.Sprint(zone["zid"]): zone}
	if err := verifyInteropReceipt(frame, trusted, map[string]any{"task_id": "go_interop_receipt_task", "intent": "wrong task"}); err == nil || !strings.Contains(err.Error(), "receipt task_digest mismatch") {
		t.Fatalf("got %v, want receipt task_digest mismatch", err)
	}
}

func TestFederationListenerCanRequireClientCertificate(t *testing.T) {
	serverCertPath, serverKeyPath, caPath, clientCert := writeTestMTLSCertificates(t)
	listener, transport, err := listenFederation("127.0.0.1", "0", serverCertPath, serverKeyPath, caPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if transport != "fed+mtls" {
		t.Fatalf("transport = %s, want fed+mtls", transport)
	}

	rejected := acceptOneByte(listener)
	conn, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err == nil {
		_, _ = conn.Write([]byte{1})
		conn.Close()
	}
	if err := <-rejected; err == nil {
		t.Fatal("server accepted client without certificate")
	}

	accepted := acceptOneByte(listener)
	conn, err = tls.Dial("tcp", listener.Addr().String(), &tls.Config{InsecureSkipVerify: true, Certificates: []tls.Certificate{clientCert}})
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

func TestFederationMTLSClientCertificateMustMatchHelloZone(t *testing.T) {
	clientZone, _ := testZoneDescriptor(t, "client-zone")
	claimedZone, _ := testZoneDescriptor(t, "claimed-zone")
	serverZone, _ := testZoneDescriptor(t, "server-zone")
	serverCertPath, serverKeyPath, caPath, clientCert := writeTestMTLSCertificatesForClientZone(t, fmt.Sprint(clientZone["zid"]))
	mismatched := exchangeTestMTLSHello(t, serverCertPath, serverKeyPath, caPath, clientCert, serverZone, map[string]map[string]any{
		fmt.Sprint(claimedZone["zid"]): claimedZone,
	}, claimedZone)
	if mismatched["type"] != "FED_TASK_ERROR" {
		t.Fatalf("got %v, want FED_TASK_ERROR", mismatched["type"])
	}
	if !strings.Contains(fmt.Sprint(mismatched["error"]), "mTLS client certificate zone mismatch") {
		t.Fatalf("got error %q, want mTLS client certificate zone mismatch", mismatched["error"])
	}

	matched := exchangeTestMTLSHello(t, serverCertPath, serverKeyPath, caPath, clientCert, serverZone, map[string]map[string]any{
		fmt.Sprint(clientZone["zid"]): clientZone,
	}, clientZone)
	if matched["type"] != "HELLO" {
		t.Fatalf("got %v, want HELLO", matched["type"])
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
	certPath, keyPath, _, _ := writeTestMTLSCertificates(t)
	return certPath, keyPath
}

func writeTestMTLSCertificates(t *testing.T) (string, string, string, tls.Certificate) {
	return writeTestMTLSCertificatesForClientZone(t, "")
}

func writeTestMTLSCertificatesForClientZone(t *testing.T, clientZone string) (string, string, string, tls.Certificate) {
	t.Helper()
	dir := t.TempDir()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	serverCertPath, serverKeyPath := writeSignedTestCertificate(t, dir, "server", caCert, caKey, x509.ExtKeyUsageServerAuth, "")
	clientCertPath, clientKeyPath := writeSignedTestCertificate(t, dir, "client", caCert, caKey, x509.ExtKeyUsageClientAuth, clientZone)
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o644); err != nil {
		t.Fatal(err)
	}
	clientCert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	return serverCertPath, serverKeyPath, caPath, clientCert
}

func writeSignedTestCertificate(t *testing.T, dir, name string, caCert *x509.Certificate, caKey *rsa.PrivateKey, usage x509.ExtKeyUsage, zoneURI string) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
	}
	if zoneURI != "" {
		uri, err := url.Parse(zoneURI)
		if err != nil {
			t.Fatal(err)
		}
		template.URIs = []*url.URL{uri}
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, name+".pem")
	keyPath := filepath.Join(dir, name+"-key.pem")
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

func acceptOneByte(listener net.Listener) chan error {
	out := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			out <- err
			return
		}
		defer conn.Close()
		buf := []byte{0}
		_, err = conn.Read(buf)
		out <- err
	}()
	return out
}

func exchangeTestMTLSHello(t *testing.T, serverCertPath, serverKeyPath, caPath string, clientCert tls.Certificate, serverZone map[string]any, trusted map[string]map[string]any, claimedZone map[string]any) map[string]any {
	t.Helper()
	listener, _, err := listenFederation("127.0.0.1", "0", serverCertPath, serverKeyPath, caPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			handle(conn, Fixture{Authority: serverZone}, trusted)
		}
	}()
	conn, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{InsecureSkipVerify: true, Certificates: []tls.Certificate{clientCert}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := fmt.Fprintf(conn, "%s\n", mustJSON(t, map[string]any{"type": "HELLO", "origin_zone": claimedZone})); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	var frame map[string]any
	if err := json.Unmarshal(line, &frame); err != nil {
		t.Fatal(err)
	}
	return frame
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
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

func TestExecuteSwarmRejectsWorkerCapabilitySubstitution(t *testing.T) {
	t.Chdir(t.TempDir())
	origin, originKey := testZoneDescriptor(t, "zone://u2-origin")
	authority, authorityKey := testZoneDescriptor(t, "zone://u2-authority")
	_, requesterKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	requester, err := workerDescriptor(WorkerProfile{
		Alias:        "agent://u2/requester",
		Transports:   []string{"go-test"},
		Capabilities: []string{"request.task"},
		Policy:       map[string]any{},
	}, requesterKey)
	if err != nil {
		t.Fatal(err)
	}
	_, originalKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	originalProfile := WorkerProfile{
		Alias:        "agent://u2/original",
		Tool:         "external.stdio",
		ToolCommand:  []string{"/usr/bin/false"},
		Transports:   []string{"go-test"},
		Capabilities: []string{"summarize.text", "migration.shared"},
		Policy:       map[string]any{"allow_network": false},
	}
	originalDescriptor, err := workerDescriptor(originalProfile, originalKey)
	if err != nil {
		t.Fatal(err)
	}
	_, replacementKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	replacementProfile := WorkerProfile{
		Alias:        "agent://u2/replacement",
		Tool:         "summarize.mock",
		Transports:   []string{"go-test"},
		Capabilities: []string{"translate.text", "migration.shared"},
		Policy:       map[string]any{"allow_network": false},
	}
	replacementDescriptor, err := workerDescriptor(replacementProfile, replacementKey)
	if err != nil {
		t.Fatal(err)
	}

	swarmID := "swarm://local/go-u2-capability-substitution"
	planSteps := []any{map[string]any{"step_id": "summary", "capability": "summarize.text", "depends_on": []any{}}}
	planDigest := digestHex(map[string]any{"intent": "Reject migration capability substitution.", "steps": planSteps})
	planBody := map[string]any{
		"swarm_id":      swarmID,
		"intent":        "Reject migration capability substitution.",
		"steps":         planSteps,
		"policy_digest": strings.Repeat("a", 64),
		"plan_digest":   planDigest,
	}
	plan := map[string]any{"type": "FED_SWARM_PLAN", "zone": origin, "plan": signBodyWithKey(originKey, planBody, "plan_signature")}
	taskBody := map[string]any{
		"task_id": "go_u2_capability_substitution",
		"from":    requester["aid"],
		"to":      originalDescriptor["alias"],
		"intent":  "Force the original worker to fail.",
		"scope":   map[string]any{"network": false},
		"budget":  map[string]any{"time_seconds": float64(30)},
	}
	signedTask := signBody(requesterKey, taskBody)
	bindingSteps := []any{map[string]any{
		"step_id":     "summary",
		"depends_on":  []any{},
		"capability":  "summarize.text",
		"task_digest": digestHex(signedTask),
	}}
	bindingBody := map[string]any{
		"format":                 "asp-swarm-execution-binding/v1",
		"swarm_id":               swarmID,
		"plan_digest":            planDigest,
		"steps":                  bindingSteps,
		"execution_graph_digest": digestHex(map[string]any{"swarm_id": swarmID, "plan_digest": planDigest, "steps": bindingSteps}),
	}
	executionBinding := signBodyWithKey(originKey, bindingBody, "binding_signature")
	requesterBinding := signBodyWithKey(originKey, map[string]any{
		"zone":  origin["zid"],
		"alias": requester["alias"],
		"aid":   requester["aid"],
	}, "signature")
	frame := map[string]any{
		"type":                   "FED_SWARM_OPEN",
		"origin_zone":            origin,
		"requester":              requester,
		"requester_zone_binding": requesterBinding,
		"swarm": map[string]any{
			"swarm_id":          swarmID,
			"plan":              plan,
			"execution_binding": executionBinding,
			"steps": []any{map[string]any{
				"step_id": "summary",
				"task":    signedTask,
			}},
		},
	}
	fixture := Fixture{
		Authority:           authority,
		AuthorityPrivateKey: authorityKey,
		Workers: []Worker{
			{Profile: originalProfile, Descriptor: originalDescriptor, PrivateKey: originalKey},
			{Profile: replacementProfile, Descriptor: replacementDescriptor, PrivateKey: replacementKey},
		},
		Runtime: &TaskRuntime{running: map[string]context.CancelFunc{}, cancelled: map[string]bool{}},
	}
	emitted := []map[string]any{}
	err = fixture.executeSwarm(func(frame map[string]any) { emitted = append(emitted, frame) }, origin, frame)
	if err == nil || !strings.Contains(err.Error(), "execution binding migration worker capability missing: summary") {
		t.Fatalf("got %v, want execution binding migration worker capability missing: summary", err)
	}
	if len(emitted) != 0 {
		t.Fatalf("emitted %d side effects before capability rejection: %#v", len(emitted), emitted)
	}

	policyOriginalProfile := originalProfile
	policyOriginalProfile.Alias = "agent://u2/policy-original"
	policyOriginalProfile.Policy = map[string]any{"allow_network": false}
	policyOriginalDescriptor, err := workerDescriptor(policyOriginalProfile, originalKey)
	if err != nil {
		t.Fatal(err)
	}
	policyReplacementProfile := replacementProfile
	policyReplacementProfile.Alias = "agent://u2/policy-replacement"
	policyReplacementProfile.Capabilities = []string{"summarize.text", "migration.shared"}
	policyReplacementProfile.Policy = map[string]any{"allow_network": true}
	policyReplacementDescriptor, err := workerDescriptor(policyReplacementProfile, replacementKey)
	if err != nil {
		t.Fatal(err)
	}
	policySwarmID := "swarm://local/go-u2-policy-migration"
	policyPlanDigest := digestHex(map[string]any{"intent": "Migrate a policy-denied task to an exact-capability worker.", "steps": planSteps})
	policyPlanBody := map[string]any{
		"swarm_id":      policySwarmID,
		"intent":        "Migrate a policy-denied task to an exact-capability worker.",
		"steps":         planSteps,
		"policy_digest": strings.Repeat("b", 64),
		"plan_digest":   policyPlanDigest,
	}
	policyPlan := map[string]any{"type": "FED_SWARM_PLAN", "zone": origin, "plan": signBodyWithKey(originKey, policyPlanBody, "plan_signature")}
	policyTaskBody := map[string]any{
		"task_id": "go_u2_policy_migration",
		"from":    requester["aid"],
		"to":      policyOriginalDescriptor["alias"],
		"intent":  "Migrate without executing the policy-denied original worker.",
		"scope":   map[string]any{"network": true},
		"budget":  map[string]any{"time_seconds": float64(30)},
	}
	policySignedTask := signBody(requesterKey, policyTaskBody)
	policyBindingSteps := []any{map[string]any{
		"step_id":     "summary",
		"depends_on":  []any{},
		"capability":  "summarize.text",
		"task_digest": digestHex(policySignedTask),
	}}
	policyBindingBody := map[string]any{
		"format":                 "asp-swarm-execution-binding/v1",
		"swarm_id":               policySwarmID,
		"plan_digest":            policyPlanDigest,
		"steps":                  policyBindingSteps,
		"execution_graph_digest": digestHex(map[string]any{"swarm_id": policySwarmID, "plan_digest": policyPlanDigest, "steps": policyBindingSteps}),
	}
	policyFrame := map[string]any{
		"type":                   "FED_SWARM_OPEN",
		"origin_zone":            origin,
		"requester":              requester,
		"requester_zone_binding": requesterBinding,
		"swarm": map[string]any{
			"swarm_id":          policySwarmID,
			"plan":              policyPlan,
			"execution_binding": signBodyWithKey(originKey, policyBindingBody, "binding_signature"),
			"steps": []any{map[string]any{
				"step_id": "summary",
				"task":    policySignedTask,
			}},
		},
	}
	managedKeyDir := t.TempDir()
	authoritySeed := authorityKey.Seed()
	authorityStore := writeManagedRuntimeStore(t, managedKeyDir, "policy-authority", authority, authoritySeed, managedkey.IdentityZID, managedkey.KeyTypeSeed)
	clear(authoritySeed)
	originalSeed := originalKey.Seed()
	originalStore := writeManagedRuntimeStore(t, managedKeyDir, "policy-original", policyOriginalDescriptor, originalSeed, managedkey.IdentityAID, managedkey.KeyTypeSeed)
	clear(originalSeed)
	replacementSeed := replacementKey.Seed()
	replacementStore := writeManagedRuntimeStore(t, managedKeyDir, "policy-replacement", policyReplacementDescriptor, replacementSeed, managedkey.IdentityAID, managedkey.KeyTypeSeed)
	clear(replacementSeed)

	managedAuthority, err := loadManagedIdentity(authorityStore, managedkey.IdentityZID)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(managedAuthority.PrivateKey)
	managedOriginal, err := loadManagedIdentity(originalStore, managedkey.IdentityAID)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(managedOriginal.PrivateKey)
	managedReplacement, err := loadManagedIdentity(replacementStore, managedkey.IdentityAID)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(managedReplacement.PrivateKey)

	policyFixture := Fixture{
		Authority:           authority,
		AuthorityPrivateKey: managedAuthority.PrivateKey,
		AuthorityGeneration: managedAuthority.KeyGeneration,
		AuthorityGenerationPin: WorkerGenerationPin{
			StorePath:      authorityStore.StorePath,
			PassphraseFile: authorityStore.PassphraseFile,
			RecordDigest:   managedAuthority.KeyGeneration.RecordDigest,
		},
		Workers: []Worker{
			{
				Profile:       policyOriginalProfile,
				Descriptor:    policyOriginalDescriptor,
				PrivateKey:    managedOriginal.PrivateKey,
				GenerationRef: managedOriginal.KeyGeneration,
				WorkerGenerationPin: WorkerGenerationPin{
					StorePath:      originalStore.StorePath,
					PassphraseFile: originalStore.PassphraseFile,
					RecordDigest:   managedOriginal.KeyGeneration.RecordDigest,
				},
			},
			{
				Profile:       policyReplacementProfile,
				Descriptor:    policyReplacementDescriptor,
				PrivateKey:    managedReplacement.PrivateKey,
				GenerationRef: managedReplacement.KeyGeneration,
				WorkerGenerationPin: WorkerGenerationPin{
					StorePath:      replacementStore.StorePath,
					PassphraseFile: replacementStore.PassphraseFile,
					RecordDigest:   managedReplacement.KeyGeneration.RecordDigest,
				},
			},
		},
		Runtime: &TaskRuntime{running: map[string]context.CancelFunc{}, cancelled: map[string]bool{}},
	}
	ordinaryPolicyFrame := map[string]any{
		"type":                   "FED_TASK_OPEN",
		"origin_zone":            origin,
		"requester":              requester,
		"requester_zone_binding": requesterBinding,
		"task":                   policySignedTask,
	}
	if _, _, err := policyFixture.verifyTaskOpen(ordinaryPolicyFrame); err == nil || !strings.Contains(err.Error(), "policy denied network access") {
		t.Fatalf("ordinary FED_TASK_OPEN got %v, want policy denied network access", err)
	}

	t.Run("tampered binding precedes original policy", func(t *testing.T) {
		binding := policyFrame["swarm"].(map[string]any)["execution_binding"].(map[string]any)
		signature := binding["binding_signature"]
		binding["binding_signature"] = "bad"
		defer func() { binding["binding_signature"] = signature }()
		emitted := []map[string]any{}
		err := policyFixture.executeSwarm(func(frame map[string]any) { emitted = append(emitted, frame) }, origin, policyFrame)
		if err == nil || !strings.Contains(err.Error(), "execution binding signature verification failed") {
			t.Fatalf("got %v, want execution binding signature verification failed", err)
		}
		if len(emitted) != 0 {
			t.Fatalf("emitted %d side effects before binding rejection: %#v", len(emitted), emitted)
		}
	})

	t.Run("policy denial migrates to exact-capability replacement", func(t *testing.T) {
		emitted := []map[string]any{}
		if err := policyFixture.executeSwarm(func(frame map[string]any) { emitted = append(emitted, frame) }, origin, policyFrame); err != nil {
			t.Fatal(err)
		}
		for _, frame := range emitted {
			event, _ := frame["event"].(map[string]any)
			if event["by"] == policyOriginalDescriptor["aid"] {
				t.Fatalf("policy-denied original worker emitted event: %#v", frame)
			}
			worker, _ := event["worker"].(map[string]any)
			if worker["aid"] == policyOriginalDescriptor["aid"] {
				t.Fatalf("policy-denied original worker emitted micro-contract: %#v", frame)
			}
		}
		closeFrame := emitted[len(emitted)-1]
		if closeFrame["type"] != "FED_SWARM_CLOSE" {
			t.Fatalf("last frame = %#v, want FED_SWARM_CLOSE", closeFrame)
		}
		closeBody := closeFrame["close"].(map[string]any)
		migration := mapsFromAny(closeBody["migration_log"])[0]
		if migration["reason"] != "policy denied network access" {
			t.Fatalf("migration reason = %v, want policy denied network access", migration["reason"])
		}
		if migration["original_worker_aid"] != policyOriginalDescriptor["aid"] || migration["migrated_to_worker_aid"] != policyReplacementDescriptor["aid"] {
			t.Fatalf("migration worker binding = %#v", migration)
		}
	})
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

func TestVerifyAuditV2FinalOutput(t *testing.T) {
	t.Chdir(t.TempDir())
	zone, zoneKey := testZoneDescriptor(t, "zone://u3-audit")
	_, upstreamKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, finalKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	upstreamWorker, err := agentDescriptor(upstreamKey, "agent://u3-audit/upstream")
	if err != nil {
		t.Fatal(err)
	}
	finalWorker, err := agentDescriptor(finalKey, "agent://u3-audit/final")
	if err != nil {
		t.Fatal(err)
	}
	fixture := Fixture{Authority: zone, AuthorityPrivateKey: zoneKey}
	upstreamManifest, err := writeArtifact("artifact://local/u3-audit/upstream.txt", "upstream\n", "")
	if err != nil {
		t.Fatal(err)
	}
	finalManifest, err := writeArtifact("artifact://local/u3-audit/final.txt", "final\n", "")
	if err != nil {
		t.Fatal(err)
	}
	resultPointer := func(manifest map[string]any) map[string]any {
		return map[string]any{"uri": manifest["uri"], "sha256": manifest["sha256"], "manifest_hash": manifest["manifest_hash"]}
	}
	swarmID := "swarm://u3-audit/final-output"
	planDigest := strings.Repeat("a", 64)
	upstreamTaskDigest := digestHex(map[string]any{"task_id": "u3_audit_upstream"})
	finalTaskDigest := digestHex(map[string]any{"task_id": "u3_audit_final"})
	bindingSteps := []map[string]any{
		{"step_id": "final", "depends_on": []string{"upstream"}, "capability": "summarize.text", "task_digest": finalTaskDigest},
		{"step_id": "upstream", "depends_on": []string{}, "capability": "summarize.text", "task_digest": upstreamTaskDigest},
	}
	graphDigest := digestHex(map[string]any{"swarm_id": swarmID, "plan_digest": planDigest, "steps": bindingSteps})
	upstreamReceipt := testSignedReceipt(t, zone, zoneKey, upstreamWorker, upstreamKey, "u3_audit_upstream", []map[string]any{upstreamManifest}, map[string]any{
		"result_artifact": resultPointer(upstreamManifest),
		"swarm": map[string]any{
			"swarm_id":               swarmID,
			"step_id":                "upstream",
			"after":                  []string{},
			"input_artifacts":        []map[string]any{},
			"plan_digest":            planDigest,
			"execution_graph_digest": graphDigest,
			"capability":             "summarize.text",
			"task_digest":            upstreamTaskDigest,
		},
	})
	upstreamSignedDigest := digestHex(upstreamReceipt)
	finalReceipt := testSignedReceipt(t, zone, zoneKey, finalWorker, finalKey, "u3_audit_final", []map[string]any{finalManifest}, map[string]any{
		"result_artifact": resultPointer(finalManifest),
		"swarm": map[string]any{
			"swarm_id": swarmID,
			"step_id":  "final",
			"after":    []string{"upstream"},
			"input_artifacts": []map[string]any{{
				"step_id":               "upstream",
				"uri":                   upstreamManifest["uri"],
				"sha256":                upstreamManifest["sha256"],
				"manifest_hash":         upstreamManifest["manifest_hash"],
				"signed_receipt_digest": upstreamSignedDigest,
			}},
			"plan_digest":            planDigest,
			"execution_graph_digest": graphDigest,
			"capability":             "summarize.text",
			"task_digest":            finalTaskDigest,
		},
	})
	finalSignedDigest := digestHex(finalReceipt)
	finalOutput := map[string]any{
		"step_id":               "final",
		"task_id":               "u3_audit_final",
		"signed_receipt_digest": finalSignedDigest,
		"artifact":              resultPointer(finalManifest),
		"selection_rule":        "single-terminal-result",
	}
	closeBody := map[string]any{
		"format":                 "asp-swarm-close/v2",
		"swarm_id":               swarmID,
		"plan_digest":            planDigest,
		"execution_graph_digest": graphDigest,
		"step_receipts": []map[string]any{
			{"step_id": "final", "task_id": "u3_audit_final", "signed_receipt_digest": finalSignedDigest},
			{"step_id": "upstream", "task_id": "u3_audit_upstream", "signed_receipt_digest": upstreamSignedDigest},
		},
		"final_output": finalOutput,
		"scheduler":    map[string]any{"mode": "ready-dag", "step_order": []string{"upstream", "final"}},
	}
	baseClose := signBodyWithKey(zoneKey, closeBody, "close_signature")
	clone := func(value map[string]any) map[string]any {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]any
		if err := json.Unmarshal(data, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	resign := func(mutate func(map[string]any)) map[string]any {
		body := clone(baseClose)
		delete(body, "close_signature")
		mutate(body)
		return signBodyWithKey(zoneKey, body, "close_signature")
	}
	verifyClose := func(name string, close map[string]any) error {
		log := &AuditLog{Path: name + ".log", Head: auditZeroHash}
		for _, record := range []map[string]any{
			{"kind": "go_fed_receipt", "zone": zone, "worker": upstreamWorker, "zone_binding": fixture.zoneBindingForDescriptor(upstreamWorker), "receipt": upstreamReceipt},
			{"kind": "go_fed_receipt", "zone": zone, "worker": finalWorker, "zone_binding": fixture.zoneBindingForDescriptor(finalWorker), "receipt": finalReceipt},
			{"kind": "go_swarm_close", "zone": zone, "close": close},
		} {
			if err := log.Append(record); err != nil {
				t.Fatal(err)
			}
		}
		return verifyAuditFile(log.Path, "")
	}
	if err := verifyClose("u3-v2-clean", baseClose); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name    string
		wantErr string
		mutate  func(map[string]any)
	}{
		{name: "missing format", wantErr: "swarm close format missing", mutate: func(body map[string]any) { delete(body, "format") }},
		{name: "unknown format", wantErr: "unsupported swarm close format", mutate: func(body map[string]any) { body["format"] = "asp-swarm-close/v3" }},
		{name: "stripped plan digest", wantErr: "swarm close v2 fields invalid", mutate: func(body map[string]any) { delete(body, "plan_digest") }},
		{name: "stripped graph digest", wantErr: "swarm close v2 fields invalid", mutate: func(body map[string]any) { delete(body, "execution_graph_digest") }},
		{name: "stripped final output", wantErr: "swarm close v2 fields invalid", mutate: func(body map[string]any) { delete(body, "final_output") }},
		{name: "unknown close field", wantErr: "swarm close v2 fields invalid", mutate: func(body map[string]any) { body["unexpected"] = true }},
		{name: "unknown step field", wantErr: "swarm close v2 step fields invalid", mutate: func(body map[string]any) {
			body["step_receipts"].([]any)[0].(map[string]any)["receipt_digest"] = finalSignedDigest
		}},
		{name: "unknown final output field", wantErr: "swarm close final output fields invalid", mutate: func(body map[string]any) {
			body["final_output"].(map[string]any)["unexpected"] = true
		}},
		{name: "unknown final artifact field", wantErr: "swarm close final output artifact fields invalid", mutate: func(body map[string]any) {
			body["final_output"].(map[string]any)["artifact"].(map[string]any)["unexpected"] = true
		}},
		{name: "null scheduler", wantErr: "swarm close scheduler invalid", mutate: func(body map[string]any) {
			body["scheduler"] = nil
		}},
		{name: "unknown scheduler field", wantErr: "swarm close scheduler invalid", mutate: func(body map[string]any) {
			body["scheduler"].(map[string]any)["unexpected"] = true
		}},
		{name: "wrong scheduler mode", wantErr: "swarm close scheduler mode invalid", mutate: func(body map[string]any) {
			body["scheduler"].(map[string]any)["mode"] = "serial"
		}},
		{name: "duplicate scheduler step", wantErr: "swarm close scheduler step duplicate", mutate: func(body map[string]any) {
			body["scheduler"].(map[string]any)["step_order"] = []any{"upstream", "upstream"}
		}},
		{name: "missing scheduler step", wantErr: "swarm close scheduler step missing", mutate: func(body map[string]any) {
			body["scheduler"].(map[string]any)["step_order"] = []any{"upstream", "missing"}
		}},
		{name: "scheduler contradicts observed receipt order", wantErr: "swarm close scheduler observed order mismatch", mutate: func(body map[string]any) {
			body["scheduler"].(map[string]any)["step_order"] = []any{"final", "upstream"}
		}},
		{name: "stripped scheduler for reordered execution", wantErr: "swarm close scheduler evidence required", mutate: func(body map[string]any) {
			delete(body, "scheduler")
		}},
		{name: "wrong plan digest", wantErr: "swarm close plan digest mismatch", mutate: func(body map[string]any) { body["plan_digest"] = strings.Repeat("b", 64) }},
		{name: "wrong graph digest", wantErr: "swarm close execution graph digest mismatch", mutate: func(body map[string]any) { body["execution_graph_digest"] = strings.Repeat("c", 64) }},
		{name: "reordered signed links", wantErr: "swarm close execution graph digest mismatch", mutate: func(body map[string]any) {
			steps := body["step_receipts"].([]any)
			body["step_receipts"] = []any{steps[1], steps[0]}
		}},
		{name: "wrong task id", wantErr: "swarm close task mismatch", mutate: func(body map[string]any) { body["step_receipts"].([]any)[0].(map[string]any)["task_id"] = "wrong_task" }},
		{name: "wrong signed receipt digest", wantErr: "swarm close signed receipt digest mismatch", mutate: func(body map[string]any) {
			body["step_receipts"].([]any)[0].(map[string]any)["signed_receipt_digest"] = strings.Repeat("d", 64)
		}},
		{name: "non-terminal final output", wantErr: "swarm close final output mismatch", mutate: func(body map[string]any) {
			body["final_output"] = map[string]any{"step_id": "upstream", "task_id": "u3_audit_upstream", "signed_receipt_digest": upstreamSignedDigest, "artifact": resultPointer(upstreamManifest), "selection_rule": "single-terminal-result"}
		}},
		{name: "wrong final artifact", wantErr: "swarm close final output mismatch", mutate: func(body map[string]any) {
			body["final_output"].(map[string]any)["artifact"] = resultPointer(upstreamManifest)
		}},
		{name: "v2 stripped into v1", wantErr: "swarm close v1 fields invalid", mutate: func(body map[string]any) { body["format"] = "asp-swarm-close/v1" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := verifyClose("u3-v2-"+strings.ReplaceAll(tc.name, " ", "-"), resign(tc.mutate)); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("got %v, want %s", err, tc.wantErr)
			}
		})
	}

	legacyBody := map[string]any{
		"format":   "asp-swarm-close/v1",
		"swarm_id": swarmID,
		"step_receipts": []map[string]any{
			{"step_id": "upstream", "task_id": "u3_audit_upstream", "receipt_digest": upstreamSignedDigest},
			{"step_id": "final", "task_id": "u3_audit_final", "receipt_digest": finalSignedDigest},
		},
	}
	if err := verifyClose("u3-v1-explicit", signBodyWithKey(zoneKey, legacyBody, "close_signature")); err != nil {
		t.Fatalf("explicit v1 close rejected: %v", err)
	}
	legacyNullScheduler := clone(legacyBody)
	legacyNullScheduler["scheduler"] = nil
	if err := verifyClose("u3-v1-null-scheduler", signBodyWithKey(zoneKey, legacyNullScheduler, "close_signature")); err == nil || !strings.Contains(err.Error(), "swarm close scheduler invalid") {
		t.Fatalf("null-scheduler legacy close = %v", err)
	}
	delete(legacyBody, "format")
	if err := verifyClose("u3-v1-missing-format", signBodyWithKey(zoneKey, legacyBody, "close_signature")); err == nil || !strings.Contains(err.Error(), "swarm close format missing") {
		t.Fatalf("missing-format legacy close = %v", err)
	}
}

type cliReplayStore struct {
	records map[string]verifier.VerificationReplayRecord
}

func newCLIReplayStore() *cliReplayStore {
	return &cliReplayStore{records: map[string]verifier.VerificationReplayRecord{}}
}

func (s *cliReplayStore) LookupVerificationReplay(verificationID string) (verifier.VerificationReplayRecord, bool, error) {
	record, ok := s.records[verificationID]
	if !ok {
		return verifier.VerificationReplayRecord{}, false, nil
	}
	clone, err := verifier.CloneVerificationReplayRecord(record)
	if err != nil {
		return verifier.VerificationReplayRecord{}, false, err
	}
	return clone, true, nil
}

func (s *cliReplayStore) PutVerificationReplayIfAbsent(record verifier.VerificationReplayRecord) (verifier.VerificationReplayRecord, bool, error) {
	if existing, ok := s.records[record.VerificationID]; ok {
		clone, err := verifier.CloneVerificationReplayRecord(existing)
		if err != nil {
			return verifier.VerificationReplayRecord{}, false, err
		}
		return clone, false, nil
	}
	stored, err := verifier.CloneVerificationReplayRecord(record)
	if err != nil {
		return verifier.VerificationReplayRecord{}, false, err
	}
	s.records[record.VerificationID] = stored
	clone, err := verifier.CloneVerificationReplayRecord(stored)
	if err != nil {
		return verifier.VerificationReplayRecord{}, false, err
	}
	return clone, true, nil
}

func cloneCLIJSONMap(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]any{}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestMemoryVerificationReplayStoreClonesRecords(t *testing.T) {
	store := newMemoryVerificationReplayStore()
	record := verifier.VerificationReplayRecord{
		VerificationID:       "u6-memory-alias",
		CanonicalProofSHA256: strings.Repeat("1", 64),
		CanonicalCloseSHA256: strings.Repeat("2", 64),
		CanonicalProofBytes:  []byte("proof-bytes"),
		CanonicalCloseBytes:  []byte("close-bytes"),
		StoredCloseDigest:    strings.Repeat("3", 64),
		ProofCloseDigest:     strings.Repeat("3", 64),
		ProofDigest:          strings.Repeat("4", 64),
		TrustInputsDigest:    strings.Repeat("5", 64),
		FinalOutput:          map[string]any{"artifact": map[string]any{"uri": "artifact://local/u6-memory"}, "selection_rule": "single-terminal-result"},
	}
	if _, inserted, err := store.PutVerificationReplayIfAbsent(record); err != nil || !inserted {
		t.Fatalf("put inserted=%v err=%v", inserted, err)
	}
	record.CanonicalProofBytes[0] = 'X'
	record.CanonicalCloseBytes[0] = 'Y'
	record.FinalOutput["selection_rule"] = "mutated-original"
	lookup, ok, err := store.LookupVerificationReplay("u6-memory-alias")
	if err != nil || !ok {
		t.Fatalf("lookup ok=%v err=%v", ok, err)
	}
	lookup.CanonicalProofBytes[0] = 'Z'
	lookup.CanonicalCloseBytes[0] = 'W'
	lookup.FinalOutput["selection_rule"] = "mutated-lookup"
	lookupAgain, ok, err := store.LookupVerificationReplay("u6-memory-alias")
	if err != nil || !ok {
		t.Fatalf("second lookup ok=%v err=%v", ok, err)
	}
	if string(lookupAgain.CanonicalProofBytes) != "proof-bytes" || string(lookupAgain.CanonicalCloseBytes) != "close-bytes" || lookupAgain.FinalOutput["selection_rule"] != "single-terminal-result" {
		t.Fatalf("store returned aliased record: %+v", lookupAgain)
	}
}

func writeCLIJSON(t *testing.T, dir, name string, value any) string {
	t.Helper()
	path := filepath.Join(dir, name)
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestVerifySwarmOutputCLIProducesSchedulerGate(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	verifierZone, verifierZoneKey := testZoneDescriptor(t, "zone://u6-cli/verifier-zone")
	_, verifierKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verifierAgent, err := agentDescriptor(verifierKey, "agent://u6-cli/verifier")
	if err != nil {
		t.Fatal(err)
	}
	verifierAgent["capabilities"] = []any{"self.declared.only"}
	verifierAgent["policy"] = map[string]any{"allow_network": false, "write_prefixes": []any{"artifact://local/"}}
	verifierAgent = signBodyWithKey(verifierKey, map[string]any{"alias": verifierAgent["alias"], "aid": verifierAgent["aid"], "did_key": verifierAgent["did_key"], "public_key_spki": verifierAgent["public_key_spki"], "transports": []any{"asp+local://u6-cli"}, "capabilities": verifierAgent["capabilities"], "policy": verifierAgent["policy"]}, "descriptor_signature")
	verifierBinding := signBodyWithKey(verifierZoneKey, map[string]any{"zone": verifierZone["zid"], "alias": verifierAgent["alias"], "aid": verifierAgent["aid"]}, "signature")
	allowlist := map[string]any{"format": "asp-swarm-output-verifier-allowlist/v1", "verifiers": []any{map[string]any{"descriptor": verifierAgent, "zone_binding": verifierBinding, "authorizations": []any{"swarm.output.verify"}}}}
	trustedVerifierZones := map[string]any{"format": "asp-swarm-output-trusted-zones/v1", "zones": []any{verifierZone}}
	revocations := map[string]any{"format": "asp-swarm-output-revocations/v1", "revocations": []any{signBodyWithKey(verifierZoneKey, map[string]any{"zone": verifierZone["zid"], "subject": "aid:ed25519:retired-u6-cli", "reason": "retired"}, "signature")}}
	trust, err := verifier.NewTrustInputsForTest(allowlist, trustedVerifierZones, revocations)
	if err != nil {
		t.Fatal(err)
	}

	coordinator, coordinatorKey := testZoneDescriptor(t, "zone://u6-cli/coordinator")
	_, workerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := agentDescriptor(workerKey, "agent://u6-cli/worker")
	if err != nil {
		t.Fatal(err)
	}
	worker["policy"] = map[string]any{"allow_network": false, "write_prefixes": []any{"artifact://local/"}}
	worker = signBodyWithKey(workerKey, map[string]any{"alias": worker["alias"], "aid": worker["aid"], "did_key": worker["did_key"], "public_key_spki": worker["public_key_spki"], "transports": []any{"asp+local://u6-cli"}, "capabilities": []any{"summarize.text"}, "policy": worker["policy"]}, "descriptor_signature")
	steps := []any{map[string]any{"step_id": "summary", "capability": "summarize.text", "depends_on": []any{}}}
	intent := "Produce a Go scheduler gate result."
	planDigest := digestHex(map[string]any{"intent": intent, "steps": steps})
	swarmID := "swarm://u6-cli/scheduler-gate"
	planBody := map[string]any{"swarm_id": swarmID, "intent": intent, "steps": steps, "policy_digest": strings.Repeat("a", 64), "plan_digest": planDigest}
	planFrame := map[string]any{"type": "FED_SWARM_PLAN", "zone": coordinator, "plan": signBodyWithKey(coordinatorKey, planBody, "plan_signature")}
	taskBody := map[string]any{"task_id": "u6_cli_summary", "from": worker["aid"], "to": worker["alias"], "intent": "Complete summary."}
	signedTask := signBodyWithKey(workerKey, taskBody, "signature")
	bindingSteps := []any{map[string]any{"step_id": "summary", "depends_on": []any{}, "capability": "summarize.text", "task_digest": digestHex(signedTask)}}
	graphDigest := digestHex(map[string]any{"swarm_id": swarmID, "plan_digest": planDigest, "steps": bindingSteps})
	binding := signBodyWithKey(coordinatorKey, map[string]any{"format": "asp-swarm-execution-binding/v1", "swarm_id": swarmID, "plan_digest": planDigest, "steps": bindingSteps, "execution_graph_digest": graphDigest}, "binding_signature")
	artifactBytes := []byte("u6 cli result bytes\n")
	artifactHash := sha256.Sum256(artifactBytes)
	artifactSHA := hex.EncodeToString(artifactHash[:])
	artifactURI := "artifact://local/u6-cli/result.txt"
	manifestBody := map[string]any{"uri": artifactURI, "sha256": artifactSHA, "size": float64(len(artifactBytes)), "media_type": "text/plain", "afp": "afp:sha256:" + artifactSHA}
	manifest := map[string]any{"uri": artifactURI, "sha256": artifactSHA, "size": float64(len(artifactBytes)), "media_type": "text/plain", "afp": "afp:sha256:" + artifactSHA, "manifest_hash": digestHex(manifestBody)}
	resultArtifact := map[string]any{"uri": artifactURI, "sha256": artifactSHA, "manifest_hash": manifest["manifest_hash"]}
	receiptBody := map[string]any{"task_id": signedTask["task_id"], "task_digest": digestHex(signedTask), "origin_zone": coordinator["zid"], "executing_zone": coordinator["zid"], "to": worker["aid"], "artifact_refs": []any{artifactURI}, "artifact_manifests": []any{manifest}, "result_artifact": resultArtifact, "swarm": map[string]any{"swarm_id": swarmID, "step_id": "summary", "after": []any{}, "plan_digest": planDigest, "execution_graph_digest": graphDigest, "capability": "summarize.text", "task_digest": digestHex(signedTask)}}
	receipt := signBodyWithKey(workerKey, receiptBody, "signature")
	receiptFrame := map[string]any{"type": "FED_RECEIPT", "zone": coordinator, "worker": worker, "zone_binding": signBodyWithKey(coordinatorKey, map[string]any{"zone": coordinator["zid"], "alias": worker["alias"], "aid": worker["aid"]}, "signature"), "receipt": receipt}
	signedReceiptDigest, err := verifier.SignedReceiptDigest(receipt)
	if err != nil {
		t.Fatal(err)
	}
	finalOutput := map[string]any{"step_id": "summary", "task_id": signedTask["task_id"], "signed_receipt_digest": signedReceiptDigest, "artifact": resultArtifact, "selection_rule": "single-terminal-result"}
	closeBody := map[string]any{"format": "asp-swarm-close/v2", "swarm_id": swarmID, "plan_digest": planDigest, "execution_graph_digest": graphDigest, "step_receipts": []any{map[string]any{"step_id": "summary", "task_id": signedTask["task_id"], "signed_receipt_digest": signedReceiptDigest}}, "final_output": finalOutput}
	closeFrame := map[string]any{"type": "FED_SWARM_CLOSE", "swarm_id": swarmID, "zone": coordinator, "close": signBodyWithKey(coordinatorKey, closeBody, "close_signature")}
	closeDigest := digestHex(closeFrame["close"])
	proofBody := map[string]any{"format": "asp-swarm-output-verification/v1", "verification_id": "u6-go-cli-scheduler", "verified_at": "2026-07-11T11:59:00Z", "swarm_id": swarmID, "plan_digest": planDigest, "execution_graph_digest": graphDigest, "close_digest": closeDigest, "final_output": finalOutput, "verifier_aid": verifierAgent["aid"], "verifier_zone": verifierZone["zid"], "trust_inputs_digest": trust.TrustInputsDigest}
	proof := map[string]any{"type": "FED_SWARM_OUTPUT_VERIFICATION", "verifier": verifierAgent, "verifier_zone": verifierZone, "verifier_zone_binding": verifierBinding, "proof": signBodyWithKey(verifierKey, proofBody, "proof_signature")}
	artifactPath := filepath.Join(dir, "result.txt")
	if err := os.WriteFile(artifactPath, artifactBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"proof":         writeCLIJSON(t, dir, "proof.json", proof),
		"plan":          writeCLIJSON(t, dir, "plan.json", planFrame),
		"binding":       writeCLIJSON(t, dir, "binding.json", binding),
		"steps":         writeCLIJSON(t, dir, "steps.json", []any{map[string]any{"step_id": "summary", "depends_on": []any{}, "task": signedTask}}),
		"workers":       writeCLIJSON(t, dir, "workers.json", []any{worker}),
		"close":         writeCLIJSON(t, dir, "close.json", closeFrame),
		"receipts":      writeCLIJSON(t, dir, "receipts.json", []any{receiptFrame}),
		"zones":         writeCLIJSON(t, dir, "trusted-zones.json", map[string]any{"zones": []any{coordinator}}),
		"allowlist":     writeCLIJSON(t, dir, "allowlist.json", allowlist),
		"verifierZones": writeCLIJSON(t, dir, "verifier-zones.json", trustedVerifierZones),
		"revocations":   writeCLIJSON(t, dir, "revocations.json", revocations),
	}
	_ = files
	bundlePath := writeCLIJSON(t, dir, "bundle.json", map[string]any{"format": "asp-swarm-output-verification-cli/v1", "proof": "proof.json", "plan": "plan.json", "execution_binding": "binding.json", "executable_steps": "steps.json", "resolved_workers": "workers.json", "close": "close.json", "receipts": "receipts.json", "trusted_zones": "trusted-zones.json", "trust_inputs": map[string]any{"allowlist": "allowlist.json", "trustedZones": "verifier-zones.json", "revocations": "revocations.json"}, "artifacts": []any{map[string]any{"uri": artifactURI, "path": filepath.Base(artifactPath)}}})

	store := newCLIReplayStore()
	var out bytes.Buffer
	if err := runVerifySwarmOutputSchedulerGate([]string{bundlePath}, store, &out, time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	var gate map[string]any
	if err := json.Unmarshal(out.Bytes(), &gate); err != nil {
		t.Fatal(err)
	}
	if gate["replay_decision"] != "accepted" || gate["stored_close_digest"] != closeDigest || gate["proof_close_digest"] != closeDigest || gate["closeDigest"] != closeDigest || gate["trustInputsDigest"] != trust.TrustInputsDigest || gate["completion_gate"] != true {
		t.Fatalf("gate=%v", gate)
	}
	if _, ok := gate["CloseBytes"].(string); !ok {
		t.Fatalf("CloseBytes missing exact byte payload: %v", gate)
	}
	var second bytes.Buffer
	if err := runVerifySwarmOutputSchedulerGate([]string{bundlePath}, store, &second, time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	var secondGate map[string]any
	if err := json.Unmarshal(second.Bytes(), &secondGate); err != nil {
		t.Fatal(err)
	}
	if secondGate["replay_decision"] != "idempotent" {
		t.Fatalf("second gate=%v", secondGate)
	}
	changedProof := cloneCLIJSONMap(t, proof)
	changedProofBody := cloneCLIJSONMap(t, changedProof["proof"].(map[string]any))
	delete(changedProofBody, "proof_signature")
	changedProofBody["verified_at"] = "2026-07-11T11:58:59Z"
	changedProof["proof"] = signBodyWithKey(verifierKey, changedProofBody, "proof_signature")
	writeCLIJSON(t, dir, "proof.json", changedProof)
	var conflictOut bytes.Buffer
	if err := runVerifySwarmOutputSchedulerGate([]string{bundlePath}, store, &conflictOut, time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	var conflictGate map[string]any
	if err := json.Unmarshal(conflictOut.Bytes(), &conflictGate); err != nil {
		t.Fatal(err)
	}
	if conflictGate["replay_decision"] != "conflict" || conflictGate["store_mutated"] != false || conflictGate["completion_gate"] != false {
		t.Fatalf("conflict gate=%v", conflictGate)
	}

	duplicateBundlePath := writeCLIJSON(t, dir, "duplicate-bundle.json", map[string]any{"format": "asp-swarm-output-verification-cli/v1", "proof": "proof.json", "plan": "plan.json", "execution_binding": "binding.json", "executable_steps": "steps.json", "resolved_workers": "workers.json", "close": "close.json", "receipts": "receipts.json", "trusted_zones": "trusted-zones.json", "trust_inputs": map[string]any{"allowlist": "allowlist.json", "trustedZones": "verifier-zones.json", "revocations": "revocations.json"}, "artifacts": []any{map[string]any{"uri": artifactURI, "path": filepath.Base(artifactPath)}, map[string]any{"uri": artifactURI, "path": "other-result.txt"}}})
	beforeDuplicateRecords := len(store.records)
	if err := runVerifySwarmOutputSchedulerGate([]string{duplicateBundlePath}, store, &bytes.Buffer{}, time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)); err == nil || !strings.Contains(err.Error(), "duplicate artifact uri") {
		t.Fatalf("duplicate artifact err=%v", err)
	}
	if len(store.records) != beforeDuplicateRecords {
		t.Fatalf("duplicate artifact mutated store: before=%d after=%d", beforeDuplicateRecords, len(store.records))
	}
	if err := runVerifySwarmOutputSchedulerGate(nil, store, &bytes.Buffer{}, time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)); err == nil || !strings.Contains(err.Error(), "usage") {
		t.Fatalf("missing arity err=%v", err)
	}
	if err := runVerifySwarmOutputSchedulerGate([]string{bundlePath, bundlePath}, store, &bytes.Buffer{}, time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)); err == nil || !strings.Contains(err.Error(), "usage") {
		t.Fatalf("extra arity err=%v", err)
	}
}

func TestU7VectorFilesUseExplicitPhaseAFormats(t *testing.T) {
	for _, path := range []string{
		filepath.Join("..", "..", "test-vectors", "asp-u7-node-created-swarm-output.json"),
		filepath.Join("..", "..", "test-vectors", "asp-u7-go-created-swarm-output.json"),
	} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var vector map[string]any
		if err := json.Unmarshal(data, &vector); err != nil {
			t.Fatal(err)
		}
		if vector["format"] != "asp-swarm-output-vector/v1" {
			t.Fatalf("%s format = %v", path, vector["format"])
		}
		evidence := vector["evidence"].(map[string]any)
		closeFrame := evidence["close_frame"].(map[string]any)
		closeProof := closeFrame["close"].(map[string]any)
		if closeProof["format"] != "asp-swarm-close/v2" {
			t.Fatalf("%s close format = %v", path, closeProof["format"])
		}
		proofFrame := vector["proof_frame"].(map[string]any)
		proof := proofFrame["proof"].(map[string]any)
		if proof["format"] != "asp-swarm-output-verification/v1" {
			t.Fatalf("%s proof format = %v", path, proof["format"])
		}
	}
	legacyData, err := os.ReadFile(filepath.Join("..", "..", "test-vectors", "asp-v10.38-fed-swarm-close.json"))
	if err != nil {
		t.Fatal(err)
	}
	var legacy map[string]any
	if err := json.Unmarshal(legacyData, &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy["schema_format"] != "asp-swarm-close-vector/legacy-v1" || legacy["legacy"] != true {
		t.Fatalf("legacy close vector is not explicitly marked: %v", legacy)
	}
}

func writeManagedRuntimeStore(t *testing.T, dir, name string, descriptor map[string]any, seed []byte, identityKind, keyType string) ManagedKeyConfig {
	t.Helper()
	storePath := filepath.Join(dir, name+"-store")
	keyPath := filepath.Join(dir, name+".key")
	descriptorPath := filepath.Join(dir, name+".descriptor.json")
	passphrasePath := filepath.Join(dir, name+".passphrase")
	passphrase := []byte(name + " managed runtime passphrase\n")
	keyBytes := append([]byte(nil), seed...)
	if keyType == managedkey.KeyTypePKCS8 {
		privateKey := ed25519.NewKeyFromSeed(seed)
		var err error
		keyBytes, err = x509.MarshalPKCS8PrivateKey(privateKey)
		if err != nil {
			t.Fatal(err)
		}
	}
	for path, data := range map[string][]byte{keyPath: keyBytes, passphrasePath: passphrase} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	descriptorBytes, err := json.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(descriptorPath, descriptorBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := managedkey.OpenStore(storePath, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := managedkey.Migrate(managedkey.MigrateOptions{Store: store, SourceKeyPath: keyPath, SourceKeyType: keyType, IdentityKind: identityKind, DescriptorPath: descriptorPath, PassphrasePath: passphrasePath, Iterations: 100000}); err != nil {
		t.Fatal(err)
	}
	return ManagedKeyConfig{StorePath: storePath, PassphraseFile: passphrasePath}
}

func managedRuntimeFixture(t *testing.T, workerKeyType string) (string, ManagedRuntimeConfig) {
	t.Helper()
	fixturePath := filepath.Join("..", "..", "test-vectors", "asp-v1.5-capability-credential.json")
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	var raw struct {
		Authority        map[string]any `json:"authority"`
		Worker           map[string]any `json:"worker"`
		AuthoritySeedHex string         `json:"authority_seed_hex"`
		WorkerSeedHex    string         `json:"worker_seed_hex"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	authoritySeed, err := hex.DecodeString(raw.AuthoritySeedHex)
	if err != nil {
		t.Fatal(err)
	}
	workerSeed, err := hex.DecodeString(raw.WorkerSeedHex)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	return fixturePath, ManagedRuntimeConfig{
		Authority: writeManagedRuntimeStore(t, dir, "authority", raw.Authority, authoritySeed, managedkey.IdentityZID, managedkey.KeyTypeSeed),
		Worker:    writeManagedRuntimeStore(t, dir, "worker", raw.Worker, workerSeed, managedkey.IdentityAID, workerKeyType),
	}
}

func TestLoadFixtureRequiresManaged(t *testing.T) {
	fixturePath, runtimeKeys := managedRuntimeFixture(t, managedkey.KeyTypeSeed)
	fixture, err := loadManagedFixture(fixturePath, runtimeKeys)
	if err != nil {
		t.Fatal(err)
	}
	if fixture.AuthorityGeneration.RecordDigest == "" || len(fixture.Workers) != 1 || fixture.Workers[0].GenerationRef.RecordDigest == "" {
		t.Fatalf("managed generation references missing: authority=%+v workers=%+v", fixture.AuthorityGeneration, fixture.Workers)
	}
	reloaded, err := loadVerifiedKeyGeneration(fixture.Workers[0].WorkerGenerationPin.StorePath, fixture.Workers[0].WorkerGenerationPin.RecordDigest, fixture.Workers[0].WorkerGenerationPin.PassphraseFile)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(reloaded.PrivateKey)
	if !sameGeneration(reloaded.KeyGeneration, fixture.Workers[0].GenerationRef) {
		t.Fatalf("record-digest-pinned worker reload drifted: got=%+v want=%+v", reloaded.KeyGeneration, fixture.Workers[0].GenerationRef)
	}
	if _, err := loadManagedFixture(fixturePath, ManagedRuntimeConfig{}); err == nil || !strings.Contains(err.Error(), "managed key store") {
		t.Fatalf("bare authority/worker configuration accepted: %v", err)
	}
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	var mismatched map[string]any
	if err := json.Unmarshal(data, &mismatched); err != nil {
		t.Fatal(err)
	}
	mismatched["worker_profile"].(map[string]any)["alias"] = "agent://wrong/profile"
	mismatchedPath := filepath.Join(t.TempDir(), "mismatched-fixture.json")
	mismatchedData, err := json.Marshal(mismatched)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mismatchedPath, mismatchedData, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadManagedFixture(mismatchedPath, runtimeKeys); err == nil || !strings.Contains(err.Error(), "worker profile") {
		t.Fatalf("worker profile substitution accepted: %v", err)
	}
	mismatched["worker_profile"].(map[string]any)["alias"] = fixture.Workers[0].Profile.Alias
	mismatched["worker_profile"].(map[string]any)["key_file"] = filepath.Join(t.TempDir(), "bare.seed")
	mismatchedData, err = json.Marshal(mismatched)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mismatchedPath, mismatchedData, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadManagedFixture(mismatchedPath, runtimeKeys); err == nil || !strings.Contains(err.Error(), "key_file") {
		t.Fatalf("bare worker key fallback accepted: %v", err)
	}
}

func TestSwarmRejectsManagedPointerDrift(t *testing.T) {
	fixturePath, runtimeKeys := managedRuntimeFixture(t, managedkey.KeyTypeSeed)
	fixture, err := loadManagedFixture(fixturePath, runtimeKeys)
	if err != nil {
		t.Fatal(err)
	}
	workerStore, err := managedkey.OpenStore(runtimeKeys.Worker.StorePath, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := managedkey.Rewrap(managedkey.RewrapOptions{Store: workerStore, IdentityKind: managedkey.IdentityAID, DescriptorPath: filepath.Join(filepath.Dir(runtimeKeys.Worker.PassphraseFile), "worker.descriptor.json"), PassphrasePath: runtimeKeys.Worker.PassphraseFile, NewPassphrasePath: runtimeKeys.Worker.PassphraseFile, Iterations: 100001}); err != nil {
		t.Fatal(err)
	}
	if err := fixture.verifySwarmGenerationPins(); err == nil || !strings.Contains(err.Error(), "active generation changed during Swarm") {
		t.Fatalf("managed pointer drift accepted: %v", err)
	}
}

func TestServeRejectsInvalidManaged(t *testing.T) {
	fixturePath, runtimeKeys := managedRuntimeFixture(t, managedkey.KeyTypeSeed)
	runtimeKeys.Authority.RecordDigest = strings.Repeat("0", 64)
	if err := serve("127.0.0.1", "0", "", "", "", "", "", "", "", "", fixturePath, "", "", "", runtimeKeys, filepath.Join(t.TempDir(), "audit.log")); err == nil {
		t.Fatal("invalid managed authority reached listener initialization")
	}
}

func TestGoSignsNodeManagedGeneration(t *testing.T) {
	fixturePath, runtimeKeys := managedRuntimeFixture(t, managedkey.KeyTypePKCS8)
	fixture, err := loadManagedFixture(fixturePath, runtimeKeys)
	if err != nil {
		t.Fatal(err)
	}
	worker := fixture.Workers[0]
	body := map[string]any{"interop": "go-signs-node-managed-generation", "record_digest": worker.GenerationRef.RecordDigest}
	signed := signBody(worker.PrivateKey, body)
	spki, _, err := publicKeySPKI(worker.PrivateKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	publicKey, _, err := publicKey(map[string]any{"public_key_spki": spki})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyMapSignature(publicKey, signed, "signature"); err != nil {
		t.Fatalf("Go signature from Node PKCS8 managed generation did not verify: %v", err)
	}
}
