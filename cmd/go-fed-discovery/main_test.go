package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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
				"step_id":        "upstream",
				"uri":            upstreamManifest["uri"],
				"sha256":         strings.Repeat("0", 64),
				"manifest_hash":  upstreamManifest["manifest_hash"],
				"receipt_digest": digestHex(upstreamReceipt),
			}},
		},
	})
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
	downstreamReceipt["swarm"].(map[string]any)["input_artifacts"].([]map[string]any)[0]["receipt_digest"] = strings.Repeat("1", 64)
	downstreamBadReceiptDigest := signBody(downstreamKey, receiptBodyWithoutSignature(downstreamReceipt))
	badDigestLog := &AuditLog{Path: "bad-digest-audit.log", Head: auditZeroHash}
	if err := badDigestLog.Append(map[string]any{"kind": "go_fed_receipt", "zone": zone, "worker": upstreamWorker, "zone_binding": fixture.zoneBindingForDescriptor(upstreamWorker), "receipt": upstreamReceipt}); err != nil {
		t.Fatal(err)
	}
	if err := badDigestLog.Append(map[string]any{"kind": "go_fed_receipt", "zone": zone, "worker": downstreamWorker, "zone_binding": fixture.zoneBindingForDescriptor(downstreamWorker), "receipt": downstreamBadReceiptDigest}); err != nil {
		t.Fatal(err)
	}
	err = verifyAuditFile("bad-digest-audit.log", "")
	if err == nil || !strings.Contains(err.Error(), "swarm input receipt digest mismatch") {
		t.Fatalf("got %v, want swarm input receipt digest mismatch", err)
	}

	downstreamStepMismatchReceipt := testSignedReceipt(t, zone, zoneKey, downstreamWorker, downstreamKey, "swarm_down_wrong_step", []map[string]any{downstreamManifest}, map[string]any{
		"swarm": map[string]any{
			"swarm_id": "swarm://test",
			"step_id":  "downstream",
			"after":    []string{"upstream"},
			"input_artifacts": []map[string]any{{
				"step_id":        "other",
				"uri":            otherManifest["uri"],
				"sha256":         otherManifest["sha256"],
				"manifest_hash":  otherManifest["manifest_hash"],
				"receipt_digest": digestHex(otherReceipt),
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
				"step_id":        "upstream",
				"uri":            otherManifest["uri"],
				"sha256":         otherManifest["sha256"],
				"manifest_hash":  otherManifest["manifest_hash"],
				"receipt_digest": digestHex(duplicateStepReceipt),
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

	downstreamReceipt["swarm"].(map[string]any)["input_artifacts"].([]map[string]any)[0]["receipt_digest"] = digestHex(upstreamReceipt)
	downstreamRecord := signBody(downstreamKey, receiptBodyWithoutSignature(downstreamReceipt))
	cleanLog := &AuditLog{Path: "clean-audit.log", Head: auditZeroHash}
	if err := cleanLog.Append(map[string]any{"kind": "go_fed_receipt", "zone": zone, "worker": upstreamWorker, "zone_binding": fixture.zoneBindingForDescriptor(upstreamWorker), "receipt": upstreamReceipt}); err != nil {
		t.Fatal(err)
	}
	if err := cleanLog.Append(map[string]any{"kind": "go_fed_receipt", "zone": zone, "worker": downstreamWorker, "zone_binding": fixture.zoneBindingForDescriptor(downstreamWorker), "receipt": downstreamRecord}); err != nil {
		t.Fatal(err)
	}
	cleanClose := signBodyWithKey(zoneKey, map[string]any{
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
		"0.0.0.0":   true,
		"::":        true,
		"fed.local": true,
	}
	for host, want := range cases {
		if got := isPublicListenHost(host); got != want {
			t.Fatalf("isPublicListenHost(%q) = %v, want %v", host, got, want)
		}
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
		"from":               "aid:ed25519:test-requester",
		"origin_zone":        zone["zid"],
		"executing_zone":     zone["zid"],
		"to":                 worker["aid"],
		"artifact_refs":      refs,
		"artifact_manifests": manifests,
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
