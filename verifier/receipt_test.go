package verifier

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyFederatedReceiptVector(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "test-vectors", "asp-v9.25-fed-receipt.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		TrustedZones []map[string]any `json:"trusted_zones"`
		Frame        map[string]any   `json:"frame"`
	}
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	trusted := map[string]map[string]any{}
	for _, zone := range vector.TrustedZones {
		trusted[zone["zid"].(string)] = zone
	}
	if err := VerifyFederatedReceipt(vector.Frame, trusted); err != nil {
		t.Fatal(err)
	}

	wrongTypeFrame := map[string]any{}
	for key, value := range vector.Frame {
		wrongTypeFrame[key] = value
	}
	wrongTypeFrame["type"] = "FED_TASK_OPEN"
	if err := VerifyFederatedReceipt(wrongTypeFrame, trusted); err == nil || !strings.Contains(err.Error(), "expected FED_RECEIPT frame") {
		t.Fatalf("got %v, want expected FED_RECEIPT frame", err)
	}

	receipt := vector.Frame["receipt"].(map[string]any)
	withoutOrigin := map[string]map[string]any{}
	for zid, zone := range trusted {
		withoutOrigin[zid] = zone
	}
	delete(withoutOrigin, receipt["origin_zone"].(string))
	if err := VerifyFederatedReceipt(vector.Frame, withoutOrigin); err == nil || !strings.Contains(err.Error(), "untrusted receipt origin zone") {
		t.Fatalf("got %v, want untrusted receipt origin zone", err)
	}

	withoutTaskDigestReceipt := map[string]any{}
	for key, value := range receipt {
		if key != "task_digest" {
			withoutTaskDigestReceipt[key] = value
		}
	}
	withoutTaskDigestFrame := map[string]any{}
	for key, value := range vector.Frame {
		withoutTaskDigestFrame[key] = value
	}
	withoutTaskDigestFrame["receipt"] = withoutTaskDigestReceipt
	if err := VerifyFederatedReceipt(withoutTaskDigestFrame, trusted); err == nil || !strings.Contains(err.Error(), "receipt task_digest missing") {
		t.Fatalf("got %v, want receipt task_digest missing", err)
	}

	if err := VerifyFederatedReceipt(vector.Frame, trusted, map[string]any{"task_id": receipt["task_id"], "intent": "wrong task"}); err == nil || !strings.Contains(err.Error(), "receipt task_digest mismatch") {
		t.Fatalf("got %v, want receipt task_digest mismatch", err)
	}

	receipt["executing_zone"] = "zid:ed25519:bad"
	if err := VerifyFederatedReceipt(vector.Frame, trusted); err == nil || !strings.Contains(err.Error(), "receipt executing_zone mismatch") {
		t.Fatalf("got %v, want receipt executing_zone mismatch", err)
	}
}

func TestVerifyFederatedReceiptAcceptsNodeCanonicalSpecialChars(t *testing.T) {
	zonePub, zoneKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	workerPub, workerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	zone := signedDescriptor(t, zoneKey, "zone_signature", map[string]any{"zid": zidFromSPKI(spkiBytes(t, zonePub)), "public_key_spki": spki(t, zonePub)})
	worker := signedDescriptor(t, workerKey, "descriptor_signature", map[string]any{"aid": aidFromSPKI(spkiBytes(t, workerPub)), "alias": "worker", "public_key_spki": spki(t, workerPub)})
	binding := signNodeCanonical(t, zoneKey, "signature", map[string]any{"zone": zone["zid"], "alias": worker["alias"], "aid": worker["aid"]})
	signedTask := signNodeCanonical(t, workerKey, "signature", map[string]any{"task_id": "html_chars_task", "intent": "a<b & c>d"})
	receipt := signNodeCanonical(t, workerKey, "signature", map[string]any{
		"task_id":        "html_chars_task",
		"task_digest":    digestNodeCanonical(signedTask),
		"origin_zone":    zone["zid"],
		"executing_zone": zone["zid"],
		"to":             worker["aid"],
		"note":           "a<b & c>d",
	})

	err = VerifyFederatedReceipt(map[string]any{"type": "FED_RECEIPT", "zone": zone, "worker": worker, "zone_binding": binding, "receipt": receipt}, map[string]map[string]any{zone["zid"].(string): zone}, signedTask)
	if err != nil {
		t.Fatal(err)
	}
}

func signedDescriptor(t *testing.T, key ed25519.PrivateKey, signatureKey string, body map[string]any) map[string]any {
	t.Helper()
	return signNodeCanonical(t, key, signatureKey, body)
}

func signNodeCanonical(t *testing.T, key ed25519.PrivateKey, signatureKey string, body map[string]any) map[string]any {
	t.Helper()
	out := map[string]any{}
	for k, v := range body {
		out[k] = v
	}
	out[signatureKey] = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, nodeCanonicalJSON(t, body)))
	return out
}

func digestNodeCanonical(value any) string {
	data := nodeCanonicalJSONNoTest(value)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func nodeCanonicalJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := nodeCanonicalJSONBytes(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func nodeCanonicalJSONNoTest(value any) []byte {
	data, err := nodeCanonicalJSONBytes(value)
	if err != nil {
		panic(err)
	}
	return data
}

func nodeCanonicalJSONBytes(value any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

func spki(t *testing.T, key ed25519.PublicKey) string {
	t.Helper()
	return base64.RawURLEncoding.EncodeToString(spkiBytes(t, key))
}

func spkiBytes(t *testing.T, key ed25519.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestArtifactManifestAFPMatchesSHA256(t *testing.T) {
	manifest := map[string]any{
		"uri":        "artifact://local/afp-test/out.md",
		"sha256":     strings.Repeat("1", 64),
		"size":       float64(1),
		"media_type": "text/markdown; charset=utf-8",
		"afp":        "afp:sha256:" + strings.Repeat("0", 64),
	}
	manifest["manifest_hash"] = digestHex(manifest)
	err := verifyReceiptArtifactManifests(map[string]any{
		"artifact_refs":      []any{manifest["uri"]},
		"artifact_manifests": []any{manifest},
	})
	if err == nil || !strings.Contains(err.Error(), "artifact manifest afp mismatch") {
		t.Fatalf("got %v, want artifact manifest afp mismatch", err)
	}
}

func TestArtifactManifestRejectsMalformedSHA256(t *testing.T) {
	manifest := map[string]any{
		"uri":        "artifact://local/sha-test/out.md",
		"sha256":     "../evil",
		"size":       float64(1),
		"media_type": "text/markdown; charset=utf-8",
		"afp":        "afp:sha256:../evil",
	}
	manifest["manifest_hash"] = digestHex(manifest)
	err := verifyReceiptArtifactManifests(map[string]any{
		"artifact_refs":      []any{manifest["uri"]},
		"artifact_manifests": []any{manifest},
	})
	if err == nil || !strings.Contains(err.Error(), "artifact manifest sha256 invalid") {
		t.Fatalf("got %v, want artifact manifest sha256 invalid", err)
	}
}

func TestArtifactManifestRejectsMalformedSize(t *testing.T) {
	for _, size := range []float64{-1, 1.5} {
		manifest := map[string]any{
			"uri":        "artifact://local/size-test/out.md",
			"sha256":     strings.Repeat("1", 64),
			"size":       size,
			"media_type": "text/markdown; charset=utf-8",
			"afp":        "afp:sha256:" + strings.Repeat("1", 64),
		}
		manifest["manifest_hash"] = digestHex(manifest)
		err := verifyReceiptArtifactManifests(map[string]any{
			"artifact_refs":      []any{manifest["uri"]},
			"artifact_manifests": []any{manifest},
		})
		if err == nil || !strings.Contains(err.Error(), "artifact manifest size invalid") {
			t.Fatalf("size %v: got %v, want artifact manifest size invalid", size, err)
		}
	}
}

func TestArtifactManifestRejectsMalformedMediaType(t *testing.T) {
	manifest := map[string]any{
		"uri":        "artifact://local/media-type-test/out.md",
		"sha256":     strings.Repeat("2", 64),
		"size":       float64(1),
		"media_type": map[string]any{"type": "text/plain"},
		"afp":        "afp:sha256:" + strings.Repeat("2", 64),
	}
	manifest["manifest_hash"] = digestHex(manifest)
	err := verifyReceiptArtifactManifests(map[string]any{
		"artifact_refs":      []any{manifest["uri"]},
		"artifact_manifests": []any{manifest},
	})
	if err == nil || !strings.Contains(err.Error(), "artifact manifest media_type invalid") {
		t.Fatalf("got %v, want artifact manifest media_type invalid", err)
	}
}

func TestArtifactManifestRejectsMalformedManifestHash(t *testing.T) {
	manifest := map[string]any{
		"uri":           "artifact://local/manifest-hash-test/out.md",
		"sha256":        strings.Repeat("3", 64),
		"size":          float64(1),
		"media_type":    "text/plain",
		"afp":           "afp:sha256:" + strings.Repeat("3", 64),
		"manifest_hash": map[string]any{"hash": strings.Repeat("4", 64)},
	}
	err := verifyReceiptArtifactManifests(map[string]any{
		"artifact_refs":      []any{manifest["uri"]},
		"artifact_manifests": []any{manifest},
	})
	if err == nil || !strings.Contains(err.Error(), "artifact manifest manifest_hash invalid") {
		t.Fatalf("got %v, want artifact manifest manifest_hash invalid", err)
	}
}

func TestArtifactManifestRejectsMalformedURI(t *testing.T) {
	manifest := map[string]any{
		"uri":        map[string]any{"path": "artifact://local/uri-test/out.md"},
		"sha256":     strings.Repeat("4", 64),
		"size":       float64(1),
		"media_type": "text/plain",
		"afp":        "afp:sha256:" + strings.Repeat("4", 64),
	}
	manifest["manifest_hash"] = digestHex(manifest)
	err := verifyReceiptArtifactManifests(map[string]any{
		"artifact_refs":      []any{"artifact://local/uri-test/out.md"},
		"artifact_manifests": []any{manifest},
	})
	if err == nil || !strings.Contains(err.Error(), "artifact manifest uri invalid") {
		t.Fatalf("got %v, want artifact manifest uri invalid", err)
	}
}

func TestArtifactManifestRejectsMalformedAFP(t *testing.T) {
	manifest := map[string]any{
		"uri":        "artifact://local/afp-shape-test/out.md",
		"sha256":     strings.Repeat("4", 64),
		"size":       float64(1),
		"media_type": "text/plain",
		"afp":        map[string]any{"sha256": strings.Repeat("4", 64)},
	}
	manifest["manifest_hash"] = digestHex(manifest)
	err := verifyReceiptArtifactManifests(map[string]any{
		"artifact_refs":      []any{manifest["uri"]},
		"artifact_manifests": []any{manifest},
	})
	if err == nil || !strings.Contains(err.Error(), "artifact manifest afp invalid") {
		t.Fatalf("got %v, want artifact manifest afp invalid", err)
	}
}

func TestArtifactManifestRejectsMalformedListEntries(t *testing.T) {
	manifest := map[string]any{
		"uri":        "artifact://local/list-shape-test/out.md",
		"sha256":     strings.Repeat("5", 64),
		"size":       float64(1),
		"media_type": "text/plain",
		"afp":        "afp:sha256:" + strings.Repeat("5", 64),
	}
	manifest["manifest_hash"] = digestHex(manifest)
	err := verifyReceiptArtifactManifests(map[string]any{
		"artifact_refs":      []any{manifest["uri"], map[string]any{"uri": manifest["uri"]}},
		"artifact_manifests": []any{manifest},
	})
	if err == nil || !strings.Contains(err.Error(), "artifact refs invalid") {
		t.Fatalf("got %v, want artifact refs invalid", err)
	}
}
