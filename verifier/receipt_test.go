package verifier

import (
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
