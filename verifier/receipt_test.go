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

	receipt := vector.Frame["receipt"].(map[string]any)
	receipt["executing_zone"] = "zid:ed25519:bad"
	if err := VerifyFederatedReceipt(vector.Frame, trusted); err == nil || !strings.Contains(err.Error(), "receipt executing_zone mismatch") {
		t.Fatalf("got %v, want receipt executing_zone mismatch", err)
	}
}
