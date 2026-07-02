package agnet

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

func canonicalJSON(t *testing.T, value map[string]any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func without(value map[string]any, key string) map[string]any {
	out := make(map[string]any, len(value)-1)
	for k, v := range value {
		if k != key {
			out[k] = v
		}
	}
	return out
}

func publicKeyFromMap(t *testing.T, value map[string]any) (ed25519.PublicKey, []byte) {
	t.Helper()
	encoded, ok := value["public_key_spki"].(string)
	if !ok {
		t.Fatal("missing public_key_spki")
	}
	return publicKey(t, encoded)
}

func zidFromSPKI(der []byte) string {
	hash := sha256.New()
	hash.Write([]byte("asp-zone-id-v1\x00"))
	hash.Write(der)
	return "zid:ed25519:" + base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
}

func verifyEncodedSignature(t *testing.T, key ed25519.PublicKey, body []byte, encoded string) {
	t.Helper()
	signature, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(key, body, signature) {
		t.Fatalf("signature verification failed for %s", string(body))
	}
}

func TestASPV15CapabilityCredentialVector(t *testing.T) {
	data, err := os.ReadFile("test-vectors/asp-v1.5-capability-credential.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Authority  map[string]any `json:"authority"`
		Worker     map[string]any `json:"worker"`
		Credential map[string]any `json:"credential"`
	}
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}

	authorityKey, authorityDER := publicKeyFromMap(t, vector.Authority)
	workerKey, workerDER := publicKeyFromMap(t, vector.Worker)

	if got := zidFromSPKI(authorityDER); got != vector.Authority["zid"] {
		t.Fatalf("authority zid mismatch: %s", got)
	}
	if got := aidFromSPKI(workerDER); got != vector.Worker["aid"] {
		t.Fatalf("worker aid mismatch: %s", got)
	}

	verifyEncodedSignature(
		t,
		authorityKey,
		canonicalJSON(t, without(vector.Authority, "zone_signature")),
		vector.Authority["zone_signature"].(string),
	)
	verifyEncodedSignature(
		t,
		workerKey,
		canonicalJSON(t, without(vector.Worker, "descriptor_signature")),
		vector.Worker["descriptor_signature"].(string),
	)

	if vector.Credential["issuer"] != vector.Authority["zid"] {
		t.Fatal("credential issuer does not match authority")
	}
	if vector.Credential["subject"] != vector.Worker["aid"] {
		t.Fatal("credential subject does not match worker")
	}
	verifyEncodedSignature(
		t,
		authorityKey,
		canonicalJSON(t, without(vector.Credential, "signature")),
		vector.Credential["signature"].(string),
	)
}
