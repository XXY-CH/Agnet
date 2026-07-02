package agnet

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

type vectorAgent struct {
	Alias         string `json:"alias"`
	SeedHex       string `json:"seed_hex"`
	AID           string `json:"aid"`
	PublicKeySPKI string `json:"public_key_spki"`
}

type aspVector struct {
	Agents struct {
		Requester vectorAgent `json:"requester"`
		Worker    vectorAgent `json:"worker"`
	} `json:"agents"`
	TaskCanonical    string `json:"task_canonical"`
	TaskSignature    string `json:"task_signature"`
	ReceiptCanonical string `json:"receipt_canonical"`
	ReceiptSignature string `json:"receipt_signature"`
}

func publicKey(t *testing.T, encoded string) (ed25519.PublicKey, []byte) {
	t.Helper()
	der, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatal(err)
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("expected ed25519 public key, got %T", parsed)
	}
	return key, der
}

func aidFromSPKI(der []byte) string {
	hash := sha256.New()
	hash.Write([]byte("asp-agent-id-v1\x00"))
	hash.Write(der)
	return "aid:ed25519:" + base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
}

func verifySignature(t *testing.T, key ed25519.PublicKey, message string, encoded string) {
	t.Helper()
	signature, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(key, []byte(message), signature) {
		t.Fatal("signature verification failed")
	}
}

func TestASPV0Vector(t *testing.T) {
	data, err := os.ReadFile("test-vectors/asp-v0.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector aspVector
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}

	requesterKey, requesterDER := publicKey(t, vector.Agents.Requester.PublicKeySPKI)
	workerKey, workerDER := publicKey(t, vector.Agents.Worker.PublicKeySPKI)

	if got := aidFromSPKI(requesterDER); got != vector.Agents.Requester.AID {
		t.Fatalf("requester aid mismatch: %s", got)
	}
	if got := aidFromSPKI(workerDER); got != vector.Agents.Worker.AID {
		t.Fatalf("worker aid mismatch: %s", got)
	}

	verifySignature(t, requesterKey, vector.TaskCanonical, vector.TaskSignature)
	verifySignature(t, workerKey, vector.ReceiptCanonical, vector.ReceiptSignature)
}
