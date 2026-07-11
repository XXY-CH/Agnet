package managedkey

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var testPassphrase = []byte("u8 deterministic passphrase <>&\n")

func testSeed(start byte) []byte {
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = start + byte(index)
	}
	return seed
}

func testPKCS8(seed []byte) []byte {
	prefix, _ := hex.DecodeString("302e020100300506032b657004220420")
	return append(prefix, seed...)
}

func mutateEnvelopeJSON(t *testing.T, data []byte, mutate func(map[string]any)) []byte {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	mutate(value)
	out, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func nonCanonicalBase64URL(value string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := strings.IndexByte(alphabet, value[len(value)-1])
	return value[:len(value)-1] + string(alphabet[(last&0b111100)|0b000001])
}

func TestEnvelopeRoundTripsPKCS8AndSeed(t *testing.T) {
	for _, test := range []struct {
		name      string
		keyType   string
		plaintext []byte
		kind      string
	}{
		{name: "pkcs8 agent", keyType: KeyTypePKCS8, plaintext: testPKCS8(testSeed(0)), kind: IdentityAID},
		{name: "seed zone", keyType: KeyTypeSeed, plaintext: testSeed(64), kind: IdentityZID},
	} {
		t.Run(test.name, func(t *testing.T) {
			identity, _, err := identityForPlaintext(test.keyType, test.plaintext, test.kind)
			if err != nil {
				t.Fatal(err)
			}
			envelopeBytes, err := SealEnvelope(SealOptions{KeyType: test.keyType, Plaintext: test.plaintext, Identity: identity, Passphrase: testPassphrase, Iterations: 100000})
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParseEnvelope(envelopeBytes)
			if err != nil {
				t.Fatal(err)
			}
			if parsed.Format != EnvelopeFormat || parsed.KeyType != test.keyType || parsed.Identity != identity {
				t.Fatalf("parsed=%+v", parsed)
			}
			opened, err := OpenEnvelope(envelopeBytes, testPassphrase)
			if err != nil {
				t.Fatal(err)
			}
			if opened.KeyType != test.keyType || opened.Identity != identity || !bytes.Equal(opened.Plaintext, test.plaintext) || len(opened.PrivateKey) != ed25519.PrivateKeySize {
				t.Fatalf("opened=%+v", opened)
			}
		})
	}
}

func TestEnvelopeParserBoundsNestingAndEntries(t *testing.T) {
	deep := strings.Repeat(`{"x":`, maxExactJSONDepth+1) + `0` + strings.Repeat(`}`, maxExactJSONDepth+1)
	if _, err := ParseEnvelope([]byte(deep)); err == nil || !strings.Contains(err.Error(), "JSON nesting limit exceeded") {
		t.Fatalf("nesting error=%v", err)
	}
	many := `[` + strings.Repeat(`null,`, maxExactJSONEntries) + `null]`
	if _, err := ParseEnvelope([]byte(many)); err == nil || !strings.Contains(err.Error(), "JSON entry limit exceeded") {
		t.Fatalf("entry error=%v", err)
	}
}

func TestEnvelopeRejectsExactSchemaAndCryptoMutations(t *testing.T) {
	seed := testSeed(96)
	identity, _, err := identityForPlaintext(KeyTypeSeed, seed, IdentityAID)
	if err != nil {
		t.Fatal(err)
	}
	envelopeBytes, err := SealEnvelope(SealOptions{KeyType: KeyTypeSeed, Plaintext: seed, Identity: identity, Passphrase: testPassphrase, Iterations: 100000})
	if err != nil {
		t.Fatal(err)
	}
	duplicate := bytes.Replace(envelopeBytes, []byte(`"format":`), []byte(`"format":"agnet-key-envelope/v1","format":`), 1)
	if _, err := ParseEnvelope(duplicate); err == nil || !strings.Contains(err.Error(), "duplicate JSON key: format") {
		t.Fatalf("duplicate error=%v", err)
	}
	nestedDuplicate := bytes.Replace(envelopeBytes, []byte(`"kind":"aid"`), []byte(`"kind":"aid","kind":"aid"`), 1)
	if _, err := ParseEnvelope(nestedDuplicate); err == nil || !strings.Contains(err.Error(), "duplicate JSON key: kind") {
		t.Fatalf("nested duplicate error=%v", err)
	}
	if _, err := ParseEnvelope(envelopeBytes[:len(envelopeBytes)-1]); err == nil {
		t.Fatal("truncated envelope accepted")
	}
	for _, test := range []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{name: "unknown top", mutate: func(value map[string]any) { value["extra"] = true }, want: "envelope fields invalid"},
		{name: "unknown identity", mutate: func(value map[string]any) { value["identity"].(map[string]any)["extra"] = true }, want: "identity fields invalid"},
		{name: "unknown kdf", mutate: func(value map[string]any) { value["kdf"].(map[string]any)["extra"] = true }, want: "kdf fields invalid"},
		{name: "unknown cipher", mutate: func(value map[string]any) { value["cipher"].(map[string]any)["extra"] = true }, want: "cipher fields invalid"},
		{name: "format", mutate: func(value map[string]any) { value["format"] = "agnet-key-envelope/v2" }, want: "envelope format invalid"},
		{name: "key type", mutate: func(value map[string]any) { value["key_type"] = KeyTypePKCS8 }, want: "ciphertext length invalid"},
		{name: "identity kind", mutate: func(value map[string]any) { value["identity"].(map[string]any)["kind"] = IdentityZID }, want: "identity value invalid"},
		{name: "identity value", mutate: func(value map[string]any) {
			value["identity"].(map[string]any)["value"] = "aid:ed25519:" + strings.Repeat("A", 43)
		}, want: "authentication failed"},
		{name: "kdf name", mutate: func(value map[string]any) { value["kdf"].(map[string]any)["name"] = "pbkdf2-sha1" }, want: "kdf name invalid"},
		{name: "padded salt", mutate: func(value map[string]any) {
			value["kdf"].(map[string]any)["salt"] = value["kdf"].(map[string]any)["salt"].(string) + "="
		}, want: "exact unpadded base64url"},
		{name: "noncanonical salt", mutate: func(value map[string]any) {
			value["kdf"].(map[string]any)["salt"] = nonCanonicalBase64URL(value["kdf"].(map[string]any)["salt"].(string))
		}, want: "exact unpadded base64url"},
		{name: "short salt", mutate: func(value map[string]any) { value["kdf"].(map[string]any)["salt"] = "AA" }, want: "salt length invalid"},
		{name: "low iterations", mutate: func(value map[string]any) { value["kdf"].(map[string]any)["iterations"] = float64(99999) }, want: "iterations invalid"},
		{name: "high iterations", mutate: func(value map[string]any) { value["kdf"].(map[string]any)["iterations"] = float64(2000001) }, want: "iterations invalid"},
		{name: "derived key bytes", mutate: func(value map[string]any) { value["kdf"].(map[string]any)["derived_key_bytes"] = float64(31) }, want: "derived key bytes invalid"},
		{name: "cipher name", mutate: func(value map[string]any) { value["cipher"].(map[string]any)["name"] = "aes-128-gcm" }, want: "cipher name invalid"},
		{name: "short nonce", mutate: func(value map[string]any) { value["cipher"].(map[string]any)["nonce"] = "AA" }, want: "nonce length invalid"},
		{name: "tag bytes", mutate: func(value map[string]any) { value["cipher"].(map[string]any)["tag_bytes"] = float64(12) }, want: "tag bytes invalid"},
		{name: "short tag", mutate: func(value map[string]any) { value["tag"] = "AA" }, want: "tag length invalid"},
		{name: "truncated ciphertext", mutate: func(value map[string]any) {
			encoded := value["ciphertext"].(string)
			decoded, _ := base64.RawURLEncoding.DecodeString(encoded)
			value["ciphertext"] = base64.RawURLEncoding.EncodeToString(decoded[1:])
		}, want: "ciphertext length invalid"},
		{name: "ciphertext content", mutate: func(value map[string]any) {
			encoded := value["ciphertext"].(string)
			decoded, _ := base64.RawURLEncoding.DecodeString(encoded)
			decoded[0] ^= 1
			value["ciphertext"] = base64.RawURLEncoding.EncodeToString(decoded)
		}, want: "authentication failed"},
		{name: "tag content", mutate: func(value map[string]any) {
			encoded := value["tag"].(string)
			decoded, _ := base64.RawURLEncoding.DecodeString(encoded)
			decoded[0] ^= 1
			value["tag"] = base64.RawURLEncoding.EncodeToString(decoded)
		}, want: "authentication failed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := mutateEnvelopeJSON(t, envelopeBytes, test.mutate)
			if _, err := OpenEnvelope(candidate, testPassphrase); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v want=%q", err, test.want)
			}
		})
	}
	if _, err := OpenEnvelope(envelopeBytes, []byte("wrong")); err == nil || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("wrong passphrase error=%v", err)
	}
	for _, size := range []int{31, 33} {
		if _, err := SealEnvelope(SealOptions{KeyType: KeyTypeSeed, Plaintext: make([]byte, size), Identity: identity, Passphrase: testPassphrase, Iterations: 100000}); err == nil || !strings.Contains(err.Error(), "seed plaintext length invalid") {
			t.Fatalf("seed size %d error=%v", size, err)
		}
	}
	if _, err := SealEnvelope(SealOptions{KeyType: KeyTypePKCS8, Plaintext: make([]byte, 48), Identity: identity, Passphrase: testPassphrase, Iterations: 100000}); err == nil || !strings.Contains(err.Error(), "PKCS8 plaintext invalid") {
		t.Fatalf("invalid PKCS8 error=%v", err)
	}
}

type envelopeVector struct {
	Format string `json:"format"`
	Cases  []struct {
		Origin            string   `json:"origin"`
		KeyType           string   `json:"key_type"`
		Identity          Identity `json:"identity"`
		Passphrase        string   `json:"passphrase"`
		Plaintext         string   `json:"plaintext"`
		EnvelopeCanonical string   `json:"envelope_canonical"`
		AADCanonical      string   `json:"aad_canonical"`
		AADSHA256         string   `json:"aad_sha256"`
	} `json:"cases"`
}

func TestEnvelopeFrozenNodeAndGoVectorsCrossOpen(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "test-vectors", "agnet-key-envelope-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector envelopeVector
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	if vector.Format != "agnet-key-envelope-test-v1" {
		t.Fatalf("format=%s", vector.Format)
	}
	if len(vector.Cases) != 2 || vector.Cases[0].Origin != "node-created" || vector.Cases[1].Origin != "go-created" {
		t.Fatalf("vector origins invalid: %+v", vector.Cases)
	}
	for _, item := range vector.Cases {
		t.Run(item.Origin, func(t *testing.T) {
			passphrase, err := base64.RawURLEncoding.DecodeString(item.Passphrase)
			if err != nil {
				t.Fatal(err)
			}
			opened, err := OpenEnvelope([]byte(item.EnvelopeCanonical), passphrase)
			if err != nil {
				t.Fatal(err)
			}
			envelope, err := ParseEnvelope([]byte(item.EnvelopeCanonical))
			if err != nil {
				t.Fatal(err)
			}
			aad, err := canonicalJSON(envelopeHeader(envelope))
			if err != nil {
				t.Fatal(err)
			}
			if string(aad) != item.AADCanonical {
				t.Fatalf("AAD canonical mismatch")
			}
			plaintext, err := base64.RawURLEncoding.DecodeString(item.Plaintext)
			if err != nil {
				t.Fatal(err)
			}
			if item.KeyType != opened.KeyType || item.Identity != opened.Identity || !bytes.Equal(plaintext, opened.Plaintext) {
				t.Fatalf("opened=%+v", opened)
			}
			hash := sha256.Sum256([]byte(item.AADCanonical))
			if hex.EncodeToString(hash[:]) != item.AADSHA256 {
				t.Fatalf("AAD digest mismatch")
			}
		})
	}
}
