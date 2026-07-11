package managedkey

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

const (
	EnvelopeFormat = "agnet-key-envelope/v1"
	KeyTypePKCS8   = "ed25519-pkcs8"
	KeyTypeSeed    = "ed25519-seed"

	kdfName           = "pbkdf2-hmac-sha256"
	cipherName        = "aes-256-gcm"
	defaultIterations = 600000
	minIterations     = 100000
	maxIterations     = 2000000
	derivedKeyBytes   = 32
	saltBytes         = 16
	nonceBytes        = 12
	tagBytes          = 16
	maxSecretBytes    = 1024 * 1024
)

var envelopeRandom io.Reader = rand.Reader

type Identity struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

type KDF struct {
	Name            string `json:"name"`
	Salt            string `json:"salt"`
	Iterations      int    `json:"iterations"`
	DerivedKeyBytes int    `json:"derived_key_bytes"`
}

type Cipher struct {
	Name     string `json:"name"`
	Nonce    string `json:"nonce"`
	TagBytes int    `json:"tag_bytes"`
}

type Envelope struct {
	Format     string   `json:"format"`
	KeyType    string   `json:"key_type"`
	Identity   Identity `json:"identity"`
	KDF        KDF      `json:"kdf"`
	Cipher     Cipher   `json:"cipher"`
	Ciphertext string   `json:"ciphertext"`
	Tag        string   `json:"tag"`
}

type SealOptions struct {
	KeyType    string
	Plaintext  []byte
	Identity   Identity
	Passphrase []byte
	Iterations int
}

type OpenedKey struct {
	KeyType    string
	Identity   Identity
	Plaintext  []byte
	PrivateKey ed25519.PrivateKey
}

func decodeBase64URLExact(encoded, label string) ([]byte, error) {
	if encoded == "" {
		return nil, fmt.Errorf("%s must use exact unpadded base64url", label)
	}
	for _, character := range encoded {
		if !((character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-' || character == '_') {
			return nil, fmt.Errorf("%s must use exact unpadded base64url", label)
		}
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		return nil, fmt.Errorf("%s must use exact unpadded base64url", label)
	}
	return decoded, nil
}

func ParseEnvelope(data []byte) (Envelope, error) {
	var zero Envelope
	if len(data) == 0 || len(data) > maxSecretBytes {
		return zero, errors.New("envelope bytes invalid")
	}
	decoded, err := decodeExactJSON(data)
	if err != nil {
		return zero, err
	}
	root, err := exactObject(decoded, []string{"format", "key_type", "identity", "kdf", "cipher", "ciphertext", "tag"}, "envelope")
	if err != nil {
		return zero, err
	}
	format, err := exactString(root["format"], "envelope format")
	if err != nil || format != EnvelopeFormat {
		return zero, errors.New("envelope format invalid")
	}
	keyType, err := exactString(root["key_type"], "key type")
	if err != nil || (keyType != KeyTypePKCS8 && keyType != KeyTypeSeed) {
		return zero, errors.New("key type invalid")
	}
	identityObject, err := exactObject(root["identity"], []string{"kind", "value"}, "identity")
	if err != nil {
		return zero, err
	}
	identityKind, err := exactString(identityObject["kind"], "identity kind")
	if err != nil {
		return zero, err
	}
	identityValue, err := exactString(identityObject["value"], "identity value")
	if err != nil {
		return zero, err
	}
	identity := Identity{Kind: identityKind, Value: identityValue}
	if err := validateIdentity(identity); err != nil {
		return zero, err
	}
	kdfObject, err := exactObject(root["kdf"], []string{"name", "salt", "iterations", "derived_key_bytes"}, "kdf")
	if err != nil {
		return zero, err
	}
	parsedKDF := KDF{}
	parsedKDF.Name, err = exactString(kdfObject["name"], "kdf name")
	if err != nil || parsedKDF.Name != kdfName {
		return zero, errors.New("kdf name invalid")
	}
	parsedKDF.Salt, err = exactString(kdfObject["salt"], "kdf salt")
	if err != nil {
		return zero, err
	}
	parsedKDF.Iterations, err = exactInteger(kdfObject["iterations"], "kdf iterations")
	if err != nil || parsedKDF.Iterations < minIterations || parsedKDF.Iterations > maxIterations {
		return zero, errors.New("kdf iterations invalid")
	}
	parsedKDF.DerivedKeyBytes, err = exactInteger(kdfObject["derived_key_bytes"], "kdf derived key bytes")
	if err != nil || parsedKDF.DerivedKeyBytes != derivedKeyBytes {
		return zero, errors.New("kdf derived key bytes invalid")
	}
	if salt, err := decodeBase64URLExact(parsedKDF.Salt, "kdf salt"); err != nil {
		return zero, err
	} else if len(salt) != saltBytes {
		return zero, errors.New("kdf salt length invalid")
	}
	cipherObject, err := exactObject(root["cipher"], []string{"name", "nonce", "tag_bytes"}, "cipher")
	if err != nil {
		return zero, err
	}
	parsedCipher := Cipher{}
	parsedCipher.Name, err = exactString(cipherObject["name"], "cipher name")
	if err != nil || parsedCipher.Name != cipherName {
		return zero, errors.New("cipher name invalid")
	}
	parsedCipher.Nonce, err = exactString(cipherObject["nonce"], "cipher nonce")
	if err != nil {
		return zero, err
	}
	parsedCipher.TagBytes, err = exactInteger(cipherObject["tag_bytes"], "cipher tag bytes")
	if err != nil || parsedCipher.TagBytes != tagBytes {
		return zero, errors.New("cipher tag bytes invalid")
	}
	if nonce, err := decodeBase64URLExact(parsedCipher.Nonce, "cipher nonce"); err != nil {
		return zero, err
	} else if len(nonce) != nonceBytes {
		return zero, errors.New("cipher nonce length invalid")
	}
	ciphertext, err := exactString(root["ciphertext"], "ciphertext")
	if err != nil {
		return zero, err
	}
	ciphertextBytes, err := decodeBase64URLExact(ciphertext, "ciphertext")
	if err != nil {
		return zero, err
	}
	expectedCiphertextBytes := ed25519.SeedSize
	if keyType == KeyTypePKCS8 {
		expectedCiphertextBytes = len(ed25519PKCS8Prefix) + ed25519.SeedSize
	}
	if len(ciphertextBytes) != expectedCiphertextBytes {
		return zero, errors.New("ciphertext length invalid")
	}
	tag, err := exactString(root["tag"], "tag")
	if err != nil {
		return zero, err
	}
	if tagValue, err := decodeBase64URLExact(tag, "tag"); err != nil {
		return zero, err
	} else if len(tagValue) != tagBytes {
		return zero, errors.New("tag length invalid")
	}
	return Envelope{Format: EnvelopeFormat, KeyType: keyType, Identity: identity, KDF: parsedKDF, Cipher: parsedCipher, Ciphertext: ciphertext, Tag: tag}, nil
}

func envelopeHeader(envelope Envelope) map[string]any {
	return map[string]any{
		"format":   envelope.Format,
		"key_type": envelope.KeyType,
		"identity": map[string]any{"kind": envelope.Identity.Kind, "value": envelope.Identity.Value},
		"kdf":      map[string]any{"name": envelope.KDF.Name, "salt": envelope.KDF.Salt, "iterations": envelope.KDF.Iterations, "derived_key_bytes": envelope.KDF.DerivedKeyBytes},
		"cipher":   map[string]any{"name": envelope.Cipher.Name, "nonce": envelope.Cipher.Nonce, "tag_bytes": envelope.Cipher.TagBytes},
	}
}

func envelopeValue(envelope Envelope) map[string]any {
	value := envelopeHeader(envelope)
	value["ciphertext"] = envelope.Ciphertext
	value["tag"] = envelope.Tag
	return value
}

func SealEnvelope(options SealOptions) ([]byte, error) {
	if len(options.Plaintext) == 0 || len(options.Plaintext) > maxSecretBytes {
		return nil, errors.New("key plaintext invalid")
	}
	if len(options.Passphrase) == 0 || len(options.Passphrase) > maxSecretBytes {
		return nil, errors.New("passphrase invalid")
	}
	iterations := options.Iterations
	if iterations == 0 {
		iterations = defaultIterations
	}
	if iterations < minIterations || iterations > maxIterations {
		return nil, errors.New("kdf iterations invalid")
	}
	if _, err := verifyPlaintextIdentity(options.KeyType, options.Plaintext, options.Identity); err != nil {
		return nil, err
	}
	salt := make([]byte, saltBytes)
	if _, err := io.ReadFull(envelopeRandom, salt); err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceBytes)
	if _, err := io.ReadFull(envelopeRandom, nonce); err != nil {
		return nil, err
	}
	envelope := Envelope{
		Format:   EnvelopeFormat,
		KeyType:  options.KeyType,
		Identity: options.Identity,
		KDF:      KDF{Name: kdfName, Salt: base64.RawURLEncoding.EncodeToString(salt), Iterations: iterations, DerivedKeyBytes: derivedKeyBytes},
		Cipher:   Cipher{Name: cipherName, Nonce: base64.RawURLEncoding.EncodeToString(nonce), TagBytes: tagBytes},
	}
	aad, err := canonicalJSON(envelopeHeader(envelope))
	if err != nil {
		return nil, err
	}
	derivedKey, err := pbkdf2.Key(sha256.New, string(options.Passphrase), salt, iterations, derivedKeyBytes)
	if err != nil {
		return nil, err
	}
	defer clear(derivedKey)
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	sealed := gcm.Seal(nil, nonce, options.Plaintext, aad)
	envelope.Ciphertext = base64.RawURLEncoding.EncodeToString(sealed[:len(sealed)-tagBytes])
	envelope.Tag = base64.RawURLEncoding.EncodeToString(sealed[len(sealed)-tagBytes:])
	return canonicalJSON(envelopeValue(envelope))
}

func OpenEnvelope(data, passphrase []byte) (OpenedKey, error) {
	var zero OpenedKey
	if len(passphrase) == 0 || len(passphrase) > maxSecretBytes {
		return zero, errors.New("passphrase invalid")
	}
	envelope, err := ParseEnvelope(data)
	if err != nil {
		return zero, err
	}
	salt, _ := decodeBase64URLExact(envelope.KDF.Salt, "kdf salt")
	nonce, _ := decodeBase64URLExact(envelope.Cipher.Nonce, "cipher nonce")
	ciphertext, _ := decodeBase64URLExact(envelope.Ciphertext, "ciphertext")
	tag, _ := decodeBase64URLExact(envelope.Tag, "tag")
	aad, err := canonicalJSON(envelopeHeader(envelope))
	if err != nil {
		return zero, err
	}
	derivedKey, err := pbkdf2.Key(sha256.New, string(passphrase), salt, envelope.KDF.Iterations, derivedKeyBytes)
	if err != nil {
		return zero, err
	}
	defer clear(derivedKey)
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return zero, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return zero, err
	}
	sealed := make([]byte, 0, len(ciphertext)+len(tag))
	sealed = append(sealed, ciphertext...)
	sealed = append(sealed, tag...)
	plaintext, err := gcm.Open(nil, nonce, sealed, aad)
	if err != nil {
		return zero, errors.New("envelope authentication failed")
	}
	privateKey, err := verifyPlaintextIdentity(envelope.KeyType, plaintext, envelope.Identity)
	if err != nil {
		clear(plaintext)
		return zero, err
	}
	return OpenedKey{KeyType: envelope.KeyType, Identity: envelope.Identity, Plaintext: plaintext, PrivateKey: privateKey}, nil
}
