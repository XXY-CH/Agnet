package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
)

func zoneDescriptor(key ed25519.PrivateKey, name string) (map[string]any, error) {
	publicKey := key.Public().(ed25519.PublicKey)
	encoded, der, err := publicKeySPKI(publicKey)
	if err != nil {
		return nil, err
	}
	return signBodyWithKey(key, map[string]any{"name": name, "zid": zidFromSPKI(der), "public_key_spki": encoded}, "zone_signature"), nil
}

func agentDescriptor(key ed25519.PrivateKey, alias string) (map[string]any, error) {
	publicKey := key.Public().(ed25519.PublicKey)
	encoded, der, err := publicKeySPKI(publicKey)
	if err != nil {
		return nil, err
	}
	return signBodyWithKey(key, map[string]any{
		"alias":           alias,
		"aid":             aidFromSPKI(der),
		"did_key":         didKeyFromPublicKey(publicKey),
		"public_key_spki": encoded,
		"transports":      []string{"go-client://local"},
		"capabilities":    []string{"summarize.text"},
		"policy":          map[string]any{},
	}, "descriptor_signature"), nil
}

func randomB64URL(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func publicKey(value map[string]any) (ed25519.PublicKey, []byte, error) {
	encoded, ok := value["public_key_spki"].(string)
	if !ok {
		return nil, nil, errors.New("missing public_key_spki")
	}
	der, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, nil, err
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, nil, err
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, nil, errors.New("expected ed25519 public key")
	}
	return key, der, nil
}

func publicKeySPKI(key ed25519.PublicKey) (string, []byte, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", nil, err
	}
	return base64.RawURLEncoding.EncodeToString(der), der, nil
}

func didKeyFromPublicKey(key ed25519.PublicKey) string {
	return "did:key:z" + base58BTCEncode(append(append([]byte{}, ed25519MultikeyPrefix...), key...))
}

func didKeyFromPublicKeySPKI(encoded string) (string, error) {
	der, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return "", err
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return "", errors.New("expected ed25519 public key")
	}
	return didKeyFromPublicKey(key), nil
}

func publicKeySPKIFromDidKey(didKey string) (string, error) {
	if !strings.HasPrefix(didKey, "did:key:z") {
		return "", errors.New("expected did:key z-base58btc value")
	}
	decoded, err := base58BTCDecode(strings.TrimPrefix(didKey, "did:key:z"))
	if err != nil {
		return "", err
	}
	if len(decoded) != 34 || !bytes.Equal(decoded[:2], ed25519MultikeyPrefix) {
		return "", errors.New("expected ed25519 did:key")
	}
	encoded, _, err := publicKeySPKI(ed25519.PublicKey(decoded[2:]))
	return encoded, err
}

func base58BTCEncode(bytesValue []byte) string {
	n := new(big.Int).SetBytes(bytesValue)
	base := big.NewInt(58)
	zero := big.NewInt(0)
	mod := new(big.Int)
	out := []byte{}
	for n.Cmp(zero) > 0 {
		n.DivMod(n, base, mod)
		out = append([]byte{base58BTCAlphabet[mod.Int64()]}, out...)
	}
	for _, b := range bytesValue {
		if b != 0 {
			break
		}
		out = append([]byte{'1'}, out...)
	}
	if len(out) == 0 {
		return "1"
	}
	return string(out)
}

func base58BTCDecode(value string) ([]byte, error) {
	n := big.NewInt(0)
	base := big.NewInt(58)
	for _, char := range value {
		index := strings.IndexRune(base58BTCAlphabet, char)
		if index < 0 {
			return nil, errors.New("invalid base58btc character")
		}
		n.Mul(n, base)
		n.Add(n, big.NewInt(int64(index)))
	}
	out := n.Bytes()
	for _, char := range value {
		if char != '1' {
			break
		}
		out = append([]byte{0}, out...)
	}
	return out, nil
}

func aidFromSPKI(der []byte) string {
	hash := sha256.New()
	hash.Write([]byte("asp-agent-id-v1\x00"))
	hash.Write(der)
	return "aid:ed25519:" + base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
}

func zidFromSPKI(der []byte) string {
	hash := sha256.New()
	hash.Write([]byte("asp-zone-id-v1\x00"))
	hash.Write(der)
	return "zid:ed25519:" + base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
}

func verifyMapSignature(key ed25519.PublicKey, value map[string]any, signatureKey string) error {
	signature, ok := value[signatureKey].(string)
	if !ok {
		return errors.New("missing " + signatureKey)
	}
	body := map[string]any{}
	for k, v := range value {
		if k != signatureKey {
			body[k] = v
		}
	}
	data, err := canonicalJSON(body)
	if err != nil {
		return err
	}
	decoded, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return err
	}
	if !ed25519.Verify(key, data, decoded) {
		return errors.New("signature verification failed")
	}
	return nil
}
