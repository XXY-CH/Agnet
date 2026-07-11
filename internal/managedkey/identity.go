package managedkey

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
)

const (
	IdentityAID = "aid"
	IdentityZID = "zid"
)

var ed25519PKCS8Prefix = []byte{0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20}

func privateKeyForPlaintext(keyType string, plaintext []byte) (ed25519.PrivateKey, error) {
	switch keyType {
	case KeyTypeSeed:
		if len(plaintext) != ed25519.SeedSize {
			return nil, errors.New("seed plaintext length invalid")
		}
		return ed25519.NewKeyFromSeed(plaintext), nil
	case KeyTypePKCS8:
		if len(plaintext) != len(ed25519PKCS8Prefix)+ed25519.SeedSize || !bytes.Equal(plaintext[:len(ed25519PKCS8Prefix)], ed25519PKCS8Prefix) {
			return nil, errors.New("PKCS8 plaintext invalid")
		}
		parsed, err := x509.ParsePKCS8PrivateKey(plaintext)
		if err != nil {
			return nil, errors.New("PKCS8 plaintext invalid")
		}
		privateKey, ok := parsed.(ed25519.PrivateKey)
		if !ok || len(privateKey) != ed25519.PrivateKeySize {
			return nil, errors.New("PKCS8 plaintext invalid")
		}
		exported, err := x509.MarshalPKCS8PrivateKey(privateKey)
		if err != nil || !bytes.Equal(exported, plaintext) {
			return nil, errors.New("PKCS8 plaintext invalid")
		}
		return append(ed25519.PrivateKey(nil), privateKey...), nil
	default:
		return nil, errors.New("key type invalid")
	}
}

func identityForPlaintext(keyType string, plaintext []byte, kind string) (Identity, ed25519.PrivateKey, error) {
	privateKey, err := privateKeyForPlaintext(keyType, plaintext)
	if err != nil {
		return Identity{}, nil, err
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	spki, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return Identity{}, nil, err
	}
	var domain, prefix string
	switch kind {
	case IdentityAID:
		domain = "asp-agent-id-v1\x00"
		prefix = "aid:ed25519:"
	case IdentityZID:
		domain = "asp-zone-id-v1\x00"
		prefix = "zid:ed25519:"
	default:
		return Identity{}, nil, errors.New("identity kind invalid")
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(domain))
	_, _ = hash.Write(spki)
	return Identity{Kind: kind, Value: prefix + base64.RawURLEncoding.EncodeToString(hash.Sum(nil))}, privateKey, nil
}

func validateIdentity(identity Identity) error {
	var prefix string
	switch identity.Kind {
	case IdentityAID:
		prefix = "aid:ed25519:"
	case IdentityZID:
		prefix = "zid:ed25519:"
	default:
		return errors.New("identity kind invalid")
	}
	if len(identity.Value) <= len(prefix) || identity.Value[:len(prefix)] != prefix {
		return errors.New("identity value invalid")
	}
	digest, err := decodeBase64URLExact(identity.Value[len(prefix):], "identity value")
	if err != nil || len(digest) != sha256.Size {
		return errors.New("identity value invalid")
	}
	return nil
}

func verifyPlaintextIdentity(keyType string, plaintext []byte, identity Identity) (ed25519.PrivateKey, error) {
	if err := validateIdentity(identity); err != nil {
		return nil, err
	}
	reconstructed, privateKey, err := identityForPlaintext(keyType, plaintext, identity.Kind)
	if err != nil {
		return nil, err
	}
	if reconstructed != identity {
		return nil, fmt.Errorf("key identity mismatch")
	}
	return privateKey, nil
}
