package verifier

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
)

const base58BTCAlphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

var ed25519MultikeyPrefix = []byte{0xed, 0x01}

func VerifyFederatedReceipt(frame map[string]any, trusted map[string]map[string]any, signedTasks ...map[string]any) error {
	if frame["type"] != "FED_RECEIPT" {
		return errors.New("expected FED_RECEIPT frame")
	}
	zone, ok := frame["zone"].(map[string]any)
	if !ok {
		return errors.New("receipt zone missing")
	}
	if err := verifyTrustedZone(zone, trusted); err != nil {
		return err
	}
	worker, ok := frame["worker"].(map[string]any)
	if !ok {
		return errors.New("receipt worker missing")
	}
	if err := verifyAgentDescriptor(worker); err != nil {
		return err
	}
	binding, ok := frame["zone_binding"].(map[string]any)
	if !ok {
		return errors.New("receipt zone binding missing")
	}
	if err := verifyZoneBinding(zone, binding, worker); err != nil {
		return err
	}
	receipt, ok := frame["receipt"].(map[string]any)
	if !ok {
		return errors.New("receipt missing")
	}
	if receipt["executing_zone"] != zone["zid"] {
		return errors.New("receipt executing_zone mismatch")
	}
	if trusted[fmt.Sprint(receipt["origin_zone"])] == nil {
		return errors.New("untrusted receipt origin zone: " + fmt.Sprint(receipt["origin_zone"]))
	}
	if !isHexDigest(optionalString(receipt["task_digest"])) {
		return errors.New("receipt task_digest missing")
	}
	if len(signedTasks) > 0 && digestHex(signedTasks[0]) != optionalString(receipt["task_digest"]) {
		return errors.New("receipt task_digest mismatch")
	}
	if receipt["to"] != worker["aid"] {
		return errors.New("receipt worker mismatch")
	}
	workerKey, _, err := publicKey(worker)
	if err != nil {
		return err
	}
	if err := verifyMapSignature(workerKey, receipt, "signature"); err != nil {
		return errors.New("remote receipt signature verification failed")
	}
	return verifyReceiptArtifactManifests(receipt)
}

func verifyTrustedZone(zone map[string]any, trusted map[string]map[string]any) error {
	if err := verifyZoneDescriptor(zone); err != nil {
		return err
	}
	known := trusted[fmt.Sprint(zone["zid"])]
	if known == nil || known["public_key_spki"] != zone["public_key_spki"] {
		return errors.New("untrusted zone: " + fmt.Sprint(zone["zid"]))
	}
	return nil
}

func verifyZoneDescriptor(zone map[string]any) error {
	key, der, err := publicKey(zone)
	if err != nil {
		return err
	}
	if zidFromSPKI(der) != zone["zid"] {
		return errors.New("zone id mismatch")
	}
	return verifyMapSignature(key, zone, "zone_signature")
}

func verifyAgentDescriptor(agent map[string]any) error {
	key, der, err := publicKey(agent)
	if err != nil {
		return err
	}
	if aidFromSPKI(der) != agent["aid"] {
		return errors.New("agent id mismatch")
	}
	if didKey := optionalString(agent["did_key"]); didKey != "" {
		expected, err := didKeyFromPublicKeySPKI(optionalString(agent["public_key_spki"]))
		if err != nil {
			return err
		}
		if didKey != expected {
			return errors.New("agent did:key mismatch")
		}
	}
	return verifyMapSignature(key, agent, "descriptor_signature")
}

func verifyZoneBinding(zone, binding, worker map[string]any) error {
	zoneKey, _, err := publicKey(zone)
	if err != nil {
		return err
	}
	if binding["zone"] != zone["zid"] || binding["alias"] != worker["alias"] || binding["aid"] != worker["aid"] {
		return errors.New("zone binding mismatch")
	}
	if err := verifyMapSignature(zoneKey, binding, "signature"); err != nil {
		return errors.New("zone binding signature verification failed")
	}
	return nil
}

func isHexDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') {
			continue
		}
		return false
	}
	return true
}

func verifyReceiptArtifactManifests(receipt map[string]any) error {
	raw, ok := receipt["artifact_manifests"]
	if !ok {
		return nil
	}
	refs, err := artifactRefsFromAny(receipt["artifact_refs"])
	if err != nil {
		return err
	}
	manifests, err := artifactManifestsFromAny(raw)
	if err != nil {
		return err
	}
	if len(refs) != len(manifests) {
		return errors.New("receipt artifact manifest count mismatch")
	}
	for index, manifest := range manifests {
		if _, ok := manifest["uri"].(string); !ok {
			return errors.New("artifact manifest uri invalid")
		}
		if manifest["uri"] != refs[index] {
			return errors.New("artifact manifest uri mismatch")
		}
		for _, field := range []string{"sha256", "media_type", "manifest_hash"} {
			if fmt.Sprint(manifest[field]) == "" {
				return errors.New("artifact manifest " + field + " missing")
			}
		}
		if _, ok := manifest["media_type"].(string); !ok {
			return errors.New("artifact manifest media_type invalid")
		}
		if _, ok := manifest["manifest_hash"].(string); !ok {
			return errors.New("artifact manifest manifest_hash invalid")
		}
		if !isHexDigest(fmt.Sprint(manifest["sha256"])) {
			return errors.New("artifact manifest sha256 invalid")
		}
		if afp, ok := manifest["afp"]; ok {
			afpText, ok := afp.(string)
			if !ok {
				return errors.New("artifact manifest afp invalid")
			}
			if afpText != "afp:sha256:"+fmt.Sprint(manifest["sha256"]) {
				return errors.New("artifact manifest afp mismatch")
			}
		}
		size, ok := manifest["size"].(float64)
		if !ok {
			return errors.New("artifact manifest size missing")
		}
		if size < 0 || size != math.Trunc(size) {
			return errors.New("artifact manifest size invalid")
		}
		body := map[string]any{}
		for k, v := range manifest {
			if k != "manifest_hash" {
				body[k] = v
			}
		}
		if manifest["manifest_hash"] != digestHex(body) {
			return errors.New("artifact manifest hash mismatch")
		}
	}
	return nil
}

func artifactRefsFromAny(value any) ([]string, error) {
	if value == nil {
		return nil, nil
	}
	if typed, ok := value.([]string); ok {
		return typed, nil
	}
	items, ok := value.([]any)
	if !ok {
		return nil, errors.New("receipt artifact manifest count mismatch")
	}
	out := []string{}
	for _, item := range items {
		text, ok := item.(string)
		if !ok {
			return nil, errors.New("artifact refs invalid")
		}
		out = append(out, text)
	}
	return out, nil
}

func artifactManifestsFromAny(value any) ([]map[string]any, error) {
	if value == nil {
		return nil, nil
	}
	if typed, ok := value.([]map[string]any); ok {
		return typed, nil
	}
	items, ok := value.([]any)
	if !ok {
		return nil, errors.New("receipt artifact manifest count mismatch")
	}
	out := []map[string]any{}
	for _, item := range items {
		entry, ok := item.(map[string]any)
		if !ok {
			return nil, errors.New("artifact manifest missing")
		}
		out = append(out, entry)
	}
	return out, nil
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

func stringsFromAny(value any) []string {
	items, _ := value.([]any)
	out := []string{}
	for _, item := range items {
		if text, ok := item.(string); ok {
			out = append(out, text)
		}
	}
	return out
}

func mapsFromAny(value any) []map[string]any {
	if typed, ok := value.([]map[string]any); ok {
		return typed
	}
	items, _ := value.([]any)
	out := []map[string]any{}
	for _, item := range items {
		if entry, ok := item.(map[string]any); ok {
			out = append(out, entry)
		}
	}
	return out
}

func optionalString(value any) string {
	text, _ := value.(string)
	return text
}

func digestHex(value any) string {
	data, _ := canonicalJSON(value)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func canonicalJSON(value any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
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
	return "did:key:z" + base58BTCEncode(append(append([]byte{}, ed25519MultikeyPrefix...), key...)), nil
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
