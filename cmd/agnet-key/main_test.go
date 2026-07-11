package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func cliWriteRestricted(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func cliDescriptor(t *testing.T, seed byte) (map[string]any, []byte) {
	t.Helper()
	keySeed := make([]byte, ed25519.SeedSize)
	for index := range keySeed {
		keySeed[index] = seed + byte(index)
	}
	key := ed25519.NewKeyFromSeed(keySeed)
	spki, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("asp-agent-id-v1\x00"))
	_, _ = hash.Write(spki)
	aid := "aid:ed25519:" + base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
	body := map[string]any{"aid": aid, "alias": "agent://u11/cli", "public_key_spki": base64.RawURLEncoding.EncodeToString(spki)}
	canonical, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := map[string]any{"aid": aid, "alias": "agent://u11/cli", "public_key_spki": base64.RawURLEncoding.EncodeToString(spki), "descriptor_signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, canonical))}
	return descriptor, keySeed
}

func cliZoneDescriptor(t *testing.T, seed byte) (map[string]any, []byte) {
	t.Helper()
	keySeed := make([]byte, ed25519.SeedSize)
	for index := range keySeed {
		keySeed[index] = seed + byte(index)
	}
	key := ed25519.NewKeyFromSeed(keySeed)
	spki, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("asp-zone-id-v1\x00"))
	_, _ = hash.Write(spki)
	zid := "zid:ed25519:" + base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
	body := map[string]any{"zid": zid, "name": "zone://u12/cli", "public_key_spki": base64.RawURLEncoding.EncodeToString(spki)}
	canonical, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	body["zone_signature"] = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, canonical))
	return body, keySeed
}

func cliRun(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	err := run(args, &stdout, &stderr)
	return stdout.String(), stderr.String(), err
}

func cliResult(t *testing.T, stdout string) map[string]any {
	t.Helper()
	var result map[string]any
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatal(err)
	}
	if len(result) != 6 {
		t.Fatalf("unsafe stdout fields: %v", result)
	}
	for _, name := range []string{"operation", "identity_kind", "identity_value", "generation", "record_digest", "envelope_sha256"} {
		if _, ok := result[name]; !ok {
			t.Fatalf("missing public field %s: %v", name, result)
		}
	}
	return result
}

func TestCLILifecyclePrintsOnlySafeMetadata(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "store")
	descriptor, seed := cliDescriptor(t, 7)
	keyPath := filepath.Join(dir, "key.seed")
	descriptorPath := filepath.Join(dir, "descriptor.json")
	oldPassphrasePath := filepath.Join(dir, "old-passphrase")
	newPassphrasePath := filepath.Join(dir, "new-passphrase")
	oldPassphrase := []byte("cli old passphrase\n")
	newPassphrase := []byte("cli new passphrase\n")
	cliWriteRestricted(t, keyPath, seed)
	descriptorBytes, err := json.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	cliWriteRestricted(t, descriptorPath, descriptorBytes)
	cliWriteRestricted(t, oldPassphrasePath, oldPassphrase)
	cliWriteRestricted(t, newPassphrasePath, newPassphrase)

	stdout, stderr, err := cliRun(t, "migrate", "--store", store, "--key-file", keyPath, "--key-type", "ed25519-seed", "--identity-kind", "aid", "--descriptor", descriptorPath, "--passphrase-file", oldPassphrasePath, "--iterations", "100000")
	if err != nil || stderr != "" {
		t.Fatalf("migrate stdout=%q stderr=%q err=%v", stdout, stderr, err)
	}
	migrated := cliResult(t, stdout)
	if migrated["operation"] != "migrate" || migrated["generation"] != float64(1) {
		t.Fatalf("migrated=%v", migrated)
	}

	stdout, stderr, err = cliRun(t, "rewrap", "--store", store, "--identity-kind", "aid", "--descriptor", descriptorPath, "--current-passphrase-file", oldPassphrasePath, "--new-passphrase-file", newPassphrasePath, "--iterations", "100001")
	if err != nil || stderr != "" {
		t.Fatalf("rewrap stdout=%q stderr=%q err=%v", stdout, stderr, err)
	}
	rewrapped := cliResult(t, stdout)
	if rewrapped["operation"] != "rewrap" || rewrapped["generation"] != float64(2) || rewrapped["identity_value"] != migrated["identity_value"] {
		t.Fatalf("rewrapped=%v migrated=%v", rewrapped, migrated)
	}

	if err := os.Remove(filepath.Join(store, "active.json")); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, err = cliRun(t, "recover", "--store", store, "--passphrase-file", newPassphrasePath)
	if err != nil || stderr != "" {
		t.Fatalf("recover stdout=%q stderr=%q err=%v", stdout, stderr, err)
	}
	recovered := cliResult(t, stdout)
	if recovered["operation"] != "recover" || recovered["generation"] != float64(2) || recovered["record_digest"] != rewrapped["record_digest"] {
		t.Fatalf("recovered=%v rewrapped=%v", recovered, rewrapped)
	}
	for _, secret := range []string{string(seed), string(oldPassphrase), string(newPassphrase)} {
		if bytes.Contains([]byte(stdout), []byte(secret)) || bytes.Contains([]byte(stderr), []byte(secret)) {
			t.Fatal("secret emitted")
		}
	}
}

func TestRotateCLIUsesExactAgentAndZoneStores(t *testing.T) {
	dir := t.TempDir()
	agentStore := filepath.Join(dir, "agent-store")
	zoneStore := filepath.Join(dir, "zone-store")
	agentDescriptor, agentSeed := cliDescriptor(t, 80)
	zoneDescriptor, zoneSeed := cliZoneDescriptor(t, 120)
	agentKeyPath := filepath.Join(dir, "agent.seed")
	zoneKeyPath := filepath.Join(dir, "zone.seed")
	agentDescriptorPath := filepath.Join(dir, "agent.json")
	zoneDescriptorPath := filepath.Join(dir, "zone.json")
	agentPassphrasePath := filepath.Join(dir, "agent.pass")
	zonePassphrasePath := filepath.Join(dir, "zone.pass")
	cliWriteRestricted(t, agentKeyPath, agentSeed)
	cliWriteRestricted(t, zoneKeyPath, zoneSeed)
	agentData, err := json.Marshal(agentDescriptor)
	if err != nil {
		t.Fatal(err)
	}
	zoneData, err := json.Marshal(zoneDescriptor)
	if err != nil {
		t.Fatal(err)
	}
	cliWriteRestricted(t, agentDescriptorPath, agentData)
	cliWriteRestricted(t, zoneDescriptorPath, zoneData)
	cliWriteRestricted(t, agentPassphrasePath, []byte("agent cli rotation pass\n"))
	cliWriteRestricted(t, zonePassphrasePath, []byte("zone cli rotation pass\n"))
	for _, args := range [][]string{
		{"migrate", "--store", agentStore, "--key-file", agentKeyPath, "--key-type", "ed25519-seed", "--identity-kind", "aid", "--descriptor", agentDescriptorPath, "--passphrase-file", agentPassphrasePath, "--iterations", "100000"},
		{"migrate", "--store", zoneStore, "--key-file", zoneKeyPath, "--key-type", "ed25519-seed", "--identity-kind", "zid", "--descriptor", zoneDescriptorPath, "--passphrase-file", zonePassphrasePath, "--iterations", "100000"},
	} {
		stdout, stderr, err := cliRun(t, args...)
		if err != nil || stderr != "" || stdout == "" {
			t.Fatalf("args=%v stdout=%q stderr=%q err=%v", args, stdout, stderr, err)
		}
	}
	stdout, stderr, err := cliRun(t, "rotate", "--store", agentStore, "--passphrase-file", agentPassphrasePath, "--zone-store", zoneStore, "--zone-passphrase-file", zonePassphrasePath, "--iterations", "100000")
	if err != nil || stderr != "" {
		t.Fatalf("rotate stdout=%q stderr=%q err=%v", stdout, stderr, err)
	}
	rotated := cliResult(t, stdout)
	if rotated["operation"] != "rotate" || rotated["generation"] != float64(2) || rotated["identity_value"] == agentDescriptor["aid"] {
		t.Fatalf("rotated=%v", rotated)
	}
	for _, args := range [][]string{
		{"rotate", "--store", agentStore, "--passphrase-file", agentPassphrasePath, "--zone-store", zoneStore},
		{"rotate", "--store", zoneStore, "--passphrase-file", zonePassphrasePath, "--zone-store", zoneStore, "--zone-passphrase-file", zonePassphrasePath},
	} {
		stdout, stderr, err := cliRun(t, args...)
		if err == nil || stdout != "" || stderr != "" {
			t.Fatalf("unsafe rotate accepted args=%v", args)
		}
	}
}

func TestCLIRejectsUnknownAndInlinePassphraseWithoutEmission(t *testing.T) {
	secret := "not-for-output"
	for _, args := range [][]string{
		{"migrate", "--passphrase", secret},
		{"migrate", "--unknown", secret},
		{"recover", "--store", "x", "--passphrase-file", "y", "unexpected"},
	} {
		stdout, stderr, err := cliRun(t, args...)
		if err == nil || stdout != "" || bytes.Contains([]byte(stderr), []byte(secret)) || bytes.Contains([]byte(err.Error()), []byte(secret)) {
			t.Fatalf("args=%v stdout=%q stderr=%q err=%v", args, stdout, stderr, err)
		}
	}
}

func TestCLIRejectsBadTypePassphraseDescriptorKDFAndUnsafeFiles(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "store")
	descriptor, seed := cliDescriptor(t, 11)
	otherDescriptor, _ := cliDescriptor(t, 12)
	keyPath := filepath.Join(dir, "key.seed")
	descriptorPath := filepath.Join(dir, "descriptor.json")
	otherDescriptorPath := filepath.Join(dir, "other-descriptor.json")
	passphrasePath := filepath.Join(dir, "passphrase")
	newPassphrasePath := filepath.Join(dir, "new-passphrase")
	cliWriteRestricted(t, keyPath, seed)
	data, err := json.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	cliWriteRestricted(t, descriptorPath, data)
	data, err = json.Marshal(otherDescriptor)
	if err != nil {
		t.Fatal(err)
	}
	cliWriteRestricted(t, otherDescriptorPath, data)
	cliWriteRestricted(t, passphrasePath, []byte("correct passphrase\n"))
	cliWriteRestricted(t, newPassphrasePath, []byte("new passphrase\n"))
	valid := []string{"migrate", "--store", store, "--key-file", keyPath, "--key-type", "ed25519-seed", "--identity-kind", "aid", "--descriptor", descriptorPath, "--passphrase-file", passphrasePath, "--iterations", "100000"}

	for _, args := range [][]string{
		{"migrate", "--store", store, "--key-file", keyPath, "--key-type", "unknown-key", "--identity-kind", "aid", "--descriptor", descriptorPath, "--passphrase-file", passphrasePath},
		{"migrate", "--store", store, "--key-file", keyPath, "--key-type", "ed25519-seed", "--identity-kind", "aid", "--descriptor", descriptorPath, "--passphrase-file", passphrasePath, "--iterations", "99999"},
		{"migrate", "--store", store, "--key-file", keyPath, "--key-type", "ed25519-seed", "--identity-kind", "aid", "--descriptor", otherDescriptorPath, "--passphrase-file", passphrasePath},
	} {
		stdout, stderr, err := cliRun(t, args...)
		if err == nil || stdout != "" || stderr != "" {
			t.Fatalf("args=%v stdout=%q stderr=%q err=%v", args, stdout, stderr, err)
		}
	}
	if err := os.Chmod(passphrasePath, 0o644); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, err := cliRun(t, valid...)
	if err == nil || stdout != "" || stderr != "" {
		t.Fatalf("unsafe passphrase stdout=%q stderr=%q err=%v", stdout, stderr, err)
	}
	if err := os.Chmod(passphrasePath, 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, err = cliRun(t, valid...)
	if err != nil || stdout == "" || stderr != "" {
		t.Fatalf("migrate stdout=%q stderr=%q err=%v", stdout, stderr, err)
	}
	cliWriteRestricted(t, passphrasePath, []byte("wrong passphrase\n"))
	stdout, stderr, err = cliRun(t, "rewrap", "--store", store, "--identity-kind", "aid", "--descriptor", descriptorPath, "--current-passphrase-file", passphrasePath, "--new-passphrase-file", newPassphrasePath)
	if err == nil || stdout != "" || stderr != "" {
		t.Fatalf("wrong passphrase stdout=%q stderr=%q err=%v", stdout, stderr, err)
	}
	cliWriteRestricted(t, passphrasePath, []byte("correct passphrase\n"))
	stdout, stderr, err = cliRun(t, "rewrap", "--store", store, "--identity-kind", "aid", "--descriptor", otherDescriptorPath, "--current-passphrase-file", passphrasePath, "--new-passphrase-file", newPassphrasePath)
	if err == nil || stdout != "" || stderr != "" {
		t.Fatalf("descriptor mismatch stdout=%q stderr=%q err=%v", stdout, stderr, err)
	}
}
