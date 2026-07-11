//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package verifier

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

const testTrustInputMaxBytes = 1024 * 1024

type trustFixture struct {
	zoneKey      ed25519.PrivateKey
	verifierKey  ed25519.PrivateKey
	zone         map[string]any
	verifier     map[string]any
	allowlist    map[string]any
	trustedZones map[string]any
	revocations  map[string]any
}

func newTrustFixture(t *testing.T) trustFixture {
	t.Helper()
	zonePub, zoneKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verifierPub, verifierKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	zone := signedDescriptor(t, zoneKey, "zone_signature", map[string]any{
		"name":            "zone://output-verifiers",
		"zid":             zidFromSPKI(spkiBytes(t, zonePub)),
		"public_key_spki": spki(t, zonePub),
	})
	verifier := signedDescriptor(t, verifierKey, "descriptor_signature", map[string]any{
		"alias":           "agent://local/output-verifier",
		"aid":             aidFromSPKI(spkiBytes(t, verifierPub)),
		"did_key":         mustDidKey(t, spki(t, verifierPub)),
		"public_key_spki": spki(t, verifierPub),
		"transports":      []any{"asp+local://output-verifier"},
		"capabilities":    []any{"self.declared.only"},
		"policy": map[string]any{
			"allow_network":  false,
			"write_prefixes": []any{"artifact://local/"},
		},
	})
	binding := signNodeCanonical(t, zoneKey, "signature", map[string]any{
		"zone":  zone["zid"],
		"alias": verifier["alias"],
		"aid":   verifier["aid"],
	})
	revocation := signNodeCanonical(t, zoneKey, "signature", map[string]any{
		"zone":    zone["zid"],
		"subject": "aid:ed25519:retired-output-verifier",
		"reason":  "retired",
	})
	return trustFixture{
		zoneKey:     zoneKey,
		verifierKey: verifierKey,
		zone:        zone,
		verifier:    verifier,
		allowlist: map[string]any{
			"format": "asp-swarm-output-verifier-allowlist/v1",
			"verifiers": []any{map[string]any{
				"descriptor":     verifier,
				"zone_binding":   binding,
				"authorizations": []any{"swarm.output.verify"},
			}},
		},
		trustedZones: map[string]any{
			"format": "asp-swarm-output-trusted-zones/v1",
			"zones":  []any{zone},
		},
		revocations: map[string]any{
			"format":      "asp-swarm-output-revocations/v1",
			"revocations": []any{revocation},
		},
	}
}

func mustDidKey(t *testing.T, spkiValue string) string {
	t.Helper()
	value, err := didKeyFromPublicKeySPKI(spkiValue)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func cloneJSONMap(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func writeSecureJSON(t *testing.T, path string, value map[string]any, raw []byte) {
	t.Helper()
	if raw == nil {
		var err error
		raw, err = json.MarshalIndent(value, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		raw = append(raw, '\n')
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeTrustFixture(t *testing.T, fixture trustFixture) TrustInputPaths {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	paths := TrustInputPaths{
		Allowlist:    filepath.Join(dir, "allowlist.json"),
		TrustedZones: filepath.Join(dir, "trusted-zones.json"),
		Revocations:  filepath.Join(dir, "revocations.json"),
	}
	writeSecureJSON(t, paths.Allowlist, fixture.allowlist, nil)
	writeSecureJSON(t, paths.TrustedZones, fixture.trustedZones, nil)
	writeSecureJSON(t, paths.Revocations, fixture.revocations, nil)
	return paths
}

func requireTrustError(t *testing.T, fixture trustFixture, mutate func(*trustFixture), contains string) {
	t.Helper()
	mutate(&fixture)
	_, err := LoadSwarmOutputTrustInputs(writeTrustFixture(t, fixture))
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(contains)) {
		t.Fatalf("got %v, want error containing %q", err, contains)
	}
}

func TestLoadSwarmOutputTrustInputsSafeSuccessAndImmutableSnapshots(t *testing.T) {
	fixture := newTrustFixture(t)
	paths := writeTrustFixture(t, fixture)
	trust, err := LoadSwarmOutputTrustInputs(paths)
	if err != nil {
		t.Fatal(err)
	}
	if len(trust.TrustInputsDigest) != 64 {
		t.Fatalf("trust digest = %q", trust.TrustInputsDigest)
	}
	fromMemory, err := NewTrustInputsForTest(fixture.allowlist, fixture.trustedZones, fixture.revocations)
	if err != nil {
		t.Fatal(err)
	}
	if trust.TrustInputsDigest != fromMemory.TrustInputsDigest {
		t.Fatalf("file digest %s != test snapshot digest %s", trust.TrustInputsDigest, fromMemory.TrustInputsDigest)
	}
	checks := []struct {
		name   string
		path   string
		format string
		value  TrustInputFileEvidence
	}{
		{"allowlist", paths.Allowlist, "asp-swarm-output-verifier-allowlist/v1", trust.Evidence.Allowlist},
		{"trusted_zones", paths.TrustedZones, "asp-swarm-output-trusted-zones/v1", trust.Evidence.TrustedZones},
		{"revocations", paths.Revocations, "asp-swarm-output-revocations/v1", trust.Evidence.Revocations},
	}
	for _, check := range checks {
		if check.value.Path != check.path || check.value.UID != uint32(os.Getuid()) || check.value.Mode != 0o600 || check.value.NLink != 1 || check.value.Device == 0 || check.value.Inode == 0 || check.value.SchemaFormat != check.format || len(check.value.SnapshotDigest) != 64 {
			t.Fatalf("%s evidence = %+v", check.name, check.value)
		}
	}

	fixture.allowlist["format"] = "mutated"
	fixture.allowlist["verifiers"].([]any)[0].(map[string]any)["descriptor"].(map[string]any)["policy"].(map[string]any)["allow_network"] = true
	if fromMemory.allowlist["format"] != "asp-swarm-output-verifier-allowlist/v1" || fromMemory.allowlist["verifiers"].([]any)[0].(map[string]any)["descriptor"].(map[string]any)["policy"].(map[string]any)["allow_network"] != false {
		t.Fatal("test snapshot retained caller-owned mutable input")
	}
}

func TestLoadSwarmOutputTrustInputsSafeOpenBoundaries(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	safe := filepath.Join(dir, "safe.json")
	writeSecureJSON(t, safe, map[string]any{"ok": true}, nil)
	value, evidence, err := SafeOpenOwnedJSON(safe)
	if err != nil {
		t.Fatal(err)
	}
	if value["ok"] != true || evidence.NLink != 1 {
		t.Fatalf("value=%v evidence=%+v", value, evidence)
	}

	symlinkPath := filepath.Join(dir, "symlink.json")
	if err := os.Symlink(safe, symlinkPath); err != nil {
		t.Fatal(err)
	}
	if _, _, err := SafeOpenOwnedJSON(symlinkPath); err == nil || (!strings.Contains(strings.ToLower(err.Error()), "no-follow") && !strings.Contains(strings.ToLower(err.Error()), "symbolic link")) {
		t.Fatalf("symlink error = %v", err)
	}

	symlinkTarget := filepath.Join(dir, "symlink-target")
	if err := os.Mkdir(symlinkTarget, 0o700); err != nil {
		t.Fatal(err)
	}
	symlinkTargetFile := filepath.Join(symlinkTarget, "input.json")
	writeSecureJSON(t, symlinkTargetFile, map[string]any{"ok": true}, nil)
	symlinkParent := filepath.Join(dir, "symlink-parent")
	if err := os.Symlink(symlinkTarget, symlinkParent); err != nil {
		t.Fatal(err)
	}
	if _, _, err := SafeOpenOwnedJSON(filepath.Join(symlinkParent, "input.json")); err == nil || !strings.Contains(strings.ToLower(err.Error()), "unsafe parent symbolic link") {
		t.Fatalf("parent symlink error = %v", err)
	}

	hardlinkPath := filepath.Join(dir, "hardlink.json")
	if err := os.Link(safe, hardlinkPath); err != nil {
		t.Fatal(err)
	}
	if _, _, err := SafeOpenOwnedJSON(safe); err == nil || !strings.Contains(strings.ToLower(err.Error()), "link count") {
		t.Fatalf("hardlink error = %v", err)
	}
	if err := os.Remove(hardlinkPath); err != nil {
		t.Fatal(err)
	}

	if _, _, err := SafeOpenOwnedJSON(dir); err == nil || !strings.Contains(strings.ToLower(err.Error()), "regular file") {
		t.Fatalf("directory error = %v", err)
	}
	if _, _, err := SafeOpenOwnedJSON("/dev/null"); err == nil || !strings.Contains(strings.ToLower(err.Error()), "regular file") {
		t.Fatalf("device error = %v", err)
	}

	nonObject := filepath.Join(dir, "non-object.json")
	writeSecureJSON(t, nonObject, nil, []byte("[]"))
	if _, _, err := SafeOpenOwnedJSON(nonObject); err == nil || !strings.Contains(strings.ToLower(err.Error()), "root must be an object") {
		t.Fatalf("non-object root error = %v", err)
	}

	if err := os.Chmod(safe, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := SafeOpenOwnedJSON(safe); err == nil || !strings.Contains(strings.ToLower(err.Error()), "mode") {
		t.Fatalf("mode error = %v", err)
	}
	if err := os.Chmod(safe, 0o600); err != nil {
		t.Fatal(err)
	}

	unsafeParent := filepath.Join(dir, "unsafe-parent")
	if err := os.Mkdir(unsafeParent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafeParent, 0o777); err != nil {
		t.Fatal(err)
	}
	unsafeChild := filepath.Join(unsafeParent, "input.json")
	writeSecureJSON(t, unsafeChild, map[string]any{"ok": true}, nil)
	if _, _, err := SafeOpenOwnedJSON(unsafeChild); err == nil || !strings.Contains(strings.ToLower(err.Error()), "unsafe parent") {
		t.Fatalf("unsafe parent error = %v", err)
	}

	oversized := filepath.Join(dir, "oversized.json")
	writeSecureJSON(t, oversized, nil, []byte(fmt.Sprintf(`{"value":"%s"}`, strings.Repeat("x", testTrustInputMaxBytes))))
	if _, _, err := SafeOpenOwnedJSON(oversized); err == nil || !strings.Contains(strings.ToLower(err.Error()), "size limit") {
		t.Fatalf("oversize error = %v", err)
	}
}

func TestLoadSwarmOutputTrustInputsFinalOpenUsesVerifiedParentHandle(t *testing.T) {
	dir := t.TempDir()
	parent := filepath.Join(dir, "parent")
	moved := filepath.Join(dir, "verified-parent")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "input.json")
	writeSecureJSON(t, path, map[string]any{"source": "verified-parent"}, nil)
	originalHook := ownedJSONAfterParentVerified
	t.Cleanup(func() { ownedJSONAfterParentVerified = originalHook })
	hookCalled := false
	ownedJSONAfterParentVerified = func() error {
		hookCalled = true
		if err := os.Rename(parent, moved); err != nil {
			return err
		}
		if err := os.Mkdir(parent, 0o700); err != nil {
			return err
		}
		writeSecureJSON(t, path, map[string]any{"source": "rebound-path"}, nil)
		return nil
	}
	value, _, err := SafeOpenOwnedJSON(path)
	if err != nil {
		t.Fatal(err)
	}
	if !hookCalled || value["source"] != "verified-parent" {
		t.Fatalf("hook=%v value=%v", hookCalled, value)
	}
}

func TestLoadSwarmOutputTrustInputsRefstatsAfterRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "input.json")
	writeSecureJSON(t, path, map[string]any{"ok": true}, nil)
	originalHook := ownedJSONAfterRead
	t.Cleanup(func() { ownedJSONAfterRead = originalHook })
	hookCalled := false
	ownedJSONAfterRead = func() error {
		hookCalled = true
		return os.Chmod(path, 0o644)
	}
	_, _, err := SafeOpenOwnedJSON(path)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "changed during read") || !hookCalled {
		t.Fatalf("hook=%v error=%v", hookCalled, err)
	}
}

func TestLoadSwarmOutputTrustInputsOwnerMismatchThroughUIDSeam(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "owner.json")
	writeSecureJSON(t, path, map[string]any{"ok": true}, nil)
	originalUID := ownedJSONCurrentUID
	t.Cleanup(func() { ownedJSONCurrentUID = originalUID })
	ownedJSONCurrentUID = func() int { return os.Getuid() + 1 }
	if _, _, err := SafeOpenOwnedJSON(path); err == nil || !strings.Contains(strings.ToLower(err.Error()), "owner mismatch") {
		t.Fatalf("owner mismatch error = %v", err)
	}
}

func injectDuplicateJSON(t *testing.T, value map[string]any, key string) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	needle := []byte(fmt.Sprintf("%q:", key))
	index := strings.Index(string(data), string(needle))
	if index < 0 {
		t.Fatalf("missing key %q", key)
	}
	start := index + len(needle)
	cursor := start
	depth := 0
	inString := false
	escaped := false
	for ; cursor < len(data); cursor++ {
		char := data[cursor]
		if inString {
			if escaped {
				escaped = false
			} else if char == '\\' {
				escaped = true
			} else if char == '"' {
				inString = false
			}
			continue
		}
		switch char {
		case '"':
			inString = true
		case '{', '[':
			depth++
		case '}', ']':
			if depth == 0 {
				goto found
			}
			depth--
		case ',':
			if depth == 0 {
				goto found
			}
		}
	}
found:
	encodedValue := strings.TrimSpace(string(data[start:cursor]))
	return []byte(fmt.Sprintf("%s%q:%s,%s", data[:index], key, encodedValue, data[index:]))
}

func TestLoadSwarmOutputTrustInputsRejectsDuplicateJSONKeysAtEveryNesting(t *testing.T) {
	cases := []struct {
		name   string
		target string
		key    string
	}{
		{"allowlist top", "allowlist", "format"},
		{"allowlist verifier", "allowlist", "authorizations"},
		{"verifier descriptor", "allowlist", "aid"},
		{"verifier policy", "allowlist", "allow_network"},
		{"zone binding", "allowlist", "zone"},
		{"trusted zones top", "trusted", "format"},
		{"zone descriptor", "trusted", "zid"},
		{"revocations top", "revocations", "format"},
		{"revocation entry", "revocations", "subject"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newTrustFixture(t)
			paths := writeTrustFixture(t, fixture)
			var target map[string]any
			var path string
			switch testCase.target {
			case "allowlist":
				target, path = fixture.allowlist, paths.Allowlist
			case "trusted":
				target, path = fixture.trustedZones, paths.TrustedZones
			default:
				target, path = fixture.revocations, paths.Revocations
			}
			writeSecureJSON(t, path, target, injectDuplicateJSON(t, target, testCase.key))
			if _, err := LoadSwarmOutputTrustInputs(paths); err == nil || !strings.Contains(strings.ToLower(err.Error()), "duplicate json key") {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestLoadSwarmOutputTrustInputsRejectsUnknownKeysAtEveryNesting(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*trustFixture)
	}{
		{"allowlist top", func(v *trustFixture) { v.allowlist["unknown"] = true }},
		{"allowlist verifier", func(v *trustFixture) { v.allowlist["verifiers"].([]any)[0].(map[string]any)["unknown"] = true }},
		{"verifier descriptor", func(v *trustFixture) {
			v.allowlist["verifiers"].([]any)[0].(map[string]any)["descriptor"].(map[string]any)["unknown"] = true
		}},
		{"verifier policy", func(v *trustFixture) {
			v.allowlist["verifiers"].([]any)[0].(map[string]any)["descriptor"].(map[string]any)["policy"].(map[string]any)["unknown"] = true
		}},
		{"zone binding", func(v *trustFixture) {
			v.allowlist["verifiers"].([]any)[0].(map[string]any)["zone_binding"].(map[string]any)["unknown"] = true
		}},
		{"trusted zones top", func(v *trustFixture) { v.trustedZones["unknown"] = true }},
		{"zone descriptor", func(v *trustFixture) { v.trustedZones["zones"].([]any)[0].(map[string]any)["unknown"] = true }},
		{"revocations top", func(v *trustFixture) { v.revocations["unknown"] = true }},
		{"revocation entry", func(v *trustFixture) { v.revocations["revocations"].([]any)[0].(map[string]any)["unknown"] = true }},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			requireTrustError(t, newTrustFixture(t), testCase.mutate, "exact schema")
		})
	}
}

func TestLoadSwarmOutputTrustInputsRejectsFormatsIdentitiesAndAuthorization(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(*trustFixture)
		contains string
	}{
		{"allowlist format", func(v *trustFixture) { v.allowlist["format"] = "wrong" }, "allowlist format"},
		{"trusted zones format", func(v *trustFixture) { v.trustedZones["format"] = "wrong" }, "trusted zones format"},
		{"revocations format", func(v *trustFixture) { v.revocations["format"] = "wrong" }, "revocations format"},
		{"duplicate verifier", func(v *trustFixture) {
			v.allowlist["verifiers"] = append(v.allowlist["verifiers"].([]any), cloneJSONMap(t, v.allowlist["verifiers"].([]any)[0].(map[string]any)))
		}, "duplicate verifier"},
		{"duplicate zone", func(v *trustFixture) {
			v.trustedZones["zones"] = append(v.trustedZones["zones"].([]any), cloneJSONMap(t, v.trustedZones["zones"].([]any)[0].(map[string]any)))
		}, "duplicate trusted zone"},
		{"duplicate revocation", func(v *trustFixture) {
			v.revocations["revocations"] = append(v.revocations["revocations"].([]any), cloneJSONMap(t, v.revocations["revocations"].([]any)[0].(map[string]any)))
		}, "duplicate revocation"},
		{"missing exact authorization", func(v *trustFixture) {
			v.allowlist["verifiers"].([]any)[0].(map[string]any)["authorizations"] = []any{"swarm.output.read"}
		}, "swarm.output.verify authorization"},
		{"revoked verifier", func(v *trustFixture) {
			v.revocations["revocations"] = []any{signNodeCanonical(t, v.zoneKey, "signature", map[string]any{"zone": v.zone["zid"], "subject": v.verifier["aid"], "reason": "revoked"})}
		}, "verifier revoked"},
		{"revoked trusted Zone", func(v *trustFixture) {
			v.revocations["revocations"] = []any{signNodeCanonical(t, v.zoneKey, "signature", map[string]any{"zone": v.zone["zid"], "subject": v.zone["zid"], "reason": "revoked"})}
		}, "trusted zone revoked"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			requireTrustError(t, newTrustFixture(t), testCase.mutate, testCase.contains)
		})
	}
}

func TestLoadSwarmOutputTrustInputsScopesRevocationsToIssuerZone(t *testing.T) {
	zoneA := newTrustFixture(t)
	zoneB := newTrustFixture(t)
	trustedZones := map[string]any{
		"format": "asp-swarm-output-trusted-zones/v1",
		"zones":  []any{zoneA.zone, zoneB.zone},
	}
	requireError := func(revocation map[string]any, contains string) {
		t.Helper()
		_, err := NewTrustInputsForTest(zoneB.allowlist, trustedZones, map[string]any{
			"format":      "asp-swarm-output-revocations/v1",
			"revocations": []any{revocation},
		})
		if err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(contains)) {
			t.Fatalf("error=%v, want %q", err, contains)
		}
	}
	signed := func(issuer trustFixture, subject, reason string) map[string]any {
		return signNodeCanonical(t, issuer.zoneKey, "signature", map[string]any{
			"zone": issuer.zone["zid"], "subject": subject, "reason": reason,
		})
	}
	requireError(signed(zoneA, zoneB.verifier["aid"].(string), "cross-zone aid"), "out-of-scope revocation")
	requireError(signed(zoneA, zoneB.verifier["alias"].(string), "cross-zone alias"), "out-of-scope revocation")
	requireError(signed(zoneA, zoneB.zone["zid"].(string), "cross-zone Zone"), "out-of-scope revocation")
	requireError(signed(zoneB, zoneB.verifier["aid"].(string), "same-zone aid"), "verifier revoked")
	requireError(signed(zoneB, zoneB.verifier["alias"].(string), "same-zone alias"), "verifier revoked")
	requireError(signed(zoneB, zoneB.zone["zid"].(string), "self-revocation"), "trusted zone revoked")
}

func TestLoadSwarmOutputTrustInputsRejectsInvalidSignatures(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(*trustFixture)
		contains string
	}{
		{"verifier descriptor", func(v *trustFixture) {
			v.allowlist["verifiers"].([]any)[0].(map[string]any)["descriptor"].(map[string]any)["descriptor_signature"] = "bad"
		}, "descriptor signature"},
		{"Zone descriptor", func(v *trustFixture) { v.trustedZones["zones"].([]any)[0].(map[string]any)["zone_signature"] = "bad" }, "zone signature"},
		{"Zone binding", func(v *trustFixture) {
			v.allowlist["verifiers"].([]any)[0].(map[string]any)["zone_binding"].(map[string]any)["signature"] = "bad"
		}, "zone binding signature"},
		{"revocation", func(v *trustFixture) { v.revocations["revocations"].([]any)[0].(map[string]any)["signature"] = "bad" }, "revocation signature"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			requireTrustError(t, newTrustFixture(t), testCase.mutate, testCase.contains)
		})
	}
}

func TestLoadSwarmOutputTrustInputsRejectsCrossNamespaceIdentityCollisions(t *testing.T) {
	fixture := newTrustFixture(t)
	makeDescriptor := func(alias string) map[string]any {
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return signedDescriptor(t, privateKey, "descriptor_signature", map[string]any{
			"alias": alias, "aid": aidFromSPKI(spkiBytes(t, publicKey)), "did_key": mustDidKey(t, spki(t, publicKey)),
			"public_key_spki": spki(t, publicKey), "transports": []any{}, "capabilities": []any{}, "policy": map[string]any{},
		})
	}
	entry := func(descriptor map[string]any) map[string]any {
		return map[string]any{
			"descriptor": descriptor,
			"zone_binding": signNodeCanonical(t, fixture.zoneKey, "signature", map[string]any{
				"zone": fixture.zone["zid"], "alias": descriptor["alias"], "aid": descriptor["aid"],
			}),
			"authorizations": []any{"swarm.output.verify"},
		}
	}
	build := func(entries ...map[string]any) error {
		values := make([]any, len(entries))
		for index, value := range entries {
			values[index] = value
		}
		_, err := NewTrustInputsForTest(
			map[string]any{"format": "asp-swarm-output-verifier-allowlist/v1", "verifiers": values},
			fixture.trustedZones,
			map[string]any{"format": "asp-swarm-output-revocations/v1", "revocations": []any{}},
		)
		return err
	}
	first := fixture.verifier
	aliasEqualsAID := makeDescriptor(first["aid"].(string))
	if err := build(entry(first), entry(aliasEqualsAID)); err == nil || !strings.Contains(strings.ToLower(err.Error()), "duplicate verifier identity") {
		t.Fatalf("alias=AID error=%v", err)
	}
	second := makeDescriptor("agent://identity/second")
	aidEqualsAlias := makeDescriptor(second["aid"].(string))
	if err := build(entry(aidEqualsAlias), entry(second)); err == nil || !strings.Contains(strings.ToLower(err.Error()), "duplicate verifier identity") {
		t.Fatalf("AID=alias error=%v", err)
	}
	selfBody := cloneJSONMap(t, fixture.verifier)
	delete(selfBody, "descriptor_signature")
	selfBody["alias"] = selfBody["aid"]
	selfDescriptor := signedDescriptor(t, fixture.verifierKey, "descriptor_signature", selfBody)
	if err := build(entry(selfDescriptor)); err == nil || !strings.Contains(strings.ToLower(err.Error()), "duplicate verifier identity") {
		t.Fatalf("self-collision error=%v", err)
	}
}
func TestU4FixedBase64URLVectorsMatchNodeDomain(t *testing.T) {
	decoded, err := decodeBase64URLExact("AA", "vector")
	if err != nil || !reflect.DeepEqual(decoded, []byte{0}) {
		t.Fatalf("decoded=%v error=%v", decoded, err)
	}
	for _, invalid := range []string{"AB", "AA==", "AA\n", "AA+/"} {
		if _, err := decodeBase64URLExact(invalid, "vector"); err == nil || !strings.Contains(strings.ToLower(err.Error()), "exact unpadded base64url") {
			t.Fatalf("input=%q error=%v", invalid, err)
		}
	}
}

func TestU4FixedCanonicalKeyOrderingMatchesNodeDomain(t *testing.T) {
	encoded, err := canonicalJSON(map[string]any{"\U00010000": 1, "\ue000": 2})
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != "{\"\":2,\"𐀀\":1}" {
		t.Fatalf("canonical=%s", encoded)
	}
}

func TestU4GoCanonicalJSONRejectsOutOfDomainStrings(t *testing.T) {
	for _, value := range []map[string]any{
		{"value": "bad\u2028value"},
		{"bad\u2029key": "value"},
		{"nested": []any{string([]byte{0xff})}},
	} {
		if _, err := canonicalJSON(value); err == nil || !strings.Contains(strings.ToLower(err.Error()), "canonical string domain") {
			t.Fatalf("value=%q error=%v", value, err)
		}
	}
}

func TestU4CanonicalErrorsFailClosedInManifestDigest(t *testing.T) {
	manifest := map[string]any{
		"uri":           "artifact://bad\u2028uri",
		"sha256":        strings.Repeat("0", 64),
		"media_type":    "text/plain",
		"size":          float64(0),
		"manifest_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	}
	err := verifyReceiptArtifactManifests(map[string]any{
		"artifact_refs":      []any{manifest["uri"]},
		"artifact_manifests": []any{manifest},
	})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "canonical string domain") {
		t.Fatalf("error=%v", err)
	}
}

func nonCanonicalBase64URLTrailingBits(encoded string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := strings.IndexByte(alphabet, encoded[len(encoded)-1])
	return encoded[:len(encoded)-1] + string(alphabet[(last&0b111100)|0b000001])
}

func TestLoadSwarmOutputTrustInputsRejectsNonScalarCanonicalStrings(t *testing.T) {
	mutations := []struct {
		name   string
		mutate func(*trustFixture)
	}{
		{"U+2028 zone name", func(v *trustFixture) {
			v.trustedZones["zones"].([]any)[0].(map[string]any)["name"] = "zone://bad\u2028name"
		}},
		{"U+2028 zone zid", func(v *trustFixture) {
			v.trustedZones["zones"].([]any)[0].(map[string]any)["zid"] = v.zone["zid"].(string) + "\u2028bad"
		}},
		{"U+2029 zone public_key_spki", func(v *trustFixture) {
			v.trustedZones["zones"].([]any)[0].(map[string]any)["public_key_spki"] = v.zone["public_key_spki"].(string) + "\u2029bad"
		}},
		{"U+2028 zone signature", func(v *trustFixture) {
			v.trustedZones["zones"].([]any)[0].(map[string]any)["zone_signature"] = v.zone["zone_signature"].(string) + "\u2028bad"
		}},
		{"U+2029 verifier alias", func(v *trustFixture) {
			v.allowlist["verifiers"].([]any)[0].(map[string]any)["descriptor"].(map[string]any)["alias"] = "agent://bad\u2029alias"
		}},
		{"U+2028 verifier aid", func(v *trustFixture) {
			v.allowlist["verifiers"].([]any)[0].(map[string]any)["descriptor"].(map[string]any)["aid"] = v.verifier["aid"].(string) + "\u2028bad"
		}},
		{"U+2029 verifier did_key", func(v *trustFixture) {
			v.allowlist["verifiers"].([]any)[0].(map[string]any)["descriptor"].(map[string]any)["did_key"] = v.verifier["did_key"].(string) + "\u2029bad"
		}},
		{"U+2028 verifier public_key_spki", func(v *trustFixture) {
			v.allowlist["verifiers"].([]any)[0].(map[string]any)["descriptor"].(map[string]any)["public_key_spki"] = v.verifier["public_key_spki"].(string) + "\u2028bad"
		}},
		{"U+2029 verifier descriptor_signature", func(v *trustFixture) {
			v.allowlist["verifiers"].([]any)[0].(map[string]any)["descriptor"].(map[string]any)["descriptor_signature"] = v.verifier["descriptor_signature"].(string) + "\u2029bad"
		}},
		{"U+2028 binding alias", func(v *trustFixture) {
			v.allowlist["verifiers"].([]any)[0].(map[string]any)["zone_binding"].(map[string]any)["alias"] = "agent://bad\u2028binding"
		}},
		{"U+2028 binding zone", func(v *trustFixture) {
			v.allowlist["verifiers"].([]any)[0].(map[string]any)["zone_binding"].(map[string]any)["zone"] = v.zone["zid"].(string) + "\u2028bad"
		}},
		{"U+2029 binding aid", func(v *trustFixture) {
			v.allowlist["verifiers"].([]any)[0].(map[string]any)["zone_binding"].(map[string]any)["aid"] = v.verifier["aid"].(string) + "\u2029bad"
		}},
		{"U+2028 binding signature", func(v *trustFixture) {
			v.allowlist["verifiers"].([]any)[0].(map[string]any)["zone_binding"].(map[string]any)["signature"] = v.allowlist["verifiers"].([]any)[0].(map[string]any)["zone_binding"].(map[string]any)["signature"].(string) + "\u2028bad"
		}},
		{"U+2029 transport", func(v *trustFixture) {
			v.allowlist["verifiers"].([]any)[0].(map[string]any)["descriptor"].(map[string]any)["transports"] = []any{"asp+local://bad\u2029transport"}
		}},
		{"U+2028 capability", func(v *trustFixture) {
			v.allowlist["verifiers"].([]any)[0].(map[string]any)["descriptor"].(map[string]any)["capabilities"] = []any{"bad\u2028capability"}
		}},
		{"U+2029 policy prefix", func(v *trustFixture) {
			v.allowlist["verifiers"].([]any)[0].(map[string]any)["descriptor"].(map[string]any)["policy"].(map[string]any)["write_prefixes"] = []any{"artifact://bad\u2029"}
		}},
		{"U+2028 authorization", func(v *trustFixture) {
			v.allowlist["verifiers"].([]any)[0].(map[string]any)["authorizations"] = []any{"swarm.output.verify", "bad\u2028authorization"}
		}},
		{"U+2029 revocation reason", func(v *trustFixture) {
			v.revocations["revocations"].([]any)[0].(map[string]any)["reason"] = "bad\u2029reason"
		}},
		{"U+2029 revocation zone", func(v *trustFixture) {
			v.revocations["revocations"].([]any)[0].(map[string]any)["zone"] = v.zone["zid"].(string) + "\u2029bad"
		}},
		{"U+2028 revocation subject", func(v *trustFixture) {
			v.revocations["revocations"].([]any)[0].(map[string]any)["subject"] = v.revocations["revocations"].([]any)[0].(map[string]any)["subject"].(string) + "\u2028bad"
		}},
		{"U+2029 revocation signature", func(v *trustFixture) {
			v.revocations["revocations"].([]any)[0].(map[string]any)["signature"] = v.revocations["revocations"].([]any)[0].(map[string]any)["signature"].(string) + "\u2029bad"
		}},
	}
	for _, testCase := range mutations {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newTrustFixture(t)
			testCase.mutate(&fixture)
			_, err := NewTrustInputsForTest(fixture.allowlist, fixture.trustedZones, fixture.revocations)
			if err == nil || (!strings.Contains(strings.ToLower(err.Error()), "canonical string domain") && !strings.Contains(strings.ToLower(err.Error()), "unicode scalar")) {
				t.Fatalf("error=%v", err)
			}
		})
	}

	path := filepath.Join(t.TempDir(), "unpaired.json")
	writeSecureJSON(t, path, nil, []byte(`{"value":"\ud800"}`))
	if _, _, err := SafeOpenOwnedJSON(path); err == nil || (!strings.Contains(strings.ToLower(err.Error()), "canonical string domain") && !strings.Contains(strings.ToLower(err.Error()), "unicode scalar")) {
		t.Fatalf("unpaired surrogate error=%v", err)
	}
}

func TestLoadSwarmOutputTrustInputsRequiresExactUnpaddedBase64URL(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*trustFixture)
	}{
		{"padded signature", func(v *trustFixture) {
			v.trustedZones["zones"].([]any)[0].(map[string]any)["zone_signature"] = v.zone["zone_signature"].(string) + "="
		}},
		{"whitespace signature", func(v *trustFixture) {
			v.trustedZones["zones"].([]any)[0].(map[string]any)["zone_signature"] = v.zone["zone_signature"].(string) + "\n"
		}},
		{"non-canonical signature trailing bits", func(v *trustFixture) {
			v.trustedZones["zones"].([]any)[0].(map[string]any)["zone_signature"] = nonCanonicalBase64URLTrailingBits(v.zone["zone_signature"].(string))
		}},
		{"padded descriptor signature", func(v *trustFixture) {
			v.allowlist["verifiers"].([]any)[0].(map[string]any)["descriptor"].(map[string]any)["descriptor_signature"] = v.verifier["descriptor_signature"].(string) + "="
		}},
		{"padded binding signature", func(v *trustFixture) {
			v.allowlist["verifiers"].([]any)[0].(map[string]any)["zone_binding"].(map[string]any)["signature"] = v.allowlist["verifiers"].([]any)[0].(map[string]any)["zone_binding"].(map[string]any)["signature"].(string) + "="
		}},
		{"padded revocation signature", func(v *trustFixture) {
			v.revocations["revocations"].([]any)[0].(map[string]any)["signature"] = v.revocations["revocations"].([]any)[0].(map[string]any)["signature"].(string) + "="
		}},
		{"padded SPKI", func(v *trustFixture) {
			body := map[string]any{"name": v.zone["name"], "zid": v.zone["zid"], "public_key_spki": v.zone["public_key_spki"].(string) + "="}
			v.trustedZones["zones"] = []any{signNodeCanonical(t, v.zoneKey, "zone_signature", body)}
		}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newTrustFixture(t)
			testCase.mutate(&fixture)
			_, err := NewTrustInputsForTest(fixture.allowlist, fixture.trustedZones, fixture.revocations)
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), "exact unpadded base64url") {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestLoadSwarmOutputTrustInputsCanonicalFormattingAndKeyOrder(t *testing.T) {
	fixture := newTrustFixture(t)
	leftPaths := writeTrustFixture(t, fixture)
	rightPaths := writeTrustFixture(t, fixture)
	writeReverseJSON := func(path string, value map[string]any, indent string) {
		ordered := reverseJSONKeys(value).(map[string]any)
		var data []byte
		var err error
		if indent == "" {
			data, err = json.Marshal(ordered)
		} else {
			data, err = json.MarshalIndent(ordered, "", indent)
		}
		if err != nil {
			t.Fatal(err)
		}
		writeSecureJSON(t, path, ordered, append([]byte("\n"), append(data, '\n')...))
	}
	writeReverseJSON(rightPaths.Allowlist, fixture.allowlist, "")
	writeReverseJSON(rightPaths.TrustedZones, fixture.trustedZones, "    ")
	writeReverseJSON(rightPaths.Revocations, fixture.revocations, "  ")
	left, err := LoadSwarmOutputTrustInputs(leftPaths)
	if err != nil {
		t.Fatal(err)
	}
	right, err := LoadSwarmOutputTrustInputs(rightPaths)
	if err != nil {
		t.Fatal(err)
	}
	if left.TrustInputsDigest != right.TrustInputsDigest || !reflect.DeepEqual(left.allowlist, right.allowlist) {
		t.Fatalf("left=%s right=%s", left.TrustInputsDigest, right.TrustInputsDigest)
	}
}

func reverseJSONKeys(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		for left, right := 0, len(keys)-1; left < right; left, right = left+1, right-1 {
			keys[left], keys[right] = keys[right], keys[left]
		}
		out := map[string]any{}
		for _, key := range keys {
			out[key] = reverseJSONKeys(typed[key])
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for index, item := range typed {
			out[index] = reverseJSONKeys(item)
		}
		return out
	default:
		return typed
	}
}

func TestLoadSwarmOutputTrustInputsOwnerStatSeam(t *testing.T) {
	fixture := newTrustFixture(t)
	paths := writeTrustFixture(t, fixture)
	info, err := os.Stat(paths.Allowlist)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint32(stat.Uid) != uint32(os.Getuid()) {
		t.Fatalf("unexpected stat seam: %#v", info.Sys())
	}
	if _, err := LoadSwarmOutputTrustInputs(paths); err != nil {
		t.Fatal(err)
	}
}
