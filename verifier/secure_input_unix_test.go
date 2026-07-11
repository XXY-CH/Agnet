//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package verifier

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSafeOpenOwnedJSONFinalOpenUsesVerifiedParentHandle(t *testing.T) {
	dir := t.TempDir()
	outer := filepath.Join(dir, "outer")
	inner := filepath.Join(outer, "inner")
	moved := filepath.Join(dir, "verified-outer")
	if err := os.MkdirAll(inner, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(inner, "input.json")
	writeSecureJSON(t, path, map[string]any{"source": "verified-parent"}, nil)
	originalHook := ownedJSONAfterParentVerified
	t.Cleanup(func() { ownedJSONAfterParentVerified = originalHook })
	hookCalled := false
	ownedJSONAfterParentVerified = func() error {
		hookCalled = true
		if err := os.Rename(outer, moved); err != nil {
			return err
		}
		if err := os.MkdirAll(inner, 0o700); err != nil {
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

func TestSafeOpenOwnedJSONBoundsFileGrowthAfterInitialStat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "growing.json")
	writeSecureJSON(t, path, map[string]any{"value": "small"}, nil)
	originalHook := ownedJSONAfterInitialStat
	t.Cleanup(func() { ownedJSONAfterInitialStat = originalHook })
	hookCalled := false
	ownedJSONAfterInitialStat = func() error {
		hookCalled = true
		file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		defer file.Close()
		_, err = file.WriteString(strings.Repeat("x", testTrustInputMaxBytes+1))
		return err
	}

	_, _, err := SafeOpenOwnedJSON(path)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "size limit") || !hookCalled {
		t.Fatalf("hook=%v error=%v", hookCalled, err)
	}
}

func TestSafeOpenOwnedJSONRefstatsAfterRead(t *testing.T) {
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

func TestSafeOpenOwnedJSONReportsParserResourceLimits(t *testing.T) {
	dir := t.TempDir()
	tooMany := filepath.Join(dir, "too-many.json")
	writeSecureJSON(t, tooMany, nil, []byte(fmt.Sprintf(`{"values":[%s0]}`, strings.Repeat("0,", 100_000))))
	if _, _, err := SafeOpenOwnedJSON(tooMany); err == nil || !strings.Contains(strings.ToLower(err.Error()), "entry limit") {
		t.Fatalf("entry limit error=%v", err)
	}

	tooDeep := filepath.Join(dir, "too-deep.json")
	writeSecureJSON(t, tooDeep, nil, []byte(fmt.Sprintf(`{"value":%s0%s}`, strings.Repeat("[", 512), strings.Repeat("]", 512))))
	if _, _, err := SafeOpenOwnedJSON(tooDeep); err == nil || !strings.Contains(strings.ToLower(err.Error()), "nesting limit") {
		t.Fatalf("nesting limit error=%v", err)
	}
}
