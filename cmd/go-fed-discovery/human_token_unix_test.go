//go:build unix

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveHumanGatewayTokenReadsPrivateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "human-token")
	if err := os.WriteFile(path, []byte("private-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	token, err := resolveHumanGatewayToken("", path)
	if err != nil {
		t.Fatal(err)
	}
	if token != "private-token" {
		t.Fatalf("token = %q", token)
	}
}

func TestResolveHumanGatewayTokenRejectsAmbiguousOrUnsafeInputs(t *testing.T) {
	root := t.TempDir()
	privatePath := filepath.Join(root, "private-token")
	if err := os.WriteFile(privatePath, []byte("private-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveHumanGatewayToken("inline-token", privatePath); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("got %v, want mutually exclusive error", err)
	}

	publicPath := filepath.Join(root, "public-token")
	if err := os.WriteFile(publicPath, []byte("public-token"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveHumanGatewayToken("", publicPath); err == nil || !strings.Contains(err.Error(), "unsafe") {
		t.Fatalf("got %v, want unsafe file error", err)
	}

	linkPath := filepath.Join(root, "token-link")
	if err := os.Symlink(privatePath, linkPath); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveHumanGatewayToken("", linkPath); err == nil || !strings.Contains(err.Error(), "open human gateway token file") {
		t.Fatalf("got %v, want no-follow open error", err)
	}
}
