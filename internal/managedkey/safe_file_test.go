//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package managedkey

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRestrictedFileAcceptsExactOwnedFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "passphrase")
	contents := []byte("restricted passphrase\n")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	opened, err := ReadRestrictedFile(path, RestrictedFileOptions{Label: "passphrase", MaxBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened.Bytes, contents) || opened.Evidence.Mode != 0o600 || opened.Evidence.NLink != 1 || opened.Evidence.Path == "" {
		t.Fatalf("opened=%+v", opened)
	}
}

func TestRestrictedFileRejectsUnsafeFilesAndDirectories(t *testing.T) {
	t.Run("file mode", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "secret")
		if err := os.WriteFile(path, []byte("secret"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadRestrictedFile(path, RestrictedFileOptions{Label: "secret", MaxBytes: 1024}); err == nil || !strings.Contains(err.Error(), "mode must be 0600") {
			t.Fatalf("error=%v", err)
		}
	})
	t.Run("symlink", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "target")
		if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadRestrictedFile(link, RestrictedFileOptions{Label: "secret", MaxBytes: 1024}); err == nil || !strings.Contains(err.Error(), "symbolic link") {
			t.Fatalf("error=%v", err)
		}
	})
	t.Run("hardlink", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "secret")
		if err := os.WriteFile(path, []byte("secret"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(path, filepath.Join(dir, "second")); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadRestrictedFile(path, RestrictedFileOptions{Label: "secret", MaxBytes: 1024}); err == nil || !strings.Contains(err.Error(), "link count must be one") {
			t.Fatalf("error=%v", err)
		}
	})
	t.Run("unsafe parent", func(t *testing.T) {
		root := t.TempDir()
		unsafe := filepath.Join(root, "unsafe")
		if err := os.Mkdir(unsafe, 0o777); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(unsafe, 0o777); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(unsafe, "secret")
		if err := os.WriteFile(path, []byte("secret"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadRestrictedFile(path, RestrictedFileOptions{Label: "secret", MaxBytes: 1024}); err == nil || !strings.Contains(err.Error(), "unsafe parent mode") {
			t.Fatalf("error=%v", err)
		}
	})
	t.Run("oversized", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "secret")
		if err := os.WriteFile(path, bytes.Repeat([]byte("x"), 17), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadRestrictedFile(path, RestrictedFileOptions{Label: "secret", MaxBytes: 16}); err == nil || !strings.Contains(err.Error(), "size limit exceeded") {
			t.Fatalf("error=%v", err)
		}
	})
}
