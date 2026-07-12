package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestSwarmStorageKeyRejectsUnsafeIdentifiers(t *testing.T) {
	for _, swarmID := range []string{"", "swarm\x00shadow", string([]byte{0xff})} {
		if _, err := swarmStorageKey(swarmID); err == nil {
			t.Fatalf("swarmStorageKey(%q) accepted unsafe identifier", swarmID)
		}
	}
	first, err := swarmStorageKey("swarm://production/east")
	if err != nil {
		t.Fatal(err)
	}
	second, err := swarmStorageKey("swarm://production/east")
	if err != nil {
		t.Fatal(err)
	}
	if first != second || strings.ContainsAny(first, "/\\") || len(first) != 64 {
		t.Fatalf("unsafe or unstable storage key %q", first)
	}
}

func TestOpenSwarmStorageDirValidatesPrivateLayout(t *testing.T) {
	root := filepath.Join(t.TempDir(), "swarm-state")
	dir, err := openSwarmStorageDir(root, "swarm://test")
	if err != nil {
		t.Fatal(err)
	}
	assertPrivateDirectory(t, root)
	assertPrivateDirectory(t, dir)

	unsafeRoot := filepath.Join(t.TempDir(), "unsafe")
	if err := os.Mkdir(unsafeRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := openSwarmStorageDir(unsafeRoot, "swarm://test"); err != nil {
		t.Fatalf("openSwarmStorageDir did not protect current-owner root: %v", err)
	}
	assertPrivateDirectory(t, unsafeRoot)

	target := filepath.Join(t.TempDir(), "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := openSwarmStorageDir(link, "swarm://test"); err == nil {
		t.Fatal("openSwarmStorageDir accepted symlink root")
	}
}

func TestSwarmLockSerializesSameProcessAndRetainsInode(t *testing.T) {
	path := testSwarmLockPath(t)
	before := lockIdentity(t, path)

	started := make(chan struct{})
	release := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- withSwarmLock(path, func() error {
			close(started)
			<-release
			return nil
		})
	}()
	<-started

	secondAcquired := make(chan struct{})
	secondDone := make(chan error, 1)
	go func() {
		secondDone <- withSwarmLock(path, func() error {
			close(secondAcquired)
			return nil
		})
	}()
	select {
	case <-secondAcquired:
		t.Fatal("same-process caller acquired per-Swarm lock before release")
	case <-time.After(75 * time.Millisecond):
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-secondDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("second caller did not acquire after release")
	}
	after := lockIdentity(t, path)
	if before != after {
		t.Fatalf("lock inode changed: before=%+v after=%+v", before, after)
	}
	assertPrivateRegularFile(t, path)
}

func TestSwarmLockTwoProcesses(t *testing.T) {
	if os.Getenv("AGNET_SWARM_LOCK_HELPER") == "1" {
		path := os.Getenv("AGNET_SWARM_LOCK_PATH")
		ready := os.Getenv("AGNET_SWARM_LOCK_READY")
		acquired := os.Getenv("AGNET_SWARM_LOCK_ACQUIRED")
		if err := os.WriteFile(ready, []byte("ready"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := withSwarmLock(path, func() error {
			return os.WriteFile(acquired, []byte("acquired"), 0o600)
		}); err != nil {
			t.Fatal(err)
		}
		return
	}

	path := testSwarmLockPath(t)
	ready := filepath.Join(filepath.Dir(path), "child-ready")
	acquired := filepath.Join(filepath.Dir(path), "child-acquired")
	started := make(chan struct{})
	release := make(chan struct{})
	parentDone := make(chan error, 1)
	go func() {
		parentDone <- withSwarmLock(path, func() error {
			close(started)
			<-release
			return nil
		})
	}()
	<-started

	cmd := helperTestProcess(t, path, ready, acquired)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waitForFile(t, ready)
	time.Sleep(75 * time.Millisecond)
	if _, err := os.Stat(acquired); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("child acquired cross-process lock before release: %v", err)
	}
	close(release)
	if err := <-parentDone; err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(acquired); err != nil {
		t.Fatalf("child never acquired lock: %v", err)
	}
}

func TestSwarmLockRejectsUnsafePathAndFileLayout(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "journal.ndjson.lock")
	outside := filepath.Join(t.TempDir(), "outside.lock")
	if err := os.WriteFile(outside, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	if err := withSwarmLock(path, func() error { return nil }); err == nil {
		t.Fatal("withSwarmLock accepted symlink")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := withSwarmLock(path, func() error { return nil }); err == nil {
		t.Fatal("withSwarmLock accepted unsafe mode")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(outside, path); err != nil {
		t.Fatal(err)
	}
	if err := withSwarmLock(path, func() error { return nil }); err == nil {
		t.Fatal("withSwarmLock accepted hard-linked file")
	}
	if err := withSwarmLock(dir+string(filepath.Separator)+"child"+string(filepath.Separator)+".."+string(filepath.Separator)+"journal.ndjson.lock", func() error { return nil }); err == nil {
		t.Fatal("withSwarmLock accepted noncanonical path")
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := withSwarmLock(filepath.Join(dir, "new.lock"), func() error { return nil }); err == nil {
		t.Fatal("withSwarmLock accepted unsafe parent layout")
	}
}

func TestSwarmLockCanceledAcquisition(t *testing.T) {
	path := testSwarmLockPath(t)
	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- withSwarmLock(path, func() error {
			close(started)
			<-release
			return nil
		})
	}()
	<-started
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err := withSwarmLockContext(ctx, path, func() error { return nil })
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("canceled acquisition error = %v, want deadline exceeded", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSwarmLockReleaseIsRaceSafe(t *testing.T) {
	path := testSwarmLockPath(t)
	const writers = 16
	var wg sync.WaitGroup
	var failures []error
	var failuresMu sync.Mutex
	for range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := withSwarmLock(path, func() error {
				data, err := os.ReadFile(filepath.Join(filepath.Dir(path), "count"))
				if err != nil && !errors.Is(err, os.ErrNotExist) {
					return err
				}
				value := len(data)
				return os.WriteFile(filepath.Join(filepath.Dir(path), "count"), []byte(strings.Repeat("x", value+1)), 0o600)
			})
			if err != nil {
				failuresMu.Lock()
				failures = append(failures, err)
				failuresMu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(failures) != 0 {
		t.Fatalf("lock writers failed: %v", failures)
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(path), "count"))
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != writers {
		t.Fatalf("serialized count = %d, want %d", len(data), writers)
	}
}

func testSwarmLockPath(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "state")
	dir, err := openSwarmStorageDir(root, "swarm://test")
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "journal.ndjson.lock")
}

func helperTestProcess(t *testing.T, path, ready, acquired string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestSwarmLockTwoProcesses$")
	cmd.Env = append(os.Environ(),
		"AGNET_SWARM_LOCK_HELPER=1",
		"AGNET_SWARM_LOCK_PATH="+path,
		"AGNET_SWARM_LOCK_READY="+ready,
		"AGNET_SWARM_LOCK_ACQUIRED="+acquired,
	)
	return cmd
}

func waitForFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", path)
}

type swarmLockTestIdentity struct{ dev, ino uint64 }

func lockIdentity(t *testing.T, path string) swarmLockTestIdentity {
	t.Helper()
	if err := withSwarmLock(path, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("lock stat has unexpected platform type")
	}
	return swarmLockTestIdentity{dev: uint64(stat.Dev), ino: uint64(stat.Ino)}
}

func assertPrivateDirectory(t *testing.T, path string) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		t.Fatalf("%s is not a private directory: %v", path, info.Mode())
	}
}

func assertPrivateRegularFile(t *testing.T, path string) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
		t.Fatalf("%s is not a private regular file: %v", path, info.Mode())
	}
}
