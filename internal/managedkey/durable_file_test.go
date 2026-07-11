package managedkey

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestDurableFileWritesSameDirectoryTempSyncRenameAndDirSync(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "value.json")
	if err := durableWriteFile(path, []byte(`{"ok":true}`), durableWriteOptions{Mode: 0o600, Fault: nil, PointPrefix: "value"}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"ok":true}` {
		t.Fatalf("data=%q", data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%o", info.Mode().Perm())
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".tmp") {
			t.Fatalf("temp left visible: %s", entry.Name())
		}
	}
}

func TestDurableFileFaultBeforeRenameLeavesPriorBytes(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "value.json")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := durableWriteFile(path, []byte("new"), durableWriteOptions{Mode: 0o600, PointPrefix: "value", Fault: func(point string) error {
		if point == "value-before-rename" {
			return errors.New("fault:value-before-rename")
		}
		return nil
	}})
	if err == nil || !strings.Contains(err.Error(), "fault:value-before-rename") {
		t.Fatalf("err=%v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "old" {
		t.Fatalf("data=%q", data)
	}
}

func TestDurableFileRejectsFIFOHelper(t *testing.T) {
	if os.Getenv("AGNET_MANAGEDKEY_FIFO_HELPER") != "1" {
		return
	}
	if _, err := readPrivateFile(os.Getenv("AGNET_MANAGEDKEY_FIFO_PATH"), "FIFO"); err == nil {
		t.Fatal("FIFO accepted")
	}
}

func TestDurableFileRejectsFIFOPromptly(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "authority.fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestDurableFileRejectsFIFOHelper$")
	cmd.Env = append(os.Environ(), "AGNET_MANAGEDKEY_FIFO_HELPER=1", "AGNET_MANAGEDKEY_FIFO_PATH="+path)
	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("FIFO rejection subprocess: %v", err)
		}
	case <-time.After(300 * time.Millisecond):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		<-done
		t.Fatal("FIFO authoritative open blocked")
	}
}
