//go:build unix

package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

const swarmLockRetryInterval = 10 * time.Millisecond

var swarmProcessLocks = struct {
	sync.Mutex
	locks map[string]*swarmProcessLock
}{locks: make(map[string]*swarmProcessLock)}

type swarmProcessLock struct {
	token chan struct{}
	refs  int
}

// swarmStorageKey converts an external Swarm identifier into a path-safe,
// fixed-width storage name. It intentionally does not embed the identifier in
// the filesystem layout.
func swarmStorageKey(swarmID string) (string, error) {
	if swarmID == "" || strings.IndexByte(swarmID, 0) >= 0 || !utf8.ValidString(swarmID) {
		return "", errors.New("swarm identifier is not safe for storage")
	}
	sum := sha256.Sum256([]byte(swarmID))
	return fmt.Sprintf("%x", sum), nil
}

// openSwarmStorageDir opens the private directory used by a single Swarm. The
// caller supplies a private, absolute storage root; both it and the keyed
// child are verified before being returned.
func openSwarmStorageDir(storageRoot, swarmID string) (string, error) {
	if err := validateAbsoluteCleanPath(storageRoot); err != nil {
		return "", fmt.Errorf("invalid swarm storage root: %w", err)
	}
	key, err := swarmStorageKey(swarmID)
	if err != nil {
		return "", err
	}
	if err := ensurePrivateStorageRoot(storageRoot); err != nil {
		return "", fmt.Errorf("secure swarm storage root: %w", err)
	}
	dir := filepath.Join(storageRoot, key)
	if _, err := ensurePrivateDirectory(dir); err != nil {
		return "", fmt.Errorf("secure swarm storage directory: %w", err)
	}
	return dir, nil
}

// withSwarmLock serializes one Swarm's journal mutation. The lock inode is
// permanent: this function only creates or opens it and never renames or
// removes it.
func withSwarmLock(lockPath string, fn func() error) error {
	return withSwarmLockContext(context.Background(), lockPath, fn)
}

// withSwarmLockContext is the cancellable form used by lock acquisition tests
// and callers that must abandon contention while shutting down.
func withSwarmLockContext(ctx context.Context, lockPath string, fn func() error) error {
	if ctx == nil {
		return errors.New("swarm lock context is nil")
	}
	if fn == nil {
		return errors.New("swarm lock callback is nil")
	}
	if _, _, err := swarmLockParentAndName(lockPath); err != nil {
		return err
	}
	releaseProcessLock, err := acquireSwarmProcessLock(ctx, lockPath)
	if err != nil {
		return err
	}
	defer releaseProcessLock()

	file, err := openSecureSwarmLock(lockPath)
	if err != nil {
		return err
	}

	if err := acquireSwarmFlock(ctx, int(file.Fd())); err != nil {
		closeErr := file.Close()
		if closeErr != nil {
			return fmt.Errorf("acquire swarm lock: %w (close: %v)", err, closeErr)
		}
		return err
	}

	var callbackErr, unlockErr, closeErr error
	func() {
		defer func() {
			unlockErr = unix.Flock(int(file.Fd()), unix.LOCK_UN)
			closeErr = file.Close()
		}()
		callbackErr = fn()
	}()
	if callbackErr != nil {
		return callbackErr
	}
	if unlockErr != nil {
		return fmt.Errorf("unlock swarm lock: %w", unlockErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close swarm lock: %w", closeErr)
	}
	return nil
}

func acquireSwarmFlock(ctx context.Context, fd int) error {
	for {
		err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return nil
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			return fmt.Errorf("acquire swarm lock: %w", err)
		}

		timer := time.NewTimer(swarmLockRetryInterval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func acquireSwarmProcessLock(ctx context.Context, lockPath string) (func(), error) {
	swarmProcessLocks.Lock()
	lock := swarmProcessLocks.locks[lockPath]
	if lock == nil {
		lock = &swarmProcessLock{token: make(chan struct{}, 1)}
		lock.token <- struct{}{}
		swarmProcessLocks.locks[lockPath] = lock
	}
	lock.refs++
	swarmProcessLocks.Unlock()

	select {
	case <-ctx.Done():
		releaseSwarmProcessLock(lockPath, lock, false)
		return nil, ctx.Err()
	case <-lock.token:
		return func() { releaseSwarmProcessLock(lockPath, lock, true) }, nil
	}
}

func releaseSwarmProcessLock(lockPath string, lock *swarmProcessLock, held bool) {
	if held {
		lock.token <- struct{}{}
	}
	swarmProcessLocks.Lock()
	lock.refs--
	if lock.refs == 0 {
		delete(swarmProcessLocks.locks, lockPath)
	}
	swarmProcessLocks.Unlock()
}

func openSecureSwarmLock(lockPath string) (*os.File, error) {
	parent, name, err := swarmLockParentAndName(lockPath)
	if err != nil {
		return nil, err
	}
	dir, err := openPrivateDirectory(parent)
	if err != nil {
		return nil, fmt.Errorf("open swarm lock parent: %w", err)
	}
	defer dir.Close()

	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	created := err == nil
	if err != nil {
		if !errors.Is(err, unix.EEXIST) {
			return nil, fmt.Errorf("create swarm lock: %w", err)
		}
		fd, err = unix.Openat(int(dir.Fd()), name, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, fmt.Errorf("open swarm lock without following links: %w", err)
		}
	}
	file := os.NewFile(uintptr(fd), lockPath)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("open swarm lock returned invalid file")
	}
	if created {
		if err := file.Chmod(0o600); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("protect new swarm lock: %w", err)
		}
	}
	if err := validatePrivateRegularFile(file); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("validate swarm lock: %w", err)
	}
	if created {
		if err := dir.Sync(); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("sync new swarm lock parent: %w", err)
		}
	}
	return file, nil
}

func swarmLockParentAndName(lockPath string) (string, string, error) {
	if err := validateAbsoluteCleanPath(lockPath); err != nil {
		return "", "", fmt.Errorf("invalid swarm lock path: %w", err)
	}
	parent := filepath.Dir(lockPath)
	name := filepath.Base(lockPath)
	if name == "." || name == string(filepath.Separator) || strings.ContainsRune(name, filepath.Separator) {
		return "", "", errors.New("swarm lock path has no file name")
	}
	return parent, name, nil
}

func validateAbsoluteCleanPath(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("path must be absolute and clean")
	}
	return nil
}

func ensurePrivateStorageRoot(path string) error {
	info, err := os.Lstat(path)
	created := false
	if errors.Is(err, fs.ErrNotExist) {
		parent := filepath.Dir(path)
		if err := validateCurrentOwnerDirectoryPath(parent); err != nil {
			return fmt.Errorf("validate storage root parent: %w", err)
		}
		if mkdirErr := os.Mkdir(path, 0o700); mkdirErr != nil {
			if !errors.Is(mkdirErr, fs.ErrExist) {
				return mkdirErr
			}
		} else {
			created = true
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return err
	}
	if err := validateCurrentOwnerDirectoryInfo(info); err != nil {
		return err
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return err
	}
	if err := validatePrivateDirectoryPath(path); err != nil {
		return err
	}
	if created {
		return syncCurrentOwnerDirectory(filepath.Dir(path))
	}
	return nil
}

func ensurePrivateDirectory(path string) (bool, error) {
	info, err := os.Lstat(path)
	if err == nil {
		return false, validatePrivateDirectoryInfo(info)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	parent := filepath.Dir(path)
	if err := validatePrivateDirectoryPath(parent); err != nil {
		return false, fmt.Errorf("validate storage parent: %w", err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		if !errors.Is(err, fs.ErrExist) {
			return false, err
		}
		if err := validatePrivateDirectoryPath(path); err != nil {
			return false, err
		}
		return false, nil
	}
	if err := validatePrivateDirectoryPath(path); err != nil {
		return false, err
	}
	if err := syncDirectory(parent); err != nil {
		return false, err
	}
	return true, nil
}

func openPrivateDirectory(path string) (*os.File, error) {
	if err := validatePrivateDirectoryPath(path); err != nil {
		return nil, err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("open private directory returned invalid file")
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := validatePrivateDirectoryInfo(info); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func validatePrivateDirectoryPath(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	return validatePrivateDirectoryInfo(info)
}

func validatePrivateDirectoryInfo(info os.FileInfo) error {
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return errors.New("not a private directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return errors.New("private directory is not owned by current user")
	}
	return nil
}

func validatePrivateRegularFile(file *os.File) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return errors.New("not a private regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() || stat.Nlink != 1 {
		return errors.New("lock file ownership or link count is unsafe")
	}
	return nil
}

func validateCurrentOwnerDirectoryPath(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	return validateCurrentOwnerDirectoryInfo(info)
}

func validateCurrentOwnerDirectoryInfo(info os.FileInfo) error {
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("not a directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return errors.New("directory is not owned by current user")
	}
	return nil
}

func syncCurrentOwnerDirectory(path string) error {
	if err := validateCurrentOwnerDirectoryPath(path); err != nil {
		return err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	dir := os.NewFile(uintptr(fd), path)
	if dir == nil {
		_ = unix.Close(fd)
		return errors.New("open storage parent returned invalid file")
	}
	defer dir.Close()
	info, err := dir.Stat()
	if err != nil {
		return err
	}
	if err := validateCurrentOwnerDirectoryInfo(info); err != nil {
		return err
	}
	return dir.Sync()
}
func syncDirectory(path string) error {
	dir, err := openPrivateDirectory(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
