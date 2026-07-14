//go:build darwin || linux

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sys/unix"
)

// acquireUnixFileLock blocks until it owns an exclusive kernel lock on a
// permanent lock inode. The kernel drops ownership on process exit; retaining
// the inode prevents an old owner from unlinking a successor's lock.
func acquireUnixFileLock(path string) (func(), error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open unix file lock: %w", err)
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX); err != nil {
		closeErr := file.Close()
		if closeErr != nil {
			return nil, errors.Join(fmt.Errorf("acquire unix file lock: %w", err), fmt.Errorf("close unix file lock: %w", closeErr))
		}
		return nil, fmt.Errorf("acquire unix file lock: %w", err)
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			// Closing also releases the lock; explicit unlock lets a waiter proceed
			// before the descriptor cleanup completes.
			_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
			_ = file.Close()
		})
	}, nil
}

const productDaemonLockName = ".product-daemon.lock"

// acquireProductDaemonLock holds an OS-backed exclusive lock for the lifetime
// of a Product/Human Gateway daemon. The permanent lock inode is safe across
// crashes: the kernel releases ownership when the process exits.
func acquireProductDaemonLock(queueRoot string) (func() error, error) {
	if queueRoot == "" {
		return nil, errors.New("product queue root required")
	}
	if err := os.MkdirAll(queueRoot, 0o700); err != nil {
		return nil, fmt.Errorf("create product queue root: %w", err)
	}
	file, err := os.OpenFile(filepath.Join(queueRoot, productDaemonLockName), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open product daemon lock: %w", err)
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		closeErr := file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			if closeErr != nil {
				return nil, fmt.Errorf("product daemon already running (close lock: %v)", closeErr)
			}
			return nil, errors.New("product daemon already running")
		}
		if closeErr != nil {
			return nil, fmt.Errorf("acquire product daemon lock: %w (close: %v)", err, closeErr)
		}
		return nil, fmt.Errorf("acquire product daemon lock: %w", err)
	}
	var once sync.Once
	var releaseErr error
	return func() error {
		once.Do(func() {
			unlockErr := unix.Flock(int(file.Fd()), unix.LOCK_UN)
			closeErr := file.Close()
			if unlockErr != nil {
				releaseErr = fmt.Errorf("unlock product daemon lock: %w", unlockErr)
			} else if closeErr != nil {
				releaseErr = fmt.Errorf("close product daemon lock: %w", closeErr)
			}
		})
		return releaseErr
	}, nil
}
