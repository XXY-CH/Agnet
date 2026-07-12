//go:build !unix

package main

import (
	"context"
	"errors"
)

var errSwarmLockUnsupported = errors.New("swarm locks are unsupported on this platform")

func swarmStorageKey(string) (string, error) {
	return "", errSwarmLockUnsupported
}

func openSwarmStorageDir(string, string) (string, error) {
	return "", errSwarmLockUnsupported
}

func withSwarmLock(string, func() error) error {
	return errSwarmLockUnsupported
}

func withSwarmLockContext(context.Context, string, func() error) error {
	return errSwarmLockUnsupported
}
