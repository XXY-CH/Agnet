//go:build unix

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

const maximumHumanGatewayTokenBytes = 64 * 1024

func resolveHumanGatewayToken(inlineToken, tokenFile string) (string, error) {
	if inlineToken != "" && tokenFile != "" {
		return "", errors.New("human gateway token and token file are mutually exclusive")
	}
	if tokenFile == "" {
		return inlineToken, nil
	}
	fd, err := unix.Open(tokenFile, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", fmt.Errorf("open human gateway token file: %w", err)
	}
	file := os.NewFile(uintptr(fd), tokenFile)
	if file == nil {
		_ = unix.Close(fd)
		return "", errors.New("open human gateway token file failed")
	}
	defer file.Close()
	if err := validatePrivateRegularFile(file); err != nil {
		return "", fmt.Errorf("human gateway token file is unsafe: %w", err)
	}
	contents, err := io.ReadAll(io.LimitReader(file, maximumHumanGatewayTokenBytes+1))
	if err != nil {
		return "", fmt.Errorf("read human gateway token file: %w", err)
	}
	if len(contents) > maximumHumanGatewayTokenBytes {
		return "", errors.New("human gateway token file exceeds size limit")
	}
	token := strings.TrimSpace(string(contents))
	if token == "" {
		return "", errors.New("human gateway token file is empty")
	}
	return token, nil
}
