//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package managedkey

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"
)

const maxRestrictedFileBytes int64 = 1024 * 1024

var restrictedFileCurrentUID = os.Getuid

type RestrictedFileOptions struct {
	Label    string
	MaxBytes int64
}

type RestrictedFileEvidence struct {
	Path   string `json:"path"`
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	UID    uint32 `json:"uid"`
	Mode   uint32 `json:"mode"`
	NLink  uint64 `json:"nlink"`
}

type RestrictedFile struct {
	Bytes    []byte
	Evidence RestrictedFileEvidence
}

func ReadRestrictedFile(path string, options RestrictedFileOptions) (RestrictedFile, error) {
	var zero RestrictedFile
	label := options.Label
	if label == "" {
		label = "restricted file"
	}
	if strings.ContainsAny(label, "\r\n") || len(label) > 64 {
		return zero, errors.New("restricted file label invalid")
	}
	maxBytes := options.MaxBytes
	if maxBytes == 0 {
		maxBytes = 64 * 1024
	}
	if maxBytes <= 0 || maxBytes > maxRestrictedFileBytes {
		return zero, errors.New("restricted file max bytes invalid")
	}
	if path == "" || strings.IndexByte(path, 0) >= 0 {
		return zero, fmt.Errorf("%s path invalid", label)
	}
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return zero, err
	}
	expectedUID := uint32(restrictedFileCurrentUID())
	parentFD, finalName, err := openRestrictedParent(absolutePath, expectedUID, label)
	if err != nil {
		return zero, err
	}
	defer unix.Close(parentFD)
	fileFD, err := unix.Openat(parentFD, finalName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return zero, fmt.Errorf("%s no-follow open rejected symbolic link: %s", label, absolutePath)
		}
		return zero, err
	}
	file := os.NewFile(uintptr(fileFD), absolutePath)
	if file == nil {
		unix.Close(fileFD)
		return zero, fmt.Errorf("%s file handle unavailable", label)
	}
	defer file.Close()
	initial, err := fstatRestricted(fileFD, absolutePath, expectedUID, maxBytes, label)
	if err != nil {
		return zero, err
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return zero, err
	}
	if int64(len(data)) > maxBytes {
		return zero, fmt.Errorf("%s size limit exceeded: %s", label, absolutePath)
	}
	var completed unix.Stat_t
	if err := unix.Fstat(fileFD, &completed); err != nil {
		return zero, err
	}
	if !sameRestrictedStat(initial, completed) {
		clear(data)
		return zero, fmt.Errorf("%s changed during read: %s", label, absolutePath)
	}
	return RestrictedFile{Bytes: data, Evidence: RestrictedFileEvidence{
		Path: absolutePath, Device: uint64(initial.Dev), Inode: uint64(initial.Ino), UID: uint32(initial.Uid), Mode: uint32(initial.Mode & 0o777), NLink: uint64(initial.Nlink),
	}}, nil
}

func openRestrictedParent(path string, expectedUID uint32, label string) (int, string, error) {
	components := restrictedPathComponents(path)
	if len(components) == 0 {
		return -1, "", fmt.Errorf("%s path invalid", label)
	}
	finalName := components[len(components)-1]
	components = components[:len(components)-1]
	for symlinkDepth := 0; symlinkDepth <= 4; symlinkDepth++ {
		fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			return -1, "", err
		}
		var rootStat unix.Stat_t
		if err := unix.Fstat(fd, &rootStat); err != nil {
			unix.Close(fd)
			return -1, "", err
		}
		if err := verifyRestrictedDirectory("/", &rootStat, expectedUID, label); err != nil {
			unix.Close(fd)
			return -1, "", err
		}
		logical := ""
		restarted := false
		for index, component := range components {
			logical += "/" + component
			next, openErr := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
			if openErr != nil {
				var stat unix.Stat_t
				if err := unix.Fstatat(fd, component, &stat, unix.AT_SYMLINK_NOFOLLOW); err == nil && stat.Mode&unix.S_IFMT == unix.S_IFLNK {
					expectedTarget, resolvedTarget, allowed := allowedRestrictedPlatformSymlink(logical, uint32(stat.Uid))
					buffer := make([]byte, 256)
					length, readErr := unix.Readlinkat(fd, component, buffer)
					unix.Close(fd)
					if !allowed || readErr != nil || string(buffer[:length]) != expectedTarget {
						return -1, "", fmt.Errorf("unsafe parent symbolic link: %s", logical)
					}
					components = append(restrictedPathComponents(resolvedTarget), components[index+1:]...)
					restarted = true
					break
				}
				unix.Close(fd)
				return -1, "", openErr
			}
			unix.Close(fd)
			fd = next
			var stat unix.Stat_t
			if err := unix.Fstat(fd, &stat); err != nil {
				unix.Close(fd)
				return -1, "", err
			}
			if err := verifyRestrictedDirectory(logical, &stat, expectedUID, label); err != nil {
				unix.Close(fd)
				return -1, "", err
			}
		}
		if !restarted {
			return fd, finalName, nil
		}
	}
	return -1, "", errors.New("unsafe parent symbolic link depth exceeded")
}

func restrictedPathComponents(path string) []string {
	cleaned := filepath.Clean(path)
	return strings.FieldsFunc(strings.TrimPrefix(cleaned, string(filepath.Separator)), func(character rune) bool { return character == filepath.Separator })
}

func allowedRestrictedPlatformSymlink(path string, uid uint32) (string, string, bool) {
	if runtime.GOOS != "darwin" || uid != 0 {
		return "", "", false
	}
	targets := map[string][2]string{
		"/etc": {"private/etc", "/private/etc"},
		"/tmp": {"private/tmp", "/private/tmp"},
		"/var": {"private/var", "/private/var"},
	}
	target, ok := targets[path]
	return target[0], target[1], ok
}

func verifyRestrictedDirectory(path string, stat *unix.Stat_t, expectedUID uint32, label string) error {
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("unsafe parent is not a directory: %s", path)
	}
	uid := uint32(stat.Uid)
	if uid != expectedUID && uid != 0 {
		return fmt.Errorf("%s owner mismatch (unsafe parent owner): %s", label, path)
	}
	writableByOthers := stat.Mode&0o022 != 0
	rootStickyDirectory := uid == 0 && stat.Mode&unix.S_ISVTX != 0
	if writableByOthers && !rootStickyDirectory {
		return fmt.Errorf("unsafe parent mode: %s", path)
	}
	return nil
}

func fstatRestricted(fd int, path string, expectedUID uint32, maxBytes int64, label string) (unix.Stat_t, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return stat, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return stat, fmt.Errorf("%s must be a regular file: %s", label, path)
	}
	if uint64(stat.Nlink) != 1 {
		return stat, fmt.Errorf("%s link count must be one: %s", label, path)
	}
	if uint32(stat.Uid) != expectedUID {
		return stat, fmt.Errorf("%s owner mismatch: %s", label, path)
	}
	if stat.Mode&0o777 != 0o600 {
		return stat, fmt.Errorf("%s mode must be 0600: %s", label, path)
	}
	if stat.Size > maxBytes {
		return stat, fmt.Errorf("%s size limit exceeded: %s", label, path)
	}
	return stat, nil
}

func sameRestrictedStat(left, right unix.Stat_t) bool {
	return uint64(left.Dev) == uint64(right.Dev) && uint64(left.Ino) == uint64(right.Ino) && uint32(left.Uid) == uint32(right.Uid) && uint32(left.Mode) == uint32(right.Mode) && uint64(left.Nlink) == uint64(right.Nlink) && left.Size == right.Size
}
