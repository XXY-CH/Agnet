//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package verifier

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

const (
	maxOwnedJSONBytes   int64 = 1024 * 1024
	maxJSONNestingDepth       = 128
	maxJSONEntries            = 100_000
)

var (
	ownedJSONCurrentUID          = os.Getuid
	ownedJSONAfterParentVerified = func() error { return nil }
	ownedJSONAfterInitialStat    = func() error { return nil }
	ownedJSONAfterRead           = func() error { return nil }
)

func SafeOpenOwnedJSON(path string) (map[string]any, TrustInputFileEvidence, error) {
	var zero TrustInputFileEvidence
	if path == "" || strings.IndexByte(path, 0) >= 0 {
		return nil, zero, errors.New("owned JSON path invalid")
	}
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return nil, zero, err
	}
	expectedUID := uint32(ownedJSONCurrentUID())
	parentFD, finalName, err := openVerifiedOwnedJSONParent(absolutePath, expectedUID)
	if err != nil {
		return nil, zero, err
	}
	defer unix.Close(parentFD)
	if err := ownedJSONAfterParentVerified(); err != nil {
		return nil, zero, err
	}
	fileFD, err := unix.Openat(parentFD, finalName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, zero, fmt.Errorf("owned JSON no-follow open rejected symbolic link: %s", absolutePath)
		}
		return nil, zero, err
	}
	file := os.NewFile(uintptr(fileFD), absolutePath)
	if file == nil {
		unix.Close(fileFD)
		return nil, zero, errors.New("owned JSON file handle unavailable")
	}
	defer file.Close()

	initial, err := fstatOwnedJSON(fileFD, absolutePath, expectedUID)
	if err != nil {
		return nil, zero, err
	}
	if err := ownedJSONAfterInitialStat(); err != nil {
		return nil, zero, err
	}
	data, err := io.ReadAll(io.LimitReader(file, maxOwnedJSONBytes+1))
	if err != nil {
		return nil, zero, err
	}
	if int64(len(data)) > maxOwnedJSONBytes {
		return nil, zero, fmt.Errorf("owned JSON size limit exceeded: %s", absolutePath)
	}
	if err := ownedJSONAfterRead(); err != nil {
		return nil, zero, err
	}
	var completed unix.Stat_t
	if err := unix.Fstat(fileFD, &completed); err != nil {
		return nil, zero, err
	}
	if !sameOwnedJSONStat(initial, completed) {
		return nil, zero, fmt.Errorf("owned JSON changed during read: %s", absolutePath)
	}
	decoded, err := decodeJSONWithoutDuplicateKeys(data)
	if err != nil {
		return nil, zero, err
	}
	value, ok := decoded.(map[string]any)
	if !ok {
		return nil, zero, errors.New("owned JSON root must be an object")
	}
	return value, TrustInputFileEvidence{
		Path:   absolutePath,
		Device: uint64(initial.Dev),
		Inode:  uint64(initial.Ino),
		UID:    uint32(initial.Uid),
		Mode:   uint32(initial.Mode & 0o777),
		NLink:  uint64(initial.Nlink),
	}, nil
}

func openVerifiedOwnedJSONParent(path string, expectedUID uint32) (int, string, error) {
	components := splitAbsolutePath(path)
	if len(components) == 0 {
		return -1, "", errors.New("owned JSON path invalid")
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
		if err := verifyOwnedJSONDirectoryStat("/", &rootStat, expectedUID); err != nil {
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
					expectedTarget, resolvedTarget, allowed := allowedOwnedJSONPlatformSymlink(logical, uint32(stat.Uid))
					buffer := make([]byte, 256)
					length, readErr := unix.Readlinkat(fd, component, buffer)
					unix.Close(fd)
					if !allowed || readErr != nil || string(buffer[:length]) != expectedTarget {
						return -1, "", fmt.Errorf("unsafe parent symbolic link: %s", logical)
					}
					components = append(splitAbsolutePath(resolvedTarget), components[index+1:]...)
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
			if err := verifyOwnedJSONDirectoryStat(logical, &stat, expectedUID); err != nil {
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

func splitAbsolutePath(path string) []string {
	cleaned := filepath.Clean(path)
	return strings.FieldsFunc(strings.TrimPrefix(cleaned, string(filepath.Separator)), func(r rune) bool { return r == filepath.Separator })
}

// allowedOwnedJSONPlatformSymlink documents the only pathname symlinks accepted
// during parent traversal. They are opened by handle with AT_SYMLINK_NOFOLLOW,
// must be root-owned, and are rewritten to their fixed platform target before
// traversal restarts from /. Arbitrary user-controlled parent symlinks fail
// closed instead of being resolved by a second path walk.
func allowedOwnedJSONPlatformSymlink(path string, uid uint32) (string, string, bool) {
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

func verifyOwnedJSONDirectoryStat(path string, stat *unix.Stat_t, expectedUID uint32) error {
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("unsafe parent is not a directory: %s", path)
	}
	uid := uint32(stat.Uid)
	if uid != expectedUID && uid != 0 {
		return fmt.Errorf("owned JSON owner mismatch (unsafe parent owner): %s", path)
	}
	writableByOthers := stat.Mode&0o022 != 0
	rootStickyDirectory := uid == 0 && stat.Mode&unix.S_ISVTX != 0
	if writableByOthers && !rootStickyDirectory {
		return fmt.Errorf("unsafe parent mode: %s", path)
	}
	return nil
}

func fstatOwnedJSON(fd int, path string, expectedUID uint32) (unix.Stat_t, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return stat, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return stat, fmt.Errorf("owned JSON must be a regular file: %s", path)
	}
	if uint64(stat.Nlink) != 1 {
		return stat, fmt.Errorf("owned JSON link count must be one: %s", path)
	}
	if uint32(stat.Uid) != expectedUID {
		return stat, fmt.Errorf("owned JSON owner mismatch: %s", path)
	}
	if stat.Mode&0o777 != 0o600 {
		return stat, fmt.Errorf("owned JSON mode must be 0600: %s", path)
	}
	if stat.Size > maxOwnedJSONBytes {
		return stat, fmt.Errorf("owned JSON size limit exceeded: %s", path)
	}
	return stat, nil
}

func sameOwnedJSONStat(left, right unix.Stat_t) bool {
	return uint64(left.Dev) == uint64(right.Dev) && uint64(left.Ino) == uint64(right.Ino) && uint32(left.Uid) == uint32(right.Uid) && uint32(left.Mode) == uint32(right.Mode) && uint64(left.Nlink) == uint64(right.Nlink) && left.Size == right.Size
}

func validateCanonicalJSONStrings(data []byte) error {
	if !utf8.Valid(data) {
		return errors.New("canonical string domain requires valid UTF-8")
	}
	for index := 0; index < len(data); {
		if data[index] != '"' {
			_, size := utf8.DecodeRune(data[index:])
			index += size
			continue
		}
		index++
		for index < len(data) && data[index] != '"' {
			if data[index] == '\\' {
				index++
				if index >= len(data) {
					return errors.New("invalid JSON string escape")
				}
				if data[index] != 'u' {
					index++
					continue
				}
				code, ok := decodeJSONHex4(data, index+1)
				if !ok {
					return errors.New("invalid JSON Unicode escape")
				}
				index += 5
				if code >= 0xd800 && code <= 0xdbff {
					if index+6 > len(data) || data[index] != '\\' || data[index+1] != 'u' {
						return errors.New("canonical string domain requires Unicode scalar values")
					}
					low, valid := decodeJSONHex4(data, index+2)
					if !valid || low < 0xdc00 || low > 0xdfff {
						return errors.New("canonical string domain requires Unicode scalar values")
					}
					index += 6
				} else if code >= 0xdc00 && code <= 0xdfff {
					return errors.New("canonical string domain requires Unicode scalar values")
				} else if code == 0x2028 || code == 0x2029 {
					return errors.New("canonical string domain excludes U+2028/U+2029")
				}
				continue
			}
			r, size := utf8.DecodeRune(data[index:])
			if r == '\u2028' || r == '\u2029' {
				return errors.New("canonical string domain excludes U+2028/U+2029")
			}
			index += size
		}
		if index < len(data) {
			index++
		}
	}
	return nil
}

func decodeJSONHex4(data []byte, start int) (uint16, bool) {
	if start+4 > len(data) {
		return 0, false
	}
	var value uint16
	for _, char := range data[start : start+4] {
		value <<= 4
		switch {
		case char >= '0' && char <= '9':
			value |= uint16(char - '0')
		case char >= 'a' && char <= 'f':
			value |= uint16(char-'a') + 10
		case char >= 'A' && char <= 'F':
			value |= uint16(char-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}

func decodeJSONWithoutDuplicateKeys(data []byte) (any, error) {
	if err := validateCanonicalJSONStrings(data); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	first, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	entries := 0
	value, err := decodeJSONToken(decoder, first, 0, &entries)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("invalid JSON trailing value")
		}
		return nil, err
	}
	return value, nil
}

func decodeJSONToken(decoder *json.Decoder, token json.Token, depth int, entries *int) (any, error) {
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return token, nil
	}
	depth++
	if depth > maxJSONNestingDepth {
		return nil, errors.New("JSON nesting limit exceeded")
	}
	switch delimiter {
	case '{':
		value := map[string]any{}
		seen := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, errors.New("invalid JSON object key")
			}
			if _, exists := seen[key]; exists {
				return nil, fmt.Errorf("duplicate JSON key: %s", key)
			}
			seen[key] = struct{}{}
			if err := recordJSONEntry(entries); err != nil {
				return nil, err
			}
			itemToken, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			item, err := decodeJSONToken(decoder, itemToken, depth, entries)
			if err != nil {
				return nil, err
			}
			value[key] = item
		}
		closing, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		if closing != json.Delim('}') {
			return nil, errors.New("invalid JSON object close")
		}
		return value, nil
	case '[':
		value := []any{}
		for decoder.More() {
			if err := recordJSONEntry(entries); err != nil {
				return nil, err
			}
			itemToken, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			item, err := decodeJSONToken(decoder, itemToken, depth, entries)
			if err != nil {
				return nil, err
			}
			value = append(value, item)
		}
		closing, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		if closing != json.Delim(']') {
			return nil, errors.New("invalid JSON array close")
		}
		return value, nil
	default:
		return nil, errors.New("invalid JSON delimiter")
	}
}

func recordJSONEntry(entries *int) error {
	*entries += 1
	if *entries > maxJSONEntries {
		return errors.New("JSON entry limit exceeded")
	}
	return nil
}
