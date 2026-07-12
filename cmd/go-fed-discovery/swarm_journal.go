package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	swarmJournalFormat   = "agnet-local-swarm-journal/v1"
	swarmJournalZeroHash = "0000000000000000000000000000000000000000000000000000000000000000"
)

// SwarmJournalEntry is one immutable state transition in the authoritative local Swarm journal.
type SwarmJournalEntry struct {
	Format            string          `json:"format"`
	Sequence          uint64          `json:"sequence"`
	PriorStateVersion uint64          `json:"prior_state_version"`
	StateVersion      uint64          `json:"state_version"`
	Kind              string          `json:"kind"`
	Payload           json.RawMessage `json:"payload"`
	Timestamp         string          `json:"timestamp"`
	PrevHash          string          `json:"prev_hash"`
	Hash              string          `json:"hash"`
}

// SwarmFaultPoint identifies a durable-storage operation that tests may fail deterministically.
type SwarmFaultPoint string

const (
	SwarmFaultCreate       SwarmFaultPoint = "create"
	SwarmFaultParentSync   SwarmFaultPoint = "parent_sync"
	SwarmFaultWrite        SwarmFaultPoint = "write"
	SwarmFaultFileSync     SwarmFaultPoint = "file_sync"
	SwarmFaultTruncate     SwarmFaultPoint = "truncate"
	SwarmFaultRollbackSync SwarmFaultPoint = "rollback_sync"
)

// SwarmFaultInjector is a test-only failure seam. A non-nil returned error aborts that operation.
type SwarmFaultInjector func(SwarmFaultPoint) error

// SwarmJournal stores the sole durable state authority for one Swarm.
type SwarmJournal struct {
	Path     string
	LockPath string

	fault SwarmFaultInjector
	mu    sync.Mutex
	poison error
}

// OpenSwarmJournal opens and validates the authoritative journal for swarmID. It never falls back
// to a projection or state file; an existing invalid journal therefore fails closed.
func OpenSwarmJournal(storageRoot, swarmID string, faults ...SwarmFaultInjector) (*SwarmJournal, error) {
	if storageRoot == "" || swarmID == "" {
		return nil, errors.New("swarm journal storage root and swarm id are required")
	}
	dir, err := openSwarmStorageDir(storageRoot, swarmID)
	if err != nil {
		return nil, err
	}
	journal := &SwarmJournal{
		Path:     filepath.Join(dir, "journal.ndjson"),
		LockPath: filepath.Join(dir, "journal.lock"),
	}
	if len(faults) > 1 {
		return nil, errors.New("at most one swarm journal fault injector is allowed")
	}
	if len(faults) == 1 {
		journal.fault = faults[0]
	}
	if _, err := journal.Replay(); err != nil {
		return nil, err
	}
	return journal, nil
}

// Replay obtains the per-Swarm cross-process lock, recovers only an unterminated final record,
// and returns the fully validated journal chain.
func (j *SwarmJournal) Replay() ([]SwarmJournalEntry, error) {
	var entries []SwarmJournalEntry
	err := j.WithLockedReplay(func(replayed []SwarmJournalEntry) error {
		entries = replayed
		return nil
	})
	return entries, err
}

// WithLockedReplay runs fn while holding the cross-process journal lock against a current,
// validated replay. Callers must treat entries as immutable snapshots.
func (j *SwarmJournal) WithLockedReplay(fn func([]SwarmJournalEntry) error) error {
	if j == nil || fn == nil {
		return errors.New("swarm journal and replay callback are required")
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.poison != nil {
		return fmt.Errorf("swarm journal poisoned: %w", j.poison)
	}
	return withSwarmLock(j.LockPath, func() error {
		entries, err := j.replayLocked()
		if err != nil {
			return err
		}
		return fn(entries)
	})
}

// Append appends one exact contiguous state transition. The journal is replayed under the lock
// immediately before append so each process observes and extends the current durable chain.
func (j *SwarmJournal) Append(kind string, payload any, priorStateVersion, stateVersion uint64, timestamp time.Time) (SwarmJournalEntry, error) {
	var appended SwarmJournalEntry
	if j == nil {
		return appended, errors.New("swarm journal is required")
	}
	if kind == "" || strings.IndexByte(kind, 0) >= 0 {
		return appended, errors.New("swarm journal kind invalid")
	}
	if priorStateVersion == math.MaxUint64 {
		return appended, errors.New("swarm journal state version overflow")
	}
	canonicalPayload, err := canonicalSwarmPayload(payload)
	if err != nil {
		return appended, err
	}
	canonicalTimestamp, err := canonicalSwarmTimestamp(timestamp)
	if err != nil {
		return appended, err
	}

	j.mu.Lock()
	defer j.mu.Unlock()
	if j.poison != nil {
		return appended, fmt.Errorf("swarm journal poisoned: %w", j.poison)
	}
	err = withSwarmLock(j.LockPath, func() error {
		entries, err := j.replayLocked()
		if err != nil {
			return err
		}
		previousHash := swarmJournalZeroHash
		previousVersion := uint64(0)
		if len(entries) != 0 {
			last := entries[len(entries)-1]
			previousHash = last.Hash
			previousVersion = last.StateVersion
		}
		if priorStateVersion != previousVersion || stateVersion != priorStateVersion+1 {
			return errors.New("swarm journal state versions are not contiguous")
		}
		entry := SwarmJournalEntry{
			Format:            swarmJournalFormat,
			Sequence:          uint64(len(entries) + 1),
			PriorStateVersion: priorStateVersion,
			StateVersion:      stateVersion,
			Kind:              kind,
			Payload:           canonicalPayload,
			Timestamp:         canonicalTimestamp,
			PrevHash:          previousHash,
		}
		entry.Hash, err = swarmJournalEntryHash(entry)
		if err != nil {
			return err
		}
		if err := j.appendLocked(entry); err != nil {
			return err
		}
		appended = entry
		return nil
	})
	return appended, err
}

func (j *SwarmJournal) replayLocked() ([]SwarmJournalEntry, error) {
	file, err := openExistingSwarmJournal(j.Path)
	if errors.Is(err, os.ErrNotExist) {
		return []SwarmJournalEntry{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()

	entries := make([]SwarmJournalEntry, 0)
	previousHash := swarmJournalZeroHash
	previousVersion := uint64(0)
	trailingOffset, err := readSwarmJournalRecords(file, func(line []byte) error {
		entry, err := decodeSwarmJournalEntry(line)
		if err != nil {
			return err
		}
		if err := validateSwarmJournalEntry(entry, uint64(len(entries)+1), previousVersion, previousHash); err != nil {
			return err
		}
		entries = append(entries, entry)
		previousHash = entry.Hash
		previousVersion = entry.StateVersion
		return nil
	})
	if err != nil {
		return nil, err
	}
	if trailingOffset >= 0 {
		if err := j.inject(SwarmFaultTruncate); err != nil {
			return nil, err
		}
		if err := file.Truncate(trailingOffset); err != nil {
			return nil, err
		}
		if err := j.inject(SwarmFaultRollbackSync); err != nil {
			j.poison = err
			return nil, fmt.Errorf("swarm journal recovery rollback sync: %w", err)
		}
		if err := file.Sync(); err != nil {
			j.poison = err
			return nil, fmt.Errorf("swarm journal recovery rollback sync: %w", err)
		}
	}
	return entries, nil
}

func (j *SwarmJournal) appendLocked(entry SwarmJournalEntry) error {
	file, _, err := createOrOpenSwarmJournal(j.Path, j.inject)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	priorOffset := info.Size()
	data, err := canonicalJSON(entry)
	if err != nil {
		return err
	}
	data = append(data, '\n')

	if err := j.inject(SwarmFaultWrite); err != nil {
		return j.rollbackAppend(file, priorOffset, err)
	}
	for remaining := data; len(remaining) > 0; {
		count, writeErr := file.Write(remaining)
		if count > 0 {
			remaining = remaining[count:]
		}
		if writeErr != nil {
			return j.rollbackAppend(file, priorOffset, writeErr)
		}
		if count == 0 {
			return j.rollbackAppend(file, priorOffset, io.ErrShortWrite)
		}
	}
	if err := j.inject(SwarmFaultFileSync); err != nil {
		return j.rollbackAppend(file, priorOffset, err)
	}
	if err := file.Sync(); err != nil {
		return j.rollbackAppend(file, priorOffset, err)
	}
	if err := j.inject(SwarmFaultParentSync); err != nil {
		return err
	}
	if err := syncSwarmJournalParent(j.Path); err != nil {
		return err
	}
	return nil
}

func (j *SwarmJournal) rollbackAppend(file *os.File, priorOffset int64, appendErr error) error {
	if err := j.inject(SwarmFaultTruncate); err != nil {
		j.poison = err
		return errors.Join(appendErr, fmt.Errorf("swarm journal rollback truncate: %w", err))
	}
	if err := file.Truncate(priorOffset); err != nil {
		j.poison = err
		return errors.Join(appendErr, fmt.Errorf("swarm journal rollback truncate: %w", err))
	}
	if err := j.inject(SwarmFaultRollbackSync); err != nil {
		j.poison = err
		return errors.Join(appendErr, fmt.Errorf("swarm journal rollback sync: %w", err))
	}
	if err := file.Sync(); err != nil {
		j.poison = err
		return errors.Join(appendErr, fmt.Errorf("swarm journal rollback sync: %w", err))
	}
	return appendErr
}

func (j *SwarmJournal) inject(point SwarmFaultPoint) error {
	if j.fault == nil {
		return nil
	}
	return j.fault(point)
}

func createOrOpenSwarmJournal(path string, inject func(SwarmFaultPoint) error) (*os.File, bool, error) {
	file, err := openExistingSwarmJournal(path)
	if err == nil {
		if _, err := file.Seek(0, io.SeekEnd); err != nil {
			file.Close()
			return nil, false, err
		}
		return file, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, false, err
	}
	if err := inject(SwarmFaultCreate); err != nil {
		return nil, false, err
	}
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW, 0o600)
	if err == nil {
		file = os.NewFile(uintptr(fd), path)
		if err := validateSwarmJournalFile(file); err != nil {
			file.Close()
			return nil, false, err
		}
		return file, true, nil
	}
	if !errors.Is(err, unix.EEXIST) {
		return nil, false, err
	}
	file, err = openExistingSwarmJournal(path)
	if err != nil {
		return nil, false, err
	}
	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		file.Close()
		return nil, false, err
	}
	return file, false, nil
}

func openExistingSwarmJournal(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, os.ErrNotExist
		}
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if err := validateSwarmJournalFile(file); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func validateSwarmJournalFile(file *os.File) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return errors.New("swarm journal must be a private regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 || int(stat.Uid) != os.Geteuid() {
		return errors.New("swarm journal ownership invalid")
	}
	return nil
}

func syncSwarmJournalParent(path string) error {
	fd, err := unix.Open(filepath.Dir(path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	dir := os.NewFile(uintptr(fd), filepath.Dir(path))
	defer dir.Close()
	return dir.Sync()
}

// readSwarmJournalRecords reads line records with byte offsets, never Scanner. It returns the
// start offset of one unterminated final record, or -1 when every record is complete.
func readSwarmJournalRecords(file *os.File, consume func([]byte) error) (int64, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return -1, err
	}
	buffer := make([]byte, 32*1024)
	pending := make([]byte, 0, 32*1024)
	var offset, pendingStart int64
	for {
		count, readErr := file.Read(buffer)
		if count > 0 {
			chunk := buffer[:count]
			start := 0
			for index, value := range chunk {
				if value != '\n' {
					continue
				}
				line := append(pending, chunk[start:index]...)
				if err := consume(line); err != nil {
					return -1, err
				}
				pending = pending[:0]
				start = index + 1
				pendingStart = offset + int64(start)
			}
			pending = append(pending, chunk[start:]...)
			offset += int64(count)
		}
		if readErr == nil {
			continue
		}
		if errors.Is(readErr, io.EOF) {
			if len(pending) != 0 {
				return pendingStart, nil
			}
			return -1, nil
		}
		return -1, readErr
	}
}

func decodeSwarmJournalEntry(line []byte) (SwarmJournalEntry, error) {
	var entry SwarmJournalEntry
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return entry, errors.New("swarm journal entry malformed")
	}
	seen := make(map[string]bool, 9)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return entry, errors.New("swarm journal entry malformed")
		}
		name, ok := token.(string)
		if !ok || seen[name] {
			return entry, errors.New("swarm journal entry duplicate field")
		}
		seen[name] = true
		switch name {
		case "format":
			err = decoder.Decode(&entry.Format)
		case "sequence":
			err = decoder.Decode(&entry.Sequence)
		case "prior_state_version":
			err = decoder.Decode(&entry.PriorStateVersion)
		case "state_version":
			err = decoder.Decode(&entry.StateVersion)
		case "kind":
			err = decoder.Decode(&entry.Kind)
		case "payload":
			err = decoder.Decode(&entry.Payload)
		case "timestamp":
			err = decoder.Decode(&entry.Timestamp)
		case "prev_hash":
			err = decoder.Decode(&entry.PrevHash)
		case "hash":
			err = decoder.Decode(&entry.Hash)
		default:
			return entry, errors.New("swarm journal entry unknown field")
		}
		if err != nil {
			return entry, errors.New("swarm journal entry malformed")
		}
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return entry, errors.New("swarm journal entry malformed")
	}
	if err := ensureSwarmJSONEOF(decoder); err != nil {
		return entry, errors.New("swarm journal entry malformed")
	}
	if len(seen) != 9 {
		return entry, errors.New("swarm journal entry fields invalid")
	}
	payload, err := canonicalSwarmPayload(entry.Payload)
	if err != nil {
		return entry, err
	}
	entry.Payload = payload
	return entry, nil
}

func validateSwarmJournalEntry(entry SwarmJournalEntry, sequence, priorVersion uint64, previousHash string) error {
	if entry.PriorStateVersion == math.MaxUint64 {
		return errors.New("swarm journal state version overflow")
	}
	if entry.Format != swarmJournalFormat || entry.Sequence != sequence || entry.PriorStateVersion != priorVersion || entry.StateVersion != priorVersion+1 {
		return errors.New("swarm journal sequence or state version invalid")
	}
	if entry.Kind == "" || strings.IndexByte(entry.Kind, 0) >= 0 {
		return errors.New("swarm journal kind invalid")
	}
	if _, err := parseCanonicalSwarmTimestamp(entry.Timestamp); err != nil {
		return err
	}
	if entry.PrevHash != previousHash || !isSwarmJournalHash(entry.PrevHash) || !isSwarmJournalHash(entry.Hash) {
		return errors.New("swarm journal hash invalid")
	}
	expectedHash, err := swarmJournalEntryHash(entry)
	if err != nil {
		return err
	}
	if entry.Hash != expectedHash {
		return errors.New("swarm journal hash mismatch")
	}
	return nil
}

func canonicalSwarmPayload(payload any) (json.RawMessage, error) {
	var source []byte
	switch typed := payload.(type) {
	case json.RawMessage:
		source = typed
	case []byte:
		source = typed
	default:
		encoded, err := canonicalJSON(payload)
		if err != nil {
			return nil, fmt.Errorf("swarm journal payload invalid: %w", err)
		}
		source = encoded
	}
	if len(source) == 0 || !json.Valid(source) {
		return nil, errors.New("swarm journal payload invalid")
	}
	if err := validateSwarmJSONNoDuplicateFields(source); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(source))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, errors.New("swarm journal payload invalid")
	}
	if err := ensureSwarmJSONEOF(decoder); err != nil {
		return nil, errors.New("swarm journal payload invalid")
	}
	canonical, err := canonicalJSON(value)
	if err != nil {
		return nil, fmt.Errorf("swarm journal payload invalid: %w", err)
	}
	return json.RawMessage(canonical), nil
}

func validateSwarmJSONNoDuplicateFields(source []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(source))
	decoder.UseNumber()
	if err := consumeSwarmJSONValue(decoder); err != nil {
		return errors.New("swarm journal payload duplicate or malformed field")
	}
	if err := ensureSwarmJSONEOF(decoder); err != nil {
		return errors.New("swarm journal payload duplicate or malformed field")
	}
	return nil
}

func consumeSwarmJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	switch delimiter := token.(type) {
	case json.Delim:
		switch delimiter {
		case '{':
			seen := map[string]struct{}{}
			for decoder.More() {
				nameToken, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := nameToken.(string)
				if !ok {
					return errors.New("object key invalid")
				}
				if _, exists := seen[name]; exists {
					return errors.New("duplicate field")
				}
				seen[name] = struct{}{}
				if err := consumeSwarmJSONValue(decoder); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return errors.New("object malformed")
			}
		case '[':
			for decoder.More() {
				if err := consumeSwarmJSONValue(decoder); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return errors.New("array malformed")
			}
		default:
			return errors.New("delimiter malformed")
		}
	}
	return nil
}

func ensureSwarmJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

func canonicalSwarmTimestamp(timestamp time.Time) (string, error) {
	if timestamp.IsZero() {
		return "", errors.New("swarm journal timestamp invalid")
	}
	return timestamp.UTC().Format(time.RFC3339Nano), nil
}

func parseCanonicalSwarmTimestamp(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.UTC().Format(time.RFC3339Nano) != value {
		return time.Time{}, errors.New("swarm journal timestamp invalid")
	}
	return parsed, nil
}

func swarmJournalEntryHash(entry SwarmJournalEntry) (string, error) {
	body := map[string]any{
		"format":              entry.Format,
		"sequence":            entry.Sequence,
		"prior_state_version": entry.PriorStateVersion,
		"state_version":       entry.StateVersion,
		"kind":                entry.Kind,
		"payload":             entry.Payload,
		"timestamp":           entry.Timestamp,
		"prev_hash":           entry.PrevHash,
	}
	data, err := canonicalJSON(body)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

func isSwarmJournalHash(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
