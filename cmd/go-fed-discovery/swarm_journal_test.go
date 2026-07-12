package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

var swarmJournalTestTime = time.Date(2026, time.July, 12, 13, 14, 15, 123456789, time.UTC)

func newTestSwarmJournal(t *testing.T, faults ...SwarmFaultInjector) *SwarmJournal {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := OpenSwarmJournal(root, "swarm://test/alpha", faults...)
	if err != nil {
		t.Fatal(err)
	}
	return journal
}

func appendTestSwarmJournal(t *testing.T, journal *SwarmJournal, prior, next uint64, suffix string) SwarmJournalEntry {
	t.Helper()
	entry, err := journal.Append("step.completed", map[string]any{"step": suffix}, prior, next, swarmJournalTestTime.Add(time.Duration(next)*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	return entry
}

func TestSwarmJournalAppendReopenAndExactVersions(t *testing.T) {
	journal := newTestSwarmJournal(t)
	first := appendTestSwarmJournal(t, journal, 0, 1, "one")
	second := appendTestSwarmJournal(t, journal, 1, 2, "two")
	if first.Sequence != 1 || second.Sequence != 2 || first.PrevHash != swarmJournalZeroHash || second.PrevHash != first.Hash {
		t.Fatalf("journal chain = %#v, %#v", first, second)
	}
	if _, err := journal.Append("step.completed", map[string]any{"step": "gap"}, 2, 4, swarmJournalTestTime); err == nil {
		t.Fatal("Append accepted non-contiguous state versions")
	}
	reopened, err := OpenSwarmJournal(filepath.Dir(filepath.Dir(journal.Path)), "swarm://test/alpha")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := reopened.Replay()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(entries, []SwarmJournalEntry{first, second}) {
		t.Fatalf("Replay() = %#v; want appended entries", entries)
	}
	for _, path := range []string{journal.Path, journal.LockPath} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %o; want 0600", path, info.Mode().Perm())
		}
	}
}

func TestSwarmJournalRejectsStateVersionWraparoundWithoutMutation(t *testing.T) {
	entry := SwarmJournalEntry{
		Format:            swarmJournalFormat,
		Sequence:          1,
		PriorStateVersion: math.MaxUint64,
		StateVersion:      0,
		Kind:              "step.completed",
		Payload:           json.RawMessage(`{"step":"wrap"}`),
		Timestamp:         swarmJournalTestTime.Format(time.RFC3339Nano),
		PrevHash:          swarmJournalZeroHash,
	}
	entry.Hash = journalTestHash(entry)
	if err := validateSwarmJournalEntry(entry, 1, math.MaxUint64, swarmJournalZeroHash); err == nil {
		t.Fatal("validateSwarmJournalEntry accepted a valid-hash version wraparound")
	}

	journal := newTestSwarmJournal(t)
	if _, err := journal.Append("step.completed", map[string]any{"step": "wrap"}, math.MaxUint64, 0, swarmJournalTestTime); err == nil || !strings.Contains(err.Error(), "overflow") {
		t.Fatalf("Append() wraparound = %v; want overflow rejection", err)
	}
	if _, err := os.Stat(journal.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Append() wraparound journal stat = %v; want not exist", err)
	}
	before := append(journalTestLine(entry), '\n')
	if err := os.WriteFile(journal.Path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Replay(); err == nil {
		t.Fatal("Replay accepted a valid-hash version wraparound")
	}
	after, err := os.ReadFile(journal.Path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatalf("Replay mutated wraparound journal: got %q; want %q", after, before)
	}
}

func TestSwarmJournalNoImplicitResponseLossIdempotence(t *testing.T) {
	journal := newTestSwarmJournal(t)
	appendTestSwarmJournal(t, journal, 0, 1, "same")
	appendTestSwarmJournal(t, journal, 1, 2, "same")
	entries, err := journal.Replay()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("Replay() has %d entries; want two distinct committed operations", len(entries))
	}
}

func TestSwarmJournalCompleteCorruptionFailsClosedWithoutMutation(t *testing.T) {
	tests := []struct {
		name string
		line func(SwarmJournalEntry) []byte
	}{
		{name: "malformed", line: func(SwarmJournalEntry) []byte { return []byte(`{"format":`) }},
		{name: "unknown field", line: func(entry SwarmJournalEntry) []byte {
			return append([]byte(`{"unknown":true,`), journalTestLine(entry)[1:]...)
		}},
		{name: "duplicate payload", line: func(entry SwarmJournalEntry) []byte {
			return []byte(`{"format":"agnet-local-swarm-journal/v1","sequence":2,"prior_state_version":1,"state_version":2,"kind":"step.completed","payload":{"step":"two"},"payload":{"step":"shadow"},"timestamp":"2026-07-12T13:14:17.123456789Z","prev_hash":"` + entry.PrevHash + `","hash":"` + entry.Hash + `"}`)
		}},
		{name: "payload nested duplicate", line: func(entry SwarmJournalEntry) []byte {
			return []byte(`{"format":"agnet-local-swarm-journal/v1","sequence":2,"prior_state_version":1,"state_version":2,"kind":"step.completed","payload":{"step":"two","step":"shadow"},"timestamp":"2026-07-12T13:14:17.123456789Z","prev_hash":"` + entry.PrevHash + `","hash":"` + entry.Hash + `"}`)
		}},
		{name: "hash", line: func(entry SwarmJournalEntry) []byte {
			entry.Hash = strings.Repeat("0", 64)
			return journalTestLine(entry)
		}},
		{name: "sequence", line: func(entry SwarmJournalEntry) []byte {
			entry.Sequence = 3
			entry.Hash = journalTestHash(entry)
			return journalTestLine(entry)
		}},
		{name: "version", line: func(entry SwarmJournalEntry) []byte {
			entry.PriorStateVersion, entry.StateVersion = 7, 8
			entry.Hash = journalTestHash(entry)
			return journalTestLine(entry)
		}},
		{name: "timestamp", line: func(entry SwarmJournalEntry) []byte {
			entry.Timestamp = "2026-07-12 13:14:17Z"
			entry.Hash = journalTestHash(entry)
			return journalTestLine(entry)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			journal := newTestSwarmJournal(t)
			first := appendTestSwarmJournal(t, journal, 0, 1, "one")
			second := SwarmJournalEntry{Format: swarmJournalFormat, Sequence: 2, PriorStateVersion: 1, StateVersion: 2, Kind: "step.completed", Payload: json.RawMessage(`{"step":"two"}`), Timestamp: swarmJournalTestTime.Add(2 * time.Second).Format(time.RFC3339Nano), PrevHash: first.Hash}
			second.Hash = journalTestHash(second)
			before, err := os.ReadFile(journal.Path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(journal.Path, append(append([]byte{}, before...), append(tt.line(second), '\n')...), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := journal.Replay(); err == nil {
				t.Fatal("Replay() succeeded for complete corrupt record")
			}
			after, err := os.ReadFile(journal.Path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(after, append(before, append(tt.line(second), '\n')...)) {
				t.Fatal("Replay mutated complete corrupt journal")
			}
		})
	}
}

func TestSwarmJournalRecoversOnlyUnterminatedTrailingRecord(t *testing.T) {
	journal := newTestSwarmJournal(t)
	first := appendTestSwarmJournal(t, journal, 0, 1, "one")
	before, err := os.ReadFile(journal.Path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(journal.Path, append(before, []byte(`{"format":"agnet-local-swarm-journal/v1"`)...), 0o600); err != nil {
		t.Fatal(err)
	}
	entries, err := journal.Replay()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(entries, []SwarmJournalEntry{first}) {
		t.Fatalf("Replay() = %#v", entries)
	}
	after, err := os.ReadFile(journal.Path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatalf("unterminated recovery = %q; want %q", after, before)
	}
}

func TestSwarmJournalFirstCreateAndRollbackFaults(t *testing.T) {
	var points []SwarmFaultPoint
	journal := newTestSwarmJournal(t, func(point SwarmFaultPoint) error {
		points = append(points, point)
		return nil
	})
	appendTestSwarmJournal(t, journal, 0, 1, "one")
	if !reflect.DeepEqual(points, []SwarmFaultPoint{SwarmFaultCreate, SwarmFaultWrite, SwarmFaultFileSync, SwarmFaultParentSync}) {
		t.Fatalf("fault order = %#v", points)
	}

	writeFailure := errors.New("write failure")
	journal = newTestSwarmJournal(t, func(point SwarmFaultPoint) error {
		if point == SwarmFaultWrite {
			return writeFailure
		}
		return nil
	})
	if _, err := journal.Append("step.completed", map[string]any{"step": "one"}, 0, 1, swarmJournalTestTime); !errors.Is(err, writeFailure) {
		t.Fatalf("Append write failure = %v", err)
	}
	data, err := os.ReadFile(journal.Path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if len(data) != 0 {
		t.Fatalf("write rollback left %q", data)
	}

	syncFailure := errors.New("sync failure")
	journal = newTestSwarmJournal(t, func(point SwarmFaultPoint) error {
		if point == SwarmFaultFileSync {
			return syncFailure
		}
		return nil
	})
	if _, err := journal.Append("step.completed", map[string]any{"step": "one"}, 0, 1, swarmJournalTestTime); !errors.Is(err, syncFailure) {
		t.Fatalf("Append sync failure = %v", err)
	}
	data, err = os.ReadFile(journal.Path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if len(data) != 0 {
		t.Fatalf("sync rollback left %q", data)
	}
}

func TestSwarmJournalRollbackRetrySyncsParentBeforeSuccess(t *testing.T) {
	writeFailure := errors.New("write failure")
	parentFailure := errors.New("parent sync failure")
	var points []SwarmFaultPoint
	var writes, parentSyncs int
	journal := newTestSwarmJournal(t, func(point SwarmFaultPoint) error {
		points = append(points, point)
		switch point {
		case SwarmFaultWrite:
			writes++
			if writes == 1 {
				return writeFailure
			}
		case SwarmFaultParentSync:
			parentSyncs++
			if parentSyncs == 1 {
				return parentFailure
			}
		}
		return nil
	})
	if _, err := journal.Append("step.completed", map[string]any{"step": "one"}, 0, 1, swarmJournalTestTime); !errors.Is(err, writeFailure) {
		t.Fatalf("first Append() = %v; want write failure", err)
	}
	if _, err := journal.Append("step.completed", map[string]any{"step": "one"}, 0, 1, swarmJournalTestTime); !errors.Is(err, parentFailure) {
		t.Fatalf("retry Append() = %v; want parent sync failure", err)
	}
	entries, err := journal.Replay()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("Replay() entries = %#v; want one committed retry", entries)
	}
	appendTestSwarmJournal(t, journal, 1, 2, "two")
	wantPoints := []SwarmFaultPoint{
		SwarmFaultCreate, SwarmFaultWrite, SwarmFaultTruncate, SwarmFaultRollbackSync,
		SwarmFaultWrite, SwarmFaultFileSync, SwarmFaultParentSync,
		SwarmFaultWrite, SwarmFaultFileSync, SwarmFaultParentSync,
	}
	if !reflect.DeepEqual(points, wantPoints) {
		t.Fatalf("fault order = %#v; want %#v", points, wantPoints)
	}
}

func TestSwarmJournalPoisonedAfterRollbackSyncFailure(t *testing.T) {
	writeFailure := errors.New("write failure")
	rollbackFailure := errors.New("rollback sync failure")
	journal := newTestSwarmJournal(t, func(point SwarmFaultPoint) error {
		switch point {
		case SwarmFaultWrite:
			return writeFailure
		case SwarmFaultRollbackSync:
			return rollbackFailure
		default:
			return nil
		}
	})
	if _, err := journal.Append("step.completed", map[string]any{"step": "one"}, 0, 1, swarmJournalTestTime); !errors.Is(err, rollbackFailure) {
		t.Fatalf("Append() = %v; want rollback failure", err)
	}
	if _, err := journal.Append("step.completed", map[string]any{"step": "two"}, 0, 1, swarmJournalTestTime); err == nil || !strings.Contains(err.Error(), "poison") {
		t.Fatalf("poisoned Append() = %v", err)
	}
}

func TestSwarmJournalCreateParentAndTruncateFaultBoundaries(t *testing.T) {
	createFailure := errors.New("create failure")
	journal := newTestSwarmJournal(t, func(point SwarmFaultPoint) error {
		if point == SwarmFaultCreate {
			return createFailure
		}
		return nil
	})
	if _, err := journal.Append("step.completed", map[string]any{"step": "one"}, 0, 1, swarmJournalTestTime); !errors.Is(err, createFailure) {
		t.Fatalf("create fault Append() = %v", err)
	}
	if _, err := os.Stat(journal.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("create fault journal stat = %v; want not exist", err)
	}

	parentFailure := errors.New("parent sync failure")
	journal = newTestSwarmJournal(t, func(point SwarmFaultPoint) error {
		if point == SwarmFaultParentSync {
			return parentFailure
		}
		return nil
	})
	if _, err := journal.Append("step.completed", map[string]any{"step": "one"}, 0, 1, swarmJournalTestTime); !errors.Is(err, parentFailure) {
		t.Fatalf("parent sync Append() = %v", err)
	}
	entries, err := journal.Replay()
	if err != nil || len(entries) != 1 {
		t.Fatalf("parent sync response-loss replay = %#v, %v", entries, err)
	}
	if _, err := journal.Append("step.completed", map[string]any{"step": "one"}, 0, 1, swarmJournalTestTime); err == nil {
		t.Fatal("response-loss retry silently deduplicated a committed append")
	}

	writeFailure := errors.New("write failure")
	truncateFailure := errors.New("truncate failure")
	journal = newTestSwarmJournal(t, func(point SwarmFaultPoint) error {
		switch point {
		case SwarmFaultWrite:
			return writeFailure
		case SwarmFaultTruncate:
			return truncateFailure
		default:
			return nil
		}
	})
	if _, err := journal.Append("step.completed", map[string]any{"step": "one"}, 0, 1, swarmJournalTestTime); !errors.Is(err, truncateFailure) {
		t.Fatalf("truncate rollback Append() = %v", err)
	}
	if _, err := journal.Replay(); err == nil || !strings.Contains(err.Error(), "poison") {
		t.Fatalf("poisoned Replay() = %v", err)
	}
}

func journalTestLine(entry SwarmJournalEntry) []byte {
	data, err := canonicalJSON(entry)
	if err != nil {
		panic(err)
	}
	return data
}

func journalTestHash(entry SwarmJournalEntry) string {
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
		panic(err)
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func TestSwarmJournalAppendRejectsInvalidTypedCandidatesWithoutMutation(t *testing.T) {
	journal := newTestSwarmJournal(t)
	if _, err := OpenVerifiedSwarm(journal, reducerTestDurableSpec(t), swarmJournalTestTime); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []struct {
		name    string
		kind    string
		payload any
	}{
		{name: "illegal transition", kind: "step.completed", payload: map[string]any{"schema_version": 1, "step_id": "prepare"}},
		{name: "malformed registered payload", kind: "step.started", payload: map[string]any{"schema_version": 2, "step_id": "prepare"}},
	} {
		t.Run(candidate.name, func(t *testing.T) {
			before, err := os.ReadFile(journal.Path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := journal.Append(candidate.kind, candidate.payload, 1, 2, swarmJournalTestTime.Add(time.Second)); err == nil {
				t.Fatalf("Append accepted %s", candidate.name)
			}
			after, err := os.ReadFile(journal.Path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(after, before) {
				t.Fatalf("%s changed journal bytes: got %q; want %q", candidate.name, after, before)
			}
			entries := mustReplaySwarm(t, journal)
			if len(entries) != 1 || entries[0].Hash == "" {
				t.Fatalf("%s changed journal head: %#v", candidate.name, entries)
			}
		})
	}
}

func TestSwarmJournalAppendValidatesOpeningSeedBeforeDurableWrite(t *testing.T) {
	journal := newTestSwarmJournal(t)
	if _, err := journal.Append("swarm.opened", map[string]any{"schema_version": 1}, 0, 1, swarmJournalTestTime); err == nil {
		t.Fatal("Append accepted an invalid opening seed")
	}
	if _, err := os.Stat(journal.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid opening seed created journal: %v", err)
	}
}

func TestSwarmJournalPreservesFutureEntriesDuringTypedReplay(t *testing.T) {
	journal := newTestSwarmJournal(t)
	if _, err := OpenVerifiedSwarm(journal, reducerTestDurableSpec(t), swarmJournalTestTime); err != nil {
		t.Fatal(err)
	}
	future, err := journal.Append("future.audit", map[string]any{"event": "recorded"}, 1, 2, swarmJournalTestTime.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	entries := mustReplaySwarm(t, journal)
	if len(entries) != 2 || !reflect.DeepEqual(entries[1], future) {
		t.Fatalf("typed replay dropped future entry: %#v", entries)
	}
	state, err := ReduceSwarmEntries(entries)
	if err != nil {
		t.Fatal(err)
	}
	if state.Version != 2 || state.Status != SwarmStatusOpen {
		t.Fatalf("future entry changed typed state: %#v", state)
	}
}
