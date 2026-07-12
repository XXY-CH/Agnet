package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
)

const swarmViewFormat = "agnet-local-swarm-view/v1"

var ErrSwarmViewRepairNeeded = errors.New("swarm view repair needed")

// SwarmViewFaultPoint identifies a single projection replacement step. It is a
// test seam only; journal and receipt commitment never consult it.
type SwarmViewFaultPoint string

const (
	SwarmViewFaultCreate        SwarmViewFaultPoint = "create"
	SwarmViewFaultWrite         SwarmViewFaultPoint = "write"
	SwarmViewFaultFileSync      SwarmViewFaultPoint = "file_sync"
	SwarmViewFaultRename        SwarmViewFaultPoint = "rename"
	SwarmViewFaultDirectorySync SwarmViewFaultPoint = "directory_sync"
)

type SwarmViewFaultInjector func(SwarmViewFaultPoint) error

// SwarmView is a complete, replay-derived status projection. Its version and
// journal head bind it to exactly one validated journal replay.
type SwarmView struct {
	Format             string                   `json:"format"`
	SwarmID            string                   `json:"swarm_id"`
	Version            uint64                   `json:"version"`
	JournalHead        string                   `json:"journal_head"`
	Status             SwarmStatus              `json:"status"`
	Steps              []SwarmStepState         `json:"steps"`
	ReadyWave          ReadyWave                `json:"ready_wave"`
	Leases             []LeaseClaim             `json:"leases"`
	CommittedArtifacts map[string]ArtifactTriple `json:"committed_artifacts"`
	LastFence          LeaseFence               `json:"last_fence"`
}

// SwarmViewPaths identifies every disposable projection for one journal.
type SwarmViewPaths struct {
	Swarm     string
	Queue     string
	Artifacts string
	Audit     string
}

type swarmQueueView struct {
	Format      string           `json:"format"`
	SwarmID     string           `json:"swarm_id"`
	Version     uint64           `json:"version"`
	JournalHead string           `json:"journal_head"`
	Status      SwarmStatus      `json:"status"`
	Steps       []SwarmStepState `json:"steps"`
	ReadyWave   ReadyWave        `json:"ready_wave"`
	Leases      []LeaseClaim     `json:"leases"`
}

type swarmArtifactIndexRecord struct {
	Format        string        `json:"format"`
	SwarmID       string        `json:"swarm_id"`
	Version       uint64        `json:"version"`
	JournalHead   string        `json:"journal_head"`
	StepID        string        `json:"step_id"`
	ReceiptDigest string        `json:"receipt_digest"`
	Role          string        `json:"role"`
	Artifact      ArtifactTriple `json:"artifact"`
}

type swarmAuditViewRecord struct {
	Format            string          `json:"format"`
	SwarmID           string          `json:"swarm_id"`
	Sequence          uint64          `json:"sequence"`
	PriorStateVersion uint64          `json:"prior_state_version"`
	StateVersion      uint64          `json:"state_version"`
	Kind              string          `json:"kind"`
	Timestamp         string          `json:"timestamp"`
	PreviousHash      string          `json:"previous_hash"`
	Hash              string          `json:"hash"`
	Payload           json.RawMessage `json:"payload"`
}

type SwarmViewReplacementFailure struct {
	Path string
	Err  error
}

// SwarmViewRepairError reports independently failed replacements. Any successful
// replacement remains valid because every file is derived from the same replay.
type SwarmViewRepairError struct {
	Failures []SwarmViewReplacementFailure
}

func (e *SwarmViewRepairError) Error() string {
	if e == nil || len(e.Failures) == 0 {
		return ErrSwarmViewRepairNeeded.Error()
	}
	return fmt.Sprintf("%s: %d replacement(s) failed", ErrSwarmViewRepairNeeded, len(e.Failures))
}

func (e *SwarmViewRepairError) Unwrap() []error {
	if e == nil {
		return nil
	}
	errs := make([]error, 1, len(e.Failures)+1)
	errs[0] = ErrSwarmViewRepairNeeded
	for _, failure := range e.Failures {
		errs = append(errs, failure.Err)
	}
	return errs
}

// SwarmMaterializer converts the locked, validated journal into disposable
// files. It never appends to, repairs, or otherwise changes the journal.
type SwarmMaterializer struct {
	journal *SwarmJournal
	root    string
	fault   SwarmViewFaultInjector
}

func NewSwarmMaterializer(journal *SwarmJournal, faults ...SwarmViewFaultInjector) (*SwarmMaterializer, error) {
	if journal == nil {
		return nil, errors.New("swarm journal is required")
	}
	if len(faults) > 1 {
		return nil, errors.New("at most one swarm view fault injector is allowed")
	}
	root := filepath.Dir(filepath.Dir(journal.Path))
	if err := validateAbsoluteCleanPath(root); err != nil {
		return nil, fmt.Errorf("swarm view storage root: %w", err)
	}
	m := &SwarmMaterializer{journal: journal, root: root}
	if len(faults) == 1 {
		m.fault = faults[0]
	}
	return m, nil
}

func (m *SwarmMaterializer) Paths() SwarmViewPaths {
	if m == nil || m.journal == nil {
		return SwarmViewPaths{}
	}
	dir := filepath.Join(filepath.Dir(m.journal.Path), "views")
	return SwarmViewPaths{
		Swarm:     filepath.Join(dir, "swarm.json"),
		Queue:     filepath.Join(dir, "queue.json"),
		Artifacts: filepath.Join(dir, "artifacts.ndjson"),
		Audit:     filepath.Join(dir, "audit.ndjson"),
	}
}

// Rebuild replays the sole authority under the journal lock, computes all bytes
// before any projection replacement, then replaces each view independently.
func (m *SwarmMaterializer) Rebuild() (SwarmView, error) {
	if m == nil || m.journal == nil {
		return SwarmView{}, errors.New("swarm materializer journal is required")
	}
	var view SwarmView
	err := m.journal.WithLockedReplay(func(entries []SwarmJournalEntry) error {
		var err error
		view, err = m.materializeLocked(entries)
		return err
	})
	return view, err
}

// ReadSwarmView reads only a projection exactly matching the current validated
// replay. Deleted, corrupt, stale, and mixed-head files are rebuilt in-place.
func ReadSwarmView(journal *SwarmJournal, faults ...SwarmViewFaultInjector) (SwarmView, error) {
	materializer, err := NewSwarmMaterializer(journal, faults...)
	if err != nil {
		return SwarmView{}, err
	}
	return materializer.Read()
}

func (m *SwarmMaterializer) Read() (SwarmView, error) {
	if m == nil || m.journal == nil {
		return SwarmView{}, errors.New("swarm materializer journal is required")
	}
	var view SwarmView
	err := m.journal.WithLockedReplay(func(entries []SwarmJournalEntry) error {
		bytesByPath, derived, err := m.deriveLocked(entries)
		if err != nil {
			return err
		}
		view = derived
		if m.projectionsMatch(bytesByPath) {
			return nil
		}
		return m.replaceAll(bytesByPath)
	})
	return view, err
}

func (m *SwarmMaterializer) materializeLocked(entries []SwarmJournalEntry) (SwarmView, error) {
	bytesByPath, view, err := m.deriveLocked(entries)
	if err != nil {
		return SwarmView{}, err
	}
	return view, m.replaceAll(bytesByPath)
}

func (m *SwarmMaterializer) deriveLocked(entries []SwarmJournalEntry) (map[string][]byte, SwarmView, error) {
	state, err := ReduceSwarmEntries(entries)
	if err != nil {
		return nil, SwarmView{}, err
	}
	if state.Version == 0 || state.Spec.SwarmID == "" || len(entries) == 0 {
		return nil, SwarmView{}, errors.New("swarm journal has no durable opening")
	}
	head := entries[len(entries)-1]
	view := SwarmView{
		Format:             swarmViewFormat,
		SwarmID:            state.Spec.SwarmID,
		Version:            state.Version,
		JournalHead:        head.Hash,
		Status:             state.Status,
		Steps:              cloneSwarmState(state).Steps,
		ReadyWave:          cloneReadyWave(state.ReadyWave),
		Leases:             cloneLeaseClaims(state.Leases),
		CommittedArtifacts: cloneCommittedArtifacts(state.CommittedArtifacts),
		LastFence:          state.LastFence,
	}
	queue := swarmQueueView{
		Format: swarmViewFormat, SwarmID: view.SwarmID, Version: view.Version, JournalHead: view.JournalHead,
		Status: view.Status, Steps: view.Steps, ReadyWave: view.ReadyWave, Leases: view.Leases,
	}
	swarmBytes, err := canonicalViewJSON(view)
	if err != nil {
		return nil, SwarmView{}, err
	}
	queueBytes, err := canonicalViewJSON(queue)
	if err != nil {
		return nil, SwarmView{}, err
	}
	artifacts, err := materializedArtifactIndex(entries, view)
	if err != nil {
		return nil, SwarmView{}, err
	}
	audit, err := materializedAuditIndex(entries, view.SwarmID)
	if err != nil {
		return nil, SwarmView{}, err
	}
	paths := m.Paths()
	return map[string][]byte{paths.Swarm: swarmBytes, paths.Queue: queueBytes, paths.Artifacts: artifacts, paths.Audit: audit}, view, nil
}

func canonicalViewJSON(value any) ([]byte, error) {
	data, err := canonicalJSON(value)
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func cloneCommittedArtifacts(source map[string]ArtifactTriple) map[string]ArtifactTriple {
	out := make(map[string]ArtifactTriple, len(source))
	for stepID, artifact := range source {
		out[stepID] = artifact
	}
	return out
}

func materializedArtifactIndex(entries []SwarmJournalEntry, view SwarmView) ([]byte, error) {
	var out bytes.Buffer
	for _, entry := range entries {
		if entry.Kind != "receipt.committed" {
			continue
		}
		var payload receiptCommittedPayload
		if err := decodeStrictSwarmPayload(entry.Payload, &payload); err != nil || payload.validateCanonical() != nil {
			return nil, errors.New("committed receipt projection payload invalid")
		}
		records := make([]swarmArtifactIndexRecord, 0, 1+len(payload.Auxiliary))
		records = append(records, swarmArtifactIndexRecord{Format: swarmViewFormat, SwarmID: view.SwarmID, Version: view.Version, JournalHead: view.JournalHead, StepID: payload.Claim.StepID, ReceiptDigest: payload.ReceiptDigest, Role: "result", Artifact: payload.Result})
		for _, artifact := range payload.Auxiliary {
			records = append(records, swarmArtifactIndexRecord{Format: swarmViewFormat, SwarmID: view.SwarmID, Version: view.Version, JournalHead: view.JournalHead, StepID: payload.Claim.StepID, ReceiptDigest: payload.ReceiptDigest, Role: "auxiliary", Artifact: artifact})
		}
		for _, record := range records {
			data, err := canonicalJSON(record)
			if err != nil {
				return nil, err
			}
			out.Write(data)
			out.WriteByte('\n')
		}
	}
	return out.Bytes(), nil
}

func materializedAuditIndex(entries []SwarmJournalEntry, swarmID string) ([]byte, error) {
	var out bytes.Buffer
	for _, entry := range entries {
		record := swarmAuditViewRecord{Format: swarmViewFormat, SwarmID: swarmID, Sequence: entry.Sequence, PriorStateVersion: entry.PriorStateVersion, StateVersion: entry.StateVersion, Kind: entry.Kind, Timestamp: entry.Timestamp, PreviousHash: entry.PrevHash, Hash: entry.Hash, Payload: append(json.RawMessage(nil), entry.Payload...)}
		data, err := canonicalJSON(record)
		if err != nil {
			return nil, err
		}
		out.Write(data)
		out.WriteByte('\n')
	}
	return out.Bytes(), nil
}

func (m *SwarmMaterializer) projectionsMatch(want map[string][]byte) bool {
	for path, expected := range want {
		actual, err := readPrivateSwarmView(path)
		if err != nil || !bytes.Equal(actual, expected) {
			return false
		}
	}
	return true
}

func readPrivateSwarmView(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("swarm view is a symlink")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if err := validatePrivateRegularFile(file); err != nil {
		return nil, err
	}
	return io.ReadAll(file)
}

func (m *SwarmMaterializer) replaceAll(bytesByPath map[string][]byte) error {
	paths := m.Paths()
	if err := mkdirPrivateDirectory(filepath.Dir(paths.Swarm)); err != nil {
		return err
	}
	ordered := []string{paths.Swarm, paths.Queue, paths.Artifacts, paths.Audit}
	failures := make([]SwarmViewReplacementFailure, 0)
	for _, path := range ordered {
		data, ok := bytesByPath[path]
		if !ok {
			return errors.New("swarm view bytes missing")
		}
		if err := m.replaceOne(path, data); err != nil {
			failures = append(failures, SwarmViewReplacementFailure{Path: path, Err: err})
		}
	}
	if len(failures) != 0 {
		return &SwarmViewRepairError{Failures: failures}
	}
	return nil
}

func (m *SwarmMaterializer) replaceOne(path string, data []byte) error {
	if err := m.inject(SwarmViewFaultCreate); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".view-")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := m.inject(SwarmViewFaultWrite); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := m.inject(SwarmViewFaultFileSync); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := m.inject(SwarmViewFaultRename); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	if err := m.inject(SwarmViewFaultDirectorySync); err != nil {
		return err
	}
	return syncDirectory(dir)
}

func (m *SwarmMaterializer) inject(point SwarmViewFaultPoint) error {
	if m.fault == nil {
		return nil
	}
	return m.fault(point)
}

// RebuildAll discovers each private journal directory under this materializer's
// root and rebuilds views from each journal's opening identity.
func (m *SwarmMaterializer) RebuildAll() ([]SwarmView, error) {
	if m == nil || m.journal == nil {
		return nil, errors.New("swarm materializer journal is required")
	}
	return rebuildAllSwarmViews(m.root, m.fault)
}

func RebuildAll(storageRoot string, faults ...SwarmViewFaultInjector) ([]SwarmView, error) {
	if len(faults) > 1 {
		return nil, errors.New("at most one swarm view fault injector is allowed")
	}
	var fault SwarmViewFaultInjector
	if len(faults) == 1 {
		fault = faults[0]
	}
	return rebuildAllSwarmViews(storageRoot, fault)
}

func rebuildAllSwarmViews(storageRoot string, fault SwarmViewFaultInjector) ([]SwarmView, error) {
	if err := validateAbsoluteCleanPath(storageRoot); err != nil {
		return nil, fmt.Errorf("swarm view storage root: %w", err)
	}
	if err := validatePrivateDirectoryPath(storageRoot); err != nil {
		return nil, err
	}
	dirs, err := os.ReadDir(storageRoot)
	if err != nil {
		return nil, err
	}
	sort.Slice(dirs, func(i, j int) bool { return dirs[i].Name() < dirs[j].Name() })
	views := make([]SwarmView, 0, len(dirs))
	var errs []error
	for _, dir := range dirs {
		if !dir.IsDir() || len(dir.Name()) != 64 {
			continue
		}
		journalPath := filepath.Join(storageRoot, dir.Name(), "journal.ndjson")
		if _, err := os.Lstat(journalPath); errors.Is(err, os.ErrNotExist) {
			continue
		}
		swarmID, err := swarmIDFromJournalOpening(journalPath)
		if err != nil {
			errs = append(errs, fmt.Errorf("discover %s: %w", dir.Name(), err))
			continue
		}
		storageKey, err := swarmStorageKey(swarmID)
		if err != nil || storageKey != dir.Name() {
			errs = append(errs, fmt.Errorf("discover %s: journal storage identity conflicts", dir.Name()))
			continue
		}
		journal, err := OpenSwarmJournal(storageRoot, swarmID)
		if err != nil {
			errs = append(errs, fmt.Errorf("open %s: %w", dir.Name(), err))
			continue
		}
		materializer, err := NewSwarmMaterializer(journal, fault)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		view, err := materializer.Rebuild()
		if err != nil {
			errs = append(errs, fmt.Errorf("rebuild %s: %w", swarmID, err))
			continue
		}
		views = append(views, view)
	}
	return views, errors.Join(errs...)
}

func swarmIDFromJournalOpening(path string) (string, error) {
	file, err := openExistingSwarmJournal(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	data, err := io.ReadAll(file)
	if err != nil {
		return "", err
	}
	line, _, ok := bytes.Cut(data, []byte{'\n'})
	if !ok || len(line) == 0 {
		return "", errors.New("journal opening missing")
	}
	entry, err := decodeSwarmJournalEntry(line)
	if err != nil || entry.Kind != "swarm.opened" {
		return "", errors.New("journal opening invalid")
	}
	var payload swarmOpenedPayload
	if err := decodeStrictSwarmPayload(entry.Payload, &payload); err != nil {
		return "", err
	}
	spec, err := durableSwarmSpecFromWire(payload.Spec)
	if err != nil {
		return "", err
	}
	return spec.SwarmID, nil
}
