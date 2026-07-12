package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const (
	defaultLocalSwarmLeaseTTL     = 30 * time.Second
	defaultLocalSwarmPollInterval = 10 * time.Millisecond
)

// LocalSwarmCoordinator owns the parent-side local execution loop. The journal
// is the authority: worker exit values are diagnostic only and never advance a
// wave or authorize an outbound frame.
type LocalSwarmCoordinator struct {
	fixture     Fixture
	storageRoot string
	owner       string
	launcher    SwarmWorkerLauncher
	now         func() time.Time

	// launchSlots and launches are allocated once for this coordinator run.
	// ResumeAll reuses this owned pool instead of creating detached launchers.
	launchSlots chan struct{}
	launches    sync.WaitGroup

	LeaseTTL     time.Duration
	PollInterval time.Duration
}

// NewLocalSwarmCoordinator constructs a durable local executor. The launcher
// is injectable so the coordinator can be exercised without spawning children.
func NewLocalSwarmCoordinator(fixture Fixture, storageRoot, owner string, launcher SwarmWorkerLauncher, now func() time.Time) (*LocalSwarmCoordinator, error) {
	if err := validateAbsoluteCleanPath(storageRoot); err != nil {
		return nil, fmt.Errorf("local swarm storage root: %w", err)
	}
	if owner == "" || hasSwarmDelimiter(owner) {
		return nil, errors.New("local swarm coordinator owner invalid")
	}
	if launcher == nil {
		launcher = ExecSwarmWorkerLauncher{}
	}
	if now == nil {
		now = time.Now
	}
	return &LocalSwarmCoordinator{
		fixture:      fixture,
		storageRoot:  storageRoot,
		owner:        owner,
		launcher:     launcher,
		now:          now,
		LeaseTTL:     defaultLocalSwarmLeaseTTL,
		PollInterval: defaultLocalSwarmPollInterval,
		launchSlots:  make(chan struct{}, maxLocalSwarmReadyWaveWidth),
	}, nil
}

// OpenAndRun completes Phase A and fsyncs swarm.opened before launching a
// child. Once open, the request context intentionally does not govern local
// work: a disconnected peer cannot cancel a durable local swarm.
func (c *LocalSwarmCoordinator) OpenAndRun(ctx context.Context, origin, request map[string]any) (SwarmView, error) {
	_ = ctx
	if c == nil {
		return SwarmView{}, errors.New("local swarm coordinator is required")
	}
	journal, _, err := c.fixture.OpenVerifiedSwarm(c.storageRoot, origin, request, c.currentTime(nil))
	if err != nil {
		return SwarmView{}, err
	}
	return c.RunReadyWaves(context.Background(), journal)
}

// RunReadyWaves records and atomically claims complete Kahn layers, starts all
// claims concurrently, and advances only after receipt commits or expiry
// transitions are visible in the authoritative journal.
func (c *LocalSwarmCoordinator) RunReadyWaves(ctx context.Context, journal *SwarmJournal) (SwarmView, error) {
	_ = ctx
	if c == nil || journal == nil || journal.expectedSwarmID == "" {
		return SwarmView{}, errors.New("local swarm coordinator journal is required")
	}
	if journal.expectedSwarmID == "" || c.storageRoot == "" {
		return SwarmView{}, errors.New("local swarm coordinator configuration invalid")
	}
	if err := c.validateTiming(); err != nil {
		return SwarmView{}, err
	}

	for {
		entries, state, err := localSwarmState(journal)
		if err != nil {
			return SwarmView{}, err
		}
		if state.Version == 0 || state.Spec.SwarmID != journal.expectedSwarmID {
			return SwarmView{}, errors.New("local swarm journal has no matching opening")
		}
		if err := validateDurableCoordinatorBounds(state.Spec); err != nil {
			return SwarmView{}, err
		}
		if localSwarmTerminal(state.Status) {
			return c.materialize(journal)
		}

		now := c.currentTime(entries)
		if len(state.Leases) != 0 {
			// Receipt commits are visible without trusting child output. At or after
			// the deadline ExpireLeases atomically frees the full active wave.
			if _, err := ExpireLeases(journal, now); err != nil && !isCoordinatorContention(err) {
				return SwarmView{}, err
			}
			c.pause()
			continue
		}

		_, wave, err := RecordNextReadyWave(journal, now)
		if err != nil {
			if isCoordinatorContention(err) {
				c.pause()
				continue
			}
			return SwarmView{}, err
		}
		if len(wave.StepIDs) == 0 {
			// The reducer will expose a terminal status on the next replay. A
			// nonterminal empty wave would otherwise spin forever and is invalid.
			entries, state, err = localSwarmState(journal)
			if err != nil {
				return SwarmView{}, err
			}
			if localSwarmTerminal(state.Status) {
				return c.materialize(journal)
			}
			return SwarmView{}, errors.New("local swarm has no dispatchable ready wave")
		}
		if len(wave.StepIDs) > maxLocalSwarmReadyWaveWidth {
			return SwarmView{}, errors.New("swarm ready wave width exceeds maximum 32")
		}

		dispatch, err := ClaimReadyWave(journal, c.owner, now.Add(c.LeaseTTL), now)
		if err != nil {
			if isCoordinatorContention(err) {
				c.pause()
				continue
			}
			return SwarmView{}, err
		}
		if err := c.launchAll(journal, dispatch); err != nil {
			return SwarmView{}, err
		}
	}
}

// ResumeAll discovers only private digest-named swarm directories, recovers
// each opening identity from its authenticated journal, re-verifies the frozen
// Phase A request, and resumes nonterminal state. It never consults views.
func (c *LocalSwarmCoordinator) ResumeAll(ctx context.Context) ([]SwarmView, error) {
	_ = ctx
	if c == nil {
		return nil, errors.New("local swarm coordinator is required")
	}
	if err := c.validateTiming(); err != nil {
		return nil, err
	}
	journals, err := discoverLocalSwarmJournals(c.storageRoot)
	if err != nil {
		return nil, err
	}
	views := make([]SwarmView, 0, len(journals))
	for _, journal := range journals {
		state, err := c.fixture.RecoverVerifiedSwarm(journal)
		if err != nil {
			return nil, fmt.Errorf("resume swarm %q: %w", journal.expectedSwarmID, err)
		}
		if localSwarmTerminal(state.Status) {
			view, err := c.materialize(journal)
			if err != nil {
				return nil, err
			}
			views = append(views, view)
			continue
		}
		view, err := c.RunReadyWaves(context.Background(), journal)
		if err != nil {
			return nil, fmt.Errorf("resume swarm %q: %w", journal.expectedSwarmID, err)
		}
		views = append(views, view)
	}
	return views, nil
}

func (c *LocalSwarmCoordinator) launchAll(journal *SwarmJournal, dispatch DispatchWave) error {
	if journal == nil || len(dispatch.Claims) == 0 || len(dispatch.Claims) > maxLocalSwarmReadyWaveWidth {
		return errors.New("local swarm dispatch exceeds launcher pool")
	}
	for _, claim := range dispatch.Claims {
		c.launchSlots <- struct{}{}
		c.launches.Add(1)
		go c.launchClaim(journal, claim)
	}
	return nil
}

func (c *LocalSwarmCoordinator) launchClaim(journal *SwarmJournal, claim LeaseClaim) {
	defer c.launches.Done()
	defer func() { <-c.launchSlots }()
	request := SwarmWorkerRequest{Format: localSwarmWorkerRequestFormat, StorageRoot: c.storageRoot, SwarmID: journal.expectedSwarmID, StepID: claim.StepID, Owner: claim.Owner, Fence: claim.Fence}
	_, err := c.launcher.Launch(context.Background(), request)
	if err == nil {
		return
	}
	// A launcher failure is an observation, never a terminal decision. The
	// lease expiry reducer selects migration or bounded failure atomically.
	entries, _, replayErr := localSwarmState(journal)
	if replayErr == nil {
		_ = RecordLeaseObservation(journal, claim, "launcher_failed", c.currentTime(entries))
	}
}

func (c *LocalSwarmCoordinator) waitForLaunches() {
	c.launches.Wait()
}

func validateDurableCoordinatorBounds(spec DurableSwarmSpec) error {
	if len(spec.Steps) > maxLocalSwarmStepCount {
		return errors.New("swarm step count exceeds maximum 32")
	}
	completed := make(map[string]bool, len(spec.Steps))
	for len(completed) < len(spec.Steps) {
		ready := 0
		for _, step := range spec.Steps {
			if completed[step.StepID] {
				continue
			}
			dependenciesComplete := true
			for _, dependency := range step.DependsOn {
				if !completed[dependency] {
					dependenciesComplete = false
					break
				}
			}
			if dependenciesComplete {
				ready++
			}
		}
		if ready == 0 {
			return errors.New("swarm dependency graph has no ready wave")
		}
		if ready > maxLocalSwarmReadyWaveWidth {
			return errors.New("swarm ready wave width exceeds maximum 32")
		}
		for _, step := range spec.Steps {
			if completed[step.StepID] {
				continue
			}
			dependenciesComplete := true
			for _, dependency := range step.DependsOn {
				if !completed[dependency] {
					dependenciesComplete = false
					break
				}
			}
			if dependenciesComplete {
				completed[step.StepID] = true
			}
		}
	}
	return nil
}

func (c *LocalSwarmCoordinator) materialize(journal *SwarmJournal) (SwarmView, error) {
	materializer, err := NewSwarmMaterializer(journal)
	if err != nil {
		return SwarmView{}, err
	}
	return materializer.Rebuild()
}

func (c *LocalSwarmCoordinator) validateTiming() error {
	if c.launcher == nil || c.now == nil || c.LeaseTTL <= 0 || c.PollInterval <= 0 || cap(c.launchSlots) != maxLocalSwarmReadyWaveWidth {
		return errors.New("local swarm coordinator timing invalid")
	}
	return nil
}

func (c *LocalSwarmCoordinator) currentTime(entries []SwarmJournalEntry) time.Time {
	now := c.now().UTC()
	if len(entries) == 0 {
		return now
	}
	last, err := parseCanonicalSwarmTimestamp(entries[len(entries)-1].Timestamp)
	if err == nil && now.Before(last) {
		return last
	}
	return now
}

func (c *LocalSwarmCoordinator) pause() {
	timer := time.NewTimer(c.PollInterval)
	<-timer.C
}

func localSwarmState(journal *SwarmJournal) ([]SwarmJournalEntry, SwarmState, error) {
	entries, err := journal.Replay()
	if err != nil {
		return nil, SwarmState{}, err
	}
	state, err := ReduceSwarmEntries(entries)
	if err != nil {
		return nil, SwarmState{}, err
	}
	return entries, state, nil
}

func localSwarmTerminal(status SwarmStatus) bool {
	return status == SwarmStatusCompleted || status == SwarmStatusFailed || status == SwarmStatusCancelled
}

func isCoordinatorContention(err error) bool {
	if err == nil {
		return false
	}
	message := err.Error()
	return strings.Contains(message, "current ready wave") || strings.Contains(message, "no persisted ready wave") || strings.Contains(message, "ready wave state changed") || strings.Contains(message, "lease clock rollback")
}

func discoverLocalSwarmJournals(storageRoot string) ([]*SwarmJournal, error) {
	if err := validateAbsoluteCleanPath(storageRoot); err != nil {
		return nil, fmt.Errorf("local swarm storage root: %w", err)
	}
	if err := validatePrivateDirectory(storageRoot); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("local swarm storage root: %w", err)
	}
	fd, err := unix.Open(storageRoot, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	root := os.NewFile(uintptr(fd), storageRoot)
	defer root.Close()
	entries, err := root.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	journals := make([]*SwarmJournal, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() || !isSwarmStorageKey(entry.Name()) {
			continue
		}
		dir := filepath.Join(storageRoot, entry.Name())
		if err := validatePrivateDirectory(dir); err != nil {
			return nil, fmt.Errorf("local swarm directory %q: %w", entry.Name(), err)
		}
		swarmID, err := recoverLocalSwarmIdentity(dir, entry.Name())
		if err != nil {
			return nil, fmt.Errorf("local swarm directory %q: %w", entry.Name(), err)
		}
		journal, err := OpenSwarmJournal(storageRoot, swarmID)
		if err != nil {
			return nil, err
		}
		journals = append(journals, journal)
	}
	sort.Slice(journals, func(i, j int) bool { return journals[i].expectedSwarmID < journals[j].expectedSwarmID })
	return journals, nil
}

func recoverLocalSwarmIdentity(dir, storageKey string) (string, error) {
	path := filepath.Join(dir, "journal.ndjson")
	file, err := openExistingSwarmJournal(path)
	if err != nil {
		return "", errors.New("local swarm journal unavailable")
	}
	defer file.Close()
	var entries []SwarmJournalEntry
	previousHash := swarmJournalZeroHash
	var previousVersion uint64
	trailing, err := readSwarmJournalRecords(file, func(line []byte) error {
		entry, err := decodeSwarmJournalEntry(line)
		if err != nil {
			return err
		}
		if err := validateSwarmJournalEntry(entry, uint64(len(entries)+1), previousVersion, previousHash); err != nil {
			return err
		}
		entries = append(entries, entry)
		previousHash, previousVersion = entry.Hash, entry.StateVersion
		return nil
	})
	if err != nil || trailing >= 0 || len(entries) == 0 || entries[0].Kind != "swarm.opened" {
		return "", errors.New("local swarm journal identity invalid")
	}
	state, err := ReduceSwarmEntries(entries)
	if err != nil || state.Spec.SwarmID == "" {
		return "", errors.New("local swarm journal identity invalid")
	}
	expectedKey, err := swarmStorageKey(state.Spec.SwarmID)
	if err != nil || expectedKey != storageKey {
		return "", errors.New("local swarm journal storage identity mismatch")
	}
	return state.Spec.SwarmID, nil
}

func isSwarmStorageKey(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

