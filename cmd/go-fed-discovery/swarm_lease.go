package main

import (
	"errors"
	"fmt"
	"math"
	"reflect"
	"time"
)

// LeaseFence is a globally monotonic generation that makes stale worker actions rejectable.
type LeaseFence uint64

// ReadyWave is one deterministic Kahn layer in immutable signed-step order.
type ReadyWave struct {
	StepIDs    []string `json:"step_ids"`
	RecordedAt string   `json:"recorded_at"`
}

// LeaseClaim binds one selected step attempt to an owner and exact pinned candidate.
type LeaseClaim struct {
	StepID         string                 `json:"step_id"`
	Owner          string                 `json:"owner"`
	Fence          LeaseFence             `json:"fence"`
	Attempt        uint64                 `json:"attempt"`
	CandidateIndex uint64                 `json:"candidate_index"`
	Capability     string                 `json:"capability"`
	Candidate      DurableWorkerCandidate `json:"candidate"`
	Deadline       string                 `json:"deadline"`
}

// DispatchWave is the sole atomic lease decision for a complete ready layer.
type DispatchWave struct {
	Wave   ReadyWave    `json:"wave"`
	Claims []LeaseClaim `json:"claims"`
}

type waveReadyPayload struct {
	SchemaVersion uint64    `json:"schema_version"`
	Wave          ReadyWave `json:"wave"`
}

type waveDispatchedPayload struct {
	SchemaVersion uint64       `json:"schema_version"`
	Wave          ReadyWave    `json:"wave"`
	Claims        []LeaseClaim `json:"claims"`
}

type leaseRenewedPayload struct {
	SchemaVersion uint64     `json:"schema_version"`
	Claim         LeaseClaim `json:"claim"`
}

type leaseExpiredPayload struct {
	SchemaVersion uint64       `json:"schema_version"`
	Now           string       `json:"now"`
	Claims        []LeaseClaim `json:"claims"`
}

type leaseObservedPayload struct {
	SchemaVersion uint64     `json:"schema_version"`
	Claim         LeaseClaim `json:"claim"`
	Outcome       string     `json:"outcome"`
}

func cloneReadyWave(wave ReadyWave) ReadyWave {
	return ReadyWave{StepIDs: append([]string(nil), wave.StepIDs...), RecordedAt: wave.RecordedAt}
}

func cloneLeaseClaims(claims []LeaseClaim) []LeaseClaim {
	return append([]LeaseClaim(nil), claims...)
}

// DeriveNextReadyWave returns the sole dispatchable Kahn layer. A nonempty active layer or any
// running step is a barrier: later signed steps cannot become ready early.
func DeriveNextReadyWave(state SwarmState) (ReadyWave, error) {
	if state.Version == 0 {
		return ReadyWave{}, errors.New("swarm must open before deriving a ready wave")
	}
	if state.Status == SwarmStatusCompleted || state.Status == SwarmStatusFailed || state.Status == SwarmStatusCancelled {
		return ReadyWave{}, nil
	}
	if len(state.ReadyWave.StepIDs) != 0 {
		return cloneReadyWave(state.ReadyWave), nil
	}
	for _, step := range state.Steps {
		if step.Status == SwarmStepStatusRunning {
			return ReadyWave{}, errors.New("current ready wave has not reached its barrier")
		}
	}
	wave := ReadyWave{StepIDs: make([]string, 0, len(state.Steps))}
	for index, step := range state.Steps {
		if step.Status == SwarmStepStatusPending && swarmDependenciesCompleted(state, index) {
			wave.StepIDs = append(wave.StepIDs, step.StepID)
		}
	}
	return wave, nil
}

// RecordNextReadyWave persists a deterministic layer before any worker may claim it.
func RecordNextReadyWave(journal *SwarmJournal, timestamp time.Time) (SwarmState, ReadyWave, error) {
	var result SwarmState
	var wave ReadyWave
	err := appendLeaseTransition(journal, "wave.ready", timestamp, func(state SwarmState) (any, error) {
		var err error
		wave, err = DeriveNextReadyWave(state)
		if err != nil {
			return nil, err
		}
		if len(wave.StepIDs) == 0 {
			result = cloneSwarmState(state)
			return nil, nil
		}
		if wave.RecordedAt != "" {
			result = cloneSwarmState(state)
			return nil, nil
		}
		wave.RecordedAt, err = canonicalLeaseTime(timestamp)
		if err != nil {
			return nil, err
		}
		return waveReadyPayload{SchemaVersion: swarmStateSchemaVersion, Wave: wave}, nil
	}, func(state SwarmState) { result = cloneSwarmState(state) })
	if err != nil {
		return SwarmState{}, ReadyWave{}, err
	}
	if len(wave.StepIDs) == 0 {
		return result, wave, nil
	}
	return result, cloneReadyWave(result.ReadyWave), nil
}

// ClaimReadyWave atomically grants every step in the persisted current wave under the journal lock.
func ClaimReadyWave(journal *SwarmJournal, owner string, deadline, timestamp time.Time) (DispatchWave, error) {
	if owner == "" {
		return DispatchWave{}, errors.New("lease owner is required")
	}
	deadlineText, err := canonicalLeaseTime(deadline)
	if err != nil {
		return DispatchWave{}, err
	}
	timestampText, err := canonicalLeaseTime(timestamp)
	if err != nil {
		return DispatchWave{}, err
	}
	if deadlineText <= timestampText {
		return DispatchWave{}, errors.New("lease deadline must be after claim timestamp")
	}
	var dispatch DispatchWave
	err = appendLeaseTransition(journal, "wave.dispatched", timestamp, func(state SwarmState) (any, error) {
		wave, err := DeriveNextReadyWave(state)
		if err != nil {
			return nil, err
		}
		if len(wave.StepIDs) == 0 || wave.RecordedAt == "" || !reflect.DeepEqual(wave, state.ReadyWave) {
			return nil, errors.New("no persisted ready wave to claim")
		}
		if state.LastFence > LeaseFence(math.MaxUint64-uint64(len(wave.StepIDs))) {
			return nil, errors.New("lease fence overflow")
		}
		dispatch.Wave = cloneReadyWave(wave)
		dispatch.Claims = make([]LeaseClaim, 0, len(wave.StepIDs))
		for _, stepID := range wave.StepIDs {
			index := swarmStepIndex(state.Steps, stepID)
			if index < 0 || state.Steps[index].Status != SwarmStepStatusPending {
				return nil, errors.New("ready wave state changed")
			}
			attempt := state.Steps[index].Attempts + 1
			candidateIndex := attempt - 1
			candidates := state.Spec.Steps[index].Candidates
			if candidateIndex >= uint64(len(candidates)) || attempt > state.Spec.Steps[index].AttemptPolicy.MaxAttempts {
				return nil, errors.New("ready step has exhausted candidate or attempt budget")
			}
			candidate := candidates[candidateIndex]
			dispatch.Claims = append(dispatch.Claims, LeaseClaim{StepID: stepID, Owner: owner, Fence: state.LastFence + LeaseFence(len(dispatch.Claims)+1), Attempt: attempt, CandidateIndex: candidateIndex, Capability: state.Spec.Steps[index].Capability, Candidate: candidate, Deadline: deadlineText})
		}
		return waveDispatchedPayload{SchemaVersion: swarmStateSchemaVersion, Wave: dispatch.Wave, Claims: dispatch.Claims}, nil
	}, nil)
	if err != nil {
		return DispatchWave{}, err
	}
	dispatch.Wave = cloneReadyWave(dispatch.Wave)
	dispatch.Claims = cloneLeaseClaims(dispatch.Claims)
	return dispatch, nil
}

// RenewLease validates the exact live owner and fence under the journal lock; it intentionally
// accepts no caller-provided global state version, so unrelated journal appends cannot invalidate it.
func RenewLease(journal *SwarmJournal, stepID, owner string, fence LeaseFence, deadline, timestamp time.Time) (LeaseClaim, error) {
	if stepID == "" || owner == "" || fence == 0 {
		return LeaseClaim{}, errors.New("lease renewal identity invalid")
	}
	deadlineText, err := canonicalLeaseTime(deadline)
	if err != nil {
		return LeaseClaim{}, err
	}
	timestampText, err := canonicalLeaseTime(timestamp)
	if err != nil {
		return LeaseClaim{}, err
	}
	var renewed LeaseClaim
	err = appendLeaseTransition(journal, "lease.renewed", timestamp, func(state SwarmState) (any, error) {
		for _, live := range state.Leases {
			if live.StepID == stepID && live.Owner == owner && live.Fence == fence {
				if timestampText > live.Deadline || deadlineText <= timestampText || deadlineText <= live.Deadline {
					return nil, errors.New("lease renewal deadline does not extend a live lease")
				}
				renewed = live
				renewed.Deadline = deadlineText
				return leaseRenewedPayload{SchemaVersion: swarmStateSchemaVersion, Claim: renewed}, nil
			}
		}
		return nil, errors.New("lease renewal does not match a live owner and fence")
	}, nil)
	return renewed, err
}

// RecordLeaseObservation persists a non-terminal worker fact only while its exact lease remains live.
// U22 owns receipt-backed terminal completion and failure transitions.
func RecordLeaseObservation(journal *SwarmJournal, claim LeaseClaim, outcome string, timestamp time.Time) error {
	if !validLeaseClaim(claim) || outcome == "" {
		return errors.New("lease observation invalid")
	}
	timestampText, err := canonicalLeaseTime(timestamp)
	if err != nil {
		return err
	}
	return appendLeaseTransition(journal, "lease.observed", timestamp, func(state SwarmState) (any, error) {
		index := leaseIndex(state.Leases, claim.StepID)
		if index < 0 || !reflect.DeepEqual(state.Leases[index], claim) || timestampText >= claim.Deadline {
			return nil, errors.New("lease observation does not match a live claim")
		}
		return leaseObservedPayload{SchemaVersion: swarmStateSchemaVersion, Claim: claim, Outcome: outcome}, nil
	}, nil)
}

// ExpireLeases is the only transition that returns a leased step to pending or fails it on budget exhaustion.
func ExpireLeases(journal *SwarmJournal, now time.Time) (SwarmState, error) {
	nowText, err := canonicalLeaseTime(now)
	if err != nil {
		return SwarmState{}, err
	}
	var result SwarmState
	err = appendLeaseTransition(journal, "lease.expired", now, func(state SwarmState) (any, error) {
		expired := make([]LeaseClaim, 0, len(state.Leases))
		for _, claim := range state.Leases {
			if claim.Deadline <= nowText {
				expired = append(expired, claim)
			}
		}
		if len(expired) == 0 {
			result = cloneSwarmState(state)
			return nil, nil
		}
		return leaseExpiredPayload{SchemaVersion: swarmStateSchemaVersion, Now: nowText, Claims: expired}, nil
	}, func(state SwarmState) { result = cloneSwarmState(state) })
	if err != nil {
		return SwarmState{}, err
	}
	return result, nil
}

func appendLeaseTransition(journal *SwarmJournal, kind string, timestamp time.Time, payload func(SwarmState) (any, error), committed func(SwarmState)) error {
	if journal == nil || payload == nil {
		return errors.New("swarm journal and lease payload are required")
	}
	stamp, err := canonicalLeaseTime(timestamp)
	if err != nil {
		return err
	}
	return journal.WithLockedReplay(func(entries []SwarmJournalEntry) error {
		state, err := ReduceSwarmEntries(entries)
		if err != nil {
			return err
		}
		if len(entries) != 0 && stamp < entries[len(entries)-1].Timestamp {
			return errors.New("lease clock rollback")
		}
		body, err := payload(state)
		if err != nil {
			return err
		}
		if body == nil {
			if committed != nil {
				committed(state)
			}
			return nil
		}
		if state.Version == math.MaxUint64 {
			return errors.New("swarm state version overflow")
		}
		encoded, err := canonicalSwarmPayload(body)
		if err != nil {
			return err
		}
		entry := SwarmJournalEntry{Format: swarmJournalFormat, Sequence: uint64(len(entries) + 1), PriorStateVersion: state.Version, StateVersion: state.Version + 1, Kind: kind, Payload: encoded, Timestamp: stamp, PrevHash: swarmJournalZeroHash}
		if len(entries) != 0 {
			entry.PrevHash = entries[len(entries)-1].Hash
		}
		entry.Hash, err = swarmJournalEntryHash(entry)
		if err != nil {
			return err
		}
		next, err := ReduceSwarmEntry(state, entry)
		if err != nil {
			return err
		}
		if err := journal.validateTypedStateIdentity(next); err != nil {
			return err
		}
		if err := journal.appendLocked(entry); err != nil {
			return err
		}
		if committed != nil {
			committed(next)
		}
		return nil
	})
}

func canonicalLeaseTime(value time.Time) (string, error) {
	if value.IsZero() || value.Location() != time.UTC {
		return "", errors.New("lease time must be canonical UTC")
	}
	canonical := value.Format(time.RFC3339Nano)
	if parsed, err := time.Parse(time.RFC3339Nano, canonical); err != nil || !parsed.Equal(value) || parsed.Location() != time.UTC {
		return "", errors.New("lease time must be canonical UTC")
	}
	return canonical, nil
}

func reduceSwarmLeaseEntry(state *SwarmState, entry SwarmJournalEntry) error {
	if state == nil {
		return errors.New("swarm lease state invalid")
	}
	if state.Status == SwarmStatusFailed && entry.Kind != "lease.expired" {
		return errors.New("swarm is failed")
	}
	switch entry.Kind {
	case "wave.ready":
		var payload waveReadyPayload
		if err := decodeStrictSwarmPayload(entry.Payload, &payload); err != nil || payload.SchemaVersion != swarmStateSchemaVersion {
			return errors.New("ready wave payload invalid")
		}
		if payload.Wave.RecordedAt != entry.Timestamp || !isCanonicalLeaseText(entry.Timestamp) || !validReadyWave(payload.Wave) || len(state.ReadyWave.StepIDs) != 0 {
			return errors.New("ready wave payload invalid")
		}
		expected, err := DeriveNextReadyWave(*state)
		if err != nil || !reflect.DeepEqual(payload.Wave.StepIDs, expected.StepIDs) {
			return errors.New("ready wave does not match Kahn layer")
		}
		state.ReadyWave = cloneReadyWave(payload.Wave)
	case "wave.dispatched":
		var payload waveDispatchedPayload
		if err := decodeStrictSwarmPayload(entry.Payload, &payload); err != nil || payload.SchemaVersion != swarmStateSchemaVersion {
			return errors.New("dispatch wave payload invalid")
		}
		if !isCanonicalLeaseText(entry.Timestamp) || !reflect.DeepEqual(payload.Wave, state.ReadyWave) || len(payload.Claims) != len(payload.Wave.StepIDs) || len(state.Leases) != 0 {
			return errors.New("dispatch does not claim the complete ready wave")
		}
		for i, claim := range payload.Claims {
			if err := validateDispatchClaim(*state, payload.Wave, claim, i, entry.Timestamp); err != nil {
				return err
			}
		}
		for _, claim := range payload.Claims {
			step := &state.Steps[swarmStepIndex(state.Steps, claim.StepID)]
			step.Status = SwarmStepStatusRunning
			step.Attempts++
			step.Observations = append(step.Observations, SwarmAttemptObservation{Attempt: claim.Attempt, Candidate: claim.Candidate, Owner: claim.Owner, Fence: claim.Fence, Outcome: "dispatched", ObservedAt: entry.Timestamp})
		}
		state.LastFence = payload.Claims[len(payload.Claims)-1].Fence
		state.Leases = cloneLeaseClaims(payload.Claims)
	case "lease.renewed":
		var payload leaseRenewedPayload
		if err := decodeStrictSwarmPayload(entry.Payload, &payload); err != nil || payload.SchemaVersion != swarmStateSchemaVersion || !validLeaseClaim(payload.Claim) || !isCanonicalLeaseText(entry.Timestamp) {
			return errors.New("lease renewal payload invalid")
		}
		index := leaseIndex(state.Leases, payload.Claim.StepID)
		if index < 0 || !sameLeaseIdentity(state.Leases[index], payload.Claim) || entry.Timestamp > state.Leases[index].Deadline || payload.Claim.Deadline <= entry.Timestamp || payload.Claim.Deadline <= state.Leases[index].Deadline {
			return errors.New("lease renewal does not match live lease")
		}
		state.Leases[index] = payload.Claim
	case "lease.observed":
		var payload leaseObservedPayload
		if err := decodeStrictSwarmPayload(entry.Payload, &payload); err != nil || payload.SchemaVersion != swarmStateSchemaVersion || !validLeaseClaim(payload.Claim) || payload.Outcome == "" || !isCanonicalLeaseText(entry.Timestamp) {
			return errors.New("lease observation payload invalid")
		}
		index := leaseIndex(state.Leases, payload.Claim.StepID)
		if index < 0 || !reflect.DeepEqual(state.Leases[index], payload.Claim) || entry.Timestamp >= payload.Claim.Deadline {
			return errors.New("lease observation does not match live lease")
		}
		stepIndex := swarmStepIndex(state.Steps, payload.Claim.StepID)
		step := &state.Steps[stepIndex]
		if step.Status != SwarmStepStatusRunning || step.Attempts != payload.Claim.Attempt {
			return errors.New("lease observation step state invalid")
		}
		step.Observations = append(step.Observations, SwarmAttemptObservation{Attempt: payload.Claim.Attempt, Candidate: payload.Claim.Candidate, Owner: payload.Claim.Owner, Fence: payload.Claim.Fence, Outcome: payload.Outcome, ObservedAt: entry.Timestamp})
	case "lease.expired":
		var payload leaseExpiredPayload
		if err := decodeStrictSwarmPayload(entry.Payload, &payload); err != nil || payload.SchemaVersion != swarmStateSchemaVersion || payload.Now != entry.Timestamp || !isCanonicalLeaseText(entry.Timestamp) || !isCanonicalLeaseText(payload.Now) || len(payload.Claims) == 0 {
			return errors.New("lease expiry payload invalid")
		}
		for _, claim := range payload.Claims {
			index := leaseIndex(state.Leases, claim.StepID)
			if index < 0 || !reflect.DeepEqual(state.Leases[index], claim) || claim.Deadline > payload.Now {
				return errors.New("lease expiry does not match live lease")
			}
			stepIndex := swarmStepIndex(state.Steps, claim.StepID)
			step := &state.Steps[stepIndex]
			if step.Status != SwarmStepStatusRunning || step.Attempts != claim.Attempt {
				return errors.New("lease expiry step state invalid")
			}
			step.Observations = append(step.Observations, SwarmAttemptObservation{Attempt: claim.Attempt, Candidate: claim.Candidate, Owner: claim.Owner, Fence: claim.Fence, Outcome: "expired", ObservedAt: payload.Now})
			if step.Attempts >= state.Spec.Steps[stepIndex].AttemptPolicy.MaxAttempts {
				step.Status = SwarmStepStatusFailed
			} else {
				step.Status = SwarmStepStatusPending
			}
			state.Leases = append(state.Leases[:index:index], state.Leases[index+1:]...)
		}
		state.ReadyWave = ReadyWave{}
	default:
		return fmt.Errorf("unknown swarm lease event %q", entry.Kind)
	}
	return nil
}

func validReadyWave(wave ReadyWave) bool {
	return len(wave.StepIDs) != 0 && isCanonicalLeaseText(wave.RecordedAt)
}

func validLeaseClaim(claim LeaseClaim) bool {
	return claim.StepID != "" && claim.Owner != "" && claim.Fence != 0 && claim.Attempt != 0 && isCanonicalLeaseText(claim.Deadline)
}

func isCanonicalLeaseText(value string) bool {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && parsed.Location() == time.UTC && parsed.Format(time.RFC3339Nano) == value
}

func validateDispatchClaim(state SwarmState, wave ReadyWave, claim LeaseClaim, position int, timestamp string) error {
	if !validLeaseClaim(claim) || !isCanonicalLeaseText(timestamp) || claim.Deadline <= timestamp || claim.StepID != wave.StepIDs[position] || claim.Fence != state.LastFence+LeaseFence(position+1) {
		return errors.New("dispatch lease claim invalid")
	}
	index := swarmStepIndex(state.Steps, claim.StepID)
	if index < 0 || state.Steps[index].Status != SwarmStepStatusPending || claim.Attempt != state.Steps[index].Attempts+1 || claim.CandidateIndex != claim.Attempt-1 || claim.CandidateIndex >= uint64(len(state.Spec.Steps[index].Candidates)) || claim.Capability != state.Spec.Steps[index].Capability || claim.Candidate != state.Spec.Steps[index].Candidates[claim.CandidateIndex] || claim.Attempt > state.Spec.Steps[index].AttemptPolicy.MaxAttempts {
		return errors.New("dispatch lease candidate or budget invalid")
	}
	return nil
}

func leaseIndex(leases []LeaseClaim, stepID string) int {
	for i := range leases {
		if leases[i].StepID == stepID {
			return i
		}
	}
	return -1
}

func sameLeaseIdentity(a, b LeaseClaim) bool {
	return a.StepID == b.StepID && a.Owner == b.Owner && a.Fence == b.Fence && a.Attempt == b.Attempt && a.CandidateIndex == b.CandidateIndex && a.Capability == b.Capability && a.Candidate == b.Candidate
}
