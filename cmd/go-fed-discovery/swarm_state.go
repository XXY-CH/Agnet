package main

import (
	"bytes"
	"encoding/base64"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"time"
)

const swarmStateSchemaVersion = 1

type SwarmStatus string

const (
	SwarmStatusOpen      SwarmStatus = "open"
	SwarmStatusRunning   SwarmStatus = "running"
	SwarmStatusCompleted SwarmStatus = "completed"
	SwarmStatusFailed    SwarmStatus = "failed"
	SwarmStatusCancelled SwarmStatus = "cancelled"
)

type SwarmStepStatus string

const (
	SwarmStepStatusPending   SwarmStepStatus = "pending"
	SwarmStepStatusRunning   SwarmStepStatus = "running"
	SwarmStepStatusCompleted SwarmStepStatus = "completed"
	SwarmStepStatusFailed    SwarmStepStatus = "failed"
	SwarmStepStatusCancelled SwarmStepStatus = "cancelled"
)

// SwarmAttemptPolicy is immutable execution policy captured at Phase A.
type SwarmAttemptPolicy struct {
	MaxAttempts uint64 `json:"max_attempts"`
}

// DurableWorkerCandidate is an ordered, generation-pinned candidate captured at Phase A.
// Its public verification material and descriptor digest are immutable inputs to receipt recovery.
type DurableWorkerCandidate struct {
	Alias            string              `json:"alias"`
	AID              string              `json:"aid"`
	GenerationPin    WorkerGenerationPin `json:"generation_pin"`
	PublicKeySPKI    string              `json:"public_key_spki"`
	DescriptorDigest string              `json:"descriptor_digest"`
}

// DurableSwarmStepSpec is the complete immutable execution input for one ordered step.
type DurableSwarmStepSpec struct {
	StepID        string                   `json:"step_id"`
	DependsOn     []string                 `json:"depends_on,omitempty"`
	TaskDigest    string                   `json:"task_digest,omitempty"`
	Capability    string                   `json:"capability,omitempty"`
	Candidates    []DurableWorkerCandidate `json:"candidates"`
	AttemptPolicy SwarmAttemptPolicy       `json:"attempt_policy"`
}

// DurableSwarmSpec is the durable Phase A seed. Plan, Binding, and Request are canonical raw
// JSON bytes; journal serialization represents them as raw base64url rather than JSON strings.
type DurableSwarmSpec struct {
	SchemaVersion       uint64                 `json:"schema_version"`
	SwarmID             string                 `json:"swarm_id"`
	Plan                []byte                 `json:"-"`
	Binding             []byte                 `json:"-"`
	Request             []byte                 `json:"-"`
	AuthorityGeneration WorkerGenerationPin    `json:"authority_generation_pin"`
	Steps               []DurableSwarmStepSpec `json:"steps"`
}

// SwarmAttemptObservation records immutable dispatch and expiry facts for one attempt.
type SwarmAttemptObservation struct {
	Attempt   uint64     `json:"attempt"`
	Candidate DurableWorkerCandidate `json:"candidate"`
	Owner     string     `json:"owner"`
	Fence     LeaseFence `json:"fence"`
	Outcome   string     `json:"outcome"`
	ObservedAt string    `json:"observed_at"`
}

type SwarmStepState struct {
	StepID       string                    `json:"step_id"`
	Status       SwarmStepStatus           `json:"status"`
	Attempts     uint64                    `json:"attempts"`
	Observations []SwarmAttemptObservation `json:"observations,omitempty"`
}

// SwarmState is a derived view only. Its sole authority is the journal consumed by ReduceSwarmEntry.
type SwarmState struct {
	Version            uint64                     `json:"version"`
	Status             SwarmStatus                `json:"status"`
	Spec               DurableSwarmSpec           `json:"spec"`
	Steps              []SwarmStepState           `json:"steps"`
	ReadyWave          ReadyWave                  `json:"ready_wave"`
	Leases             []LeaseClaim               `json:"leases,omitempty"`
	CommittedArtifacts map[string]ArtifactTriple  `json:"committed_artifacts,omitempty"`
	LastFence          LeaseFence                 `json:"last_fence"`
}

type durableSwarmSpecWire struct {
	SchemaVersion       uint64                 `json:"schema_version"`
	SwarmID             string                 `json:"swarm_id"`
	Plan                string                 `json:"plan"`
	Binding             string                 `json:"binding"`
	Request             string                 `json:"request"`
	AuthorityGeneration WorkerGenerationPin    `json:"authority_generation_pin"`
	Steps               []DurableSwarmStepSpec `json:"steps"`
}

type swarmOpenedPayload struct {
	SchemaVersion uint64                `json:"schema_version"`
	Spec          durableSwarmSpecWire `json:"spec"`
}

type swarmStepTransitionPayload struct {
	SchemaVersion uint64 `json:"schema_version"`
	StepID        string `json:"step_id"`
}

type swarmCancelledPayload struct {
	SchemaVersion uint64 `json:"schema_version"`
}

func (spec DurableSwarmSpec) wire() (durableSwarmSpecWire, error) {
	if err := validateDurableSwarmSpec(spec); err != nil {
		return durableSwarmSpecWire{}, err
	}
	return durableSwarmSpecWire{
		SchemaVersion:       spec.SchemaVersion,
		SwarmID:             spec.SwarmID,
		Plan:                base64.RawURLEncoding.EncodeToString(spec.Plan),
		Binding:             base64.RawURLEncoding.EncodeToString(spec.Binding),
		Request:             base64.RawURLEncoding.EncodeToString(spec.Request),
		AuthorityGeneration: spec.AuthorityGeneration,
		Steps:               cloneDurableSteps(spec.Steps),
	}, nil
}

func durableSwarmSpecFromWire(wire durableSwarmSpecWire) (DurableSwarmSpec, error) {
	plan, err := decodeCanonicalSwarmRaw("plan", wire.Plan)
	if err != nil {
		return DurableSwarmSpec{}, err
	}
	binding, err := decodeCanonicalSwarmRaw("binding", wire.Binding)
	if err != nil {
		return DurableSwarmSpec{}, err
	}
	request, err := decodeCanonicalSwarmRaw("request", wire.Request)
	if err != nil {
		return DurableSwarmSpec{}, err
	}
	spec := DurableSwarmSpec{SchemaVersion: wire.SchemaVersion, SwarmID: wire.SwarmID, Plan: plan, Binding: binding, Request: request, AuthorityGeneration: wire.AuthorityGeneration, Steps: cloneDurableSteps(wire.Steps)}
	if err := validateDurableSwarmSpec(spec); err != nil {
		return DurableSwarmSpec{}, err
	}
	return spec, nil
}

func decodeCanonicalSwarmRaw(field, encoded string) ([]byte, error) {
	if encoded == "" || bytes.ContainsRune([]byte(encoded), '=') {
		return nil, fmt.Errorf("swarm durable %s invalid", field)
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) == 0 || !json.Valid(raw) {
		return nil, fmt.Errorf("swarm durable %s invalid", field)
	}
	if err := validateSwarmJSONNoDuplicateFields(raw); err != nil {
		return nil, fmt.Errorf("swarm durable %s invalid", field)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil || ensureSwarmJSONEOF(decoder) != nil {
		return nil, fmt.Errorf("swarm durable %s invalid", field)
	}
	canonical, err := canonicalJSON(value)
	if err != nil || !bytes.Equal(raw, canonical) {
		return nil, fmt.Errorf("swarm durable %s is not canonical", field)
	}
	return append([]byte(nil), raw...), nil
}

func validateDurableSwarmSpec(spec DurableSwarmSpec) error {
	if spec.SchemaVersion != swarmStateSchemaVersion || spec.SwarmID == "" || hasSwarmDelimiter(spec.SwarmID) {
		return errors.New("swarm durable spec invalid")
	}
	for name, raw := range map[string][]byte{"plan": spec.Plan, "binding": spec.Binding, "request": spec.Request} {
		encoded := base64.RawURLEncoding.EncodeToString(raw)
		if _, err := decodeCanonicalSwarmRaw(name, encoded); err != nil {
			return err
		}
	}
	if len(spec.Steps) == 0 {
		return errors.New("swarm durable steps missing")
	}
	seen := make(map[string]bool, len(spec.Steps))
	for _, step := range spec.Steps {
		if step.StepID == "" || hasSwarmDelimiter(step.StepID) || seen[step.StepID] || step.AttemptPolicy.MaxAttempts == 0 || len(step.Candidates) == 0 {
			return errors.New("swarm durable step invalid")
		}
		for _, dependency := range step.DependsOn {
			if !seen[dependency] {
				return errors.New("swarm durable step dependency invalid")
			}
		}
		for _, candidate := range step.Candidates {
			if candidate.Alias == "" || candidate.AID == "" || candidate.GenerationPin.StorePath == "" || candidate.GenerationPin.PassphraseFile == "" || !isHexDigest(candidate.GenerationPin.RecordDigest) || candidate.PublicKeySPKI == "" || !isHexDigest(candidate.DescriptorDigest) {
				return errors.New("swarm durable worker verification pin invalid")
			}
			key, der, err := publicKey(map[string]any{"public_key_spki": candidate.PublicKeySPKI})
			if err != nil || len(key) != 32 || candidate.AID != aidFromSPKI(der) {
				return errors.New("swarm durable worker verification pin invalid")
			}
		}
		seen[step.StepID] = true
	}
	return nil
}

func decodeStrictSwarmPayload(raw []byte, target any) error {
	if len(raw) == 0 || !json.Valid(raw) || validateSwarmJSONNoDuplicateFields(raw) != nil {
		return errors.New("swarm state payload invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil || ensureSwarmJSONEOF(decoder) != nil {
		return errors.New("swarm state payload invalid")
	}
	return nil
}

// ReduceSwarmEntry applies one registered state transition without I/O and without mutating either input.
func ReduceSwarmEntry(prior SwarmState, entry SwarmJournalEntry) (SwarmState, error) {
	stateAffecting, err := isSwarmStateEntryKind(entry.Kind)
	if err != nil {
		return SwarmState{}, err
	}
	if !stateAffecting {
		return SwarmState{}, errors.New("swarm entry kind does not affect state")
	}
	if entry.PriorStateVersion == math.MaxUint64 || entry.StateVersion != entry.PriorStateVersion+1 || entry.PriorStateVersion != prior.Version {
		return SwarmState{}, errors.New("swarm state versions are not contiguous")
	}
	if prior.Version != 0 && (prior.Status == SwarmStatusCompleted || prior.Status == SwarmStatusCancelled) {
		return SwarmState{}, errors.New("swarm is terminal")
	}
	next := cloneSwarmState(prior)
	switch entry.Kind {
	case "swarm.opened":
		if prior.Version != 0 || len(prior.Steps) != 0 || prior.Status != "" {
			return SwarmState{}, errors.New("swarm already opened")
		}
		var payload swarmOpenedPayload
		if err := decodeStrictSwarmPayload(entry.Payload, &payload); err != nil || payload.SchemaVersion != swarmStateSchemaVersion {
			return SwarmState{}, errors.New("swarm opened payload invalid")
		}
		spec, err := durableSwarmSpecFromWire(payload.Spec)
		if err != nil {
			return SwarmState{}, err
		}
		next.Spec = spec
		next.Steps = make([]SwarmStepState, len(spec.Steps))
		next.CommittedArtifacts = make(map[string]ArtifactTriple, len(next.Steps))
		for i, step := range spec.Steps {
			next.Steps[i] = SwarmStepState{StepID: step.StepID, Status: SwarmStepStatusPending}
		}
	case "wave.ready", "wave.dispatched", "lease.renewed", "lease.observed", "lease.expired":
		if prior.Version == 0 {
			return SwarmState{}, errors.New("swarm must open before leasing")
		}
		if err := reduceSwarmLeaseEntry(&next, entry); err != nil {
			return SwarmState{}, err
		}
	case "receipt.committed":
		if prior.Version == 0 {
			return SwarmState{}, errors.New("swarm must open before receipt commitment")
		}
		if err := reduceSwarmReceiptEntry(&next, entry); err != nil {
			return SwarmState{}, err
		}
	case "swarm.cancelled":
		if prior.Version == 0 || prior.Status == SwarmStatusCompleted || prior.Status == SwarmStatusFailed || prior.Status == SwarmStatusCancelled {
			return SwarmState{}, errors.New("illegal swarm cancellation")
		}
		var payload swarmCancelledPayload
		if err := decodeStrictSwarmPayload(entry.Payload, &payload); err != nil || payload.SchemaVersion != swarmStateSchemaVersion {
			return SwarmState{}, errors.New("swarm cancellation payload invalid")
		}
		for _, step := range next.Steps {
			if step.Status == SwarmStepStatusRunning {
				return SwarmState{}, errors.New("cannot cancel a running step without a lease-bound terminal event")
			}
		}
		for i := range next.Steps {
			if next.Steps[i].Status == SwarmStepStatusPending {
				next.Steps[i].Status = SwarmStepStatusCancelled
			}
		}
	}
	next.Version = entry.StateVersion
	next.Status = deriveSwarmStatus(next.Steps)
	if entry.Kind == "swarm.cancelled" {
		next.Status = SwarmStatusCancelled
	}
	return next, nil
}

// isSwarmStateEntryKind identifies state authority held by U20. Other namespaces are retained
// by typed journals for future reducers, while unknown state namespaces fail closed.
func isSwarmStateEntryKind(kind string) (bool, error) {
	switch kind {
	case "swarm.opened", "swarm.cancelled", "wave.ready", "wave.dispatched", "lease.renewed", "lease.observed", "lease.expired", "receipt.committed":
		return true, nil
	default:
		if strings.HasPrefix(kind, "swarm.") || strings.HasPrefix(kind, "step.") || strings.HasPrefix(kind, "receipt.") {
			return false, errors.New("swarm entry kind invalid")
		}
		return false, nil
	}
}

func reduceSwarmTypedEntry(prior SwarmState, entry SwarmJournalEntry) (SwarmState, error) {
	stateAffecting, err := isSwarmStateEntryKind(entry.Kind)
	if err != nil {
		return SwarmState{}, err
	}
	if stateAffecting {
		return ReduceSwarmEntry(prior, entry)
	}
	if entry.PriorStateVersion == math.MaxUint64 || entry.StateVersion != entry.PriorStateVersion+1 || entry.PriorStateVersion != prior.Version {
		return SwarmState{}, errors.New("swarm state versions are not contiguous")
	}
	next := cloneSwarmState(prior)
	next.Version = entry.StateVersion
	return next, nil
}

// ReduceSwarmEntries derives a state exclusively from a verified typed journal replay.
func ReduceSwarmEntries(entries []SwarmJournalEntry) (SwarmState, error) {
	state := SwarmState{}
	for _, entry := range entries {
		next, err := reduceSwarmTypedEntry(state, entry)
		if err != nil {
			return SwarmState{}, fmt.Errorf("reduce swarm journal entry %d: %w", entry.Sequence, err)
		}
		state = next
	}
	return state, nil
}

func swarmStepIndex(steps []SwarmStepState, stepID string) int {
	for i := range steps {
		if steps[i].StepID == stepID {
			return i
		}
	}
	return -1
}

func swarmDependenciesCompleted(state SwarmState, index int) bool {
	for _, dependency := range state.Spec.Steps[index].DependsOn {
		dependencyIndex := swarmStepIndex(state.Steps, dependency)
		if dependencyIndex < 0 || state.Steps[dependencyIndex].Status != SwarmStepStatusCompleted {
			return false
		}
	}
	return true
}

func deriveSwarmStatus(steps []SwarmStepState) SwarmStatus {
	if len(steps) == 0 {
		return ""
	}
	allCompleted, allCancelled := true, true
	for _, step := range steps {
		if step.Status == SwarmStepStatusFailed {
			return SwarmStatusFailed
		}
		if step.Status == SwarmStepStatusRunning {
			return SwarmStatusRunning
		}
		allCompleted = allCompleted && step.Status == SwarmStepStatusCompleted
		allCancelled = allCancelled && step.Status == SwarmStepStatusCancelled
	}
	if allCompleted {
		return SwarmStatusCompleted
	}
	if allCancelled {
		return SwarmStatusCancelled
	}
	return SwarmStatusOpen
}

func cloneSwarmState(state SwarmState) SwarmState {
	clone := SwarmState{Version: state.Version, Status: state.Status, Spec: cloneDurableSwarmSpec(state.Spec), ReadyWave: cloneReadyWave(state.ReadyWave), Leases: cloneLeaseClaims(state.Leases), LastFence: state.LastFence}
	if state.CommittedArtifacts != nil {
		clone.CommittedArtifacts = make(map[string]ArtifactTriple, len(state.CommittedArtifacts))
		for stepID, artifact := range state.CommittedArtifacts {
			clone.CommittedArtifacts[stepID] = artifact
		}
	}
	clone.Steps = make([]SwarmStepState, len(state.Steps))
	for i, step := range state.Steps {
		clone.Steps[i] = step
		clone.Steps[i].Observations = append([]SwarmAttemptObservation(nil), step.Observations...)
	}
	return clone
}

func cloneDurableSwarmSpec(spec DurableSwarmSpec) DurableSwarmSpec {
	return DurableSwarmSpec{SchemaVersion: spec.SchemaVersion, SwarmID: spec.SwarmID, Plan: append([]byte(nil), spec.Plan...), Binding: append([]byte(nil), spec.Binding...), Request: append([]byte(nil), spec.Request...), AuthorityGeneration: spec.AuthorityGeneration, Steps: cloneDurableSteps(spec.Steps)}
}

func cloneDurableSteps(steps []DurableSwarmStepSpec) []DurableSwarmStepSpec {
	clone := make([]DurableSwarmStepSpec, len(steps))
	for i, step := range steps {
		clone[i] = step
		clone[i].DependsOn = append([]string(nil), step.DependsOn...)
		clone[i].Candidates = append([]DurableWorkerCandidate(nil), step.Candidates...)
	}
	return clone
}

// OpenVerifiedSwarm atomically creates a swarm.opened entry or confirms the existing byte-identical seed.
func OpenVerifiedSwarm(journal *SwarmJournal, spec DurableSwarmSpec, timestamp time.Time) (SwarmState, error) {
	if journal == nil {
		return SwarmState{}, errors.New("swarm journal is required")
	}
	wire, err := spec.wire()
	if err != nil {
		return SwarmState{}, err
	}
	if spec.SwarmID != journal.expectedSwarmID {
		return SwarmState{}, errors.New("swarm journal identity conflicts with durable seed")
	}
	payload, err := canonicalJSON(swarmOpenedPayload{SchemaVersion: swarmStateSchemaVersion, Spec: wire})
	if err != nil {
		return SwarmState{}, err
	}
	payload, err = canonicalSwarmPayload(payload)
	if err != nil {
		return SwarmState{}, err
	}
	var result SwarmState
	err = journal.WithLockedReplay(func(entries []SwarmJournalEntry) error {
		if len(entries) != 0 {
			if entries[0].Kind != "swarm.opened" || !bytes.Equal(entries[0].Payload, payload) {
				return errors.New("swarm open seed conflicts with durable journal")
			}
			state, err := ReduceSwarmEntries(entries)
			if err != nil {
				return err
			}
			if err := journal.validateTypedStateIdentity(state); err != nil {
				return err
			}
			result = state
			return nil
		}
		canonicalTimestamp, err := canonicalSwarmTimestamp(timestamp)
		if err != nil {
			return err
		}
		entry := SwarmJournalEntry{Format: swarmJournalFormat, Sequence: 1, PriorStateVersion: 0, StateVersion: 1, Kind: "swarm.opened", Payload: payload, Timestamp: canonicalTimestamp, PrevHash: swarmJournalZeroHash}
		entry.Hash, err = swarmJournalEntryHash(entry)
		if err != nil {
			return err
		}
		result, err = ReduceSwarmEntry(SwarmState{}, entry)
		if err != nil {
			return err
		}
		if err := journal.validateTypedStateIdentity(result); err != nil {
			return err
		}
		return journal.appendLocked(entry)
	})
	if err != nil {
		return SwarmState{}, err
	}
	return cloneSwarmState(result), nil
}

// DurableSpecFromVerifiedBinding runs Phase A verification and freezes its exact execution input.
func (f Fixture) DurableSpecFromVerifiedBinding(origin, request map[string]any) (DurableSwarmSpec, error) {
	if err := f.verifySwarmGenerationPins(); err != nil {
		return DurableSwarmSpec{}, err
	}
	verified, err := f.preflightSwarmExecution(origin, request, false)
	if err != nil {
		return DurableSwarmSpec{}, err
	}
	swarm, _ := request["swarm"].(map[string]any)
	plan, _ := swarm["plan"].(map[string]any)
	binding, _ := swarm["execution_binding"].(map[string]any)
	planRaw, err := canonicalJSON(plan)
	if err != nil {
		return DurableSwarmSpec{}, err
	}
	bindingRaw, err := canonicalJSON(binding)
	if err != nil {
		return DurableSwarmSpec{}, err
	}
	requestRaw, err := canonicalJSON(map[string]any{"origin": origin, "request": request})
	if err != nil {
		return DurableSwarmSpec{}, err
	}
	spec := DurableSwarmSpec{SchemaVersion: swarmStateSchemaVersion, SwarmID: verified.swarmID, Plan: planRaw, Binding: bindingRaw, Request: requestRaw, AuthorityGeneration: f.AuthorityGenerationPin, Steps: make([]DurableSwarmStepSpec, 0, len(verified.executionSteps))}
	for _, verifiedStep := range verified.executionSteps {
		step := DurableSwarmStepSpec{StepID: verifiedStep.stepID, DependsOn: append([]string(nil), verifiedStep.after...), TaskDigest: verifiedStep.taskDigest, Capability: verifiedStep.capability, AttemptPolicy: SwarmAttemptPolicy{MaxAttempts: 1}}
		candidate, err := durableCandidateForWorker(verifiedStep.originalWorker)
		if err != nil {
			return DurableSwarmSpec{}, err
		}
		step.Candidates = append(step.Candidates, candidate)
		if verifiedStep.migrationWorker != nil {
			candidate, err := durableCandidateForWorker(verifiedStep.migrationWorker)
			if err != nil {
				return DurableSwarmSpec{}, err
			}
			step.Candidates = append(step.Candidates, candidate)
		}
		spec.Steps = append(spec.Steps, step)
	}
	if err := validateDurableSwarmSpec(spec); err != nil {
		return DurableSwarmSpec{}, err
	}
	return cloneDurableSwarmSpec(spec), nil
}

func durableCandidateForWorker(worker *Worker) (DurableWorkerCandidate, error) {
	if worker == nil || worker.Descriptor == nil || worker.GenerationRef.RecordDigest != worker.WorkerGenerationPin.RecordDigest || worker.GenerationRef.DescriptorDigest == "" || digestHex(worker.Descriptor) != worker.GenerationRef.DescriptorDigest {
		return DurableWorkerCandidate{}, errors.New("worker durable verification pin invalid")
	}
	key, der, err := publicKey(worker.Descriptor)
	if err != nil || optionalString(worker.Descriptor["aid"]) != aidFromSPKI(der) || !bytes.Equal(key, worker.PrivateKey.Public().(ed25519.PublicKey)) {
		return DurableWorkerCandidate{}, errors.New("worker durable verification pin invalid")
	}
	return DurableWorkerCandidate{Alias: optionalString(worker.Descriptor["alias"]), AID: optionalString(worker.Descriptor["aid"]), GenerationPin: worker.WorkerGenerationPin, PublicKeySPKI: optionalString(worker.Descriptor["public_key_spki"]), DescriptorDigest: worker.GenerationRef.DescriptorDigest}, nil
}

// OpenVerifiedSwarm verifies Phase A before opening the authoritative journal.
func (f Fixture) OpenVerifiedSwarm(storageRoot string, origin, request map[string]any, timestamp time.Time) (*SwarmJournal, SwarmState, error) {
	spec, err := f.DurableSpecFromVerifiedBinding(origin, request)
	if err != nil {
		return nil, SwarmState{}, err
	}
	journal, err := OpenSwarmJournal(storageRoot, spec.SwarmID)
	if err != nil {
		return nil, SwarmState{}, err
	}
	state, err := OpenVerifiedSwarm(journal, spec, timestamp)
	if err != nil {
		return nil, SwarmState{}, err
	}
	return journal, state, nil
}

// RecoverVerifiedSwarm replays the journal then repeats Phase A verification from the frozen request.
func (f Fixture) RecoverVerifiedSwarm(journal *SwarmJournal) (SwarmState, error) {
	if journal == nil {
		return SwarmState{}, errors.New("swarm journal is required")
	}
	entries, err := journal.Replay()
	if err != nil {
		return SwarmState{}, err
	}
	state, err := ReduceSwarmEntries(entries)
	if err != nil {
		return SwarmState{}, err
	}
	if state.Version == 0 {
		return SwarmState{}, errors.New("swarm journal has no opening")
	}
	var envelope struct {
		Origin  map[string]any `json:"origin"`
		Request map[string]any `json:"request"`
	}
	if err := decodeStrictSwarmPayload(state.Spec.Request, &envelope); err != nil || envelope.Origin == nil || envelope.Request == nil {
		return SwarmState{}, errors.New("swarm durable request invalid")
	}
	reverified, err := f.DurableSpecFromVerifiedBinding(envelope.Origin, envelope.Request)
	if err != nil {
		return SwarmState{}, err
	}
	if !reflect.DeepEqual(state.Spec, reverified) {
		return SwarmState{}, errors.New("swarm recovery verification differs from durable seed")
	}
	return cloneSwarmState(state), nil
}


