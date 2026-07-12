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
	SwarmStatusClosing   SwarmStatus = "closing"
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
	// Descriptor is canonical JSON for the exact signed descriptor used for receipt verification.
	// A string preserves DurableWorkerCandidate comparability used by lease invariants.
	Descriptor       string              `json:"descriptor,omitempty"`
	// ZoneBinding is canonical JSON for the authority-signed worker-zone binding.
	ZoneBinding       string              `json:"zone_binding,omitempty"`
	// Runtime is the exact non-secret container profile captured at dispatch.
	// Key material is intentionally excluded; generation pin remains authoritative.
	Runtime          *WorkerProfile      `json:"runtime,omitempty"`
	RuntimeKind      string              `json:"runtime_kind,omitempty"`
}

// DurableSwarmStepSpec is the complete immutable execution input for one ordered step.
type DurableSwarmStepSpec struct {
	StepID        string                   `json:"step_id"`
	DependsOn     []string                 `json:"depends_on,omitempty"`
	TaskID        string                   `json:"task_id,omitempty"`
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
	// LocalAuthority is the canonical signed coordinator Zone descriptor, not the remote origin.
	LocalAuthority      map[string]any         `json:"local_authority,omitempty"`
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
	StoredClose        StoredSwarmClose           `json:"-"`
	OutputVerification *SwarmOutputVerification   `json:"output_verification,omitempty"`
}

// SwarmOutputVerification is replay-derived proof metadata. The exact proof
// and close bytes remain in the immutable journal event.
type SwarmOutputVerification struct {
	VerificationID    string `json:"verification_id"`
	SubmissionDigest  string `json:"submission_digest"`
	ProofDigest       string `json:"proof_digest"`
	CloseDigest       string `json:"close_digest"`
	TrustInputsDigest string `json:"trust_inputs_digest"`
	VerifiedAt        string `json:"verified_at"`
	CompletedAt       string `json:"completed_at"`
}
type durableSwarmSpecWire struct {
	SchemaVersion       uint64                 `json:"schema_version"`
	SwarmID             string                 `json:"swarm_id"`
	Plan                string                 `json:"plan"`
	Binding             string                 `json:"binding"`
	Request             string                 `json:"request"`
	AuthorityGeneration WorkerGenerationPin    `json:"authority_generation_pin"`
	LocalAuthority      map[string]any         `json:"local_authority,omitempty"`
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
		LocalAuthority:      cloneFrozenMap(spec.LocalAuthority),
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
	spec := DurableSwarmSpec{SchemaVersion: wire.SchemaVersion, SwarmID: wire.SwarmID, Plan: plan, Binding: binding, Request: request, AuthorityGeneration: wire.AuthorityGeneration, LocalAuthority: cloneFrozenMap(wire.LocalAuthority), Steps: cloneDurableSteps(wire.Steps)}
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
	// A seed with a frozen local authority is the U26 format. Older journals did
	// not carry this material and remain replayable through their explicit legacy path.
	frozen := spec.LocalAuthority != nil
	if frozen && (len(spec.LocalAuthority) == 0 || verifyZoneDescriptor(spec.LocalAuthority) != nil || spec.AuthorityGeneration.StorePath == "" || spec.AuthorityGeneration.PassphraseFile == "" || !isHexDigest(spec.AuthorityGeneration.RecordDigest)) {
		return errors.New("swarm durable local authority pin invalid")
	}
	if len(spec.Steps) == 0 {
		return errors.New("swarm durable steps missing")
	}
	seen := make(map[string]bool, len(spec.Steps))
	for _, step := range spec.Steps {
		if step.StepID == "" || hasSwarmDelimiter(step.StepID) || seen[step.StepID] || step.AttemptPolicy.MaxAttempts == 0 || len(step.Candidates) == 0 {
			return errors.New("swarm durable step invalid")
		}
		if frozen && (step.TaskID == "" || hasSwarmDelimiter(step.TaskID) || !isHexDigest(step.TaskDigest)) {
			return errors.New("swarm durable signed task identity invalid")
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
			if err != nil || len(key) != ed25519.PublicKeySize || candidate.AID != aidFromSPKI(der) {
				return errors.New("swarm durable worker verification pin invalid")
			}
			if frozen {
				descriptor, err := frozenAgentDescriptor(candidate.Descriptor)
				if err != nil || digestHex(descriptor) != candidate.DescriptorDigest || verifyAgentDescriptor(descriptor) != nil || optionalString(descriptor["aid"]) != candidate.AID || optionalString(descriptor["public_key_spki"]) != candidate.PublicKeySPKI {
					return errors.New("swarm durable worker descriptor pin invalid")
				}
				binding, err := frozenZoneBinding(candidate.ZoneBinding)
				if err != nil || verifyZoneBinding(spec.LocalAuthority, binding, descriptor) != nil {
					return errors.New("swarm durable worker zone binding pin invalid")
				}
			}
			if candidate.Runtime != nil {
				runtime := candidate.Runtime
				if runtime.KeyFile != "" || runtime.KeyStore != "" || runtime.PassphraseFile != "" || runtime.KeyGeneration != (WorkerGenerationPin{}) || (candidate.RuntimeKind != "" && candidate.RuntimeKind != "docker" && candidate.RuntimeKind != "apple-container") {
					return errors.New("swarm durable worker runtime invalid")
				}
				if candidate.RuntimeKind != "" && (runtime.SandboxClaim != "container-namespace" || runtime.Docker == nil) {
					return errors.New("swarm durable worker runtime invalid")
				}
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
	if prior.Version != 0 && (prior.Status == SwarmStatusCancelled || (prior.Status == SwarmStatusCompleted && entry.Kind != "close.stored") || (prior.Status == SwarmStatusClosing && entry.Kind != "output.verification_failed" && entry.Kind != "output.verified")) {
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
	case "close.stored":
		if prior.Version == 0 || prior.Status != SwarmStatusCompleted || len(prior.Leases) != 0 {
			return SwarmState{}, errors.New("illegal swarm close")
		}
		for _, step := range prior.Steps {
			if step.Status != SwarmStepStatusCompleted {
				return SwarmState{}, errors.New("illegal swarm close")
			}
		}
		stored, err := storedSwarmCloseFromEntry(entry)
		if err != nil {
			return SwarmState{}, err
		}
		next.StoredClose = stored
	case "output.verification_failed":
		var payload outputVerificationFailurePayload
		if prior.Status != SwarmStatusClosing || prior.OutputVerification != nil || decodeStrictSwarmPayload(entry.Payload, &payload) != nil || payload.SchemaVersion != swarmStateSchemaVersion || !isHexDigest(payload.SubmissionDigest) || payload.ErrorCode != "output_proof_rejected" {
			return SwarmState{}, errors.New("output verification failure invalid")
		}
	case "output.verified":
		var payload outputVerifiedPayload
		if prior.Status != SwarmStatusClosing || prior.OutputVerification != nil || decodeStrictSwarmPayload(entry.Payload, &payload) != nil || !validOutputVerifiedPayload(payload) || payload.SwarmID != prior.Spec.SwarmID || payload.PriorStatus != prior.Status || payload.NextStatus != SwarmStatusCompleted || payload.CloseDigest != prior.StoredClose.Digest || payload.CompletedAt != entry.Timestamp || verifyOutputVerifiedCompletionAuthorization(prior.Spec, payload) != nil {
			return SwarmState{}, errors.New("output verification invalid")
		}
		_, final, err := storedOutputFinal(prior.StoredClose)
		if err != nil {
			return SwarmState{}, err
		}
		expectedFinal, err := canonicalJSON(final)
		if err != nil || !bytes.Equal(payload.FinalOutput, expectedFinal) {
			return SwarmState{}, errors.New("output verification final output conflicts with close")
		}
		next.OutputVerification = &SwarmOutputVerification{VerificationID: payload.VerificationID, SubmissionDigest: payload.SubmissionDigest, ProofDigest: payload.ProofDigest, CloseDigest: payload.CloseDigest, TrustInputsDigest: payload.TrustInputsDigest, VerifiedAt: payload.VerifiedAt, CompletedAt: payload.CompletedAt}
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
	if entry.Kind == "close.stored" || entry.Kind == "output.verification_failed" {
		next.Status = SwarmStatusClosing
	}
	if entry.Kind == "output.verified" {
		next.Status = SwarmStatusCompleted
	}
	return next, nil
}

// isSwarmStateEntryKind identifies state authority held by U20. Other namespaces are retained
// by typed journals for future reducers, while unknown state namespaces fail closed.
func isSwarmStateEntryKind(kind string) (bool, error) {
	switch kind {
	case "swarm.opened", "swarm.cancelled", "wave.ready", "wave.dispatched", "lease.renewed", "lease.observed", "lease.expired", "receipt.committed", "close.stored", "output.verification_failed", "output.verified":
		return true, nil
	default:
		if strings.HasPrefix(kind, "swarm.") || strings.HasPrefix(kind, "step.") || strings.HasPrefix(kind, "receipt.") || strings.HasPrefix(kind, "output.") {
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
	for index, entry := range entries {
		if entry.Kind == "close.stored" {
			stored, err := storedSwarmCloseFromEntry(entry)
			if err != nil {
				return SwarmState{}, fmt.Errorf("reduce swarm journal entry %d: %w", entry.Sequence, err)
			}
			if err := verifyJournalCloseV2(stored.Bytes, state, entries[:index]); err != nil {
				return SwarmState{}, fmt.Errorf("reduce swarm journal entry %d: %w", entry.Sequence, err)
			}
		}
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
	clone.StoredClose = StoredSwarmClose{Bytes: append([]byte(nil), state.StoredClose.Bytes...), Digest: state.StoredClose.Digest}
	if state.OutputVerification != nil {
		value := *state.OutputVerification
		clone.OutputVerification = &value
	}
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
	return DurableSwarmSpec{SchemaVersion: spec.SchemaVersion, SwarmID: spec.SwarmID, Plan: append([]byte(nil), spec.Plan...), Binding: append([]byte(nil), spec.Binding...), Request: append([]byte(nil), spec.Request...), AuthorityGeneration: spec.AuthorityGeneration, LocalAuthority: cloneFrozenMap(spec.LocalAuthority), Steps: cloneDurableSteps(spec.Steps)}
}

// cloneFrozenMap makes durable descriptor snapshots independent of callers and replay views.
// Descriptors have already passed canonical JSON validation before entering durable state.
func cloneFrozenMap(value map[string]any) map[string]any {
	if value == nil {
		return nil
	}
	raw, err := canonicalJSON(value)
	if err != nil {
		return nil
	}
	var clone map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&clone) != nil || ensureSwarmJSONEOF(decoder) != nil {
		return nil
	}
	return clone
}

func frozenAgentDescriptor(raw string) (map[string]any, error) {
	if raw == "" || !json.Valid([]byte(raw)) || validateSwarmJSONNoDuplicateFields([]byte(raw)) != nil {
		return nil, errors.New("frozen worker descriptor invalid")
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	var descriptor map[string]any
	if err := decoder.Decode(&descriptor); err != nil || ensureSwarmJSONEOF(decoder) != nil {
		return nil, errors.New("frozen worker descriptor invalid")
	}
	canonical, err := canonicalJSON(descriptor)
	if err != nil || string(canonical) != raw {
		return nil, errors.New("frozen worker descriptor is not canonical")
	}
	return descriptor, nil
}

func frozenZoneBinding(raw string) (map[string]any, error) {
	if raw == "" || !json.Valid([]byte(raw)) || validateSwarmJSONNoDuplicateFields([]byte(raw)) != nil {
		return nil, errors.New("frozen worker zone binding invalid")
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	var binding map[string]any
	if err := decoder.Decode(&binding); err != nil || ensureSwarmJSONEOF(decoder) != nil {
		return nil, errors.New("frozen worker zone binding invalid")
	}
	canonical, err := canonicalJSON(binding)
	if err != nil || string(canonical) != raw {
		return nil, errors.New("frozen worker zone binding is not canonical")
	}
	return binding, nil
}

func cloneDurableSteps(steps []DurableSwarmStepSpec) []DurableSwarmStepSpec {
	clone := make([]DurableSwarmStepSpec, len(steps))
	for i, step := range steps {
		clone[i] = step
		clone[i].DependsOn = append([]string(nil), step.DependsOn...)
		clone[i].Candidates = make([]DurableWorkerCandidate, len(step.Candidates))
		for candidateIndex, candidate := range step.Candidates {
			clone[i].Candidates[candidateIndex] = candidate
			if candidate.Runtime != nil {
				runtime := *candidate.Runtime
				runtime.ToolCommand = append([]string(nil), candidate.Runtime.ToolCommand...)
				if candidate.Runtime.Docker != nil {
					docker := *candidate.Runtime.Docker
					docker.Command = append([]string(nil), candidate.Runtime.Docker.Command...)
					docker.ScratchInputs = append([]DockerScratchInput(nil), candidate.Runtime.Docker.ScratchInputs...)
					runtime.Docker = &docker
				}
				clone[i].Candidates[candidateIndex].Runtime = &runtime
			}
		}
	}
	return clone
}

// OpenVerifiedSwarm atomically creates a swarm.opened entry or confirms the existing byte-identical seed.
func OpenVerifiedSwarm(journal *SwarmJournal, spec DurableSwarmSpec, timestamp time.Time) (SwarmState, error) {
	if journal == nil { return SwarmState{}, errors.New("swarm journal is required") }
	wire, err := spec.wire(); if err != nil { return SwarmState{}, err }
	if spec.SwarmID != journal.expectedSwarmID { return SwarmState{}, errors.New("swarm journal identity conflicts with durable seed") }
	payload, err := canonicalJSON(swarmOpenedPayload{SchemaVersion: swarmStateSchemaVersion, Spec: wire}); if err != nil { return SwarmState{}, err }
	payload, err = canonicalSwarmPayload(payload); if err != nil { return SwarmState{}, err }
	var result SwarmState
	err = journal.WithLockedReplay(func(entries []SwarmJournalEntry) error {
		if len(entries) != 0 {
			if entries[0].Kind != "swarm.opened" || !bytes.Equal(entries[0].Payload, payload) { return errors.New("swarm open seed conflicts with durable journal") }
			state, err := ReduceSwarmEntries(entries); if err != nil { return err }
			if err := journal.validateTypedStateIdentity(state); err != nil { return err }
			result = state
			return nil
		}
		canonicalTimestamp, err := canonicalSwarmTimestamp(timestamp); if err != nil { return err }
		entry := SwarmJournalEntry{Format: swarmJournalFormat, Sequence: 1, PriorStateVersion: 0, StateVersion: 1, Kind: "swarm.opened", Payload: payload, Timestamp: canonicalTimestamp, PrevHash: swarmJournalZeroHash}
		entry.Hash, err = swarmJournalEntryHash(entry); if err != nil { return err }
		result, err = ReduceSwarmEntry(SwarmState{}, entry); if err != nil { return err }
		if err := journal.validateTypedStateIdentity(result); err != nil { return err }
		return journal.appendLocked(entry)
	})
	if err != nil { return SwarmState{}, err }
	return cloneSwarmState(result), nil
}
// DurableSpecFromVerifiedBinding runs Phase A verification and freezes its exact execution input.
func (f Fixture) DurableSpecFromVerifiedBinding(origin, request map[string]any) (DurableSwarmSpec, error) {
	if err := f.verifySwarmGenerationPins(); err != nil { return DurableSwarmSpec{}, err }
	if err := f.verifyAuthoritySeed(); err != nil || f.Authority == nil { return DurableSwarmSpec{}, errors.New("swarm local authority verification pin invalid") }
	localAuthority := cloneFrozenMap(f.Authority)
	if localAuthority == nil || verifyZoneDescriptor(localAuthority) != nil { return DurableSwarmSpec{}, errors.New("swarm local authority descriptor invalid") }
	verified, err := f.preflightSwarmExecution(origin, request, false); if err != nil { return DurableSwarmSpec{}, err }
	swarm, _ := request["swarm"].(map[string]any)
	plan, _ := swarm["plan"].(map[string]any)
	binding, _ := swarm["execution_binding"].(map[string]any)
	planRaw, err := canonicalJSON(plan); if err != nil { return DurableSwarmSpec{}, err }
	bindingRaw, err := canonicalJSON(binding); if err != nil { return DurableSwarmSpec{}, err }
	requestRaw, err := canonicalJSON(map[string]any{"origin": origin, "request": request}); if err != nil { return DurableSwarmSpec{}, err }
	spec := DurableSwarmSpec{SchemaVersion: swarmStateSchemaVersion, SwarmID: verified.swarmID, Plan: planRaw, Binding: bindingRaw, Request: requestRaw, AuthorityGeneration: f.AuthorityGenerationPin, LocalAuthority: localAuthority, Steps: make([]DurableSwarmStepSpec, 0, len(verified.executionSteps))}
	for _, verifiedStep := range verified.executionSteps {
		taskID := optionalString(verifiedStep.signedTask["task_id"])
		if taskID == "" || hasSwarmDelimiter(taskID) { return DurableSwarmSpec{}, errors.New("swarm signed task_id missing") }
		step := DurableSwarmStepSpec{StepID: verifiedStep.stepID, DependsOn: append([]string(nil), verifiedStep.after...), TaskID: taskID, TaskDigest: verifiedStep.taskDigest, Capability: verifiedStep.capability, AttemptPolicy: SwarmAttemptPolicy{MaxAttempts: 1}}
		candidate, err := f.durableCandidateForWorker(verifiedStep.originalWorker); if err != nil { return DurableSwarmSpec{}, err }
		step.Candidates = append(step.Candidates, candidate)
		if verifiedStep.migrationWorker != nil {
			candidate, err := f.durableCandidateForWorker(verifiedStep.migrationWorker); if err != nil { return DurableSwarmSpec{}, err }
			step.Candidates = append(step.Candidates, candidate)
		}
		spec.Steps = append(spec.Steps, step)
	}
	if err := validateDurableSwarmSpec(spec); err != nil { return DurableSwarmSpec{}, err }
	return cloneDurableSwarmSpec(spec), nil
}

func (f Fixture) durableCandidateForWorker(worker *Worker) (DurableWorkerCandidate, error) {
	candidate, err := durableCandidateForWorker(worker)
	if err != nil { return DurableWorkerCandidate{}, err }
	bindingRaw, err := canonicalJSON(f.zoneBinding(worker))
	if err != nil { return DurableWorkerCandidate{}, errors.New("worker durable zone binding pin invalid") }
	candidate.ZoneBinding = string(bindingRaw)
	return candidate, nil
}

func durableCandidateForWorker(worker *Worker) (DurableWorkerCandidate, error) {
	if worker == nil || worker.Descriptor == nil || worker.GenerationRef.RecordDigest != worker.WorkerGenerationPin.RecordDigest || worker.GenerationRef.DescriptorDigest == "" || digestHex(worker.Descriptor) != worker.GenerationRef.DescriptorDigest {
		return DurableWorkerCandidate{}, errors.New("worker durable verification pin invalid")
	}
	key, der, err := publicKey(worker.Descriptor)
	if err != nil || optionalString(worker.Descriptor["aid"]) != aidFromSPKI(der) || !bytes.Equal(key, worker.PrivateKey.Public().(ed25519.PublicKey)) {
		return DurableWorkerCandidate{}, errors.New("worker durable verification pin invalid")
	}
	runtime := worker.Profile
	runtime.KeyFile, runtime.KeyStore, runtime.PassphraseFile, runtime.KeyGeneration = "", "", "", WorkerGenerationPin{}
	runtime.ToolCommand = append([]string(nil), runtime.ToolCommand...)
	if runtime.Docker != nil {
		docker := *runtime.Docker
		docker.Command = append([]string(nil), runtime.Docker.Command...)
		docker.ScratchInputs = append([]DockerScratchInput(nil), runtime.Docker.ScratchInputs...)
		runtime.Docker = &docker
	}
	runtimeKind := ""
	if runtime.SandboxClaim == "container-namespace" {
		runtimeKind, err = configuredContainerRuntime()
		if err != nil { return DurableWorkerCandidate{}, errors.New("worker durable runtime pin invalid") }
	}
	descriptorRaw, err := canonicalJSON(worker.Descriptor)
	if err != nil {
		return DurableWorkerCandidate{}, errors.New("worker durable descriptor pin invalid")
	}
	return DurableWorkerCandidate{Alias: optionalString(worker.Descriptor["alias"]), AID: optionalString(worker.Descriptor["aid"]), GenerationPin: worker.WorkerGenerationPin, PublicKeySPKI: optionalString(worker.Descriptor["public_key_spki"]), DescriptorDigest: worker.GenerationRef.DescriptorDigest, Descriptor: string(descriptorRaw), Runtime: &runtime, RuntimeKind: runtimeKind}, nil
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


