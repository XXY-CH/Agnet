package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"time"
)

// StagedReceipt preserves the exact canonical signed v2 receipt bytes and their byte digest.
type StagedReceipt struct {
	Bytes  []byte
	Digest string
}

type ReceiptExpectation struct {
	SwarmID    string
	Claim      LeaseClaim
	TaskDigest string
	GraphDigest string
	Result     ArtifactTriple
	Auxiliary  []ArtifactTriple
	DependsOn  map[string]ArtifactTriple
}

type receiptV2Wire struct {
	Format              string                `json:"format"`
	SwarmID             string                `json:"swarm_id"`
	StepID              string                `json:"step_id"`
	TaskDigest          string                `json:"task_digest"`
	GraphDigest         string                `json:"graph_digest"`
	Capability          string                `json:"capability"`
	WorkerAID           string                `json:"worker_aid"`
	WorkerGenerationPin WorkerGenerationPin   `json:"worker_generation_pin"`
	Attempt             uint64                `json:"attempt"`
	Fence               LeaseFence            `json:"fence"`
	Result              ArtifactTriple         `json:"result"`
	Auxiliary           []ArtifactTriple       `json:"auxiliary"`
	Dependencies        []receiptDependencyV2 `json:"dependencies,omitempty"`
	Signature           string                `json:"signature"`
}

type receiptDependencyV2 struct {
	StepID  string        `json:"step_id"`
	Artifact ArtifactTriple `json:"artifact"`
}

// StageReceipt validates exact canonical JSON before accepting bytes as a receipt staging value.
func StageReceipt(raw []byte) (StagedReceipt, error) {
	if _, err := parseReceiptV2(raw); err != nil {
		return StagedReceipt{}, err
	}
	return StagedReceipt{Bytes: append([]byte(nil), raw...), Digest: digestBytesHex(raw)}, nil
}

// VerifyReceiptV2 validates a canonical signed receipt against its frozen execution identity.
func verifyReceiptV2(raw []byte, expected ReceiptExpectation) error {
	receipt, err := parseReceiptV2(raw)
	if err != nil {
		return err
	}
	if expected.SwarmID == "" || !validLeaseClaim(expected.Claim) || !isHexDigest(expected.TaskDigest) || !isHexDigest(expected.GraphDigest) {
		return errors.New("receipt v2 expectation invalid")
	}
	candidate := expected.Claim.Candidate
	key, der, err := publicKey(map[string]any{"public_key_spki": candidate.PublicKeySPKI})
	if err != nil || candidate.AID != aidFromSPKI(der) || !isHexDigest(candidate.DescriptorDigest) || !isHexDigest(candidate.GenerationPin.RecordDigest) {
		return errors.New("receipt v2 worker verification pin invalid")
	}
	if receipt.SwarmID != expected.SwarmID || receipt.StepID != expected.Claim.StepID || receipt.TaskDigest != expected.TaskDigest || receipt.GraphDigest != expected.GraphDigest || receipt.Capability != expected.Claim.Capability || receipt.WorkerAID != candidate.AID || receipt.WorkerGenerationPin != candidate.GenerationPin || receipt.Attempt != expected.Claim.Attempt || receipt.Fence != expected.Claim.Fence {
		return errors.New("receipt v2 frozen identity mismatch")
	}
	if receipt.Result != expected.Result || !reflect.DeepEqual(receipt.Auxiliary, expected.Auxiliary) {
		return errors.New("receipt v2 artifact triples mismatch")
	}
	if len(receipt.Dependencies) != len(expected.DependsOn) {
		return errors.New("receipt v2 dependency count mismatch")
	}
	for _, dependency := range receipt.Dependencies {
		if dependency.StepID == "" || dependency.Artifact != expected.DependsOn[dependency.StepID] {
			return errors.New("receipt v2 dependency mismatch")
		}
	}
	var signed map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&signed); err != nil || ensureSwarmJSONEOF(decoder) != nil || verifyMapSignature(key, signed, "signature") != nil {
		return errors.New("receipt v2 signature verification failed")
	}
	return nil
}

func parseReceiptV2(raw []byte) (receiptV2Wire, error) {
	if len(raw) == 0 || !json.Valid(raw) || validateSwarmJSONNoDuplicateFields(raw) != nil {
		return receiptV2Wire{}, errors.New("receipt v2 invalid")
	}
	var value any
	canonicalDecoder := json.NewDecoder(bytes.NewReader(raw))
	canonicalDecoder.UseNumber()
	if err := canonicalDecoder.Decode(&value); err != nil || ensureSwarmJSONEOF(canonicalDecoder) != nil {
		return receiptV2Wire{}, errors.New("receipt v2 invalid")
	}
	canonical, err := canonicalJSON(value)
	if err != nil || !bytes.Equal(raw, canonical) {
		return receiptV2Wire{}, errors.New("receipt v2 bytes are not canonical")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var receipt receiptV2Wire
	if err := decoder.Decode(&receipt); err != nil || ensureSwarmJSONEOF(decoder) != nil {
		return receiptV2Wire{}, errors.New("receipt v2 invalid")
	}
	if receipt.Format != "agnet-receipt/v2" || receipt.SwarmID == "" || receipt.StepID == "" || hasSwarmDelimiter(receipt.SwarmID) || hasSwarmDelimiter(receipt.StepID) || !isHexDigest(receipt.TaskDigest) || !isHexDigest(receipt.GraphDigest) || receipt.Capability == "" || receipt.WorkerAID == "" || receipt.Attempt == 0 || receipt.Fence == 0 || receipt.Signature == "" || !validArtifactTriple(receipt.Result) {
		return receiptV2Wire{}, errors.New("receipt v2 fields invalid")
	}
	if receipt.WorkerGenerationPin.StorePath == "" || receipt.WorkerGenerationPin.PassphraseFile == "" || !isHexDigest(receipt.WorkerGenerationPin.RecordDigest) {
		return receiptV2Wire{}, errors.New("receipt v2 generation pin invalid")
	}
	seen := make(map[string]bool, len(receipt.Dependencies))
	for _, artifact := range append(append([]ArtifactTriple{}, receipt.Auxiliary...), receipt.Result) {
		if !validArtifactTriple(artifact) {
			return receiptV2Wire{}, errors.New("receipt v2 artifact triple invalid")
		}
	}
	for _, dependency := range receipt.Dependencies {
		if dependency.StepID == "" || hasSwarmDelimiter(dependency.StepID) || seen[dependency.StepID] || !validArtifactTriple(dependency.Artifact) {
			return receiptV2Wire{}, errors.New("receipt v2 dependency invalid")
		}
		seen[dependency.StepID] = true
	}
	return receipt, nil
}

// ReceiptCommit requests one lease-fenced publication transaction.
type ReceiptCommit struct {
	Claim     LeaseClaim
	Receipt   StagedReceipt
	Result    StagedArtifact
	Auxiliary []StagedArtifact
}

type receiptCommittedPayload struct {
	SchemaVersion uint64          `json:"schema_version"`
	Claim         LeaseClaim      `json:"claim"`
	Receipt       string          `json:"receipt"`
	ReceiptDigest string          `json:"receipt_digest"`
	Result        ArtifactTriple `json:"result"`
	Auxiliary     []ArtifactTriple `json:"auxiliary"`
}

// CommitReceipt atomically validates a live lease and appends receipt.committed. It never writes
// a result view: successful fsync of this journal event is the publication boundary.
func CommitReceipt(journal *SwarmJournal, commit ReceiptCommit, timestamp time.Time) (SwarmState, error) {
	if journal == nil {
		return SwarmState{}, errors.New("swarm journal is required")
	}
	stamp, err := canonicalLeaseTime(timestamp)
	if err != nil {
		return SwarmState{}, err
	}
	if commit.Receipt.Digest != digestBytesHex(commit.Receipt.Bytes) {
		return SwarmState{}, errors.New("staged receipt digest invalid")
	}
	if _, err := parseReceiptV2(commit.Receipt.Bytes); err != nil {
		return SwarmState{}, err
	}
	var result SwarmState
	err = journal.WithLockedReplay(func(entries []SwarmJournalEntry) error {
		state, err := ReduceSwarmEntries(entries)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if entry.Kind != "receipt.committed" {
				continue
			}
			var payload receiptCommittedPayload
			if err := decodeStrictSwarmPayload(entry.Payload, &payload); err != nil {
				return errors.New("committed receipt payload invalid")
			}
			if payload.Claim.StepID != commit.Claim.StepID {
				continue
			}
			if exactCommittedReceipt(payload, commit) {
				result = cloneSwarmState(state)
				return nil
			}
			return errors.New("receipt commit conflicts with committed step")
		}
		if len(entries) != 0 && stamp < entries[len(entries)-1].Timestamp {
			return errors.New("receipt clock rollback")
		}
		stepIndex := swarmStepIndex(state.Steps, commit.Claim.StepID)
		if stepIndex < 0 || state.Steps[stepIndex].Status != SwarmStepStatusRunning || state.Steps[stepIndex].Attempts != commit.Claim.Attempt || !swarmDependenciesCompleted(state, stepIndex) {
			return errors.New("receipt does not target a running ready step")
		}
		leaseIndex := leaseIndex(state.Leases, commit.Claim.StepID)
		if leaseIndex < 0 || !reflect.DeepEqual(state.Leases[leaseIndex], commit.Claim) || stamp >= commit.Claim.Deadline {
			return errors.New("receipt lease fence is not live")
		}
		if _, err := readStagedArtifact(journal, commit.Result); err != nil {
			return err
		}
		auxiliary := make([]ArtifactTriple, len(commit.Auxiliary))
		for i, artifact := range commit.Auxiliary {
			if _, err := readStagedArtifact(journal, artifact); err != nil {
				return err
			}
			auxiliary[i] = artifact.Triple()
		}
		expectedDependencies, err := committedDependencyTriples(state, stepIndex)
		if err != nil {
			return err
		}
		expected := ReceiptExpectation{SwarmID: state.Spec.SwarmID, Claim: commit.Claim, TaskDigest: state.Spec.Steps[stepIndex].TaskDigest, GraphDigest: digestBytesHex(state.Spec.Binding), Result: commit.Result.Triple(), Auxiliary: auxiliary, DependsOn: expectedDependencies}
		if err := VerifyReceiptV2(commit.Receipt.Bytes, expected); err != nil {
			return err
		}
		if state.Version == math.MaxUint64 {
			return errors.New("swarm state version overflow")
		}
		payload := receiptCommittedPayload{SchemaVersion: swarmStateSchemaVersion, Claim: commit.Claim, Receipt: base64.RawURLEncoding.EncodeToString(commit.Receipt.Bytes), ReceiptDigest: commit.Receipt.Digest, Result: commit.Result.Triple(), Auxiliary: auxiliary}
		encoded, err := canonicalSwarmPayload(payload)
		if err != nil {
			return err
		}
		entry := SwarmJournalEntry{Format: swarmJournalFormat, Sequence: uint64(len(entries) + 1), PriorStateVersion: state.Version, StateVersion: state.Version + 1, Kind: "receipt.committed", Payload: encoded, Timestamp: stamp, PrevHash: swarmJournalZeroHash}
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
		result = cloneSwarmState(next)
		return nil
	})
	if err != nil {
		return SwarmState{}, err
	}
	return result, nil
}

func exactCommittedReceipt(payload receiptCommittedPayload, commit ReceiptCommit) bool {
	raw, err := base64.RawURLEncoding.DecodeString(payload.Receipt)
	return err == nil && payload.SchemaVersion == swarmStateSchemaVersion && payload.Claim == commit.Claim && payload.ReceiptDigest == commit.Receipt.Digest && bytes.Equal(raw, commit.Receipt.Bytes)
}

func committedDependencyTriples(state SwarmState, stepIndex int) (map[string]ArtifactTriple, error) {
	if stepIndex < 0 || stepIndex >= len(state.Spec.Steps) {
		return nil, errors.New("receipt committed dependency step invalid")
	}
	results := make(map[string]ArtifactTriple, len(state.Spec.Steps[stepIndex].DependsOn))
	for _, dependency := range state.Spec.Steps[stepIndex].DependsOn {
		artifact, ok := state.CommittedArtifacts[dependency]
		if !ok {
			return nil, errors.New("receipt committed dependency missing")
		}
		results[dependency] = artifact
	}
	return results, nil
}

func (payload receiptCommittedPayload) validateCanonical() error {
	if payload.SchemaVersion != swarmStateSchemaVersion || !validLeaseClaim(payload.Claim) || payload.ReceiptDigest == "" || !validArtifactTriple(payload.Result) {
		return errors.New("committed receipt payload invalid")
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload.Receipt)
	if err != nil || base64.RawURLEncoding.EncodeToString(raw) != payload.Receipt || digestBytesHex(raw) != payload.ReceiptDigest {
		return errors.New("committed receipt bytes invalid")
	}
	if _, err := parseReceiptV2(raw); err != nil {
		return err
	}
	for _, artifact := range payload.Auxiliary {
		if !validArtifactTriple(artifact) {
			return errors.New("committed receipt auxiliary invalid")
		}
	}
	return nil
}

func (payload receiptCommittedPayload) String() string { return fmt.Sprintf("receipt %s", payload.ReceiptDigest) }

func reduceSwarmReceiptEntry(state *SwarmState, entry SwarmJournalEntry) error {
	if state == nil || state.Status == SwarmStatusFailed {
		return errors.New("receipt commitment state invalid")
	}
	var payload receiptCommittedPayload
	if err := decodeStrictSwarmPayload(entry.Payload, &payload); err != nil {
		return errors.New("committed receipt payload invalid")
	}
	if err := payload.validateCanonical(); err != nil || !isCanonicalLeaseText(entry.Timestamp) {
		return errors.New("committed receipt payload invalid")
	}
	stepIndex := swarmStepIndex(state.Steps, payload.Claim.StepID)
	leaseAt := leaseIndex(state.Leases, payload.Claim.StepID)
	if stepIndex < 0 || leaseAt < 0 || state.Steps[stepIndex].Status != SwarmStepStatusRunning || state.Steps[stepIndex].Attempts != payload.Claim.Attempt || !reflect.DeepEqual(state.Leases[leaseAt], payload.Claim) || entry.Timestamp >= payload.Claim.Deadline || !swarmDependenciesCompleted(*state, stepIndex) {
		return errors.New("committed receipt does not match a live lease")
	}
	raw, _ := base64.RawURLEncoding.DecodeString(payload.Receipt)
	expectedDependencies, err := committedDependencyTriples(*state, stepIndex)
	if err != nil {
		return err
	}
	expected := ReceiptExpectation{SwarmID: state.Spec.SwarmID, Claim: payload.Claim, TaskDigest: state.Spec.Steps[stepIndex].TaskDigest, GraphDigest: digestBytesHex(state.Spec.Binding), Result: payload.Result, Auxiliary: payload.Auxiliary, DependsOn: expectedDependencies}
	if err := VerifyReceiptV2(raw, expected); err != nil {
		return err
	}
	if state.CommittedArtifacts == nil {
		return errors.New("committed artifact state missing")
	}
	state.CommittedArtifacts[payload.Claim.StepID] = payload.Result
	state.Steps[stepIndex].Status = SwarmStepStatusCompleted
	state.Steps[stepIndex].Observations = append(state.Steps[stepIndex].Observations, SwarmAttemptObservation{Attempt: payload.Claim.Attempt, Candidate: payload.Claim.Candidate, Owner: payload.Claim.Owner, Fence: payload.Claim.Fence, Outcome: "receipt.committed", ObservedAt: entry.Timestamp})
	state.Leases = append(state.Leases[:leaseAt:leaseAt], state.Leases[leaseAt+1:]...)
	state.ReadyWave = ReadyWave{}
	return nil
}
