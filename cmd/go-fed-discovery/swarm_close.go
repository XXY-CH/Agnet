package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"agnet/internal/managedkey"
)

// ReadyWaveEvidence is the exact persisted ready-layer evidence, kept in journal order.
type ReadyWaveEvidence struct {
	StepIDs    []string `json:"step_ids"`
	RecordedAt string   `json:"recorded_at"`
}

// DispatchAttemptEvidence is one exact lease claim from a persisted dispatch wave.
type DispatchAttemptEvidence struct {
	StepID         string                 `json:"step_id"`
	Owner          string                 `json:"owner"`
	Fence          LeaseFence             `json:"fence"`
	Attempt        uint64                 `json:"attempt"`
	CandidateIndex uint64                 `json:"candidate_index"`
	Capability     string                 `json:"capability"`
	Candidate      DurableWorkerCandidate `json:"candidate"`
	Deadline       string                 `json:"deadline"`
}

// DispatchWaveEvidence binds all attempts that were atomically leased for one ready layer.
type DispatchWaveEvidence struct {
	Wave     ReadyWaveEvidence         `json:"wave"`
	Attempts []DispatchAttemptEvidence `json:"attempts"`
}

// StoredSwarmClose is the exact canonical signed close record committed to the journal.
type StoredSwarmClose struct {
	Bytes  []byte `json:"-"`
	Digest string `json:"digest"`
}

type swarmCloseStepEvidence struct {
	StepID              string                    `json:"step_id"`
	TaskID              string                    `json:"task_id"`
	SignedReceiptDigest string                    `json:"signed_receipt_digest"`
	Observations        []SwarmAttemptObservation `json:"observations"`
}

type swarmCloseFinalOutput struct {
	StepID              string        `json:"step_id"`
	TaskID              string        `json:"task_id"`
	SignedReceiptDigest string        `json:"signed_receipt_digest"`
	Artifact            ArtifactTriple `json:"artifact"`
	SelectionRule       string        `json:"selection_rule"`
}

type closeStoredPayload struct {
	SchemaVersion uint64 `json:"schema_version"`
	Close         string `json:"close"`
	Digest        string `json:"digest"`
}

// BuildSwarmCloseV2 derives a close candidate solely from a locked journal replay. It never
// consults wall-clock state, random values, mutable projections, or map iteration order.
func BuildSwarmCloseV2(journal *SwarmJournal) (StoredSwarmClose, error) {
	if journal == nil {
		return StoredSwarmClose{}, errors.New("swarm journal is required")
	}
	var close StoredSwarmClose
	err := journal.WithLockedReplay(func(entries []SwarmJournalEntry) error {
		state, err := ReduceSwarmEntries(entries)
		if err != nil {
			return err
		}
		close, err = buildSwarmCloseV2Locked(entries, state)
		return err
	})
	return close, err
}

// EnsureStableClose appends a close.stored event exactly once. A retry rebuilds identical bytes
// before append and returns the previously stored bytes after append-before-response crashes.
func EnsureStableClose(journal *SwarmJournal) (StoredSwarmClose, error) {
	if journal == nil {
		return StoredSwarmClose{}, errors.New("swarm journal is required")
	}
	var result StoredSwarmClose
	err := journal.WithLockedReplay(func(entries []SwarmJournalEntry) error {
		state, err := ReduceSwarmEntries(entries)
		if err != nil {
			return err
		}
		if err := swarmMutationAllowed(state); err != nil {
			return err
		}
		for index, entry := range entries {
			if entry.Kind != "close.stored" {
				continue
			}
			stored, err := storedSwarmCloseFromEntry(entry)
			if err != nil {
				return err
			}
			prior, err := ReduceSwarmEntries(entries[:index])
			if err != nil {
				return err
			}
			candidate, err := buildSwarmCloseV2Locked(entries[:index], prior)
			if err != nil {
				return err
			}
			if !bytes.Equal(stored.Bytes, candidate.Bytes) || stored.Digest != candidate.Digest {
				return errors.New("swarm close conflicts with stored close")
			}
			result = stored
			return nil
		}
		candidate, err := buildSwarmCloseV2Locked(entries, state)
		if err != nil {
			return err
		}
		if state.Version == ^uint64(0) || len(entries) == 0 {
			return errors.New("swarm close state version invalid")
		}
		payload, err := canonicalSwarmPayload(closeStoredPayload{SchemaVersion: swarmStateSchemaVersion, Close: base64.RawURLEncoding.EncodeToString(candidate.Bytes), Digest: candidate.Digest})
		if err != nil {
			return err
		}
		entry := SwarmJournalEntry{Format: swarmJournalFormat, Sequence: uint64(len(entries) + 1), PriorStateVersion: state.Version, StateVersion: state.Version + 1, Kind: "close.stored", Payload: payload, Timestamp: entries[len(entries)-1].Timestamp, PrevHash: entries[len(entries)-1].Hash}
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
		result = candidate
		return nil
	})
	return result, err
}

func buildSwarmCloseV2Locked(entries []SwarmJournalEntry, state SwarmState) (StoredSwarmClose, error) {
	if state.Version == 0 || state.Status == SwarmStatusClosing {
		return StoredSwarmClose{}, errors.New("swarm close state invalid")
	}
	if state.Status != SwarmStatusCompleted || len(state.Leases) != 0 || len(state.Steps) == 0 {
		return StoredSwarmClose{}, errors.New("swarm close requires all steps committed")
	}
	for _, step := range state.Steps {
		if step.Status != SwarmStepStatusCompleted {
			return StoredSwarmClose{}, errors.New("swarm close requires all steps committed")
		}
	}
	planDigest, graphDigest, err := swarmCloseBindingDigests(state.Spec)
	if err != nil {
		return StoredSwarmClose{}, err
	}
	ready, dispatch, receipts, err := swarmCloseJournalEvidence(entries, state)
	if err != nil {
		return StoredSwarmClose{}, err
	}
	final, err := deriveJournalFinalOutput(state, receipts)
	if err != nil {
		return StoredSwarmClose{}, err
	}
	body := map[string]any{
		"format":                 "asp-swarm-close/v2",
		"swarm_id":               state.Spec.SwarmID,
		"plan_digest":            planDigest,
		"execution_graph_digest": graphDigest,
		"step_receipts":          receipts,
		"final_output":           final,
		"scheduler": map[string]any{
			"mode":           "parallel-ready-dag",
			"ready_waves":    ready,
			"dispatch_waves": dispatch,
		},
	}
	bodyRaw, err := canonicalJSON(body)
	if err != nil {
		return StoredSwarmClose{}, err
	}
	var canonicalBody map[string]any
	if err := json.Unmarshal(bodyRaw, &canonicalBody); err != nil {
		return StoredSwarmClose{}, err
	}
	key, err := pinnedCloseAuthorityKey(state.Spec)
	if err != nil {
		return StoredSwarmClose{}, err
	}
	defer clear(key)
	signed := signBodyWithKey(key, canonicalBody, "close_signature")
	raw, err := canonicalJSON(signed)
	if err != nil {
		return StoredSwarmClose{}, err
	}
	if err := verifyJournalCloseV2(raw, state, entries); err != nil {
		return StoredSwarmClose{}, err
	}
	return StoredSwarmClose{Bytes: raw, Digest: digestBytesHex(raw)}, nil
}

func swarmCloseBindingDigests(spec DurableSwarmSpec) (string, string, error) {
	var binding map[string]any
	decoder := json.NewDecoder(bytes.NewReader(spec.Binding))
	decoder.UseNumber()
	if err := decoder.Decode(&binding); err != nil || ensureSwarmJSONEOF(decoder) != nil || binding["format"] != "asp-swarm-execution-binding/v1" || binding["swarm_id"] != spec.SwarmID {
		return "", "", errors.New("swarm close binding invalid")
	}
	planDigest, graphDigest := optionalString(binding["plan_digest"]), optionalString(binding["execution_graph_digest"])
	if !isHexDigest(planDigest) || !isHexDigest(graphDigest) {
		return "", "", errors.New("swarm close binding invalid")
	}
	return planDigest, graphDigest, nil
}

func swarmCloseJournalEvidence(entries []SwarmJournalEntry, state SwarmState) ([]ReadyWaveEvidence, []DispatchWaveEvidence, []swarmCloseStepEvidence, error) {
	ready := make([]ReadyWaveEvidence, 0)
	dispatch := make([]DispatchWaveEvidence, 0)
	receiptsByStep := make(map[string]receiptCommittedPayload, len(state.Steps))
	for _, entry := range entries {
		switch entry.Kind {
		case "wave.ready":
			var payload waveReadyPayload
			if err := decodeStrictSwarmPayload(entry.Payload, &payload); err != nil || payload.SchemaVersion != swarmStateSchemaVersion {
				return nil, nil, nil, errors.New("swarm close ready wave evidence invalid")
			}
			ready = append(ready, ReadyWaveEvidence{StepIDs: append([]string(nil), payload.Wave.StepIDs...), RecordedAt: payload.Wave.RecordedAt})
		case "wave.dispatched":
			var payload waveDispatchedPayload
			if err := decodeStrictSwarmPayload(entry.Payload, &payload); err != nil || payload.SchemaVersion != swarmStateSchemaVersion {
				return nil, nil, nil, errors.New("swarm close dispatch wave evidence invalid")
			}
			attempts := make([]DispatchAttemptEvidence, len(payload.Claims))
			for i, claim := range payload.Claims {
				attempts[i] = DispatchAttemptEvidence{StepID: claim.StepID, Owner: claim.Owner, Fence: claim.Fence, Attempt: claim.Attempt, CandidateIndex: claim.CandidateIndex, Capability: claim.Capability, Candidate: claim.Candidate, Deadline: claim.Deadline}
			}
			dispatch = append(dispatch, DispatchWaveEvidence{Wave: ReadyWaveEvidence{StepIDs: append([]string(nil), payload.Wave.StepIDs...), RecordedAt: payload.Wave.RecordedAt}, Attempts: attempts})
		case "receipt.committed":
			var payload receiptCommittedPayload
			if err := decodeStrictSwarmPayload(entry.Payload, &payload); err != nil || payload.validateCanonical() != nil || receiptsByStep[payload.Claim.StepID].ReceiptDigest != "" {
				return nil, nil, nil, errors.New("swarm close receipt evidence invalid")
			}
			receiptsByStep[payload.Claim.StepID] = payload
		}
	}
	receipts := make([]swarmCloseStepEvidence, 0, len(state.Spec.Steps))
	for index, specStep := range state.Spec.Steps {
		payload, ok := receiptsByStep[specStep.StepID]
		if !ok || state.Steps[index].Status != SwarmStepStatusCompleted {
			return nil, nil, nil, errors.New("swarm close receipt missing")
		}
		receipts = append(receipts, swarmCloseStepEvidence{StepID: specStep.StepID, TaskID: specStep.TaskID, SignedReceiptDigest: payload.ReceiptDigest, Observations: append([]SwarmAttemptObservation(nil), state.Steps[index].Observations...)})
	}
	return ready, dispatch, receipts, nil
}

func deriveJournalFinalOutput(state SwarmState, receipts []swarmCloseStepEvidence) (swarmCloseFinalOutput, error) {
	if len(receipts) != len(state.Spec.Steps) {
		return swarmCloseFinalOutput{}, errors.New("swarm close receipt count invalid")
	}
	referenced := make(map[string]bool, len(state.Spec.Steps))
	for _, step := range state.Spec.Steps {
		for _, dependency := range step.DependsOn {
			referenced[dependency] = true
		}
	}
	terminal := -1
	for i, step := range state.Spec.Steps {
		if !referenced[step.StepID] {
			if terminal >= 0 {
				return swarmCloseFinalOutput{}, errors.New("single terminal step required")
			}
			terminal = i
		}
	}
	if terminal < 0 {
		return swarmCloseFinalOutput{}, errors.New("single terminal step required")
	}
	step := state.Spec.Steps[terminal]
	artifact, ok := state.CommittedArtifacts[step.StepID]
	if !ok || !validArtifactTriple(artifact) {
		return swarmCloseFinalOutput{}, errors.New("terminal result artifact missing")
	}
	return swarmCloseFinalOutput{StepID: step.StepID, TaskID: step.TaskID, SignedReceiptDigest: receipts[terminal].SignedReceiptDigest, Artifact: artifact, SelectionRule: "single-terminal-result"}, nil
}

func pinnedCloseAuthorityKey(spec DurableSwarmSpec) (ed25519.PrivateKey, error) {
	if spec.AuthorityGeneration.StorePath == "" || spec.AuthorityGeneration.PassphraseFile == "" || !isHexDigest(spec.AuthorityGeneration.RecordDigest) {
		return nil, errors.New("swarm close authority generation pin invalid")
	}
	authority, err := swarmCloseAuthorityDescriptor(spec)
	if err != nil {
		return nil, err
	}
	loaded, err := loadVerifiedKeyGeneration(spec.AuthorityGeneration.StorePath, spec.AuthorityGeneration.RecordDigest, spec.AuthorityGeneration.PassphraseFile)
	if err != nil {
		return nil, err
	}
	clear(loaded.Plaintext)
	if loaded.Identity.Kind != managedkey.IdentityZID || loaded.Identity.Value != optionalString(authority["zid"]) || loaded.KeyGeneration.RecordDigest != spec.AuthorityGeneration.RecordDigest {
		clear(loaded.PrivateKey)
		return nil, errors.New("swarm close authority generation mismatch")
	}
	key, _, err := publicKey(authority)
	if err != nil || !bytes.Equal(key, loaded.PrivateKey.Public().(ed25519.PublicKey)) {
		clear(loaded.PrivateKey)
		return nil, errors.New("swarm close authority key mismatch")
	}
	return loaded.PrivateKey, nil
}

func storedSwarmCloseFromEntry(entry SwarmJournalEntry) (StoredSwarmClose, error) {
	var payload closeStoredPayload
	if err := decodeStrictSwarmPayload(entry.Payload, &payload); err != nil || payload.SchemaVersion != swarmStateSchemaVersion || !isHexDigest(payload.Digest) || payload.Close == "" || bytes.ContainsRune([]byte(payload.Close), '=') {
		return StoredSwarmClose{}, errors.New("stored swarm close invalid")
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload.Close)
	if err != nil || base64.RawURLEncoding.EncodeToString(raw) != payload.Close || digestBytesHex(raw) != payload.Digest {
		return StoredSwarmClose{}, errors.New("stored swarm close invalid")
	}
	return StoredSwarmClose{Bytes: append([]byte(nil), raw...), Digest: payload.Digest}, nil
}

func swarmCloseAuthorityDescriptor(spec DurableSwarmSpec) (map[string]any, error) {
	if spec.LocalAuthority != nil {
		if verifyZoneDescriptor(spec.LocalAuthority) != nil {
			return nil, errors.New("swarm close local authority invalid")
		}
		return cloneFrozenMap(spec.LocalAuthority), nil
	}
	// Explicit legacy fallback: pre-U26 journals did not freeze the local authority.
	var envelope struct {
		Origin map[string]any `json:"origin"`
	}
	if err := decodeStrictSwarmPayload(spec.Request, &envelope); err != nil || envelope.Origin == nil || verifyZoneDescriptor(envelope.Origin) != nil {
		return nil, errors.New("swarm close authority request invalid")
	}
	return envelope.Origin, nil
}

func verifyJournalCloseV2(raw []byte, state SwarmState, entries []SwarmJournalEntry) error {
	if len(raw) == 0 || !json.Valid(raw) || validateSwarmJSONNoDuplicateFields(raw) != nil {
		return errors.New("swarm close bytes invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var close map[string]any
	if err := decoder.Decode(&close); err != nil || ensureSwarmJSONEOF(decoder) != nil {
		return errors.New("swarm close bytes invalid")
	}
	canonical, err := canonicalJSON(close)
	if err != nil || !bytes.Equal(raw, canonical) {
		return errors.New("swarm close bytes are not canonical")
	}
	planDigest, graphDigest, err := swarmCloseBindingDigests(state.Spec)
	if err != nil {
		return err
	}
	ready, dispatch, receipts, err := swarmCloseJournalEvidence(entries, state)
	if err != nil {
		return err
	}
	final, err := deriveJournalFinalOutput(state, receipts)
	if err != nil {
		return err
	}
	expected := map[string]any{"format": "asp-swarm-close/v2", "swarm_id": state.Spec.SwarmID, "plan_digest": planDigest, "execution_graph_digest": graphDigest, "step_receipts": receipts, "final_output": final, "scheduler": map[string]any{"mode": "parallel-ready-dag", "ready_waves": ready, "dispatch_waves": dispatch}}
	expectedRaw, err := canonicalJSON(expected)
	if err != nil {
		return err
	}
	var normalizedExpected map[string]any
	if err := json.Unmarshal(expectedRaw, &normalizedExpected); err != nil {
		return err
	}
	for field := range normalizedExpected {
		if !reflect.DeepEqual(close[field], normalizedExpected[field]) {
			return fmt.Errorf("swarm close %s evidence mismatch", field)
		}
	}
	if len(close) != len(normalizedExpected)+1 {
		return errors.New("swarm close fields invalid")
	}
	authority, err := swarmCloseAuthorityDescriptor(state.Spec)
	if err != nil {
		return err
	}
	key, _, err := publicKey(authority)
	if err != nil || verifyMapSignature(key, close, "close_signature") != nil {
		return errors.New("swarm close signature verification failed")
	}
	return nil
}
