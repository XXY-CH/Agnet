package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"time"

	"agnet/verifier"
)

const (
	swarmOutputVerificationFrameType      = "FED_SWARM_OUTPUT_VERIFY"
	maxSwarmOutputVerificationFrameBytes  = 256 << 10
	maxSwarmOutputVerificationProofBytes  = 192 << 10
	maxSwarmOutputVerificationAttempts    = 8
	maxSwarmOutputVerificationRecordBytes = 224 << 10
)

var errOutputProofRejected = errors.New("output verification rejected")

// OutputVerificationAttempt is the durable result of a submitted output proof.
// It deliberately contains only journal-derived or verifier-authenticated data.
type OutputVerificationAttempt struct {
	SwarmID           string         `json:"swarm_id"`
	VerificationID    string         `json:"verification_id"`
	Decision          string         `json:"decision"`
	ProofDigest       string         `json:"proof_digest"`
	CloseDigest       string         `json:"close_digest"`
	TrustInputsDigest string         `json:"trust_inputs_digest"`
	VerifiedAt        string         `json:"verified_at"`
	FinalOutput       map[string]any `json:"final_output"`
}

type parsedOutputVerificationFrame struct {
	SwarmID          string
	Proof            map[string]any
	ProofBytes       []byte
	SubmissionDigest string
}

type outputVerificationFailurePayload struct {
	SchemaVersion    uint64 `json:"schema_version"`
	SubmissionDigest string `json:"submission_digest"`
	ErrorCode        string `json:"error_code"`
}

// outputVerifiedPayload is the exact, local-authority-signed completion authorization.
// CompletionSignature covers every field returned by outputVerifiedPayloadBody.
type outputVerifiedPayload struct {
	SchemaVersion        uint64          `json:"schema_version"`
	SwarmID              string          `json:"swarm_id"`
	VerificationID       string          `json:"verification_id"`
	CanonicalProofDigest string          `json:"canonical_proof_digest"`
	SubmissionDigest     string          `json:"submission_digest"`
	Proof                string          `json:"proof"`
	ProofDigest          string          `json:"proof_digest"`
	Close                string          `json:"close"`
	CloseDigest          string          `json:"close_digest"`
	TrustInputsDigest    string          `json:"trust_inputs_digest"`
	FinalOutput          json.RawMessage `json:"final_output"`
	VerifiedAt           string          `json:"verified_at"`
	VerifierAID          string          `json:"verifier_aid"`
	VerifierZone         string          `json:"verifier_zone"`
	PriorStatus          SwarmStatus     `json:"prior_status"`
	NextStatus           SwarmStatus     `json:"next_status"`
	ReplayDecision       string          `json:"replay_decision"`
	CompletedAt          string          `json:"completed_at"`
	CompletionSignature  string          `json:"completion_signature"`
}

type swarmOutputProofVerifier func(map[string]any, verifier.TrustInputs, verifier.FrozenSwarmOutputEvidence, time.Time) (verifier.VerifiedSwarmOutput, error)

func parseOutputVerificationFrame(raw []byte) (parsedOutputVerificationFrame, error) {
	var zero parsedOutputVerificationFrame
	if len(raw) == 0 || len(raw) > maxSwarmOutputVerificationFrameBytes || !json.Valid(raw) || validateSwarmJSONNoDuplicateFields(raw) != nil {
		return zero, errors.New("output verification frame invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var frame map[string]any
	if err := decoder.Decode(&frame); err != nil || ensureSwarmJSONEOF(decoder) != nil || !hasRequiredAllowedMapFields(frame, []string{"type", "swarm_id", "proof"}, []string{"origin_zone"}) || frame["type"] != swarmOutputVerificationFrameType {
		return zero, errors.New("output verification frame invalid")
	}
	swarmID, ok := frame["swarm_id"].(string)
	proof, ok := frame["proof"].(map[string]any)
	if !ok || swarmID == "" || hasSwarmDelimiter(swarmID) || containsOutputPathField(proof) {
		return zero, errors.New("output verification frame invalid")
	}
	proofBytes, err := canonicalJSON(proof)
	if err != nil || len(proofBytes) == 0 || len(proofBytes) > maxSwarmOutputVerificationProofBytes {
		return zero, errors.New("output verification proof invalid")
	}
	return parsedOutputVerificationFrame{SwarmID: swarmID, Proof: proof, ProofBytes: proofBytes, SubmissionDigest: digestBytesHex(raw)}, nil
}

// RecordOutputVerification accepts only a bounded proof frame. Close records,
// receipt evidence, artifact bytes, and trust inputs are always resolved from
// the local durable authority under the journal lock.

func containsOutputPathField(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		for key, item := range typed {
			if key == "path" || key == "artifact_path" || containsOutputPathField(item) {
				return true
			}
		}
	case []any:
		for _, item := range typed {
			if containsOutputPathField(item) {
				return true
			}
		}
	}
	return false
}
func (c *LocalSwarmCoordinator) RecordOutputVerification(ctx context.Context, frameBytes []byte) (OutputVerificationAttempt, error) {
	_ = ctx
	var zero OutputVerificationAttempt
	if c == nil || c.storageRoot == "" || c.now == nil {
		return zero, errors.New("local swarm coordinator output gate unavailable")
	}
	frame, err := parseOutputVerificationFrame(frameBytes)
	if err != nil {
		return zero, err
	}
	journal, err := OpenSwarmJournal(c.storageRoot, frame.SwarmID)
	if err != nil {
		return zero, errors.New("output verification swarm unavailable")
	}
	var result OutputVerificationAttempt
	err = journal.WithLockedReplay(func(entries []SwarmJournalEntry) error {
		state, err := ReduceSwarmEntries(entries)
		if err != nil {
			return err
		}
		if err := swarmMutationAllowed(state); err != nil {
			return err
		}
		if state.Version == 0 || state.Spec.SwarmID != frame.SwarmID {
			return errors.New("output verification swarm unavailable")
		}
		if state.Status == SwarmStatusCompleted {
			stored, ok, err := storedOutputVerification(entries)
			if err != nil {
				return err
			}
			if !ok {
				return errors.New("output verification completed state invalid")
			}
			if stored.VerificationID != outputVerificationID(frame.Proof) || stored.SubmissionDigest != frame.SubmissionDigest {
				return errors.New("output verification replay conflicts")
			}
			result, err = outputAttemptFromVerified(frame.SwarmID, stored, "idempotent")
			return err
		}
		if state.Status != SwarmStatusClosing {
			return errors.New("output verification requires stored close")
		}
		if failedOutputVerificationAttempts(entries) >= maxSwarmOutputVerificationAttempts {
			return errors.New("output verification attempt limit exceeded")
		}
		storedClose, closeIndex, err := storedOutputClose(entries)
		if err != nil {
			return err
		}
		closeState, err := ReduceSwarmEntries(entries[:closeIndex])
		if err != nil {
			return err
		}
		if err := verifyJournalCloseV2(storedClose.Bytes, closeState, entries[:closeIndex]); err != nil {
			return err
		}
		close, finalOutput, err := storedOutputFinal(storedClose)
		if err != nil {
			return err
		}
		if _, err := readJournalOutputArtifact(journal, state, finalOutput); err != nil {
			return appendOutputFailure(journal, entries, state, frame.SubmissionDigest, c.currentTime(entries))
		}
		verified, err := c.verifyOutput(frame.Proof, verifier.FrozenSwarmOutputEvidence{SwarmID: state.Spec.SwarmID, PlanDigest: optionalString(close["plan_digest"]), ExecutionGraphDigest: optionalString(close["execution_graph_digest"]), StoredCloseDigest: storedClose.Digest, FinalOutput: finalOutput}, c.currentTime(entries))
		if err != nil || verified.VerificationID != outputVerificationID(frame.Proof) || verified.CloseDigest != storedClose.Digest || verified.ProofDigest != digestBytesHex(verified.ProofBytes) || verified.TrustInputsDigest != c.outputVerificationTrust.TrustInputsDigest || !bytes.Equal(verified.ProofBytes, proofBodyBytes(frame.Proof)) {
			return appendOutputFailure(journal, entries, state, frame.SubmissionDigest, c.currentTime(entries))
		}
		return appendOutputVerified(journal, entries, state, frame, storedClose, verified, c.currentTime(entries), &result)
	})
	if err != nil {
		return zero, err
	}
	return result, nil
}

func (c *LocalSwarmCoordinator) verifyOutput(proof map[string]any, frozen verifier.FrozenSwarmOutputEvidence, now time.Time) (verifier.VerifiedSwarmOutput, error) {
	verify := c.outputVerifier
	if verify == nil {
		verify = verifier.VerifySwarmOutputProof
	}
	return verify(proof, c.outputVerificationTrust, frozen, now)
}

func outputVerificationID(proof map[string]any) string {
	body, _ := proof["proof"].(map[string]any)
	return optionalString(body["verification_id"])
}

func proofBodyBytes(proof map[string]any) []byte {
	body, ok := proof["proof"].(map[string]any)
	if !ok {
		return nil
	}
	raw, err := canonicalJSON(body)
	if err != nil {
		return nil
	}
	return raw
}

func failedOutputVerificationAttempts(entries []SwarmJournalEntry) int {
	count := 0
	for _, entry := range entries {
		if entry.Kind == "output.verification_failed" {
			count++
		}
	}
	return count
}

func storedOutputClose(entries []SwarmJournalEntry) (StoredSwarmClose, int, error) {
	for index, entry := range entries {
		if entry.Kind != "close.stored" {
			continue
		}
		close, err := storedSwarmCloseFromEntry(entry)
		if err != nil {
			return StoredSwarmClose{}, 0, err
		}
		return close, index, nil
	}
	return StoredSwarmClose{}, 0, errors.New("stored swarm close missing")
}

func mustReduceBeforeClose(entries []SwarmJournalEntry, closeIndex int) SwarmState {
	state, err := ReduceSwarmEntries(entries[:closeIndex])
	if err != nil {
		return SwarmState{}
	}
	return state
}

func storedOutputFinal(stored StoredSwarmClose) (map[string]any, map[string]any, error) {
	var close map[string]any
	decoder := json.NewDecoder(bytes.NewReader(stored.Bytes))
	decoder.UseNumber()
	if err := decoder.Decode(&close); err != nil || ensureSwarmJSONEOF(decoder) != nil {
		return nil, nil, errors.New("stored output close invalid")
	}
	final, ok := close["final_output"].(map[string]any)
	if !ok {
		return nil, nil, errors.New("stored output close invalid")
	}
	canonical, err := canonicalJSON(final)
	if err != nil || len(canonical) > maxSwarmOutputVerificationRecordBytes {
		return nil, nil, errors.New("stored output close invalid")
	}
	return close, final, nil
}

func readJournalOutputArtifact(journal *SwarmJournal, state SwarmState, final map[string]any) ([]byte, error) {
	artifactMap, ok := final["artifact"].(map[string]any)
	if !ok {
		return nil, errors.New("stored final artifact invalid")
	}
	artifact := ArtifactTriple{URI: optionalString(artifactMap["uri"]), SHA256: optionalString(artifactMap["sha256"]), ManifestHash: optionalString(artifactMap["manifest_hash"])}
	if !validArtifactTriple(artifact) {
		return nil, errors.New("stored final artifact invalid")
	}
	committed := false
	for _, value := range state.CommittedArtifacts {
		if value == artifact {
			committed = true
			break
		}
	}
	if !committed {
		return nil, ErrArtifactNotCommitted
	}
	dir := filepath.Join(filepath.Dir(journal.Path), "objects")
	if err := validatePrivateDirectory(dir); err != nil {
		return nil, err
	}
	info, err := os.Stat(filepath.Join(dir, artifact.SHA256))
	if err != nil || info.Size() <= 0 || uint64(info.Size()) > math.MaxUint64 {
		return nil, errors.New("stored final artifact unavailable")
	}
	return readStagedArtifact(journal, StagedArtifact{SHA256: artifact.SHA256, Size: uint64(info.Size()), Path: filepath.Join(dir, artifact.SHA256)})
}

func appendOutputFailure(journal *SwarmJournal, entries []SwarmJournalEntry, state SwarmState, submissionDigest string, now time.Time) error {
	payload := outputVerificationFailurePayload{SchemaVersion: swarmStateSchemaVersion, SubmissionDigest: submissionDigest, ErrorCode: "output_proof_rejected"}
	if err := appendOutputEvent(journal, entries, state, "output.verification_failed", payload, now); err != nil {
		return err
	}
	return errOutputProofRejected
}

func appendOutputVerified(journal *SwarmJournal, entries []SwarmJournalEntry, state SwarmState, frame parsedOutputVerificationFrame, stored StoredSwarmClose, verified verifier.VerifiedSwarmOutput, now time.Time, out *OutputVerificationAttempt) error {
	finalRaw, err := canonicalJSON(verified.FinalOutput)
	if err != nil || len(finalRaw) == 0 || len(finalRaw) > maxSwarmOutputVerificationRecordBytes {
		return errors.New("verified final output invalid")
	}
	completedAt, err := canonicalSwarmTimestamp(now)
	if err != nil {
		return err
	}
	payload := outputVerifiedPayload{SchemaVersion: swarmStateSchemaVersion, SwarmID: state.Spec.SwarmID, VerificationID: verified.VerificationID, SubmissionDigest: frame.SubmissionDigest, Proof: base64.RawURLEncoding.EncodeToString(frame.ProofBytes), CanonicalProofDigest: digestBytesHex(frame.ProofBytes), ProofDigest: verified.ProofDigest, Close: base64.RawURLEncoding.EncodeToString(stored.Bytes), CloseDigest: stored.Digest, TrustInputsDigest: verified.TrustInputsDigest, FinalOutput: finalRaw, VerifiedAt: verified.VerifiedAt, VerifierAID: verified.VerifierAID, VerifierZone: verified.VerifierZone, PriorStatus: state.Status, NextStatus: SwarmStatusCompleted, ReplayDecision: "accepted", CompletedAt: completedAt}
	key, err := pinnedCloseAuthorityKey(state.Spec)
	if err != nil {
		return errors.New("output completion authority unavailable")
	}
	defer clear(key)
	signed := signBodyWithKey(key, outputVerifiedPayloadBody(payload), "completion_signature")
	payload.CompletionSignature, _ = signed["completion_signature"].(string)
	if !validOutputVerifiedPayload(payload) {
		return errors.New("verified output payload invalid")
	}
	if err := appendOutputEvent(journal, entries, state, "output.verified", payload, now); err != nil {
		return err
	}
	var final map[string]any
	if err := json.Unmarshal(finalRaw, &final); err != nil {
		return err
	}
	*out = OutputVerificationAttempt{SwarmID: state.Spec.SwarmID, VerificationID: verified.VerificationID, Decision: "accepted", ProofDigest: verified.ProofDigest, CloseDigest: stored.Digest, TrustInputsDigest: verified.TrustInputsDigest, VerifiedAt: verified.VerifiedAt, FinalOutput: final}
	return nil
}

func appendOutputEvent(journal *SwarmJournal, entries []SwarmJournalEntry, state SwarmState, kind string, payload any, now time.Time) error {
	if state.Version == math.MaxUint64 || len(entries) == 0 {
		return errors.New("output verification state invalid")
	}
	if err := swarmMutationAllowed(state); err != nil {
		return err
	}
	encoded, err := canonicalSwarmPayload(payload)
	if err != nil || len(encoded) > maxSwarmOutputVerificationRecordBytes {
		return errors.New("output verification record invalid")
	}
	stamp, err := canonicalSwarmTimestamp(now)
	if err != nil {
		return err
	}
	entry := SwarmJournalEntry{Format: swarmJournalFormat, Sequence: uint64(len(entries) + 1), PriorStateVersion: state.Version, StateVersion: state.Version + 1, Kind: kind, Payload: encoded, Timestamp: stamp, PrevHash: entries[len(entries)-1].Hash}
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
	return journal.appendLocked(entry)
}

func storedOutputVerification(entries []SwarmJournalEntry) (outputVerifiedPayload, bool, error) {
	for _, entry := range entries {
		if entry.Kind != "output.verified" {
			continue
		}
		var payload outputVerifiedPayload
		if err := decodeStrictSwarmPayload(entry.Payload, &payload); err != nil || !validOutputVerifiedPayload(payload) {
			return outputVerifiedPayload{}, false, errors.New("stored output verification invalid")
		}
		return payload, true, nil
	}
	return outputVerifiedPayload{}, false, nil
}

func outputAttemptFromVerified(swarmID string, payload outputVerifiedPayload, decision string) (OutputVerificationAttempt, error) {
	var final map[string]any
	if err := json.Unmarshal(payload.FinalOutput, &final); err != nil {
		return OutputVerificationAttempt{}, errors.New("stored output verification invalid")
	}
	return OutputVerificationAttempt{SwarmID: swarmID, VerificationID: payload.VerificationID, Decision: decision, ProofDigest: payload.ProofDigest, CloseDigest: payload.CloseDigest, TrustInputsDigest: payload.TrustInputsDigest, VerifiedAt: payload.VerifiedAt, FinalOutput: final}, nil
}

func validOutputVerificationID(value string) bool {
	return value != "" && len(value) <= 256 && !hasSwarmDelimiter(value)
}

func validOutputVerifiedPayload(payload outputVerifiedPayload) bool {
	if payload.SchemaVersion != swarmStateSchemaVersion || payload.SwarmID == "" || hasSwarmDelimiter(payload.SwarmID) || !validOutputVerificationID(payload.VerificationID) || !isHexDigest(payload.SubmissionDigest) || payload.Proof == "" || payload.Close == "" || !isHexDigest(payload.CanonicalProofDigest) || !isHexDigest(payload.ProofDigest) || !isHexDigest(payload.CloseDigest) || !isHexDigest(payload.TrustInputsDigest) || payload.VerifiedAt == "" || payload.VerifierAID == "" || payload.VerifierZone == "" || payload.PriorStatus != SwarmStatusClosing || payload.NextStatus != SwarmStatusCompleted || payload.ReplayDecision != "accepted" || len(payload.FinalOutput) == 0 || len(payload.FinalOutput) > maxSwarmOutputVerificationRecordBytes {
		return false
	}
	if _, err := parseCanonicalSwarmTimestamp(payload.CompletedAt); err != nil {
		return false
	}
	signature, err := base64.RawURLEncoding.DecodeString(payload.CompletionSignature)
	if err != nil || base64.RawURLEncoding.EncodeToString(signature) != payload.CompletionSignature || len(signature) != ed25519.SignatureSize {
		return false
	}
	proof, err := base64.RawURLEncoding.DecodeString(payload.Proof)
	if err != nil || base64.RawURLEncoding.EncodeToString(proof) != payload.Proof || len(proof) > maxSwarmOutputVerificationProofBytes || digestBytesHex(proof) != payload.CanonicalProofDigest {
		return false
	}
	close, err := base64.RawURLEncoding.DecodeString(payload.Close)
	if err != nil || base64.RawURLEncoding.EncodeToString(close) != payload.Close || digestBytesHex(close) != payload.CloseDigest {
		return false
	}
	var final map[string]any
	if !json.Valid(payload.FinalOutput) || json.Unmarshal(payload.FinalOutput, &final) != nil {
		return false
	}
	canonical, err := canonicalJSON(final)
	return err == nil && bytes.Equal(canonical, payload.FinalOutput)
}

// outputVerifiedPayloadBody is intentionally the sole signing preimage. It includes
// every completion claim and excludes only the detached completion signature itself.
func outputVerifiedPayloadBody(payload outputVerifiedPayload) map[string]any {
	return map[string]any{
		"schema_version":         payload.SchemaVersion,
		"swarm_id":               payload.SwarmID,
		"verification_id":        payload.VerificationID,
		"canonical_proof_digest": payload.CanonicalProofDigest,
		"submission_digest":      payload.SubmissionDigest,
		"proof":                  payload.Proof,
		"proof_digest":           payload.ProofDigest,
		"close":                  payload.Close,
		"close_digest":           payload.CloseDigest,
		"trust_inputs_digest":    payload.TrustInputsDigest,
		"final_output":           payload.FinalOutput,
		"verified_at":            payload.VerifiedAt,
		"verifier_aid":           payload.VerifierAID,
		"verifier_zone":          payload.VerifierZone,
		"prior_status":           payload.PriorStatus,
		"next_status":            payload.NextStatus,
		"replay_decision":        payload.ReplayDecision,
		"completed_at":           payload.CompletedAt,
	}
}

// verifyOutputVerifiedCompletionAuthorization is pure: it validates against only
// the frozen local-authority descriptor carried by the durable seed.
func verifyOutputVerifiedCompletionAuthorization(spec DurableSwarmSpec, payload outputVerifiedPayload) error {
	if len(spec.LocalAuthority) == 0 || verifyZoneDescriptor(spec.LocalAuthority) != nil {
		return errors.New("output completion authority invalid")
	}
	key, _, err := publicKey(spec.LocalAuthority)
	if err != nil {
		return errors.New("output completion authority invalid")
	}
	signed := outputVerifiedPayloadBody(payload)
	signed["completion_signature"] = payload.CompletionSignature
	if err := verifyMapSignature(key, signed, "completion_signature"); err != nil {
		return errors.New("output completion signature invalid")
	}
	return nil
}

func normalizeOutputVerificationError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("output verification rejected")
}
