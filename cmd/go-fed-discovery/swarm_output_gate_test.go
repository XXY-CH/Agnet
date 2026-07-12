package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"

	"agnet/verifier"
	"testing"
	"time"
)

func outputGateFrame(t *testing.T, swarmID, proof string) []byte {
	t.Helper()
	raw, err := canonicalJSON(map[string]any{
		"type":     swarmOutputVerificationFrameType,
		"swarm_id": swarmID,
		"proof":    map[string]any{"proof": proof},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func unsignedOutputVerifiedPayload(t *testing.T, swarmID string, stored StoredSwarmClose, final map[string]any) outputVerifiedPayload {
	t.Helper()
	proof, err := canonicalJSON(map[string]any{"proof": map[string]any{"verification_id": "forged-proof"}})
	if err != nil {
		t.Fatal(err)
	}
	finalRaw, err := canonicalJSON(final)
	if err != nil {
		t.Fatal(err)
	}
	return outputVerifiedPayload{
		SchemaVersion:        swarmStateSchemaVersion,
		SwarmID:              swarmID,
		VerificationID:       "forged-proof",
		SubmissionDigest:     strings.Repeat("a", 64),
		Proof:                base64.RawURLEncoding.EncodeToString(proof),
		CanonicalProofDigest: digestBytesHex(proof),
		ProofDigest:          strings.Repeat("b", 64),
		Close:                base64.RawURLEncoding.EncodeToString(stored.Bytes),
		CloseDigest:          stored.Digest,
		TrustInputsDigest:    strings.Repeat("c", 64),
		FinalOutput:          finalRaw,
		VerifiedAt:           "2026-07-11T12:00:00Z",
		VerifierAID:          "agent://trusted/verifier",
		VerifierZone:         "zone://trusted/verifier",
		PriorStatus:          SwarmStatusClosing,
		NextStatus:           SwarmStatusCompleted,
		ReplayDecision:       "accepted",
		CompletedAt:          swarmJournalTestTime.UTC().Format(time.RFC3339Nano),
	}
}

func signedOutputVerifiedPayload(t *testing.T, spec DurableSwarmSpec, payload outputVerifiedPayload) outputVerifiedPayload {
	t.Helper()
	key, err := pinnedCloseAuthorityKey(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	signed := signBodyWithKey(key, outputVerifiedPayloadBody(payload), "completion_signature")
	payload.CompletionSignature, _ = signed["completion_signature"].(string)
	return payload
}

func appendForgedOutputVerified(t *testing.T, journal *SwarmJournal, payload outputVerifiedPayload) {
	t.Helper()
	if err := journal.WithLockedReplay(func(entries []SwarmJournalEntry) error {
		state, err := ReduceSwarmEntries(entries)
		if err != nil {
			return err
		}
		encoded, err := canonicalSwarmPayload(payload)
		if err != nil {
			return err
		}
		entry := SwarmJournalEntry{Format: swarmJournalFormat, Sequence: uint64(len(entries) + 1), PriorStateVersion: state.Version, StateVersion: state.Version + 1, Kind: "output.verified", Payload: encoded, Timestamp: swarmJournalTestTime.Add(time.Minute).UTC().Format(time.RFC3339Nano), PrevHash: entries[len(entries)-1].Hash}
		entry.Hash, err = swarmJournalEntryHash(entry)
		if err != nil {
			return err
		}
		return journal.appendLocked(entry)
	}); err != nil {
		t.Fatal(err)
	}
}

func TestOutputVerifiedRequiresLocalCompletionAuthorization(t *testing.T) {
	journal, spec := newCloseTestJournal(t)
	commitCloseTestJournal(t, journal, spec, false)
	stored, err := EnsureStableClose(journal)
	if err != nil {
		t.Fatal(err)
	}
	_, final, err := storedOutputFinal(stored)
	if err != nil {
		t.Fatal(err)
	}
	entries := mustReplaySwarm(t, journal)
	state, err := ReduceSwarmEntries(entries)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := unsignedOutputVerifiedPayload(t, spec.SwarmID, stored, final)
	completedAt := swarmJournalTestTime.Add(time.Minute).UTC().Format(time.RFC3339Nano)
	unsigned.CompletedAt = completedAt
	valid := signedOutputVerifiedPayload(t, spec, unsigned)
	if _, err := ReduceSwarmEntry(state, reducerTestTimedEntry(t, "output.verified", valid, state.Version, state.Version+1, completedAt)); err != nil {
		t.Fatalf("ReduceSwarmEntry rejected pinned local authorization: %v", err)
	}
	arbitrary := valid
	arbitrary.CompletionSignature = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	wrongKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
	wrongKeySigned := valid
	wrongSignature := signBodyWithKey(wrongKey, outputVerifiedPayloadBody(wrongKeySigned), "completion_signature")
	wrongKeySigned.CompletionSignature, _ = wrongSignature["completion_signature"].(string)
	clear(wrongKey)
	mutated := valid
	mutated.SubmissionDigest = strings.Repeat("d", 64)
	for name, payload := range map[string]outputVerifiedPayload{"missing": unsigned, "arbitrary": arbitrary, "wrong-key": wrongKeySigned, "mutated": mutated} {
		entry := reducerTestTimedEntry(t, "output.verified", payload, state.Version, state.Version+1, swarmJournalTestTime.Add(time.Minute).UTC().Format(time.RFC3339Nano))
		if _, err := ReduceSwarmEntry(state, entry); err == nil {
			t.Fatalf("ReduceSwarmEntry accepted %s output.verified signature", name)
		}
	}
	before := len(entries)
	if _, err := journal.Append("output.verified", unsigned, state.Version, state.Version+1, swarmJournalTestTime.Add(time.Minute)); err == nil {
		t.Fatal("SwarmJournal.Append accepted an unsigned output.verified payload")
	}
	if after := len(mustReplaySwarm(t, journal)); after != before {
		t.Fatalf("forged append mutated journal: before=%d after=%d", before, after)
	}

	forgedJournal, forgedSpec := newCloseTestJournal(t)
	commitCloseTestJournal(t, forgedJournal, forgedSpec, false)
	forgedStored, err := EnsureStableClose(forgedJournal)
	if err != nil {
		t.Fatal(err)
	}
	_, forgedFinal, err := storedOutputFinal(forgedStored)
	if err != nil {
		t.Fatal(err)
	}
	appendForgedOutputVerified(t, forgedJournal, unsignedOutputVerifiedPayload(t, forgedSpec.SwarmID, forgedStored, forgedFinal))
	if _, err := forgedJournal.Replay(); err == nil {
		t.Fatal("Replay accepted a valid-hash forged output.verified record")
	}
	storageRoot := filepath.Dir(filepath.Dir(forgedJournal.Path))
	if _, err := OpenSwarmJournal(storageRoot, forgedSpec.SwarmID); err == nil {
		t.Fatal("OpenSwarmJournal reopened a valid-hash forged output.verified record")
	}
	coordinator, err := NewLocalSwarmCoordinator(Fixture{}, storageRoot, "output-gate-replay", nil, func() time.Time { return swarmJournalTestTime })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.ResumeAll(context.Background()); err == nil {
		t.Fatal("ResumeAll accepted a valid-hash forged output.verified record")
	}
}

func TestRecordOutputVerificationAuditsRepeatedInvalidProofs(t *testing.T) {
	journal, spec := newCloseTestJournal(t)
	commitCloseTestJournal(t, journal, spec, false)
	if _, err := EnsureStableClose(journal); err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewLocalSwarmCoordinator(Fixture{}, filepath.Dir(filepath.Dir(journal.Path)), "output-gate", nil, func() time.Time { return swarmJournalTestTime })
	if err != nil {
		t.Fatal(err)
	}
	frame := outputGateFrame(t, spec.SwarmID, "invalid")
	for range 2 {
		if _, err := coordinator.RecordOutputVerification(context.Background(), frame); err == nil {
			t.Fatal("invalid proof unexpectedly completed swarm")
		}
	}
	entries := mustReplaySwarm(t, journal)
	failures := 0
	for _, entry := range entries {
		if entry.Kind != "output.verification_failed" {
			continue
		}
		failures++
		var payload outputVerificationFailurePayload
		if err := decodeStrictSwarmPayload(entry.Payload, &payload); err != nil {
			t.Fatal(err)
		}
		if payload.ErrorCode != "output_proof_rejected" {
			t.Fatalf("unsafe failure payload: %#v", payload)
		}
	}
	if failures != 2 {
		t.Fatalf("failed attempts = %d, want 2", failures)
	}
	state, err := ReduceSwarmEntries(entries)
	if err != nil || state.Status != SwarmStatusClosing {
		t.Fatalf("invalid proof changed closing state: %#v, %v", state, err)
	}
}

func TestParseOutputVerificationFrameRejectsPathsAndOversize(t *testing.T) {
	badPath := []byte(`{"type":"FED_SWARM_OUTPUT_VERIFY","swarm_id":"swarm://gate","proof":{"path":"/tmp/proof"}}`)
	if _, err := parseOutputVerificationFrame(badPath); err == nil {
		t.Fatal("path-bearing frame accepted")
	}
	over := make([]byte, maxSwarmOutputVerificationFrameBytes+1)
	if _, err := parseOutputVerificationFrame(over); err == nil {
		t.Fatal("oversize frame accepted")
	}
}

func TestOutputVerificationFrameProofIsCanonicalizedWithoutCallerClose(t *testing.T) {
	frame := outputGateFrame(t, "swarm://gate", "x")
	parsed, err := parseOutputVerificationFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.SwarmID != "swarm://gate" || len(parsed.ProofBytes) == 0 {
		t.Fatalf("parsed = %#v", parsed)
	}
	var proof map[string]any
	if err := json.Unmarshal(parsed.ProofBytes, &proof); err != nil || proof["proof"] != "x" {
		t.Fatalf("proof bytes = %s, %v", parsed.ProofBytes, err)
	}
}

func TestRecordOutputVerificationCompletesAndReplaysExactSubmission(t *testing.T) {
	journal, spec := newCloseTestJournal(t)
	commitCloseTestJournal(t, journal, spec, false)
	stored, err := EnsureStableClose(journal)
	if err != nil {
		t.Fatal(err)
	}
	_, final, err := storedOutputFinal(stored)
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewLocalSwarmCoordinator(Fixture{}, filepath.Dir(filepath.Dir(journal.Path)), "output-gate", nil, func() time.Time { return swarmJournalTestTime })
	if err != nil {
		t.Fatal(err)
	}
	coordinator.outputVerificationTrust = verifier.TrustInputs{TrustInputsDigest: strings.Repeat("b", 64)}
	frame, err := canonicalJSON(map[string]any{"type": swarmOutputVerificationFrameType, "swarm_id": spec.SwarmID, "proof": map[string]any{"proof": map[string]any{"verification_id": "proof-1"}}})
	if err != nil {
		t.Fatal(err)
	}
	coordinator.outputVerifier = func(proof map[string]any, _ verifier.TrustInputs, frozen verifier.FrozenSwarmOutputEvidence, _ time.Time) (verifier.VerifiedSwarmOutput, error) {
		return verifier.VerifiedSwarmOutput{CloseDigest: frozen.StoredCloseDigest, ProofDigest: digestBytesHex(proofBodyBytes(proof)), TrustInputsDigest: strings.Repeat("b", 64), ProofBytes: proofBodyBytes(proof), FinalOutput: final, VerificationID: "proof-1", VerifiedAt: "2026-07-11T12:00:00Z", VerifierAID: "agent://trusted/verifier", VerifierZone: "zone://trusted/verifier"}, nil
	}
	accepted, err := coordinator.RecordOutputVerification(context.Background(), frame)
	if err != nil || accepted.Decision != "accepted" {
		t.Fatalf("accepted = %#v, %v", accepted, err)
	}
	replayed, err := coordinator.RecordOutputVerification(context.Background(), frame)
	if err != nil || replayed.Decision != "idempotent" || replayed.VerificationID != accepted.VerificationID {
		t.Fatalf("replayed = %#v, %v", replayed, err)
	}
	changed := append([]byte(nil), frame...)
	changed[len(changed)-1] = ' '
	if _, err := coordinator.RecordOutputVerification(context.Background(), changed); err == nil {
		t.Fatal("changed submission replay accepted")
	}
	entries := mustReplaySwarm(t, journal)
	verified := 0
	for _, entry := range entries {
		if entry.Kind == "output.verified" {
			verified++
		}
	}
	if verified != 1 {
		t.Fatalf("verified entries = %d, want 1", verified)
	}
	state, err := ReduceSwarmEntries(entries)
	if err != nil || state.Status != SwarmStatusCompleted || state.OutputVerification == nil {
		t.Fatalf("completed state = %#v, %v", state, err)
	}
}

func TestRecordOutputVerificationStopsAppendingAfterAttemptCap(t *testing.T) {
	journal, spec := newCloseTestJournal(t)
	commitCloseTestJournal(t, journal, spec, false)
	if _, err := EnsureStableClose(journal); err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewLocalSwarmCoordinator(Fixture{}, filepath.Dir(filepath.Dir(journal.Path)), "output-gate", nil, func() time.Time { return swarmJournalTestTime })
	if err != nil {
		t.Fatal(err)
	}
	frame := outputGateFrame(t, spec.SwarmID, "invalid")
	for range maxSwarmOutputVerificationAttempts {
		if _, err := coordinator.RecordOutputVerification(context.Background(), frame); err == nil {
			t.Fatal("invalid proof unexpectedly accepted")
		}
	}
	before := len(mustReplaySwarm(t, journal))
	if _, err := coordinator.RecordOutputVerification(context.Background(), frame); err == nil {
		t.Fatal("attempt beyond cap unexpectedly accepted")
	}
	if after := len(mustReplaySwarm(t, journal)); after != before {
		t.Fatalf("attempt cap appended event: before=%d after=%d", before, after)
	}
}

func TestRecordOutputVerificationRejectsChangedFrozenTrustInputs(t *testing.T) {
	journal, spec := newCloseTestJournal(t)
	commitCloseTestJournal(t, journal, spec, false)
	stored, err := EnsureStableClose(journal)
	if err != nil {
		t.Fatal(err)
	}
	_, final, err := storedOutputFinal(stored)
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewLocalSwarmCoordinator(Fixture{}, filepath.Dir(filepath.Dir(journal.Path)), "output-gate", nil, func() time.Time { return swarmJournalTestTime })
	if err != nil {
		t.Fatal(err)
	}
	coordinator.outputVerificationTrust = verifier.TrustInputs{TrustInputsDigest: strings.Repeat("b", 64)}
	coordinator.outputVerifier = func(proof map[string]any, _ verifier.TrustInputs, frozen verifier.FrozenSwarmOutputEvidence, _ time.Time) (verifier.VerifiedSwarmOutput, error) {
		return verifier.VerifiedSwarmOutput{CloseDigest: frozen.StoredCloseDigest, ProofDigest: digestBytesHex(proofBodyBytes(proof)), TrustInputsDigest: strings.Repeat("c", 64), ProofBytes: proofBodyBytes(proof), FinalOutput: final, VerificationID: outputVerificationID(proof), VerifiedAt: "2026-07-11T12:00:00Z", VerifierAID: "agent://trusted/verifier", VerifierZone: "zone://trusted/verifier"}, nil
	}
	frame, err := canonicalJSON(map[string]any{"type": swarmOutputVerificationFrameType, "swarm_id": spec.SwarmID, "proof": map[string]any{"proof": map[string]any{"verification_id": "proof-1"}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.RecordOutputVerification(context.Background(), frame); !errors.Is(err, errOutputProofRejected) {
		t.Fatalf("error = %v, want normalized trust rejection", err)
	}
	state, err := ReduceSwarmEntries(mustReplaySwarm(t, journal))
	if err != nil || state.Status != SwarmStatusClosing {
		t.Fatalf("state = %#v, %v", state, err)
	}
}

func TestRecordOutputVerificationRetriesExactlyAfterSyncedResponseLoss(t *testing.T) {
	journal, spec := newCloseTestJournal(t)
	commitCloseTestJournal(t, journal, spec, false)
	stored, err := EnsureStableClose(journal)
	if err != nil {
		t.Fatal(err)
	}
	_, final, err := storedOutputFinal(stored)
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewLocalSwarmCoordinator(Fixture{}, filepath.Dir(filepath.Dir(journal.Path)), "output-gate", nil, func() time.Time { return swarmJournalTestTime })
	if err != nil {
		t.Fatal(err)
	}
	coordinator.outputVerificationTrust = verifier.TrustInputs{TrustInputsDigest: strings.Repeat("b", 64)}
	coordinator.outputVerifier = func(proof map[string]any, _ verifier.TrustInputs, frozen verifier.FrozenSwarmOutputEvidence, _ time.Time) (verifier.VerifiedSwarmOutput, error) {
		return verifier.VerifiedSwarmOutput{CloseDigest: frozen.StoredCloseDigest, ProofDigest: digestBytesHex(proofBodyBytes(proof)), TrustInputsDigest: strings.Repeat("b", 64), ProofBytes: proofBodyBytes(proof), FinalOutput: final, VerificationID: outputVerificationID(proof), VerifiedAt: "2026-07-11T12:00:00Z", VerifierAID: "agent://trusted/verifier", VerifierZone: "zone://trusted/verifier"}, nil
	}
	frame, err := canonicalJSON(map[string]any{"type": swarmOutputVerificationFrameType, "swarm_id": spec.SwarmID, "proof": map[string]any{"proof": map[string]any{"verification_id": "proof-1"}}})
	if err != nil {
		t.Fatal(err)
	}
	responseLoss := errors.New("response lost after synced append")
	fired := false
	journal.fault = func(point SwarmFaultPoint) error {
		if point == SwarmFaultParentSync && !fired {
			fired = true
			return responseLoss
		}
		return nil
	}
	parsed, err := parseOutputVerificationFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.WithLockedReplay(func(entries []SwarmJournalEntry) error {
		state, err := ReduceSwarmEntries(entries)
		if err != nil {
			return err
		}
		verified := verifier.VerifiedSwarmOutput{CloseDigest: stored.Digest, ProofDigest: digestBytesHex(proofBodyBytes(parsed.Proof)), TrustInputsDigest: strings.Repeat("b", 64), ProofBytes: proofBodyBytes(parsed.Proof), FinalOutput: final, VerificationID: outputVerificationID(parsed.Proof), VerifiedAt: "2026-07-11T12:00:00Z", VerifierAID: "agent://trusted/verifier", VerifierZone: "zone://trusted/verifier"}
		return appendOutputVerified(journal, entries, state, parsed, stored, verified, swarmJournalTestTime, &OutputVerificationAttempt{})
	}); !errors.Is(err, responseLoss) {
		t.Fatalf("synced append error = %v, want response loss", err)
	}
	journal.fault = nil
	replayed, err := coordinator.RecordOutputVerification(context.Background(), frame)
	if err != nil || replayed.Decision != "idempotent" {
		t.Fatalf("exact retry = %#v, %v", replayed, err)
	}
	entries := mustReplaySwarm(t, journal)
	verified := 0
	for _, entry := range entries {
		if entry.Kind == "output.verified" {
			verified++
		}
	}
	if verified != 1 {
		t.Fatalf("output verification entries = %d, want 1", verified)
	}
}
