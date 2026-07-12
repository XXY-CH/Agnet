package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"agnet/verifier"
)

func TestU28DisbandIsSignedStableAndTerminal(t *testing.T) {
	journal, spec := newCloseTestJournal(t)
	completeDisbandTestJournal(t, journal, spec)

	candidate, err := BuildSwarmDisband(journal)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySwarmDisband(candidate.Bytes, journal); err != nil {
		t.Fatalf("VerifySwarmDisband() = %v", err)
	}
	stored, err := EnsureDisband(journal)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored.Bytes, candidate.Bytes) || stored.Digest != candidate.Digest {
		t.Fatalf("stored disband differs: %#v", stored)
	}
	retry, err := EnsureDisband(journal)
	if err != nil || !bytes.Equal(retry.Bytes, stored.Bytes) {
		t.Fatalf("disband retry = %#v, %v", retry, err)
	}
	entries := mustReplaySwarm(t, journal)
	disbanded := 0
	for _, entry := range entries {
		if entry.Kind == "swarm.disbanded" {
			disbanded++
		}
	}
	if disbanded != 1 {
		t.Fatalf("disband events = %d", disbanded)
	}
	state, err := ReduceSwarmEntries(entries)
	if err != nil || state.Status != SwarmStatusDisbanded {
		t.Fatalf("disbanded state = %#v, %v", state, err)
	}
	if _, _, err := RecordNextReadyWave(journal, swarmJournalTestTime.Add(2*time.Hour)); err == nil {
		t.Fatal("post-disband mutator was accepted")
	}
	if _, err := StageArtifact(journal, []byte("post-disband")); err == nil {
		t.Fatal("post-disband artifact staging was accepted")
	}
	if _, err := ReadSwarmView(journal); err != nil {
		t.Fatalf("read-only view failed after disband: %v", err)
	}
}

func TestU28DisbandRequiresCompletedVerifiedOutput(t *testing.T) {
	journal, _ := newCloseTestJournal(t)
	if _, err := BuildSwarmDisband(journal); err == nil {
		t.Fatal("disband accepted an incomplete swarm")
	}
}

func TestU28DisbandRejectsEveryMutationAndProjectsRawRecord(t *testing.T) {
	journal, spec := newCloseTestJournal(t)
	completeDisbandTestJournal(t, journal, spec)
	view, err := ReadSwarmView(journal)
	if err != nil { t.Fatal(err) }
	frames, err := durableSwarmResponseFrames(journal, view)
	if err != nil { t.Fatal(err) }
	stored, err := EnsureDisband(journal)
	if err != nil { t.Fatal(err) }
	disbandFrames := 0
	for _, frame := range frames {
		if frame["type"] != "FED_SWARM_DISBAND" { continue }
		disbandFrames++
		raw, ok := frame["disband"].(json.RawMessage)
		if !ok || !bytes.Equal(raw, stored.Bytes) { t.Fatalf("disband projection = %#v", frame) }
	}
	if disbandFrames != 1 { t.Fatalf("disband projection count = %d", disbandFrames) }
	assertDisbanded := func(name string, err error) {
		t.Helper()
		if !errors.Is(err, ErrSwarmDisbanded) { t.Fatalf("%s error = %v", name, err) }
	}
	_, openErr := OpenVerifiedSwarm(journal, spec, swarmJournalTestTime.Add(2*time.Hour))
	assertDisbanded("open", openErr)
	_, _, readyErr := RecordNextReadyWave(journal, swarmJournalTestTime.Add(2*time.Hour))
	assertDisbanded("ready", readyErr)
	_, claimErr := ClaimReadyWave(journal, "owner", swarmJournalTestTime.Add(3*time.Hour), swarmJournalTestTime.Add(2*time.Hour))
	assertDisbanded("claim", claimErr)
	_, renewErr := RenewLease(journal, "step", "owner", 1, swarmJournalTestTime.Add(3*time.Hour), swarmJournalTestTime.Add(2*time.Hour))
	assertDisbanded("renew", renewErr)
	observeErr := RecordLeaseObservation(journal, LeaseClaim{StepID: "step", Owner: "owner", Fence: 1, Attempt: 1, Deadline: swarmJournalTestTime.Add(3*time.Hour).Format(time.RFC3339Nano)}, "observed", swarmJournalTestTime.Add(2*time.Hour))
	assertDisbanded("observe", observeErr)
	_, expireErr := ExpireLeases(journal, swarmJournalTestTime.Add(2*time.Hour))
	assertDisbanded("expire", expireErr)
	_, stageErr := StageArtifact(journal, []byte("blocked"))
	assertDisbanded("stage", stageErr)
	_, closeErr := EnsureStableClose(journal)
	assertDisbanded("close", closeErr)
	_, appendErr := journal.Append("future.audit", map[string]any{"event":"blocked"}, view.Version, view.Version+1, swarmJournalTestTime.Add(2*time.Hour))
	assertDisbanded("append", appendErr)
	coordinator, err := NewLocalSwarmCoordinator(Fixture{}, filepath.Dir(filepath.Dir(journal.Path)), "disband-proof", nil, func() time.Time { return swarmJournalTestTime })
	if err != nil { t.Fatal(err) }
	frame, err := canonicalJSON(map[string]any{"type": swarmOutputVerificationFrameType, "swarm_id": spec.SwarmID, "proof": map[string]any{"proof": map[string]any{"verification_id": "post-disband"}}})
	if err != nil { t.Fatal(err) }
	_, proofErr := coordinator.RecordOutputVerification(context.Background(), frame)
	assertDisbanded("proof", proofErr)
	for _, entry := range mustReplaySwarm(t, journal) {
		if entry.Kind != "receipt.committed" { continue }
		var payload receiptCommittedPayload
		if err := decodeStrictSwarmPayload(entry.Payload, &payload); err != nil { t.Fatal(err) }
		raw, err := base64.RawURLEncoding.DecodeString(payload.Receipt)
		if err != nil { t.Fatal(err) }
		path := filepath.Join(filepath.Dir(journal.Path), "objects", payload.Result.SHA256)
		info, err := os.Stat(path)
		if err != nil { t.Fatal(err) }
		_, commitErr := CommitReceipt(journal, ReceiptCommit{Claim: payload.Claim, Receipt: StagedReceipt{Bytes: raw, Digest: payload.ReceiptDigest}, Result: StagedArtifact{SHA256: payload.Result.SHA256, Size: uint64(info.Size()), Path: path}}, swarmJournalTestTime.Add(2*time.Hour))
		assertDisbanded("commit", commitErr)
		break
	}
}

func TestU28DisbandRejectsValidHashForgedReplay(t *testing.T) {
	journal, spec := newCloseTestJournal(t)
	completeDisbandTestJournal(t, journal, spec)
	candidate, err := BuildSwarmDisband(journal)
	if err != nil { t.Fatal(err) }
	var forged swarmDisbandWire
	if err := json.Unmarshal(candidate.Bytes, &forged); err != nil { t.Fatal(err) }
	forged.PlanDigest = strings.Repeat("f", 64)
	key, err := pinnedCloseAuthorityKey(spec)
	if err != nil { t.Fatal(err) }
	signed := signBodyWithKey(key, swarmDisbandBody(forged), "disband_signature")
	clear(key)
	forged.DisbandSignature, _ = signed["disband_signature"].(string)
	raw, err := canonicalJSON(forged)
	if err != nil { t.Fatal(err) }
	if err := journal.WithLockedReplay(func(entries []SwarmJournalEntry) error {
		state, err := ReduceSwarmEntries(entries)
		if err != nil { return err }
		payload, err := canonicalSwarmPayload(swarmDisbandStoredPayload{SchemaVersion: swarmStateSchemaVersion, Disband: base64.RawURLEncoding.EncodeToString(raw), Digest: digestBytesHex(raw)})
		if err != nil { return err }
		entry := SwarmJournalEntry{Format: swarmJournalFormat, Sequence: uint64(len(entries)+1), PriorStateVersion: state.Version, StateVersion: state.Version+1, Kind: "swarm.disbanded", Payload: payload, Timestamp: state.OutputVerification.CompletedAt, PrevHash: entries[len(entries)-1].Hash}
		entry.Hash, err = swarmJournalEntryHash(entry)
		if err != nil { return err }
		return journal.appendLocked(entry)
	}); err != nil { t.Fatal(err) }
	if _, err := journal.Replay(); err == nil { t.Fatal("replay accepted forged disband with valid journal hash") }
}

func completeDisbandTestJournal(t *testing.T, journal *SwarmJournal, spec DurableSwarmSpec) {
	t.Helper()
	commitCloseTestJournal(t, journal, spec, false)
	stored, err := EnsureStableClose(journal)
	if err != nil {
		t.Fatal(err)
	}
	_, final, err := storedOutputFinal(stored)
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewLocalSwarmCoordinator(Fixture{}, filepath.Dir(filepath.Dir(journal.Path)), "disband-test", nil, func() time.Time { return swarmJournalTestTime })
	if err != nil {
		t.Fatal(err)
	}
	coordinator.outputVerificationTrust = verifier.TrustInputs{TrustInputsDigest: strings.Repeat("b", 64)}
	coordinator.outputVerifier = func(proof map[string]any, _ verifier.TrustInputs, frozen verifier.FrozenSwarmOutputEvidence, _ time.Time) (verifier.VerifiedSwarmOutput, error) {
		return verifier.VerifiedSwarmOutput{CloseDigest: frozen.StoredCloseDigest, ProofDigest: digestBytesHex(proofBodyBytes(proof)), TrustInputsDigest: strings.Repeat("b", 64), ProofBytes: proofBodyBytes(proof), FinalOutput: final, VerificationID: outputVerificationID(proof), VerifiedAt: "2026-07-11T12:00:00Z", VerifierAID: "agent://trusted/verifier", VerifierZone: "zone://trusted/verifier"}, nil
	}
	frame, err := canonicalJSON(map[string]any{"type": swarmOutputVerificationFrameType, "swarm_id": spec.SwarmID, "proof": map[string]any{"proof": map[string]any{"verification_id": "disband-proof"}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.RecordOutputVerification(context.Background(), frame); err != nil {
		t.Fatal(err)
	}
}
