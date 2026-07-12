package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"agnet/internal/managedkey"
)

func TestBuildSwarmCloseV2RejectsUncommittedStep(t *testing.T) {
	journal := newTestSwarmJournal(t)
	if _, err := OpenVerifiedSwarm(journal, reducerTestDurableSpec(t), swarmJournalTestTime); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildSwarmCloseV2(journal); err == nil {
		t.Fatal("BuildSwarmCloseV2 accepted an uncommitted swarm")
	}
}

func TestSwarmCloseV2IsByteStableAndExactlyOnce(t *testing.T) {
	journalA, spec := newCloseTestJournal(t)
	commitCloseTestJournal(t, journalA, spec, false)
	first, err := BuildSwarmCloseV2(journalA)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySwarmCloseV2(first.Bytes, journalA); err != nil {
		t.Fatalf("VerifySwarmCloseV2() = %v", err)
	}
	journalB, _ := newCloseTestJournal(t)
	commitCloseTestJournal(t, journalB, spec, true)
	second, err := BuildSwarmCloseV2(journalB)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Bytes, second.Bytes) || first.Digest != second.Digest {
		t.Fatalf("inverse completion order changed close: %s != %s", first.Bytes, second.Bytes)
	}
	stored, err := EnsureStableClose(journalA)
	if err != nil || !bytes.Equal(stored.Bytes, first.Bytes) || stored.Digest != first.Digest {
		t.Fatalf("stored close = %#v, %v", stored, err)
	}
	retry, err := EnsureStableClose(journalA)
	if err != nil || !bytes.Equal(retry.Bytes, first.Bytes) || retry.Digest != first.Digest {
		t.Fatalf("close retry = %#v, %v", retry, err)
	}
	entries := mustReplaySwarm(t, journalA)
	closeCount := 0
	for _, entry := range entries {
		if entry.Kind == "close.stored" {
			closeCount++
		}
	}
	if closeCount != 1 {
		t.Fatalf("close entries = %d; want 1", closeCount)
	}
	var close map[string]any
	if err := json.Unmarshal(first.Bytes, &close); err != nil {
		t.Fatal(err)
	}
	scheduler := close["scheduler"].(map[string]any)
	if scheduler["mode"] != "parallel-ready-dag" || len(scheduler["ready_waves"].([]any)) != 2 || len(scheduler["dispatch_waves"].([]any)) != 2 {
		t.Fatalf("scheduler evidence = %#v", scheduler)
	}
	steps := close["step_receipts"].([]any)
	if steps[0].(map[string]any)["step_id"] != "first" || steps[0].(map[string]any)["task_id"] != "close_first" || steps[1].(map[string]any)["step_id"] != "second" || steps[2].(map[string]any)["step_id"] != "final" {
		t.Fatalf("signed receipt order = %#v", steps)
	}
	observations := steps[0].(map[string]any)["observations"].([]any)
	if len(observations) != 3 || observations[1].(map[string]any)["outcome"] != "started" {
		t.Fatalf("observation evidence = %#v", observations)
	}
	final := close["final_output"].(map[string]any)
	if final["step_id"] != "final" || final["task_id"] != "close_final" || final["selection_rule"] != "single-terminal-result" {
		t.Fatalf("final output = %#v", final)
	}
	state, err := ReduceSwarmEntries(entries)
	if err != nil || state.Status != SwarmStatusClosing {
		t.Fatalf("close state = %#v, %v", state, err)
	}
}

func TestEnsureStableCloseRecoversAppendBeforeResponseAndAppendFailure(t *testing.T) {
	journal, spec := newCloseTestJournal(t)
	commitCloseTestJournal(t, journal, spec, false)
	want, err := BuildSwarmCloseV2(journal)
	if err != nil {
		t.Fatal(err)
	}
	failure := errors.New("append interrupted")
	journal.fault = func(point SwarmFaultPoint) error {
		if point == SwarmFaultFileSync {
			return failure
		}
		return nil
	}
	if _, err := EnsureStableClose(journal); !errors.Is(err, failure) {
		t.Fatalf("close append failure = %v", err)
	}
	journal.fault = nil
	got, err := EnsureStableClose(journal)
	if err != nil || !bytes.Equal(got.Bytes, want.Bytes) || got.Digest != want.Digest {
		t.Fatalf("sign-before-append retry = %#v, %v", got, err)
	}
	again, err := EnsureStableClose(journal)
	if err != nil || !bytes.Equal(again.Bytes, want.Bytes) {
		t.Fatalf("append-before-response retry = %#v, %v", again, err)
	}
}

func TestDurableSwarmResponseStoresAndEmitsSignedClose(t *testing.T) {
	journal, spec := newCloseTestJournal(t)
	commitCloseTestJournal(t, journal, spec, false)
	view, err := ReadSwarmView(journal)
	if err != nil {
		t.Fatal(err)
	}
	frames, err := durableSwarmResponseFrames(journal, view)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) == 0 || frames[len(frames)-1]["type"] != "FED_SWARM_CLOSE" {
		t.Fatalf("frames = %#v", frames)
	}
	raw, ok := frames[len(frames)-1]["close"].(json.RawMessage)
	if !ok {
		t.Fatalf("close frame = %#v", frames[len(frames)-1])
	}
	stored, err := EnsureStableClose(journal)
	if err != nil || !bytes.Equal(raw, stored.Bytes) {
		t.Fatalf("close bytes were reserialized: %v", err)
	}
	if err := VerifySwarmCloseV2(raw, journal); err != nil {
		t.Fatalf("emitted close did not verify: %v", err)
	}
}

func TestSendPreservesRawMessageBytes(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() {
		send(server, map[string]any{"type": "FED_RECEIPT", "receipt": json.RawMessage(`{"html":"<tag>&"}`)})
		server.Close()
		close(done)
	}()
	buffer := make([]byte, 256)
	count, err := client.Read(buffer)
	if err != nil { t.Fatal(err) }
	<-done
	if !bytes.Contains(buffer[:count], []byte(`"receipt":{"html":"<tag>&"}`)) {
		t.Fatalf("raw receipt bytes were changed: %q", buffer[:count])
	}
}

func TestEnsureStableCloseRejectsConflictingStoredCandidate(t *testing.T) {
	journal, spec := newCloseTestJournal(t)
	commitCloseTestJournal(t, journal, spec, false)
	candidate, err := BuildSwarmCloseV2(journal)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(candidate.Bytes, &body); err != nil {
		t.Fatal(err)
	}
	delete(body, "close_signature")
	body["plan_digest"] = strings.Repeat("e", 64)
	key, err := pinnedCloseAuthorityKey(spec)
	if err != nil {
		t.Fatal(err)
	}
	forged, err := canonicalJSON(signBodyWithKey(key, body, "close_signature"))
	clear(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.WithLockedReplay(func(entries []SwarmJournalEntry) error {
		state, err := ReduceSwarmEntries(entries)
		if err != nil {
			return err
		}
		payload, err := canonicalSwarmPayload(closeStoredPayload{SchemaVersion: swarmStateSchemaVersion, Close: base64.RawURLEncoding.EncodeToString(forged), Digest: digestBytesHex(forged)})
		if err != nil {
			return err
		}
		entry := SwarmJournalEntry{Format: swarmJournalFormat, Sequence: uint64(len(entries) + 1), PriorStateVersion: state.Version, StateVersion: state.Version + 1, Kind: "close.stored", Payload: payload, Timestamp: entries[len(entries)-1].Timestamp, PrevHash: entries[len(entries)-1].Hash}
		entry.Hash, err = swarmJournalEntryHash(entry)
		if err != nil {
			return err
		}
		return journal.appendLocked(entry)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureStableClose(journal); err == nil {
		t.Fatal("EnsureStableClose accepted a different signed close candidate")
	}
}

func newCloseTestJournal(t *testing.T) (*SwarmJournal, DurableSwarmSpec) {
	t.Helper()
	authorityKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize))
	authority, err := zoneDescriptor(authorityKey, "close-test-authority")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	seed := authorityKey.Seed()
	config := writeManagedRuntimeStore(t, root, "authority", authority, seed, managedkey.IdentityZID, managedkey.KeyTypeSeed)
	clear(seed)
	loaded, err := loadManagedIdentity(config, managedkey.IdentityZID)
	if err != nil {
		t.Fatal(err)
	}
	clear(loaded.PrivateKey)
	stepDigests := []string{strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)}
	taskIDs := []string{"close_first", "close_second", "close_final"}
	bindingSteps := []any{
		map[string]any{"step_id": "first", "depends_on": []any{}, "capability": "analysis", "task_digest": stepDigests[0]},
		map[string]any{"step_id": "second", "depends_on": []any{}, "capability": "analysis", "task_digest": stepDigests[1]},
		map[string]any{"step_id": "final", "depends_on": []any{"first", "second"}, "capability": "analysis", "task_digest": stepDigests[2]},
	}
	planDigest := strings.Repeat("d", 64)
	swarmID := "swarm://test/deterministic-close"
	binding := map[string]any{"format": "asp-swarm-execution-binding/v1", "swarm_id": swarmID, "plan_digest": planDigest, "steps": bindingSteps, "execution_graph_digest": digestHex(map[string]any{"swarm_id": swarmID, "plan_digest": planDigest, "steps": bindingSteps}), "binding_signature": "journal-only"}
	bindingRaw, err := canonicalJSON(binding)
	if err != nil {
		t.Fatal(err)
	}
	requestRaw, err := canonicalJSON(map[string]any{"origin": authority})
	if err != nil {
		t.Fatal(err)
	}
	candidate := reducerTestCandidate(t, "agent://test/worker")
	workerDescriptor, err := agentDescriptor(u22TestWorkerKey(), "agent://test/worker")
	if err != nil {
		t.Fatal(err)
	}
	descriptorRaw, err := canonicalJSON(workerDescriptor)
	if err != nil {
		t.Fatal(err)
	}
	candidate.Descriptor = string(descriptorRaw)
	zoneBindingRaw, err := canonicalJSON(signBodyWithKey(authorityKey, map[string]any{"zone": authority["zid"], "alias": candidate.Alias, "aid": candidate.AID}, "signature"))
	if err != nil {
		t.Fatal(err)
	}
	candidate.ZoneBinding = string(zoneBindingRaw)
	spec := DurableSwarmSpec{SchemaVersion: swarmStateSchemaVersion, SwarmID: swarmID, Plan: []byte(`{"plan":"canonical"}`), Binding: bindingRaw, Request: requestRaw, AuthorityGeneration: WorkerGenerationPin{StorePath: config.StorePath, PassphraseFile: config.PassphraseFile, RecordDigest: loaded.KeyGeneration.RecordDigest}, LocalAuthority: authority, Steps: []DurableSwarmStepSpec{
		{StepID: "first", TaskID: taskIDs[0], TaskDigest: stepDigests[0], Capability: "analysis", Candidates: []DurableWorkerCandidate{candidate}, AttemptPolicy: SwarmAttemptPolicy{MaxAttempts: 1}},
		{StepID: "second", TaskID: taskIDs[1], TaskDigest: stepDigests[1], Capability: "analysis", Candidates: []DurableWorkerCandidate{candidate}, AttemptPolicy: SwarmAttemptPolicy{MaxAttempts: 1}},
		{StepID: "final", TaskID: taskIDs[2], DependsOn: []string{"first", "second"}, TaskDigest: stepDigests[2], Capability: "analysis", Candidates: []DurableWorkerCandidate{candidate}, AttemptPolicy: SwarmAttemptPolicy{MaxAttempts: 1}},
	}}
	journal, err := OpenSwarmJournal(root, swarmID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenVerifiedSwarm(journal, spec, swarmJournalTestTime); err != nil {
		t.Fatal(err)
	}
	return journal, spec
}

func commitCloseTestJournal(t *testing.T, journal *SwarmJournal, spec DurableSwarmSpec, inverse bool) {
	t.Helper()
	if _, _, err := RecordNextReadyWave(journal, swarmJournalTestTime.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	dispatch, err := ClaimReadyWave(journal, "close-owner", swarmJournalTestTime.Add(time.Minute), swarmJournalTestTime.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	first, second := dispatch.Claims[0], dispatch.Claims[1]
	if err := RecordLeaseObservation(journal, first, "started", swarmJournalTestTime.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := RecordLeaseObservation(journal, second, "started", swarmJournalTestTime.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	firstArtifact, err := StageArtifact(journal, []byte("first-result"))
	if err != nil {
		t.Fatal(err)
	}
	secondArtifact, err := StageArtifact(journal, []byte("second-result"))
	if err != nil {
		t.Fatal(err)
	}
	commit := func(claim LeaseClaim, artifact StagedArtifact, at int) {
		if _, err := CommitReceipt(journal, ReceiptCommit{Claim: claim, Receipt: u22Receipt(t, spec, claim, artifact), Result: artifact}, swarmJournalTestTime.Add(time.Duration(at)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	if inverse {
		commit(second, secondArtifact, 5)
		commit(first, firstArtifact, 5)
	} else {
		commit(first, firstArtifact, 5)
		commit(second, secondArtifact, 5)
	}
	if _, _, err := RecordNextReadyWave(journal, swarmJournalTestTime.Add(7*time.Second)); err != nil {
		t.Fatal(err)
	}
	finalDispatch, err := ClaimReadyWave(journal, "close-owner", swarmJournalTestTime.Add(time.Minute), swarmJournalTestTime.Add(8*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	finalArtifact, err := StageArtifact(journal, []byte("final-result"))
	if err != nil {
		t.Fatal(err)
	}
	dependencies := []receiptDependencyV2{{StepID: "first", Artifact: firstArtifact.Triple()}, {StepID: "second", Artifact: secondArtifact.Triple()}}
	if _, err := CommitReceipt(journal, ReceiptCommit{Claim: finalDispatch.Claims[0], Receipt: u22ReceiptWithDependencies(t, spec, finalDispatch.Claims[0], finalArtifact, dependencies), Result: finalArtifact}, swarmJournalTestTime.Add(9*time.Second)); err != nil {
		t.Fatal(err)
	}
}
