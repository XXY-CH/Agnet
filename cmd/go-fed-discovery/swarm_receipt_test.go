package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestU22StageArtifactIsPrivateImmutableAndInvisibleUntilCommitted(t *testing.T) {
	journal := newTestSwarmJournal(t)
	if _, err := OpenVerifiedSwarm(journal, reducerTestDurableSpec(t), swarmJournalTestTime); err != nil {
		t.Fatal(err)
	}
	artifact, err := StageArtifact(journal, []byte("receipt-bound output"))
	if err != nil {
		t.Fatal(err)
	}
	if artifact.SHA256 == "" || artifact.Size != uint64(len("receipt-bound output")) {
		t.Fatalf("stage = %#v", artifact)
	}
	if _, err := ReadCommittedArtifact(journal, artifact); !errors.Is(err, ErrArtifactNotCommitted) {
		t.Fatalf("read hidden stage = %v; want ErrArtifactNotCommitted", err)
	}
	info, err := os.Stat(artifact.Path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("artifact mode = %o; want 0600", info.Mode().Perm())
	}
	if filepath.Base(filepath.Dir(artifact.Path)) != "objects" {
		t.Fatalf("stage object escaped hidden CAS: %q", artifact.Path)
	}
	second, err := StageArtifact(journal, []byte("receipt-bound output"))
	if err != nil {
		t.Fatal(err)
	}
	if second != artifact {
		t.Fatalf("same bytes yielded a mutable or distinct stage: %#v != %#v", second, artifact)
	}
	if err := os.WriteFile(artifact.Path, []byte("forged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := StageArtifact(journal, []byte("receipt-bound output")); err == nil {
		t.Fatal("stage accepted conflicting existing digest object")
	}
}

func TestU22CommitReceiptFencesPublicationAndIsExactlyOnce(t *testing.T) {
	journal := newTestSwarmJournal(t)
	spec := reducerTestDurableSpec(t)
	spec.Steps[0].TaskDigest = strings.Repeat("a", 64)
	spec.Steps[0].Capability = "analysis"
	if _, err := OpenVerifiedSwarm(journal, spec, swarmJournalTestTime); err != nil {
		t.Fatal(err)
	}
	if _, _, err := RecordNextReadyWave(journal, swarmJournalTestTime.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	dispatch, err := ClaimReadyWave(journal, "worker-a", swarmJournalTestTime.Add(time.Minute), swarmJournalTestTime.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	result, err := StageArtifact(journal, []byte("committed result"))
	if err != nil {
		t.Fatal(err)
	}
	commit := ReceiptCommit{Claim: dispatch.Claims[0], Receipt: u22Receipt(t, spec, dispatch.Claims[0], result), Result: result}
	state, err := CommitReceipt(journal, commit, swarmJournalTestTime.Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if state.Steps[0].Status != SwarmStepStatusCompleted || state.Status != SwarmStatusCompleted || len(state.Leases) != 0 {
		t.Fatalf("committed state = %#v", state)
	}
	got, err := ReadCommittedArtifact(journal, result)
	if err != nil || !bytes.Equal(got, []byte("committed result")) {
		t.Fatalf("committed artifact = %q, %v", got, err)
	}
	if err := os.Remove(result.Path); err != nil {
		t.Fatal(err)
	}
	before := len(mustReplaySwarm(t, journal))
	second, err := CommitReceipt(journal, commit, swarmJournalTestTime.Add(4*time.Second))
	if err != nil || second.Version != state.Version || len(mustReplaySwarm(t, journal)) != before {
		t.Fatalf("exact replay = %#v, %v", second, err)
	}
	for _, mutate := range []func(*ReceiptCommit){
		func(c *ReceiptCommit) { c.Claim.Owner = "other" },
		func(c *ReceiptCommit) { c.Claim.Fence++ },
		func(c *ReceiptCommit) { c.Claim.Attempt++ },
		func(c *ReceiptCommit) { c.Claim.Capability = "other" },
		func(c *ReceiptCommit) { c.Claim.Candidate.GenerationPin.RecordDigest = "other" },
		func(c *ReceiptCommit) {
			c.Receipt.Bytes = append([]byte(nil), c.Receipt.Bytes...)
			c.Receipt.Bytes = append(c.Receipt.Bytes, ' ')
		},
	} {
		conflict := commit
		mutate(&conflict)
		if _, err := CommitReceipt(journal, conflict, swarmJournalTestTime.Add(5*time.Second)); err == nil {
			t.Fatal("conflicting replay committed")
		}
	}
}

func TestU22CommitReceiptRejectsBadFenceAndNoPublicationOnJournalSyncFailure(t *testing.T) {
	failure := errors.New("journal sync failed")
	journal := newTestSwarmJournal(t, func(point SwarmFaultPoint) error {
		if point == SwarmFaultFileSync {
			return failure
		}
		return nil
	})
	spec := reducerTestDurableSpec(t)
	spec.Steps[0].TaskDigest, spec.Steps[0].Capability = strings.Repeat("a", 64), "analysis"
	journal.fault = nil
	if _, err := OpenVerifiedSwarm(journal, spec, swarmJournalTestTime); err != nil {
		t.Fatal(err)
	}
	if _, _, err := RecordNextReadyWave(journal, swarmJournalTestTime.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	dispatch, err := ClaimReadyWave(journal, "worker-a", swarmJournalTestTime.Add(time.Minute), swarmJournalTestTime.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	result, err := StageArtifact(journal, []byte("unpublished"))
	if err != nil {
		t.Fatal(err)
	}
	journal.fault = func(point SwarmFaultPoint) error {
		if point == SwarmFaultFileSync {
			return failure
		}
		return nil
	}
	commit := ReceiptCommit{Claim: dispatch.Claims[0], Receipt: u22Receipt(t, spec, dispatch.Claims[0], result), Result: result}
	if _, err := CommitReceipt(journal, commit, swarmJournalTestTime.Add(3*time.Second)); !errors.Is(err, failure) {
		t.Fatalf("commit fault = %v", err)
	}
	if _, err := ReadCommittedArtifact(journal, result); !errors.Is(err, ErrArtifactNotCommitted) {
		t.Fatalf("artifact published before journal fsync: %v", err)
	}
}

func TestU22VerifierRejectsNoncanonicalAndFrozenTaskGraphBindings(t *testing.T) {
	spec := reducerTestDurableSpec(t)
	spec.Steps[0].TaskDigest, spec.Steps[0].Capability = strings.Repeat("a", 64), "analysis"
	claim := LeaseClaim{StepID: "prepare", Owner: "worker-a", Fence: 1, Attempt: 1, CandidateIndex: 0, Capability: "analysis", Candidate: spec.Steps[0].Candidates[0], Deadline: swarmJournalTestTime.Add(time.Minute).Format(time.RFC3339Nano)}
	artifact := StagedArtifact{SHA256: strings.Repeat("b", 64), Size: 1}
	receipt := u22Receipt(t, spec, claim, artifact)
	expected := ReceiptExpectation{SwarmID: spec.SwarmID, Claim: claim, TaskDigest: spec.Steps[0].TaskDigest, GraphDigest: digestBytesHex(spec.Binding), Result: artifact.Triple(), Auxiliary: []ArtifactTriple{}, DependsOn: map[string]ArtifactTriple{}}
	if err := VerifyReceiptV2(receipt.Bytes, expected); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*ReceiptExpectation){
		func(e *ReceiptExpectation) { e.TaskDigest = strings.Repeat("c", 64) },
		func(e *ReceiptExpectation) { e.GraphDigest = strings.Repeat("d", 64) },
		func(e *ReceiptExpectation) { e.Claim.Capability = "other" },
		func(e *ReceiptExpectation) { e.Claim.Candidate.GenerationPin.RecordDigest = "other" },
	} {
		wrong := expected
		mutate(&wrong)
		if err := VerifyReceiptV2(receipt.Bytes, wrong); err == nil {
			t.Fatal("verifier accepted a frozen binding mismatch")
		}
	}
	if _, err := StageReceipt(append(append([]byte(nil), receipt.Bytes...), ' ')); err == nil {
		t.Fatal("receipt stage accepted noncanonical bytes")
	}
}

func TestU22VerifierRejectsArbitraryAndWrongKeySignatures(t *testing.T) {
	spec := reducerTestDurableSpec(t)
	spec.Steps[0].TaskDigest, spec.Steps[0].Capability = strings.Repeat("a", 64), "analysis"
	claim := LeaseClaim{StepID: "prepare", Owner: "worker-a", Fence: 1, Attempt: 1, CandidateIndex: 0, Capability: "analysis", Candidate: spec.Steps[0].Candidates[0], Deadline: swarmJournalTestTime.Add(time.Minute).Format(time.RFC3339Nano)}
	artifact := StagedArtifact{SHA256: strings.Repeat("b", 64), Size: 1}
	expected := ReceiptExpectation{SwarmID: spec.SwarmID, Claim: claim, TaskDigest: spec.Steps[0].TaskDigest, GraphDigest: digestBytesHex(spec.Binding), Result: artifact.Triple(), Auxiliary: []ArtifactTriple{}, DependsOn: map[string]ArtifactTriple{}}
	valid := u22Receipt(t, spec, claim, artifact)

	for _, signature := range []string{"arbitrary", base64.RawURLEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize)), receiptBodyForSignature(t, valid.Bytes)))} {
		forged := replaceReceiptSignature(t, valid.Bytes, signature)
		if err := VerifyReceiptV2(forged.Bytes, expected); err == nil {
			t.Fatal("verifier accepted an arbitrary or wrong-key signature")
		}
	}
}

func TestU22ReducerAndTypedAppendRejectForgedDependencyTriple(t *testing.T) {
	journal := newTestSwarmJournal(t)
	spec := reducerTestDurableSpec(t)
	spec.Steps[0].TaskDigest, spec.Steps[0].Capability = strings.Repeat("a", 64), "analysis"
	spec.Steps = append(spec.Steps, DurableSwarmStepSpec{StepID: "publish", DependsOn: []string{"prepare"}, TaskDigest: strings.Repeat("c", 64), Capability: "analysis", Candidates: []DurableWorkerCandidate{spec.Steps[0].Candidates[0]}, AttemptPolicy: SwarmAttemptPolicy{MaxAttempts: 1}})
	if _, err := OpenVerifiedSwarm(journal, spec, swarmJournalTestTime); err != nil {
		t.Fatal(err)
	}
	if _, _, err := RecordNextReadyWave(journal, swarmJournalTestTime.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	firstDispatch, err := ClaimReadyWave(journal, "worker-a", swarmJournalTestTime.Add(time.Minute), swarmJournalTestTime.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	upstream, err := StageArtifact(journal, []byte("upstream"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CommitReceipt(journal, ReceiptCommit{Claim: firstDispatch.Claims[0], Receipt: u22Receipt(t, spec, firstDispatch.Claims[0], upstream), Result: upstream}, swarmJournalTestTime.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := RecordNextReadyWave(journal, swarmJournalTestTime.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	secondDispatch, err := ClaimReadyWave(journal, "worker-a", swarmJournalTestTime.Add(time.Minute), swarmJournalTestTime.Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	state, err := ReduceSwarmEntries(mustReplaySwarm(t, journal))
	if err != nil {
		t.Fatal(err)
	}
	downstream, err := StageArtifact(journal, []byte("downstream"))
	if err != nil {
		t.Fatal(err)
	}
	forged := ArtifactTriple{URI: "artifact://local/sha256/" + strings.Repeat("d", 64), SHA256: strings.Repeat("d", 64), ManifestHash: strings.Repeat("d", 64)}
	receipt := u22ReceiptWithDependencies(t, spec, secondDispatch.Claims[0], downstream, []receiptDependencyV2{{StepID: "prepare", Artifact: forged}})
	payload := receiptCommittedPayload{SchemaVersion: swarmStateSchemaVersion, Claim: secondDispatch.Claims[0], Receipt: base64.RawURLEncoding.EncodeToString(receipt.Bytes), ReceiptDigest: receipt.Digest, Result: downstream.Triple()}
	entry := reducerTestTimedEntry(t, "receipt.committed", payload, state.Version, state.Version+1, swarmJournalTestTime.Add(6*time.Second).Format(time.RFC3339Nano))
	if _, err := ReduceSwarmEntry(state, entry); err == nil {
		t.Fatal("reducer accepted a self-asserted forged dependency triple")
	}
	if _, err := ReduceSwarmEntries(append(mustReplaySwarm(t, journal), entry)); err == nil {
		t.Fatal("replay accepted a self-asserted forged dependency triple")
	}
	if _, err := journal.Append("receipt.committed", payload, state.Version, state.Version+1, swarmJournalTestTime.Add(6*time.Second)); err == nil {
		t.Fatal("typed append accepted a self-asserted forged dependency triple")
	}
}

func TestU22ExpiredReceiptCannotPublish(t *testing.T) {
	journal := newTestSwarmJournal(t)
	spec := reducerTestDurableSpec(t)
	spec.Steps[0].TaskDigest, spec.Steps[0].Capability = strings.Repeat("a", 64), "analysis"
	if _, err := OpenVerifiedSwarm(journal, spec, swarmJournalTestTime); err != nil {
		t.Fatal(err)
	}
	if _, _, err := RecordNextReadyWave(journal, swarmJournalTestTime.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	dispatch, err := ClaimReadyWave(journal, "worker-a", swarmJournalTestTime.Add(3*time.Second), swarmJournalTestTime.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	result, err := StageArtifact(journal, []byte("expired"))
	if err != nil {
		t.Fatal(err)
	}
	commit := ReceiptCommit{Claim: dispatch.Claims[0], Receipt: u22Receipt(t, spec, dispatch.Claims[0], result), Result: result}
	if _, err := CommitReceipt(journal, commit, swarmJournalTestTime.Add(3*time.Second)); err == nil {
		t.Fatal("expired lease committed a receipt")
	}
	if _, err := ReadCommittedArtifact(journal, result); !errors.Is(err, ErrArtifactNotCommitted) {
		t.Fatalf("expired receipt published artifact: %v", err)
	}
}

func u22Receipt(t *testing.T, spec DurableSwarmSpec, claim LeaseClaim, result StagedArtifact) StagedReceipt {
	return u22ReceiptWithDependencies(t, spec, claim, result, nil)
}

func u22ReceiptWithDependencies(t *testing.T, spec DurableSwarmSpec, claim LeaseClaim, result StagedArtifact, dependencies []receiptDependencyV2) StagedReceipt {
	t.Helper()
	stepIndex := -1
	for i := range spec.Steps {
		if spec.Steps[i].StepID == claim.StepID {
			stepIndex = i
			break
		}
	}
	if stepIndex < 0 {
		t.Fatal("receipt step missing")
	}
	body := map[string]any{
		"format": "agnet-receipt/v2", "swarm_id": spec.SwarmID, "step_id": claim.StepID,
		"task_digest": spec.Steps[stepIndex].TaskDigest, "graph_digest": digestBytesHex(spec.Binding), "capability": claim.Capability, "worker_aid": claim.Candidate.AID,
		"worker_generation_pin": claim.Candidate.GenerationPin, "attempt": claim.Attempt, "fence": claim.Fence,
		"result": result.Triple(), "auxiliary": []any{},
	}
	if spec.Steps[stepIndex].TaskID != "" {
		body["task_id"] = spec.Steps[stepIndex].TaskID
	}
	if len(dependencies) != 0 {
		body["dependencies"] = dependencies
	}
	unsigned, err := canonicalJSON(body)
	if err != nil {
		t.Fatal(err)
	}
	var canonicalBody map[string]any
	if err := json.Unmarshal(unsigned, &canonicalBody); err != nil {
		t.Fatal(err)
	}
	raw, err := canonicalJSON(signBody(u22TestWorkerKey(), canonicalBody))
	if err != nil {
		t.Fatal(err)
	}
	staged, err := StageReceipt(raw)
	if err != nil {
		t.Fatal(err)
	}
	return staged
}

func u22TestWorkerKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed([]byte(strings.Repeat("7", ed25519.SeedSize)))
}

func receiptBodyForSignature(t *testing.T, raw []byte) []byte {
	t.Helper()
	var receipt map[string]any
	if err := json.Unmarshal(raw, &receipt); err != nil {
		t.Fatal(err)
	}
	delete(receipt, "signature")
	body, err := canonicalJSON(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func replaceReceiptSignature(t *testing.T, raw []byte, signature string) StagedReceipt {
	t.Helper()
	var receipt map[string]any
	if err := json.Unmarshal(raw, &receipt); err != nil {
		t.Fatal(err)
	}
	receipt["signature"] = signature
	encoded, err := canonicalJSON(receipt)
	if err != nil {
		t.Fatal(err)
	}
	staged, err := StageReceipt(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return staged
}
