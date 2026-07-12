package main

import (
	"reflect"
	"testing"
	"time"
)

func TestReadyWaveUsesSignedOrderAndWaveBarrier(t *testing.T) {
	journal := newTestSwarmJournal(t)
	spec := reducerTestDurableSpec(t)
	spec.Steps = []DurableSwarmStepSpec{
		{StepID: "prepare", TaskDigest: spec.Steps[0].TaskDigest, Capability: spec.Steps[0].Capability, Candidates: spec.Steps[0].Candidates, AttemptPolicy: SwarmAttemptPolicy{MaxAttempts: 2}},
		{StepID: "lint", TaskDigest: spec.Steps[0].TaskDigest, Capability: spec.Steps[0].Capability, Candidates: spec.Steps[0].Candidates, AttemptPolicy: SwarmAttemptPolicy{MaxAttempts: 2}},
		{StepID: "publish", DependsOn: []string{"prepare", "lint"}, TaskDigest: spec.Steps[0].TaskDigest, Capability: spec.Steps[0].Capability, Candidates: spec.Steps[0].Candidates, AttemptPolicy: SwarmAttemptPolicy{MaxAttempts: 2}},
	}
	if _, err := OpenVerifiedSwarm(journal, spec, swarmJournalTestTime); err != nil {
		t.Fatal(err)
	}
	state, wave, err := RecordNextReadyWave(journal, swarmJournalTestTime.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := wave.StepIDs, []string{"prepare", "lint"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ready order = %#v; want %#v", got, want)
	}
	if !reflect.DeepEqual(state.ReadyWave, wave) {
		t.Fatalf("persisted ready wave = %#v; want %#v", state.ReadyWave, wave)
	}
	deadline := swarmJournalTestTime.Add(time.Minute)
	dispatch, err := ClaimReadyWave(journal, "worker-a", deadline, swarmJournalTestTime.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := dispatch.Wave.StepIDs, []string{"prepare", "lint"}; !reflect.DeepEqual(got, want) || len(dispatch.Claims) != 2 {
		t.Fatalf("dispatch = %#v", dispatch)
	}
	state, err = ReduceSwarmEntries(mustReplaySwarm(t, journal))
	if err != nil {
		t.Fatal(err)
	}
	blocked, err := DeriveNextReadyWave(state)
	if err != nil || !reflect.DeepEqual(blocked.StepIDs, []string{"prepare", "lint"}) {
		t.Fatalf("derived wave while current wave running = %#v, %v", blocked, err)
	}
	retainedState, retained, err := RecordNextReadyWave(journal, swarmJournalTestTime.Add(3*time.Second))
	if err != nil || !reflect.DeepEqual(retained.StepIDs, []string{"prepare", "lint"}) || !reflect.DeepEqual(retainedState.ReadyWave, dispatch.Wave) {
		t.Fatalf("running wave was bypassed: state=%#v wave=%#v err=%v", retainedState, retained, err)
	}
}

func TestLeaseRenewalAndExpiryPreservePinsAndOrder(t *testing.T) {
	journal := newTestSwarmJournal(t)
	spec := reducerTestDurableSpec(t)
	first := spec.Steps[0].Candidates[0]
	second := reducerTestCandidate(t, "agent://test/migration")
	spec.Steps[0].Candidates = []DurableWorkerCandidate{first, second}
	spec.Steps[0].AttemptPolicy.MaxAttempts = 2
	spec.Steps[0].Capability = "analysis"
	if _, err := OpenVerifiedSwarm(journal, spec, swarmJournalTestTime); err != nil {
		t.Fatal(err)
	}
	if _, _, err := RecordNextReadyWave(journal, swarmJournalTestTime.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	dispatch, err := ClaimReadyWave(journal, "worker-a", swarmJournalTestTime.Add(10*time.Second), swarmJournalTestTime.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	claim := dispatch.Claims[0]
	if claim.Candidate != first || claim.Capability != "analysis" || claim.Fence == 0 {
		t.Fatalf("first claim = %#v; want candidate %#v, capability pin, and fence", claim, first)
	}
	if _, err := journal.Append("future.audit", map[string]any{"note": "unrelated"}, 3, 4, swarmJournalTestTime.Add(2500*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	renewed, err := RenewLease(journal, "prepare", "worker-a", claim.Fence, swarmJournalTestTime.Add(20*time.Second), swarmJournalTestTime.Add(3*time.Second))
	if err != nil || renewed.Fence != claim.Fence {
		t.Fatalf("renewed = %#v, %v", renewed, err)
	}
	if _, err := RenewLease(journal, "prepare", "worker-b", claim.Fence, swarmJournalTestTime.Add(21*time.Second), swarmJournalTestTime.Add(4*time.Second)); err == nil {
		t.Fatal("renewal accepted a different owner")
	}
	state, err := ExpireLeases(journal, swarmJournalTestTime.Add(21*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if state.Steps[0].Status != SwarmStepStatusPending || state.Steps[0].Attempts != 1 {
		t.Fatalf("expired retry state = %#v", state.Steps[0])
	}
	if _, _, err := RecordNextReadyWave(journal, swarmJournalTestTime.Add(22*time.Second)); err != nil {
		t.Fatal(err)
	}
	dispatch, err = ClaimReadyWave(journal, "worker-b", swarmJournalTestTime.Add(30*time.Second), swarmJournalTestTime.Add(23*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if got := dispatch.Claims[0]; got.Candidate != second || got.Fence <= claim.Fence {
		t.Fatalf("migrated claim = %#v; want ordered migration candidate and increasing fence", got)
	}
	state, err = ExpireLeases(journal, swarmJournalTestTime.Add(31*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if state.Steps[0].Status != SwarmStepStatusFailed || state.Status != SwarmStatusFailed {
		t.Fatalf("exhausted expiry = %#v", state)
	}
}

func TestLeaseDeadlinesRequireUTCAndNoClockRollback(t *testing.T) {
	journal := newTestSwarmJournal(t)
	if _, err := OpenVerifiedSwarm(journal, reducerTestDurableSpec(t), swarmJournalTestTime); err != nil {
		t.Fatal(err)
	}
	if _, _, err := RecordNextReadyWave(journal, swarmJournalTestTime.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := ClaimReadyWave(journal, "worker-a", swarmJournalTestTime.Add(time.Minute).In(time.FixedZone("not-utc", 3600)), swarmJournalTestTime.Add(2*time.Second)); err == nil {
		t.Fatal("accepted non-UTC lease deadline")
	}
	if _, err := ClaimReadyWave(journal, "worker-a", swarmJournalTestTime.Add(time.Minute), swarmJournalTestTime); err == nil {
		t.Fatal("accepted clock rollback")
	}
}

func TestClaimAndRenewalRejectExpiredOrNonExtendingDeadlines(t *testing.T) {
	journal := newTestSwarmJournal(t)
	if _, err := OpenVerifiedSwarm(journal, reducerTestDurableSpec(t), swarmJournalTestTime); err != nil {
		t.Fatal(err)
	}
	if _, _, err := RecordNextReadyWave(journal, swarmJournalTestTime.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := ClaimReadyWave(journal, "worker-a", swarmJournalTestTime.Add(2*time.Second), swarmJournalTestTime.Add(2*time.Second)); err == nil {
		t.Fatal("claim accepted a deadline equal to its event timestamp")
	}
	dispatch, err := ClaimReadyWave(journal, "worker-a", swarmJournalTestTime.Add(5*time.Second), swarmJournalTestTime.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	claim := dispatch.Claims[0]
	entriesBefore := mustReplaySwarm(t, journal)
	if err := RecordLeaseObservation(journal, claim, "late-report", swarmJournalTestTime.Add(6*time.Second)); err == nil {
		t.Fatal("observation accepted after its lease deadline before expiry append")
	}
	if got := len(mustReplaySwarm(t, journal)); got != len(entriesBefore) {
		t.Fatalf("expired observation appended %d entries; want %d", got, len(entriesBefore))
	}
	if _, err := RenewLease(journal, claim.StepID, claim.Owner, claim.Fence, swarmJournalTestTime.Add(7*time.Second), swarmJournalTestTime.Add(6*time.Second)); err == nil {
		t.Fatal("renewal revived an already expired lease")
	}
	if got := len(mustReplaySwarm(t, journal)); got != len(entriesBefore) {
		t.Fatalf("expired renewal appended %d entries; want %d", got, len(entriesBefore))
	}
	if _, err := RenewLease(journal, claim.StepID, claim.Owner, claim.Fence, swarmJournalTestTime.Add(5*time.Second), swarmJournalTestTime.Add(3*time.Second)); err == nil {
		t.Fatal("renewal accepted a deadline that did not extend the live lease")
	}
}

func TestLeaseObservationRejectsStaleReclaimedWorkerWithoutAppend(t *testing.T) {
	journal := newTestSwarmJournal(t)
	spec := reducerTestDurableSpec(t)
	spec.Steps[0].AttemptPolicy.MaxAttempts = 2
	first := spec.Steps[0].Candidates[0]
	second := reducerTestCandidate(t, "agent://test/reclaimed")
	spec.Steps[0].Candidates = []DurableWorkerCandidate{first, second}
	if _, err := OpenVerifiedSwarm(journal, spec, swarmJournalTestTime); err != nil {
		t.Fatal(err)
	}
	if _, _, err := RecordNextReadyWave(journal, swarmJournalTestTime.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	firstDispatch, err := ClaimReadyWave(journal, "worker-a", swarmJournalTestTime.Add(3*time.Second), swarmJournalTestTime.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ExpireLeases(journal, swarmJournalTestTime.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := RecordNextReadyWave(journal, swarmJournalTestTime.Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := ClaimReadyWave(journal, "worker-b", swarmJournalTestTime.Add(9*time.Second), swarmJournalTestTime.Add(6*time.Second)); err != nil {
		t.Fatal(err)
	}
	entriesBefore := mustReplaySwarm(t, journal)
	if err := RecordLeaseObservation(journal, firstDispatch.Claims[0], "reported", swarmJournalTestTime.Add(7*time.Second)); err == nil {
		t.Fatal("stale worker observation was accepted after lease reclaim")
	}
	if got := len(mustReplaySwarm(t, journal)); got != len(entriesBefore) {
		t.Fatalf("stale worker observation appended %d entries; want %d", got, len(entriesBefore))
	}
}
