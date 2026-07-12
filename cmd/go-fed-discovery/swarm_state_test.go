package main

import (
	"encoding/base64"
	"errors"
	"os"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestSwarmReducerRunsOnlyThroughDispatchedWave(t *testing.T) {
	spec := reducerTestDurableSpec(t)
	state, err := ReduceSwarmEntry(SwarmState{}, reducerTestOpenedEntry(t, spec))
	if err != nil {
		t.Fatal(err)
	}
	readyAt := swarmJournalTestTime.Add(time.Second).Format(time.RFC3339Nano)
	wave := ReadyWave{StepIDs: []string{"prepare"}, RecordedAt: readyAt}
	state, err = ReduceSwarmEntry(state, reducerTestTimedEntry(t, "wave.ready", waveReadyPayload{SchemaVersion: swarmStateSchemaVersion, Wave: wave}, state.Version, state.Version+1, readyAt))
	if err != nil {
		t.Fatal(err)
	}
	dispatchedAt := swarmJournalTestTime.Add(2 * time.Second).Format(time.RFC3339Nano)
	claim := LeaseClaim{StepID: "prepare", Owner: "worker-a", Fence: 1, Attempt: 1, CandidateIndex: 0, Capability: spec.Steps[0].Capability, Candidate: spec.Steps[0].Candidates[0], Deadline: swarmJournalTestTime.Add(3 * time.Second).Format(time.RFC3339Nano)}
	state, err = ReduceSwarmEntry(state, reducerTestTimedEntry(t, "wave.dispatched", waveDispatchedPayload{SchemaVersion: swarmStateSchemaVersion, Wave: wave, Claims: []LeaseClaim{claim}}, state.Version, state.Version+1, dispatchedAt))
	if err != nil {
		t.Fatal(err)
	}
	if state.Steps[0].Status != SwarmStepStatusRunning || state.Steps[0].Attempts != 1 || !reflect.DeepEqual(state.Leases, []LeaseClaim{claim}) {
		t.Fatalf("dispatch state = %#v", state)
	}
	if next, err := ReduceSwarmEntry(state, reducerTestEntry(t, "swarm.cancelled", map[string]any{"schema_version": 1}, state.Version, state.Version+1)); err == nil || !reflect.DeepEqual(next, SwarmState{}) {
		t.Fatalf("running step accepted unfenced cancellation: next=%#v err=%v", next, err)
	}
	observedAt := swarmJournalTestTime.Add(2500 * time.Millisecond).Format(time.RFC3339Nano)
	state, err = ReduceSwarmEntry(state, reducerTestTimedEntry(t, "lease.observed", leaseObservedPayload{SchemaVersion: swarmStateSchemaVersion, Claim: claim, Outcome: "reported"}, state.Version, state.Version+1, observedAt))
	if err != nil {
		t.Fatal(err)
	}
	if got := state.Steps[0].Observations[len(state.Steps[0].Observations)-1]; got.Outcome != "reported" || got.ObservedAt != observedAt {
		t.Fatalf("lease observation = %#v", got)
	}
}

func TestSwarmReducerRejectsLegacyStepTransitionsWithoutMutation(t *testing.T) {
	state, err := ReduceSwarmEntry(SwarmState{}, reducerTestOpenedEntry(t, reducerTestDurableSpec(t)))
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"step.started", "step.completed", "step.failed", "step.retrying", "step.cancelled"} {
		entry := reducerTestEntry(t, kind, map[string]any{"schema_version": 1, "step_id": "prepare"}, state.Version, state.Version+1)
		if next, err := ReduceSwarmEntry(state, entry); err == nil || !reflect.DeepEqual(next, SwarmState{}) {
			t.Fatalf("ReduceSwarmEntry accepted legacy %s: next=%#v err=%v", kind, next, err)
		}
	}
}

func TestSwarmReducerDoesNotMutatePriorStateOrEntry(t *testing.T) {
	spec := reducerTestDurableSpec(t)
	opened := reducerTestOpenedEntry(t, spec)
	state, err := ReduceSwarmEntry(SwarmState{}, opened)
	if err != nil {
		t.Fatal(err)
	}
	prior := state
	priorSpec := append([]byte(nil), state.Spec.Plan...)
	readyAt := swarmJournalTestTime.Add(time.Second).Format(time.RFC3339Nano)
	entry := reducerTestTimedEntry(t, "wave.ready", waveReadyPayload{SchemaVersion: swarmStateSchemaVersion, Wave: ReadyWave{StepIDs: []string{"prepare"}, RecordedAt: readyAt}}, 1, 2, readyAt)
	entryPayload := append([]byte(nil), entry.Payload...)
	next, err := ReduceSwarmEntry(state, entry)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(state, prior) || !reflect.DeepEqual(state.Spec.Plan, priorSpec) {
		t.Fatalf("prior state mutated: got %#v; want %#v", state, prior)
	}
	if string(entry.Payload) != string(entryPayload) {
		t.Fatalf("entry payload mutated: got %q; want %q", entry.Payload, entryPayload)
	}
	next.Spec.Plan[0] ^= 0xff
	if reflect.DeepEqual(next.Spec.Plan, state.Spec.Plan) {
		t.Fatal("reducer returned an aliased durable spec")
	}
}

func TestSwarmOpenIdempotentAndRejectsConflict(t *testing.T) {
	journal := newTestSwarmJournal(t)
	spec := reducerTestDurableSpec(t)
	at := swarmJournalTestTime
	first, err := OpenVerifiedSwarm(journal, spec, at)
	if err != nil {
		t.Fatal(err)
	}
	second, err := OpenVerifiedSwarm(journal, spec, at)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("idempotent open = %#v; want %#v", second, first)
	}
	conflict := spec
	conflict.Binding = []byte(`{"binding":"other"}`)
	if _, err := OpenVerifiedSwarm(journal, conflict, at); err == nil {
		t.Fatal("OpenVerifiedSwarm accepted a conflicting seed")
	}
	entries, err := journal.Replay()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("journal entries = %d; want exactly one opening", len(entries))
	}
}

func TestSwarmReplayPinsRejectsActivePointerSubstitution(t *testing.T) {
	// Reducer recovery consumes only the durable seed; this pin is deliberately
	// distinct from any current active pointer and must survive replay unchanged.
	journal := newTestSwarmJournal(t)
	spec := reducerTestDurableSpec(t)
	state, err := OpenVerifiedSwarm(journal, spec, swarmJournalTestTime)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := ReduceSwarmEntries(mustReplaySwarm(t, journal))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(replayed.Spec.Steps[0].Candidates[0].GenerationPin, state.Spec.Steps[0].Candidates[0].GenerationPin) {
		t.Fatalf("generation pin drifted on replay: got %#v want %#v", replayed.Spec.Steps[0].Candidates[0].GenerationPin, state.Spec.Steps[0].Candidates[0].GenerationPin)
	}
	if replayed.Spec.Steps[0].Candidates[0].GenerationPin.RecordDigest != "pinned-record-digest" {
		t.Fatal("replay substituted a live worker generation")
	}
}

func mustReplaySwarm(t *testing.T, journal *SwarmJournal) []SwarmJournalEntry {
	t.Helper()
	entries, err := journal.Replay()
	if err != nil {
		t.Fatal(err)
	}
	return entries
}

func reducerTestDurableSpec(t *testing.T) DurableSwarmSpec {
	t.Helper()
	plan := []byte(`{"plan":"canonical"}`)
	binding := []byte(`{"binding":"canonical"}`)
	request := []byte(`{"request":"canonical"}`)
	for _, raw := range [][]byte{plan, binding, request} {
		var decoded any
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatal(err)
		}
	}
	return DurableSwarmSpec{
		SchemaVersion: 1,
		SwarmID:       "swarm://test/alpha",
		Plan:          plan,
		Binding:       binding,
		Request:       request,
		Steps: []DurableSwarmStepSpec{{
			StepID:    "prepare",
			Candidates: []DurableWorkerCandidate{{Alias: "agent://test/worker", AID: "did:key:test", GenerationPin: WorkerGenerationPin{StorePath: "/keys/test", PassphraseFile: "/keys/pass", RecordDigest: "pinned-record-digest"}}},
			AttemptPolicy: SwarmAttemptPolicy{MaxAttempts: 1},
		}},
	}
}

func reducerTestOpenedEntry(t *testing.T, spec DurableSwarmSpec) SwarmJournalEntry {
	t.Helper()
	wire, err := spec.wire()
	if err != nil {
		t.Fatal(err)
	}
	return reducerTestEntry(t, "swarm.opened", swarmOpenedPayload{SchemaVersion: swarmStateSchemaVersion, Spec: wire}, 0, 1)
}

func reducerTestEntry(t *testing.T, kind string, payload any, prior, version uint64) SwarmJournalEntry {
	t.Helper()
	raw, err := canonicalJSON(payload)
	if err != nil {
		t.Fatal(err)
	}
	return SwarmJournalEntry{Kind: kind, Payload: raw, PriorStateVersion: prior, StateVersion: version}
}

func reducerTestTimedEntry(t *testing.T, kind string, payload any, prior, version uint64, timestamp string) SwarmJournalEntry {
	t.Helper()
	entry := reducerTestEntry(t, kind, payload, prior, version)
	entry.Timestamp = timestamp
	return entry
}

func TestSwarmOpenSeedUsesRawBase64URL(t *testing.T) {
	journal := newTestSwarmJournal(t)
	spec := reducerTestDurableSpec(t)
	if _, err := OpenVerifiedSwarm(journal, spec, time.Now()); err != nil {
		t.Fatal(err)
	}
	entry := mustReplaySwarm(t, journal)[0]
	var payload map[string]any
	if err := json.Unmarshal(entry.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	seed := payload["spec"].(map[string]any)
	for field, raw := range map[string][]byte{"plan": spec.Plan, "binding": spec.Binding, "request": spec.Request} {
		encoded, ok := seed[field].(string)
		if !ok || strings.Contains(encoded, "=") {
			t.Fatalf("seed %s is not raw base64url: %#v", field, seed[field])
		}
		decoded, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil || !reflect.DeepEqual(decoded, raw) {
			t.Fatalf("seed %s = %q decoded %q, %v; want %q", field, encoded, decoded, err, raw)
		}
	}
}


func TestSwarmReducerSkipsFutureEntriesAndRejectsStateNamespaces(t *testing.T) {
	spec := reducerTestDurableSpec(t)
	entries := []SwarmJournalEntry{
		reducerTestOpenedEntry(t, spec),
		reducerTestEntry(t, "future.audit", map[string]any{"event": "recorded"}, 1, 2),
	}
	state, err := ReduceSwarmEntries(entries)
	if err != nil {
		t.Fatal(err)
	}
	if state.Version != 2 || state.Status != SwarmStatusOpen || state.Steps[0].Status != SwarmStepStatusPending {
		t.Fatalf("future-entry replay state = %#v", state)
	}
	for _, kind := range []string{"step.started", "step.completed", "step.failed", "step.retrying", "step.cancelled", "step.future"} {
		if _, err := ReduceSwarmEntries(append(entries[:2:2], reducerTestEntry(t, kind, map[string]any{"event": "forged"}, 2, 3))); err == nil {
			t.Fatalf("ReduceSwarmEntries accepted legacy or unknown step namespace %q", kind)
		}
	}
}

func TestSwarmCancellationIsTerminal(t *testing.T) {
	spec := reducerTestDurableSpec(t)
	spec.Steps = append(spec.Steps, DurableSwarmStepSpec{
		StepID:        "publish",
		Candidates:    []DurableWorkerCandidate{{Alias: "agent://test/publisher", AID: "did:key:publisher", GenerationPin: WorkerGenerationPin{StorePath: "/keys/publisher", PassphraseFile: "/keys/publisher-pass", RecordDigest: "publisher-record-digest"}}},
		AttemptPolicy: SwarmAttemptPolicy{MaxAttempts: 1},
	})
	state, err := ReduceSwarmEntry(SwarmState{}, reducerTestOpenedEntry(t, spec))
	if err != nil {
		t.Fatal(err)
	}
	state, err = ReduceSwarmEntry(state, reducerTestEntry(t, "swarm.cancelled", map[string]any{"schema_version": 1}, 1, 2))
	if err != nil {
		t.Fatal(err)
	}
	if state.Status != SwarmStatusCancelled || state.Steps[0].Status != SwarmStepStatusCancelled || state.Steps[1].Status != SwarmStepStatusCancelled {
		t.Fatalf("cancellation state = %#v", state)
	}
	if _, err := ReduceSwarmEntry(state, reducerTestEntry(t, "swarm.cancelled", map[string]any{"schema_version": 1}, 2, 3)); err == nil {
		t.Fatal("ReduceSwarmEntry allowed a transition after cancellation")
	}
}

func TestOpenVerifiedSwarmRejectsMismatchedJournalIdentityBeforeAppend(t *testing.T) {
	journal := newTestSwarmJournal(t)
	spec := reducerTestDurableSpec(t)
	spec.SwarmID = "swarm://test/beta"
	if _, err := OpenVerifiedSwarm(journal, spec, swarmJournalTestTime); err == nil {
		t.Fatal("OpenVerifiedSwarm accepted a seed for a different journal identity")
	}
	if _, err := os.Stat(journal.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("mismatched seed created journal: %v", err)
	}
}
