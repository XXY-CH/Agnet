package main

import (
	"agnet/internal/managedkey"
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

type coordinatorTestLauncher struct {
	t        *testing.T
	journal  *SwarmJournal
	now      func() time.Time

	mu       sync.Mutex
	launched []SwarmWorkerRequest
}

func (l *coordinatorTestLauncher) Launch(_ context.Context, request SwarmWorkerRequest) (SwarmWorkerResult, error) {
	l.mu.Lock()
	l.launched = append(l.launched, request)
	l.mu.Unlock()

	state, claim, err := exactLiveClaim(l.journal, request)
	if err != nil {
		return SwarmWorkerResult{}, err
	}
	artifact, err := StageArtifact(l.journal, []byte("coordinator output "+request.StepID))
	if err != nil {
		return SwarmWorkerResult{}, err
	}
	dependencies, err := committedDependencyTriples(state, swarmStepIndex(state.Steps, claim.StepID))
	if err != nil {
		panic(err)
	}
	orderedDependencies := make([]receiptDependencyV2, 0, len(dependencies))
	for _, stepID := range state.Spec.Steps[swarmStepIndex(state.Steps, claim.StepID)].DependsOn {
		orderedDependencies = append(orderedDependencies, receiptDependencyV2{StepID: stepID, Artifact: dependencies[stepID]})
	}
	receipt := u22ReceiptWithDependencies(l.t, state.Spec, claim, artifact, orderedDependencies)
	if _, err := CommitReceipt(l.journal, ReceiptCommit{Claim: claim, Receipt: receipt, Result: artifact}, l.now()); err != nil {
		panic(err)
	}
	return SwarmWorkerResult{Format: localSwarmWorkerResultFormat, SwarmID: request.SwarmID, StepID: request.StepID, Fence: request.Fence, ReceiptDigest: receipt.Digest}, nil
}


func TestLocalSwarmCoordinatorRunsWholeReadyWaveBeforeDependent(t *testing.T) {
	now := swarmJournalTestTime.Add(time.Hour)
	root := t.TempDir()
	spec := reducerTestDurableSpec(t)
	spec.Steps = []DurableSwarmStepSpec{
		{StepID: "left", TaskDigest: spec.Steps[0].TaskDigest, Capability: "analysis", Candidates: spec.Steps[0].Candidates, AttemptPolicy: SwarmAttemptPolicy{MaxAttempts: 1}},
		{StepID: "right", TaskDigest: spec.Steps[0].TaskDigest, Capability: "analysis", Candidates: spec.Steps[0].Candidates, AttemptPolicy: SwarmAttemptPolicy{MaxAttempts: 1}},
		{StepID: "join", DependsOn: []string{"left", "right"}, TaskDigest: spec.Steps[0].TaskDigest, Capability: "analysis", Candidates: spec.Steps[0].Candidates, AttemptPolicy: SwarmAttemptPolicy{MaxAttempts: 1}},
	}
	journal, err := OpenSwarmJournal(root, spec.SwarmID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenVerifiedSwarm(journal, spec, now); err != nil {
		t.Fatal(err)
	}
	launcher := &coordinatorTestLauncher{t: t, journal: journal, now: func() time.Time { return now }}
	coordinator, err := NewLocalSwarmCoordinator(Fixture{}, root, "test-coordinator", launcher, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	view, err := coordinator.RunReadyWaves(context.Background(), journal)
	if err != nil {
		t.Fatal(err)
	}
	if view.Status != SwarmStatusCompleted {
		t.Fatalf("status = %q, want completed", view.Status)
	}
	launcher.mu.Lock()
	defer launcher.mu.Unlock()
	if len(launcher.launched) != 3 || launcher.launched[2].StepID != "join" {
		t.Fatalf("launch order = %#v, want left/right wave before join", launcher.launched)
	}
}

func TestLocalSwarmCoordinatorDoesNotRerunCommittedStep(t *testing.T) {
	now := swarmJournalTestTime.Add(2 * time.Hour)
	root := t.TempDir()
	spec := reducerTestDurableSpec(t)
	journal, err := OpenSwarmJournal(root, spec.SwarmID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenVerifiedSwarm(journal, spec, now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := RecordNextReadyWave(journal, now); err != nil {
		t.Fatal(err)
	}
	dispatch, err := ClaimReadyWave(journal, "test-coordinator", now.Add(time.Minute), now)
	if err != nil {
		t.Fatal(err)
	}
	launcher := &coordinatorTestLauncher{t: t, journal: journal, now: func() time.Time { return now }}
	if _, err := launcher.Launch(context.Background(), SwarmWorkerRequest{Format: localSwarmWorkerRequestFormat, StorageRoot: root, SwarmID: spec.SwarmID, StepID: dispatch.Claims[0].StepID, Owner: dispatch.Claims[0].Owner, Fence: dispatch.Claims[0].Fence}); err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewLocalSwarmCoordinator(Fixture{}, root, "test-coordinator", launcher, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.RunReadyWaves(context.Background(), journal); err != nil {
		t.Fatal(err)
	}
	launcher.mu.Lock()
	defer launcher.mu.Unlock()
	if len(launcher.launched) != 1 {
		t.Fatalf("committed step launched %d times, want 1", len(launcher.launched))
	}
}

func TestLocalSwarmCoordinatorExpiresThenMigratesOnce(t *testing.T) {
	openedAt := swarmJournalTestTime.Add(3 * time.Hour)
	resumeAt := openedAt.Add(2 * time.Minute)
	root := t.TempDir()
	spec := reducerTestDurableSpec(t)
	spec.Steps[0].Candidates = []DurableWorkerCandidate{spec.Steps[0].Candidates[0], reducerTestCandidate(t, "agent://test/migration")}
	spec.Steps[0].AttemptPolicy = SwarmAttemptPolicy{MaxAttempts: 2}
	journal, err := OpenSwarmJournal(root, spec.SwarmID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenVerifiedSwarm(journal, spec, openedAt); err != nil {
		t.Fatal(err)
	}
	if _, _, err := RecordNextReadyWave(journal, openedAt); err != nil {
		t.Fatal(err)
	}
	if _, err := ClaimReadyWave(journal, "crashed-coordinator", openedAt.Add(time.Second), openedAt); err != nil {
		t.Fatal(err)
	}
	launcher := &coordinatorTestLauncher{t: t, journal: journal, now: func() time.Time { return resumeAt }}
	coordinator, err := NewLocalSwarmCoordinator(Fixture{}, root, "resumed-coordinator", launcher, func() time.Time { return resumeAt })
	if err != nil {
		t.Fatal(err)
	}
	view, err := coordinator.RunReadyWaves(context.Background(), journal)
	if err != nil {
		t.Fatal(err)
	}
	if view.Status != SwarmStatusCompleted || view.Steps[0].Attempts != 2 || len(view.Steps[0].Observations) < 3 {
		t.Fatalf("migration state = %#v, want one expiry then second-attempt completion", view.Steps[0])
	}
	if view.Steps[0].Observations[1].Outcome != "expired" || view.Steps[0].Observations[2].Attempt != 2 {
		t.Fatalf("migration observations = %#v", view.Steps[0].Observations)
	}
}

func TestLocalSwarmCoordinatorFailsWhenExpiredAttemptBudgetIsExhausted(t *testing.T) {
	openedAt := swarmJournalTestTime.Add(4 * time.Hour)
	root := t.TempDir()
	spec := reducerTestDurableSpec(t)
	journal, err := OpenSwarmJournal(root, spec.SwarmID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenVerifiedSwarm(journal, spec, openedAt); err != nil {
		t.Fatal(err)
	}
	if _, _, err := RecordNextReadyWave(journal, openedAt); err != nil {
		t.Fatal(err)
	}
	if _, err := ClaimReadyWave(journal, "crashed-coordinator", openedAt.Add(time.Second), openedAt); err != nil {
		t.Fatal(err)
	}
	launcher := &coordinatorTestLauncher{t: t, journal: journal, now: func() time.Time { return openedAt.Add(2 * time.Minute) }}
	coordinator, err := NewLocalSwarmCoordinator(Fixture{}, root, "resumed-coordinator", launcher, launcher.now)
	if err != nil {
		t.Fatal(err)
	}
	view, err := coordinator.RunReadyWaves(context.Background(), journal)
	if err != nil {
		t.Fatal(err)
	}
	if view.Status != SwarmStatusFailed || len(view.Leases) != 0 || len(launcher.launched) != 0 {
		t.Fatalf("exhausted expiry must fail without relaunch: view=%#v launches=%d", view, len(launcher.launched))
	}
}

func TestLocalSwarmCoordinatorIgnoresDisconnectedCallerContext(t *testing.T) {
	now := swarmJournalTestTime.Add(5 * time.Hour)
	root := t.TempDir()
	spec := reducerTestDurableSpec(t)
	journal, err := OpenSwarmJournal(root, spec.SwarmID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenVerifiedSwarm(journal, spec, now); err != nil {
		t.Fatal(err)
	}
	launcher := &coordinatorTestLauncher{t: t, journal: journal, now: func() time.Time { return now }}
	coordinator, err := NewLocalSwarmCoordinator(Fixture{}, root, "test-coordinator", launcher, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	view, err := coordinator.RunReadyWaves(ctx, journal)
	if err != nil || view.Status != SwarmStatusCompleted {
		t.Fatalf("disconnected caller cancelled local work: view=%#v err=%v", view, err)
	}
}

func TestLocalSwarmCoordinatorExcludesConcurrentExecutors(t *testing.T) {
	now := swarmJournalTestTime.Add(6 * time.Hour)
	root := t.TempDir()
	spec := reducerTestDurableSpec(t)
	journal, err := OpenSwarmJournal(root, spec.SwarmID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenVerifiedSwarm(journal, spec, now); err != nil {
		t.Fatal(err)
	}
	launcher := &coordinatorTestLauncher{t: t, journal: journal, now: func() time.Time { return now }}
	coordinator, err := NewLocalSwarmCoordinator(Fixture{}, root, "test-coordinator", launcher, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	errs := make(chan error, 2)
	for range 2 {
		go func() {
			_, err := coordinator.RunReadyWaves(context.Background(), journal)
			errs <- err
		}()
	}
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	launcher.mu.Lock()
	defer launcher.mu.Unlock()
	if len(launcher.launched) != 1 {
		t.Fatalf("concurrent coordinators launched %d workers, want one", len(launcher.launched))
	}
}

type blockingCoordinatorLauncher struct {
	started chan struct{}
	release <-chan struct{}

	mu       sync.Mutex
	active   int
	maximum  int
	finished int
}

func (l *blockingCoordinatorLauncher) Launch(_ context.Context, _ SwarmWorkerRequest) (SwarmWorkerResult, error) {
	l.mu.Lock()
	l.active++
	if l.active > l.maximum {
		l.maximum = l.active
	}
	l.mu.Unlock()
	l.started <- struct{}{}
	<-l.release
	l.mu.Lock()
	l.active--
	l.finished++
	l.mu.Unlock()
	return SwarmWorkerResult{}, nil
}

func TestLocalSwarmCoordinatorBoundsOwnedLaunchesAndReapsThem(t *testing.T) {
	now := swarmJournalTestTime.Add(7 * time.Hour)
	root := t.TempDir()
	base := reducerTestDurableSpec(t)
	spec := base
	spec.Steps = make([]DurableSwarmStepSpec, 0, maxLocalSwarmReadyWaveWidth)
	for i := range maxLocalSwarmReadyWaveWidth {
		spec.Steps = append(spec.Steps, DurableSwarmStepSpec{
			StepID:        fmt.Sprintf("parallel-%02d", i),
			TaskDigest:    base.Steps[0].TaskDigest,
			Capability:    base.Steps[0].Capability,
			Candidates:    base.Steps[0].Candidates,
			AttemptPolicy: SwarmAttemptPolicy{MaxAttempts: 1},
		})
	}
	journal, err := OpenSwarmJournal(root, spec.SwarmID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenVerifiedSwarm(journal, spec, now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := RecordNextReadyWave(journal, now); err != nil {
		t.Fatal(err)
	}
	dispatch, err := ClaimReadyWave(journal, "test-coordinator", now.Add(time.Minute), now)
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	launcher := &blockingCoordinatorLauncher{started: make(chan struct{}, maxLocalSwarmReadyWaveWidth), release: release}
	coordinator, err := NewLocalSwarmCoordinator(Fixture{}, root, "test-coordinator", launcher, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.launchAll(journal, dispatch); err != nil {
		t.Fatal(err)
	}
	for range maxLocalSwarmReadyWaveWidth {
		select {
		case <-launcher.started:
		case <-time.After(time.Second):
			t.Fatal("allowed ready wave did not launch concurrently")
		}
	}
	launcher.mu.Lock()
	if launcher.maximum > maxLocalSwarmReadyWaveWidth {
		launcher.mu.Unlock()
		t.Fatalf("active launchers = %d, want at most %d", launcher.maximum, maxLocalSwarmReadyWaveWidth)
	}
	launcher.mu.Unlock()
	close(release)
	done := make(chan struct{})
	go func() {
		coordinator.waitForLaunches()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("owned launchers did not finish after release")
	}
	launcher.mu.Lock()
	defer launcher.mu.Unlock()
	if launcher.active != 0 || launcher.finished != maxLocalSwarmReadyWaveWidth {
		t.Fatalf("launcher accounting active=%d finished=%d", launcher.active, launcher.finished)
	}
}

func TestLocalSwarmCoordinatorRejectsOversizedSignedSwarmBeforeOpeningJournal(t *testing.T) {
	fixturePath, runtimeKeys := managedRuntimeFixture(t, managedkey.KeyTypeSeed)
	fixture, err := loadManagedFixture(fixturePath, runtimeKeys)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(fixture.AuthorityPrivateKey)
	defer clear(fixture.Workers[0].PrivateKey)

	origin := fixture.Authority
	requester := fixture.Workers[0].Descriptor
	planSteps := make([]any, 0, maxLocalSwarmStepCount+1)
	bindingSteps := make([]any, 0, maxLocalSwarmStepCount+1)
	executableSteps := make([]any, 0, maxLocalSwarmStepCount+1)
	for i := 0; i <= maxLocalSwarmStepCount; i++ {
		stepID := fmt.Sprintf("step-%02d", i)
		planSteps = append(planSteps, map[string]any{"step_id": stepID, "capability": "summarize.text", "depends_on": []any{}})
		task := signBody(fixture.Workers[0].PrivateKey, map[string]any{
			"task_id": fmt.Sprintf("oversized-signed-swarm-%02d", i),
			"from":    requester["aid"],
			"to":      requester["alias"],
			"intent":  "Produce a bounded coordinator test result.",
		})
		bindingSteps = append(bindingSteps, map[string]any{"step_id": stepID, "depends_on": []any{}, "capability": "summarize.text", "task_digest": digestHex(task)})
		executableSteps = append(executableSteps, map[string]any{"step_id": stepID, "task": task})
	}
	swarmID := "swarm://test/oversized-signed"
	planDigest := digestHex(map[string]any{"intent": "Reject oversized signed swarm.", "steps": planSteps})
	plan := map[string]any{"type": "FED_SWARM_PLAN", "zone": origin, "plan": signBodyWithKey(fixture.AuthorityPrivateKey, map[string]any{
		"swarm_id": swarmID, "intent": "Reject oversized signed swarm.", "steps": planSteps, "policy_digest": strings.Repeat("a", 64), "plan_digest": planDigest,
	}, "plan_signature")}
	binding := signBodyWithKey(fixture.AuthorityPrivateKey, map[string]any{
		"format": "asp-swarm-execution-binding/v1", "swarm_id": swarmID, "plan_digest": planDigest, "steps": bindingSteps,
		"execution_graph_digest": digestHex(map[string]any{"swarm_id": swarmID, "plan_digest": planDigest, "steps": bindingSteps}),
	}, "binding_signature")
	request := map[string]any{
		"type": "FED_SWARM_OPEN", "origin_zone": origin, "requester": requester,
		"requester_zone_binding": signBodyWithKey(fixture.AuthorityPrivateKey, map[string]any{"zone": origin["zid"], "alias": requester["alias"], "aid": requester["aid"]}, "signature"),
		"swarm": map[string]any{"swarm_id": swarmID, "plan": plan, "execution_binding": binding, "steps": executableSteps},
	}
	root := t.TempDir()
	coordinator, err := NewLocalSwarmCoordinator(fixture, root, "test-coordinator", nil, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.OpenAndRun(context.Background(), origin, request); err == nil || !strings.Contains(err.Error(), "swarm step count exceeds maximum") {
		t.Fatalf("OpenAndRun() error = %v, want oversized swarm rejection", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("oversized signed preflight opened a journal: %#v", entries)
	}
}
