package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"agnet/internal/managedkey"
)

func TestLocalWorkerRequestCanonicalBoundedAndSecretFree(t *testing.T) {
    request := SwarmWorkerRequest{Format: localSwarmWorkerRequestFormat, StorageRoot: "/private/swarm", SwarmID: "swarm://test/worker", StepID: "prepare", Owner: "worker-a", Fence: 7}
    encoded, err := request.MarshalCanonical()
    if err != nil { t.Fatal(err) }
    if !bytes.Equal(encoded, []byte(`{"format":"agnet-local-swarm-worker-request/v1","storage_root":"/private/swarm","swarm_id":"swarm://test/worker","step_id":"prepare","owner":"worker-a","fence":7}`)) { t.Fatalf("request = %s", encoded) }
    if strings.Contains(string(encoded), "passphrase") || strings.Contains(string(encoded), "secret") { t.Fatalf("request exposes secret surface: %s", encoded) }
    if _, err := ParseSwarmWorkerRequest(append(encoded, '\n')); err == nil { t.Fatal("accepted noncanonical request") }
    oversized := request
    oversized.StorageRoot = "/" + strings.Repeat("x", localSwarmWorkerMaxMessageBytes)
    if _, err := oversized.MarshalCanonical(); err == nil { t.Fatal("accepted oversized request") }
}

func TestLocalWorkerLauncherUsesPipesOnly(t *testing.T) {
	launcher := ExecSwarmWorkerLauncher{runner: func(ctx context.Context) (*exec.Cmd, error) {
		return exec.CommandContext(ctx, "/bin/false"), nil
	}}
	_, err := launcher.Launch(context.Background(), SwarmWorkerRequest{Format: localSwarmWorkerRequestFormat, StorageRoot: "/private/swarm", SwarmID: "swarm://test/worker", StepID: "prepare", Owner: "worker-a", Fence: 7})
	if err == nil { t.Fatal("false helper unexpectedly succeeded") }
	if strings.Contains(err.Error(), "passphrase") { t.Fatalf("launcher error leaks secret surface: %v", err) }
}

func TestLocalWorkerLauncherRejectsForgedChildMetadata(t *testing.T) {
	t.Setenv("AGNET_CONTAINER_RUNTIME", "docker")
	fixturePath, runtimeKeys := managedRuntimeFixture(t, managedkey.KeyTypeSeed)
	fixture, err := loadManagedFixture(fixturePath, runtimeKeys)
	if err != nil { t.Fatal(err) }
	candidate, err := durableCandidateForWorker(&fixture.Workers[0])
	if err != nil { t.Fatal(err) }
	profile := WorkerProfile{SandboxClaim: "container-namespace", Docker: new(testDockerReceiptProfile())}
	candidate.Runtime, candidate.RuntimeKind = &profile, "docker"
	journal := newTestSwarmJournal(t)
	now := time.Now().UTC()
	spec := reducerTestDurableSpec(t)
	spec.Steps[0].Candidates = []DurableWorkerCandidate{candidate}
	spec.Steps[0].TaskDigest, spec.Steps[0].Capability = strings.Repeat("a", 64), "analysis"
	if _, err := OpenVerifiedSwarm(journal, spec, now); err != nil { t.Fatal(err) }
	if _, _, err := RecordNextReadyWave(journal, now.Add(time.Millisecond)); err != nil { t.Fatal(err) }
	dispatch, err := ClaimReadyWave(journal, "forged-child-test", now.Add(time.Second), now.Add(2*time.Millisecond))
	if err != nil { t.Fatal(err) }
	request := SwarmWorkerRequest{Format: localSwarmWorkerRequestFormat, StorageRoot: filepath.Dir(filepath.Dir(journal.Path)), SwarmID: spec.SwarmID, StepID: dispatch.Claims[0].StepID, Owner: dispatch.Claims[0].Owner, Fence: dispatch.Claims[0].Fence}
	if _, err := RunLocalSwarmWorker(context.Background(), request, LocalSwarmWorkerDeps{Adapter: localWorkerTestAdapter{result: DockerRunResult{Result: []byte("authoritative result"), MediaType: "text/plain"}}, Now: time.Now, LeaseTTL: 300 * time.Millisecond, Heartbeat: 50 * time.Millisecond}); err != nil { t.Fatal(err) }
	forged, err := (SwarmWorkerResult{Format: localSwarmWorkerResultFormat, SwarmID: request.SwarmID, StepID: request.StepID, Fence: request.Fence, ReceiptDigest: strings.Repeat("b", 64)}).MarshalCanonical()
	if err != nil { t.Fatal(err) }
	launcher := ExecSwarmWorkerLauncher{runner: func(ctx context.Context) (*exec.Cmd, error) {
		command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLocalWorkerLauncherForgedChildProcess$", "--")
		command.Env = append(os.Environ(), "AGNET_SWARM_WORKER_FORGED_RESULT="+base64.RawURLEncoding.EncodeToString(forged))
		return command, nil
	}}
	if _, err := launcher.Launch(context.Background(), request); err == nil { t.Fatal("accepted forged canonical child metadata") }
}

func TestLocalWorkerLauncherForgedChildProcess(t *testing.T) {
	encoded := os.Getenv("AGNET_SWARM_WORKER_FORGED_RESULT")
	if encoded == "" { return }
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil { os.Exit(2) }
	if _, err := os.Stdout.Write(raw); err != nil { os.Exit(2) }
	os.Exit(0)
}

type localWorkerTestAdapter struct { result DockerRunResult; started chan struct{}; waitForCancel bool }

func (adapter localWorkerTestAdapter) Run(ctx context.Context, _ DockerRunRequest) (DockerRunResult, error) {
    if adapter.started != nil { close(adapter.started) }
    if adapter.waitForCancel { <-ctx.Done(); return DockerRunResult{}, ctx.Err() }
    return adapter.result, nil
}

type localWorkerCancellationAdapter struct { startedPath string; cleanedPath string }

func (adapter localWorkerCancellationAdapter) Run(ctx context.Context, _ DockerRunRequest) (DockerRunResult, error) {
	if err := os.WriteFile(adapter.startedPath, []byte("started"), 0o600); err != nil { return DockerRunResult{}, err }
	<-ctx.Done()
	if err := os.WriteFile(adapter.cleanedPath, []byte("cleaned"), 0o600); err != nil { return DockerRunResult{}, err }
	return DockerRunResult{}, ctx.Err()
}

func TestLocalWorkerLauncherCancellationReachesChild(t *testing.T) {
	t.Setenv("AGNET_CONTAINER_RUNTIME", "docker")
	fixturePath, runtimeKeys := managedRuntimeFixture(t, managedkey.KeyTypeSeed)
	fixture, err := loadManagedFixture(fixturePath, runtimeKeys)
	if err != nil { t.Fatal(err) }
	candidate, err := durableCandidateForWorker(&fixture.Workers[0])
	if err != nil { t.Fatal(err) }
	profile := WorkerProfile{SandboxClaim: "container-namespace", Docker: new(testDockerReceiptProfile())}
	candidate.Runtime, candidate.RuntimeKind = &profile, "docker"
	journal := newTestSwarmJournal(t)
	now := time.Now().UTC()
	spec := reducerTestDurableSpec(t)
	spec.Steps[0].Candidates = []DurableWorkerCandidate{candidate}
	spec.Steps[0].TaskDigest, spec.Steps[0].Capability = strings.Repeat("a", 64), "analysis"
	if _, err := OpenVerifiedSwarm(journal, spec, now); err != nil { t.Fatal(err) }
	if _, _, err := RecordNextReadyWave(journal, now.Add(time.Millisecond)); err != nil { t.Fatal(err) }
	dispatch, err := ClaimReadyWave(journal, "cancellation-test", now.Add(time.Second), now.Add(2*time.Millisecond))
	if err != nil { t.Fatal(err) }
	request := SwarmWorkerRequest{Format: localSwarmWorkerRequestFormat, StorageRoot: filepath.Dir(filepath.Dir(journal.Path)), SwarmID: spec.SwarmID, StepID: dispatch.Claims[0].StepID, Owner: dispatch.Claims[0].Owner, Fence: dispatch.Claims[0].Fence}
	startedPath := filepath.Join(t.TempDir(), "adapter-started")
	cleanedPath := filepath.Join(filepath.Dir(startedPath), "adapter-cleaned")
	launcher := ExecSwarmWorkerLauncher{runner: func(ctx context.Context) (*exec.Cmd, error) {
		command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLocalWorkerLauncherCancellationChildProcess$", "--")
		command.Env = append(os.Environ(), "AGNET_SWARM_WORKER_CANCELLATION_CHILD=1", "AGNET_SWARM_WORKER_STARTED_PATH="+startedPath, "AGNET_SWARM_WORKER_CLEANED_PATH="+cleanedPath)
		return command, nil
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := launcher.Launch(ctx, request); done <- err }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(startedPath); err == nil { break }
		if time.Now().After(deadline) { t.Fatal("child adapter did not start") }
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err == nil { t.Fatal("cancelled child unexpectedly succeeded") }
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled child did not exit within bound")
	}
	if _, err := os.Stat(cleanedPath); err != nil { t.Fatalf("child cleanup did not finish: %v", err) }
	entries, err := journal.Replay()
	if err != nil { t.Fatal(err) }
	state, err := ReduceSwarmEntries(entries)
	if err != nil { t.Fatal(err) }
	if state.Steps[0].Status != SwarmStepStatusRunning { t.Fatalf("cancelled child committed step: %#v", state.Steps[0]) }
	for _, entry := range entries { if entry.Kind == "receipt.committed" { t.Fatal("cancelled child appended receipt commitment") } }
}

func TestLocalWorkerLauncherCancellationChildProcess(t *testing.T) {
	if os.Getenv("AGNET_SWARM_WORKER_CANCELLATION_CHILD") == "" { return }
	deps := LocalSwarmWorkerDeps{Adapter: localWorkerCancellationAdapter{startedPath: os.Getenv("AGNET_SWARM_WORKER_STARTED_PATH"), cleanedPath: os.Getenv("AGNET_SWARM_WORKER_CLEANED_PATH")}, Now: time.Now, LeaseTTL: 300 * time.Millisecond, Heartbeat: 50 * time.Millisecond}
	if err := localSwarmWorkerMain(os.Stdin, os.Stdout, deps); err == nil { os.Exit(2) }
	os.Exit(0)
}

func TestLocalWorkerCommitsDockerResultAndTranscript(t *testing.T) {
    t.Setenv("AGNET_CONTAINER_RUNTIME", "docker")
    fixturePath, runtimeKeys := managedRuntimeFixture(t, managedkey.KeyTypeSeed)
    fixture, err := loadManagedFixture(fixturePath, runtimeKeys)
    if err != nil { t.Fatal(err) }
    candidate, err := durableCandidateForWorker(&fixture.Workers[0])
    if err != nil { t.Fatal(err) }
    profile := WorkerProfile{SandboxClaim: "container-namespace", Docker: new(testDockerReceiptProfile())}
    candidate.Runtime, candidate.RuntimeKind = &profile, "docker"
    journal := newTestSwarmJournal(t)
    now := time.Now().UTC()
    spec := reducerTestDurableSpec(t)
    spec.Steps[0].Candidates = []DurableWorkerCandidate{candidate}
    spec.Steps[0].TaskDigest, spec.Steps[0].Capability = strings.Repeat("a", 64), "analysis"
    if _, err := OpenVerifiedSwarm(journal, spec, now); err != nil { t.Fatal(err) }
    if _, _, err := RecordNextReadyWave(journal, now.Add(time.Millisecond)); err != nil { t.Fatal(err) }
    dispatch, err := ClaimReadyWave(journal, "local-test", now.Add(time.Second), now.Add(2*time.Millisecond))
    if err != nil { t.Fatal(err) }
    adapter := localWorkerTestAdapter{result: DockerRunResult{Result: []byte("docker result"), MediaType: "text/plain", Transcript: []byte("docker transcript"), TranscriptMediaType: "text/plain"}}
    result, err := RunLocalSwarmWorker(context.Background(), SwarmWorkerRequest{Format: localSwarmWorkerRequestFormat, StorageRoot: filepath.Dir(filepath.Dir(journal.Path)), SwarmID: spec.SwarmID, StepID: dispatch.Claims[0].StepID, Owner: dispatch.Claims[0].Owner, Fence: dispatch.Claims[0].Fence}, LocalSwarmWorkerDeps{Adapter: adapter, Now: time.Now, LeaseTTL: 300 * time.Millisecond, Heartbeat: 50 * time.Millisecond})
    if err != nil { t.Fatal(err) }
    if result.Format != localSwarmWorkerResultFormat || result.ReceiptDigest == "" { t.Fatalf("result = %#v", result) }
    state, _, err := exactLiveClaim(journal, SwarmWorkerRequest{Format: localSwarmWorkerRequestFormat, StorageRoot: filepath.Dir(filepath.Dir(journal.Path)), SwarmID: spec.SwarmID, StepID: dispatch.Claims[0].StepID, Owner: dispatch.Claims[0].Owner, Fence: dispatch.Claims[0].Fence})
    if err == nil || state.Version != 0 { t.Fatal("committed worker retained a live lease") }
    entries, err := journal.Replay(); if err != nil { t.Fatal(err) }
    committed, err := ReduceSwarmEntries(entries); if err != nil || committed.Steps[0].Status != SwarmStepStatusCompleted { t.Fatalf("commit = %#v, %v", committed, err) }
}

func TestLocalWorkerHeartbeatPreventsExpiry(t *testing.T) {
    journal := newTestSwarmJournal(t)
    now := time.Now().UTC()
    if _, err := OpenVerifiedSwarm(journal, reducerTestDurableSpec(t), now); err != nil { t.Fatal(err) }
    if _, _, err := RecordNextReadyWave(journal, now.Add(time.Millisecond)); err != nil { t.Fatal(err) }
    dispatch, err := ClaimReadyWave(journal, "heartbeat", now.Add(80*time.Millisecond), now.Add(2*time.Millisecond)); if err != nil { t.Fatal(err) }
    _, stop, errs := StartLeaseHeartbeat(context.Background(), journal, dispatch.Claims[0], 80*time.Millisecond, 15*time.Millisecond, time.Now)
    defer stop()
    time.Sleep(100 * time.Millisecond)
    select { case err := <-errs: if err != nil { t.Fatalf("heartbeat = %v", err) }; default: }
    state, err := ExpireLeases(journal, time.Now().UTC()); if err != nil { t.Fatal(err) }
    if len(state.Leases) != 1 { t.Fatalf("heartbeat lease expired: %#v", state.Leases) }
}
