package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"agnet/verifier"
)

const u30ProcessHelperEnv = "AGNET_U30_PROCESS_HELPER"

type u30ChildProcess struct {
	cmd    *exec.Cmd
	output bytes.Buffer
}

func TestTwoProcessClaimHasOneWinner(t *testing.T) {
	if os.Getenv(u30ProcessHelperEnv) != "" {
		u30RunProcessHelper(t)
		return
	}

	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	spec := reducerTestDurableSpec(t)
	journal, err := OpenSwarmJournal(root, spec.SwarmID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenVerifiedSwarm(journal, spec, swarmJournalTestTime); err != nil {
		t.Fatal(err)
	}
	if _, _, err := RecordNextReadyWave(journal, swarmJournalTestTime.Add(time.Second)); err != nil {
		t.Fatal(err)
	}

	release := filepath.Join(root, "claim-release")
	children := []*u30ChildProcess{
		u30StartProcess(t, "claim", "AGNET_U30_ROOT="+root, "AGNET_U30_SWARM="+spec.SwarmID, "AGNET_U30_MARKER="+filepath.Join(root, "claim-a"), "AGNET_U30_RELEASE="+release, "AGNET_U30_OWNER=worker-a"),
		u30StartProcess(t, "claim", "AGNET_U30_ROOT="+root, "AGNET_U30_SWARM="+spec.SwarmID, "AGNET_U30_MARKER="+filepath.Join(root, "claim-b"), "AGNET_U30_RELEASE="+release, "AGNET_U30_OWNER=worker-b"),
	}
	for _, marker := range []string{filepath.Join(root, "claim-a"), filepath.Join(root, "claim-b")} {
		waitForFile(t, marker)
	}
	if err := os.WriteFile(release, []byte("release"), 0o600); err != nil {
		t.Fatal(err)
	}

	wins := 0
	outputs := make([]string, 0, len(children))
	for _, child := range children {
		if err := child.cmd.Wait(); err != nil {
			t.Fatalf("claim helper: %v: %s", err, child.output.String())
		}
		output := child.output.String()
		outputs = append(outputs, output)
		if strings.Contains(output, "result=win") {
			wins++
		}
	}
	entries := mustReplaySwarm(t, journal)
	state, err := ReduceSwarmEntries(entries)
	if err != nil {
		t.Fatal(err)
	}
	if wins != 1 || len(state.Leases) != 1 || state.Leases[0].Fence != 1 {
		t.Fatalf("two_process_winner=%d leases=%#v outputs=%q; want one winner and one fenced lease", wins, state.Leases, outputs)
	}
	t.Logf("two_process_winner=%d journal_sequence=%d fence=%d child_outputs=%q", wins, len(entries), state.Leases[0].Fence, outputs)
}

func TestReadyWaveWorkersOverlapInSeparateProcesses(t *testing.T) {
	if os.Getenv(u30ProcessHelperEnv) != "" {
		u30RunProcessHelper(t)
		return
	}
	root := t.TempDir()
	now := swarmJournalTestTime.Add(24 * time.Hour)
	spec := reducerTestDurableSpec(t)
	base := spec.Steps[0]
	spec.Steps = []DurableSwarmStepSpec{
		{StepID: "left", TaskDigest: base.TaskDigest, Capability: base.Capability, Candidates: base.Candidates, AttemptPolicy: SwarmAttemptPolicy{MaxAttempts: 1}},
		{StepID: "right", TaskDigest: base.TaskDigest, Capability: base.Capability, Candidates: base.Candidates, AttemptPolicy: SwarmAttemptPolicy{MaxAttempts: 1}},
		{StepID: "join", DependsOn: []string{"left", "right"}, TaskDigest: base.TaskDigest, Capability: base.Capability, Candidates: base.Candidates, AttemptPolicy: SwarmAttemptPolicy{MaxAttempts: 1}},
	}
	journal, err := OpenSwarmJournal(root, spec.SwarmID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenVerifiedSwarm(journal, spec, now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := RecordNextReadyWave(journal, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	dispatch, err := ClaimReadyWave(journal, "u30-overlap", now.Add(time.Minute), now.Add(2*time.Second))
	if err != nil || len(dispatch.Claims) != 2 {
		t.Fatalf("dispatch=%#v err=%v", dispatch, err)
	}

	release := filepath.Join(root, "overlap-release")
	children := make([]*u30ChildProcess, 0, len(dispatch.Claims))
	markers := make([]string, 0, len(dispatch.Claims))
	for _, claim := range dispatch.Claims {
		marker := filepath.Join(root, "overlap-"+claim.StepID)
		markers = append(markers, marker)
		children = append(children, u30StartProcess(t, "observe", "AGNET_U30_ROOT="+root, "AGNET_U30_SWARM="+spec.SwarmID, "AGNET_U30_STEP="+claim.StepID, "AGNET_U30_OWNER="+claim.Owner, "AGNET_U30_FENCE="+strconv.FormatUint(uint64(claim.Fence), 10), "AGNET_U30_AT="+now.Add(3*time.Second).Format(time.RFC3339Nano), "AGNET_U30_MARKER="+marker, "AGNET_U30_RELEASE="+release))
	}
	pids := make([]int, 0, len(markers))
	for _, marker := range markers {
		waitForFile(t, marker)
		raw, err := os.ReadFile(marker)
		if err != nil {
			t.Fatal(err)
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
		if err != nil || pid <= 0 {
			t.Fatalf("worker marker=%q pid=%d err=%v", raw, pid, err)
		}
		if err := syscall.Kill(pid, 0); err != nil {
			t.Fatalf("worker pid %d is not alive during overlap: %v", pid, err)
		}
		pids = append(pids, pid)
	}
	if pids[0] == pids[1] {
		t.Fatalf("overlap pids=%v; want distinct child processes", pids)
	}
	if err := os.WriteFile(release, []byte("release"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, child := range children {
		if err := child.cmd.Wait(); err != nil {
			t.Fatalf("overlap helper: %v: %s", err, child.output.String())
		}
	}
	entries := mustReplaySwarm(t, journal)
	observations := 0
	for _, entry := range entries {
		if entry.Kind == "lease.observed" {
			observations++
		}
	}
	if observations != 2 {
		t.Fatalf("overlap_pids=%v observations=%d journal_entries=%d", pids, observations, len(entries))
	}
	t.Logf("overlap_pids=%v ready_wave=%v observation_count=%d journal_sequence=%d", pids, dispatch.Wave.StepIDs, observations, len(entries))
}

func TestCrashReceiptSyncBeforeResponseReplaysExactlyOnce(t *testing.T) {
	if os.Getenv(u30ProcessHelperEnv) != "" {
		u30RunProcessHelper(t)
		return
	}
	root := t.TempDir()
	now := swarmJournalTestTime.Add(48 * time.Hour)
	_, spec, claim, result, receipt := u30ClaimedReceipt(t, root, now)
	marker := filepath.Join(root, "receipt-parent-sync")
	env := append(u30ReceiptHelperEnv(root, spec.SwarmID, claim.StepID, receipt, result, now.Add(3*time.Second)), "AGNET_U30_FAIL_POINT=parent_sync", "AGNET_U30_MARKER="+marker)
	child := u30StartProcess(t, "receipt", env...)
	waitForFile(t, marker)
	if err := child.cmd.Wait(); err != nil {
		t.Fatalf("receipt response-loss helper: %v: %s", err, child.output.String())
	}
	if !strings.Contains(child.output.String(), "commit_error=") {
		t.Fatalf("receipt helper did not report injected response loss: %q", child.output.String())
	}

	reopened, err := OpenSwarmJournal(root, spec.SwarmID)
	if err != nil {
		t.Fatal(err)
	}
	entries := mustReplaySwarm(t, reopened)
	if got := u30EntryCount(entries, "receipt.committed"); got != 1 {
		t.Fatalf("receipt sync replay count=%d entries=%#v", got, entries)
	}
	state, err := CommitReceipt(reopened, ReceiptCommit{Claim: claim, Receipt: receipt, Result: result}, now.Add(4*time.Second))
	if err != nil || state.Steps[0].Status != SwarmStepStatusCompleted {
		t.Fatalf("receipt exact replay state=%#v err=%v", state, err)
	}
	conflict := claim
	conflict.Fence++
	if _, err := CommitReceipt(reopened, ReceiptCommit{Claim: conflict, Receipt: receipt, Result: result}, now.Add(5*time.Second)); err == nil {
		t.Fatal("conflicting receipt replay was accepted")
	}
	t.Logf("receipt_replay_decision=idempotent conflict=rejected journal_sequence=%d receipt_digest=%s", len(entries), receipt.Digest)
}

func TestFailureInjectionReceiptSyncBarrierBlocksDependent(t *testing.T) {
	if os.Getenv(u30ProcessHelperEnv) != "" {
		u30RunProcessHelper(t)
		return
	}
	root := t.TempDir()
	now := swarmJournalTestTime.Add(60 * time.Hour)
	spec := reducerTestDurableSpec(t)
	base := spec.Steps[0]
	spec.Steps = []DurableSwarmStepSpec{
		{StepID: "prepare", TaskDigest: strings.Repeat("a", 64), Capability: "analysis", Candidates: base.Candidates, AttemptPolicy: SwarmAttemptPolicy{MaxAttempts: 1}},
		{StepID: "publish", DependsOn: []string{"prepare"}, TaskDigest: strings.Repeat("b", 64), Capability: "analysis", Candidates: base.Candidates, AttemptPolicy: SwarmAttemptPolicy{MaxAttempts: 1}},
	}
	journal, err := OpenSwarmJournal(root, spec.SwarmID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenVerifiedSwarm(journal, spec, now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := RecordNextReadyWave(journal, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	dispatch, err := ClaimReadyWave(journal, "u30-sync", now.Add(time.Minute), now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	claim := dispatch.Claims[0]
	result, err := StageArtifact(journal, []byte("u30 sync barrier result"))
	if err != nil {
		t.Fatal(err)
	}
	receipt := u22Receipt(t, spec, claim, result)
	marker, release := filepath.Join(root, "receipt-before-sync"), filepath.Join(root, "receipt-sync-release")
	env := append(u30ReceiptHelperEnv(root, spec.SwarmID, claim.StepID, receipt, result, now.Add(3*time.Second)), "AGNET_U30_FAIL_POINT=file_sync", "AGNET_U30_MARKER="+marker, "AGNET_U30_RELEASE="+release)
	child := u30StartProcess(t, "receipt", env...)
	waitForFile(t, marker)
	type nextResult struct {
		wave ReadyWave
		err  error
	}
	next := make(chan nextResult, 1)
	go func() {
		_, wave, err := RecordNextReadyWave(journal, now.Add(4*time.Second))
		next <- nextResult{wave: wave, err: err}
	}()
	select {
	case got := <-next:
		t.Fatalf("dependent advanced before upstream sync: wave=%#v err=%v", got.wave, got.err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := os.WriteFile(release, []byte("release"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := child.cmd.Wait(); err != nil {
		t.Fatalf("receipt sync helper: %v: %s", err, child.output.String())
	}
	select {
	case got := <-next:
		if got.err != nil || len(got.wave.StepIDs) != 1 || got.wave.StepIDs[0] != "publish" {
			t.Fatalf("dependent wave after sync=%#v err=%v", got.wave, got.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("dependent did not unblock after upstream receipt sync")
	}
	entries := mustReplaySwarm(t, journal)
	if u30EntryCount(entries, "receipt.committed") != 1 {
		t.Fatalf("sync barrier receipt entries=%#v", entries)
	}
	t.Logf("dependency_sync_barrier=blocked_before_fsync_then_publish_ready journal_sequence=%d", len(entries))
}

func TestCrashWorkerObservationThenReclaimRejectsStaleCommit(t *testing.T) {
	if os.Getenv(u30ProcessHelperEnv) != "" {
		u30RunProcessHelper(t)
		return
	}
	root := t.TempDir()
	now := swarmJournalTestTime.Add(72 * time.Hour)
	spec := reducerTestDurableSpec(t)
	spec.Steps[0].TaskDigest, spec.Steps[0].Capability = strings.Repeat("a", 64), "analysis"
	spec.Steps[0].Candidates = []DurableWorkerCandidate{spec.Steps[0].Candidates[0], reducerTestCandidate(t, "agent://test/u30-reclaim")}
	spec.Steps[0].AttemptPolicy = SwarmAttemptPolicy{MaxAttempts: 2}
	journal, err := OpenSwarmJournal(root, spec.SwarmID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenVerifiedSwarm(journal, spec, now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := RecordNextReadyWave(journal, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	first, err := ClaimReadyWave(journal, "u30-stale", now.Add(3*time.Second), now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	claim := first.Claims[0]
	result, err := StageArtifact(journal, []byte("stale staged result"))
	if err != nil {
		t.Fatal(err)
	}
	receipt := u22Receipt(t, spec, claim, result)
	marker := filepath.Join(root, "observation")
	release := filepath.Join(root, "observation-release")
	child := u30StartProcess(t, "observe", "AGNET_U30_ROOT="+root, "AGNET_U30_SWARM="+spec.SwarmID, "AGNET_U30_STEP="+claim.StepID, "AGNET_U30_OWNER="+claim.Owner, "AGNET_U30_FENCE="+strconv.FormatUint(uint64(claim.Fence), 10), "AGNET_U30_AT="+now.Add(2500*time.Millisecond).Format(time.RFC3339Nano), "AGNET_U30_MARKER="+marker, "AGNET_U30_RELEASE="+release)
	waitForFile(t, marker)
	if err := child.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := child.cmd.Wait(); err == nil {
		t.Fatal("observed worker unexpectedly survived forced crash")
	}
	if _, err := ExpireLeases(journal, now.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := RecordNextReadyWave(journal, now.Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	second, err := ClaimReadyWave(journal, "u30-reclaimer", now.Add(9*time.Second), now.Add(6*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if second.Claims[0].Fence <= claim.Fence {
		t.Fatalf("reclaim fence=%d stale_fence=%d", second.Claims[0].Fence, claim.Fence)
	}
	if _, err := CommitReceipt(journal, ReceiptCommit{Claim: claim, Receipt: receipt, Result: result}, now.Add(7*time.Second)); err == nil {
		t.Fatal("stale worker committed after reclaim")
	}
	if _, err := ReadCommittedArtifact(journal, result); !errors.Is(err, ErrArtifactNotCommitted) {
		t.Fatalf("stale artifact became visible: %v", err)
	}
	t.Logf("stale_fence_rejection=true stale_fence=%d reclaimed_fence=%d observation_pid_marker=%s", claim.Fence, second.Claims[0].Fence, marker)
}

func TestCrashMigrationThenFailureExhaustion(t *testing.T) {
	now := swarmJournalTestTime.Add(84 * time.Hour)
	journal := newTestSwarmJournal(t)
	spec := reducerTestDurableSpec(t)
	spec.Steps[0].Candidates = []DurableWorkerCandidate{spec.Steps[0].Candidates[0], reducerTestCandidate(t, "agent://test/u30-exhaustion")}
	spec.Steps[0].AttemptPolicy = SwarmAttemptPolicy{MaxAttempts: 2}
	if _, err := OpenVerifiedSwarm(journal, spec, now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := RecordNextReadyWave(journal, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	first, err := ClaimReadyWave(journal, "u30-first", now.Add(3*time.Second), now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ExpireLeases(journal, now.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := RecordNextReadyWave(journal, now.Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	second, err := ClaimReadyWave(journal, "u30-second", now.Add(8*time.Second), now.Add(6*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	state, err := ExpireLeases(journal, now.Add(9*time.Second))
	if err != nil || state.Status != SwarmStatusFailed || state.Steps[0].Attempts != 2 || second.Claims[0].Fence <= first.Claims[0].Fence {
		t.Fatalf("retry_migration_outcome state=%#v first=%#v second=%#v err=%v", state, first.Claims[0], second.Claims[0], err)
	}
	t.Logf("retry_migration_outcome=one_migration_then_failure attempts=%d fences=%d,%d", state.Steps[0].Attempts, first.Claims[0].Fence, second.Claims[0].Fence)
}

func TestReadyWaveInverseFinishOrderKeepsSignedEvidence(t *testing.T) {
	firstJournal, spec := newCloseTestJournal(t)
	commitCloseTestJournal(t, firstJournal, spec, false)
	secondJournal, _ := newCloseTestJournal(t)
	commitCloseTestJournal(t, secondJournal, spec, true)
	first, err := BuildSwarmCloseV2(firstJournal)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildSwarmCloseV2(secondJournal)
	if err != nil || !bytes.Equal(first.Bytes, second.Bytes) || first.Digest != second.Digest {
		t.Fatalf("inverse completion order changed signed close: first=%s second=%s err=%v", first.Digest, second.Digest, err)
	}
	t.Logf("ready_wave_order=stable signed_receipt_order=stable close_digest=%s", first.Digest)
}

func TestTwoProcessProofSubmittersCompleteAndDisbandOnce(t *testing.T) {
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
	coordinator, err := NewLocalSwarmCoordinator(Fixture{}, filepath.Dir(filepath.Dir(journal.Path)), "u30-proof-race", nil, func() time.Time { return swarmJournalTestTime })
	if err != nil {
		t.Fatal(err)
	}
	coordinator.outputVerificationTrust = verifier.TrustInputs{TrustInputsDigest: strings.Repeat("b", 64)}
	coordinator.outputVerifier = func(proof map[string]any, _ verifier.TrustInputs, frozen verifier.FrozenSwarmOutputEvidence, _ time.Time) (verifier.VerifiedSwarmOutput, error) {
		return verifier.VerifiedSwarmOutput{CloseDigest: frozen.StoredCloseDigest, ProofDigest: digestBytesHex(proofBodyBytes(proof)), TrustInputsDigest: strings.Repeat("b", 64), ProofBytes: proofBodyBytes(proof), FinalOutput: final, VerificationID: "u30-proof-race", VerifiedAt: "2026-07-12T13:14:16Z", VerifierAID: "agent://trusted/verifier", VerifierZone: "zone://trusted/verifier"}, nil
	}
	frame, err := canonicalJSON(map[string]any{"type": swarmOutputVerificationFrameType, "swarm_id": spec.SwarmID, "proof": map[string]any{"proof": map[string]any{"verification_id": "u30-proof-race"}}})
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		attempt OutputVerificationAttempt
		err     error
	}
	start, results := make(chan struct{}), make(chan result, 2)
	for range 2 {
		go func() {
			<-start
			attempt, err := coordinator.RecordOutputVerification(context.Background(), frame)
			results <- result{attempt, err}
		}()
	}
	close(start)
	accepted, idempotent := 0, 0
	for range 2 {
		got := <-results
		if got.err != nil {
			t.Fatal(got.err)
		}
		if got.attempt.Decision == "accepted" {
			accepted++
		}
		if got.attempt.Decision == "idempotent" {
			idempotent++
		}
	}
	if accepted != 1 || idempotent != 1 || u30EntryCount(mustReplaySwarm(t, journal), "output.verified") != 1 {
		t.Fatalf("verification_race_result accepted=%d idempotent=%d", accepted, idempotent)
	}
	if _, err := EnsureDisband(journal); err != nil {
		t.Fatal(err)
	}
	entries := mustReplaySwarm(t, journal)
	if u30EntryCount(entries, "swarm.disbanded") != 1 {
		t.Fatalf("disband_count=%d", u30EntryCount(entries, "swarm.disbanded"))
	}
	t.Logf("verification_race_result=one_completion disband_count=1 journal_sequence=%d", len(entries))
}

func TestFailureInjectionMatrixDurableEvidence(t *testing.T) {
	t.Run("stage_object_failure_keeps_orphan_hidden", func(t *testing.T) {
		journal := newTestSwarmJournal(t)
		if _, err := OpenVerifiedSwarm(journal, reducerTestDurableSpec(t), swarmJournalTestTime); err != nil {
			t.Fatal(err)
		}
		objects, err := swarmArtifactObjectsDir(journal)
		if err != nil {
			t.Fatal(err)
		}
		data := []byte("u30 stage fault")
		digest := digestBytesHex(data)
		if err := os.Mkdir(filepath.Join(objects, digest), 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := StageArtifact(journal, data); err == nil {
			t.Fatal("stage object collision was accepted")
		}
		entries := mustReplaySwarm(t, journal)
		if u30EntryCount(entries, "receipt.committed") != 0 {
			t.Fatalf("stage failure published journal entries=%#v", entries)
		}
		t.Logf("crash_matrix=stage journal_sequence=%d committed_receipts=0", len(entries))
	})
	t.Run("receipt_append_write_or_sync_restores_prior_chain", func(t *testing.T) {
		for _, point := range []SwarmFaultPoint{SwarmFaultWrite, SwarmFaultFileSync} {
			t.Run(string(point), func(t *testing.T) {
				root := t.TempDir()
				now := swarmJournalTestTime.Add(96 * time.Hour)
				journal, _, claim, result, receipt := u30ClaimedReceipt(t, root, now)
				before, err := os.ReadFile(journal.Path)
				if err != nil {
					t.Fatal(err)
				}
				injected := errors.New("u30 " + string(point))
				journal.fault = func(got SwarmFaultPoint) error {
					if got == point {
						return injected
					}
					return nil
				}
				if _, err := CommitReceipt(journal, ReceiptCommit{Claim: claim, Receipt: receipt, Result: result}, now.Add(3*time.Second)); !errors.Is(err, injected) {
					t.Fatalf("receipt %s error=%v", point, err)
				}
				journal.fault = nil
				after, err := os.ReadFile(journal.Path)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(before, after) || u30EntryCount(mustReplaySwarm(t, journal), "receipt.committed") != 0 {
					t.Fatalf("receipt %s did not restore chain", point)
				}
				t.Logf("crash_matrix=receipt_%s prior_chain_restored=true", point)
			})
		}
	})
	t.Run("view_replacement_replays_authoritative_journal", func(t *testing.T) {
		journal, _ := committedViewJournal(t)
		before := mustReplaySwarm(t, journal)
		materializer, err := NewSwarmMaterializer(journal, func(point SwarmViewFaultPoint) error {
			if point == SwarmViewFaultRename {
				return errors.New("u30 view rename")
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := materializer.Rebuild(); err == nil {
			t.Fatal("view rename fault unexpectedly rebuilt")
		}
		if _, err := ReadSwarmView(journal); err != nil {
			t.Fatal(err)
		}
		after := mustReplaySwarm(t, journal)
		if len(before) != len(after) || before[len(before)-1].Hash != after[len(after)-1].Hash {
			t.Fatal("projection fault changed journal authority")
		}
		t.Logf("crash_matrix=view_replacement journal_head=%s", after[len(after)-1].Hash)
	})
	t.Run("close_and_disband_append_faults_regenerate_identical_bytes", func(t *testing.T) {
		journal, spec := newCloseTestJournal(t)
		commitCloseTestJournal(t, journal, spec, false)
		closeCandidate, err := BuildSwarmCloseV2(journal)
		if err != nil {
			t.Fatal(err)
		}
		journal.fault = func(point SwarmFaultPoint) error {
			if point == SwarmFaultFileSync {
				return errors.New("u30 close sync")
			}
			return nil
		}
		if _, err := EnsureStableClose(journal); err == nil {
			t.Fatal("close sync fault unexpectedly stored close")
		}
		journal.fault = nil
		stored, err := EnsureStableClose(journal)
		if err != nil || !bytes.Equal(stored.Bytes, closeCandidate.Bytes) {
			t.Fatalf("close regeneration=%#v err=%v", stored, err)
		}
		disbandJournal, disbandSpec := newCloseTestJournal(t)
		completeDisbandTestJournal(t, disbandJournal, disbandSpec)
		disbandCandidate, err := BuildSwarmDisband(disbandJournal)
		if err != nil {
			t.Fatal(err)
		}
		disbandJournal.fault = func(point SwarmFaultPoint) error {
			if point == SwarmFaultFileSync {
				return errors.New("u30 disband sync")
			}
			return nil
		}
		if _, err := EnsureDisband(disbandJournal); err == nil {
			t.Fatal("disband sync fault unexpectedly stored disband")
		}
		disbandJournal.fault = nil
		disband, err := EnsureDisband(disbandJournal)
		if err != nil || !bytes.Equal(disband.Bytes, disbandCandidate.Bytes) {
			t.Fatalf("disband regeneration=%#v err=%v", disband, err)
		}
		t.Logf("crash_matrix=close,disband close_bytes_equal=true disband_bytes_equal=true")
	})
}

func u30ClaimedReceipt(t *testing.T, root string, now time.Time) (*SwarmJournal, DurableSwarmSpec, LeaseClaim, StagedArtifact, StagedReceipt) {
	t.Helper()
	spec := reducerTestDurableSpec(t)
	spec.Steps[0].TaskDigest, spec.Steps[0].Capability = strings.Repeat("a", 64), "analysis"
	journal, err := OpenSwarmJournal(root, spec.SwarmID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenVerifiedSwarm(journal, spec, now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := RecordNextReadyWave(journal, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	dispatch, err := ClaimReadyWave(journal, "u30-receipt", now.Add(time.Minute), now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	result, err := StageArtifact(journal, []byte("u30 receipt result"))
	if err != nil {
		t.Fatal(err)
	}
	receipt := u22Receipt(t, spec, dispatch.Claims[0], result)
	return journal, spec, dispatch.Claims[0], result, receipt
}

func u30ReceiptHelperEnv(root, swarmID, stepID string, receipt StagedReceipt, result StagedArtifact, at time.Time) []string {
	return []string{
		"AGNET_U30_ROOT=" + root, "AGNET_U30_SWARM=" + swarmID, "AGNET_U30_STEP=" + stepID,
		"AGNET_U30_RECEIPT=" + base64.RawURLEncoding.EncodeToString(receipt.Bytes), "AGNET_U30_RESULT_SHA=" + result.SHA256,
		"AGNET_U30_RESULT_SIZE=" + strconv.FormatUint(result.Size, 10), "AGNET_U30_AT=" + at.UTC().Format(time.RFC3339Nano),
	}
}

func u30StartProcess(t *testing.T, action string, env ...string) *u30ChildProcess {
	t.Helper()
	child := &u30ChildProcess{cmd: exec.Command(os.Args[0], "-test.run=^TestTwoProcessClaimHasOneWinner$", "-test.count=1")}
	child.cmd.Env = append(os.Environ(), append([]string{u30ProcessHelperEnv + "=" + action}, env...)...)
	child.cmd.Stdout, child.cmd.Stderr = &child.output, &child.output
	if err := child.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if child.cmd.Process != nil {
			_ = child.cmd.Process.Kill()
		}
	})
	return child
}

func u30RunProcessHelper(t *testing.T) {
	t.Helper()
	action := os.Getenv(u30ProcessHelperEnv)
	marker, release := os.Getenv("AGNET_U30_MARKER"), os.Getenv("AGNET_U30_RELEASE")
	writeMarker := func() {
		if marker != "" {
			if err := os.WriteFile(marker, []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	waitRelease := func() {
		if release != "" {
			if err := u30WaitForFile(release, 5*time.Second); err != nil {
				t.Fatal(err)
			}
		}
	}
	switch action {
	case "claim":
		writeMarker()
		waitRelease()
		journal, err := OpenSwarmJournal(os.Getenv("AGNET_U30_ROOT"), os.Getenv("AGNET_U30_SWARM"))
		if err != nil {
			t.Fatal(err)
		}
		_, err = ClaimReadyWave(journal, os.Getenv("AGNET_U30_OWNER"), time.Now().UTC().Add(time.Minute), time.Now().UTC())
		result := "lose"
		if err == nil {
			result = "win"
		}
		_, _ = fmt.Fprintf(os.Stdout, "pid=%d result=%s\n", os.Getpid(), result)
	case "observe":
		journal, err := OpenSwarmJournal(os.Getenv("AGNET_U30_ROOT"), os.Getenv("AGNET_U30_SWARM"))
		if err != nil {
			t.Fatal(err)
		}
		fence, err := strconv.ParseUint(os.Getenv("AGNET_U30_FENCE"), 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		entries := mustReplaySwarm(t, journal)
		state, err := ReduceSwarmEntries(entries)
		if err != nil {
			t.Fatal(err)
		}
		var claim LeaseClaim
		for _, candidate := range state.Leases {
			if candidate.StepID == os.Getenv("AGNET_U30_STEP") && candidate.Owner == os.Getenv("AGNET_U30_OWNER") && candidate.Fence == LeaseFence(fence) {
				claim = candidate
				break
			}
		}
		if !validLeaseClaim(claim) {
			t.Fatal("helper lease is not live")
		}
		at := time.Now().UTC()
		if encoded := os.Getenv("AGNET_U30_AT"); encoded != "" {
			parsed, err := time.Parse(time.RFC3339Nano, encoded)
			if err != nil {
				t.Fatal(err)
			}
			at = parsed
		}
		if err := RecordLeaseObservation(journal, claim, "worker_started", at); err != nil {
			t.Fatal(err)
		}
		writeMarker()
		waitRelease()
		_, _ = fmt.Fprintf(os.Stdout, "pid=%d observed=%s\n", os.Getpid(), claim.StepID)
	case "receipt":
		at, err := time.Parse(time.RFC3339Nano, os.Getenv("AGNET_U30_AT"))
		if err != nil {
			t.Fatal(err)
		}
		faultPoint, err := u30FaultPoint(os.Getenv("AGNET_U30_FAIL_POINT"))
		if err != nil {
			t.Fatal(err)
		}
		journal, err := OpenSwarmJournal(os.Getenv("AGNET_U30_ROOT"), os.Getenv("AGNET_U30_SWARM"), func(point SwarmFaultPoint) error {
			if point != faultPoint {
				return nil
			}
			writeMarker()
			if faultPoint == SwarmFaultFileSync {
				waitRelease()
				return nil
			}
			return errors.New("u30 injected " + string(point))
		})
		if err != nil {
			t.Fatal(err)
		}
		entries := mustReplaySwarm(t, journal)
		state, err := ReduceSwarmEntries(entries)
		if err != nil {
			t.Fatal(err)
		}
		var claim LeaseClaim
		for _, candidate := range state.Leases {
			if candidate.StepID == os.Getenv("AGNET_U30_STEP") {
				claim = candidate
				break
			}
		}
		if !validLeaseClaim(claim) {
			t.Fatal("receipt helper lease is not live")
		}
		raw, err := base64.RawURLEncoding.DecodeString(os.Getenv("AGNET_U30_RECEIPT"))
		if err != nil {
			t.Fatal(err)
		}
		receipt, err := StageReceipt(raw)
		if err != nil {
			t.Fatal(err)
		}
		size, err := strconv.ParseUint(os.Getenv("AGNET_U30_RESULT_SIZE"), 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		result := StagedArtifact{SHA256: os.Getenv("AGNET_U30_RESULT_SHA"), Size: size, Path: filepath.Join(filepath.Dir(journal.Path), "objects", os.Getenv("AGNET_U30_RESULT_SHA"))}
		_, err = CommitReceipt(journal, ReceiptCommit{Claim: claim, Receipt: receipt, Result: result}, at)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stdout, "pid=%d commit_error=%v\n", os.Getpid(), err)
			return
		}
		_, _ = fmt.Fprintf(os.Stdout, "pid=%d receipt=%s\n", os.Getpid(), receipt.Digest)
	default:
		t.Fatalf("unknown U30 helper action %q", action)
	}
}

func u30FaultPoint(value string) (SwarmFaultPoint, error) {
	if value == "" {
		return "", nil
	}
	for _, point := range []SwarmFaultPoint{SwarmFaultFileSync, SwarmFaultParentSync} {
		if value == string(point) {
			return point, nil
		}
	}
	return "", errors.New("unknown U30 fault point")
}

func u30WaitForFile(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		time.Sleep(5 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for %s", path)
}

func u30EntryCount(entries []SwarmJournalEntry, kind string) int {
	count := 0
	for _, entry := range entries {
		if entry.Kind == kind {
			count++
		}
	}
	return count
}
