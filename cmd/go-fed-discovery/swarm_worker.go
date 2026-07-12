package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

const (
	localSwarmWorkerRequestFormat   = "agnet-local-swarm-worker-request/v1"
	localSwarmWorkerResultFormat    = "agnet-local-swarm-worker-result/v1"
	localSwarmWorkerMaxMessageBytes = 64 << 10
	localSwarmWorkerWaitDelay       = 2 * time.Second
)

// SwarmWorkerRequest is the entire parent-to-child protocol. It deliberately
// contains only routing and fence identity; the child recovers all authority
// (including generation pins) from the authoritative journal.
type SwarmWorkerRequest struct {
	Format      string     `json:"format"`
	StorageRoot string     `json:"storage_root"`
	SwarmID     string     `json:"swarm_id"`
	StepID      string     `json:"step_id"`
	Owner       string     `json:"owner"`
	Fence       LeaseFence `json:"fence"`
}

// SwarmWorkerResult is bounded canonical metadata. Result and transcript bytes
// never cross the child protocol; they are staged under the journal authority.
type SwarmWorkerResult struct {
	Format        string     `json:"format"`
	SwarmID       string     `json:"swarm_id"`
	StepID        string     `json:"step_id"`
	Fence         LeaseFence `json:"fence"`
	ReceiptDigest string     `json:"receipt_digest"`
}

func (request SwarmWorkerRequest) validate() error {
	if request.Format != localSwarmWorkerRequestFormat || request.StorageRoot == "" || !filepath.IsAbs(request.StorageRoot) || request.SwarmID == "" || request.StepID == "" || request.Owner == "" || request.Fence == 0 || hasSwarmDelimiter(request.StorageRoot) || hasSwarmDelimiter(request.SwarmID) || hasSwarmDelimiter(request.StepID) || hasSwarmDelimiter(request.Owner) {
		return errors.New("local swarm worker request invalid")
	}
	return nil
}

func (result SwarmWorkerResult) validate() error {
	if result.Format != localSwarmWorkerResultFormat || result.SwarmID == "" || result.StepID == "" || result.Fence == 0 || !isHexDigest(result.ReceiptDigest) || hasSwarmDelimiter(result.SwarmID) || hasSwarmDelimiter(result.StepID) {
		return errors.New("local swarm worker result invalid")
	}
	return nil
}

func canonicalWorkerMessage(value any) ([]byte, error) {
	raw, err := canonicalJSON(value)
	if err != nil || len(raw) == 0 || len(raw) > localSwarmWorkerMaxMessageBytes {
		return nil, errors.New("local swarm worker message invalid")
	}
	return raw, nil
}

func (request SwarmWorkerRequest) MarshalCanonical() ([]byte, error) {
	if err := request.validate(); err != nil {
		return nil, err
	}
	return canonicalWorkerMessage(request)
}

func (result SwarmWorkerResult) MarshalCanonical() ([]byte, error) {
	if err := result.validate(); err != nil {
		return nil, err
	}
	return canonicalWorkerMessage(result)
}

func parseWorkerMessage(raw []byte, target any) error {
	if len(raw) == 0 || len(raw) > localSwarmWorkerMaxMessageBytes || !json.Valid(raw) || validateSwarmJSONNoDuplicateFields(raw) != nil {
		return errors.New("local swarm worker message invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil || ensureSwarmJSONEOF(decoder) != nil {
		return errors.New("local swarm worker message invalid")
	}
	canonical, err := canonicalWorkerMessage(target)
	if err != nil || !bytes.Equal(raw, canonical) {
		return errors.New("local swarm worker message noncanonical")
	}
	return nil
}

func ParseSwarmWorkerRequest(raw []byte) (SwarmWorkerRequest, error) {
	var request SwarmWorkerRequest
	if err := parseWorkerMessage(raw, &request); err != nil {
		return request, err
	}
	return request, request.validate()
}

func ParseSwarmWorkerResult(raw []byte) (SwarmWorkerResult, error) {
	var result SwarmWorkerResult
	if err := parseWorkerMessage(raw, &result); err != nil {
		return result, err
	}
	return result, result.validate()
}

type SwarmWorkerLauncher interface {
	Launch(context.Context, SwarmWorkerRequest) (SwarmWorkerResult, error)
}

type swarmWorkerCommand func(context.Context) (*exec.Cmd, error)

// ExecSwarmWorkerLauncher executes exactly this binary. It supplies request
// bytes through an anonymous pipe and captures bounded canonical metadata
// through another; it adds no environment variables and sends no secret path.
// runner is private solely to substitute a child process in package tests.
type ExecSwarmWorkerLauncher struct{ runner swarmWorkerCommand }

func defaultSwarmWorkerCommand(ctx context.Context) (*exec.Cmd, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, errors.New("local swarm worker executable unavailable")
	}
	return exec.CommandContext(ctx, executable, "--local-swarm-worker"), nil
}

func (launcher ExecSwarmWorkerLauncher) Launch(ctx context.Context, request SwarmWorkerRequest) (SwarmWorkerResult, error) {
	raw, err := request.MarshalCanonical()
	if err != nil {
		return SwarmWorkerResult{}, err
	}
	runner := launcher.runner
	if runner == nil {
		runner = defaultSwarmWorkerCommand
	}
	command, err := runner(ctx)
	if err != nil || command == nil {
		return SwarmWorkerResult{}, errors.New("local swarm worker executable unavailable")
	}
	command.Cancel = func() error {
		if command.Process == nil {
			return nil
		}
		return command.Process.Signal(syscall.SIGTERM)
	}
	command.WaitDelay = localSwarmWorkerWaitDelay
	stdin, err := command.StdinPipe()
	if err != nil {
		return SwarmWorkerResult{}, errors.New("local swarm worker pipe unavailable")
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		return SwarmWorkerResult{}, errors.New("local swarm worker pipe unavailable")
	}
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		return SwarmWorkerResult{}, errors.New("local swarm worker start failed")
	}
	if _, err := stdin.Write(raw); err != nil {
		_ = stdin.Close()
		_ = command.Wait()
		return SwarmWorkerResult{}, errors.New("local swarm worker request failed")
	}
	if err := stdin.Close(); err != nil {
		_ = command.Wait()
		return SwarmWorkerResult{}, errors.New("local swarm worker request failed")
	}
	resultRaw, readErr := io.ReadAll(io.LimitReader(stdout, localSwarmWorkerMaxMessageBytes+1))
	waitErr := command.Wait()
	if readErr != nil || len(resultRaw) > localSwarmWorkerMaxMessageBytes || waitErr != nil {
		return SwarmWorkerResult{}, errors.New("local swarm worker failed")
	}
	result, err := ParseSwarmWorkerResult(resultRaw)
	if err != nil {
		return SwarmWorkerResult{}, err
	}
	if err := verifyCommittedWorkerResult(request, result); err != nil {
		return SwarmWorkerResult{}, err
	}
	return result, nil
}

func verifyCommittedWorkerResult(request SwarmWorkerRequest, result SwarmWorkerResult) error {
	if result.SwarmID != request.SwarmID || result.StepID != request.StepID || result.Fence != request.Fence {
		return errors.New("local swarm worker result does not match request")
	}
	journal, err := OpenSwarmJournal(request.StorageRoot, request.SwarmID)
	if err != nil {
		return errors.New("local swarm worker journal unavailable")
	}
	entries, err := journal.Replay()
	if err != nil {
		return errors.New("local swarm worker journal unavailable")
	}
	if _, err := ReduceSwarmEntries(entries); err != nil {
		return errors.New("local swarm worker journal unavailable")
	}
	for _, entry := range entries {
		if entry.Kind != "receipt.committed" {
			continue
		}
		var payload receiptCommittedPayload
		if err := decodeStrictSwarmPayload(entry.Payload, &payload); err != nil {
			return errors.New("local swarm worker journal unavailable")
		}
		if payload.Claim.StepID != request.StepID || payload.Claim.Owner != request.Owner || payload.Claim.Fence != request.Fence || payload.ReceiptDigest != result.ReceiptDigest {
			continue
		}
		if err := payload.validateCanonical(); err != nil || !validArtifactTriple(payload.Result) {
			return errors.New("local swarm worker journal unavailable")
		}
		return nil
	}
	return errors.New("local swarm worker result is not committed")
}

// LocalSwarmWorkerDeps is deliberately injectable for deterministic tests. In
// production the child obtains its adapter from the selected local runtime.
type LocalSwarmWorkerDeps struct {
	Adapter   DockerAdapter
	Now       func() time.Time
	LeaseTTL  time.Duration
	Heartbeat time.Duration
}

func (deps LocalSwarmWorkerDeps) normalized() (LocalSwarmWorkerDeps, error) {
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if deps.LeaseTTL <= 0 {
		deps.LeaseTTL = 30 * time.Second
	}
	if deps.Heartbeat <= 0 {
		deps.Heartbeat = deps.LeaseTTL / 3
	}
	if deps.Heartbeat <= 0 || deps.Heartbeat >= deps.LeaseTTL/2 {
		return deps, errors.New("local swarm worker heartbeat must be below half ttl")
	}
	return deps, nil
}

// StartLeaseHeartbeat renews only an exact live lease. Any renewal error
// cancels execution, so an expired/stale/stopped child cannot publish.
func StartLeaseHeartbeat(parent context.Context, journal *SwarmJournal, claim LeaseClaim, ttl, interval time.Duration, now func() time.Time) (context.Context, context.CancelFunc, <-chan error) {
	ctx, cancel := context.WithCancel(parent)
	errs := make(chan error, 1)
	if journal == nil || !validLeaseClaim(claim) || ttl <= 0 || interval <= 0 || interval >= ttl/2 || now == nil {
		errs <- errors.New("lease heartbeat invalid")
		cancel()
		close(errs)
		return ctx, cancel, errs
	}
	go func() {
		defer close(errs)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		live := claim
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				at := now().UTC()
				renewed, err := RenewLease(journal, live.StepID, live.Owner, live.Fence, at.Add(ttl), at)
				if err != nil {
					errs <- errors.New("lease heartbeat renewal failed")
					cancel()
					return
				}
				live = renewed
			}
		}
	}()
	return ctx, cancel, errs
}

func exactLiveClaim(journal *SwarmJournal, request SwarmWorkerRequest) (SwarmState, LeaseClaim, error) {
	entries, err := journal.Replay()
	if err != nil {
		return SwarmState{}, LeaseClaim{}, err
	}
	state, err := ReduceSwarmEntries(entries)
	if err != nil {
		return SwarmState{}, LeaseClaim{}, err
	}
	for _, claim := range state.Leases {
		if claim.StepID == request.StepID && claim.Owner == request.Owner && claim.Fence == request.Fence {
			return state, claim, nil
		}
	}
	return SwarmState{}, LeaseClaim{}, errors.New("local swarm worker lease is not live")
}

func localWorkerProfile(candidate DurableWorkerCandidate) (WorkerProfile, error) {
	if candidate.Runtime == nil {
		return WorkerProfile{}, errors.New("local swarm worker runtime missing")
	}
	profile := *candidate.Runtime
	if profile.KeyFile != "" || profile.KeyStore != "" || profile.PassphraseFile != "" || profile.KeyGeneration != (WorkerGenerationPin{}) {
		return WorkerProfile{}, errors.New("local swarm worker runtime must not carry key material")
	}
	if profile.SandboxClaim != "container-namespace" || profile.Docker == nil {
		return WorkerProfile{}, errors.New("local swarm worker requires container runtime")
	}
	if _, err := validateDockerWorkerProfile(*profile.Docker); err != nil {
		return WorkerProfile{}, err
	}
	return profile, nil
}

type localDockerCommandRunner struct{}

func (localDockerCommandRunner) Run(ctx context.Context, command DockerCommand) ([]byte, error) {
	process := exec.CommandContext(ctx, command.Path, command.Args...)
	process.Env = append([]string(nil), command.Env...)
	process.Stdin = bytes.NewReader(command.Stdin)
	return process.CombinedOutput()
}

func localWorkerAdapter(runtimeKind string) (DockerAdapter, error) {
	switch runtimeKind {
	case "apple-container":
		home, err := os.UserHomeDir()
		if err != nil || !filepath.IsAbs(home) {
			return nil, errors.New("local swarm worker Apple runtime unavailable")
		}
		return newAppleContainerCLIAdapter(appleContainerExecRunner{}, home), nil
	case "docker":
		host := DockerHost{CommandPath: dockerCommandPath, SocketPath: dockerLocalUnixSocket, Environment: dockerSanitizedEnvironment,
			BinaryDigest: func(path string) (string, error) {
				data, err := os.ReadFile(path)
				if err != nil {
					return "", err
				}
				hash := sha256.Sum256(data)
				return fmt.Sprintf("%x", hash[:]), nil
			},
			SocketIdentity: func(path string) (DockerSocketIdentity, error) {
				info, err := os.Stat(path)
				if err != nil {
					return DockerSocketIdentity{}, err
				}
				stat, ok := info.Sys().(*syscall.Stat_t)
				if !ok {
					return DockerSocketIdentity{}, errors.New("docker socket identity unavailable")
				}
				return DockerSocketIdentity{Device: uint64(stat.Dev), Inode: stat.Ino, Mode: uint32(stat.Mode), UID: stat.Uid}, nil
			},
		}
		return NewDockerCLIAdapter(localDockerCommandRunner{}, host)
	default:
		return nil, errors.New("local swarm worker runtime unavailable")
	}
}

func loadPinnedWorkerForClaim(claim LeaseClaim) (ed25519.PrivateKey, error) {
	loaded, err := loadVerifiedKeyGeneration(claim.Candidate.GenerationPin.StorePath, claim.Candidate.GenerationPin.RecordDigest, claim.Candidate.GenerationPin.PassphraseFile)
	if err != nil {
		return nil, errors.New("local swarm worker pinned key unavailable")
	}
	defer clear(loaded.Plaintext)
	if loaded.KeyGeneration.RecordDigest != claim.Candidate.GenerationPin.RecordDigest || loaded.KeyGeneration.DescriptorDigest != claim.Candidate.DescriptorDigest || loaded.Identity.Kind != "aid" {
		clear(loaded.PrivateKey)
		return nil, errors.New("local swarm worker pinned key mismatch")
	}
	public := loaded.PrivateKey.Public().(ed25519.PublicKey)
	encoded, der, err := publicKeySPKI(public)
	if err != nil || encoded != claim.Candidate.PublicKeySPKI || aidFromSPKI(der) != claim.Candidate.AID {
		clear(loaded.PrivateKey)
		return nil, errors.New("local swarm worker pinned key mismatch")
	}
	return loaded.PrivateKey, nil
}

func localWorkerReceipt(state SwarmState, claim LeaseClaim, result StagedArtifact, auxiliary []StagedArtifact, key ed25519.PrivateKey) (StagedReceipt, error) {
	stepIndex := swarmStepIndex(state.Steps, claim.StepID)
	if stepIndex < 0 {
		return StagedReceipt{}, errors.New("local swarm worker step missing")
	}
	dependencies, err := committedDependencyTriples(state, stepIndex)
	if err != nil {
		return StagedReceipt{}, err
	}
	dependencyList := make([]receiptDependencyV2, 0, len(dependencies))
	for _, stepID := range state.Spec.Steps[stepIndex].DependsOn {
		dependencyList = append(dependencyList, receiptDependencyV2{StepID: stepID, Artifact: dependencies[stepID]})
	}
	auxiliaryTriples := make([]ArtifactTriple, len(auxiliary))
	for i := range auxiliary {
		auxiliaryTriples[i] = auxiliary[i].Triple()
	}
	auxiliaryValues := make([]any, len(auxiliaryTriples))
	for i := range auxiliaryTriples {
		auxiliaryValues[i] = map[string]any{"uri": auxiliaryTriples[i].URI, "sha256": auxiliaryTriples[i].SHA256, "manifest_hash": auxiliaryTriples[i].ManifestHash}
	}
	resultValue := map[string]any{"uri": result.Triple().URI, "sha256": result.Triple().SHA256, "manifest_hash": result.Triple().ManifestHash}
	body := map[string]any{"format": "agnet-receipt/v2", "swarm_id": state.Spec.SwarmID, "step_id": claim.StepID, "task_id": state.Spec.Steps[stepIndex].TaskID, "task_digest": state.Spec.Steps[stepIndex].TaskDigest, "graph_digest": digestBytesHex(state.Spec.Binding), "capability": claim.Capability, "worker_aid": claim.Candidate.AID, "worker_generation_pin": claim.Candidate.GenerationPin, "attempt": claim.Attempt, "fence": claim.Fence, "result": resultValue, "auxiliary": auxiliaryValues}
	if len(dependencyList) != 0 {
		body["dependencies"] = dependencyList
	}
	bodyRaw, err := canonicalJSON(body)
	if err != nil {
		return StagedReceipt{}, err
	}
	var normalizedBody map[string]any
	decoder := json.NewDecoder(bytes.NewReader(bodyRaw))
	decoder.UseNumber()
	if err := decoder.Decode(&normalizedBody); err != nil {
		return StagedReceipt{}, errors.New("local swarm worker receipt invalid")
	}
	if ensureSwarmJSONEOF(decoder) != nil {
		return StagedReceipt{}, errors.New("local swarm worker receipt invalid")
	}
	signed := signBodyWithKey(key, normalizedBody, "signature")
	raw, err := canonicalJSON(signed)
	if err != nil {
		return StagedReceipt{}, err
	}
	return StageReceipt(raw)
}

// RunLocalSwarmWorker replays the exact claim, reloads its pinned managed key,
// renews before half-TTL, executes only the container adapter, then stages and
// lease-fenced commits a v2 receipt.
func RunLocalSwarmWorker(ctx context.Context, request SwarmWorkerRequest, deps LocalSwarmWorkerDeps) (SwarmWorkerResult, error) {
	if err := request.validate(); err != nil {
		return SwarmWorkerResult{}, err
	}
	deps, err := deps.normalized()
	if err != nil {
		return SwarmWorkerResult{}, err
	}
	journal, err := OpenSwarmJournal(request.StorageRoot, request.SwarmID)
	if err != nil {
		return SwarmWorkerResult{}, err
	}
	state, claim, err := exactLiveClaim(journal, request)
	if err != nil {
		return SwarmWorkerResult{}, err
	}
	profile, err := localWorkerProfile(claim.Candidate)
	if err != nil {
		return SwarmWorkerResult{}, err
	}
	if deps.Adapter == nil {
		deps.Adapter, err = localWorkerAdapter(claim.Candidate.RuntimeKind)
		if err != nil {
			return SwarmWorkerResult{}, err
		}
	}
	key, err := loadPinnedWorkerForClaim(claim)
	if err != nil {
		return SwarmWorkerResult{}, err
	}
	defer clear(key)
	execution, stopHeartbeat, heartbeatErrs := StartLeaseHeartbeat(ctx, journal, claim, deps.LeaseTTL, deps.Heartbeat, deps.Now)
	defer stopHeartbeat()
	runRequest, err := validateDockerWorkerProfile(*profile.Docker)
	if err != nil {
		return SwarmWorkerResult{}, err
	}
	runResult, err := deps.Adapter.Run(execution, runRequest)
	if err != nil {
		return SwarmWorkerResult{}, errors.New("local swarm worker container execution failed")
	}
	select {
	case err := <-heartbeatErrs:
		if err != nil {
			return SwarmWorkerResult{}, err
		}
	default:
	}
	if err := execution.Err(); err != nil {
		return SwarmWorkerResult{}, errors.New("local swarm worker lease lost")
	}
	if len(runResult.Result) == 0 || runResult.MediaType == "" {
		return SwarmWorkerResult{}, errors.New("local swarm worker result invalid")
	}
	result, err := StageArtifact(journal, runResult.Result)
	if err != nil {
		return SwarmWorkerResult{}, err
	}
	auxiliary := []StagedArtifact{}
	if len(runResult.Transcript) != 0 {
		if runResult.TranscriptMediaType == "" {
			return SwarmWorkerResult{}, errors.New("local swarm worker transcript invalid")
		}
		transcript, err := StageArtifact(journal, runResult.Transcript)
		if err != nil {
			return SwarmWorkerResult{}, err
		}
		auxiliary = append(auxiliary, transcript)
	}
	// Re-read immediately before signing/committing so a stale worker always uses
	// the exact journal lease (and CommitReceipt remains the final fence).
	state, claim, err = exactLiveClaim(journal, request)
	if err != nil {
		return SwarmWorkerResult{}, err
	}
	receipt, err := localWorkerReceipt(state, claim, result, auxiliary, key)
	if err != nil {
		return SwarmWorkerResult{}, err
	}
	if _, err := CommitReceipt(journal, ReceiptCommit{Claim: claim, Receipt: receipt, Result: result, Auxiliary: auxiliary}, deps.Now().UTC()); err != nil {
		return SwarmWorkerResult{}, err
	}
	return SwarmWorkerResult{Format: localSwarmWorkerResultFormat, SwarmID: request.SwarmID, StepID: request.StepID, Fence: request.Fence, ReceiptDigest: receipt.Digest}, nil
}

// localSwarmWorkerMain is invoked by the hidden main mode. The production
// adapter is intentionally provided by the daemon setup; a standalone child
// never reconstructs authority from flags, argv, or environment additions.
func localSwarmWorkerMain(in io.Reader, out io.Writer, deps LocalSwarmWorkerDeps) error {
	raw, err := io.ReadAll(io.LimitReader(in, localSwarmWorkerMaxMessageBytes+1))
	if err != nil || len(raw) > localSwarmWorkerMaxMessageBytes {
		return errors.New("local swarm worker input invalid")
	}
	request, err := ParseSwarmWorkerRequest(raw)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	result, err := RunLocalSwarmWorker(ctx, request, deps)
	if err != nil {
		return err
	}
	encoded, err := result.MarshalCanonical()
	if err != nil {
		return err
	}
	_, err = out.Write(encoded)
	return err
}

var localSwarmWorkerDepsMu sync.RWMutex
var localSwarmWorkerDeps LocalSwarmWorkerDeps

func setLocalSwarmWorkerDeps(deps LocalSwarmWorkerDeps) {
	localSwarmWorkerDepsMu.Lock()
	localSwarmWorkerDeps = deps
	localSwarmWorkerDepsMu.Unlock()
}
func getLocalSwarmWorkerDeps() LocalSwarmWorkerDeps {
	localSwarmWorkerDepsMu.RLock()
	defer localSwarmWorkerDepsMu.RUnlock()
	return localSwarmWorkerDeps
}
