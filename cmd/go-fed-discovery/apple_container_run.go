package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	appleContainerUser                 = "65532:65532"
	appleContainerUlimit               = "nofile=64:64"
	appleContainerNprocUlimit          = "nproc=64:64"
	appleContainerNetwork              = "none"
	appleContainerWorkdir              = "/work"
	appleContainerBindMountType        = "virtiofs"
	appleContainerResultPath           = "/work/result"
	appleContainerMinMemoryBytes int64 = 200 << 20
)

// appleContainerLifecycleRunner is the process boundary for mutable Apple
// Container CLI commands. Start receives distinct bounded stdout and stderr
// drains; all remaining commands return their small control output.
type appleContainerLifecycleRunner interface {
	Run(context.Context, string, ...string) ([]byte, error)
	Start(context.Context, string, []string, io.Writer, io.Writer) error
}

type appleContainerExecRunner struct{}

func (appleContainerExecRunner) Run(ctx context.Context, executable string, arguments ...string) ([]byte, error) {
	return exec.CommandContext(ctx, executable, arguments...).CombinedOutput()
}

func (appleContainerExecRunner) Start(ctx context.Context, executable string, arguments []string, stdout, stderr io.Writer) error {
	command := exec.CommandContext(ctx, executable, arguments...)
	command.Stdout = stdout
	command.Stderr = stderr
	return command.Run()
}

// Run mounts one agent-owned private workspace at /work and returns bytes only
// after the mounted directory has passed its postflight authority checks.
func (a *AppleContainerCLIAdapter) Run(ctx context.Context, request DockerRunRequest) (runResult DockerRunResult, runErr error) {
	if a == nil || a.runner == nil {
		return DockerRunResult{}, errors.New("apple container CLI adapter is not configured")
	}
	if err := validateAppleRunRequest(request); err != nil {
		return DockerRunResult{}, err
	}
	lifecycle := a.lifecycleRunner
	if lifecycle == nil {
		lifecycle = appleContainerExecRunner{}
	}
	before, err := a.Preflight(ctx, request.Image)
	if err != nil {
		return DockerRunResult{}, err
	}
	workspace, inputBytes, err := stageAppleWorkspace(request.ScratchInputs)
	if err != nil {
		return DockerRunResult{}, err
	}
	defer func() {
		if cleanupErr := removeAppleWorkspace(workspace); cleanupErr != nil && runErr == nil {
			runResult = DockerRunResult{}
			runErr = fmt.Errorf("remove apple private workspace: %w", cleanupErr)
		}
	}()
	workspaceIdentity, err := pinAppleWorkspace(workspace)
	if err != nil {
		return DockerRunResult{}, err
	}
	resultPath := filepath.Join(workspace, "result")
	resultIdentity, err := pinAppleStagedResult(resultPath)
	if err != nil {
		return DockerRunResult{}, err
	}
	if err := validateAppleWorkspace(workspace, request.ScratchInputs, inputBytes, request.MaxOutputBytes); err != nil {
		return DockerRunResult{}, err
	}

	newID := a.newContainerID
	if newID == nil {
		newID = newAppleContainerID
	}
	containerID, err := newID()
	if err != nil {
		return DockerRunResult{}, err
	}
	if err := validateAppleContainerID(containerID); err != nil {
		return DockerRunResult{}, err
	}
	cleanupArmed := true
	defer func() {
		if !cleanupArmed {
			return
		}
		cleanupContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cleanupErr := a.runLifecycle(cleanupContext, lifecycle, "container", "delete", "--force", containerID)
		if cleanupErr != nil && runErr == nil {
			runResult = DockerRunResult{}
			runErr = fmt.Errorf("force delete apple container %q: %w", containerID, cleanupErr)
		}
	}()

	if err := a.runLifecycle(ctx, lifecycle, append(appleContainerCreateArgs(request, containerID, workspace), request.Command...)...); err != nil {
		return DockerRunResult{}, fmt.Errorf("create apple container: %w", err)
	}
	preInspect, err := a.inspectRun(ctx, lifecycle, containerID, request, before, workspace)
	if err != nil {
		return DockerRunResult{}, err
	}
	runContext, cancel := context.WithTimeout(ctx, time.Duration(request.TimeoutMillis)*time.Millisecond)
	stdout := newAppleLimitedCapture(request.MaxOutputBytes)
	stderr := newAppleLimitedCapture(request.MaxOutputBytes)
	startErr := lifecycle.Start(runContext, appleContainerBinaryPath, []string{"start", "--attach", containerID}, stdout, stderr)
	timedOut := errors.Is(runContext.Err(), context.DeadlineExceeded)
	cancel()
	if stdout.Overflowed() || stderr.Overflowed() {
		return DockerRunResult{}, errors.New("apple container stdout or stderr exceeded max_output_bytes")
	}
	if timedOut {
		return DockerRunResult{}, errors.New("apple container execution timed out")
	}
	if startErr != nil {
		return DockerRunResult{}, fmt.Errorf("start attached apple container: %w", startErr)
	}
	// Apple Container CLI 1.1's post-exit inspect output does not include an
	// exit status. A successful attached start is therefore the authoritative
	// observation of a zero exit; nonzero exits are returned by Start above.
	observedExitCode := 0
	postInspect, err := a.inspectRun(ctx, lifecycle, containerID, request, before, workspace)
	if err != nil {
		return DockerRunResult{}, err
	}
	if preInspect.configFingerprint != postInspect.configFingerprint {
		return DockerRunResult{}, errors.New("apple container configuration changed during execution")
	}
	if err := revalidateAppleWorkspace(workspace, workspaceIdentity); err != nil {
		return DockerRunResult{}, err
	}
	if err := validateAppleWorkspace(workspace, request.ScratchInputs, inputBytes, request.MaxOutputBytes); err != nil {
		return DockerRunResult{}, err
	}
	if err := revalidateAppleStagedResult(resultPath, resultIdentity); err != nil {
		return DockerRunResult{}, err
	}
	result, err := readAppleStagedResult(resultPath, request.MaxOutputBytes, resultIdentity)
	if err != nil {
		return DockerRunResult{}, err
	}
	after, err := a.Preflight(ctx, request.Image)
	if err != nil {
		return DockerRunResult{}, err
	}
	if !sameApplePreflightEvidence(before, after) {
		return DockerRunResult{}, errors.New("apple container runtime or image identity changed during execution")
	}
	transcript, err := json.Marshal(struct {
		StdoutB64 string `json:"stdout_b64"`
		StderrB64 string `json:"stderr_b64"`
	}{
		StdoutB64: base64.RawStdEncoding.EncodeToString(stdout.Bytes()),
		StderrB64: base64.RawStdEncoding.EncodeToString(stderr.Bytes()),
	})
	if err != nil {
		return DockerRunResult{}, fmt.Errorf("encode apple container transcript: %w", err)
	}
	runtimeIdentity := appleRuntimeIdentity(before)
	constraints := containerAdapterConstraints(request)
	return DockerRunResult{
		Result:              result,
		MediaType:           "application/octet-stream",
		Transcript:          transcript,
		TranscriptMediaType: "application/json",
		Evidence: map[string]any{
			"format":                  containerAdapterEvidenceFormat,
			"runtime":                 "apple-container",
			"image":                   request.Image,
			"image_id":                before.ImageID,
			"container_id":            containerID,
			"runtime_identity":        runtimeIdentity,
			"runtime_identity_digest": digestHex(runtimeIdentity),
			"constraints":             constraints,
			"configuration_digest":    digestHex(constraints),
			"observed":                map[string]any{"exit_code": float64(observedExitCode)},
		},
	}, nil
}

func (a *AppleContainerCLIAdapter) runLifecycle(ctx context.Context, lifecycle appleContainerLifecycleRunner, arguments ...string) error {
	if len(arguments) == 0 || arguments[0] != "container" {
		return errors.New("invalid apple container lifecycle command")
	}
	_, err := lifecycle.Run(ctx, appleContainerBinaryPath, arguments[1:]...)
	return err
}

func validateAppleRunRequest(request DockerRunRequest) error {
	if err := validateDockerImage(request.Image); err != nil {
		return fmt.Errorf("apple container image: %w", err)
	}
	if _, ok := dockerTaggedImageReference(request.Image); !ok {
		return errors.New("apple container local lookup requires a tag before @")
	}
	if _, err := validateDockerCommand(request.Command); err != nil {
		return err
	}
	cpu, err := strconv.ParseFloat(request.CPUs, 64)
	if err != nil || cpu <= 0 || cpu > 64 {
		return errors.New("apple container CPUs are invalid")
	}
	if request.MemoryBytes < appleContainerMinMemoryBytes || request.MemoryBytes > dockerMaxMemoryBytes {
		return errors.New("apple container memory is outside its supported range")
	}
	if request.TimeoutMillis <= 0 || request.TimeoutMillis > dockerMaxTimeoutMillis {
		return errors.New("apple container timeout is invalid")
	}
	if request.MaxOutputBytes <= 0 || request.MaxOutputBytes > dockerMaxOutputBytes {
		return errors.New("apple container max output is invalid")
	}
	if !sort.SliceIsSorted(request.ScratchInputs, func(left, right int) bool {
		return request.ScratchInputs[left].Path < request.ScratchInputs[right].Path
	}) {
		return errors.New("apple container scratch inputs are not deterministic")
	}
	for index, input := range request.ScratchInputs {
		if err := validateDockerScratchPath(input.Path); err != nil {
			return fmt.Errorf("apple container scratch input %d: %w", index, err)
		}
		if index > 0 && request.ScratchInputs[index-1].Path == input.Path {
			return fmt.Errorf("apple container scratch input path %q is duplicated", input.Path)
		}
	}
	return nil
}

func appleContainerCreateArgs(request DockerRunRequest, containerID, workspace string) []string {
	return []string{
		"container", "create", "--name", containerID,
		"--read-only", "--cpus", request.CPUs, "--memory", strconv.FormatInt(request.MemoryBytes, 10),
		"--ulimit", appleContainerUlimit, "--ulimit", appleContainerNprocUlimit,
		"--network", appleContainerNetwork, "--no-dns",
		"--mount", "type=bind,source=" + workspace + ",target=/work",
		"--cap-drop", "ALL", "--user", appleContainerUser,
		request.Image,
	}
}

func newAppleContainerID() (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", fmt.Errorf("generate apple container identifier: %w", err)
	}
	return "agnet-" + hex.EncodeToString(random[:]), nil
}

func validateAppleContainerID(value string) error {
	if !strings.HasPrefix(value, "agnet-") || len(value) != len("agnet-")+32 || !isLowerHex(value[len("agnet-"):]) {
		return errors.New("apple container identifier is invalid")
	}
	return nil
}

func stageAppleWorkspace(inputs []DockerScratchInput) (string, int64, error) {
	workspace, err := os.MkdirTemp("", "agnet-apple-workspace-*")
	if err != nil {
		return "", 0, fmt.Errorf("create apple private workspace: %w", err)
	}
	if err := os.Chmod(workspace, 0o700); err != nil {
		_ = os.RemoveAll(workspace)
		return "", 0, fmt.Errorf("protect apple private workspace: %w", err)
	}
	inputRoot := filepath.Join(workspace, "input")
	if err := os.Mkdir(inputRoot, 0o700); err != nil {
		_ = os.RemoveAll(workspace)
		return "", 0, fmt.Errorf("create apple workspace input root: %w", err)
	}
	var inputBytes int64
	for _, input := range inputs {
		path := filepath.Join(inputRoot, filepath.FromSlash(input.Path))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			_ = os.RemoveAll(workspace)
			return "", 0, fmt.Errorf("create apple workspace input parent: %w", err)
		}
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			_ = os.RemoveAll(workspace)
			return "", 0, fmt.Errorf("create apple workspace input %q: %w", input.Path, err)
		}
		if _, err := file.Write(input.Bytes); err != nil {
			_ = file.Close()
			_ = os.RemoveAll(workspace)
			return "", 0, fmt.Errorf("write apple workspace input %q: %w", input.Path, err)
		}
		if err := file.Close(); err != nil {
			_ = os.RemoveAll(workspace)
			return "", 0, fmt.Errorf("close apple workspace input %q: %w", input.Path, err)
		}
		inputBytes += int64(len(input.Bytes))
	}
	if err := filepath.Walk(inputRoot, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			return os.Chmod(path, 0o555)
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("apple workspace input is unsafe")
		}
		return os.Chmod(path, 0o444)
	}); err != nil {
		_ = os.RemoveAll(workspace)
		return "", 0, fmt.Errorf("lock apple workspace inputs: %w", err)
	}
	resultPath := filepath.Join(workspace, "result")
	result, err := os.OpenFile(resultPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o666)
	if err != nil {
		_ = os.RemoveAll(workspace)
		return "", 0, fmt.Errorf("create apple workspace result: %w", err)
	}
	if err := result.Close(); err != nil {
		_ = os.RemoveAll(workspace)
		return "", 0, fmt.Errorf("close apple workspace result: %w", err)
	}
	if err := os.Chmod(resultPath, 0o666); err != nil {
		_ = os.RemoveAll(workspace)
		return "", 0, fmt.Errorf("permit apple workspace result writes: %w", err)
	}
	return workspace, inputBytes, nil
}

func removeAppleWorkspace(workspace string) error {
	if err := filepath.Walk(workspace, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			return os.Chmod(path, 0o700)
		}
		return os.Chmod(path, 0o600)
	}); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.RemoveAll(workspace); err != nil {
		return err
	}
	return nil
}

type appleWorkspaceIdentity struct {
	dev, ino uint64
	uid      uint32
	mode     os.FileMode
}

func pinAppleWorkspace(path string) (appleWorkspaceIdentity, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return appleWorkspaceIdentity{}, errors.New("apple workspace is not a private directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return appleWorkspaceIdentity{}, errors.New("apple workspace is not agent-owned")
	}
	return appleWorkspaceIdentity{dev: uint64(stat.Dev), ino: uint64(stat.Ino), uid: stat.Uid, mode: info.Mode()}, nil
}

func revalidateAppleWorkspace(path string, want appleWorkspaceIdentity) error {
	got, err := pinAppleWorkspace(path)
	if err != nil {
		return err
	}
	if got != want {
		return errors.New("apple workspace identity changed during execution")
	}
	return nil
}

func validateAppleWorkspace(workspace string, inputs []DockerScratchInput, inputBytes, maximumResult int64) error {
	if _, err := pinAppleWorkspace(workspace); err != nil {
		return err
	}
	expected := map[string]bool{".": true, "input": true, "result": true}
	directories := map[string]bool{".": true, "input": true}
	for _, input := range inputs {
		parts := strings.Split(input.Path, "/")
		for index := range parts {
			rel := filepath.ToSlash(filepath.Join(append([]string{"input"}, parts[:index+1]...)...))
			expected[rel] = true
			if index < len(parts)-1 {
				directories[rel] = true
			}
		}
	}
	seen := make(map[string]bool, len(expected))
	var total int64
	err := filepath.Walk(workspace, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(workspace, path)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			return errors.New("apple workspace contains escaping path")
		}
		rel = filepath.ToSlash(rel)
		if !expected[rel] {
			return errors.New("apple workspace contains unexpected entry")
		}
		seen[rel] = true
		if directories[rel] != info.IsDir() {
			return errors.New("apple workspace entry kind is invalid")
		}
		if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
			return errors.New("apple workspace contains unsafe entry")
		}
		if info.IsDir() {
			return nil
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Nlink != 1 {
			return errors.New("apple workspace contains linked file")
		}
		if info.Size() < 0 {
			return errors.New("apple workspace entry size is invalid")
		}
		if rel == "result" && info.Size() > maximumResult {
			return errors.New("apple container result exceeds max_output_bytes")
		}
		total += info.Size()
		if total > inputBytes+maximumResult {
			return errors.New("apple workspace exceeds aggregate size limit")
		}
		return nil
	})
	if err != nil {
		return err
	}
	for rel := range expected {
		if !seen[rel] {
			return errors.New("apple workspace is missing required entry")
		}
	}
	resultInfo, err := os.Lstat(filepath.Join(workspace, "result"))
	if err != nil || !resultInfo.Mode().IsRegular() || resultInfo.Mode()&os.ModeSymlink != 0 || resultInfo.Size() > maximumResult {
		return errors.New("apple workspace result is invalid")
	}
	return nil
}

type appleLimitedCapture struct {
	limit    int64
	buffer   bytes.Buffer
	overflow bool
	mu       sync.Mutex
}

func newAppleLimitedCapture(limit int64) *appleLimitedCapture {
	return &appleLimitedCapture{limit: limit}
}

func (capture *appleLimitedCapture) Write(data []byte) (int, error) {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	remaining := capture.limit - int64(capture.buffer.Len())
	if remaining <= 0 {
		capture.overflow = capture.overflow || len(data) > 0
		return len(data), nil
	}
	keep := len(data)
	if int64(keep) > remaining {
		keep = int(remaining)
		capture.overflow = true
	}
	_, _ = capture.buffer.Write(data[:keep])
	return len(data), nil
}

func (capture *appleLimitedCapture) Bytes() []byte {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return append([]byte(nil), capture.buffer.Bytes()...)
}

func (capture *appleLimitedCapture) Overflowed() bool {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return capture.overflow
}

type appleRunInspection struct {
	containerID       string
	image             string
	configFingerprint string
	exitCode          int64
	exitKnown         bool
}

func (a *AppleContainerCLIAdapter) inspectRun(ctx context.Context, lifecycle appleContainerLifecycleRunner, containerID string, request DockerRunRequest, proof AppleContainerPreflightEvidence, workspace string) (appleRunInspection, error) {
	output, err := lifecycle.Run(ctx, appleContainerBinaryPath, "inspect", containerID)
	if err != nil {
		return appleRunInspection{}, fmt.Errorf("inspect apple container: %w", err)
	}
	inspection, state, err := normalizeAppleRunInspect(output)
	if err != nil {
		return appleRunInspection{}, err
	}
	if inspection.containerID != containerID {
		return appleRunInspection{}, errors.New("apple container inspect id does not match created container")
	}
	if !sameAppleInspectableImage(inspection.image, request.Image) {
		return appleRunInspection{}, errors.New("apple container inspect image does not match pinned request")
	}
	if err := validateAppleInspectConstraints(inspection.configFingerprint, request, workspace); err != nil {
		return appleRunInspection{}, err
	}
	if state.running {
		return appleRunInspection{}, errors.New("apple container did not stop after attached start")
	}
	if state.exitKnown && state.exitCode != 0 {
		return appleRunInspection{}, fmt.Errorf("apple container exited with status %d", state.exitCode)
	}
	if proof.ImageDescriptorDigest == "" || proof.ImageID == "" {
		return appleRunInspection{}, errors.New("apple container preflight image proof is incomplete")
	}
	return inspection, nil
}

type appleInspectState struct {
	running   bool
	exitCode  int64
	exitKnown bool
}

func normalizeAppleRunInspect(data []byte) (appleRunInspection, appleInspectState, error) {
	var documents []map[string]any
	if err := decodeOneJSON(data, &documents); err != nil {
		return appleRunInspection{}, appleInspectState{}, fmt.Errorf("apple container inspect is malformed: %w", err)
	}
	if len(documents) != 1 {
		return appleRunInspection{}, appleInspectState{}, errors.New("apple container inspect did not return exactly one container")
	}
	document := documents[0]
	id := appleStringAt(document, []string{"id"}, []string{"configuration", "id"})
	image := appleStringAt(document, []string{"image"}, []string{"configuration", "image", "reference"}, []string{"configuration", "image", "name"})
	config := appleMapAt(document, []string{"config"}, []string{"configuration"})
	state := appleMapAt(document, []string{"state"}, []string{"status"})
	if id == "" || image == "" || config == nil || state == nil {
		return appleRunInspection{}, appleInspectState{}, errors.New("apple container inspect lacks required identity or configuration")
	}
	configJSON, err := json.Marshal(config)
	if err != nil {
		return appleRunInspection{}, appleInspectState{}, fmt.Errorf("encode apple container configuration: %w", err)
	}
	running, ok := appleBoolAt(state, []string{"running"})
	if !ok {
		status := appleStringAt(state, []string{"state"})
		if status == "running" {
			running, ok = true, true
		}
		if status == "stopped" || status == "exited" {
			running, ok = false, true
		}
	}
	exitCode, exitKnown := appleIntAt(state, []string{"exit_code"}, []string{"exitCode"})
	if !ok {
		return appleRunInspection{}, appleInspectState{}, errors.New("apple container inspect lacks runtime state")
	}
	return appleRunInspection{containerID: id, image: image, configFingerprint: string(configJSON), exitCode: exitCode, exitKnown: exitKnown}, appleInspectState{running: running, exitCode: exitCode, exitKnown: exitKnown}, nil
}

func validateAppleInspectConstraints(configJSON string, request DockerRunRequest, workspace string) error {
	var config map[string]any
	if err := json.Unmarshal([]byte(configJSON), &config); err != nil {
		return err
	}
	if appleInspectUser(config) != appleContainerUser {
		return errors.New("apple container inspect user is not constrained")
	}
	if !sameStringSlice(appleStringsAt(config, []string{"cmd"}, []string{"initProcess", "arguments"}, []string{"arguments"}), request.Command) {
		return errors.New("apple container inspect command does not match request")
	}
	readOnly, ok := appleBoolAt(config, []string{"read_only"}, []string{"readOnly"}, []string{"rootfs", "readOnly"})
	if !ok || !readOnly {
		return errors.New("apple container inspect root filesystem is not read-only")
	}
	cpus := appleStringAt(config, []string{"cpus"}, []string{"resources", "cpus"})
	if cpus == "" {
		cpus = appleNumberStringAt(config, []string{"cpus"}, []string{"resources", "cpus"})
	}
	if cpus != request.CPUs {
		return errors.New("apple container inspect CPU limit does not match request")
	}
	memory, ok := appleIntAt(config, []string{"memory"}, []string{"memoryBytes"}, []string{"resources", "memoryInBytes"})
	if !ok || memory != request.MemoryBytes {
		return errors.New("apple container inspect memory limit does not match request")
	}
	if !appleHasPrivateWorkspaceMount(config, workspace) {
		return errors.New("apple container inspect private workspace mount evidence is not exact")
	}
	if !appleInspectDNSDisabled(config) || !appleStringListContains(config, "ALL", []string{"cap_drop"}, []string{"capDrop"}) || (!appleStringListContains(config, appleContainerUlimit, []string{"ulimits"}) && !appleHasRlimit(config, "RLIMIT_NOFILE", "nofile")) || (!appleStringListContains(config, appleContainerNprocUlimit, []string{"ulimits"}) && !appleHasRlimit(config, "RLIMIT_NPROC", "nproc")) {
		return errors.New("apple container inspect constraints are not enforced")
	}
	if !appleEmptyListAt(config, []string{"publishedPorts"}) || !appleEmptyListAt(config, []string{"publishedSockets"}) {
		return errors.New("apple container inspect exposes host ports or sockets")
	}
	if ssh, present := appleBoolAt(config, []string{"ssh"}); present && ssh {
		return errors.New("apple container inspect enables SSH forwarding")
	}
	return nil
}
func appleMapAt(root map[string]any, paths ...[]string) map[string]any {
	for _, path := range paths {
		if value, ok := appleValueAt(root, path); ok {
			if object, ok := value.(map[string]any); ok {
				return object
			}
		}
	}
	return nil
}
func appleStringAt(root map[string]any, paths ...[]string) string {
	for _, path := range paths {
		if value, ok := appleValueAt(root, path); ok {
			if text, ok := value.(string); ok {
				return text
			}
		}
	}
	return ""
}
func appleNumberStringAt(root map[string]any, paths ...[]string) string {
	for _, path := range paths {
		if value, ok := appleValueAt(root, path); ok {
			if number, ok := value.(float64); ok {
				return strconv.FormatFloat(number, 'f', -1, 64)
			}
		}
	}
	return ""
}
func appleBoolAt(root map[string]any, paths ...[]string) (bool, bool) {
	for _, path := range paths {
		if value, ok := appleValueAt(root, path); ok {
			if boolean, ok := value.(bool); ok {
				return boolean, true
			}
		}
	}
	return false, false
}
func appleIntAt(root map[string]any, paths ...[]string) (int64, bool) {
	for _, path := range paths {
		if value, ok := appleValueAt(root, path); ok {
			if number, ok := value.(float64); ok && number >= -float64(^uint64(0)>>1)-1 && number <= float64(^uint64(0)>>1) {
				return int64(number), true
			}
		}
	}
	return 0, false
}
func appleStringsAt(root map[string]any, paths ...[]string) []string {
	for _, path := range paths {
		if value, ok := appleValueAt(root, path); ok {
			if values, ok := value.([]any); ok {
				out := make([]string, len(values))
				for index, value := range values {
					text, ok := value.(string)
					if !ok {
						return nil
					}
					out[index] = text
				}
				return out
			}
		}
	}
	return nil
}
func appleStringListContains(root map[string]any, want string, paths ...[]string) bool {
	for _, path := range paths {
		for _, got := range appleStringsAt(root, path) {
			if got == want {
				return true
			}
		}
	}
	return false
}
func appleEmptyListAt(root map[string]any, path []string) bool {
	value, present := appleValueAt(root, path)
	if !present {
		return true
	}
	values, ok := value.([]any)
	return ok && len(values) == 0
}
func appleInspectUser(root map[string]any) string {
	if user := appleStringAt(root, []string{"user"}, []string{"initProcess", "user"}); user != "" {
		return user
	}
	user := appleMapAt(root, []string{"initProcess", "user"})
	if user == nil {
		return ""
	}
	if raw, ok := user["raw"].(map[string]any); ok {
		if userString := appleStringAt(raw, []string{"userString"}); userString != "" {
			return userString
		}
	}
	if identity, ok := user["id"].(map[string]any); ok {
		user = identity
	}
	uid, uidOK := appleIntAt(user, []string{"uid"})
	gid, gidOK := appleIntAt(user, []string{"gid"})
	if uidOK && gidOK {
		return strconv.FormatInt(uid, 10) + ":" + strconv.FormatInt(gid, 10)
	}
	return ""
}
func appleHasPrivateWorkspaceMount(root map[string]any, workspace string) bool {
	value, present := appleValueAt(root, []string{"mounts"})
	if !present {
		return false
	}
	mounts, ok := value.([]any)
	if !ok || len(mounts) != 1 {
		return false
	}
	mount, ok := mounts[0].(map[string]any)
	if !ok || appleStringAt(mount, []string{"destination"}, []string{"target"}) != appleContainerWorkdir || appleStringAt(mount, []string{"source"}) != workspace {
		return false
	}
	if !appleInspectMountIsReadWrite(mount) {
		return false
	}
	kind, ok := mount["type"].(map[string]any)
	if !ok || len(kind) != 1 {
		return false
	}
	_, ok = kind[appleContainerBindMountType]
	return ok
}

func appleInspectMountIsReadWrite(mount map[string]any) bool {
	value, present := appleValueAt(mount, []string{"options"})
	if !present {
		return false
	}
	options, ok := value.([]any)
	if !ok {
		return false
	}
	for _, option := range options {
		value, ok := option.(string)
		if !ok {
			return false
		}
		switch strings.ToLower(value) {
		case "ro", "readonly", "read-only":
			return false
		}
	}
	return true
}
func appleHasRlimit(root map[string]any, names ...string) bool {
	value, present := appleValueAt(root, []string{"initProcess", "rlimits"})
	if !present {
		return false
	}
	limits, ok := value.([]any)
	if !ok {
		return false
	}
	for _, value := range limits {
		limit, ok := value.(map[string]any)
		if !ok {
			continue
		}
		name := appleStringAt(limit, []string{"limit"})
		nameMatches := false
		for _, allowed := range names {
			if name == allowed {
				nameMatches = true
				break
			}
		}
		soft, softOK := appleIntAt(limit, []string{"soft"})
		hard, hardOK := appleIntAt(limit, []string{"hard"})
		if nameMatches && softOK && hardOK && soft == 64 && hard == 64 {
			return true
		}
	}
	return false
}
func appleInspectDNSDisabled(root map[string]any) bool {
	if noDNS, present := appleBoolAt(root, []string{"no_dns"}, []string{"noDNS"}); present {
		return noDNS
	}
	value, present := appleValueAt(root, []string{"dns"})
	if !present || value == nil {
		return true
	}
	dns, ok := value.(map[string]any)
	if !ok {
		return false
	}
	return appleEmptyListAt(dns, []string{"nameservers"}) && appleEmptyListAt(dns, []string{"searchDomains"}) && appleEmptyListAt(dns, []string{"options"}) && appleStringAt(dns, []string{"domain"}) == ""
}
func sameAppleInspectableImage(left, right string) bool {
	leftName, leftDigest, leftOK := strings.Cut(left, "@")
	rightName, rightDigest, rightOK := strings.Cut(right, "@")
	if !leftOK || !rightOK || leftDigest != rightDigest {
		return false
	}
	leftRepository, _, _ := splitDockerImageTag(leftName)
	rightRepository, _, _ := splitDockerImageTag(rightName)
	return leftRepository == rightRepository
}
func appleValueAt(root map[string]any, path []string) (any, bool) {
	var value any = root
	for _, segment := range path {
		object, ok := value.(map[string]any)
		if !ok {
			return nil, false
		}
		value, ok = object[segment]
		if !ok {
			return nil, false
		}
	}
	return value, true
}
func sameStringSlice(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

type appleStagedFileIdentity struct {
	dev, ino, nlink uint64
	mode            os.FileMode
}

func pinAppleStagedResult(path string) (appleStagedFileIdentity, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o666 || info.Mode()&os.ModeSymlink != 0 {
		return appleStagedFileIdentity{}, errors.New("apple staged result is not a writable regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return appleStagedFileIdentity{}, errors.New("apple staged result is not singly linked")
	}
	return appleStagedFileIdentity{dev: uint64(stat.Dev), ino: uint64(stat.Ino), nlink: uint64(stat.Nlink), mode: info.Mode()}, nil
}

func revalidateAppleStagedResult(path string, want appleStagedFileIdentity) error {
	got, err := pinAppleStagedResult(path)
	if err != nil {
		return err
	}
	if got != want {
		return errors.New("apple staged result identity changed during execution")
	}
	return nil
}

func readAppleStagedResult(path string, maximum int64, want appleStagedFileIdentity) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open apple container result without following links: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > maximum {
		return nil, errors.New("apple container result exceeds max_output_bytes")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return nil, errors.New("apple container result identity changed during read")
	}
	got := appleStagedFileIdentity{dev: uint64(stat.Dev), ino: uint64(stat.Ino), nlink: uint64(stat.Nlink), mode: info.Mode()}
	if got != want {
		return nil, errors.New("apple container result identity changed during read")
	}
	result, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, fmt.Errorf("read apple container result: %w", err)
	}
	if int64(len(result)) > maximum {
		return nil, errors.New("apple container result exceeds max_output_bytes")
	}
	return result, nil
}

func sameApplePreflightEvidence(left, right AppleContainerPreflightEvidence) bool {
	return left.Runtime == right.Runtime && left.BinaryPath == right.BinaryPath &&
		left.BinaryDigestBefore == right.BinaryDigestBefore && left.BinaryDigestAfter == right.BinaryDigestAfter &&
		left.CLIVersionBefore == right.CLIVersionBefore && left.CLIVersionAfter == right.CLIVersionAfter &&
		left.CLICommit == right.CLICommit && left.APIServerVersion == right.APIServerVersion &&
		left.APIServerCommit == right.APIServerCommit && left.AppRoot == right.AppRoot &&
		left.Image == right.Image && left.ImageDescriptorDigest == right.ImageDescriptorDigest && left.ImageID == right.ImageID
}
