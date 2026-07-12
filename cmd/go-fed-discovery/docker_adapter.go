package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	dockerMaxCPUMillis      int64 = 64_000
	dockerMaxMemoryBytes    int64 = 64 << 30
	dockerMaxTimeoutMillis  int64 = 15 * 60 * 1000
	dockerMaxOutputBytes    int64 = 64 << 20
	dockerMaxScratchBytes   int64 = 64 << 20
	dockerDigestHexLength         = 64
)

// DockerAdapter is the execution boundary for a validated container run.
// Implementations belong to later execution slices; this contract deliberately
// does not provide a host or external-tool fallback.
type DockerAdapter interface {
	Run(context.Context, DockerRunRequest) (DockerRunResult, error)
}

// DockerRunRequest contains only normalized, bounded values suitable for an
// adapter. Scratch inputs contain decoded bytes and are ordered by path.
type DockerRunRequest struct {
	Image         string
	Command       []string
	CPUs          string
	MemoryBytes   int64
	TimeoutMillis int64
	MaxOutputBytes int64
	MaxScratchInputBytes int64
	MaxScratchBytes      int64
	ScratchInputs []DockerScratchInput
}

// DockerRunResult keeps execution output binary-safe. It deliberately carries
// no artifact location or publication state.
type DockerRunResult struct {
	Result              []byte
	MediaType           string
	Transcript          []byte
	TranscriptMediaType string
	Evidence            map[string]any
}

// DockerWorkerProfile is the declarative, serializable input to Docker
// validation. The image must be an immutable sha256-pinned reference.
type DockerWorkerProfile struct {
	Image         string               `json:"image"`
	Command       []string             `json:"command"`
	Limits        DockerLimits         `json:"limits"`
	ScratchInputs []DockerScratchInput `json:"scratch_inputs,omitempty"`
}

// DockerScratchInput is encoded on a profile and decoded on a run request.
// BytesB64 must use unpadded standard base64. Bytes is populated only after
// validation and is never serialized.
type DockerScratchInput struct {
	Path     string `json:"path"`
	BytesB64 string `json:"bytes_b64,omitempty"`
	Bytes    []byte `json:"-"`
}

// DockerLimits bounds a single container run. Every field is required so a
// profile cannot rely on an adapter default for resource or output limits.
type DockerLimits struct {
	CPUMillis            int64 `json:"cpu_millis"`
	MemoryBytes          int64 `json:"memory_bytes"`
	TimeoutMillis        int64 `json:"timeout_millis"`
	MaxOutputBytes       int64 `json:"max_output_bytes"`
	MaxScratchInputBytes int64 `json:"max_scratch_input_bytes"`
	MaxScratchBytes      int64 `json:"max_scratch_bytes"`
}

// validateDockerWorkerProfile creates the sole adapter request representation.
// It validates every declarative value and decodes scratch bytes before an
// adapter can be probed or invoked.
func validateDockerWorkerProfile(profile DockerWorkerProfile) (DockerRunRequest, error) {
	if err := validateDockerImage(profile.Image); err != nil {
		return DockerRunRequest{}, err
	}
	command, err := validateDockerCommand(profile.Command)
	if err != nil {
		return DockerRunRequest{}, err
	}
	if err := validateDockerLimits(profile.Limits); err != nil {
		return DockerRunRequest{}, err
	}
	scratchInputs, err := normalizeDockerScratchInputs(profile.ScratchInputs, profile.Limits)
	if err != nil {
		return DockerRunRequest{}, err
	}
	return DockerRunRequest{
		Image:          profile.Image,
		Command:        command,
		CPUs:           renderCPUs(profile.Limits.CPUMillis),
		MemoryBytes:    profile.Limits.MemoryBytes,
		TimeoutMillis:  profile.Limits.TimeoutMillis,
		MaxOutputBytes: profile.Limits.MaxOutputBytes,
		MaxScratchInputBytes: profile.Limits.MaxScratchInputBytes,
		MaxScratchBytes:      profile.Limits.MaxScratchBytes,
		ScratchInputs:  scratchInputs,
	}, nil
}

func validateDockerImage(image string) error {
	if image == "" || image != strings.ToLower(image) || strings.ContainsAny(image, "\t\n\r ") {
		return errors.New("docker image must be a lowercase digest-pinned reference")
	}
	name, digest, ok := strings.Cut(image, "@")
	if !ok || name == "" || strings.Contains(digest, "@") {
		return errors.New("docker image must contain one digest pin")
	}
	if !strings.HasPrefix(digest, "sha256:") || len(digest) != len("sha256:")+dockerDigestHexLength || !isLowerHex(digest[len("sha256:"):]) {
		return errors.New("docker image digest must be sha256 with 64 lowercase hexadecimal characters")
	}
	repository, tag, tagged := splitDockerImageTag(name)
	if tagged && !validDockerImageTag(tag) {
		return errors.New("docker image tag is invalid")
	}
	if !validDockerImageName(repository) {
		return errors.New("docker image name is invalid")
	}
	return nil
}

func splitDockerImageTag(name string) (repository, tag string, tagged bool) {
	lastSlash := strings.LastIndexByte(name, '/')
	lastComponent := name[lastSlash+1:]
	colon := strings.LastIndexByte(lastComponent, ':')
	if colon < 0 {
		return name, "", false
	}
	colon += lastSlash + 1
	return name[:colon], name[colon+1:], true
}

func dockerTaggedImageReference(image string) (string, bool) {
	name, _, ok := strings.Cut(image, "@")
	if !ok {
		return "", false
	}
	_, _, tagged := splitDockerImageTag(name)
	return name, tagged
}

func validDockerImageTag(tag string) bool {
	if tag == "" || len(tag) > 128 {
		return false
	}
	for index, character := range tag {
		isAlphaNumeric := character >= 'a' && character <= 'z' || character >= '0' && character <= '9'
		isSeparator := character == '.' || character == '_' || character == '-'
		if !isAlphaNumeric && !isSeparator {
			return false
		}
		if index == 0 && !isAlphaNumeric && character != '_' {
			return false
		}
	}
	return true
}

func validDockerImageName(name string) bool {
	parts := strings.Split(name, "/")
	if len(parts) == 0 {
		return false
	}
	for index, part := range parts {
		if part == "" {
			return false
		}
		if index == 0 {
			if host, port, found := strings.Cut(part, ":"); found {
				if !validDockerNamePart(host) || !validDockerPort(port) {
					return false
				}
				continue
			}
		}
		if !validDockerNamePart(part) {
			return false
		}
	}
	return true
}

func validDockerNamePart(part string) bool {
	if part == "" {
		return false
	}
	previousSeparator := false
	for _, character := range part {
		isAlphaNumeric := character >= 'a' && character <= 'z' || character >= '0' && character <= '9'
		isSeparator := character == '.' || character == '_' || character == '-'
		if !isAlphaNumeric && !isSeparator {
			return false
		}
		if isSeparator && previousSeparator {
			return false
		}
		previousSeparator = isSeparator
	}
	first, last := part[0], part[len(part)-1]
	return first != '.' && first != '_' && first != '-' && last != '.' && last != '_' && last != '-'
}

func validDockerPort(port string) bool {
	if port == "" || len(port) > 5 {
		return false
	}
	value, err := strconv.ParseUint(port, 10, 16)
	return err == nil && value > 0
}

func isLowerHex(value string) bool {
	for _, character := range value {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

func validateDockerCommand(command []string) ([]string, error) {
	if len(command) == 0 || command[0] == "" {
		return nil, errors.New("docker command missing")
	}
	normalized := make([]string, len(command))
	for index, argument := range command {
		if strings.Contains(argument, "\x00") {
			return nil, fmt.Errorf("docker command argument %d contains NUL", index)
		}
		normalized[index] = argument
	}
	return normalized, nil
}

func validateDockerLimits(limits DockerLimits) error {
	checks := []struct {
		name  string
		value int64
		max   int64
	}{
		{name: "cpu_millis", value: limits.CPUMillis, max: dockerMaxCPUMillis},
		{name: "memory_bytes", value: limits.MemoryBytes, max: dockerMaxMemoryBytes},
		{name: "timeout_millis", value: limits.TimeoutMillis, max: dockerMaxTimeoutMillis},
		{name: "max_output_bytes", value: limits.MaxOutputBytes, max: dockerMaxOutputBytes},
		{name: "max_scratch_input_bytes", value: limits.MaxScratchInputBytes, max: dockerMaxScratchBytes},
		{name: "max_scratch_bytes", value: limits.MaxScratchBytes, max: dockerMaxScratchBytes},
	}
	for _, check := range checks {
		if check.value <= 0 || check.value > check.max {
			return fmt.Errorf("docker limit %s is outside its allowed bound", check.name)
		}
	}
	if limits.MaxScratchInputBytes > limits.MaxScratchBytes {
		return errors.New("docker max_scratch_input_bytes exceeds max_scratch_bytes")
	}
	return nil
}

func normalizeDockerScratchInputs(inputs []DockerScratchInput, limits DockerLimits) ([]DockerScratchInput, error) {
	normalized := make([]DockerScratchInput, len(inputs))
	for index, input := range inputs {
		if err := validateDockerScratchPath(input.Path); err != nil {
			return nil, fmt.Errorf("docker scratch input %d: %w", index, err)
		}
		decodedSize, err := rawBase64DecodedSize(input.BytesB64)
		if err != nil {
			return nil, fmt.Errorf("docker scratch input %q: %w", input.Path, err)
		}
		if decodedSize > limits.MaxScratchInputBytes {
			return nil, fmt.Errorf("docker scratch input %q exceeds max_scratch_input_bytes", input.Path)
		}
		decoded, err := base64.RawStdEncoding.DecodeString(input.BytesB64)
		if err != nil {
			return nil, fmt.Errorf("docker scratch input %q has invalid unpadded base64: %w", input.Path, err)
		}
		normalized[index] = DockerScratchInput{Path: input.Path, Bytes: decoded}
	}
	sort.Slice(normalized, func(left, right int) bool { return normalized[left].Path < normalized[right].Path })

	var total int64
	for index, input := range normalized {
		if index > 0 && input.Path == normalized[index-1].Path {
			return nil, fmt.Errorf("docker scratch input path %q is duplicated", input.Path)
		}
		var err error
		total, err = checkedDockerScratchTotal(total, int64(len(input.Bytes)), limits.MaxScratchBytes)
		if err != nil {
			return nil, err
		}
	}
	return normalized, nil
}

func checkedDockerScratchTotal(total, size, maximum int64) (int64, error) {
	if total < 0 || size < 0 || maximum < 0 || total > maximum || size > maximum-total {
		return 0, errors.New("docker scratch inputs exceed max_scratch_bytes")
	}
	return total + size, nil
}

func validateDockerScratchPath(value string) error {
	if value == "" || strings.Contains(value, "\x00") || strings.Contains(value, "\\") || strings.HasPrefix(value, "/") {
		return errors.New("path must be a relative slash path")
	}
	if path.Clean(value) != value || value == "." {
		return errors.New("path must not contain traversal or redundant segments")
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return errors.New("path must not contain traversal or empty segments")
		}
	}
	return nil
}

func rawBase64DecodedSize(value string) (int64, error) {
	if strings.Contains(value, "=") {
		return 0, errors.New("base64 padding is not allowed")
	}
	length := len(value)
	remaining := length % 4
	if remaining == 1 {
		return 0, errors.New("invalid unpadded base64 length")
	}
	groups := length / 4
	if int64(groups) > (int64(^uint64(0)>>1)-2)/3 {
		return 0, errors.New("base64 input is too large")
	}
	decoded := int64(groups) * 3
	switch remaining {
	case 2:
		decoded++
	case 3:
		decoded += 2
	}
	return decoded, nil
}

// renderCPUs converts milli-CPUs to Docker's decimal CPU representation without
// floating-point rounding.
func renderCPUs(milliCPUs int64) string {
	if milliCPUs <= 0 {
		return ""
	}
	whole, fractional := milliCPUs/1000, milliCPUs%1000
	if fractional == 0 {
		return strconv.FormatInt(whole, 10)
	}
	fraction := strings.TrimRight(fmt.Sprintf("%03d", fractional), "0")
	return strconv.FormatInt(whole, 10) + "." + fraction
}

const (
	dockerCommandPath      = "/usr/local/bin/docker"
	dockerLocalUnixSocket  = "/var/run/docker.sock"
	dockerLocalUnixEndpoint = "unix:///var/run/docker.sock"
)

var (
	dockerSanitizedEnvironment = []string{"HOME=/var/empty", "LANG=C", "PATH=/usr/bin:/bin"}
	dockerVersionArgs          = []string{"--host", dockerLocalUnixEndpoint, "--config", "/var/empty", "version", "--format", "{{json .}}"}
	dockerInfoArgs             = []string{"--host", dockerLocalUnixEndpoint, "--config", "/var/empty", "info", "--format", "{{json .}}"}
)

// DockerCommand is the complete, hermetic command passed to DockerCommandRunner.
// Stdin is used only for deterministic tar copies; the runner must not inherit
// process input. The preflight never accepts command flags or environment from a
// caller.
type DockerCommand struct {
	Path  string
	Args  []string
	Env   []string
	Stdin []byte
}

// DockerCommandRunner is the only process boundary used by DockerCLIAdapter.
// Tests inject a runner; production integration must execute exactly Command.
type DockerCommandRunner interface {
	Run(context.Context, DockerCommand) ([]byte, error)
}

// DockerStreamingCommandRunner is optional for runners that can expose Docker
// stdout and stderr as independent streams. The adapter retains the basic
// runner for preflight and deterministic fake-runner tests.
type DockerStreamingCommandRunner interface {
	DockerCommandRunner
	RunStreaming(context.Context, DockerCommand) (stdout io.ReadCloser, stderr io.ReadCloser, wait func() error, err error)
}

// DockerSocketIdentity is the stable local identity of the approved Unix
// socket. Device and inode make substitution detectable during a probe.
type DockerSocketIdentity struct {
	Device uint64
	Inode  uint64
	Mode   uint32
	UID    uint32
}

// DockerHost provides the explicitly approved Docker binary, endpoint, and
// identity readers. There is deliberately no path lookup or ambient environment
// fallback: callers must select the local Docker installation up front.
type DockerHost struct {
	CommandPath    string
	SocketPath     string
	Environment    []string
	BinaryDigest   func(string) (string, error)
	SocketIdentity func(string) (DockerSocketIdentity, error)
}

// DockerProbe is evidence that one immutable image was present locally through
// a particular local Docker daemon without pulling or contacting a registry.
type DockerProbe struct {
	CommandPath           string
	SocketPath            string
	BinaryDigest          string
	Socket                DockerSocketIdentity
	ClientVersion         string
	ClientAPIVersion      string
	DaemonID              string
	DaemonVersion         string
	DaemonAPIVersion      string
	Image                 string
	ImageDescriptorDigest string
	ImageID               string
}

// DockerCLIAdapter owns the strict local-Docker identity proof. It does not
// implement container execution; DockerAdapter execution remains a separate
// boundary with an explicit run policy.
type DockerCLIAdapter struct {
	runner DockerCommandRunner
	host   DockerHost
}

// NewDockerCLIAdapter accepts only the fixed local Docker binary and approved
// Unix socket. Rejecting inherited Docker settings before invoking the runner
// prevents a remote daemon, alternate context, or user config from influencing
// the proof.
func NewDockerCLIAdapter(runner DockerCommandRunner, host DockerHost) (*DockerCLIAdapter, error) {
	if runner == nil {
		return nil, errors.New("docker command runner is required")
	}
	if host.CommandPath != dockerCommandPath {
		return nil, errors.New("docker command path is not the approved local binary")
	}
	if host.SocketPath != dockerLocalUnixSocket {
		return nil, errors.New("docker socket path is not the approved local Unix endpoint")
	}
	if host.BinaryDigest == nil || host.SocketIdentity == nil {
		return nil, errors.New("docker host identity readers are required")
	}
	if err := rejectUnsafeDockerEnvironment(host.Environment); err != nil {
		return nil, err
	}
	return &DockerCLIAdapter{runner: runner, host: host}, nil
}

// Preflight proves that image is already available through the selected local
// daemon. It issues only read-only version, info, and image-inspect commands;
// it never invokes pull, build, tag, or run.
func (adapter *DockerCLIAdapter) Preflight(ctx context.Context, image string) (DockerProbe, error) {
	if adapter == nil || adapter.runner == nil {
		return DockerProbe{}, errors.New("docker CLI adapter is not configured")
	}
	if err := validateDockerImage(image); err != nil {
		return DockerProbe{}, err
	}
	binaryBefore, socketBefore, err := adapter.hostIdentity()
	if err != nil {
		return DockerProbe{}, err
	}
	versionOutput, err := adapter.run(ctx, dockerVersionArgs)
	if err != nil {
		return DockerProbe{}, err
	}
	version, err := parseDockerVersion(versionOutput)
	if err != nil {
		return DockerProbe{}, err
	}
	infoOutput, err := adapter.run(ctx, dockerInfoArgs)
	if err != nil {
		return DockerProbe{}, err
	}
	info, err := parseDockerInfo(infoOutput)
	if err != nil {
		return DockerProbe{}, err
	}
	firstImage, err := adapter.inspectImage(ctx, image)
	if err != nil {
		return DockerProbe{}, err
	}
	secondImage, err := adapter.inspectImage(ctx, image)
	if err != nil {
		return DockerProbe{}, err
	}
	if firstImage.ID != secondImage.ID || !sameDockerRepoDigests(firstImage.RepoDigests, secondImage.RepoDigests) {
		return DockerProbe{}, errors.New("docker image changed during preflight")
	}
	binaryAfter, socketAfter, err := adapter.hostIdentity()
	if err != nil {
		return DockerProbe{}, err
	}
	if binaryBefore != binaryAfter {
		return DockerProbe{}, errors.New("docker binary changed during preflight")
	}
	if socketBefore != socketAfter {
		return DockerProbe{}, errors.New("docker socket changed during preflight")
	}
	return DockerProbe{
		CommandPath:           adapter.host.CommandPath,
		SocketPath:            adapter.host.SocketPath,
		BinaryDigest:          binaryBefore,
		Socket:                socketBefore,
		ClientVersion:         version.Client.Version,
		ClientAPIVersion:      version.Client.APIVersion,
		DaemonID:              info.ID,
		DaemonVersion:         info.ServerVersion,
		DaemonAPIVersion:      version.Server.APIVersion,
		Image:                 image,
		ImageDescriptorDigest: dockerImageDescriptorDigest(image),
		ImageID:               firstImage.ID,
	}, nil
}

const dockerContainerUser = "65532:65532"
const dockerCleanupTimeout = 5 * time.Second


// Run executes a complete local Docker lifecycle. A result is returned only
// after the container, image, binary, and socket all remain unchanged across
// the run; cleanup uses an independent context so cancellation cannot orphan a
// created container.
func (adapter *DockerCLIAdapter) Run(ctx context.Context, request DockerRunRequest) (DockerRunResult, error) {
	if adapter == nil || adapter.runner == nil {
		return DockerRunResult{}, errors.New("docker CLI adapter is not configured")
	}
	if err := validateDockerImage(request.Image); err != nil {
		return DockerRunResult{}, err
	}
	if _, err := validateDockerCommand(request.Command); err != nil {
		return DockerRunResult{}, err
	}
	nanoCPUs := dockerNanoCPUs(request.CPUs)
	if request.MemoryBytes <= 0 || request.MemoryBytes > dockerMaxMemoryBytes || request.TimeoutMillis <= 0 || request.TimeoutMillis > dockerMaxTimeoutMillis || request.MaxOutputBytes <= 0 || request.MaxOutputBytes > dockerMaxOutputBytes || nanoCPUs <= 0 || nanoCPUs > dockerMaxCPUMillis*1_000_000 {
		return DockerRunResult{}, errors.New("docker run request limits are invalid")
	}
	for index, input := range request.ScratchInputs {
		if err := validateDockerScratchPath(input.Path); err != nil {
			return DockerRunResult{}, fmt.Errorf("docker run scratch input: %w", err)
		}
		if index > 0 && request.ScratchInputs[index-1].Path >= input.Path {
			return DockerRunResult{}, errors.New("docker run scratch inputs are not strictly path sorted")
		}
	}

	runContext, cancel := context.WithTimeout(ctx, time.Duration(request.TimeoutMillis)*time.Millisecond)
	defer cancel()
	probeBefore, err := adapter.Preflight(runContext, request.Image)
	if err != nil {
		return DockerRunResult{}, err
	}
	inputArchive, err := dockerScratchTar(request.ScratchInputs)
	if err != nil {
		return DockerRunResult{}, err
	}

	createdOutput, err := adapter.runWithStdin(runContext, dockerCreateArgs(request), nil)
	if err != nil {
		return DockerRunResult{}, err
	}
	containerID, err := normalizeDockerContainerID(createdOutput)
	if err != nil {
		return DockerRunResult{}, err
	}
	defer func() {
		cleanupContext, cancel := context.WithTimeout(context.Background(), dockerCleanupTimeout)
		defer cancel()
		_, _ = adapter.run(cleanupContext, dockerRemoveArgs(containerID))
	}()

	beforeStart, err := adapter.inspectContainer(runContext, containerID)
	if err != nil {
		return DockerRunResult{}, err
	}
	if err := validateDockerContainerConstraints(beforeStart, containerID, request); err != nil {
		return DockerRunResult{}, err
	}
	if beforeStart.State.Running {
		return DockerRunResult{}, errors.New("docker container started before input copy")
	}
	if _, err := adapter.runWithStdin(runContext, dockerCopyInputsArgs(containerID), inputArchive); err != nil {
		return DockerRunResult{}, err
	}
	stdout, stderr, err := adapter.startAndCapture(runContext, dockerStartArgs(containerID), request.MaxOutputBytes)
	if err != nil {
		return DockerRunResult{}, err
	}
	afterStart, err := adapter.inspectContainer(runContext, containerID)
	if err != nil {
		return DockerRunResult{}, err
	}
	if err := validateDockerContainerConstraints(afterStart, containerID, request); err != nil {
		return DockerRunResult{}, err
	}
	if afterStart.State.Running || afterStart.State.ExitCode != 0 {
		return DockerRunResult{}, errors.New("docker container did not exit successfully")
	}
	resultArchive, err := adapter.run(runContext, dockerCopyResultArgs(containerID))
	if err != nil {
		return DockerRunResult{}, err
	}
	result, err := extractDockerResult(resultArchive, request.MaxOutputBytes)
	if err != nil {
		return DockerRunResult{}, err
	}
	probeAfter, err := adapter.Preflight(runContext, request.Image)
	if err != nil {
		return DockerRunResult{}, err
	}
	if probeBefore != probeAfter {
		return DockerRunResult{}, errors.New("docker runtime identity changed during execution")
	}
	transcript, err := json.Marshal(struct {
		Stdout string `json:"stdout_b64"`
		Stderr string `json:"stderr_b64"`
	}{Stdout: base64.RawStdEncoding.EncodeToString(stdout), Stderr: base64.RawStdEncoding.EncodeToString(stderr)})
	if err != nil {
		return DockerRunResult{}, fmt.Errorf("encode docker transcript: %w", err)
	}
	runtimeIdentity := dockerRuntimeIdentity(probeBefore)
	constraints := containerAdapterConstraints(request)
	return DockerRunResult{
		Result:              result,
		MediaType:           "application/octet-stream",
		Transcript:          transcript,
		TranscriptMediaType: "application/json; charset=utf-8",
		Evidence: map[string]any{
			"format":                  containerAdapterEvidenceFormat,
			"runtime":                 "docker",
			"image":                   request.Image,
			"image_id":                probeBefore.ImageID,
			"runtime_identity":        runtimeIdentity,
			"runtime_identity_digest": digestHex(runtimeIdentity),
			"constraints":             constraints,
			"configuration_digest":    digestHex(constraints),
			"observed":                map[string]any{"exit_code": float64(afterStart.State.ExitCode)},
		},
	}, nil
}

func dockerCreateArgs(request DockerRunRequest) []string {
	args := []string{"--host", dockerLocalUnixEndpoint, "--config", "/var/empty", "create", "--read-only", "--cpus", request.CPUs, "--memory", strconv.FormatInt(request.MemoryBytes, 10), "--ulimit", "nofile=64:64", "--network", "none", "--cap-drop", "ALL", "--user", dockerContainerUser, "--tmpfs", "/work:rw,nosuid,nodev,noexec,size=" + strconv.FormatInt(request.MemoryBytes, 10)}
	args = append(args, request.Image)
	return append(args, request.Command...)
}

func dockerCopyInputsArgs(containerID string) []string {
	return []string{"--host", dockerLocalUnixEndpoint, "--config", "/var/empty", "cp", "-", containerID + ":/work"}
}

func dockerStartArgs(containerID string) []string {
	return []string{"--host", dockerLocalUnixEndpoint, "--config", "/var/empty", "start", "--attach", containerID}
}

func dockerCopyResultArgs(containerID string) []string {
	return []string{"--host", dockerLocalUnixEndpoint, "--config", "/var/empty", "cp", containerID + ":/work/result", "-"}
}

func dockerRemoveArgs(containerID string) []string {
	return []string{"--host", dockerLocalUnixEndpoint, "--config", "/var/empty", "rm", "--force", containerID}
}

func normalizeDockerContainerID(output []byte) (string, error) {
	id := strings.TrimSuffix(string(output), "\n")
	if !validDockerContainerID(id) {
		return "", errors.New("docker create did not return one normalized container ID")
	}
	return id, nil
}

func (adapter *DockerCLIAdapter) inspectContainer(ctx context.Context, containerID string) (dockerContainerInspectDocument, error) {
	output, err := adapter.run(ctx, dockerContainerInspectArgs(containerID))
	if err != nil {
		return dockerContainerInspectDocument{}, err
	}
	return parseDockerContainerInspect(output)
}

func (adapter *DockerCLIAdapter) startAndCapture(ctx context.Context, args []string, maximum int64) ([]byte, []byte, error) {
	command := adapter.command(args, nil)
	if streaming, ok := adapter.runner.(DockerStreamingCommandRunner); ok {
		stdoutReader, stderrReader, wait, err := streaming.RunStreaming(ctx, command)
		if err != nil {
			return nil, nil, fmt.Errorf("start docker container: %w", err)
		}
		if stdoutReader == nil || stderrReader == nil || wait == nil {
			return nil, nil, errors.New("docker streaming runner returned an incomplete stream")
		}
		defer stdoutReader.Close()
		defer stderrReader.Close()
		var stdout, stderr []byte
		var stdoutErr, stderrErr error
		var captures sync.WaitGroup
		captures.Add(2)
		go func() { defer captures.Done(); stdout, stdoutErr = limitedCapture(stdoutReader, maximum) }()
		go func() { defer captures.Done(); stderr, stderrErr = limitedCapture(stderrReader, maximum) }()
		captures.Wait()
		waitErr := wait()
		if stdoutErr != nil || stderrErr != nil || waitErr != nil {
			return nil, nil, errors.Join(stdoutErr, stderrErr, waitErr)
		}
		return stdout, stderr, nil
	}
	output, err := adapter.run(ctx, args)
	if err != nil {
		return nil, nil, err
	}
	stdout, err := limitedCapture(bytes.NewReader(output), maximum)
	if err != nil {
		return nil, nil, err
	}
	return stdout, nil, nil
}

func (adapter *DockerCLIAdapter) hostIdentity() (string, DockerSocketIdentity, error) {
	binaryDigest, err := adapter.host.BinaryDigest(adapter.host.CommandPath)
	if err != nil {
		return "", DockerSocketIdentity{}, fmt.Errorf("read docker binary identity: %w", err)
	}
	if !validDockerDigest(binaryDigest) {
		return "", DockerSocketIdentity{}, errors.New("docker binary digest is not a sha256 digest")
	}
	socket, err := adapter.host.SocketIdentity(adapter.host.SocketPath)
	if err != nil {
		return "", DockerSocketIdentity{}, fmt.Errorf("read docker socket identity: %w", err)
	}
	if socket.Device == 0 || socket.Inode == 0 || socket.UID != 0 || socket.Mode&0o170000 != 0o140000 || socket.Mode&0o002 != 0 {
		return "", DockerSocketIdentity{}, errors.New("docker socket identity is unsafe")
	}
	return binaryDigest, socket, nil
}

func (adapter *DockerCLIAdapter) command(args []string, stdin []byte) DockerCommand {
	return DockerCommand{
		Path:  adapter.host.CommandPath,
		Args:  append([]string(nil), args...),
		Env:   append([]string(nil), dockerSanitizedEnvironment...),
		Stdin: append([]byte(nil), stdin...),
	}
}

func (adapter *DockerCLIAdapter) run(ctx context.Context, args []string) ([]byte, error) {
	return adapter.runWithStdin(ctx, args, nil)
}

func (adapter *DockerCLIAdapter) runWithStdin(ctx context.Context, args []string, stdin []byte) ([]byte, error) {
	output, err := adapter.runner.Run(ctx, adapter.command(args, stdin))
	if err != nil {
		return nil, fmt.Errorf("run docker %s: %w", dockerCommandName(args), err)
	}
	return output, nil
}

func dockerInspectArgs(image string) []string {
	return []string{"--host", dockerLocalUnixEndpoint, "--config", "/var/empty", "image", "inspect", "--format", "{{json .}}", image}
}

func dockerCommandName(args []string) string {
	for _, arg := range args {
		if !strings.HasPrefix(arg, "-") && arg != dockerLocalUnixEndpoint && arg != "/var/empty" && arg != "{{json .}}" {
			return arg
		}
	}
	return "command"
}

func rejectUnsafeDockerEnvironment(environment []string) error {
	for _, entry := range environment {
		key, value, found := strings.Cut(entry, "=")
		if !found || key == "" {
			return errors.New("docker environment contains malformed entry")
		}
		if key == "DOCKER_CONTEXT" && value == "default" {
			continue
		}
		if strings.HasPrefix(key, "DOCKER_") && value != "" {
			return fmt.Errorf("inherited docker environment %s is not allowed", key)
		}
	}
	return nil
}

type dockerVersionDocument struct {
	Client struct {
		Version    string `json:"Version"`
		APIVersion string `json:"ApiVersion"`
	} `json:"Client"`
	Server struct {
		Version    string `json:"Version"`
		APIVersion string `json:"ApiVersion"`
	} `json:"Server"`
}

func parseDockerVersion(output []byte) (dockerVersionDocument, error) {
	var document dockerVersionDocument
	if err := json.Unmarshal(output, &document); err != nil {
		return dockerVersionDocument{}, fmt.Errorf("docker version must return structured JSON: %w", err)
	}
	clientMajor, err := dockerVersionMajor(document.Client.Version)
	if err != nil || clientMajor < 24 {
		return dockerVersionDocument{}, errors.New("docker client version must be at least 24")
	}
	if !atLeastDockerAPI(document.Client.APIVersion, 1, 43) || !atLeastDockerAPI(document.Server.APIVersion, 1, 43) {
		return dockerVersionDocument{}, errors.New("docker client and daemon API versions must be at least 1.43")
	}
	return document, nil
}

func dockerVersionMajor(version string) (int, error) {
	major, _, _ := strings.Cut(version, ".")
	if major == "" {
		return 0, errors.New("empty Docker version")
	}
	parsed, err := strconv.Atoi(major)
	if err != nil || parsed < 0 {
		return 0, errors.New("invalid Docker version")
	}
	return parsed, nil
}

func atLeastDockerAPI(version string, requiredMajor, requiredMinor int) bool {
	major, minorText, found := strings.Cut(version, ".")
	if !found {
		return false
	}
	minor, suffix, _ := strings.Cut(minorText, ".")
	if suffix != "" || major == "" || minor == "" {
		return false
	}
	parsedMajor, majorErr := strconv.Atoi(major)
	parsedMinor, minorErr := strconv.Atoi(minor)
	if majorErr != nil || minorErr != nil || parsedMajor < 0 || parsedMinor < 0 {
		return false
	}
	return parsedMajor > requiredMajor || parsedMajor == requiredMajor && parsedMinor >= requiredMinor
}

type dockerInfoDocument struct {
	ID            string `json:"ID"`
	ServerVersion string `json:"ServerVersion"`
	OSType        string `json:"OSType"`
}

func parseDockerInfo(output []byte) (dockerInfoDocument, error) {
	var document dockerInfoDocument
	if err := json.Unmarshal(output, &document); err != nil {
		return dockerInfoDocument{}, fmt.Errorf("docker info must return structured JSON: %w", err)
	}
	if document.ID == "" || document.ServerVersion == "" || document.OSType != "linux" {
		return dockerInfoDocument{}, errors.New("docker daemon identity is incomplete or non-local-container")
	}
	return document, nil
}

type dockerImageDocument struct {
	ID          string   `json:"Id"`
	RepoDigests []string `json:"RepoDigests"`
}

func (adapter *DockerCLIAdapter) inspectImage(ctx context.Context, image string) (dockerImageDocument, error) {
	output, err := adapter.run(ctx, dockerInspectArgs(image))
	if err != nil {
		return dockerImageDocument{}, err
	}
	var documents []dockerImageDocument
	if err := json.Unmarshal(output, &documents); err != nil {
		return dockerImageDocument{}, fmt.Errorf("docker image inspect must return structured JSON: %w", err)
	}
	if len(documents) != 1 {
		return dockerImageDocument{}, errors.New("docker image inspect must return exactly one image")
	}
	document := documents[0]
	if !validDockerDigest(document.ID) || !containsDockerRepoDigest(document.RepoDigests, image) {
		return dockerImageDocument{}, errors.New("docker image does not match the requested local digest")
	}
	return document, nil
}

func dockerImageDescriptorDigest(image string) string {
	_, digest, _ := strings.Cut(image, "@")
	return digest
}

func validDockerDigest(value string) bool {
	return strings.HasPrefix(value, "sha256:") && len(value) == len("sha256:")+dockerDigestHexLength && isLowerHex(value[len("sha256:"):])
}

func containsDockerRepoDigest(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func sameDockerRepoDigests(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	counts := make(map[string]int, len(left))
	for _, value := range left {
		counts[value]++
	}
	for _, value := range right {
		if counts[value] == 0 {
			return false
		}
		counts[value]--
	}
	return true
}
