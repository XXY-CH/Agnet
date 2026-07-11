package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
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
	if !validDockerImageName(name) {
		return errors.New("docker image name is invalid")
	}
	return nil
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
