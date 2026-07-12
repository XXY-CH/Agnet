package main

import (
	"math"
	"reflect"
	"testing"
)

const testDockerImage = "registry.example/agent/tool:stable-1@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func validDockerWorkerProfile() DockerWorkerProfile {
	return DockerWorkerProfile{
		Image:   testDockerImage,
		Command: []string{"/usr/local/bin/tool", "--emit", "ok"},
		Limits: DockerLimits{
			CPUMillis:            1500,
			MemoryBytes:          64 << 20,
			TimeoutMillis:        30_000,
			MaxOutputBytes:       1 << 20,
			MaxScratchInputBytes: 32,
			MaxScratchBytes:      48,
		},
		ScratchInputs: []DockerScratchInput{
			{Path: "z/last.bin", BytesB64: "AAEC"},
			{Path: "a/first.bin", BytesB64: "cGF5bG9hZA"},
		},
	}
}

func TestDockerWorkerProfileNormalizesExactRequest(t *testing.T) {
	request, err := validateDockerWorkerProfile(validDockerWorkerProfile())
	if err != nil {
		t.Fatalf("validateDockerWorkerProfile() error = %v", err)
	}

	if request.Image != testDockerImage {
		t.Errorf("Image = %q; want %q", request.Image, testDockerImage)
	}
	if !reflect.DeepEqual(request.Command, []string{"/usr/local/bin/tool", "--emit", "ok"}) {
		t.Errorf("Command = %#v", request.Command)
	}
	if request.CPUs != "1.5" {
		t.Errorf("CPUs = %q; want 1.5", request.CPUs)
	}
	if request.MemoryBytes != 64<<20 || request.TimeoutMillis != 30_000 || request.MaxOutputBytes != 1<<20 {
		t.Errorf("request limits = %+v", request)
	}
	wantScratch := []DockerScratchInput{
		{Path: "a/first.bin", Bytes: []byte("payload")},
		{Path: "z/last.bin", Bytes: []byte{0, 1, 2}},
	}
	if !reflect.DeepEqual(request.ScratchInputs, wantScratch) {
		t.Errorf("ScratchInputs = %#v; want %#v", request.ScratchInputs, wantScratch)
	}
}

func TestDockerWorkerProfileRejectsInvalidImage(t *testing.T) {
	tests := []struct {
		name  string
		image string
	}{
		{name: "missing image", image: ""},
		{name: "uppercase", image: "registry.example/Agent/tool@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		{name: "tag only", image: "registry.example/agent/tool:latest"},
		{name: "empty tag", image: "registry.example/agent/tool:@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		{name: "uppercase tag", image: "registry.example/agent/tool:Stable@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		{name: "malformed tag", image: "registry.example/agent/tool:stable:1@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		{name: "multiple digest separators", image: "registry.example/agent/tool:stable@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		{name: "unsupported digest algorithm", image: "registry.example/agent/tool@sha512:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		{name: "short digest", image: "registry.example/agent/tool@sha256:0123456789abcdef"},
		{name: "nonhex digest", image: "registry.example/agent/tool@sha256:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"},
		{name: "whitespace", image: "registry.example/agent tool@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile := validDockerWorkerProfile()
			profile.Image = tt.image
			if _, err := validateDockerWorkerProfile(profile); err == nil {
				t.Fatal("validateDockerWorkerProfile() succeeded; want error")
			}
		})
	}
}

func TestDockerWorkerProfileRejectsInvalidCommand(t *testing.T) {
	tests := []struct {
		name    string
		command []string
	}{
		{name: "missing", command: nil},
		{name: "empty executable", command: []string{""}},
		{name: "nul executable", command: []string{"tool\x00evil"}},
		{name: "nul argument", command: []string{"tool", "--x=\x00"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile := validDockerWorkerProfile()
			profile.Command = tt.command
			if _, err := validateDockerWorkerProfile(profile); err == nil {
				t.Fatal("validateDockerWorkerProfile() succeeded; want error")
			}
		})
	}
}

func TestDockerWorkerProfileRejectsInvalidLimits(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*DockerLimits)
	}{
		{name: "zero cpu", mutate: func(l *DockerLimits) { l.CPUMillis = 0 }},
		{name: "negative cpu", mutate: func(l *DockerLimits) { l.CPUMillis = -1 }},
		{name: "zero memory", mutate: func(l *DockerLimits) { l.MemoryBytes = 0 }},
		{name: "negative memory", mutate: func(l *DockerLimits) { l.MemoryBytes = -1 }},
		{name: "zero timeout", mutate: func(l *DockerLimits) { l.TimeoutMillis = 0 }},
		{name: "negative timeout", mutate: func(l *DockerLimits) { l.TimeoutMillis = -1 }},
		{name: "zero output", mutate: func(l *DockerLimits) { l.MaxOutputBytes = 0 }},
		{name: "negative output", mutate: func(l *DockerLimits) { l.MaxOutputBytes = -1 }},
		{name: "zero input bound", mutate: func(l *DockerLimits) { l.MaxScratchInputBytes = 0 }},
		{name: "negative input bound", mutate: func(l *DockerLimits) { l.MaxScratchInputBytes = -1 }},
		{name: "zero aggregate bound", mutate: func(l *DockerLimits) { l.MaxScratchBytes = 0 }},
		{name: "negative aggregate bound", mutate: func(l *DockerLimits) { l.MaxScratchBytes = -1 }},
		{name: "cpu above cap", mutate: func(l *DockerLimits) { l.CPUMillis = dockerMaxCPUMillis + 1 }},
		{name: "memory above cap", mutate: func(l *DockerLimits) { l.MemoryBytes = dockerMaxMemoryBytes + 1 }},
		{name: "timeout above cap", mutate: func(l *DockerLimits) { l.TimeoutMillis = dockerMaxTimeoutMillis + 1 }},
		{name: "output above cap", mutate: func(l *DockerLimits) { l.MaxOutputBytes = dockerMaxOutputBytes + 1 }},
		{name: "input bound above cap", mutate: func(l *DockerLimits) { l.MaxScratchInputBytes = dockerMaxScratchBytes + 1 }},
		{name: "aggregate bound above cap", mutate: func(l *DockerLimits) { l.MaxScratchBytes = dockerMaxScratchBytes + 1 }},
		{name: "input bound exceeds aggregate", mutate: func(l *DockerLimits) { l.MaxScratchInputBytes = l.MaxScratchBytes + 1 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile := validDockerWorkerProfile()
			tt.mutate(&profile.Limits)
			if _, err := validateDockerWorkerProfile(profile); err == nil {
				t.Fatal("validateDockerWorkerProfile() succeeded; want error")
			}
		})
	}
}

func TestDockerWorkerProfileRejectsInvalidScratchInputs(t *testing.T) {
	tests := []struct {
		name   string
		inputs []DockerScratchInput
		limits func(*DockerLimits)
	}{
		{name: "empty path", inputs: []DockerScratchInput{{Path: "", BytesB64: "AA"}}},
		{name: "absolute path", inputs: []DockerScratchInput{{Path: "/tmp/input", BytesB64: "AA"}}},
		{name: "traversal", inputs: []DockerScratchInput{{Path: "dir/../input", BytesB64: "AA"}}},
		{name: "leading traversal", inputs: []DockerScratchInput{{Path: "../input", BytesB64: "AA"}}},
		{name: "backslash", inputs: []DockerScratchInput{{Path: "dir\\input", BytesB64: "AA"}}},
		{name: "nul", inputs: []DockerScratchInput{{Path: "dir/\x00input", BytesB64: "AA"}}},
		{name: "duplicate path", inputs: []DockerScratchInput{{Path: "input", BytesB64: "AA"}, {Path: "input", BytesB64: "AQ"}}},
		{name: "padded base64", inputs: []DockerScratchInput{{Path: "input", BytesB64: "AA=="}}},
		{name: "malformed base64", inputs: []DockerScratchInput{{Path: "input", BytesB64: "***"}}},
		{name: "per input exceeds bound", inputs: []DockerScratchInput{{Path: "input", BytesB64: "AAEC"}}, limits: func(l *DockerLimits) { l.MaxScratchInputBytes = 2 }},
		{name: "aggregate exceeds bound", inputs: []DockerScratchInput{{Path: "a", BytesB64: "AAEC"}, {Path: "b", BytesB64: "AwQF"}}, limits: func(l *DockerLimits) { l.MaxScratchBytes = 5 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile := validDockerWorkerProfile()
			profile.ScratchInputs = tt.inputs
			if tt.limits != nil {
				tt.limits(&profile.Limits)
			}
			if _, err := validateDockerWorkerProfile(profile); err == nil {
				t.Fatal("validateDockerWorkerProfile() succeeded; want error")
			}
		})
	}
}

func TestDockerWorkerProfileRejectsAggregateOverflow(t *testing.T) {
	if _, err := checkedDockerScratchTotal(math.MaxInt64, 1, math.MaxInt64); err == nil {
		t.Fatal("checkedDockerScratchTotal() succeeded; want overflow error")
	}
}
func TestDockerWorkerProfileRenderCPUs(t *testing.T) {
	tests := []struct {
		milli int64
		want  string
	}{
		{milli: 1, want: "0.001"},
		{milli: 999, want: "0.999"},
		{milli: 1000, want: "1"},
		{milli: 1500, want: "1.5"},
		{milli: 64_000, want: "64"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := renderCPUs(tt.milli); got != tt.want {
				t.Errorf("renderCPUs(%d) = %q; want %q", tt.milli, got, tt.want)
			}
		})
	}
}
