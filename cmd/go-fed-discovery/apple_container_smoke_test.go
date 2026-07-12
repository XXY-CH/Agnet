package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// TestAppleContainerRealIsolationSmoke deliberately exercises the production
// adapter against the one approved, already-local Apple Container image. It
// has no fallback: opting in with missing local prerequisites fails.
func TestAppleContainerRealIsolationSmoke(t *testing.T) {
	if os.Getenv("AGNET_APPLE_CONTAINER_SMOKE") != "1" {
		t.Skip("set AGNET_APPLE_CONTAINER_SMOKE=1 to run the Apple Container isolation smoke test")
	}
	if runtime.GOOS != "darwin" {
		t.Fatal("AGNET_APPLE_CONTAINER_SMOKE=1 requires Darwin and the local Apple Container runtime")
	}
	image := os.Getenv("AGNET_APPLE_CONTAINER_SMOKE_IMAGE")
	if image != applePreflightTestImage {
		t.Fatalf("AGNET_APPLE_CONTAINER_SMOKE_IMAGE = %q; want exact approved local image %q", image, applePreflightTestImage)
	}
	cleanApplePreflightEnvironment(t)

	homeDir, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	adapter := newAppleContainerCLIAdapter(appleContainerExecRunner{}, homeDir)
	assertNoAgnetAppleContainers(t)

	for _, scenario := range []struct {
		name       string
		command    string
		maxOutput  int64
		wantResult string
		wantErr    string
	}{
		{
			name: "UID 65532 scratch work and constraints",
			command: `set -eu
[ "$(id -u)" = "65532" ]
[ "$(id -g)" = "65532" ]
[ -r /work/input/payload ]
[ -w /work ]
[ "$(cat /work/input/payload)" = "scratch-bytes" ]
if printf mutate > /work/input/payload; then exit 19; fi
if printf denied > /etc/agnet-root-write; then exit 20; fi
if [ -r /proc/net/route ] && awk '$2 == "00000000" { found=1 } END { exit !found }' /proc/net/route; then exit 21; fi
if [ -e /etc/resolv.conf ] && [ -s /etc/resolv.conf ]; then exit 22; fi
printf result-bytes > /work/result
[ "$(cat /work/result)" = "result-bytes" ]
printf stdout-ok
printf stderr-ok >&2`,
			maxOutput:  4096,
			wantResult: "result-bytes",
		},
		{
			name:      "stdout one write overflow has no result",
			command:   "printf 123456789; printf ignored > /work/result",
			maxOutput: 8,
			wantErr:   "exceeded max_output_bytes",
		},
		{
			name:      "stderr one write overflow has no result",
			command:   "printf 123456789 >&2; printf ignored > /work/result",
			maxOutput: 8,
			wantErr:   "exceeded max_output_bytes",
		},
		{
			name:      "stdout many writes overflow has no result",
			command:   "printf 1234; printf 5678; printf 9; printf ignored > /work/result",
			maxOutput: 8,
			wantErr:   "exceeded max_output_bytes",
		},
		{
			name:      "oversize result has no promotable bytes",
			command:   "printf 123456789 > /work/result",
			maxOutput: 8,
			wantErr:   "exceeds max_output_bytes",
		},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			request := DockerRunRequest{
				Image:          image,
				Command:        []string{"/bin/sh", "-ceu", scenario.command},
				CPUs:           "1",
				MemoryBytes:    256 << 20,
				TimeoutMillis:  30_000,
				MaxOutputBytes: scenario.maxOutput,
				ScratchInputs:  []DockerScratchInput{{Path: "payload", Bytes: []byte("scratch-bytes")}},
			}
			result, err := adapter.Run(context.Background(), request)
			if scenario.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), scenario.wantErr) {
					t.Fatalf("Run() error = %v; want %q", err, scenario.wantErr)
				}
				if result.Result != nil || result.Transcript != nil || result.Evidence != nil {
					t.Fatalf("overflow Run() produced promotable result = %#v", result)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if got := string(result.Result); got != scenario.wantResult {
					t.Fatalf("result = %q; want %q", got, scenario.wantResult)
				}
				if result.Evidence["runtime"] != "apple-container" || result.Evidence["image"] != image || result.Evidence["image_id"] != strings.TrimPrefix(strings.Split(image, "@")[1], "sha256:") {
					t.Fatalf("runtime evidence = %#v", result.Evidence)
				}
				assertAppleSmokeTranscript(t, result.Transcript)
			}
			assertNoAgnetAppleContainers(t)
		})
	}
}

func assertAppleSmokeTranscript(t *testing.T, transcript []byte) {
	t.Helper()
	var encoded struct {
		StdoutB64 string `json:"stdout_b64"`
		StderrB64 string `json:"stderr_b64"`
	}
	if err := json.Unmarshal(transcript, &encoded); err != nil {
		t.Fatalf("decode bounded transcript: %v: %s", err, transcript)
	}
	stdout, err := base64.RawStdEncoding.DecodeString(encoded.StdoutB64)
	if err != nil {
		t.Fatalf("decode bounded stdout: %v", err)
	}
	stderr, err := base64.RawStdEncoding.DecodeString(encoded.StderrB64)
	if err != nil {
		t.Fatalf("decode bounded stderr: %v", err)
	}
	if string(stdout) != "stdout-ok" || !strings.Contains(string(stderr), "stderr-ok") {
		t.Fatalf("bounded transcript = stdout %q stderr %q", stdout, stderr)
	}
	if !strings.Contains(string(stderr), "/work/input/payload") || !strings.Contains(string(stderr), "/etc/agnet-root-write") {
		t.Fatalf("isolation denial diagnostics missing: %q", stderr)
	}
}

func assertNoAgnetAppleContainers(t *testing.T) {
	t.Helper()
	output, err := exec.Command(appleContainerBinaryPath, "list", "--all", "--format", "json").CombinedOutput()
	if err != nil {
		t.Fatalf("list Apple containers: %v: %s", err, output)
	}
	var containers []map[string]any
	if err := json.Unmarshal(output, &containers); err != nil {
		t.Fatalf("decode Apple container list: %v: %s", err, output)
	}
	for _, container := range containers {
		for _, key := range []string{"id", "name", "container_id", "containerID"} {
			if value, ok := container[key].(string); ok && strings.HasPrefix(value, "agnet-") {
				t.Fatalf("Agnet Apple container remains after smoke scenario: %s", value)
			}
		}
	}
}
