//go:build docker_smoke

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
)

const (
	dockerSmokeOptIn = "AGNET_DOCKER_SMOKE"
	dockerSmokeImage = "docker.io/library/node:24-alpine@sha256:a0b9bf06e4e6193cf7a0f58816cc935ff8c2a908f81e6f1a95432d679c54fbfd"
	dockerSmokeInput = "deterministic docker smoke input\n"
)

type dockerSmokeRunner struct {
	mu       sync.Mutex
	commands []DockerCommand
}

func (r *dockerSmokeRunner) Run(ctx context.Context, command DockerCommand) ([]byte, error) {
	r.record(command)
	process := exec.CommandContext(ctx, command.Path, command.Args...)
	process.Env = append([]string(nil), command.Env...)
	process.Stdin = bytes.NewReader(command.Stdin)
	output, err := process.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

func (r *dockerSmokeRunner) RunStreaming(ctx context.Context, command DockerCommand) (io.ReadCloser, io.ReadCloser, func() error, error) {
	r.record(command)
	process := exec.CommandContext(ctx, command.Path, command.Args...)
	process.Env = append([]string(nil), command.Env...)
	process.Stdin = bytes.NewReader(command.Stdin)
	stdout, err := process.StdoutPipe()
	if err != nil {
		return nil, nil, nil, err
	}
	stderr, err := process.StderrPipe()
	if err != nil {
		return nil, nil, nil, err
	}
	if err := process.Start(); err != nil {
		return nil, nil, nil, err
	}
	return stdout, stderr, process.Wait, nil
}

func (r *dockerSmokeRunner) record(command DockerCommand) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.commands = append(r.commands, DockerCommand{
		Path:  command.Path,
		Args:  append([]string(nil), command.Args...),
		Env:   append([]string(nil), command.Env...),
		Stdin: append([]byte(nil), command.Stdin...),
	})
}

func (r *dockerSmokeRunner) snapshot() []DockerCommand {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]DockerCommand(nil), r.commands...)
}

func TestDockerCompatibilitySmoke(t *testing.T) {
	adapter, runner := requireDockerSmokeAdapter(t)

	probe, err := adapter.Preflight(context.Background(), dockerSmokeImage)
	if err != nil {
		t.Fatalf("BLOCKED: Docker prerequisite failure (the exact preloaded image is required; no pull/build is attempted): %v", err)
	}
	if probe.Image != dockerSmokeImage || probe.ImageDescriptorDigest != strings.Split(dockerSmokeImage, "@")[1] || !validDockerDigest(probe.ImageID) {
		t.Fatalf("preflight did not prove the exact local image: %#v", probe)
	}

	result, err := adapter.Run(context.Background(), dockerSmokeRequest(dockerSmokeProgram()))
	if err != nil {
		t.Fatalf("DockerCLIAdapter.Run() error = %v", err)
	}
	if got, want := string(result.Result), "docker-smoke:"+dockerSmokeInput; got != want {
		t.Fatalf("result = %q, want %q", got, want)
	}
	if result.Evidence["runtime"] != "docker" || result.Evidence["image"] != dockerSmokeImage || !validDockerContainerID(fmt.Sprint(result.Evidence["container_id"])) {
		t.Fatalf("DockerCLIAdapter evidence = %#v", result.Evidence)
	}
	assertDockerSmokeTranscript(t, result.Transcript)
	assertDockerSmokeCreateConstraints(t, runner.snapshot())
	assertDockerSmokeForceRemoval(t, runner.snapshot())
}

func TestDockerCompatibilitySmokeRejectsOutputOverflow(t *testing.T) {
	adapter, runner := requireDockerSmokeAdapter(t)
	if _, err := adapter.Preflight(context.Background(), dockerSmokeImage); err != nil {
		t.Fatalf("BLOCKED: Docker prerequisite failure (the exact preloaded image is required; no pull/build is attempted): %v", err)
	}

	request := dockerSmokeRequest(`process.stdout.write("012345678");`)
	request.MaxOutputBytes = 8
	result, err := adapter.Run(context.Background(), request)
	if err == nil || result.Result != nil {
		t.Fatalf("Run() = %#v, %v; want bounded-output failure without promotable result", result, err)
	}
	assertDockerSmokeForceRemoval(t, runner.snapshot())
}

func requireDockerSmokeAdapter(t *testing.T) (*DockerCLIAdapter, *dockerSmokeRunner) {
	t.Helper()
	if os.Getenv(dockerSmokeOptIn) != "1" {
		t.Skipf("set %s=1 to run the real local-Docker compatibility smoke; it never falls back to Apple Container", dockerSmokeOptIn)
	}
	if err := dockerSmokePrerequisites(); err != nil {
		t.Fatalf("BLOCKED: Docker prerequisite failure: %v", err)
	}
	runner := &dockerSmokeRunner{}
	adapter, err := NewDockerCLIAdapter(runner, DockerHost{
		CommandPath:    dockerCommandPath,
		SocketPath:     dockerLocalUnixSocket,
		Environment:    os.Environ(),
		BinaryDigest:   dockerSmokeBinaryDigest,
		SocketIdentity: dockerSmokeSocketIdentity,
	})
	if err != nil {
		t.Fatalf("BLOCKED: Docker prerequisite failure: %v", err)
	}
	return adapter, runner
}

func dockerSmokePrerequisites() error {
	binary, err := os.Stat(dockerCommandPath)
	if err != nil {
		return fmt.Errorf("required Docker binary %q is unavailable: %w", dockerCommandPath, err)
	}
	if !binary.Mode().IsRegular() || binary.Mode()&0o111 == 0 {
		return fmt.Errorf("required Docker binary %q is not an executable regular file", dockerCommandPath)
	}
	if _, err := dockerSmokeSocketIdentity(dockerLocalUnixSocket); err != nil {
		return fmt.Errorf("required local Docker socket %q is unavailable or unsafe: %w", dockerLocalUnixSocket, err)
	}
	return nil
}

func dockerSmokeBinaryDigest(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func dockerSmokeSocketIdentity(path string) (DockerSocketIdentity, error) {
	info, err := os.Stat(path)
	if err != nil {
		return DockerSocketIdentity{}, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return DockerSocketIdentity{}, errors.New("Docker socket has no Unix stat identity")
	}
	return DockerSocketIdentity{
		Device: uint64(stat.Dev),
		Inode:  uint64(stat.Ino),
		Mode:   uint32(stat.Mode),
		UID:    uint32(stat.Uid),
	}, nil
}

func dockerSmokeRequest(program string) DockerRunRequest {
	return DockerRunRequest{
		Image:          dockerSmokeImage,
		Command:        []string{"node", "-e", program},
		CPUs:           "1.5",
		MemoryBytes:    64 << 20,
		TimeoutMillis:  30_000,
		MaxOutputBytes: 1 << 20,
		ScratchInputs:  []DockerScratchInput{{Path: "payload.txt", Bytes: []byte(dockerSmokeInput)}},
	}
}

func dockerSmokeProgram() string {
	return `const fs = require("node:fs");
const os = require("node:os");
const fail = (message) => { console.error(message); process.exit(1); };
try {
  if (fs.readFileSync("/work/payload.txt", "utf8") !== "deterministic docker smoke input\\n") fail("scratch input changed");
  if (Object.keys(os.networkInterfaces()).some((name) => name !== "lo")) fail("default network interface present");
  for (const path of ["/root/agnet-smoke", "/tmp/agnet-smoke"]) {
    try { fs.writeFileSync(path, "blocked"); fail("root filesystem accepted write: " + path); }
    catch (error) { if (error && error.message && error.message.startsWith("root filesystem accepted write:")) throw error; }
  }
  fs.writeFileSync("/work/only-writable", "ok");
  fs.writeFileSync("/work/result", "docker-smoke:" + fs.readFileSync("/work/payload.txt", "utf8"));
  process.stdout.write("stdout-ok\\n");
  process.stderr.write("stderr-ok\\n");
} catch (error) { console.error(error.stack || String(error)); process.exit(1); }`
}

func assertDockerSmokeTranscript(t *testing.T, transcript []byte) {
	t.Helper()
	var captured struct {
		Stdout string `json:"stdout_b64"`
		Stderr string `json:"stderr_b64"`
	}
	if err := json.Unmarshal(transcript, &captured); err != nil {
		t.Fatalf("transcript JSON = %q: %v", transcript, err)
	}
	stdout, stdoutErr := base64.RawStdEncoding.DecodeString(captured.Stdout)
	stderr, stderrErr := base64.RawStdEncoding.DecodeString(captured.Stderr)
	if stdoutErr != nil || stderrErr != nil || string(stdout) != "stdout-ok\n" || string(stderr) != "stderr-ok\n" {
		t.Fatalf("bounded transcript = stdout %q (%v), stderr %q (%v)", stdout, stdoutErr, stderr, stderrErr)
	}
}

func assertDockerSmokeCreateConstraints(t *testing.T, commands []DockerCommand) {
	t.Helper()
	var create []string
	for _, command := range commands {
		if len(command.Args) > 4 && command.Args[4] == "create" {
			create = command.Args
			break
		}
	}
	if create == nil {
		t.Fatalf("DockerCLIAdapter did not create a container: %#v", commands)
	}
	for _, pair := range [][2]string{
		{"--read-only", ""},
		{"--cpus", "1.5"},
		{"--memory", "67108864"},
		{"--ulimit", "nofile=64:64"},
		{"--network", "none"},
		{"--cap-drop", "ALL"},
		{"--user", dockerContainerUser},
		{"--tmpfs", "/work:rw,nosuid,nodev,noexec,size=67108864"},
	} {
		if !dockerSmokeHasArgument(create, pair[0], pair[1]) {
			t.Fatalf("Docker create command lacks %q %q: %#v", pair[0], pair[1], create)
		}
	}
}

func dockerSmokeHasArgument(arguments []string, flag, value string) bool {
	for index, argument := range arguments {
		if argument == flag && (value == "" || index+1 < len(arguments) && arguments[index+1] == value) {
			return true
		}
	}
	return false
}

func assertDockerSmokeForceRemoval(t *testing.T, commands []DockerCommand) {
	t.Helper()
	if len(commands) == 0 {
		t.Fatal("DockerCLIAdapter issued no lifecycle commands")
	}
	last := commands[len(commands)-1].Args
	if len(last) < 7 || last[4] != "rm" || last[5] != "--force" || !validDockerContainerID(last[6]) {
		t.Fatalf("DockerCLIAdapter did not force-remove its container last: %#v", commands[len(commands)-1])
	}
}

func TestDockerCompatibilitySmokeDoesNotRunWithoutOptIn(t *testing.T) {
	if os.Getenv(dockerSmokeOptIn) == "1" {
		t.Skip("opt-in is active; prerequisite behavior is exercised by the real smoke tests")
	}
	adapter, _ := requireDockerSmokeAdapter(t)
	if adapter != nil {
		t.Fatal("real Docker adapter initialized without explicit opt-in")
	}
}
