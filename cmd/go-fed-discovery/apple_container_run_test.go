package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

const appleLifecycleTestContainerID = "agnet-00000000000000000000000000000000"

func TestAppleContainerAdapterRunsConstrainedLifecycle(t *testing.T) {
	cleanApplePreflightEnvironment(t)
	runner := newAppleLifecycleFake(t, applePreflightTestImage)
	adapter := newAppleContainerCLIAdapter(runner, "/Users/alice")
	adapter.readFile = func(string) ([]byte, error) { return []byte("signed-apple-container"), nil }
	adapter.lifecycleRunner = runner
	adapter.newContainerID = func() (string, error) { return appleLifecycleTestContainerID, nil }

	got, err := adapter.Run(context.Background(), validAppleLifecycleRequest())
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Result) != "result" || got.MediaType != "application/octet-stream" {
		t.Fatalf("result = %#v", got)
	}
	if got.TranscriptMediaType != "application/json" || !strings.Contains(string(got.Transcript), "stdout_b64") || !strings.Contains(string(got.Transcript), "stderr_b64") {
		t.Fatalf("transcript = %q (%q)", got.Transcript, got.TranscriptMediaType)
	}
	if got.Evidence["runtime"] != "apple-container" || got.Evidence["image"] != applePreflightTestImage || got.Evidence["image_id"] != strings.TrimPrefix(strings.Split(applePreflightTestImage, "@")[1], "sha256:") || got.Evidence["container_id"] != appleLifecycleTestContainerID {
		t.Fatalf("evidence = %#v", got.Evidence)
	}

	want := []string{
		"container create --name " + appleLifecycleTestContainerID + " --read-only --cpus 1.5 --memory 268435456 --ulimit nofile=64:64 --ulimit nproc=64:64 --network none --no-dns --mount type=bind,source=",
		"container inspect " + appleLifecycleTestContainerID,
		"container start --attach " + appleLifecycleTestContainerID,
		"container inspect " + appleLifecycleTestContainerID,
		"container delete --force " + appleLifecycleTestContainerID,
	}
	assertAppleLifecycleSubsequence(t, runner.calls, want)
	if got := runner.calls[len(runner.calls)-1]; got != "container delete --force "+appleLifecycleTestContainerID {
		t.Fatalf("last runtime command = %q", got)
	}
	createCall := ""
	for _, call := range runner.calls {
		if strings.HasPrefix(call, "container create ") {
			createCall = call
			break
		}
	}
	if strings.Count(createCall, "--mount") != 1 || !strings.Contains(createCall, "--mount type=bind,source=") || !strings.Contains(createCall, ",target=/work") || strings.Contains(createCall, "tmpfs") || strings.Contains(createCall, "/work/input") || strings.Contains(createCall, "/work/result") {
		t.Fatalf("create call does not contain exactly one private workspace mount: %q", createCall)
	}
	for _, call := range runner.calls {
		if strings.Contains(call, "--volume") || strings.Contains(call, "--publish") || strings.Contains(call, "--ssh") || strings.Contains(call, " pull ") || strings.Contains(call, " build ") {
			t.Fatalf("unsafe lifecycle command %q", call)
		}
	}
	if _, err := os.Lstat(runner.workspace); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("private workspace survived cleanup: %v", err)
	}
}

func TestAppleContainerAdapterUsesAttachedStartAsObservedZeroExit(t *testing.T) {
	cleanApplePreflightEnvironment(t)
	runner := newAppleLifecycleFake(t, applePreflightTestImage)
	runner.omitInspectExitStatus = true
	adapter := newAppleContainerCLIAdapter(runner, "/Users/alice")
	adapter.readFile = func(string) ([]byte, error) { return []byte("signed-apple-container"), nil }
	adapter.lifecycleRunner = runner
	adapter.newContainerID = func() (string, error) { return appleLifecycleTestContainerID, nil }

	got, err := adapter.Run(context.Background(), validAppleLifecycleRequest())
	if err != nil {
		t.Fatalf("Run() failed when Apple inspect omitted exit status: %v", err)
	}
	observed, ok := got.Evidence["observed"].(map[string]any)
	if !ok || observed["exit_code"] != float64(0) {
		t.Fatalf("observed evidence = %#v; want exit_code 0", got.Evidence["observed"])
	}
	if err := validateContainerAdapterEvidence(validAppleLifecycleRequest(), "apple-container", got.Evidence); err != nil {
		t.Fatalf("Apple evidence failed strict promotion validation: %v", err)
	}
}

func TestAppleContainerAdapterCleansUpOnEveryLifecycleFailure(t *testing.T) {
	cleanApplePreflightEnvironment(t)
	for _, step := range []string{"create", "inspect", "start", "postflight", "delete"} {
		t.Run(step, func(t *testing.T) {
			runner := newAppleLifecycleFake(t, applePreflightTestImage)
			runner.failStep = step
			adapter := newAppleContainerCLIAdapter(runner, "/Users/alice")
			adapter.readFile = func(string) ([]byte, error) { return []byte("signed-apple-container"), nil }
			adapter.lifecycleRunner = runner
			adapter.newContainerID = func() (string, error) { return appleLifecycleTestContainerID, nil }

			if got, err := adapter.Run(context.Background(), validAppleLifecycleRequest()); err == nil || got.Result != nil || got.Evidence != nil {
				t.Fatalf("Run() = %#v, %v; want no result or evidence and an error", got, err)
			}
			if !containsAppleCall(runner.calls, "container delete --force "+appleLifecycleTestContainerID) {
				t.Fatalf("cleanup missing after %s: %#v", step, runner.calls)
			}
			if runner.calls[len(runner.calls)-1] != "container delete --force "+appleLifecycleTestContainerID {
				t.Fatalf("cleanup was not last: %#v", runner.calls)
			}
		})
	}
}

func TestAppleContainerAdapterRejectsUnsupportedMemoryBeforeRuntime(t *testing.T) {
	cleanApplePreflightEnvironment(t)
	runner := newAppleLifecycleFake(t, applePreflightTestImage)
	adapter := newAppleContainerCLIAdapter(runner, "/Users/alice")
	adapter.readFile = func(string) ([]byte, error) { return []byte("signed-apple-container"), nil }
	adapter.lifecycleRunner = runner
	request := validAppleLifecycleRequest()
	request.MemoryBytes = 199 << 20

	if _, err := adapter.Run(context.Background(), request); err == nil {
		t.Fatal("Run() succeeded below Apple Container's 200 MiB minimum")
	}
	if len(runner.calls) != 0 {
		t.Fatalf("runtime was invoked for unsupported memory: %#v", runner.calls)
	}
}

func TestAppleContainerAdapterNormalizesCurrentInspectSchema(t *testing.T) {
	request := validAppleLifecycleRequest()
	actualImage := "docker.io/library/node@sha256:a0b9bf06e4e6193cf7a0f58816cc935ff8c2a908f81e6f1a95432d679c54fbfd"
	workspace := "/private/tmp/agnet-apple-workspace-test"
	inspect := `[{"id":"` + appleLifecycleTestContainerID + `","configuration":{"id":"` + appleLifecycleTestContainerID + `","image":{"reference":"` + actualImage + `"},"mounts":[{"type":{"virtiofs":{}},"source":"` + workspace + `","destination":"/work","options":[]}],"networks":[],"dns":{"nameservers":[],"domain":null,"searchDomains":[],"options":[]},"initProcess":{"arguments":["/usr/local/bin/tool","--emit","ok"],"user":{"raw":{"userString":"65532:65532"}},"rlimits":[{"limit":"RLIMIT_NOFILE","soft":64,"hard":64},{"limit":"RLIMIT_NPROC","soft":64,"hard":64}]},"resources":{"cpus":1.5,"memoryInBytes":268435456},"readOnly":true,"capDrop":["ALL"]},"status":{"state":"stopped"}}]`

	normalized, state, err := normalizeAppleRunInspect([]byte(inspect))
	if err != nil {
		t.Fatal(err)
	}
	if !sameAppleInspectableImage(normalized.image, request.Image) {
		t.Fatalf("image %q did not match request %q", normalized.image, request.Image)
	}
	if state.running || state.exitKnown {
		t.Fatalf("state = %#v; want stopped without an inspect exit code", state)
	}
	if err := validateAppleInspectConstraints(normalized.configFingerprint, request, workspace); err != nil {
		t.Fatal(err)
	}
}

func TestAppleContainerAdapterRejectsUnsafeInspectWorkspaceMount(t *testing.T) {
	request := validAppleLifecycleRequest()
	workspace := "/private/tmp/agnet-apple-workspace-test"
	inspect := appleLifecycleInspectJSON(appleLifecycleTestContainerID, request.Image, workspace)
	for _, test := range []struct {
		name   string
		mutate func(string) string
	}{
		{
			name: "unexpected fake mount type",
			mutate: func(value string) string {
				return strings.Replace(value, `"type":{"virtiofs":{}}`, `"type":{"mysteryfs":{}}`, 1)
			},
		},
		{
			name: "different source",
			mutate: func(value string) string {
				return strings.Replace(value, `"source":"`+workspace+`"`, `"source":"`+workspace+`-substituted"`, 1)
			},
		},
		{
			name: "different destination",
			mutate: func(value string) string {
				return strings.Replace(value, `"destination":"/work"`, `"destination":"/work-substituted"`, 1)
			},
		},
		{
			name: "read only mount",
			mutate: func(value string) string {
				return strings.Replace(value, `"options":[]`, `"options":["ro"]`, 1)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			normalized, _, err := normalizeAppleRunInspect([]byte(test.mutate(inspect)))
			if err != nil {
				t.Fatal(err)
			}
			if err := validateAppleInspectConstraints(normalized.configFingerprint, request, workspace); err == nil {
				t.Fatal("validateAppleInspectConstraints() accepted unsafe workspace mount")
			}
		})
	}
}

func TestAppleContainerAdapterTimeoutCleansUp(t *testing.T) {
	cleanApplePreflightEnvironment(t)
	runner := newAppleLifecycleFake(t, applePreflightTestImage)
	runner.waitForCancel = true
	adapter := newAppleContainerCLIAdapter(runner, "/Users/alice")
	adapter.readFile = func(string) ([]byte, error) { return []byte("signed-apple-container"), nil }
	adapter.lifecycleRunner = runner
	adapter.newContainerID = func() (string, error) { return appleLifecycleTestContainerID, nil }
	request := validAppleLifecycleRequest()
	request.TimeoutMillis = 1

	if got, err := adapter.Run(context.Background(), request); err == nil || got.Result != nil {
		t.Fatalf("Run() = %#v, %v; want timeout without a result", got, err)
	}
	if runner.calls[len(runner.calls)-1] != "container delete --force "+appleLifecycleTestContainerID {
		t.Fatalf("cleanup was not last: %#v", runner.calls)
	}
}

func TestAppleLimitedCaptureRejectsOverflowWithoutResult(t *testing.T) {
	cleanApplePreflightEnvironment(t)
	runner := newAppleLifecycleFake(t, applePreflightTestImage)
	runner.stdout = strings.Repeat("x", 9)
	adapter := newAppleContainerCLIAdapter(runner, "/Users/alice")
	adapter.readFile = func(string) ([]byte, error) { return []byte("signed-apple-container"), nil }
	adapter.lifecycleRunner = runner
	adapter.newContainerID = func() (string, error) { return appleLifecycleTestContainerID, nil }
	request := validAppleLifecycleRequest()
	request.MaxOutputBytes = 8

	if got, err := adapter.Run(context.Background(), request); err == nil || got.Result != nil {
		t.Fatalf("Run() = %#v, %v; want bounded-output failure", got, err)
	}
	if !containsAppleCall(runner.calls, "container delete --force "+appleLifecycleTestContainerID) {
		t.Fatalf("cleanup missing: %#v", runner.calls)
	}
}

func TestAppleWorkspacePostflightRejectsUnsafeEntries(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(t *testing.T, workspace string)
	}{
		{"symlink", func(t *testing.T, workspace string) {
			result := filepath.Join(workspace, "result")
			if err := os.Remove(result); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("input/payload", result); err != nil {
				t.Fatal(err)
			}
		}},
		{"hardlink", func(t *testing.T, workspace string) {
			result := filepath.Join(workspace, "result")
			if err := os.Remove(result); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(filepath.Join(workspace, "input", "payload"), result); err != nil {
				t.Fatal(err)
			}
		}},
		{"device", func(t *testing.T, workspace string) {
			result := filepath.Join(workspace, "result")
			if err := os.Remove(result); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Mkfifo(result, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"extra entry", func(t *testing.T, workspace string) {
			if err := os.WriteFile(filepath.Join(workspace, "unexpected"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"aggregate overflow", func(t *testing.T, workspace string) {
			if err := os.WriteFile(filepath.Join(workspace, "result"), []byte("123456789"), 0o666); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			inputs := []DockerScratchInput{{Path: "payload", Bytes: []byte("input")}}
			workspace, inputBytes, err := stageAppleWorkspace(inputs)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := removeAppleWorkspace(workspace); err != nil {
					t.Error(err)
				}
			}()
			test.mutate(t, workspace)
			if err := validateAppleWorkspace(workspace, inputs, inputBytes, 8); err == nil {
				t.Fatal("validateAppleWorkspace() succeeded for unsafe workspace")
			}
		})
	}
}

func TestAppleWorkspaceIdentityRejectsSubstitution(t *testing.T) {
	workspace, _, err := stageAppleWorkspace(nil)
	if err != nil {
		t.Fatal(err)
	}
	parent := filepath.Dir(workspace)
	defer func() { _ = removeAppleWorkspace(workspace) }()
	pinned, err := pinAppleWorkspace(workspace)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(workspace, workspace+"-replaced"); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = removeAppleWorkspace(workspace + "-replaced") }()
	if err := os.Mkdir(filepath.Join(parent, filepath.Base(workspace)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := revalidateAppleWorkspace(workspace, pinned); err == nil {
		t.Fatal("revalidateAppleWorkspace() accepted substituted directory")
	}
}

type appleLifecycleFake struct {
	t                     *testing.T
	image                 string
	calls                 []string
	failStep              string
	stdout                string
	stderr                string
	inspects              int
	workspace             string
	waitForCancel         bool
	omitInspectExitStatus bool
}

func newAppleLifecycleFake(t *testing.T, image string) *appleLifecycleFake {
	return &appleLifecycleFake{t: t, image: image, stdout: "stdout", stderr: "stderr"}
}

func (f *appleLifecycleFake) Run(_ context.Context, executable string, arguments ...string) ([]byte, error) {
	if executable != appleContainerBinaryPath {
		return nil, fmt.Errorf("unexpected executable %q", executable)
	}
	call := "container " + strings.Join(arguments, " ")
	f.calls = append(f.calls, call)
	if strings.Join(arguments, " ") == "--version" {
		return []byte("container CLI version 1.1.0 (build: release, commit: 5973b9c)\n"), nil
	}
	if strings.Join(arguments, " ") == "system status --format json" {
		if f.failStep == "postflight" && countAppleCall(f.calls, "container system status --format json") > 2 {
			return []byte(strings.Replace(string(validAppleStatusJSON()), "5973b9c", "deadbee", 1)), nil
		}
		return validAppleStatusJSON(), nil
	}
	lookup, _, _ := strings.Cut(f.image, "@")
	if len(arguments) == 3 && arguments[0] == "image" && arguments[1] == "inspect" && arguments[2] == lookup {
		return validAppleImageInspectJSON(f.image), nil
	}
	switch arguments[0] {
	case "create":
		if f.failStep == "create" {
			return nil, errors.New("create failed")
		}
		for _, argument := range arguments {
			if !strings.HasPrefix(argument, "type=bind,source=") {
				continue
			}
			for _, field := range strings.Split(argument, ",") {
				if strings.HasPrefix(field, "source=") {
					f.workspace = strings.TrimPrefix(field, "source=")
				}
			}
		}
		return []byte(appleLifecycleTestContainerID + "\n"), nil
	case "inspect":
		if f.failStep == "inspect" {
			return nil, errors.New("inspect failed")
		}
		f.inspects++
		inspect := appleLifecycleInspectJSON(appleLifecycleTestContainerID, f.image, f.workspace)
		if f.omitInspectExitStatus {
			inspect = strings.Replace(inspect, `,"exit_code":0`, "", 1)
		}
		return []byte(inspect), nil
	case "delete":
		if f.failStep == "delete" {
			return nil, errors.New("delete failed")
		}
		return nil, nil
	default:
		return nil, fmt.Errorf("unexpected call %q", arguments)
	}
}

func (f *appleLifecycleFake) Start(ctx context.Context, executable string, arguments []string, stdout, stderr io.Writer) error {
	if executable != appleContainerBinaryPath {
		return fmt.Errorf("unexpected executable %q", executable)
	}
	f.calls = append(f.calls, "container "+strings.Join(arguments, " "))
	if f.waitForCancel {
		<-ctx.Done()
		return ctx.Err()
	}
	_, _ = stdout.Write([]byte(f.stdout))
	_, _ = stderr.Write([]byte(f.stderr))
	if f.workspace != "" {
		_ = os.WriteFile(filepath.Join(f.workspace, "result"), []byte("result"), 0o666)
	}
	if f.failStep == "start" {
		return errors.New("start failed")
	}
	return nil
}

func validAppleLifecycleRequest() DockerRunRequest {
	return DockerRunRequest{
		Image:   applePreflightTestImage,
		Command: []string{"/usr/local/bin/tool", "--emit", "ok"},
		CPUs:    "1.5", MemoryBytes: 256 << 20, TimeoutMillis: 30_000, MaxOutputBytes: 1 << 20,
		ScratchInputs: []DockerScratchInput{{Path: "a/input", Bytes: []byte("input")}},
	}
}
func appleLifecycleInspectJSON(id, image, workspace string) string {
	return `[{"id":"` + id + `","image":"` + image + `","image_id":"` + strings.TrimPrefix(strings.Split(image, "@")[1], "sha256:") + `","config":{"user":"65532:65532","cmd":["/usr/local/bin/tool","--emit","ok"],"read_only":true,"cpus":"1.5","memory":268435456,"network":"none","no_dns":true,"mounts":[{"source":"` + workspace + `","destination":"/work","options":[],"type":{"virtiofs":{}}}],"cap_drop":["ALL"],"ulimits":["nofile=64:64","nproc=64:64"]},"state":{"running":false,"exit_code":0}}]`
}

func assertAppleLifecycleSubsequence(t *testing.T, calls, want []string) {
	t.Helper()
	at := 0
	for _, call := range calls {
		if at < len(want) && strings.Contains(call, want[at]) {
			at++
		}
	}
	if at != len(want) {
		t.Fatalf("lifecycle calls = %#v; missing sequence %#v", calls, want[at:])
	}
}

func containsAppleCall(calls []string, want string) bool { return countAppleCall(calls, want) > 0 }
func countAppleCall(calls []string, want string) int {
	n := 0
	for _, call := range calls {
		if strings.Contains(call, want) {
			n++
		}
	}
	return n
}
