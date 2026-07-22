package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type binaryDockerAdapter struct {
	result   DockerRunResult
	requests []DockerRunRequest
}

func (a *binaryDockerAdapter) Run(_ context.Context, request DockerRunRequest) (DockerRunResult, error) {
	a.requests = append(a.requests, request)
	return a.result, nil
}

func TestContainerNamespaceProbe(t *testing.T) {
	t.Setenv("AGNET_CONTAINER_RUNTIME", "")
	defaultProbe := containerNamespaceProbe("container-namespace")
	if got := defaultProbe["runtime"]; got != "apple-container" {
		t.Fatalf("Darwin default runtime = %q, want apple-container", got)
	}
	if defaultProbe["supported"] != false {
		t.Fatalf("default probe must not claim an execution adapter: %#v", defaultProbe)
	}

	t.Setenv("AGNET_CONTAINER_RUNTIME", "docker")
	dockerProbe := containerNamespaceProbe("container-namespace")
	if got := dockerProbe["runtime"]; got != "docker" {
		t.Fatalf("explicit Docker runtime = %q", got)
	}

	t.Setenv("AGNET_CONTAINER_RUNTIME", "/tmp/untrusted-runtime")
	invalidProbe := containerNamespaceProbe("container-namespace")
	if invalidProbe["supported"] != false || !strings.Contains(invalidProbe["reason"].(string), "AGNET_CONTAINER_RUNTIME") {
		t.Fatalf("unsafe runtime probe = %#v", invalidProbe)
	}
}

func TestRunToolReturnsBinary(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("AGNET_CONTAINER_RUNTIME", "docker")
	want := []byte{0x00, 0xff, 0x01, '\n', 0x80}
	marker := filepath.Join(t.TempDir(), "host-external-ran")
	adapter := &binaryDockerAdapter{result: DockerRunResult{
		Result:              append([]byte(nil), want...),
		MediaType:           "application/octet-stream",
		Transcript:          []byte{0x00, 0xff},
		TranscriptMediaType: "application/octet-stream",
		Evidence: map[string]any{
			"runtime":      "docker",
			"image":        "registry.example/agent/tool@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			"image_id":     "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			"container_id": strings.Repeat("a", 64),
		},
	}}
	profile := WorkerProfile{
		Tool:         "external.stdio",
		ToolCommand:  []string{"/bin/sh", "-c", "touch " + marker},
		SandboxClaim: "container-namespace",
		Docker: &DockerWorkerProfile{
			Image:   "registry.example/agent/tool@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			Command: []string{"/usr/local/bin/tool"},
			Limits: DockerLimits{
				CPUMillis:            1_000,
				MemoryBytes:          1,
				TimeoutMillis:        1,
				MaxOutputBytes:       1,
				MaxScratchInputBytes: 1,
				MaxScratchBytes:      1,
			},
		},
	}
	request, err := validateDockerWorkerProfile(*profile.Docker)
	if err != nil {
		t.Fatal(err)
	}
	adapter.result.Evidence = verifiedContainerAdapterEvidence("docker", request)
	_, result, sandbox, err := runToolWithDockerAdapter(context.Background(), adapter, profile, nil, nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result.Result, want) {
		t.Fatalf("result bytes = %x, want %x", result.Result, want)
	}
	if result.MediaType != "application/octet-stream" {
		t.Fatalf("media type = %q", result.MediaType)
	}
	if got := sandbox["mode"]; got != "container-namespace" {
		t.Fatalf("sandbox mode = %q", got)
	}
	if len(adapter.requests) != 1 {
		t.Fatalf("adapter runs = %d, want 1", len(adapter.requests))
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("container profile fell through to host external tool: %v", err)
	}
}

func TestRunToolRejectsContainerWithoutAdapter(t *testing.T) {
	profile := WorkerProfile{
		Tool:         "summarize.mock",
		SandboxClaim: "container-namespace",
		Docker: &DockerWorkerProfile{
			Image:   "registry.example/agent/tool@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			Command: []string{"/usr/local/bin/tool"},
			Limits: DockerLimits{
				CPUMillis:            1_000,
				MemoryBytes:          1,
				TimeoutMillis:        1,
				MaxOutputBytes:       1,
				MaxScratchInputBytes: 1,
				MaxScratchBytes:      1,
			},
		},
	}
	_, _, _, err := runTool(context.Background(), profile, map[string]any{"task_id": "container_no_adapter"}, map[string]any{}, "", "")
	if err == nil || err.Error() != "container_adapter_unavailable" {
		t.Fatalf("runTool() error = %v", err)
	}

	profile.SandboxClaim = "in-process"
	if err := validateSandboxClaim(profile); err == nil {
		t.Fatal("validateSandboxClaim() accepted a Docker profile outside container-namespace")
	}
}

func TestRunExternalToolStagesTranscriptWithoutArtifactPublication(t *testing.T) {
	t.Chdir(t.TempDir())
	profile := WorkerProfile{
		Tool:        "external.stdio",
		ToolCommand: []string{"/bin/sh", "-c", `printf '{"text":"external result"}'`},
	}
	_, result, _, err := runTool(context.Background(), profile, map[string]any{
		"task_id": "tool_result_external",
		"intent":  "test staging",
		"to":      "agent://test/worker",
	}, map[string]any{"zid": "zone://test"}, filepath.Join(t.TempDir(), "artifact-store"), "")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(result.Result), "external result"; got != want {
		t.Fatalf("result = %q, want %q", got, want)
	}
	if got, want := result.MediaType, "text/markdown; charset=utf-8"; got != want {
		t.Fatalf("media type = %q, want %q", got, want)
	}
	if got, want := string(result.Transcript), `{"text":"external result"}`; got != want {
		t.Fatalf("transcript = %q, want %q", got, want)
	}
	if _, err := os.Stat("artifacts"); !os.IsNotExist(err) {
		t.Fatalf("tool execution published artifact before task success: %v", err)
	}
}

func TestRunExternalToolReceivesExactPayloadInStdin(t *testing.T) {
	t.Chdir(t.TempDir())
	marker := filepath.Join(t.TempDir(), "external-stdin.json")
	profile := WorkerProfile{
		Tool:        "external.stdio",
		ToolCommand: []string{"/bin/sh", "-c", `tmp=$1; cat > "$tmp"; printf '{"text":"external result"}'`, "sh", marker},
	}
	payload := map[string]any{
		"message": "hello",
		"nested": map[string]any{
			"flag": true,
			"tags": []any{"alpha", "beta"},
		},
	}
	task := map[string]any{
		"task_id": "tool_result_external_payload",
		"intent":  "test staging",
		"to":      "agent://test/worker",
		"payload": payload,
	}
	result, _, err := runExternalTool(context.Background(), profile, task, map[string]any{"zid": "zone://test"}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(result.Result), "external result"; got != want {
		t.Fatalf("result = %q, want %q", got, want)
	}
	stdinData, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	var stdin map[string]any
	if err := json.Unmarshal(stdinData, &stdin); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(stdin["payload"], payload) {
		t.Fatalf("stdin payload = %#v, want %#v", stdin["payload"], payload)
	}
	if got, want := stdin["task_id"], task["task_id"]; got != want {
		t.Fatalf("stdin task_id = %#v, want %#v", got, want)
	}
}

func TestMCPToolStagesTextAndTranscript(t *testing.T) {
	t.Chdir(t.TempDir())
	profile := WorkerProfile{
		Tool:        "mcp.stdio",
		ToolName:    "echo",
		ToolCommand: []string{os.Args[0], "-test.run=^TestMCPToolProcess$"},
	}
	_, result, _, err := runTool(context.Background(), profile, map[string]any{
		"task_id": "tool_result_mcp",
		"intent":  "test MCP staging",
		"to":      "agent://test/worker",
	}, map[string]any{"zid": "zone://test"}, filepath.Join(t.TempDir(), "artifact-store"), "")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(result.Result), "mcp result"; got != want {
		t.Fatalf("result = %q, want %q", got, want)
	}
	if got, want := result.MediaType, "text/markdown; charset=utf-8"; got != want {
		t.Fatalf("media type = %q, want %q", got, want)
	}
	if len(result.Transcript) == 0 || result.TranscriptMediaType != "application/json; charset=utf-8" {
		t.Fatalf("MCP transcript not staged: %#v", result)
	}
	if _, err := os.Stat("artifacts"); !os.IsNotExist(err) {
		t.Fatalf("MCP tool execution published artifact before task success: %v", err)
	}
}

func TestMCPToolProcess(t *testing.T) {
	if len(os.Args) < 2 || os.Args[len(os.Args)-1] != "-test.run=^TestMCPToolProcess$" {
		return
	}
	scanner := bufio.NewScanner(os.Stdin)
	encoder := json.NewEncoder(os.Stdout)
	for scanner.Scan() {
		var request map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &request); err != nil {
			t.Fatal(err)
		}
		id, hasID := request["id"]
		if !hasID {
			continue
		}
		response := map[string]any{"jsonrpc": "2.0", "id": id}
		switch request["method"] {
		case "initialize":
			response["result"] = map[string]any{"protocolVersion": "2025-11-25", "serverInfo": map[string]any{"name": "test"}}
		case "resources/list":
			response["result"] = map[string]any{"resources": []any{}}
		case "prompts/list":
			response["result"] = map[string]any{"prompts": []any{}}
		case "tools/list":
			response["result"] = map[string]any{"tools": []any{map[string]any{"name": "echo", "inputSchema": map[string]any{"required": []any{"task_id", "intent", "to", "origin"}}}}}
		case "tools/call":
			response["result"] = map[string]any{"content": []any{map[string]any{"type": "text", "text": "mcp result"}}}
		default:
			t.Fatalf("unexpected MCP method %q", request["method"])
		}
		if err := encoder.Encode(response); err != nil {
			t.Fatal(err)
		}
	}
}
