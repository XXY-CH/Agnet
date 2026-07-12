package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func runTool(ctx context.Context, profile WorkerProfile, task, origin map[string]any, artifactStoreDir, liveTranscriptDir string) (string, ToolResult, map[string]any, error) {
	return runToolWithContainerAdapter(ctx, nil, profile, task, origin, artifactStoreDir, liveTranscriptDir)
}

// runToolWithDockerAdapter is retained for Docker-focused callers. Apple and
// Docker adapters share the deliberately narrow DockerAdapter result contract.
func runToolWithDockerAdapter(ctx context.Context, adapter DockerAdapter, profile WorkerProfile, task, origin map[string]any, artifactStoreDir, liveTranscriptDir string) (string, ToolResult, map[string]any, error) {
	return runToolWithContainerAdapter(ctx, adapter, profile, task, origin, artifactStoreDir, liveTranscriptDir)
}

// runToolWithContainerAdapter is the sole container execution seam. Passing a
// nil adapter deliberately rejects a container profile rather than falling
// through to a host, external, or MCP tool.
func runToolWithContainerAdapter(ctx context.Context, adapter DockerAdapter, profile WorkerProfile, task, origin map[string]any, artifactStoreDir, liveTranscriptDir string) (string, ToolResult, map[string]any, error) {
	tool := profile.Tool
	if tool == "" {
		tool = "text.echo"
	}
	if profile.SandboxClaim == "container-namespace" {
		result, sandbox, err := runDockerTool(ctx, adapter, profile)
		return tool, result, sandbox, err
	}
	if profile.Docker != nil {
		return tool, ToolResult{}, nil, errors.New("docker profile requires container-namespace sandbox claim")
	}
	taskID := fmt.Sprint(task["task_id"])
	intent := fmt.Sprint(task["intent"])
	textResult := func(text string) ToolResult {
		return ToolResult{Result: []byte(text), MediaType: "text/markdown; charset=utf-8"}
	}
	switch tool {
	case "summarize.mock":
		return tool, textResult("# Go Tool Summary\n\nTask: " + taskID + "\nOrigin: " + fmt.Sprint(origin["zid"]) + "\nSummary: " + intent + "\n"), inProcessSandbox(), nil
	case "translate.mock":
		return tool, textResult("# Go Tool Translation\n\nTask: " + taskID + "\nOrigin: " + fmt.Sprint(origin["zid"]) + "\nTranslation: " + strings.ToUpper(intent) + "\n"), inProcessSandbox(), nil
	case "external.stdio":
		result, sandbox, err := runExternalTool(ctx, profile, task, origin, artifactStoreDir, liveTranscriptDir)
		return tool, result, sandbox, err
	case "mcp.stdio":
		result, sandbox, err := runMCPTool(ctx, profile, task, origin, artifactStoreDir, liveTranscriptDir)
		return tool, result, sandbox, err
	default:
		return tool, textResult("# Go Tool Output\n\nTask: " + taskID + "\nOrigin: " + fmt.Sprint(origin["zid"]) + "\nOutput: " + intent + "\n"), inProcessSandbox(), nil
	}
}

func runDockerTool(ctx context.Context, adapter DockerAdapter, profile WorkerProfile) (ToolResult, map[string]any, error) {
	if profile.Docker == nil {
		return ToolResult{}, nil, errors.New("container_profile_missing")
	}
	request, err := validateDockerWorkerProfile(*profile.Docker)
	if err != nil {
		return ToolResult{}, nil, errors.New("container_profile_invalid")
	}
	if adapter == nil {
		return ToolResult{}, nil, errors.New("container_adapter_unavailable")
	}
	runtimeKind, err := configuredContainerRuntime()
	if err != nil {
		return ToolResult{}, nil, errors.New("container_runtime_invalid")
	}
	dockerResult, err := adapter.Run(ctx, request)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return ToolResult{}, nil, errors.New("container_timeout")
		}
		return ToolResult{}, nil, errors.New("container_adapter_failed")
	}
	if err := validateContainerAdapterEvidence(request, runtimeKind, dockerResult.Evidence); err != nil {
		return ToolResult{}, nil, errors.New("container_evidence_invalid")
	}
	return ToolResult{
		Result:              dockerResult.Result,
		MediaType:           dockerResult.MediaType,
		Transcript:          dockerResult.Transcript,
		TranscriptMediaType: dockerResult.TranscriptMediaType,
		Evidence:            dockerResult.Evidence,
	}, map[string]any{"mode": "container-namespace"}, nil
}

const containerAdapterEvidenceFormat = "agnet-container-adapter-evidence/v1"

func containerAdapterConstraints(request DockerRunRequest) map[string]any {
	return map[string]any{
		"command":                 append([]string(nil), request.Command...),
		"cpu_millis":              float64(dockerNanoCPUs(request.CPUs) / 1_000_000),
		"memory_bytes":            float64(request.MemoryBytes),
		"timeout_millis":          float64(request.TimeoutMillis),
		"max_output_bytes":        float64(request.MaxOutputBytes),
		"max_scratch_input_bytes": float64(request.MaxScratchInputBytes),
		"max_scratch_bytes":       float64(request.MaxScratchBytes),
		"network":                 "none",
		"read_only_rootfs":        true,
		"user":                    dockerContainerUser,
		"cap_drop":                []string{"ALL"},
		"nofile_limit":            float64(64),
	}
}

func dockerRuntimeIdentity(probe DockerProbe) map[string]any {
	return map[string]any{
		"runtime":                 "docker",
		"image":                   probe.Image,
		"image_id":                probe.ImageID,
		"image_descriptor_digest": probe.ImageDescriptorDigest,
		"command_path":            probe.CommandPath,
		"socket_path":             probe.SocketPath,
		"socket_device":           strconv.FormatUint(probe.Socket.Device, 10),
		"socket_inode":            strconv.FormatUint(probe.Socket.Inode, 10),
		"socket_mode":             strconv.FormatUint(uint64(probe.Socket.Mode), 10),
		"socket_uid":              strconv.FormatUint(uint64(probe.Socket.UID), 10),
		"binary_digest":           probe.BinaryDigest,
		"client_version":          probe.ClientVersion,
		"client_api_version":      probe.ClientAPIVersion,
		"daemon_id":               probe.DaemonID,
		"daemon_version":          probe.DaemonVersion,
		"daemon_api_version":      probe.DaemonAPIVersion,
	}
}

func appleRuntimeIdentity(proof AppleContainerPreflightEvidence) map[string]any {
	return map[string]any{
		"runtime":                 "apple-container",
		"image":                   proof.Image,
		"image_id":                proof.ImageID,
		"image_descriptor_digest": proof.ImageDescriptorDigest,
		"binary_path":             proof.BinaryPath,
		"binary_digest":           proof.BinaryDigestBefore,
		"cli_version":             proof.CLIVersionBefore,
		"cli_commit":              proof.CLICommit,
		"api_server_version":      proof.APIServerVersion,
		"api_server_commit":       proof.APIServerCommit,
		"app_root":                proof.AppRoot,
	}
}

func requiredContainerRuntimeIdentityFields(runtimeKind string) []string {
	if runtimeKind == "docker" {
		return []string{"runtime", "image", "image_id", "image_descriptor_digest", "command_path", "socket_path", "socket_device", "socket_inode", "socket_mode", "socket_uid", "binary_digest", "client_version", "client_api_version", "daemon_id", "daemon_version", "daemon_api_version"}
	}
	return []string{"runtime", "image", "image_id", "image_descriptor_digest", "binary_path", "binary_digest", "cli_version", "cli_commit", "api_server_version", "api_server_commit", "app_root"}
}

func validateContainerRuntimeIdentity(runtimeKind string, image, imageID string, identity any, digest any) error {
	runtimeIdentity, ok := identity.(map[string]any)
	if !ok || !hasRequiredAllowedMapFields(runtimeIdentity, requiredContainerRuntimeIdentityFields(runtimeKind), nil) ||
		runtimeIdentity["runtime"] != runtimeKind || runtimeIdentity["image"] != image || runtimeIdentity["image_id"] != imageID || digest != digestHex(runtimeIdentity) {
		return errors.New("runtime identity")
	}
	for _, field := range requiredContainerRuntimeIdentityFields(runtimeKind) {
		if optionalString(runtimeIdentity[field]) == "" {
			return errors.New("runtime identity")
		}
	}
	return nil
}

func validateContainerAdapterEvidence(request DockerRunRequest, runtimeKind string, evidence map[string]any) error {
	if !hasRequiredAllowedMapFields(evidence, []string{"format", "runtime", "image", "image_id", "container_id", "runtime_identity", "runtime_identity_digest", "constraints", "configuration_digest", "observed"}, nil) ||
		evidence["format"] != containerAdapterEvidenceFormat || optionalString(evidence["runtime"]) != runtimeKind {
		return errors.New("runtime")
	}
	if runtimeKind != "docker" && runtimeKind != "apple-container" {
		return errors.New("runtime")
	}
	if optionalString(evidence["image"]) != request.Image {
		return errors.New("image")
	}
	_, imageID, found := strings.Cut(request.Image, "@sha256:")
	if !found || optionalString(evidence["image_id"]) != imageID {
		return errors.New("image identity")
	}
	containerID := optionalString(evidence["container_id"])
	if runtimeKind == "docker" && !validDockerContainerID(containerID) {
		return errors.New("container identity")
	}
	if runtimeKind == "apple-container" && validateAppleContainerID(containerID) != nil {
		return errors.New("container identity")
	}
	if err := validateContainerRuntimeIdentity(runtimeKind, request.Image, imageID, evidence["runtime_identity"], evidence["runtime_identity_digest"]); err != nil {
		return err
	}
	constraints, ok := evidence["constraints"].(map[string]any)
	if !ok || !reflect.DeepEqual(constraints, containerAdapterConstraints(request)) || evidence["configuration_digest"] != digestHex(constraints) {
		return errors.New("constraints")
	}
	observed, ok := evidence["observed"].(map[string]any)
	if !ok || !hasRequiredAllowedMapFields(observed, []string{"exit_code"}, nil) || observed["exit_code"] != float64(0) {
		return errors.New("observed")
	}
	return nil
}

func inProcessSandbox() map[string]any {
	return map[string]any{"mode": "in-process"}
}

func validateSandboxClaim(profile WorkerProfile) error {
	if profile.Docker != nil && profile.SandboxClaim != "container-namespace" {
		return errors.New("docker profile requires container-namespace sandbox claim")
	}
	if profile.SandboxClaim == "container-namespace" {
		if profile.Docker == nil {
			return errors.New("container-namespace sandbox claim requires docker profile")
		}
		_, err := validateDockerWorkerProfile(*profile.Docker)
		return err
	}
	if profile.SandboxClaim == "" {
		return nil
	}
	if profile.SandboxClaim == expectedSandboxMode(profile) {
		return nil
	}
	return sandboxClaimError{
		claim: profile.SandboxClaim,
		probe: sandboxRuntimeProbe(profile),
	}
}

func expectedSandboxMode(profile WorkerProfile) string {
	switch profile.Tool {
	case "external.stdio", "mcp.stdio":
		return "local-temp-dir"
	default:
		return "in-process"
	}
}

func sandboxRuntimeProbe(profile WorkerProfile) map[string]any {
	switch profile.SandboxClaim {
	case "container-namespace":
		return sandboxClaimProbe(profile.SandboxClaim)
	default:
		return map[string]any{
			"claim":     profile.SandboxClaim,
			"supported": false,
			"reason":    "sandbox claim does not match worker runtime mode: " + expectedSandboxMode(profile),
		}
	}
}

func sandboxClaimProbe(claim string) map[string]any {
	switch claim {
	case "in-process", "local-temp-dir":
		return map[string]any{"claim": claim, "supported": true, "reason": "sandbox runtime is available"}
	case "container-namespace":
		return containerNamespaceProbe(claim)
	default:
		return map[string]any{"claim": claim, "supported": false, "reason": "unknown sandbox claim"}
	}
}

func containerNamespaceProbe(claim string) map[string]any {
	runtimeKind, err := configuredContainerRuntime()
	if err != nil {
		return map[string]any{
			"claim":     claim,
			"supported": false,
			"reason":    err.Error(),
		}
	}
	return map[string]any{
		"claim":     claim,
		"runtime":   runtimeKind,
		"supported": false,
		"reason":    "container namespace execution requires an approved " + runtimeKind + " adapter",
	}
}

func configuredContainerRuntime() (string, error) {
	switch selected := os.Getenv("AGNET_CONTAINER_RUNTIME"); selected {
	case "docker", "apple-container":
		return selected, nil
	case "":
		if runtime.GOOS == "darwin" {
			return "apple-container", nil
		}
		return "docker", nil
	default:
		return "", errors.New("AGNET_CONTAINER_RUNTIME must be exactly docker or apple-container")
	}
}

func newToolSandbox(kind string, toolCommand []string) (string, map[string]any, func(), error) {
	dir, err := os.MkdirTemp("", "agnet-"+kind+"-*")
	if err != nil {
		return "", nil, nil, err
	}
	if err := os.MkdirAll(filepath.Join(dir, "cache"), 0o755); err != nil {
		return "", nil, nil, err
	}
	env := sandboxEnv(dir)
	sandbox := map[string]any{
		"mode":            "local-temp-dir",
		"isolation_level": "local-process",
		"kind":            kind,
		"cwd":             dir,
		"env":             env,
		"network":         "not_granted",
		"cleanup":         "remove-all",
	}
	if len(toolCommand) > 0 {
		sandbox["tool_command_digest"] = digestHex(toolCommand)
		executable := toolCommand[0]
		if !filepath.IsAbs(executable) {
			executable, err = exec.LookPath(executable)
			if err != nil {
				return "", nil, nil, err
			}
		}
		data, err := os.ReadFile(executable)
		if err != nil {
			return "", nil, nil, err
		}
		sandbox["tool_binary_digest"] = digestBytesHex(data)
	}
	return dir, sandbox, func() { _ = os.RemoveAll(dir) }, nil
}

func sandboxEnv(dir string) []string {
	return []string{
		"PATH=/usr/bin:/bin",
		"HOME=" + dir,
		"TMPDIR=" + dir,
		"XDG_CACHE_HOME=" + filepath.Join(dir, "cache"),
	}
}

type liveTranscriptWriter struct {
	file   *os.File
	taskID string
}

func newLiveTranscriptWriter(dir, taskID string) (*liveTranscriptWriter, func(), error) {
	if dir == "" {
		return nil, func() {}, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, nil, err
	}
	file, err := os.Create(filepath.Join(dir, url.PathEscape(taskID)+".ndjson"))
	if err != nil {
		return nil, nil, err
	}
	return &liveTranscriptWriter{file: file, taskID: taskID}, func() { _ = file.Close() }, nil
}

func (w *liveTranscriptWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if err := json.NewEncoder(w.file).Encode(map[string]any{"type": "stdout.chunk", "task_id": w.taskID, "text": string(p)}); err != nil {
		return 0, err
	}
	_ = w.file.Sync()
	return len(p), nil
}

func (w *liveTranscriptWriter) WriteMCPResponse(method string, response map[string]any) error {
	if w == nil {
		return nil
	}
	if err := json.NewEncoder(w.file).Encode(map[string]any{"type": "mcp.response", "task_id": w.taskID, "method": method, "response": response}); err != nil {
		return err
	}
	_ = w.file.Sync()
	return nil
}

func runExternalTool(parent context.Context, profile WorkerProfile, task, origin map[string]any, _ string, liveTranscriptDir string) (ToolResult, map[string]any, error) {
	if len(profile.ToolCommand) == 0 {
		return ToolResult{}, nil, errors.New("external.stdio tool_command missing")
	}
	dir, sandbox, cleanup, err := newToolSandbox("external", profile.ToolCommand)
	if err != nil {
		return ToolResult{}, nil, err
	}
	defer cleanup()
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, profile.ToolCommand[0], profile.ToolCommand[1:]...)
	cmd.Dir = dir
	cmd.Env = sandboxEnv(dir)
	input := map[string]any{
		"task_id": task["task_id"],
		"intent":  task["intent"],
		"to":      task["to"],
		"origin":  origin["zid"],
		"tool":    profile.Tool,
	}
	data, err := json.Marshal(input)
	if err != nil {
		return ToolResult{}, nil, err
	}
	cmd.Stdin = bytes.NewReader(data)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return ToolResult{}, nil, err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	liveWriter, closeLive, err := newLiveTranscriptWriter(liveTranscriptDir, fmt.Sprint(task["task_id"]))
	if err != nil {
		return ToolResult{}, nil, err
	}
	defer closeLive()
	if err := cmd.Start(); err != nil {
		return ToolResult{}, nil, err
	}
	var output bytes.Buffer
	writers := []io.Writer{&output}
	if liveWriter != nil {
		writers = append(writers, liveWriter)
	}
	copyDone := make(chan error, 1)
	go func() {
		_, err := io.Copy(io.MultiWriter(writers...), stdout)
		copyDone <- err
	}()
	err = cmd.Wait()
	if copyErr := <-copyDone; copyErr != nil && err == nil {
		err = copyErr
	}
	if ctx.Err() == context.Canceled {
		return ToolResult{}, nil, errors.New("external tool cancelled")
	}
	if ctx.Err() == context.DeadlineExceeded {
		return ToolResult{}, nil, errors.New("external tool timed out")
	}
	transcriptData := output.Bytes()
	sandbox["tool_transcript_digest"] = digestBytesHex(transcriptData)
	if err != nil {
		message := strings.TrimSpace(stderr.String())
		if message == "" {
			message = err.Error()
		}
		return ToolResult{}, nil, errors.New("external tool failed: " + message)
	}
	var result map[string]any
	if err := json.Unmarshal(transcriptData, &result); err != nil {
		return ToolResult{}, nil, err
	}
	text, ok := result["text"].(string)
	if !ok || text == "" {
		return ToolResult{}, nil, errors.New("external tool text missing")
	}
	return ToolResult{
		Result:              []byte(text),
		MediaType:           "text/markdown; charset=utf-8",
		Transcript:          transcriptData,
		TranscriptMediaType: "application/json; charset=utf-8",
	}, sandbox, nil
}

func runMCPTool(parent context.Context, profile WorkerProfile, task, origin map[string]any, _ string, liveTranscriptDir string) (ToolResult, map[string]any, error) {
	if len(profile.ToolCommand) == 0 {
		return ToolResult{}, nil, errors.New("mcp.stdio tool_command missing")
	}
	toolName := profile.ToolName
	if toolName == "" {
		return ToolResult{}, nil, errors.New("mcp.stdio tool_name missing")
	}
	dir, sandbox, cleanup, err := newToolSandbox("mcp", profile.ToolCommand)
	if err != nil {
		return ToolResult{}, nil, err
	}
	defer cleanup()
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, profile.ToolCommand[0], profile.ToolCommand[1:]...)
	cmd.Dir = dir
	cmd.Env = sandboxEnv(dir)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return ToolResult{}, nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return ToolResult{}, nil, err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	liveWriter, closeLive, err := newLiveTranscriptWriter(liveTranscriptDir, fmt.Sprint(task["task_id"]))
	if err != nil {
		return ToolResult{}, nil, err
	}
	defer closeLive()
	if err := cmd.Start(); err != nil {
		return ToolResult{}, nil, err
	}
	scanner := bufio.NewScanner(stdout)
	writeRPC := func(message map[string]any) error {
		data, err := json.Marshal(message)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(stdin, string(data))
		return err
	}
	if err := writeRPC(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": "2025-11-25",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "agnet-go", "version": "v3.7"},
		},
	}); err != nil {
		return ToolResult{}, nil, err
	}
	initializeResponse, err := readRPCResponse(scanner, 1)
	if err != nil {
		return ToolResult{}, nil, err
	}
	if err := liveWriter.WriteMCPResponse("initialize", initializeResponse); err != nil {
		return ToolResult{}, nil, err
	}
	if result, ok := initializeResponse["result"].(map[string]any); ok {
		sandbox["mcp_session"] = map[string]any{
			"protocol_version": result["protocolVersion"],
			"server_info":      result["serverInfo"],
		}
	}
	if err := writeRPC(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized", "params": map[string]any{}}); err != nil {
		return ToolResult{}, nil, err
	}
	if _, err := recordMCPListEvidence(writeRPC, scanner, liveWriter, sandbox, 2, "resources/list", "resources", "mcp_resources"); err != nil {
		return ToolResult{}, nil, err
	}
	if _, err := recordMCPListEvidence(writeRPC, scanner, liveWriter, sandbox, 3, "prompts/list", "prompts", "mcp_prompts"); err != nil {
		return ToolResult{}, nil, err
	}
	tools, err := recordMCPListEvidence(writeRPC, scanner, liveWriter, sandbox, 4, "tools/list", "tools", "mcp_tools")
	if err != nil {
		return ToolResult{}, nil, err
	}
	schema, err := recordMCPSelectedToolEvidence(sandbox, tools, toolName)
	if err != nil {
		return ToolResult{}, nil, err
	}
	args := map[string]any{
		"task_id": task["task_id"],
		"intent":  task["intent"],
		"to":      task["to"],
		"origin":  origin["zid"],
	}
	sandbox["mcp_tool_arguments_digest"] = digestHex(args)
	if err := validateMCPRequiredArguments(schema, args); err != nil {
		return ToolResult{}, nil, err
	}
	if err := writeRPC(map[string]any{
		"jsonrpc": "2.0",
		"id":      5,
		"method":  "tools/call",
		"params":  map[string]any{"name": toolName, "arguments": args},
	}); err != nil {
		return ToolResult{}, nil, err
	}
	response, err := readRPCResponse(scanner, 5)
	if err != nil {
		return ToolResult{}, nil, err
	}
	if err := liveWriter.WriteMCPResponse("tools/call", response); err != nil {
		return ToolResult{}, nil, err
	}
	transcriptData, err := json.Marshal(response)
	if err != nil {
		return ToolResult{}, nil, err
	}
	sandbox["tool_transcript_digest"] = digestBytesHex(transcriptData)
	_ = stdin.Close()
	if ctx.Err() == context.Canceled {
		return ToolResult{}, nil, errors.New("mcp tool cancelled")
	}
	if err := cmd.Wait(); err != nil && ctx.Err() == nil {
		message := strings.TrimSpace(stderr.String())
		if message == "" {
			message = err.Error()
		}
		return ToolResult{}, nil, errors.New("mcp tool failed: " + message)
	}
	if ctx.Err() == context.DeadlineExceeded {
		return ToolResult{}, nil, errors.New("mcp tool timed out")
	}
	text, err := mcpText(response)
	if err != nil {
		return ToolResult{}, nil, err
	}
	return ToolResult{
		Result:              []byte(text),
		MediaType:           "text/markdown; charset=utf-8",
		Transcript:          transcriptData,
		TranscriptMediaType: "application/json; charset=utf-8",
	}, sandbox, nil
}

func recordMCPListEvidence(writeRPC func(map[string]any) error, scanner *bufio.Scanner, liveWriter *liveTranscriptWriter, sandbox map[string]any, id float64, method, field, prefix string) ([]any, error) {
	if err := writeRPC(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": map[string]any{}}); err != nil {
		return nil, err
	}
	response, err := readRPCResponse(scanner, id)
	if err != nil {
		return nil, err
	}
	if err := liveWriter.WriteMCPResponse(method, response); err != nil {
		return nil, err
	}
	result, _ := response["result"].(map[string]any)
	items, _ := result[field].([]any)
	sandbox[prefix+"_count"] = float64(len(items))
	sandbox[prefix+"_digest"] = digestHex(items)
	return items, nil
}

func recordMCPSelectedToolEvidence(sandbox map[string]any, tools []any, toolName string) (any, error) {
	for _, item := range tools {
		tool, _ := item.(map[string]any)
		if tool["name"] == toolName {
			sandbox["mcp_selected_tool"] = toolName
			sandbox["mcp_selected_tool_digest"] = digestHex(tool)
			var selectedSchema any
			if schema, ok := tool["inputSchema"]; ok {
				selectedSchema = schema
				sandbox["mcp_selected_tool_schema_digest"] = digestHex(schema)
			}
			return selectedSchema, nil
		}
	}
	return nil, errors.New("mcp selected tool missing from tools/list")
}

func validateMCPRequiredArguments(schema any, args map[string]any) error {
	body, _ := schema.(map[string]any)
	required, _ := body["required"].([]any)
	for _, item := range required {
		name, ok := item.(string)
		if !ok {
			continue
		}
		// ponytail: required-only gate; full JSON Schema validation belongs in a later policy slice.
		if _, ok := args[name]; !ok {
			return errors.New("mcp tool arguments missing required field: " + name)
		}
	}
	return nil
}

func readRPCResponse(scanner *bufio.Scanner, id float64) (map[string]any, error) {
	for scanner.Scan() {
		var message map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &message); err != nil {
			return nil, err
		}
		if message["id"] == id {
			if message["error"] != nil {
				return nil, errors.New("mcp error: " + fmt.Sprint(message["error"]))
			}
			return message, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return nil, errors.New("mcp response missing")
}

func mcpText(response map[string]any) (string, error) {
	result, _ := response["result"].(map[string]any)
	content, _ := result["content"].([]any)
	for _, item := range content {
		entry, _ := item.(map[string]any)
		if entry["type"] == "text" {
			text, _ := entry["text"].(string)
			if text != "" {
				return text, nil
			}
		}
	}
	return "", errors.New("mcp text content missing")
}
