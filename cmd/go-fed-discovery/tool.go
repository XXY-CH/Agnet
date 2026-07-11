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
	"strings"
	"time"
)

func runTool(ctx context.Context, profile WorkerProfile, task, origin map[string]any, artifactStoreDir, liveTranscriptDir string) (string, ToolResult, map[string]any, error) {
	return runToolWithDockerAdapter(ctx, nil, profile, task, origin, artifactStoreDir, liveTranscriptDir)
}

// runToolWithDockerAdapter is the sole container execution seam. Passing a nil
// adapter deliberately rejects a container profile rather than falling through
// to a host, external, or MCP tool.
func runToolWithDockerAdapter(ctx context.Context, adapter DockerAdapter, profile WorkerProfile, task, origin map[string]any, artifactStoreDir, liveTranscriptDir string) (string, ToolResult, map[string]any, error) {
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
		return tool, textResult("# Go Tool Summary\n\nTask: "+taskID+"\nOrigin: "+fmt.Sprint(origin["zid"])+"\nSummary: "+intent+"\n"), inProcessSandbox(), nil
	case "translate.mock":
		return tool, textResult("# Go Tool Translation\n\nTask: "+taskID+"\nOrigin: "+fmt.Sprint(origin["zid"])+"\nTranslation: "+strings.ToUpper(intent)+"\n"), inProcessSandbox(), nil
	case "external.stdio":
		result, sandbox, err := runExternalTool(ctx, profile, task, origin, artifactStoreDir, liveTranscriptDir)
		return tool, result, sandbox, err
	case "mcp.stdio":
		result, sandbox, err := runMCPTool(ctx, profile, task, origin, artifactStoreDir, liveTranscriptDir)
		return tool, result, sandbox, err
	default:
		return tool, textResult("# Go Tool Output\n\nTask: "+taskID+"\nOrigin: "+fmt.Sprint(origin["zid"])+"\nOutput: "+intent+"\n"), inProcessSandbox(), nil
	}
}

func runDockerTool(ctx context.Context, adapter DockerAdapter, profile WorkerProfile) (ToolResult, map[string]any, error) {
	if profile.Docker == nil {
		return ToolResult{}, nil, errors.New("container-namespace sandbox claim requires docker profile")
	}
	request, err := validateDockerWorkerProfile(*profile.Docker)
	if err != nil {
		return ToolResult{}, nil, err
	}
	if adapter == nil {
		return ToolResult{}, nil, errors.New("container-namespace sandbox adapter is not configured")
	}
	dockerResult, err := adapter.Run(ctx, request)
	if err != nil {
		return ToolResult{}, nil, err
	}
	return ToolResult{
		Result:              dockerResult.Result,
		MediaType:           dockerResult.MediaType,
		Transcript:          dockerResult.Transcript,
		TranscriptMediaType: dockerResult.TranscriptMediaType,
		Evidence:            dockerResult.Evidence,
	}, map[string]any{"mode": "container-namespace"}, nil
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
	return map[string]any{
		"claim":     claim,
		"supported": false,
		"reason":    "container namespace execution requires a DockerAdapter",
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
