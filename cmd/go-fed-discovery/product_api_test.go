package main

import (
	"agnet/internal/managedkey"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const productAPITestToken = "product-test-token"

type productAPITestHarness struct {
	server  *httptest.Server
	fixture Fixture
	worker  string
}

func newProductAPITestHarness(t *testing.T) productAPITestHarness {
	return newProductAPITestHarnessWithWorker(t, nil)
}

func newProductAPITestHarnessWithWorker(t *testing.T, configure func(*WorkerProfile)) productAPITestHarness {
	t.Helper()
	fixturePath, runtimeKeys := managedRuntimeFixture(t, managedkey.KeyTypeSeed)
	absoluteFixturePath, err := filepath.Abs(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := loadManagedFixture(absoluteFixturePath, runtimeKeys)
	if err != nil {
		t.Fatal(err)
	}
	if configure != nil {
		configure(&fixture.Workers[0].Profile)
	}
	root := t.TempDir()
	t.Chdir(root)
	auditPath := filepath.Join(root, "audit.log")
	audit, err := openAuditLog(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	fixture.Audit = audit
	fixture.TaskStateDir = taskStateDirForAudit(auditPath)
	fixture.QueueDir = queueDirForAudit(auditPath)
	fixture.ApprovalDir = approvalDirForAudit(auditPath)
	fixture.ArtifactStoreDir = filepath.Join(root, "artifact-store")
	fixture.LiveTranscriptDir = liveTranscriptDirForAudit(auditPath)
	fixture.Runtime = &TaskRuntime{running: map[string]context.CancelFunc{}, cancelled: map[string]bool{}}
	server := httptest.NewServer(newHumanGatewayMux(auditPath, fixture, productAPITestToken, "127.0.0.1", nil))
	t.Cleanup(server.Close)
	return productAPITestHarness{server: server, fixture: fixture, worker: fixture.Workers[0].Profile.Alias}
}

func (h productAPITestHarness) request(t *testing.T, method, path string, body any, authenticated bool) (int, http.Header, map[string]any) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequest(method, h.server.URL+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if authenticated {
		request.Header.Set("Authorization", "Bearer "+productAPITestToken)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	payload := map[string]any{}
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &payload); err != nil {
			t.Fatalf("decode %s %s response: %v; body=%s", method, path, err, data)
		}
	}
	return response.StatusCode, response.Header, payload
}

type concurrentProductResponse struct {
	status  int
	payload map[string]any
	err     error
}

func (h productAPITestHarness) concurrentRequests(t *testing.T, count int, path string, body any) []concurrentProductResponse {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan concurrentProductResponse, count)
	for range count {
		go func() {
			<-start
			request, requestErr := http.NewRequest(http.MethodPost, h.server.URL+path, bytes.NewReader(encoded))
			if requestErr != nil {
				results <- concurrentProductResponse{err: requestErr}
				return
			}
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Authorization", "Bearer "+productAPITestToken)
			response, requestErr := http.DefaultClient.Do(request)
			if requestErr != nil {
				results <- concurrentProductResponse{err: requestErr}
				return
			}
			defer response.Body.Close()
			payload := map[string]any{}
			requestErr = json.NewDecoder(response.Body).Decode(&payload)
			results <- concurrentProductResponse{status: response.StatusCode, payload: payload, err: requestErr}
		}()
	}
	close(start)
	responses := make([]concurrentProductResponse, 0, count)
	for range count {
		responses = append(responses, <-results)
	}
	return responses
}

func (h productAPITestHarness) concurrentRetryRequests(t *testing.T, parentID string, taskIDs []string) []concurrentProductResponse {
	t.Helper()
	start := make(chan struct{})
	results := make(chan concurrentProductResponse, len(taskIDs))
	for _, taskID := range taskIDs {
		encoded, err := json.Marshal(map[string]any{"task_id": taskID})
		if err != nil {
			t.Fatal(err)
		}
		go func(body []byte) {
			<-start
			request, requestErr := http.NewRequest(http.MethodPost, h.server.URL+"/api/v1/tasks/"+parentID+"/retry", bytes.NewReader(body))
			if requestErr != nil {
				results <- concurrentProductResponse{err: requestErr}
				return
			}
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Authorization", "Bearer "+productAPITestToken)
			response, requestErr := http.DefaultClient.Do(request)
			if requestErr != nil {
				results <- concurrentProductResponse{err: requestErr}
				return
			}
			defer response.Body.Close()
			payload := map[string]any{}
			requestErr = json.NewDecoder(response.Body).Decode(&payload)
			results <- concurrentProductResponse{status: response.StatusCode, payload: payload, err: requestErr}
		}(encoded)
	}
	close(start)
	responses := make([]concurrentProductResponse, 0, len(taskIDs))
	for range taskIDs {
		responses = append(responses, <-results)
	}
	return responses
}

func productTaskPayload(taskID, worker, intent string) map[string]any {
	return map[string]any{
		"task_id": taskID,
		"to":      worker,
		"intent":  intent,
		"scope": map[string]any{
			"network":      false,
			"write":        []any{},
			"data_domains": []any{"workspace"},
		},
		"correlation": map[string]any{
			"workspace_id":    "workspace-1",
			"conversation_id": "conversation-1",
			"session_id":      "session-1",
			"run_id":          "run-1",
			"tool_call_id":    "tool-call-1",
			"task_id":         taskID,
			"payload_digest":  "sha256:" + strings.Repeat("a", 64),
		},
	}
}

func responseData(t *testing.T, payload map[string]any) map[string]any {
	t.Helper()
	data, ok := payload["data"].(map[string]any)
	if !ok {
		t.Fatalf("response data = %#v", payload["data"])
	}
	return data
}

func waitForProductTaskStatus(t *testing.T, harness productAPITestHarness, taskID, want string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		status, _, payload := harness.request(t, http.MethodGet, "/api/v1/tasks/"+taskID, nil, true)
		if status == http.StatusOK {
			data := responseData(t, payload)
			if data["status"] == want {
				return data
			}
			if data["status"] == "failed" {
				t.Fatalf("task failed: %#v", data)
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("task %s did not reach %s", taskID, want)
	return nil
}

func TestProductAPICreatesTasksIdempotently(t *testing.T) {
	harness := newProductAPITestHarness(t)
	request := productTaskPayload("pi:task-create", harness.worker, "summarize the workspace")

	status, _, _ := harness.request(t, http.MethodPost, "/api/v1/tasks", request, false)
	if status != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d, want %d", status, http.StatusUnauthorized)
	}

	status, header, payload := harness.request(t, http.MethodPost, "/api/v1/tasks", request, true)
	if status != http.StatusCreated {
		t.Fatalf("create status = %d, payload=%#v", status, payload)
	}
	if header.Get("Location") != "/api/v1/tasks/pi:task-create" {
		t.Fatalf("Location = %q", header.Get("Location"))
	}
	created := responseData(t, payload)
	if created["status"] != "queued" || created["intent"] != "summarize the workspace" {
		t.Fatalf("created task = %#v", created)
	}

	status, _, payload = harness.request(t, http.MethodPost, "/api/v1/tasks", request, true)
	if status != http.StatusOK || payload["replayed"] != true {
		t.Fatalf("idempotent create status=%d payload=%#v", status, payload)
	}

	conflict := productTaskPayload("pi:task-create", harness.worker, "different intent")
	status, _, payload = harness.request(t, http.MethodPost, "/api/v1/tasks", conflict, true)
	if status != http.StatusConflict || payload["error"] == nil {
		t.Fatalf("conflicting create status=%d payload=%#v", status, payload)
	}

	payloadConflict := productTaskPayload("pi:task-create", harness.worker, "summarize the workspace")
	payloadCorrelation := payloadConflict["correlation"].(map[string]any)
	payloadCorrelation["payload_digest"] = "sha256:" + strings.Repeat("b", 64)
	status, _, payload = harness.request(t, http.MethodPost, "/api/v1/tasks", payloadConflict, true)
	if status != http.StatusConflict || payload["error"] == nil {
		t.Fatalf("changed payload conflict status=%d payload=%#v", status, payload)
	}
}

func TestProductAPIRequiresFullCorrelationAndAuthenticatesCapabilities(t *testing.T) {
	harness := newProductAPITestHarness(t)
	request := productTaskPayload("pi:task-correlation", harness.worker, "bind full correlation")
	correlation, ok := request["correlation"].(map[string]any)
	if !ok {
		t.Fatal("product task test payload has no correlation")
	}
	correlation["task_id"] = "pi:task-correlation"
	correlation["run_id"] = "run-1"
	correlation["payload_digest"] = "sha256:" + strings.Repeat("a", 64)

	status, _, _ := harness.request(t, http.MethodGet, "/api/v1/capabilities", nil, false)
	if status != http.StatusUnauthorized {
		t.Fatalf("unauthenticated capability status = %d, want %d", status, http.StatusUnauthorized)
	}
	status, _, payload := harness.request(t, http.MethodGet, "/api/v1/capabilities", nil, true)
	if status != http.StatusOK {
		t.Fatalf("capabilities status=%d payload=%#v", status, payload)
	}
	capabilities := responseData(t, payload)
	if capabilities["package_version"] != "0.1.0-dev.6" || capabilities["product_api"] != "agnet.product-api/v1" {
		t.Fatalf("capabilities = %#v", capabilities)
	}

	delete(correlation, "payload_digest")
	status, _, payload = harness.request(t, http.MethodPost, "/api/v1/tasks", request, true)
	if status != http.StatusUnprocessableEntity || payload["error"] == nil {
		t.Fatalf("missing correlation field status=%d payload=%#v", status, payload)
	}
}

func TestProductAPIExecutesAndStreamsVerifiedReceipt(t *testing.T) {
	harness := newProductAPITestHarness(t)
	taskID := "pi:task-execute"
	status, _, payload := harness.request(t, http.MethodPost, "/api/v1/tasks", productTaskPayload(taskID, harness.worker, "hello from Pi"), true)
	if status != http.StatusCreated {
		t.Fatalf("create status=%d payload=%#v", status, payload)
	}

	status, _, payload = harness.request(t, http.MethodPost, "/api/v1/tasks/"+taskID+"/execute", map[string]any{}, true)
	if status != http.StatusAccepted {
		t.Fatalf("execute status=%d payload=%#v", status, payload)
	}
	completed := waitForProductTaskStatus(t, harness, taskID, "completed")
	if completed["receipt_digest"] == "" || completed["artifact_refs"] == nil {
		t.Fatalf("completed task = %#v", completed)
	}

	status, _, payload = harness.request(t, http.MethodGet, "/api/v1/tasks/"+taskID+"/receipt", nil, true)
	if status != http.StatusOK {
		t.Fatalf("receipt status=%d payload=%#v", status, payload)
	}
	receiptData := responseData(t, payload)
	if receiptData["committed"] != true || receiptData["signed_task"] == nil {
		t.Fatalf("committed receipt evidence = %#v", receiptData)
	}
	if receiptData["status"] != "completed" {
		t.Fatalf("receipt wrapper = %#v", receiptData)
	}
	signedTask, _ := receiptData["signed_task"].(map[string]any)
	receipt, _ := receiptData["receipt"].(map[string]any)
	if digestHex(signedTask["correlation"]) != digestHex(receipt["correlation"]) {
		t.Fatalf("receipt correlation is not bound to signed task: %#v", receiptData)
	}

	var queueItem map[string]any
	var err error
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		queueItem, err = harness.fixture.readQueueItem(taskID)
		if err == nil && optionalString(queueItem["status"]) == "completed" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if optionalString(queueItem["status"]) != "completed" {
		t.Fatalf("queue projection did not settle: %#v", queueItem)
	}
	queueItem["status"] = "running"
	if err := writeJSONStateFile(filepath.Join(harness.fixture.QueueDir, taskID+".json"), queueItem); err != nil {
		t.Fatal(err)
	}
	status, _, payload = harness.request(t, http.MethodGet, "/api/v1/tasks/"+taskID+"/events?after=0", nil, true)
	if status != http.StatusOK {
		t.Fatalf("events status=%d payload=%#v", status, payload)
	}
	recoveredQueue, err := harness.fixture.readQueueItem(taskID)
	if err != nil {
		t.Fatal(err)
	}
	if recoveredQueue["status"] != "completed" || recoveredQueue["receipt_digest"] != receiptData["receipt_digest"] {
		t.Fatalf("terminal queue projection was not recovered: %#v", recoveredQueue)
	}
	events, _ := payload["data"].([]any)
	if len(events) < 5 {
		t.Fatalf("events = %#v", events)
	}
	seen := map[string]bool{}
	lastCursor := float64(0)
	terminalEvents := 0
	for _, value := range events {
		event, _ := value.(map[string]any)
		cursor, _ := event["cursor"].(float64)
		if cursor <= lastCursor {
			t.Fatalf("non-monotonic event cursor: %#v", events)
		}
		lastCursor = cursor
		eventType, _ := event["type"].(string)
		seen[eventType] = true
		verified, _ := event["verified"].(bool)
		if verified {
			t.Fatalf("authority event claimed caller-local verification: %#v", event)
		}
		if eventType == "receipt.committed" {
			terminalEvents++
		}
	}
	for _, eventType := range []string{"task.accepted", "task.started", "artifact.created", "task.completed", "receipt.committed"} {
		if !seen[eventType] {
			t.Fatalf("missing %s in %#v", eventType, events)
		}
	}
	if terminalEvents != 1 || seen["receipt.verified"] {
		t.Fatalf("terminal event contract violated: %#v", events)
	}

	if err := harness.fixture.appendAudit(map[string]any{"kind": "go_queue_action", "task_id": taskID, "action": "late-test"}); err != nil {
		t.Fatal(err)
	}
	status, _, payload = harness.request(t, http.MethodGet, "/api/v1/tasks/"+taskID+"/events?after="+payload["next_cursor"].(string), nil, true)
	if status != http.StatusOK {
		t.Fatalf("cursor follow-up status=%d payload=%#v", status, payload)
	}
	followUp, _ := payload["data"].([]any)
	if len(followUp) != 0 {
		t.Fatalf("follow-up events = %#v", followUp)
	}
}

func TestProductAPICancelsQueuedTaskWithReceipt(t *testing.T) {
	harness := newProductAPITestHarness(t)
	taskID := "pi:task-cancel"
	status, _, payload := harness.request(t, http.MethodPost, "/api/v1/tasks", productTaskPayload(taskID, harness.worker, "do not run"), true)
	if status != http.StatusCreated {
		t.Fatalf("create status=%d payload=%#v", status, payload)
	}

	status, _, payload = harness.request(t, http.MethodPost, "/api/v1/tasks/"+taskID+"/cancel", map[string]any{"reason": "user aborted streaming"}, true)
	if status != http.StatusOK {
		t.Fatalf("cancel status=%d payload=%#v", status, payload)
	}
	cancelled := responseData(t, payload)
	if cancelled["status"] != "cancelled" {
		t.Fatalf("cancelled task = %#v", cancelled)
	}

	status, _, payload = harness.request(t, http.MethodGet, "/api/v1/tasks/"+taskID+"/receipt", nil, true)
	if status != http.StatusOK {
		t.Fatalf("cancel receipt status=%d payload=%#v", status, payload)
	}
	receiptData := responseData(t, payload)
	receipt, _ := receiptData["receipt"].(map[string]any)
	if receiptData["committed"] != true || receipt["status"] != "cancelled" {
		t.Fatalf("cancel receipt = %#v", receiptData)
	}
	signedTask, _ := receiptData["signed_task"].(map[string]any)
	if signedTask == nil || receipt["task_digest"] != digestHex(signedTask) || optionalString(receipt["cancel_digest"]) == "" {
		t.Fatalf("cancel task binding = %#v", receiptData)
	}

	status, _, payload = harness.request(t, http.MethodPost, "/api/v1/tasks/"+taskID+"/execute", map[string]any{}, true)
	if status != http.StatusOK || payload["replayed"] != true || responseData(t, payload)["status"] != "cancelled" {
		t.Fatalf("execute cancelled status=%d payload=%#v", status, payload)
	}
}

func TestProductAPIRetriesFailedTaskAsNewAttempt(t *testing.T) {
	harness := newProductAPITestHarness(t)
	parentID := "pi:task-retry-1"
	status, _, payload := harness.request(t, http.MethodPost, "/api/v1/tasks", productTaskPayload(parentID, harness.worker, "retry me"), true)
	if status != http.StatusCreated {
		t.Fatalf("create status=%d payload=%#v", status, payload)
	}
	item, err := harness.fixture.readQueueItem(parentID)
	if err != nil {
		t.Fatal(err)
	}
	item["status"] = "failed"
	item["error"] = "simulated failure"
	if err := writeJSONStateFile(filepath.Join(harness.fixture.QueueDir, parentID+".json"), item); err != nil {
		t.Fatal(err)
	}
	if err := harness.fixture.writeTaskState(parentID, "failed", &harness.fixture.Workers[0], map[string]any{"error": "simulated failure"}); err != nil {
		t.Fatal(err)
	}

	retryID := "pi:task-retry-2"
	status, _, payload = harness.request(t, http.MethodPost, "/api/v1/tasks/"+parentID+"/retry", map[string]any{"task_id": retryID}, true)
	if status != http.StatusCreated {
		t.Fatalf("retry status=%d payload=%#v", status, payload)
	}
	attempt := responseData(t, payload)
	if attempt["status"] != "queued" || attempt["retry_of"] != parentID || attempt["retry_attempt"] != float64(1) {
		t.Fatalf("retry attempt = %#v", attempt)
	}

	status, _, payload = harness.request(t, http.MethodPost, "/api/v1/tasks/"+parentID+"/retry", map[string]any{"task_id": retryID}, true)
	if status != http.StatusOK || payload["replayed"] != true {
		t.Fatalf("idempotent retry status=%d payload=%#v", status, payload)
	}

	if err := os.Remove(filepath.Join(harness.fixture.QueueDir, retryID+".json")); err != nil {
		t.Fatal(err)
	}
}

func TestProductAPICancellationWinsRunningTaskRace(t *testing.T) {
	harness := newProductAPITestHarnessWithWorker(t, func(profile *WorkerProfile) {
		profile.Tool = "external.stdio"
		profile.ToolName = "blocking-test-tool"
		profile.ToolCommand = []string{"/bin/sh", "-c", "sleep 5"}
	})
	taskID := "pi:task-cancel-running"
	status, _, payload := harness.request(t, http.MethodPost, "/api/v1/tasks", productTaskPayload(taskID, harness.worker, "block until cancelled"), true)
	if status != http.StatusCreated {
		t.Fatalf("create status=%d payload=%#v", status, payload)
	}
	status, _, payload = harness.request(t, http.MethodPost, "/api/v1/tasks/"+taskID+"/execute", map[string]any{}, true)
	if status != http.StatusAccepted {
		t.Fatalf("execute status=%d payload=%#v", status, payload)
	}
	waitForProductTaskStatus(t, harness, taskID, "running")

	status, _, payload = harness.request(t, http.MethodPost, "/api/v1/tasks/"+taskID+"/cancel", map[string]any{"reason": "user cancelled"}, true)
	if status != http.StatusOK {
		t.Fatalf("cancel status=%d payload=%#v", status, payload)
	}
	waitForProductTaskStatus(t, harness, taskID, "cancelled")
	time.Sleep(100 * time.Millisecond)
	status, _, payload = harness.request(t, http.MethodGet, "/api/v1/tasks/"+taskID, nil, true)
	if status != http.StatusOK || responseData(t, payload)["status"] != "cancelled" {
		t.Fatalf("post-race task status=%d payload=%#v", status, payload)
	}
}

func TestHumanGatewayAuthenticatesEveryReadInterface(t *testing.T) {
	harness := newProductAPITestHarness(t)
	paths := []string{
		"/",
		"/api/audit",
		"/api/tasks",
		"/api/queue",
		"/api/security",
		"/api/session",
		"/api/approvals",
		"/api/requester/registry",
		"/api/requester/rebindings",
		"/api/artifacts/manifest?uri=artifact://local/missing",
		"/api/artifacts/verify?task_id=missing&uri=artifact://local/missing",
		"/api/artifacts/read?task_id=missing&uri=artifact://local/missing",
		"/api/transcripts/stream?task_id=missing",
		"/api/transcripts/live?task_id=missing",
		"/api/v1/tasks/missing",
		"/api/v1/tasks/missing/receipt",
		"/api/v1/tasks/missing/events",
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			status, _, payload := harness.request(t, http.MethodGet, path, nil, false)
			if status != http.StatusUnauthorized {
				t.Fatalf("unauthenticated read status=%d payload=%#v", status, payload)
			}
		})
	}
}

func TestProductAPICreateAndRetryAreAtomicallyIdempotent(t *testing.T) {
	harness := newProductAPITestHarness(t)
	const attempts = 16
	taskID := "pi:task-atomic-create"
	responses := harness.concurrentRequests(t, attempts, "/api/v1/tasks", productTaskPayload(taskID, harness.worker, "atomic create"))
	created, replayed := 0, 0
	for _, response := range responses {
		if response.err != nil {
			t.Fatal(response.err)
		}
		switch response.status {
		case http.StatusCreated:
			created++
		case http.StatusOK:
			if response.payload["replayed"] != true {
				t.Fatalf("non-replayed duplicate response: %#v", response.payload)
			}
			replayed++
		default:
			t.Fatalf("atomic create status=%d payload=%#v", response.status, response.payload)
		}
	}
	if created != 1 || replayed != attempts-1 {
		t.Fatalf("create outcomes: created=%d replayed=%d", created, replayed)
	}

	item, err := harness.fixture.readQueueItem(taskID)
	if err != nil {
		t.Fatal(err)
	}
	item["status"] = "failed"
	item["error"] = "simulated failure"
	if err := writeJSONStateFile(filepath.Join(harness.fixture.QueueDir, taskID+".json"), item); err != nil {
		t.Fatal(err)
	}
	if err := harness.fixture.writeTaskState(taskID, "failed", &harness.fixture.Workers[0], map[string]any{"error": "simulated failure"}); err != nil {
		t.Fatal(err)
	}
	retryID := "pi:task-atomic-retry"
	responses = harness.concurrentRequests(t, attempts, "/api/v1/tasks/"+taskID+"/retry", map[string]any{"task_id": retryID})
	created, replayed = 0, 0
	for _, response := range responses {
		if response.err != nil {
			t.Fatal(response.err)
		}
		switch response.status {
		case http.StatusCreated:
			created++
		case http.StatusOK:
			if response.payload["replayed"] != true {
				t.Fatalf("non-replayed retry response: %#v", response.payload)
			}
			replayed++
		default:
			t.Fatalf("atomic retry status=%d payload=%#v", response.status, response.payload)
		}
	}
	if created != 1 || replayed != attempts-1 {
		t.Fatalf("retry outcomes: created=%d replayed=%d", created, replayed)
	}
	distinctRetryIDs := []string{"pi:task-atomic-retry-a", "pi:task-atomic-retry-b"}
	distinctResponses := harness.concurrentRetryRequests(t, taskID, distinctRetryIDs)
	seenAttempts := map[int]bool{}
	for _, response := range distinctResponses {
		if response.err != nil {
			t.Fatal(response.err)
		}
		if response.status != http.StatusCreated {
			t.Fatalf("distinct retry status=%d payload=%#v", response.status, response.payload)
		}
		seenAttempts[int(responseData(t, response.payload)["retry_attempt"].(float64))] = true
	}
	if !seenAttempts[2] || !seenAttempts[3] || len(seenAttempts) != 2 {
		t.Fatalf("distinct retry attempts=%#v", seenAttempts)
	}

	entries, err := readAuditEntries(harness.fixture.Audit.Path)
	if err != nil {
		t.Fatal(err)
	}
	queued := map[string]int{}
	for _, entry := range entries {
		record, _ := entry["record"].(map[string]any)
		event, _ := record["event"].(map[string]any)
		if optionalString(event["type"]) == "task.queued" {
			queued[optionalString(event["task_id"])]++
		}
	}
	if queued[taskID] != 1 || queued[retryID] != 1 {
		t.Fatalf("queued event counts = %#v", queued)
	}
}

func TestProductAPIExecuteIsAtomicallyIdempotent(t *testing.T) {
	harness := newProductAPITestHarness(t)
	const attempts = 16
	taskID := "pi:task-atomic-execute"
	status, _, payload := harness.request(t, http.MethodPost, "/api/v1/tasks", productTaskPayload(taskID, harness.worker, "execute once"), true)
	if status != http.StatusCreated {
		t.Fatalf("create status=%d payload=%#v", status, payload)
	}

	responses := harness.concurrentRequests(t, attempts, "/api/v1/tasks/"+taskID+"/execute", map[string]any{})
	accepted, replayed := 0, 0
	leaseIDs := map[string]bool{}
	for _, response := range responses {
		if response.err != nil {
			t.Fatal(response.err)
		}
		switch response.status {
		case http.StatusAccepted:
			accepted++
		case http.StatusOK:
			if response.payload["replayed"] != true {
				t.Fatalf("non-replayed duplicate execute response: %#v", response.payload)
			}
			replayed++
		default:
			t.Fatalf("atomic execute status=%d payload=%#v", response.status, response.payload)
		}
		leaseID := optionalString(responseData(t, response.payload)["lease_id"])
		if leaseID == "" {
			t.Fatalf("execute response missing lease: %#v", response.payload)
		}
		leaseIDs[leaseID] = true
	}
	if accepted != 1 || replayed != attempts-1 || len(leaseIDs) != 1 {
		t.Fatalf("execute outcomes: accepted=%d replayed=%d leases=%#v", accepted, replayed, leaseIDs)
	}

	status, _, payload = harness.request(t, http.MethodPost, "/api/v1/tasks/"+taskID+"/execute", map[string]any{}, true)
	if status != http.StatusOK || payload["replayed"] != true || !leaseIDs[optionalString(responseData(t, payload)["lease_id"])] {
		t.Fatalf("later execute status=%d payload=%#v", status, payload)
	}
	entries, err := readAuditEntries(harness.fixture.Audit.Path)
	if err != nil {
		t.Fatal(err)
	}
	claims := 0
	for _, entry := range entries {
		record, _ := entry["record"].(map[string]any)
		if record["kind"] == "go_queue_action" && record["action"] == "claim" && record["task_id"] == taskID && record["status"] == "ok" {
			claims++
		}
	}
	if claims != 1 {
		t.Fatalf("successful claim count=%d", claims)
	}

	waitForProductTaskStatus(t, harness, taskID, "completed")
	entries, err = readAuditEntries(harness.fixture.Audit.Path)
	if err != nil {
		t.Fatal(err)
	}
	receipts := 0
	for _, entry := range entries {
		record, _ := entry["record"].(map[string]any)
		receipt, _ := record["receipt"].(map[string]any)
		if record["kind"] == "go_fed_receipt" && receipt["task_id"] == taskID {
			receipts++
		}
	}
	if receipts != 1 {
		t.Fatalf("execute receipt count=%d", receipts)
	}
}

func TestProductAPICancelIsAtomicallyIdempotent(t *testing.T) {
	harness := newProductAPITestHarness(t)
	const attempts = 16
	taskID := "pi:task-atomic-cancel"
	status, _, payload := harness.request(t, http.MethodPost, "/api/v1/tasks", productTaskPayload(taskID, harness.worker, "cancel once"), true)
	if status != http.StatusCreated {
		t.Fatalf("create status=%d payload=%#v", status, payload)
	}

	request := map[string]any{"reason": "one cancellation"}
	responses := harness.concurrentRequests(t, attempts, "/api/v1/tasks/"+taskID+"/cancel", request)
	winners, replayed := 0, 0
	receiptDigests := map[string]bool{}
	for _, response := range responses {
		if response.err != nil {
			t.Fatal(response.err)
		}
		if response.status != http.StatusOK {
			t.Fatalf("atomic cancel status=%d payload=%#v", response.status, response.payload)
		}
		if response.payload["replayed"] == true {
			replayed++
		} else {
			winners++
		}
		cancelled := responseData(t, response.payload)
		if cancelled["status"] != "cancelled" || optionalString(cancelled["receipt_digest"]) == "" {
			t.Fatalf("cancel response=%#v", response.payload)
		}
		receiptDigests[optionalString(cancelled["receipt_digest"])] = true
	}
	if winners != 1 || replayed != attempts-1 || len(receiptDigests) != 1 {
		t.Fatalf("cancel outcomes: winners=%d replayed=%d receipts=%#v", winners, replayed, receiptDigests)
	}

	status, _, payload = harness.request(t, http.MethodPost, "/api/v1/tasks/"+taskID+"/cancel", request, true)
	if status != http.StatusOK || payload["replayed"] != true || !receiptDigests[optionalString(responseData(t, payload)["receipt_digest"])] {
		t.Fatalf("later cancel status=%d payload=%#v", status, payload)
	}
	entries, err := readAuditEntries(harness.fixture.Audit.Path)
	if err != nil {
		t.Fatal(err)
	}
	receipts := 0
	for _, entry := range entries {
		record, _ := entry["record"].(map[string]any)
		receipt, _ := record["receipt"].(map[string]any)
		if record["kind"] == "go_fed_receipt" && receipt["task_id"] == taskID && receipt["status"] == "cancelled" {
			receipts++
		}
	}
	if receipts != 1 {
		t.Fatalf("cancel receipt count=%d", receipts)
	}
}

func TestProductAPICancelRecoversCancellationIntentAfterDurableFaults(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		inject func(*Fixture) error
	}{
		{
			name: "cancellation event audit append",
			inject: func(fixture *Fixture) error {
				failed := false
				fixture.Audit.syncFile = func(file *os.File) error {
					if !failed {
						failed = true
						return errors.New("injected cancellation event audit sync failure")
					}
					return file.Sync()
				}
				return nil
			},
		},
		{
			name: "cancellation receipt audit append",
			inject: func(fixture *Fixture) error {
				syncs := 0
				fixture.Audit.syncFile = func(file *os.File) error {
					syncs++
					if syncs == 2 {
						return errors.New("injected cancellation receipt audit sync failure")
					}
					return file.Sync()
				}
				return nil
			},
		},
		{
			name: "post-receipt task state settlement",
			inject: func(fixture *Fixture) error {
				failed := false
				fixture.taskStateFault = func(point taskStateFaultPoint, transition map[string]any) error {
					if !failed && point == taskStateFaultWrite && optionalString(transition["to"]) == "cancelled" {
						failed = true
						return errors.New("injected cancelled task state write failure")
					}
					return nil
				}
				return nil
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			harness := newProductAPITestHarness(t)
			taskID := "pi:task-cancel-recovery-" + strings.ReplaceAll(testCase.name, " ", "-")
			status, _, payload := harness.request(t, http.MethodPost, "/api/v1/tasks", productTaskPayload(taskID, harness.worker, "recover cancellation intent"), true)
			if status != http.StatusCreated {
				t.Fatalf("create status=%d payload=%#v", status, payload)
			}
			if err := testCase.inject(&harness.fixture); err != nil {
				t.Fatal(err)
			}

			if view, replayed, err := harness.fixture.cancelProductTask(taskID, "initial cancellation"); err == nil || replayed || view != nil {
				t.Fatalf("first cancel view=%#v replayed=%v err=%v", view, replayed, err)
			}
			harness.fixture.Audit.syncFile = nil
			harness.fixture.taskStateFault = nil

			view, _, err := harness.fixture.cancelProductTask(taskID, "later request must resume original intent")
			if err != nil || optionalString(view["status"]) != "cancelled" || optionalString(view["receipt_digest"]) == "" {
				t.Fatalf("recovered cancel view=%#v err=%v", view, err)
			}
			third, replayed, err := harness.fixture.cancelProductTask(taskID, "third cancellation is idempotent")
			if err != nil || !replayed || optionalString(third["receipt_digest"]) != optionalString(view["receipt_digest"]) {
				t.Fatalf("idempotent cancel view=%#v replayed=%v err=%v", third, replayed, err)
			}

			committed, err := harness.fixture.productCommittedReceipt(taskID)
			if err != nil || optionalString(committed["status"]) != "cancelled" || optionalString(committed["receipt_digest"]) != optionalString(view["receipt_digest"]) {
				t.Fatalf("committed receipt=%#v err=%v", committed, err)
			}
			receipt, _ := committed["receipt"].(map[string]any)
			cancel, _ := receipt["cancel"].(map[string]any)
			if optionalString(cancel["reason"]) != "initial cancellation" {
				t.Fatalf("recovered receipt lost original cancellation intent: %#v", receipt)
			}
			state, stateErr := harness.fixture.readTaskState(taskID)
			item, queueErr := harness.fixture.readQueueItem(taskID)
			if stateErr != nil || queueErr != nil || optionalString(state["status"]) != "cancelled" || optionalString(state["receipt_digest"]) != optionalString(committed["receipt_digest"]) || optionalString(item["status"]) != "cancelled" || optionalString(item["receipt_digest"]) != optionalString(committed["receipt_digest"]) {
				t.Fatalf("state=%#v stateErr=%v queue=%#v queueErr=%v", state, stateErr, item, queueErr)
			}
			entries, err := readAuditEntries(harness.fixture.Audit.Path)
			if err != nil {
				t.Fatal(err)
			}
			receipts, events := 0, 0
			for _, entry := range entries {
				record, _ := entry["record"].(map[string]any)
				receipt, _ := record["receipt"].(map[string]any)
				if optionalString(record["kind"]) == "go_fed_receipt" && optionalString(receipt["task_id"]) == taskID && optionalString(receipt["status"]) == "cancelled" {
					receipts++
				}
				event, _ := record["event"].(map[string]any)
				if optionalString(record["kind"]) == "go_fed_event" && optionalString(event["task_id"]) == taskID && optionalString(event["type"]) == "task.cancelled" {
					events++
				}
			}
			if receipts != 1 || events != 1 {
				t.Fatalf("cancelled receipts=%d events=%d", receipts, events)
			}
		})
	}
}

func TestProductTaskStateJournalIsDurableAndTerminal(t *testing.T) {
	harness := newProductAPITestHarness(t)
	taskID := "pi:task-durable-state"
	status, _, payload := harness.request(t, http.MethodPost, "/api/v1/tasks", productTaskPayload(taskID, harness.worker, "durable state"), true)
	if status != http.StatusCreated {
		t.Fatalf("create status=%d payload=%#v", status, payload)
	}
	journalPath := filepath.Join(harness.fixture.TaskStateDir, taskID+".journal.jsonl")
	journal, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	transitions := bytes.Split(bytes.TrimSpace(journal), []byte("\n"))
	if len(transitions) != 1 {
		t.Fatalf("initial transitions=%d journal=%s", len(transitions), journal)
	}
	var queued map[string]any
	if err := json.Unmarshal(transitions[0], &queued); err != nil {
		t.Fatal(err)
	}
	if queued["from"] != "" || queued["to"] != "queued" || queued["transition_hash"] == "" {
		t.Fatalf("queued transition=%#v", queued)
	}

	projectionPath := filepath.Join(harness.fixture.TaskStateDir, taskID+".json")
	if err := writeJSONStateFile(projectionPath, map[string]any{"task_id": taskID, "status": "completed", "receipt_digest": "forged"}); err != nil {
		t.Fatal(err)
	}
	status, _, payload = harness.request(t, http.MethodGet, "/api/v1/tasks/"+taskID, nil, true)
	if status != http.StatusOK || responseData(t, payload)["status"] != "queued" {
		t.Fatalf("forged projection affected authority: status=%d payload=%#v", status, payload)
	}

	status, _, payload = harness.request(t, http.MethodPost, "/api/v1/tasks/"+taskID+"/cancel", map[string]any{"reason": "durable cancellation"}, true)
	if status != http.StatusOK || responseData(t, payload)["status"] != "cancelled" {
		t.Fatalf("cancel status=%d payload=%#v", status, payload)
	}
	journal, err = os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	transitions = bytes.Split(bytes.TrimSpace(journal), []byte("\n"))
	if len(transitions) != 3 {
		t.Fatalf("terminal transitions=%d journal=%s", len(transitions), journal)
	}
	states := []string{}
	for _, encoded := range transitions {
		var transition map[string]any
		if err := json.Unmarshal(encoded, &transition); err != nil {
			t.Fatal(err)
		}
		states = append(states, optionalString(transition["to"]))
	}
	if strings.Join(states, ",") != "queued,cancelling,cancelled" {
		t.Fatalf("durable transitions=%v", states)
	}
	if err := harness.fixture.writeTaskState(taskID, "running", &harness.fixture.Workers[0], map[string]any{}); err == nil {
		t.Fatal("terminal task regressed to running")
	}
	state, err := harness.fixture.readTaskState(taskID)
	if err != nil {
		t.Fatal(err)
	}
	if state["status"] != "cancelled" || state["revision"] != float64(3) {
		t.Fatalf("durable terminal state=%#v", state)
	}
	restartedFixture := harness.fixture
	restartedFixture.Runtime = &TaskRuntime{running: map[string]context.CancelFunc{}, cancelled: map[string]bool{}}
	restartedServer := httptest.NewServer(newHumanGatewayMux(restartedFixture.Audit.Path, restartedFixture, productAPITestToken, "127.0.0.1", nil))
	t.Cleanup(restartedServer.Close)
	restarted := productAPITestHarness{server: restartedServer, fixture: restartedFixture, worker: harness.worker}
	status, _, payload = restarted.request(t, http.MethodGet, "/api/v1/tasks/"+taskID, nil, true)
	if status != http.StatusOK || responseData(t, payload)["status"] != "cancelled" {
		t.Fatalf("restart lost terminal state: status=%d payload=%#v", status, payload)
	}

	tampered := bytes.Replace(journal, []byte(`"to":"cancelled"`), []byte(`"to":"running"`), 1)
	if bytes.Equal(tampered, journal) {
		t.Fatal("journal tamper fixture did not change bytes")
	}
	if err := os.WriteFile(journalPath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	status, _, payload = restarted.request(t, http.MethodGet, "/api/v1/tasks/"+taskID, nil, true)
	if status != http.StatusInternalServerError {
		t.Fatalf("tampered journal status=%d payload=%#v", status, payload)
	}
}

func prepareProductRecoveryState(t *testing.T, harness productAPITestHarness, taskID, state string) (map[string]any, string) {
	t.Helper()
	status, _, payload := harness.request(t, http.MethodPost, "/api/v1/tasks", productTaskPayload(taskID, harness.worker, "durability recovery"), true)
	if status != http.StatusCreated {
		t.Fatalf("create status=%d payload=%#v", status, payload)
	}
	item, err := harness.fixture.readQueueItem(taskID)
	if err != nil {
		t.Fatal(err)
	}
	task, _ := item["task"].(map[string]any)
	claim := productQueueAction(harness.fixture, "claim", taskID, task)
	claim["owner"] = "product://local"
	claim["lease_seconds"] = float64(300)
	claimed, err := harness.fixture.applyAuthorizedProductQueueAction(claim)
	if err != nil {
		t.Fatal(err)
	}
	leaseID := optionalString(claimed["lease_id"])
	if _, err := harness.fixture.transitionTaskState(taskID, "claimed", harness.worker, map[string]any{"lease_id": leaseID, "lease_owner": "product://local"}); err != nil {
		t.Fatal(err)
	}
	if state == "claimed" {
		return task, leaseID
	}
	item, err = harness.fixture.readQueueItem(taskID)
	if err != nil {
		t.Fatal(err)
	}
	item["status"] = "running"
	if err := writeJSONStateFile(filepath.Join(harness.fixture.QueueDir, taskID+".json"), item); err != nil {
		t.Fatal(err)
	}
	if _, err := harness.fixture.transitionTaskState(taskID, "running", harness.worker, map[string]any{"signed_task": task}); err != nil {
		t.Fatal(err)
	}
	if state == "completing" {
		if _, err := harness.fixture.transitionTaskState(taskID, "completing", harness.worker, map[string]any{}); err != nil {
			t.Fatal(err)
		}
	} else if state == "failing" {
		if _, err := harness.fixture.transitionTaskState(taskID, "failing", harness.worker, map[string]any{"error": "interrupted failure"}); err != nil {
			t.Fatal(err)
		}
	}
	return task, leaseID
}

func TestProductAPIReservesRuntimeBeforeLaunchingDrain(t *testing.T) {
	harness := newProductAPITestHarness(t)
	taskID := "pi:task-launch-reservation"
	status, _, payload := harness.request(t, http.MethodPost, "/api/v1/tasks", productTaskPayload(taskID, harness.worker, "reserve before launch"), true)
	if status != http.StatusCreated {
		t.Fatalf("create status=%d payload=%#v", status, payload)
	}
	type result struct {
		view     map[string]any
		replayed bool
		err      error
	}
	harness.fixture.Runtime.mu.Lock()
	done := make(chan result, 1)
	go func() {
		view, replayed, err := harness.fixture.executeProductTask(taskID)
		done <- result{view: view, replayed: replayed, err: err}
	}()
	select {
	case got := <-done:
		harness.fixture.Runtime.mu.Unlock()
		t.Fatalf("execute returned before runtime ownership reservation: %#v", got)
	case <-time.After(100 * time.Millisecond):
		harness.fixture.Runtime.mu.Unlock()
	}
	got := <-done
	if got.err != nil || got.replayed {
		t.Fatalf("execute result=%#v", got)
	}
	waitForProductTaskStatus(t, harness, taskID, "completed")
	deadline := time.Now().Add(time.Second)
	owned := true
	for owned && time.Now().Before(deadline) {
		harness.fixture.Runtime.mu.Lock()
		_, owned = harness.fixture.Runtime.running[taskID]
		harness.fixture.Runtime.mu.Unlock()
		if owned {
			time.Sleep(time.Millisecond)
		}
	}
	if owned {
		t.Fatal("runtime ownership was not cleared after drain")
	}
}

func TestProductTaskLockReleaseIsIdempotent(t *testing.T) {
	queueDir := t.TempDir()
	const taskID = "double-release"
	firstRelease, err := acquireProductTaskLock(queueDir, taskID)
	if err != nil {
		t.Fatal(err)
	}
	firstRelease()
	secondRelease, err := acquireProductTaskLock(queueDir, taskID)
	if err != nil {
		t.Fatal(err)
	}
	defer secondRelease()
	firstRelease()
	lockPath := filepath.Join(queueDir, ".product-task-locks", taskID+".lock")
	if _, err := os.Stat(lockPath); err != nil {
		t.Fatalf("old owner release removed current owner lock: %v", err)
	}
}

func TestProductTaskLockDoesNotStealOldLiveLock(t *testing.T) {
	queueDir := t.TempDir()
	const taskID = "old-live-owner"
	release, err := acquireProductTaskLock(queueDir, taskID)
	if err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(queueDir, ".product-task-locks", taskID+".lock")
	old := time.Now().Add(-time.Minute)
	if err := os.Chtimes(lockPath, old, old); err != nil {
		release()
		t.Fatal(err)
	}
	acquired := make(chan func(), 1)
	errs := make(chan error, 1)
	go func() {
		nextRelease, acquireErr := acquireProductTaskLock(queueDir, taskID)
		if acquireErr != nil {
			errs <- acquireErr
			return
		}
		acquired <- nextRelease
	}()
	select {
	case nextRelease := <-acquired:
		nextRelease()
		t.Fatal("old live lock was stolen by age")
	case err := <-errs:
		t.Fatalf("contending lock failed: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	release()
	select {
	case nextRelease := <-acquired:
		nextRelease()
	case err := <-errs:
		t.Fatalf("contending lock failed after release: %v", err)
	case <-time.After(time.Second):
		t.Fatal("contending lock did not acquire after release")
	}
}

func TestTaskStateJournalFirstCreateSyncsParentOrRollsBack(t *testing.T) {
	failure := errors.New("injected task journal parent sync failure")
	failed := false
	fixture := Fixture{
		TaskStateDir: t.TempDir(),
		taskStateFault: func(point taskStateFaultPoint, transition map[string]any) error {
			if point == taskStateFaultParentSync && !failed {
				failed = true
				return failure
			}
			return nil
		},
	}
	const taskID = "pi:first-create-parent-sync"
	if _, err := fixture.transitionTaskState(taskID, "queued", "worker", map[string]any{}); !errors.Is(err, failure) {
		t.Fatalf("transition error=%v; want parent sync failure", err)
	}
	transitions, err := readTaskStateTransitions(taskStateJournalPath(fixture.TaskStateDir, taskID))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if len(transitions) != 0 {
		t.Fatalf("failed first append remained accepted: %#v", transitions)
	}
	fixture.taskStateFault = nil
	state, err := fixture.transitionTaskState(taskID, "queued", "worker", map[string]any{})
	if err != nil || state["status"] != "queued" {
		t.Fatalf("retry state=%#v err=%v", state, err)
	}
}
func TestProductAPIReservedDrainStartsAfterExecuteReleasesTaskLock(t *testing.T) {
	harness := newProductAPITestHarness(t)
	taskID := "pi:task-drain-after-unlock"
	status, _, payload := harness.request(t, http.MethodPost, "/api/v1/tasks", productTaskPayload(taskID, harness.worker, "launch after unlock"), true)
	if status != http.StatusCreated {
		t.Fatalf("create status=%d payload=%#v", status, payload)
	}
	type result struct {
		view     map[string]any
		replayed bool
		err      error
	}
	harness.fixture.Runtime.mu.Lock()
	done := make(chan result, 1)
	go func() {
		view, replayed, err := harness.fixture.executeProductTask(taskID)
		done <- result{view: view, replayed: replayed, err: err}
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		item, err := harness.fixture.readQueueItem(taskID)
		if err == nil && optionalString(item["status"]) == "claimed" {
			break
		}
		if time.Now().After(deadline) {
			harness.fixture.Runtime.mu.Unlock()
			t.Fatalf("execute did not reach runtime reservation: item=%#v err=%v", item, err)
		}
		time.Sleep(time.Millisecond)
	}
	if err := os.MkdirAll(harness.fixture.ApprovalDir, 0o700); err != nil {
		harness.fixture.Runtime.mu.Unlock()
		t.Fatal(err)
	}
	approvalPath := filepath.Join(harness.fixture.ApprovalDir, taskID+".json")
	if err := unix.Mkfifo(approvalPath, 0o600); err != nil {
		harness.fixture.Runtime.mu.Unlock()
		t.Fatal(err)
	}
	harness.fixture.Runtime.mu.Unlock()
	// Keep final view construction blocked long enough for an incorrectly
	// launched drain to contend on the still-held kernel lock.
	time.Sleep(100 * time.Millisecond)
	if err := os.WriteFile(approvalPath, []byte(`{"task_id":"pi:task-drain-after-unlock","status":"pending"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	got := <-done
	if err := os.Remove(approvalPath); err != nil {
		t.Fatal(err)
	}
	if got.err != nil || got.replayed {
		t.Fatalf("execute result=%#v", got)
	}
	waitForProductTaskStatus(t, harness, taskID, "completed")
}

func TestProductAPIRestartRecoveryResumesClaimedAndFailsUnsafeWork(t *testing.T) {
	t.Run("claimed product lease resumes", func(t *testing.T) {
		harness := newProductAPITestHarness(t)
		taskID := "pi:task-recover-claimed"
		_, leaseID := prepareProductRecoveryState(t, harness, taskID, "claimed")
		harness.fixture.Runtime = &TaskRuntime{running: map[string]context.CancelFunc{}, cancelled: map[string]bool{}}
		view, replayed, err := harness.fixture.executeProductTask(taskID)
		if err != nil || !replayed || optionalString(view["lease_id"]) != leaseID {
			t.Fatalf("recovery view=%#v replayed=%v err=%v", view, replayed, err)
		}
		waitForProductTaskStatus(t, harness, taskID, "completed")
	})
	for _, abandonedStatus := range []string{"running", "completing"} {
		t.Run(abandonedStatus, func(t *testing.T) {
			harness := newProductAPITestHarness(t)
			taskID := "pi:task-recover-" + abandonedStatus
			prepareProductRecoveryState(t, harness, taskID, abandonedStatus)
			harness.fixture.Runtime = &TaskRuntime{running: map[string]context.CancelFunc{}, cancelled: map[string]bool{}}
			view, replayed, err := harness.fixture.executeProductTask(taskID)
			if err != nil || !replayed || view["status"] != "failed" || optionalString(view["receipt_digest"]) == "" {
				t.Fatalf("recovery view=%#v replayed=%v err=%v", view, replayed, err)
			}
			committed, err := harness.fixture.productCommittedReceipt(taskID)
			if err != nil {
				t.Fatalf("failure receipt did not verify: %v", err)
			}
			state, stateErr := harness.fixture.readTaskState(taskID)
			queueItem, queueErr := harness.fixture.readQueueItem(taskID)
			if stateErr != nil || queueErr != nil {
				t.Fatalf("state err=%v queue err=%v", stateErr, queueErr)
			}
			if committed["status"] != "failed" || state["receipt_digest"] != committed["receipt_digest"] || queueItem["status"] != "failed" || queueItem["receipt_digest"] != committed["receipt_digest"] {
				t.Fatalf("receipt=%#v state=%#v queue=%#v", committed, state, queueItem)
			}
			retry, replayed, err := harness.fixture.retryProductTask(taskID, taskID+"-retry")
			if err != nil || replayed || retry["status"] != "queued" || retry["retry_of"] != taskID {
				t.Fatalf("retry=%#v replayed=%v err=%v", retry, replayed, err)
			}
		})
	}
}

func TestProductAPIRetryReceiptRebindsCorrelationToRetryTask(t *testing.T) {
	harness := newProductAPITestHarness(t)
	parentID := "pi:task-retry-correlation-parent"
	prepareProductRecoveryState(t, harness, parentID, "running")
	parent, replayed, err := harness.fixture.executeProductTask(parentID)
	if err != nil || !replayed || parent["status"] != "failed" {
		t.Fatalf("parent recovery result=%#v replayed=%v err=%v", parent, replayed, err)
	}

	retryID := parentID + "-retry"
	retry, replayed, err := harness.fixture.retryProductTask(parentID, retryID)
	if err != nil || replayed || retry["task_id"] != retryID || retry["retry_of"] != parentID || intFromMap(retry, "retry_attempt") != 1 {
		t.Fatalf("retry=%#v replayed=%v err=%v", retry, replayed, err)
	}
	if _, replayed, err = harness.fixture.executeProductTask(retryID); err != nil || replayed {
		t.Fatalf("retry execute replayed=%v err=%v", replayed, err)
	}
	waitForProductTaskStatus(t, harness, retryID, "completed")

	status, _, payload := harness.request(t, http.MethodGet, "/api/v1/tasks/"+retryID+"/receipt", nil, true)
	if status != http.StatusOK {
		t.Fatalf("retry receipt status=%d payload=%#v", status, payload)
	}
	committed := responseData(t, payload)
	if optionalString(committed["task_id"]) != retryID {
		t.Fatalf("committed task_id=%#v", committed["task_id"])
	}
	signedTask, ok := committed["signed_task"].(map[string]any)
	if !ok || optionalString(signedTask["task_id"]) != retryID {
		t.Fatalf("signed task=%#v", committed["signed_task"])
	}
	receipt, ok := committed["receipt"].(map[string]any)
	if !ok || optionalString(receipt["task_id"]) != retryID {
		t.Fatalf("receipt=%#v", committed["receipt"])
	}
	for label, value := range map[string]any{
		"request":     retry["correlation"],
		"signed task": signedTask["correlation"],
		"receipt":     receipt["correlation"],
	} {
		correlation, ok := value.(map[string]any)
		if !ok || optionalString(correlation["task_id"]) != retryID {
			t.Fatalf("%s correlation=%#v", label, value)
		}
	}
	queueItem, err := harness.fixture.readQueueItem(retryID)
	if err != nil || optionalString(queueItem["retry_of"]) != parentID || intFromMap(queueItem, "retry_attempt") != 1 {
		t.Fatalf("retry queue item=%#v err=%v", queueItem, err)
	}
}
func TestProductAPIRetryRejectsCorruptQueueCorrelationWithoutCreatingAttempt(t *testing.T) {
	harness := newProductAPITestHarness(t)
	parentID := "pi:task-retry-corrupt-parent"
	status, _, payload := harness.request(t, http.MethodPost, "/api/v1/tasks", productTaskPayload(parentID, harness.worker, "retry me"), true)
	if status != http.StatusCreated {
		t.Fatalf("create status=%d payload=%#v", status, payload)
	}
	parent, err := harness.fixture.readQueueItem(parentID)
	if err != nil {
		t.Fatal(err)
	}
	parent["status"] = "failed"
	parent["error"] = "simulated failure"
	parent["correlation"] = map[string]any{"task_id": parentID}
	if err := writeJSONStateFile(filepath.Join(harness.fixture.QueueDir, parentID+".json"), parent); err != nil {
		t.Fatal(err)
	}
	if err := harness.fixture.writeTaskState(parentID, "failed", &harness.fixture.Workers[0], map[string]any{"error": "simulated failure"}); err != nil {
		t.Fatal(err)
	}
	auditBefore, err := readAuditEntries(harness.fixture.Audit.Path)
	if err != nil {
		t.Fatal(err)
	}
	parentBefore := digestHex(parent)
	retryID := parentID + "-retry"
	if retry, replayed, retryErr := harness.fixture.retryProductTask(parentID, retryID); retryErr == nil || replayed || retry != nil {
		t.Fatalf("corrupt retry=%#v replayed=%v err=%v", retry, replayed, retryErr)
	}
	if _, err := harness.fixture.readQueueItem(retryID); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("corrupt retry queue err=%v", err)
	}
	if _, err := harness.fixture.readTaskState(retryID); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("corrupt retry state err=%v", err)
	}
	auditAfter, err := readAuditEntries(harness.fixture.Audit.Path)
	if err != nil {
		t.Fatal(err)
	}
	if len(auditAfter) != len(auditBefore) {
		t.Fatalf("corrupt retry created signed audit task: before=%d after=%d", len(auditBefore), len(auditAfter))
	}
	parentAfter, err := harness.fixture.readQueueItem(parentID)
	if err != nil || digestHex(parentAfter) != parentBefore {
		t.Fatalf("corrupt retry mutated parent=%#v err=%v", parentAfter, err)
	}
}

func TestProductAPICreateProductTaskRejectsInvalidInternalRequestWithoutPersisting(t *testing.T) {
	harness := newProductAPITestHarness(t)
	taskID := "pi:task-invalid-internal"
	request := productTaskRequest{
		TaskID: taskID,
		To:     harness.worker,
		Intent: "reject before signing",
		Scope: map[string]any{
			"network":      false,
			"write":        []any{},
			"data_domains": []any{"workspace"},
		},
		Correlation: map[string]any{
			"workspace_id":    "workspace-1",
			"conversation_id": "conversation-1",
			"session_id":      "session-1",
			"tool_call_id":    "tool-call-1",
			"task_id":         taskID,
			"payload_digest":  "sha256:" + strings.Repeat("a", 64),
		},
	}
	auditBefore, err := readAuditEntries(harness.fixture.Audit.Path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if task, replayed, createErr := harness.fixture.createProductTask(request, nil); createErr == nil || replayed || task != nil {
		t.Fatalf("invalid internal create task=%#v replayed=%v err=%v", task, replayed, createErr)
	}
	if _, err := harness.fixture.readQueueItem(taskID); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid internal create queue err=%v", err)
	}
	if _, err := harness.fixture.readTaskState(taskID); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid internal create state err=%v", err)
	}
	auditAfter, err := readAuditEntries(harness.fixture.Audit.Path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if len(auditAfter) != len(auditBefore) {
		t.Fatalf("invalid internal create signed audit task: before=%d after=%d", len(auditBefore), len(auditAfter))
	}
}

func mustJSONLine(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return append(data, '\n')
}

func rewriteTaskJournal(t *testing.T, fixture Fixture, taskID string, count int) {
	t.Helper()
	journalPath := taskStateJournalPath(fixture.TaskStateDir, taskID)
	transitions, err := readTaskStateTransitions(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(transitions) < count {
		t.Fatalf("transitions=%#v", transitions)
	}
	var journal []byte
	for _, transition := range transitions[:count] {
		journal = append(journal, mustJSONLine(t, transition)...)
	}
	if err := os.WriteFile(journalPath, journal, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeJSONStateFile(taskStateProjectionPath(fixture.TaskStateDir, taskID), projectTaskState(transitions[:count])); err != nil {
		t.Fatal(err)
	}
}

func TestProductAPIRestartRecoveryUsesPersistedQueueStateBeforeJournalProjection(t *testing.T) {
	t.Run("claimed queue with queued journal resumes", func(t *testing.T) {
		harness := newProductAPITestHarness(t)
		taskID := "pi:task-skew-claimed-queued"
		_, leaseID := prepareProductRecoveryState(t, harness, taskID, "claimed")
		rewriteTaskJournal(t, harness.fixture, taskID, 1)
		harness.fixture.Runtime = &TaskRuntime{running: map[string]context.CancelFunc{}, cancelled: map[string]bool{}}
		view, replayed, err := harness.fixture.executeProductTask(taskID)
		if err != nil || !replayed || optionalString(view["lease_id"]) != leaseID {
			t.Fatalf("recovery view=%#v replayed=%v err=%v", view, replayed, err)
		}
		waitForProductTaskStatus(t, harness, taskID, "completed")
	})

	t.Run("running queue with claimed journal fails without rejected drain", func(t *testing.T) {
		harness := newProductAPITestHarness(t)
		taskID := "pi:task-skew-running-claimed"
		prepareProductRecoveryState(t, harness, taskID, "running")
		rewriteTaskJournal(t, harness.fixture, taskID, 2)
		harness.fixture.Runtime = &TaskRuntime{running: map[string]context.CancelFunc{}, cancelled: map[string]bool{}}
		if !harness.fixture.Runtime.Reserve(taskID) {
			t.Fatal("reserve stale drain ownership")
		}
		view, replayed, err := harness.fixture.executeProductTask(taskID)
		if err != nil || !replayed || view["status"] != "failed" {
			t.Fatalf("recovery view=%#v replayed=%v err=%v", view, replayed, err)
		}
		if harness.fixture.Runtime.Owns(taskID) {
			t.Fatal("unsafe skew launched a drain")
		}
	})

	t.Run("claimed skew rejects invalid queue task evidence", func(t *testing.T) {
		harness := newProductAPITestHarness(t)
		taskID := "pi:task-skew-invalid-evidence"
		prepareProductRecoveryState(t, harness, taskID, "claimed")
		item, err := harness.fixture.readQueueItem(taskID)
		if err != nil {
			t.Fatal(err)
		}
		item["task_digest"] = strings.Repeat("0", 64)
		if err := writeJSONStateFile(filepath.Join(harness.fixture.QueueDir, taskID+".json"), item); err != nil {
			t.Fatal(err)
		}
		rewriteTaskJournal(t, harness.fixture, taskID, 1)
		if _, replayed, err := harness.fixture.executeProductTask(taskID); err == nil || replayed {
			t.Fatalf("invalid evidence replayed=%v err=%v", replayed, err)
		}
		if harness.fixture.Runtime.Owns(taskID) {
			t.Fatal("invalid evidence launched a drain")
		}
	})
}

func TestTaskStateClaimedSelfTransitionOnlyAllowsLeaseRotation(t *testing.T) {
	harness := newProductAPITestHarness(t)
	taskID := "pi:task-reject-claimed-self-transition"
	_, leaseID := prepareProductRecoveryState(t, harness, taskID, "claimed")
	_, err := harness.fixture.transitionTaskState(taskID, "claimed", harness.worker, map[string]any{
		"lease_id":         "lease:sha256:replacement",
		"lease_owner":      "product://local",
		"lease_expires_at": time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano),
		"error":            "not a lease renewal field",
	})
	if err == nil || !strings.Contains(err.Error(), "task state transition invalid") {
		t.Fatalf("arbitrary claimed self-transition err=%v", err)
	}
	state, err := harness.fixture.readTaskState(taskID)
	if err != nil {
		t.Fatal(err)
	}
	if state["status"] != "claimed" || optionalString(state["lease_id"]) != leaseID || state["revision"] != float64(2) {
		t.Fatalf("rejected transition changed state: %#v", state)
	}
}

func TestProductAPIExpiredClaimedLeaseRecovery(t *testing.T) {
	for _, testCase := range []struct {
		name         string
		journalCount int
	}{
		{name: "queued journal", journalCount: 1},
		{name: "claimed journal", journalCount: 2},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			harness := newProductAPITestHarness(t)
			taskID := "pi:task-expired-" + strings.ReplaceAll(testCase.name, " ", "-")
			_, oldLeaseID := prepareProductRecoveryState(t, harness, taskID, "claimed")
			rewriteTaskJournal(t, harness.fixture, taskID, testCase.journalCount)
			item, err := harness.fixture.readQueueItem(taskID)
			if err != nil {
				t.Fatal(err)
			}
			item["lease_expires_at"] = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)
			if err := writeJSONStateFile(filepath.Join(harness.fixture.QueueDir, taskID+".json"), item); err != nil {
				t.Fatal(err)
			}
			harness.fixture.Runtime = &TaskRuntime{running: map[string]context.CancelFunc{}, cancelled: map[string]bool{}}
			view, replayed, err := harness.fixture.executeProductTask(taskID)
			if err != nil || !replayed {
				t.Fatalf("recovery view=%#v replayed=%v err=%v", view, replayed, err)
			}
			newLeaseID := optionalString(view["lease_id"])
			if newLeaseID == "" || newLeaseID == oldLeaseID {
				t.Fatalf("lease was not rotated: old=%q view=%#v", oldLeaseID, view)
			}
			waitForProductTaskStatus(t, harness, taskID, "completed")
			transitions, err := readTaskStateTransitions(taskStateJournalPath(harness.fixture.TaskStateDir, taskID))
			if err != nil {
				t.Fatal(err)
			}
			if testCase.journalCount == 2 {
				renewal := transitions[2]
				extra, _ := renewal["extra"].(map[string]any)
				if renewal["from"] != "claimed" || renewal["to"] != "claimed" || optionalString(extra["lease_id"]) != newLeaseID {
					t.Fatalf("claimed lease renewal transition=%#v", renewal)
				}
			}
		})
	}

	t.Run("running journal converges to verified failure", func(t *testing.T) {
		harness := newProductAPITestHarness(t)
		taskID := "pi:task-expired-running"
		_, oldLeaseID := prepareProductRecoveryState(t, harness, taskID, "running")
		item, err := harness.fixture.readQueueItem(taskID)
		if err != nil {
			t.Fatal(err)
		}
		item["status"] = "claimed"
		item["lease_expires_at"] = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)
		if err := writeJSONStateFile(filepath.Join(harness.fixture.QueueDir, taskID+".json"), item); err != nil {
			t.Fatal(err)
		}
		harness.fixture.Runtime = &TaskRuntime{running: map[string]context.CancelFunc{}, cancelled: map[string]bool{}}
		view, replayed, err := harness.fixture.executeProductTask(taskID)
		if err != nil || !replayed || view["status"] != "failed" || optionalString(view["receipt_digest"]) == "" {
			t.Fatalf("recovery view=%#v replayed=%v err=%v", view, replayed, err)
		}
		if optionalString(view["lease_id"]) != oldLeaseID {
			t.Fatalf("unsafe running skew rotated lease: old=%q view=%#v", oldLeaseID, view)
		}
		committed, err := harness.fixture.productCommittedReceipt(taskID)
		if err != nil || committed["status"] != "failed" {
			t.Fatalf("committed=%#v err=%v", committed, err)
		}
	})
}

func TestProductAPIUnsafeAdjacentPreterminalSkewsBecomeVerifiedFailures(t *testing.T) {
	for _, testCase := range []struct {
		name          string
		preparedState string
		queueStatus   string
		journalCount  int
	}{
		{name: "claimed queue running journal", preparedState: "running", queueStatus: "claimed", journalCount: 3},
		{name: "claimed queue completing journal", preparedState: "completing", queueStatus: "claimed", journalCount: 4},
		{name: "claimed queue failing journal", preparedState: "failing", queueStatus: "claimed", journalCount: 4},
		{name: "running queue queued journal", preparedState: "running", queueStatus: "running", journalCount: 1},
		{name: "queued queue running journal", preparedState: "running", queueStatus: "queued", journalCount: 3},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			harness := newProductAPITestHarness(t)
			taskID := "pi:task-skew-" + strings.ReplaceAll(testCase.name, " ", "-")
			prepareProductRecoveryState(t, harness, taskID, testCase.preparedState)
			item, err := harness.fixture.readQueueItem(taskID)
			if err != nil {
				t.Fatal(err)
			}
			item["status"] = testCase.queueStatus
			if err := writeJSONStateFile(filepath.Join(harness.fixture.QueueDir, taskID+".json"), item); err != nil {
				t.Fatal(err)
			}
			rewriteTaskJournal(t, harness.fixture, taskID, testCase.journalCount)
			harness.fixture.Runtime = &TaskRuntime{running: map[string]context.CancelFunc{}, cancelled: map[string]bool{}}
			view, replayed, err := harness.fixture.executeProductTask(taskID)
			if err != nil || !replayed || view["status"] != "failed" || optionalString(view["receipt_digest"]) == "" {
				t.Fatalf("recovery view=%#v replayed=%v err=%v", view, replayed, err)
			}
			committed, err := harness.fixture.productCommittedReceipt(taskID)
			if err != nil || committed["status"] != "failed" {
				t.Fatalf("committed=%#v err=%v", committed, err)
			}
		})
	}
}

func TestProductAPIDrainFailureConvergesToOneDurableFailure(t *testing.T) {
	harness := newProductAPITestHarness(t)
	taskID := "pi:task-drain-rejection"
	task, leaseID := prepareProductRecoveryState(t, harness, taskID, "running")
	if !harness.fixture.Runtime.Reserve(taskID) {
		t.Fatal("reserve runtime")
	}
	harness.fixture.drainProductTask(taskID, leaseID, task)
	committed, err := harness.fixture.productCommittedReceipt(taskID)
	if err != nil {
		t.Fatal(err)
	}
	item, err := harness.fixture.readQueueItem(taskID)
	if err != nil {
		t.Fatal(err)
	}
	if committed["status"] != "failed" || item["status"] != "failed" || item["receipt_digest"] != committed["receipt_digest"] {
		t.Fatalf("receipt=%#v queue=%#v", committed, item)
	}
	entries, err := readAuditEntries(harness.fixture.Audit.Path)
	if err != nil {
		t.Fatal(err)
	}
	receipts := 0
	for _, entry := range entries {
		record, _ := entry["record"].(map[string]any)
		receipt, _ := record["receipt"].(map[string]any)
		if optionalString(receipt["task_id"]) == taskID {
			receipts++
		}
	}
	if receipts != 1 {
		t.Fatalf("terminal receipts=%d", receipts)
	}
}

func TestProductCommittedReceiptRejectsUnboundDurableEvidence(t *testing.T) {
	t.Run("signed receipt status omitted", func(t *testing.T) {
		harness := newProductAPITestHarness(t)
		taskID := "pi:task-receipt-status-omitted"
		status, _, payload := harness.request(t, http.MethodPost, "/api/v1/tasks", productTaskPayload(taskID, harness.worker, "receipt status required"), true)
		if status != http.StatusCreated {
			t.Fatalf("create status=%d payload=%#v", status, payload)
		}
		status, _, payload = harness.request(t, http.MethodPost, "/api/v1/tasks/"+taskID+"/execute", map[string]any{}, true)
		if status != http.StatusAccepted {
			t.Fatalf("execute status=%d payload=%#v", status, payload)
		}
		waitForProductTaskStatus(t, harness, taskID, "completed")
		record, err := harness.fixture.auditProof(taskID)
		if err != nil {
			t.Fatal(err)
		}
		delete(record, "audit_hash")
		receipt, _ := record["receipt"].(map[string]any)
		delete(receipt, "signature")
		delete(receipt, "status")
		record["receipt"] = signBody(harness.fixture.Workers[0].PrivateKey, receipt)
		entry, err := auditEntry(auditZeroHash, record)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(harness.fixture.Audit.Path, mustJSONLine(t, entry), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := harness.fixture.productCommittedReceipt(taskID); err == nil || !strings.Contains(err.Error(), "terminal status") {
			t.Fatalf("omitted signed status err=%v", err)
		}
	})

	for _, testCase := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "misfiled queue task id", mutate: func(item map[string]any) { item["task_id"] = "pi:task-other" }},
		{name: "stored queue task digest", mutate: func(item map[string]any) { item["task_digest"] = strings.Repeat("f", 64) }},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			harness := newProductAPITestHarness(t)
			taskID := "pi:task-receipt-unbound-" + strings.ReplaceAll(testCase.name, " ", "-")
			status, _, payload := harness.request(t, http.MethodPost, "/api/v1/tasks", productTaskPayload(taskID, harness.worker, "bind receipt evidence"), true)
			if status != http.StatusCreated {
				t.Fatalf("create status=%d payload=%#v", status, payload)
			}
			status, _, payload = harness.request(t, http.MethodPost, "/api/v1/tasks/"+taskID+"/execute", map[string]any{}, true)
			if status != http.StatusAccepted {
				t.Fatalf("execute status=%d payload=%#v", status, payload)
			}
			waitForProductTaskStatus(t, harness, taskID, "completed")
			item, err := harness.fixture.readQueueItem(taskID)
			if err != nil {
				t.Fatal(err)
			}
			testCase.mutate(item)
			if err := writeJSONStateFile(filepath.Join(harness.fixture.QueueDir, taskID+".json"), item); err != nil {
				t.Fatal(err)
			}
			if _, err := harness.fixture.productCommittedReceipt(taskID); err == nil {
				t.Fatal("unbound durable evidence accepted")
			}
		})
	}
}

func rollTaskJournalBackBeforeTerminal(t *testing.T, harness productAPITestHarness, taskID string) {
	t.Helper()
	journalPath := taskStateJournalPath(harness.fixture.TaskStateDir, taskID)
	journal, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(journal), []byte("\n"))
	kept := make([][]byte, 0, len(lines))
	for _, line := range lines {
		var transition map[string]any
		if err := json.Unmarshal(line, &transition); err != nil {
			t.Fatal(err)
		}
		if terminalTaskStatus(optionalString(transition["to"])) {
			break
		}
		kept = append(kept, line)
	}
	if err := os.WriteFile(journalPath, append(bytes.Join(kept, []byte("\n")), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	transitions, err := readTaskStateTransitions(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	projection := projectTaskState(transitions)
	if err := writeJSONStateFile(taskStateProjectionPath(harness.fixture.TaskStateDir, taskID), projection); err != nil {
		t.Fatal(err)
	}
	queueItem, err := harness.fixture.readQueueItem(taskID)
	if err != nil {
		t.Fatal(err)
	}
	queueItem["status"] = projection["status"]
	delete(queueItem, "receipt_digest")
	if err := writeJSONStateFile(filepath.Join(harness.fixture.QueueDir, taskID+".json"), queueItem); err != nil {
		t.Fatal(err)
	}
}

func TestProductAPIReconcilesVerifiedReceiptBeforeTaskAndEventResponses(t *testing.T) {
	for _, responseKind := range []string{"task", "events"} {
		t.Run(responseKind, func(t *testing.T) {
			harness := newProductAPITestHarness(t)
			taskID := "pi:task-reconcile-" + responseKind
			status, _, payload := harness.request(t, http.MethodPost, "/api/v1/tasks", productTaskPayload(taskID, harness.worker, "reconcile receipt"), true)
			if status != http.StatusCreated {
				t.Fatalf("create status=%d payload=%#v", status, payload)
			}
			status, _, payload = harness.request(t, http.MethodPost, "/api/v1/tasks/"+taskID+"/execute", map[string]any{}, true)
			if status != http.StatusAccepted {
				t.Fatalf("execute status=%d payload=%#v", status, payload)
			}
			waitForProductTaskStatus(t, harness, taskID, "completed")
			committed, err := harness.fixture.productCommittedReceipt(taskID)
			if err != nil {
				t.Fatal(err)
			}
			rollTaskJournalBackBeforeTerminal(t, harness, taskID)
			path := "/api/v1/tasks/" + taskID
			if responseKind == "events" {
				path += "/events?after=0"
			}
			status, _, payload = harness.request(t, http.MethodGet, path, nil, true)
			if status != http.StatusOK {
				t.Fatalf("response status=%d payload=%#v", status, payload)
			}
			state, stateErr := harness.fixture.readTaskState(taskID)
			queueItem, queueErr := harness.fixture.readQueueItem(taskID)
			if stateErr != nil || queueErr != nil {
				t.Fatalf("state err=%v queue err=%v", stateErr, queueErr)
			}
			if state["status"] != "completed" || state["receipt_digest"] != committed["receipt_digest"] || queueItem["status"] != "completed" || queueItem["receipt_digest"] != committed["receipt_digest"] {
				t.Fatalf("state=%#v queue=%#v receipt=%#v", state, queueItem, committed)
			}
		})
	}
}

func TestProductAPIReconcilesVerifiedCancelledReceiptAfterRollback(t *testing.T) {
	for _, responseKind := range []string{"task", "events"} {
		t.Run(responseKind, func(t *testing.T) {
			harness := newProductAPITestHarness(t)
			taskID := "pi:task-reconcile-cancelled-" + responseKind
			status, _, payload := harness.request(t, http.MethodPost, "/api/v1/tasks", productTaskPayload(taskID, harness.worker, "reconcile cancelled receipt"), true)
			if status != http.StatusCreated {
				t.Fatalf("create status=%d payload=%#v", status, payload)
			}
			status, _, payload = harness.request(t, http.MethodPost, "/api/v1/tasks/"+taskID+"/cancel", map[string]any{"reason": "cancel before execution"}, true)
			if status != http.StatusOK || responseData(t, payload)["status"] != "cancelled" {
				t.Fatalf("cancel status=%d payload=%#v", status, payload)
			}
			committed, err := harness.fixture.productCommittedReceipt(taskID)
			if err != nil || committed["status"] != "cancelled" {
				t.Fatalf("committed=%#v err=%v", committed, err)
			}
			rollTaskJournalBackBeforeTerminal(t, harness, taskID)
			path := "/api/v1/tasks/" + taskID
			if responseKind == "events" {
				path += "/events?after=0"
			}
			status, _, payload = harness.request(t, http.MethodGet, path, nil, true)
			if status != http.StatusOK {
				t.Fatalf("response status=%d payload=%#v", status, payload)
			}
			if responseKind == "events" {
				events, _ := payload["data"].([]any)
				terminal := 0
				for _, value := range events {
					event, _ := value.(map[string]any)
					committedPayload, _ := event["payload"].(map[string]any)
					if event["type"] == "receipt.committed" && committedPayload["status"] == "cancelled" {
						terminal++
					}
				}
				if terminal != 1 {
					t.Fatalf("cancelled terminal events=%#v", events)
				}
			}
			state, stateErr := harness.fixture.readTaskState(taskID)
			queueItem, queueErr := harness.fixture.readQueueItem(taskID)
			if stateErr != nil || queueErr != nil {
				t.Fatalf("state err=%v queue err=%v", stateErr, queueErr)
			}
			if state["status"] != "cancelled" || state["receipt_digest"] != committed["receipt_digest"] || queueItem["status"] != "cancelled" || queueItem["receipt_digest"] != committed["receipt_digest"] {
				t.Fatalf("state=%#v queue=%#v receipt=%#v", state, queueItem, committed)
			}
			transitions, err := readTaskStateTransitions(taskStateJournalPath(harness.fixture.TaskStateDir, taskID))
			if err != nil {
				t.Fatal(err)
			}
			states := make([]string, 0, len(transitions))
			for _, transition := range transitions {
				states = append(states, optionalString(transition["to"]))
			}
			if strings.Join(states, ",") != "queued,cancelling,cancelled" {
				t.Fatalf("recovered cancellation transitions=%v", states)
			}
		})
	}
}

func TestProductAPIDoesNotReconcileUnverifiedOrConflictingReceipt(t *testing.T) {
	t.Run("unverified", func(t *testing.T) {
		harness := newProductAPITestHarness(t)
		taskID := "pi:task-unverified-receipt"
		task, _ := prepareProductRecoveryState(t, harness, taskID, "running")
		forged := map[string]any{"task_id": taskID, "task_digest": digestHex(task), "status": "failed", "artifact_refs": []string{}, "artifact_manifests": []map[string]any{}, "signature": "invalid"}
		if err := harness.fixture.appendAudit(map[string]any{"kind": "go_fed_receipt", "zone": harness.fixture.Authority, "worker": harness.fixture.Workers[0].Descriptor, "zone_binding": harness.fixture.zoneBinding(&harness.fixture.Workers[0]), "receipt": forged}); err != nil {
			t.Fatal(err)
		}
		status, _, _ := harness.request(t, http.MethodGet, "/api/v1/tasks/"+taskID, nil, true)
		if status == http.StatusOK {
			t.Fatal("unverified receipt was accepted")
		}
		state, err := harness.fixture.readTaskState(taskID)
		if err != nil || state["status"] != "running" || optionalString(state["receipt_digest"]) != "" {
			t.Fatalf("unverified receipt repaired state=%#v err=%v", state, err)
		}
	})
	t.Run("conflicting terminal digest", func(t *testing.T) {
		harness := newProductAPITestHarness(t)
		taskID := "pi:task-conflicting-terminal-digest"
		status, _, payload := harness.request(t, http.MethodPost, "/api/v1/tasks", productTaskPayload(taskID, harness.worker, "preserve digest"), true)
		if status != http.StatusCreated {
			t.Fatalf("create status=%d payload=%#v", status, payload)
		}
		status, _, payload = harness.request(t, http.MethodPost, "/api/v1/tasks/"+taskID+"/execute", map[string]any{}, true)
		if status != http.StatusAccepted {
			t.Fatalf("execute status=%d payload=%#v", status, payload)
		}
		waitForProductTaskStatus(t, harness, taskID, "completed")
		if _, err := harness.fixture.transitionTaskState(taskID, "completed", harness.worker, map[string]any{"receipt_digest": "sha256:conflicting"}); err != nil {
			t.Fatal(err)
		}
		queueItem, err := harness.fixture.readQueueItem(taskID)
		if err != nil {
			t.Fatal(err)
		}
		queueItem["receipt_digest"] = "sha256:queue-conflicting"
		if err := writeJSONStateFile(filepath.Join(harness.fixture.QueueDir, taskID+".json"), queueItem); err != nil {
			t.Fatal(err)
		}
		status, _, _ = harness.request(t, http.MethodGet, "/api/v1/tasks/"+taskID, nil, true)
		if status == http.StatusOK {
			t.Fatal("conflicting terminal digest was accepted")
		}
		state, err := harness.fixture.readTaskState(taskID)
		queueItem, queueErr := harness.fixture.readQueueItem(taskID)
		if err != nil || queueErr != nil || state["receipt_digest"] != "sha256:conflicting" || queueItem["receipt_digest"] != "sha256:queue-conflicting" {
			t.Fatalf("terminal digest overwritten state=%#v queue=%#v stateErr=%v queueErr=%v", state, queueItem, err, queueErr)
		}
	})
}

func TestProductTaskStateJournalRecoversOnlyUnterminatedFinalRecord(t *testing.T) {
	t.Run("unterminated", func(t *testing.T) {
		harness := newProductAPITestHarness(t)
		taskID := "pi:task-torn-journal"
		status, _, payload := harness.request(t, http.MethodPost, "/api/v1/tasks", productTaskPayload(taskID, harness.worker, "recover torn journal"), true)
		if status != http.StatusCreated {
			t.Fatalf("create status=%d payload=%#v", status, payload)
		}
		journalPath := taskStateJournalPath(harness.fixture.TaskStateDir, taskID)
		original, err := os.ReadFile(journalPath)
		if err != nil {
			t.Fatal(err)
		}
		torn := append(append([]byte{}, original...), []byte(`{"format":"agnet-task-state-transition/v1"`)...)
		if err := os.WriteFile(journalPath, torn, 0o600); err != nil {
			t.Fatal(err)
		}
		status, _, payload = harness.request(t, http.MethodGet, "/api/v1/tasks/"+taskID, nil, true)
		if status != http.StatusOK || responseData(t, payload)["status"] != "queued" {
			t.Fatalf("torn response status=%d payload=%#v", status, payload)
		}
		recovered, err := os.ReadFile(journalPath)
		if err != nil || !bytes.Equal(recovered, original) {
			t.Fatalf("recovered=%q want=%q err=%v", recovered, original, err)
		}
	})
	t.Run("newline terminated malformed", func(t *testing.T) {
		harness := newProductAPITestHarness(t)
		taskID := "pi:task-malformed-journal"
		status, _, payload := harness.request(t, http.MethodPost, "/api/v1/tasks", productTaskPayload(taskID, harness.worker, "reject malformed journal"), true)
		if status != http.StatusCreated {
			t.Fatalf("create status=%d payload=%#v", status, payload)
		}
		journalPath := taskStateJournalPath(harness.fixture.TaskStateDir, taskID)
		original, err := os.ReadFile(journalPath)
		if err != nil {
			t.Fatal(err)
		}
		malformed := append(append([]byte{}, original...), []byte("{not-json}\n")...)
		if err := os.WriteFile(journalPath, malformed, 0o600); err != nil {
			t.Fatal(err)
		}
		status, _, _ = harness.request(t, http.MethodGet, "/api/v1/tasks/"+taskID, nil, true)
		if status != http.StatusInternalServerError {
			t.Fatalf("malformed status=%d", status)
		}
		unchanged, err := os.ReadFile(journalPath)
		if err != nil || !bytes.Equal(unchanged, malformed) {
			t.Fatalf("malformed journal changed=%q err=%v", unchanged, err)
		}
	})
}

func TestProductAPIFailureCommitsOneDurableTerminalReceipt(t *testing.T) {
	harness := newProductAPITestHarnessWithWorker(t, func(profile *WorkerProfile) {
		profile.Tool = "external.stdio"
		profile.ToolName = "failing-test-tool"
		profile.ToolCommand = []string{"/bin/sh", "-c", "exit 7"}
	})
	taskID := "pi:task-failed-receipt"
	status, _, payload := harness.request(t, http.MethodPost, "/api/v1/tasks", productTaskPayload(taskID, harness.worker, "fail with evidence"), true)
	if status != http.StatusCreated {
		t.Fatalf("create status=%d payload=%#v", status, payload)
	}
	status, _, payload = harness.request(t, http.MethodPost, "/api/v1/tasks/"+taskID+"/execute", map[string]any{}, true)
	if status != http.StatusAccepted {
		t.Fatalf("execute status=%d payload=%#v", status, payload)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		status, _, payload = harness.request(t, http.MethodGet, "/api/v1/tasks/"+taskID, nil, true)
		if status == http.StatusOK && responseData(t, payload)["status"] == "failed" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if responseData(t, payload)["status"] != "failed" {
		t.Fatalf("failed task did not settle: %#v", payload)
	}

	status, _, payload = harness.request(t, http.MethodGet, "/api/v1/tasks/"+taskID+"/receipt", nil, true)
	if status != http.StatusOK {
		t.Fatalf("failure receipt status=%d payload=%#v", status, payload)
	}
	committed := responseData(t, payload)
	receipt, _ := committed["receipt"].(map[string]any)
	if committed["committed"] != true || receipt["status"] != "failed" || committed["signed_task"] == nil {
		t.Fatalf("failure receipt=%#v", committed)
	}

	entries, err := readAuditEntries(harness.fixture.Audit.Path)
	if err != nil {
		t.Fatal(err)
	}
	receiptRecords := 0
	var durableRecord map[string]any
	for _, entry := range entries {
		record, _ := entry["record"].(map[string]any)
		durableReceipt, _ := record["receipt"].(map[string]any)
		if optionalString(record["kind"]) == "go_fed_receipt" && optionalString(durableReceipt["task_id"]) == taskID {
			receiptRecords++
			durableRecord = record
		}
	}
	if receiptRecords != 1 {
		t.Fatalf("durable terminal receipt records=%d", receiptRecords)
	}
	signedTask, _ := committed["signed_task"].(map[string]any)
	if err := verifyReceiptRecord(durableRecord, harness.fixture.ArtifactStoreDir, signedTask); err != nil {
		t.Fatalf("verify durable failure receipt: %v", err)
	}

	queueSettled := false
	for time.Now().Before(deadline) {
		item, itemErr := harness.fixture.readQueueItem(taskID)
		if itemErr == nil && optionalString(item["status"]) == "failed" {
			queueSettled = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !queueSettled {
		t.Fatal("failed queue item did not settle")
	}

	status, _, payload = harness.request(t, http.MethodGet, "/api/v1/tasks/"+taskID+"/events?after=0", nil, true)
	if status != http.StatusOK {
		t.Fatalf("failure events status=%d payload=%#v", status, payload)
	}
	events, _ := payload["data"].([]any)
	terminal := 0
	for _, value := range events {
		event, _ := value.(map[string]any)
		if event["type"] == "receipt.committed" {
			terminal++
		}
	}
	if terminal != 1 {
		t.Fatalf("failure terminal events=%#v", events)
	}
}

func TestProductAPICommittedReceiptSurvivesCompletedStateAppendFailure(t *testing.T) {
	harness := newProductAPITestHarness(t)
	const taskID = "pi:task-completed-state-append-failure"
	status, _, payload := harness.request(t, http.MethodPost, "/api/v1/tasks", productTaskPayload(taskID, harness.worker, "recover committed completion"), true)
	if status != http.StatusCreated {
		t.Fatalf("create status=%d payload=%#v", status, payload)
	}
	failed := false
	harness.fixture.taskStateFault = func(point taskStateFaultPoint, transition map[string]any) error {
		if point == taskStateFaultWrite && optionalString(transition["to"]) == "completed" && !failed {
			failed = true
			return errors.New("injected completed state append failure")
		}
		return nil
	}
	if _, replayed, err := harness.fixture.executeProductTask(taskID); err != nil || replayed {
		t.Fatalf("execute replayed=%v err=%v", replayed, err)
	}
	deadline := time.Now().Add(5 * time.Second)
	var state, item map[string]any
	var committed map[string]any
	for time.Now().Before(deadline) {
		committed, _ = harness.fixture.productCommittedReceipt(taskID)
		state, _ = harness.fixture.readTaskState(taskID)
		item, _ = harness.fixture.readQueueItem(taskID)
		if committed != nil && optionalString(state["status"]) == "completed" && optionalString(item["status"]) == "completed" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !failed {
		t.Fatal("completed state append fault was not exercised")
	}
	if committed == nil || committed["status"] != "completed" || state["receipt_digest"] != committed["receipt_digest"] || item["receipt_digest"] != committed["receipt_digest"] {
		t.Fatalf("receipt=%#v state=%#v queue=%#v", committed, state, item)
	}
	entries, err := readAuditEntries(harness.fixture.Audit.Path)
	if err != nil {
		t.Fatal(err)
	}
	receipts := 0
	for _, entry := range entries {
		record, _ := entry["record"].(map[string]any)
		receipt, _ := record["receipt"].(map[string]any)
		if optionalString(record["kind"]) == "go_fed_receipt" && optionalString(receipt["task_id"]) == taskID {
			receipts++
		}
	}
	if receipts != 1 {
		t.Fatalf("durable terminal receipts=%d", receipts)
	}
	events, _, err := harness.fixture.productTaskEvents(taskID, 0)
	if err != nil {
		t.Fatal(err)
	}
	terminalEvents := 0
	for _, event := range events {
		if optionalString(event["type"]) == "receipt.committed" {
			terminalEvents++
		}
	}
	if terminalEvents != 1 {
		t.Fatalf("terminal events=%#v", events)
	}
}

func TestLegacyTaskStateMigrationCreatesReplayableGenesis(t *testing.T) {
	harness := newProductAPITestHarness(t)
	taskID := "pi:legacy-state"
	legacy := map[string]any{
		"task_id":        taskID,
		"status":         "running",
		"revision":       float64(7),
		"state_hash":     "legacy-projection-hash",
		"receipt_digest": "",
	}
	if err := writeJSONStateFile(taskStateProjectionPath(harness.fixture.TaskStateDir, taskID), legacy); err != nil {
		t.Fatal(err)
	}
	if _, err := harness.fixture.transitionTaskState(taskID, "completing", harness.worker, map[string]any{}); err != nil {
		t.Fatal(err)
	}
	state, err := harness.fixture.readTaskState(taskID)
	if err != nil {
		t.Fatal(err)
	}
	if state["status"] != "completing" || state["revision"] != float64(2) {
		t.Fatalf("migrated state=%#v", state)
	}
	data, err := os.ReadFile(taskStateJournalPath(harness.fixture.TaskStateDir, taskID))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("migration transitions=%q", data)
	}
	var genesis map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &genesis); err != nil {
		t.Fatal(err)
	}
	if genesis["from"] != "" || genesis["to"] != "running" || genesis["migration_source_digest"] != digestHex(legacy) {
		t.Fatalf("migration genesis=%#v", genesis)
	}
}

type productDurableSnapshot struct {
	queue          []byte
	stateJournal   []byte
	stateProjection []byte
	audit          []byte
	artifactEntries int
}

func snapshotProductDurables(t *testing.T, fixture Fixture, taskID string) productDurableSnapshot {
	t.Helper()
	read := func(path string) []byte {
		data, err := os.ReadFile(path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		return data
	}
	entries, err := os.ReadDir(fixture.ArtifactStoreDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return productDurableSnapshot{
		queue:           read(filepath.Join(fixture.QueueDir, taskID+".json")),
		stateJournal:    read(taskStateJournalPath(fixture.TaskStateDir, taskID)),
		stateProjection: read(taskStateProjectionPath(fixture.TaskStateDir, taskID)),
		audit:           read(fixture.Audit.Path),
		artifactEntries: len(entries),
	}
}

func assertProductDurablesUnchanged(t *testing.T, fixture Fixture, taskID string, want productDurableSnapshot) {
	t.Helper()
	if got := snapshotProductDurables(t, fixture, taskID); !bytes.Equal(got.queue, want.queue) || !bytes.Equal(got.stateJournal, want.stateJournal) || !bytes.Equal(got.stateProjection, want.stateProjection) || !bytes.Equal(got.audit, want.audit) || got.artifactEntries != want.artifactEntries {
		t.Fatalf("durables changed: got=%#v want=%#v", got, want)
	}
}

func invalidateSignedProductTaskCorrelation(t *testing.T, fixture Fixture, taskID string) {
	t.Helper()
	item, err := fixture.readQueueItem(taskID)
	if err != nil {
		t.Fatal(err)
	}
	task, ok := item["task"].(map[string]any)
	if !ok {
		t.Fatalf("queue signed task=%#v", item["task"])
	}
	unsigned := map[string]any{}
	for key, value := range task {
		if key != "signature" {
			unsigned[key] = value
		}
	}
	correlation, ok := unsigned["correlation"].(map[string]any)
	if !ok {
		t.Fatalf("signed correlation=%#v", unsigned["correlation"])
	}
	correlation, err = cloneProductCorrelation(correlation)
	if err != nil {
		t.Fatal(err)
	}
	delete(correlation, "run_id")
	unsigned["correlation"] = correlation
	signedTask := signBody(fixture.AuthorityPrivateKey, unsigned)
	item["task"] = signedTask
	item["task_digest"] = digestHex(signedTask)
	item["correlation"] = correlation
	if err := writeJSONStateFile(filepath.Join(fixture.QueueDir, taskID+".json"), item); err != nil {
		t.Fatal(err)
	}
}

func prepareFailedProductParent(t *testing.T, harness productAPITestHarness, taskID string) {
	t.Helper()
	status, _, payload := harness.request(t, http.MethodPost, "/api/v1/tasks", productTaskPayload(taskID, harness.worker, "retry me"), true)
	if status != http.StatusCreated {
		t.Fatalf("create status=%d payload=%#v", status, payload)
	}
	item, err := harness.fixture.readQueueItem(taskID)
	if err != nil {
		t.Fatal(err)
	}
	item["status"] = "failed"
	item["error"] = "simulated failure"
	if err := writeJSONStateFile(filepath.Join(harness.fixture.QueueDir, taskID+".json"), item); err != nil {
		t.Fatal(err)
	}
	if err := harness.fixture.writeTaskState(taskID, "failed", &harness.fixture.Workers[0], map[string]any{"error": "simulated failure"}); err != nil {
		t.Fatal(err)
	}
}

func TestProductAPIRejectsInvalidSignedCorrelationBeforeEveryDurableEffect(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		prepare func(t *testing.T, harness productAPITestHarness, taskID string)
		invoke  func(t *testing.T, harness productAPITestHarness, taskID string)
	}{
		{
			name: "execute",
			invoke: func(t *testing.T, harness productAPITestHarness, taskID string) {
				if view, replayed, err := harness.fixture.executeProductTask(taskID); err == nil || replayed || view != nil {
					t.Fatalf("execute view=%#v replayed=%v err=%v", view, replayed, err)
				}
			},
		},
		{
			name: "failure convergence",
			invoke: func(t *testing.T, harness productAPITestHarness, taskID string) {
				if err := harness.fixture.convergeProductFailureLocked(taskID, "", errors.New("injected failure")); err == nil {
					t.Fatal("failure convergence accepted invalid correlation")
				}
			},
		},
		{
			name: "drain",
			prepare: func(t *testing.T, harness productAPITestHarness, taskID string) {
				if _, err := harness.fixture.claimQueueItem(taskID, "product://local", 300); err != nil {
					t.Fatal(err)
				}
			},
			invoke: func(t *testing.T, harness productAPITestHarness, taskID string) {
				item, err := harness.fixture.readQueueItem(taskID)
				if err != nil {
					t.Fatal(err)
				}
				task, _ := item["task"].(map[string]any)
				harness.fixture.drainProductTask(taskID, optionalString(item["lease_id"]), task)
			},
		},
		{
			name: "cancel",
			invoke: func(t *testing.T, harness productAPITestHarness, taskID string) {
				if view, replayed, err := harness.fixture.cancelProductTask(taskID, "reject invalid evidence"); err == nil || replayed || view != nil {
					t.Fatalf("cancel view=%#v replayed=%v err=%v", view, replayed, err)
				}
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			harness := newProductAPITestHarness(t)
			taskID := "pi:task-invalid-signed-correlation-" + strings.ReplaceAll(testCase.name, " ", "-")
			status, _, payload := harness.request(t, http.MethodPost, "/api/v1/tasks", productTaskPayload(taskID, harness.worker, "reject invalid evidence"), true)
			if status != http.StatusCreated {
				t.Fatalf("create status=%d payload=%#v", status, payload)
			}
			if testCase.prepare != nil {
				testCase.prepare(t, harness, taskID)
			}
			invalidateSignedProductTaskCorrelation(t, harness.fixture, taskID)
			before := snapshotProductDurables(t, harness.fixture, taskID)
			testCase.invoke(t, harness, taskID)
			assertProductDurablesUnchanged(t, harness.fixture, taskID, before)
		})
	}
}

func TestProductAPIRetryLeavesNoAttemptEffectsOnInvalidOrFailedChild(t *testing.T) {
	t.Run("invalid direct retry id", func(t *testing.T) {
		harness := newProductAPITestHarness(t)
		parentID := "pi:task-retry-invalid-direct"
		prepareFailedProductParent(t, harness, parentID)
		before := snapshotProductDurables(t, harness.fixture, parentID)
		if retry, replayed, err := harness.fixture.retryProductTask(parentID, "invalid retry id"); err == nil || replayed || retry != nil {
			t.Fatalf("retry=%#v replayed=%v err=%v", retry, replayed, err)
		}
		assertProductDurablesUnchanged(t, harness.fixture, parentID, before)
	})

	t.Run("injected child creation failure", func(t *testing.T) {
		harness := newProductAPITestHarness(t)
		parentID := "pi:task-retry-child-failure"
		childID := parentID + "-child"
		prepareFailedProductParent(t, harness, parentID)
		before := snapshotProductDurables(t, harness.fixture, parentID)
		harness.fixture.taskStateFault = func(point taskStateFaultPoint, transition map[string]any) error {
			if point == taskStateFaultWrite && optionalString(transition["task_id"]) == childID && optionalString(transition["to"]) == "queued" {
				return errors.New("injected child state failure")
			}
			return nil
		}
		if retry, replayed, err := harness.fixture.retryProductTask(parentID, childID); err == nil || replayed || retry != nil {
			t.Fatalf("retry=%#v replayed=%v err=%v", retry, replayed, err)
		}
		assertProductDurablesUnchanged(t, harness.fixture, parentID, before)
		if _, err := harness.fixture.readQueueItem(childID); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("failed child queue err=%v", err)
		}
		if _, err := harness.fixture.readTaskState(childID); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("failed child state err=%v", err)
		}
	})
}

func TestProductAPIRetryReconstructsAttemptFromDurableChildAfterParentMetadataLoss(t *testing.T) {
	harness := newProductAPITestHarness(t)
	parentID := "pi:task-retry-reconstruct-parent"
	prepareFailedProductParent(t, harness, parentID)
	firstID := parentID + "-first"
	first, replayed, err := harness.fixture.retryProductTask(parentID, firstID)
	if err != nil || replayed || intFromMap(first, "retry_attempt") != 1 {
		t.Fatalf("first retry=%#v replayed=%v err=%v", first, replayed, err)
	}
	parent, err := harness.fixture.readQueueItem(parentID)
	if err != nil {
		t.Fatal(err)
	}
	delete(parent, "last_retry_attempt")
	if err := writeJSONStateFile(filepath.Join(harness.fixture.QueueDir, parentID+".json"), parent); err != nil {
		t.Fatal(err)
	}
	second, replayed, err := harness.fixture.retryProductTask(parentID, parentID+"-second")
	if err != nil || replayed || intFromMap(second, "retry_attempt") != 2 {
		t.Fatalf("reconstructed retry=%#v replayed=%v err=%v", second, replayed, err)
	}
}
