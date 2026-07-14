package main

import (
	"agnet/internal/managedkey"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
			"pi_session_id":   "pi-session-1",
			"tool_call_id":    "tool-call-1",
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
