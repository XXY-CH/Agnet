package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const productAPIMaxBodyBytes = 1 << 20

type productTaskRequest struct {
	TaskID            string         `json:"task_id"`
	To                string         `json:"to"`
	Intent            string         `json:"intent"`
	Scope             map[string]any `json:"scope"`
	Budget            map[string]any `json:"budget,omitempty"`
	Correlation       map[string]any `json:"correlation"`
	ArtifactRef       string         `json:"artifact_ref,omitempty"`
	ApprovalExpiresAt string         `json:"approval_expires_at,omitempty"`
}

type productRetryRequest struct {
	TaskID string `json:"task_id"`
}

type productCancelRequest struct {
	Reason string `json:"reason"`
}

func registerProductAPIRoutes(mux *http.ServeMux, fixture Fixture, requireWriteToken func(http.ResponseWriter, *http.Request) bool) {
	mux.HandleFunc("/api/v1/tasks", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/tasks" {
			writeProductError(w, http.StatusNotFound, "not_found", "resource not found")
			return
		}
		if r.Method != http.MethodPost {
			writeProductError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}
		if !requireWriteToken(w, r) {
			return
		}
		var request productTaskRequest
		if err := decodeProductJSON(r, &request); err != nil {
			writeProductError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		if err := validateProductTaskRequest(request); err != nil {
			writeProductError(w, http.StatusUnprocessableEntity, "validation_error", err.Error())
			return
		}
		view, replayed, err := fixture.createProductTask(request, nil)
		if err != nil {
			status := http.StatusInternalServerError
			code := "internal_error"
			if errors.Is(err, errProductTaskConflict) {
				status = http.StatusConflict
				code = "idempotency_conflict"
			} else if strings.Contains(err.Error(), "does not match worker alias") || strings.Contains(err.Error(), "policy") {
				status = http.StatusUnprocessableEntity
				code = "task_rejected"
			}
			writeProductError(w, status, code, err.Error())
			return
		}
		status := http.StatusCreated
		if replayed {
			status = http.StatusOK
		} else {
			w.Header().Set("Location", "/api/v1/tasks/"+url.PathEscape(request.TaskID))
		}
		writeProductData(w, status, view, replayed)
	})

	mux.HandleFunc("/api/v1/tasks/", func(w http.ResponseWriter, r *http.Request) {
		remainder := strings.TrimPrefix(r.URL.Path, "/api/v1/tasks/")
		parts := strings.Split(remainder, "/")
		if len(parts) == 0 || parts[0] == "" || len(parts) > 2 {
			writeProductError(w, http.StatusNotFound, "not_found", "resource not found")
			return
		}
		taskID, err := url.PathUnescape(parts[0])
		if err != nil || validateTaskID(taskID) != nil {
			writeProductError(w, http.StatusBadRequest, "invalid_task_id", "task_id invalid")
			return
		}
		action := ""
		if len(parts) == 2 {
			action = parts[1]
		}
		switch {
		case action == "" && r.Method == http.MethodGet:
			view, err := fixture.productTaskView(taskID)
			if err != nil {
				writeProductLookupError(w, err)
				return
			}
			writeProductData(w, http.StatusOK, view, false)
		case action == "execute" && r.Method == http.MethodPost:
			if !requireWriteToken(w, r) {
				return
			}
			if err := decodeOptionalEmptyProductJSON(r); err != nil {
				writeProductError(w, http.StatusBadRequest, "invalid_request", err.Error())
				return
			}
			view, replayed, err := fixture.executeProductTask(taskID)
			if err != nil {
				writeProductStateError(w, err)
				return
			}
			status := http.StatusAccepted
			if replayed {
				status = http.StatusOK
			}
			writeProductData(w, status, view, replayed)
		case action == "cancel" && r.Method == http.MethodPost:
			if !requireWriteToken(w, r) {
				return
			}
			var request productCancelRequest
			if err := decodeProductJSON(r, &request); err != nil {
				writeProductError(w, http.StatusBadRequest, "invalid_request", err.Error())
				return
			}
			view, replayed, err := fixture.cancelProductTask(taskID, request.Reason)
			if err != nil {
				writeProductStateError(w, err)
				return
			}
			writeProductData(w, http.StatusOK, view, replayed)
		case action == "retry" && r.Method == http.MethodPost:
			if !requireWriteToken(w, r) {
				return
			}
			var request productRetryRequest
			if err := decodeProductJSON(r, &request); err != nil {
				writeProductError(w, http.StatusBadRequest, "invalid_request", err.Error())
				return
			}
			if err := validateTaskID(request.TaskID); err != nil {
				writeProductError(w, http.StatusUnprocessableEntity, "validation_error", "task_id invalid")
				return
			}
			view, replayed, err := fixture.retryProductTask(taskID, request.TaskID)
			if err != nil {
				writeProductStateError(w, err)
				return
			}
			status := http.StatusCreated
			if replayed {
				status = http.StatusOK
			} else {
				w.Header().Set("Location", "/api/v1/tasks/"+url.PathEscape(request.TaskID))
			}
			writeProductData(w, status, view, replayed)
		case action == "receipt" && r.Method == http.MethodGet:
			receipt, err := fixture.productCommittedReceipt(taskID)
			if err != nil {
				if strings.Contains(err.Error(), "artifact") || strings.Contains(err.Error(), "receipt") && !errors.Is(err, os.ErrNotExist) {
					writeProductError(w, http.StatusConflict, "verification_failed", "receipt verification failed")
					return
				}
				writeProductLookupError(w, err)
				return
			}
			writeProductData(w, http.StatusOK, receipt, false)
		case action == "events" && r.Method == http.MethodGet:
			after, err := parseProductCursor(r.URL.Query().Get("after"))
			if err != nil {
				writeProductError(w, http.StatusBadRequest, "invalid_cursor", err.Error())
				return
			}
			events, next, err := fixture.productTaskEvents(taskID, after)
			if err != nil {
				if strings.Contains(err.Error(), "verify") || strings.Contains(err.Error(), "artifact") || strings.Contains(err.Error(), "receipt") {
					writeProductError(w, http.StatusConflict, "verification_failed", "event verification failed")
					return
				}
				writeProductLookupError(w, err)
				return
			}
			writeProductCollection(w, http.StatusOK, events, strconv.Itoa(next))
		default:
			if action == "" || action == "execute" || action == "cancel" || action == "retry" || action == "receipt" || action == "events" {
				writeProductError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
				return
			}
			writeProductError(w, http.StatusNotFound, "not_found", "resource not found")
		}
	})
}

var errProductTaskConflict = errors.New("product task idempotency conflict")

func decodeProductJSON(r *http.Request, target any) error {
	decoder := json.NewDecoder(io.LimitReader(r.Body, productAPIMaxBodyBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errors.New("invalid JSON body")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("invalid JSON body")
	}
	return nil
}

func decodeOptionalEmptyProductJSON(r *http.Request) error {
	if r.Body == nil || r.ContentLength == 0 {
		return nil
	}
	var body struct{}
	return decodeProductJSON(r, &body)
}

func validateProductTaskRequest(request productTaskRequest) error {
	if err := validateTaskID(request.TaskID); err != nil {
		return err
	}
	if request.To == "" || len(request.To) > 512 {
		return errors.New("task target is required")
	}
	if request.Intent == "" || len(request.Intent) > 64*1024 {
		return errors.New("task intent is required")
	}
	if request.Scope == nil {
		return errors.New("task scope is required")
	}
	for key := range request.Scope {
		switch key {
		case "network", "write", "data_domains", "expires_at":
		default:
			return errors.New("task scope field invalid")
		}
	}
	if network, exists := request.Scope["network"]; exists {
		if _, ok := network.(bool); !ok {
			return errors.New("task scope network invalid")
		}
	}
	for _, key := range []string{"write", "data_domains"} {
		if value, exists := request.Scope[key]; exists {
			if !isProductStringArray(value) {
				return errors.New("task scope " + key + " invalid")
			}
		}
	}
	for _, key := range []string{"workspace_id", "conversation_id", "pi_session_id", "tool_call_id"} {
		value := optionalString(request.Correlation[key])
		if value == "" || len(value) > 256 {
			return errors.New("task correlation " + key + " is required")
		}
	}
	if request.ArtifactRef != "" && (len(request.ArtifactRef) > 2048 || hasSwarmDelimiter(request.ArtifactRef)) {
		return errors.New("task artifact_ref invalid")
	}
	if request.ApprovalExpiresAt != "" {
		if _, err := time.Parse(time.RFC3339Nano, request.ApprovalExpiresAt); err != nil {
			return errors.New("approval_expires_at invalid")
		}
	}
	return nil
}

func isProductStringArray(value any) bool {
	items, ok := value.([]any)
	if !ok {
		_, ok = value.([]string)
		return ok
	}
	for _, item := range items {
		if _, ok := item.(string); !ok {
			return false
		}
	}
	return true
}

func productRequestMap(request productTaskRequest) map[string]any {
	result := map[string]any{
		"task_id":     request.TaskID,
		"to":          request.To,
		"intent":      request.Intent,
		"scope":       request.Scope,
		"correlation": request.Correlation,
	}
	if request.Budget != nil {
		result["budget"] = request.Budget
	}
	if request.ArtifactRef != "" {
		result["artifact_ref"] = request.ArtifactRef
	}
	if request.ApprovalExpiresAt != "" {
		result["approval_expires_at"] = request.ApprovalExpiresAt
	}
	return result
}

func acquireProductTaskLock(queueDir, taskID string) (func(), error) {
	if queueDir == "" {
		return nil, errors.New("product task queue unavailable")
	}
	lockRoot := filepath.Join(queueDir, ".product-task-locks")
	if err := os.MkdirAll(lockRoot, 0o700); err != nil {
		return nil, err
	}
	lockPath := filepath.Join(lockRoot, url.PathEscape(taskID)+".lock")
	deadline := time.Now().Add(5 * time.Second)
	for {
		if err := os.Mkdir(lockPath, 0o700); err == nil {
			return func() { _ = os.Remove(lockPath) }, nil
		} else if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		if info, err := os.Stat(lockPath); err == nil && time.Since(info.ModTime()) > 30*time.Second {
			_ = os.Remove(lockPath)
			continue
		}
		if !time.Now().Before(deadline) {
			return nil, errors.New("product task idempotency lock timeout")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (f Fixture) createProductTask(request productTaskRequest, retry map[string]any) (map[string]any, bool, error) {
	release, err := acquireProductTaskLock(f.QueueDir, request.TaskID)
	if err != nil {
		return nil, false, err
	}
	defer release()
	requestMap := productRequestMap(request)
	if retry != nil {
		requestMap["retry"] = retry
	}
	requestDigest := digestHex(requestMap)
	if existing, err := f.readQueueItem(request.TaskID); err == nil {
		if optionalString(existing["product_request_digest"]) != requestDigest {
			return nil, false, errProductTaskConflict
		}
		if _, statErr := os.Stat(taskStateJournalPath(f.TaskStateDir, request.TaskID)); errors.Is(statErr, os.ErrNotExist) {
			migrationStatus := optionalString(existing["status"])
			if legacyState, legacyErr := f.readTaskState(request.TaskID); legacyErr == nil {
				migrationStatus = optionalString(legacyState["status"])
			} else if !errors.Is(legacyErr, os.ErrNotExist) {
				return nil, false, legacyErr
			}
			if migrationStatus == "" {
				migrationStatus = "queued"
			}
			if _, transitionErr := f.transitionTaskState(request.TaskID, migrationStatus, optionalString(existing["worker"]), map[string]any{}); transitionErr != nil {
				return nil, false, transitionErr
			}
		} else if statErr != nil {
			return nil, false, statErr
		}
		view, viewErr := f.productTaskView(request.TaskID)
		return view, true, viewErr
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, false, err
	}
	requester, err := f.humanGatewayRequester()
	if err != nil {
		return nil, false, err
	}
	task := productRequestMap(request)
	task["from"] = requester["aid"]
	if retry != nil {
		task["retry_of"] = retry["retry_of"]
		task["retry_attempt"] = retry["retry_attempt"]
	}
	signedTask := signBody(f.AuthorityPrivateKey, task)
	frame := map[string]any{
		"type":                   "FED_TASK_OPEN",
		"origin_zone":            f.Authority,
		"requester":              requester,
		"requester_zone_binding": f.zoneBindingForDescriptor(requester),
		"task":                   signedTask,
	}
	extra := map[string]any{
		"product_request_digest": requestDigest,
		"correlation":            request.Correlation,
	}
	if retry != nil {
		extra["retry_of"] = retry["retry_of"]
		extra["retry_attempt"] = retry["retry_attempt"]
	}
	_, workerID, err := f.enqueueQueueItemWithExtra(f.Authority, frame, extra)
	if err != nil {
		return nil, false, err
	}
	stateExtra := map[string]any{"correlation": request.Correlation}
	if retry != nil {
		stateExtra["retry_of"] = retry["retry_of"]
		stateExtra["retry_attempt"] = retry["retry_attempt"]
	}
	if _, err := f.transitionTaskState(request.TaskID, "queued", fmt.Sprint(workerID), stateExtra); err != nil {
		return nil, false, err
	}
	queuedEvent := map[string]any{"type": "task.queued", "task_id": request.TaskID, "by": requester["aid"], "zone": f.Authority["zid"]}
	if retry != nil {
		queuedEvent["retry_of"] = retry["retry_of"]
		queuedEvent["retry_attempt"] = retry["retry_attempt"]
	}
	if err := f.sendTaskEvent(func(map[string]any) {}, queuedEvent); err != nil {
		return nil, false, err
	}
	view, err := f.productTaskView(request.TaskID)
	return view, false, err
}

func (f Fixture) productTaskView(taskID string) (map[string]any, error) {
	item, err := f.readQueueItem(taskID)
	if err != nil {
		return nil, err
	}
	task, _ := item["task"].(map[string]any)
	view := map[string]any{
		"task_id":     taskID,
		"status":      optionalString(item["status"]),
		"worker":      item["worker"],
		"intent":      task["intent"],
		"scope":       task["scope"],
		"correlation": item["correlation"],
	}
	for _, key := range []string{"error", "lease_id", "lease_owner", "lease_expires_at", "retry_of", "retry_attempt", "receipt_digest"} {
		if value, exists := item[key]; exists {
			view[key] = value
		}
	}
	if state, stateErr := f.readTaskState(taskID); stateErr == nil {
		if status := optionalString(state["status"]); status != "" {
			view["status"] = status
		}
		for _, key := range []string{"error", "receipt_digest"} {
			if value, exists := state[key]; exists {
				view[key] = value
			}
		}
	} else if !errors.Is(stateErr, os.ErrNotExist) {
		return nil, stateErr
	}
	if approval, approvalErr := f.readApprovalState(taskID); approvalErr == nil {
		view["approval"] = approval
	} else if !errors.Is(approvalErr, os.ErrNotExist) && f.ApprovalDir != "" {
		return nil, approvalErr
	}
	if record, receiptErr := f.auditProof(taskID); receiptErr == nil {
		receipt, _ := record["receipt"].(map[string]any)
		view["receipt_digest"] = digestHex(receipt)
		view["artifact_refs"] = receipt["artifact_refs"]
	} else if !strings.Contains(receiptErr.Error(), "not found") && !errors.Is(receiptErr, os.ErrNotExist) {
		return nil, receiptErr
	}
	return view, nil
}

func (f Fixture) executeProductTask(taskID string) (map[string]any, bool, error) {
	item, err := f.readQueueItem(taskID)
	if err != nil {
		return nil, false, err
	}
	view, err := f.productTaskView(taskID)
	if err != nil {
		return nil, false, err
	}
	status := optionalString(view["status"])
	if status != "queued" {
		if status == "claimed" || status == "running" || status == "completing" || status == "completed" || status == "cancelled" {
			return view, true, nil
		}
		return nil, false, fmt.Errorf("task cannot execute from status %s", status)
	}
	task, _ := item["task"].(map[string]any)
	claim := productQueueAction(f, "claim", taskID, task)
	claim["owner"] = "product://local"
	claim["lease_seconds"] = float64(300)
	result, err := f.applyAuthorizedProductQueueAction(claim)
	if err != nil {
		return nil, false, err
	}
	if _, err := f.transitionTaskState(taskID, "claimed", optionalString(item["worker"]), map[string]any{"lease_id": result["lease_id"], "lease_owner": "product://local"}); err != nil {
		return nil, false, err
	}
	leaseID := optionalString(result["lease_id"])
	go f.drainProductTask(taskID, leaseID, task)
	view, err = f.productTaskView(taskID)
	return view, false, err
}

func (f Fixture) terminalProjectionSettled(taskID, status, receiptDigest string) (bool, error) {
	state, err := f.readTaskState(taskID)
	if err != nil {
		return false, err
	}
	if optionalString(state["status"]) != status || optionalString(state["receipt_digest"]) != receiptDigest {
		return false, nil
	}
	item, err := f.readQueueItem(taskID)
	if err != nil {
		return false, err
	}
	if optionalString(item["status"]) == status && optionalString(item["receipt_digest"]) == receiptDigest {
		return true, nil
	}
	item["status"] = status
	item["receipt_digest"] = receiptDigest
	if err := writeJSONStateFile(filepath.Join(f.QueueDir, url.PathEscape(taskID)+".json"), item); err != nil {
		return false, err
	}
	return true, nil
}

func productQueueAction(f Fixture, action, taskID string, task map[string]any) map[string]any {
	return map[string]any{
		"action":       action,
		"task_id":      taskID,
		"actor":        "human://local",
		"task":         task,
		"action_grant": f.queueActionGrant(action, taskID, task),
	}
}

func (f Fixture) applyAuthorizedProductQueueAction(action map[string]any) (map[string]any, error) {
	if err := f.requireQueueActionGrant(action); err != nil {
		_ = f.recordQueueAction(action, nil, err)
		return nil, err
	}
	result, err := f.applyQueueAction(action)
	if auditErr := f.recordQueueAction(action, result, err); auditErr != nil {
		return nil, auditErr
	}
	return result, err
}

func (f Fixture) drainProductTask(taskID, leaseID string, task map[string]any) {
	action := productQueueAction(f, "drain", taskID, task)
	action["lease_id"] = leaseID
	_, _ = f.applyAuthorizedProductQueueAction(action)
}

func (f Fixture) cancelProductTask(taskID, reason string) (map[string]any, bool, error) {
	item, err := f.readQueueItem(taskID)
	if err != nil {
		return nil, false, err
	}
	view, err := f.productTaskView(taskID)
	if err != nil {
		return nil, false, err
	}
	status := optionalString(view["status"])
	if status == "cancelled" {
		return view, true, nil
	}
	if status == "completed" || status == "failed" {
		return nil, false, fmt.Errorf("%s task cannot be cancelled", status)
	}
	requester, _ := item["requester"].(map[string]any)
	task, _ := item["task"].(map[string]any)
	origin, _ := item["origin_zone_descriptor"].(map[string]any)
	worker := f.workerByAlias(optionalString(task["to"]))
	if requester == nil || origin == nil || worker == nil {
		return nil, false, errors.New("task cancellation evidence unavailable")
	}
	cancelBody := map[string]any{
		"task_id":   taskID,
		"from":      requester["aid"],
		"to":        task["to"],
		"reason":    reason,
		"issued_at": time.Now().UTC().Format(time.RFC3339Nano),
	}
	cancel := signBody(f.AuthorityPrivateKey, cancelBody)
	if err := f.cancelTask(func(map[string]any) {}, origin, worker, requester, cancel); err != nil {
		return nil, false, err
	}
	item["status"] = "cancelled"
	if state, stateErr := f.readTaskState(taskID); stateErr == nil {
		item["receipt_digest"] = state["receipt_digest"]
	}
	if err := writeJSONStateFile(filepath.Join(f.QueueDir, url.PathEscape(taskID)+".json"), item); err != nil {
		return nil, false, err
	}
	view, err = f.productTaskView(taskID)
	return view, false, err
}

func (f Fixture) retryProductTask(parentID, taskID string) (map[string]any, bool, error) {
	if taskID == parentID {
		return nil, false, errors.New("retry task_id must differ from parent")
	}
	release, err := acquireProductTaskLock(f.QueueDir, "retry-parent:"+parentID)
	if err != nil {
		return nil, false, err
	}
	defer release()
	parent, err := f.readQueueItem(parentID)
	if err != nil {
		return nil, false, err
	}
	parentView, err := f.productTaskView(parentID)
	if err != nil {
		return nil, false, err
	}
	if optionalString(parentView["status"]) != "failed" {
		return nil, false, errors.New("retry parent is not failed")
	}
	attempt := 0
	if existing, existingErr := f.readQueueItem(taskID); existingErr == nil {
		if optionalString(existing["retry_of"]) != parentID {
			return nil, false, errProductTaskConflict
		}
		attempt = intFromMap(existing, "retry_attempt")
		if attempt < 1 {
			return nil, false, errors.New("retry attempt missing")
		}
	} else if !errors.Is(existingErr, os.ErrNotExist) {
		return nil, false, existingErr
	} else {
		attempt = intFromMap(parent, "last_retry_attempt") + 1
		if parentAttempt := intFromMap(parent, "retry_attempt"); attempt <= parentAttempt {
			attempt = parentAttempt + 1
		}
		parent["last_retry_attempt"] = float64(attempt)
		if err := writeJSONStateFile(filepath.Join(f.QueueDir, url.PathEscape(parentID)+".json"), parent); err != nil {
			return nil, false, err
		}
	}
	parentTask, _ := parent["task"].(map[string]any)
	correlation, _ := parent["correlation"].(map[string]any)
	correlationCopy := map[string]any{}
	for key, value := range correlation {
		correlationCopy[key] = value
	}
	correlationCopy["attempt"] = float64(attempt)
	request := productTaskRequest{
		TaskID:            taskID,
		To:                optionalString(parentTask["to"]),
		Intent:            optionalString(parentTask["intent"]),
		Correlation:       correlationCopy,
		ArtifactRef:       optionalString(parentTask["artifact_ref"]),
		ApprovalExpiresAt: optionalString(parentTask["approval_expires_at"]),
	}
	request.Scope, _ = parentTask["scope"].(map[string]any)
	request.Budget, _ = parentTask["budget"].(map[string]any)
	return f.createProductTask(request, map[string]any{"retry_of": parentID, "retry_attempt": float64(attempt)})
}

func (f Fixture) productCommittedReceipt(taskID string) (map[string]any, error) {
	item, err := f.readQueueItem(taskID)
	if err != nil {
		return nil, err
	}
	record, err := f.auditProof(taskID)
	if err != nil {
		return nil, err
	}
	receipt, _ := record["receipt"].(map[string]any)
	status := optionalString(receipt["status"])
	if status == "" {
		status = optionalString(item["status"])
	}
	if status != "completed" && status != "failed" && status != "cancelled" {
		return nil, errors.New("receipt terminal status invalid")
	}
	task, ok := item["task"].(map[string]any)
	if !ok {
		return nil, errors.New("receipt signed task missing")
	}
	if err := verifyReceiptRecord(record, f.ArtifactStoreDir, task); err != nil {
		return nil, err
	}
	committed := map[string]any{
		"committed":      true,
		"task_id":        taskID,
		"status":         status,
		"receipt_digest": digestHex(receipt),
		"audit_hash":     record["audit_hash"],
		"zone":           record["zone"],
		"worker":         record["worker"],
		"zone_binding":   record["zone_binding"],
		"receipt":        receipt,
		"signed_task":    task,
	}
	return committed, nil
}

func (f Fixture) productTaskEvents(taskID string, after int) ([]map[string]any, int, error) {
	if _, err := f.readQueueItem(taskID); err != nil {
		return nil, after, err
	}
	entries, err := readAuditEntriesOrEmpty(f.Audit.Path)
	if err != nil {
		return nil, after, err
	}
	if after < 0 || after > len(entries) {
		return nil, after, errors.New("event cursor out of range")
	}
	terminalCursor := 0
	for index, entry := range entries {
		record, _ := entry["record"].(map[string]any)
		if optionalString(record["kind"]) != "go_fed_receipt" {
			continue
		}
		receipt, _ := record["receipt"].(map[string]any)
		if optionalString(receipt["task_id"]) == taskID {
			terminalCursor = index + 1
			break
		}
	}
	if terminalCursor > 0 {
		if _, err := f.productCommittedReceipt(taskID); err != nil {
			return nil, after, err
		}
		if after >= terminalCursor {
			return []map[string]any{}, len(entries), nil
		}
	}
	events := []map[string]any{}
	scanEnd := len(entries)
	if terminalCursor > 0 {
		scanEnd = terminalCursor
	}
	for index := after; index < scanEnd; index++ {
		entry := entries[index]
		record, _ := entry["record"].(map[string]any)
		switch optionalString(record["kind"]) {
		case "go_fed_event":
			event, _ := record["event"].(map[string]any)
			if optionalString(event["task_id"]) == taskID {
				events = append(events, map[string]any{"cursor": float64(index + 1), "type": event["type"], "payload": event, "verified": false})
			}
		case "go_fed_receipt":
			receipt, _ := record["receipt"].(map[string]any)
			if optionalString(receipt["task_id"]) == taskID {
				committed, err := f.productCommittedReceipt(taskID)
				if err != nil {
					return nil, after, err
				}
				settled, err := f.terminalProjectionSettled(taskID, optionalString(committed["status"]), optionalString(committed["receipt_digest"]))
				if err != nil {
					return nil, after, err
				}
				if !settled {
					return events, index, nil
				}
				delete(committed, "verified")
				events = append(events, map[string]any{"cursor": float64(index + 1), "type": "receipt.committed", "payload": committed, "verified": false})
				return events, len(entries), nil
			}
		case "go_queue_action":
			if optionalString(record["task_id"]) == taskID {
				events = append(events, map[string]any{"cursor": float64(index + 1), "type": "queue." + optionalString(record["action"]), "payload": record, "verified": false})
			}
		}
	}
	return events, len(entries), nil
}

func parseProductCursor(value string) (int, error) {
	if value == "" {
		return 0, nil
	}
	cursor, err := strconv.Atoi(value)
	if err != nil || cursor < 0 {
		return 0, errors.New("event cursor invalid")
	}
	return cursor, nil
}

func writeProductData(w http.ResponseWriter, status int, data any, replayed bool) {
	payload := map[string]any{"data": data}
	if replayed {
		payload["replayed"] = true
	}
	writeProductJSON(w, status, payload)
}

func writeProductCollection(w http.ResponseWriter, status int, data any, nextCursor string) {
	writeProductJSON(w, status, map[string]any{"data": data, "next_cursor": nextCursor})
}

func writeProductError(w http.ResponseWriter, status int, code, message string) {
	writeProductJSON(w, status, map[string]any{"error": map[string]any{"code": code, "message": message}})
}

func writeProductLookupError(w http.ResponseWriter, err error) {
	if errors.Is(err, os.ErrNotExist) || strings.Contains(err.Error(), "not found") {
		writeProductError(w, http.StatusNotFound, "not_found", "task not found")
		return
	}
	writeProductError(w, http.StatusInternalServerError, "internal_error", "internal error")
}

func writeProductStateError(w http.ResponseWriter, err error) {
	if errors.Is(err, os.ErrNotExist) {
		writeProductError(w, http.StatusNotFound, "not_found", "task not found")
		return
	}
	if errors.Is(err, errProductTaskConflict) || strings.Contains(err.Error(), "cannot") || strings.Contains(err.Error(), "not failed") || strings.Contains(err.Error(), "not queued") || strings.Contains(err.Error(), "completion already committed") {
		writeProductError(w, http.StatusConflict, "state_conflict", err.Error())
		return
	}
	writeProductError(w, http.StatusInternalServerError, "internal_error", "internal error")
}

func writeProductJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
