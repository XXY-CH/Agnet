package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func (f Fixture) queueActionGrant(action, taskID string, task map[string]any) map[string]any {
	return signBodyWithKey(f.AuthorityPrivateKey, map[string]any{
		"action":               action,
		"task_id":              taskID,
		"task_digest":          digestHex(task),
		"actor":                "human://local",
		"authority":            f.Authority["zid"],
		"authority_descriptor": f.Authority,
		"scope":                map[string]any{"actions": []any{action}},
		"expires_at":           "2099-01-01T00:00:00Z",
	}, "grant_signature")
}

func (f Fixture) writeQueueItem(origin map[string]any, worker *Worker, task map[string]any, status string, extra map[string]any) error {
	if f.QueueDir == "" {
		return nil
	}
	taskID := fmt.Sprint(task["task_id"])
	body := map[string]any{
		"task_id":     taskID,
		"status":      status,
		"worker":      worker.Descriptor["aid"],
		"origin_zone": origin["zid"],
		"task_digest": digestHex(task),
	}
	for key, value := range extra {
		body[key] = value
	}
	// ponytail: one queue file per task; replace with leases when multiple workers can drain it.
	return writeJSONStateFile(filepath.Join(f.QueueDir, url.PathEscape(taskID)+".json"), body)
}

func (f Fixture) readQueueItem(taskID string) (map[string]any, error) {
	if f.QueueDir == "" {
		return nil, errors.New("queue unavailable")
	}
	data, err := os.ReadFile(filepath.Join(f.QueueDir, url.PathEscape(taskID)+".json"))
	if err != nil {
		return nil, err
	}
	var item map[string]any
	if err := json.Unmarshal(data, &item); err != nil {
		return nil, err
	}
	return item, nil
}

func (f Fixture) enqueueQueueItem(origin map[string]any, frame map[string]any) (string, any, error) {
	return f.enqueueQueueItemWithExtra(origin, frame, map[string]any{})
}

func (f Fixture) enqueueResumeQueueItem(origin map[string]any, frame map[string]any) (string, any, error) {
	checkpointID := fmt.Sprint(frame["checkpoint_id"])
	if checkpointID == "" || checkpointID == "<nil>" {
		return "", nil, errors.New("resume checkpoint_id missing")
	}
	if err := f.requireCheckpoint(checkpointID); err != nil {
		return "", nil, err
	}
	return f.enqueueQueueItemWithExtra(origin, frame, map[string]any{"resume_checkpoint": checkpointID})
}

func (f Fixture) enqueueQueueItemWithExtra(origin map[string]any, frame map[string]any, extra map[string]any) (string, any, error) {
	worker, task, err := f.verifyTaskOpen(taskOpenFrameForVerification(frame))
	if err != nil {
		return "", nil, err
	}
	requester, _ := frame["requester"].(map[string]any)
	body := map[string]any{"origin_zone_descriptor": origin, "requester": requester, "requester_zone_binding": frame["requester_zone_binding"], "task": task}
	for key, value := range extra {
		body[key] = value
	}
	if err := f.writeQueueItem(origin, worker, task, "queued", body); err != nil {
		return "", nil, err
	}
	return fmt.Sprint(task["task_id"]), worker.Descriptor["aid"], nil
}

func (f Fixture) claimQueueItem(taskID, owner string, leaseSeconds int) (string, error) {
	item, err := f.readQueueItem(taskID)
	if err != nil {
		return "", err
	}
	if optionalString(item["status"]) != "queued" {
		return "", errors.New("queue item is not queued: " + taskID)
	}
	if queueRetryBackoffActive(item) {
		return "", errors.New("queue retry backoff active: " + taskID)
	}
	return f.writeClaimedQueueItem(taskID, owner, leaseSeconds, item)
}

func (f Fixture) retryQueueItem(origin map[string]any, frame map[string]any, retryAfterSeconds int) (string, error) {
	retryOf := fmt.Sprint(frame["retry_of"])
	if retryOf == "" || retryOf == "<nil>" {
		return "", errors.New("queue retry_of missing")
	}
	worker, task, err := f.verifyTaskOpen(taskOpenFrameForVerification(frame))
	if err != nil {
		return "", err
	}
	taskID := fmt.Sprint(task["task_id"])
	if taskID == retryOf {
		return "", errors.New("queue retry task_id must differ from parent")
	}
	release, err := acquireProductTaskLock(f.QueueDir, "queue-retry-parent:"+retryOf)
	if err != nil {
		return "", err
	}
	defer release()
	parent, err := f.readQueueItem(retryOf)
	if err != nil {
		return "", err
	}
	if optionalString(parent["status"]) != "failed" {
		return "", errors.New("queue retry parent is not failed: " + retryOf)
	}
	if existing, existingErr := f.readQueueItem(taskID); existingErr == nil {
		if optionalString(existing["retry_of"]) == retryOf {
			return taskID, nil
		}
		return "", errors.New("queue retry task conflict: " + taskID)
	} else if !errors.Is(existingErr, os.ErrNotExist) {
		return "", existingErr
	}
	attempt := intFromMap(parent, "last_retry_attempt") + 1
	if parentAttempt := intFromMap(parent, "retry_attempt"); attempt <= parentAttempt {
		attempt = parentAttempt + 1
	}
	parent["last_retry_attempt"] = float64(attempt)
	if err := writeJSONStateFile(filepath.Join(f.QueueDir, url.PathEscape(retryOf)+".json"), parent); err != nil {
		return "", err
	}
	retryAfterAt := time.Now().Add(time.Duration(retryAfterSeconds) * time.Second).UTC().Format(time.RFC3339Nano)
	requester, _ := frame["requester"].(map[string]any)
	extra := map[string]any{"origin_zone_descriptor": origin, "requester": requester, "task": task, "retry_of": retryOf, "retry_attempt": attempt, "retry_after_at": retryAfterAt}
	if err := f.writeQueueItem(origin, worker, task, "queued", extra); err != nil {
		return "", err
	}
	return taskID, nil
}

func (f Fixture) applyQueueAction(action map[string]any) (map[string]any, error) {
	switch optionalString(action["action"]) {
	case "enqueue":
		origin, _ := action["origin_zone"].(map[string]any)
		if len(origin) == 0 {
			return nil, errors.New("queue action origin_zone missing")
		}
		taskID, workerID, err := f.enqueueQueueItem(origin, action)
		if err != nil {
			return nil, err
		}
		return map[string]any{"ok": true, "action": "enqueue", "task_id": taskID, "worker": workerID}, nil
	case "claim":
		taskID := fmt.Sprint(action["task_id"])
		if taskID == "" || taskID == "<nil>" {
			return nil, errors.New("queue action task_id missing")
		}
		if err := validateTaskID(taskID); err != nil {
			return nil, err
		}
		owner := fmt.Sprint(action["owner"])
		if owner == "" || owner == "<nil>" {
			return nil, errors.New("queue action owner missing")
		}
		leaseID, err := f.claimQueueItem(taskID, owner, frameSeconds(action, "lease_seconds", 60))
		if err != nil {
			return nil, err
		}
		return map[string]any{"ok": true, "action": "claim", "task_id": taskID, "lease_id": leaseID, "owner": owner}, nil
	case "drain":
		taskID := fmt.Sprint(action["task_id"])
		if taskID == "" || taskID == "<nil>" {
			return nil, errors.New("queue action task_id missing")
		}
		if err := validateTaskID(taskID); err != nil {
			return nil, err
		}
		leaseID := fmt.Sprint(action["lease_id"])
		if leaseID == "" || leaseID == "<nil>" {
			return nil, errors.New("queue action lease_id missing")
		}
		if err := f.drainQueueItem(func(map[string]any) {}, taskID, leaseID); err != nil {
			return nil, err
		}
		return map[string]any{"ok": true, "action": "drain", "task_id": taskID}, nil
	default:
		return nil, errors.New("unsupported queue action")
	}
}

func (f Fixture) requireQueueActionGrant(action map[string]any) error {
	grant, ok := action["action_grant"].(map[string]any)
	if !ok {
		return errors.New("queue action grant missing")
	}
	authority, ok := grant["authority_descriptor"].(map[string]any)
	if !ok {
		return errors.New("queue action grant authority descriptor missing")
	}
	if err := verifyZoneDescriptor(authority); err != nil {
		return err
	}
	if grant["authority"] != authority["zid"] {
		return errors.New("queue action grant authority mismatch")
	}
	if grant["action"] != action["action"] {
		return errors.New("queue action grant action mismatch")
	}
	actions, err := queueActionGrantActions(grant)
	if err != nil {
		return err
	}
	if !stringInSlice(optionalString(action["action"]), actions) {
		return errors.New("queue action grant scope mismatch")
	}
	if optionalString(grant["actor"]) == "" {
		return errors.New("queue action grant actor missing")
	}
	if optionalString(action["actor"]) == "" {
		return errors.New("queue action actor missing")
	}
	if grant["actor"] != action["actor"] {
		return errors.New("queue action grant actor mismatch")
	}
	if !f.queueActionActorAllowed(optionalString(action["actor"]), optionalString(action["action"])) {
		return errors.New("queue action actor policy denied")
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, optionalString(grant["expires_at"]))
	if err != nil {
		return errors.New("queue action grant expires_at invalid")
	}
	if !time.Now().UTC().Before(expiresAt) {
		return errors.New("queue action grant expired")
	}
	if grant["task_id"] != queueActionTaskID(action, nil) {
		return errors.New("queue action grant task mismatch")
	}
	task, _ := action["task"].(map[string]any)
	expectedTaskDigest := any(nil)
	if task != nil {
		expectedTaskDigest = digestHex(task)
	}
	if grant["task_digest"] != expectedTaskDigest {
		return errors.New("queue action grant task digest mismatch")
	}
	authorityKey, _, err := publicKey(authority)
	if err != nil {
		return err
	}
	if err := verifyMapSignature(authorityKey, grant, "grant_signature"); err != nil {
		return errors.New("queue action grant signature verification failed")
	}
	grantDigest := digestHex(grant)
	return f.consumeQueueActionGrant(grantDigest, action)
}

func queueActionGrantAllows(grant map[string]any, action string) bool {
	actions, err := queueActionGrantActions(grant)
	return err == nil && stringInSlice(action, actions)
}

func queueActionGrantActions(grant map[string]any) ([]string, error) {
	scope, _ := grant["scope"].(map[string]any)
	if scope == nil {
		return nil, nil
	}
	value := scope["actions"]
	if value == nil {
		return nil, nil
	}
	if typed, ok := value.([]string); ok {
		return typed, nil
	}
	items, ok := value.([]any)
	if !ok {
		return nil, errors.New("queue action grant scope invalid")
	}
	var actions []string
	for _, item := range items {
		text, ok := item.(string)
		if !ok {
			return nil, errors.New("queue action grant scope invalid")
		}
		actions = append(actions, text)
	}
	return actions, nil
}

func stringInSlice(needle string, haystack []string) bool {
	for _, item := range haystack {
		if item == needle {
			return true
		}
	}
	return false
}

func (f Fixture) queueActionActorAllowed(actor, action string) bool {
	if len(f.QueueActorPolicy) == 0 {
		return actor == "human://local" && (action == "enqueue" || action == "claim" || action == "drain")
	}
	for _, allowed := range f.QueueActorPolicy[actor] {
		if allowed == action {
			return true
		}
	}
	return false
}

func (f Fixture) approvalActorAllowed(actor, action string) bool {
	if len(f.ApprovalActorPolicy) == 0 {
		return actor == "human://local" && (action == "approve" || action == "deny")
	}
	for _, allowed := range f.ApprovalActorPolicy[actor] {
		if allowed == action {
			return true
		}
	}
	return false
}

func (f Fixture) approvalActionsFor(actor string) []string {
	if actor == "" {
		return []string{}
	}
	if len(f.ApprovalActorPolicy) == 0 {
		if actor == "human://local" {
			return []string{"approve", "deny"}
		}
		return []string{}
	}
	return append([]string{}, f.ApprovalActorPolicy[actor]...)
}

func (f Fixture) approvalSessionActor(r *http.Request) string {
	if len(f.ApprovalSessions) == 0 {
		return ""
	}
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		return ""
	}
	return f.ApprovalSessions[strings.TrimPrefix(header, "Bearer ")]
}

func (f Fixture) consumeQueueActionGrant(grantDigest string, action map[string]any) error {
	if f.Audit == nil || f.Audit.Path == "" {
		return nil
	}
	dir := queueGrantDirForAudit(f.Audit.Path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	path := filepath.Join(dir, grantDigest+".json")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		return errors.New("queue action grant replay")
	}
	if err != nil {
		return err
	}
	defer file.Close()
	record := map[string]any{
		"grant_digest": grantDigest,
		"action":       optionalString(action["action"]),
		"task_id":      queueActionTaskID(action, nil),
		"actor":        queueActionActor(action),
		"consumed_at":  time.Now().UTC().Format(time.RFC3339Nano),
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	_, err = file.Write(append(data, '\n'))
	return err
}

func (f Fixture) recordQueueAction(action map[string]any, result map[string]any, actionErr error) error {
	record := map[string]any{
		"kind":         "go_queue_action",
		"action":       optionalString(action["action"]),
		"task_id":      queueActionTaskID(action, result),
		"source":       "human_gateway.local",
		"grant_digest": queueActionGrantDigest(action),
		"actor":        queueActionActor(action),
	}
	if actorPolicyResult := f.queueActionActorPolicyResult(action); actorPolicyResult != "" {
		record["actor_policy_result"] = actorPolicyResult
	}
	if actionErr != nil {
		record["status"] = "error"
		record["error"] = actionErr.Error()
	} else {
		record["status"] = "ok"
		record["result_digest"] = digestHex(result)
	}
	return f.appendAudit(record)
}
func queueActionGrantDigest(action map[string]any) any {
	grant, ok := action["action_grant"].(map[string]any)
	if !ok {
		return nil
	}
	return digestHex(grant)
}

func queueActionActor(action map[string]any) string {
	if actor := optionalString(action["actor"]); actor != "" {
		return actor
	}
	if grant, ok := action["action_grant"].(map[string]any); ok {
		return optionalString(grant["actor"])
	}
	return ""
}

func (f Fixture) queueActionActorPolicyResult(action map[string]any) string {
	actionName := optionalString(action["action"])
	grant, ok := action["action_grant"].(map[string]any)
	if !ok {
		return ""
	}
	authority, ok := grant["authority_descriptor"].(map[string]any)
	if !ok || verifyZoneDescriptor(authority) != nil {
		return ""
	}
	if grant["authority"] != authority["zid"] || grant["action"] != action["action"] || !queueActionGrantAllows(grant, actionName) {
		return ""
	}
	actor := optionalString(action["actor"])
	if actor == "" || optionalString(grant["actor"]) == "" || grant["actor"] != action["actor"] {
		return ""
	}
	if f.queueActionActorAllowed(actor, actionName) {
		return "allow"
	}
	return "deny"
}

func queueActionTaskID(action, result map[string]any) string {
	if taskID := optionalString(action["task_id"]); taskID != "" {
		return taskID
	}
	if taskID := optionalString(result["task_id"]); taskID != "" {
		return taskID
	}
	task, _ := action["task"].(map[string]any)
	return optionalString(task["task_id"])
}

func (f Fixture) reclaimQueueItem(taskID, owner string, leaseSeconds int) (string, error) {
	item, err := f.readQueueItem(taskID)
	if err != nil {
		return "", err
	}
	if optionalString(item["status"]) != "claimed" {
		return "", errors.New("queue item is not claimed: " + taskID)
	}
	if !queueLeaseExpired(item) {
		return "", errors.New("queue lease is still active: " + taskID)
	}
	return f.writeClaimedQueueItem(taskID, owner, leaseSeconds, item)
}

func (f Fixture) writeClaimedQueueItem(taskID, owner string, leaseSeconds int, item map[string]any) (string, error) {
	origin, _ := item["origin_zone_descriptor"].(map[string]any)
	requester, _ := item["requester"].(map[string]any)
	task, _ := item["task"].(map[string]any)
	worker, task, err := f.verifyTaskOpen(map[string]any{"type": "FED_TASK_OPEN", "origin_zone": origin, "requester": requester, "requester_zone_binding": item["requester_zone_binding"], "task": task})
	if err != nil {
		return "", err
	}
	leaseExpiresAt := time.Now().Add(time.Duration(leaseSeconds) * time.Second).UTC().Format(time.RFC3339Nano)
	leaseID := "lease:sha256:" + digestHex(map[string]any{"task_id": taskID, "owner": owner, "task_digest": item["task_digest"], "lease_expires_at": leaseExpiresAt})
	extra := map[string]any{"origin_zone_descriptor": origin, "requester": requester, "task": task, "lease_owner": owner, "lease_id": leaseID, "lease_expires_at": leaseExpiresAt}
	copyQueueCarryFields(extra, item)
	if err := f.writeQueueItem(origin, worker, task, "claimed", extra); err != nil {
		return "", err
	}
	return leaseID, nil
}

func (f Fixture) drainQueueItem(send sendFunc, taskID, leaseID string) error {
	item, err := f.readQueueItem(taskID)
	if err != nil {
		return err
	}
	if optionalString(item["status"]) != "claimed" {
		return errors.New("queue item is not claimed: " + taskID)
	}
	if leaseID == "" || leaseID == "<nil>" || optionalString(item["lease_id"]) != leaseID {
		return errors.New("queue lease mismatch: " + taskID)
	}
	if queueLeaseExpired(item) {
		return errors.New("queue lease expired: " + taskID)
	}
	origin, _ := item["origin_zone_descriptor"].(map[string]any)
	requester, _ := item["requester"].(map[string]any)
	task, _ := item["task"].(map[string]any)
	worker, task, err := f.verifyTaskOpen(map[string]any{"type": "FED_TASK_OPEN", "origin_zone": origin, "requester": requester, "requester_zone_binding": item["requester_zone_binding"], "task": task})
	if err != nil {
		return err
	}
	extra := map[string]any{"origin_zone_descriptor": origin, "requester": requester, "task": task, "lease_owner": item["lease_owner"], "lease_id": item["lease_id"], "lease_expires_at": item["lease_expires_at"]}
	copyQueueCarryFields(extra, item)
	if err := f.writeQueueItem(origin, worker, task, "running", extra); err != nil {
		return err
	}
	var parentCheckpoint any
	restoredStateDigest := ""
	if checkpointID := optionalString(item["resume_checkpoint"]); checkpointID != "" {
		parent, err := f.checkpointByID(checkpointID)
		if err != nil {
			return err
		}
		parentCheckpoint = checkpointID
		restoredStateDigest = optionalString(parent["state_digest"])
	}
	err = f.executeTask(send, origin, worker, task, parentCheckpoint, restoredStateDigest, nil, true, nil, nil)
	if err == nil {
		if state, stateErr := f.readTaskState(taskID); stateErr == nil {
			extra["receipt_digest"] = state["receipt_digest"]
		}
		return f.writeQueueItem(origin, worker, task, "completed", extra)
	}
	if err != nil {
		if f.Runtime.WasCancelled(taskID) {
			if state, stateErr := f.readTaskState(taskID); stateErr == nil {
				extra["receipt_digest"] = state["receipt_digest"]
			}
			return f.writeQueueItem(origin, worker, task, "cancelled", extra)
		}
		if receiptErr := f.failTask(send, origin, worker, task, err); receiptErr != nil {
			err = fmt.Errorf("%v; failure receipt: %w", err, receiptErr)
		}
		if state, stateErr := f.readTaskState(taskID); stateErr == nil {
			extra["receipt_digest"] = state["receipt_digest"]
		}
		extra["error"] = err.Error()
		_ = f.writeQueueItem(origin, worker, task, "failed", extra)
		return err
	}
	return nil
}
