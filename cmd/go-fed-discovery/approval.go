package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

func (f Fixture) writeTaskState(taskID, status string, worker *Worker, extra map[string]any) error {
	if f.TaskStateDir == "" {
		return nil
	}
	body := map[string]any{
		"task_id": taskID,
		"status":  status,
		"worker":  worker.Descriptor["aid"],
	}
	for key, value := range extra {
		body[key] = value
	}
	// ponytail: one JSON file per task; replace with an indexed store when scheduling needs queries.
	return writeJSONStateFile(filepath.Join(f.TaskStateDir, url.PathEscape(taskID)+".json"), body)
}

func approvalExpiresAt(task map[string]any) string {
	if expiresAt := optionalString(task["approval_expires_at"]); expiresAt != "" {
		return expiresAt
	}
	return time.Now().Add(60 * time.Second).UTC().Format(time.RFC3339Nano)
}

func (f Fixture) writeApprovalState(taskID, status string, reasons []string, by string, approval map[string]any, expiresAt string) error {
	if f.ApprovalDir == "" {
		return nil
	}
	body := map[string]any{
		"task_id": taskID,
		"status":  status,
		"reasons": stringsAny(reasons),
	}
	if expiresAt != "" {
		body["expires_at"] = expiresAt
	}
	if by != "" {
		body["by"] = by
	}
	if approval != nil {
		body["approval"] = approval
	}
	return writeJSONStateFile(filepath.Join(f.ApprovalDir, url.PathEscape(taskID)+".json"), body)
}

func (f Fixture) readApprovalState(taskID string) (map[string]any, error) {
	if f.ApprovalDir == "" {
		return nil, errors.New("approval state unavailable")
	}
	data, err := os.ReadFile(filepath.Join(f.ApprovalDir, url.PathEscape(taskID)+".json"))
	if err != nil {
		return nil, err
	}
	var state map[string]any
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	return state, nil
}

func (f Fixture) applyApprovalAction(taskID, actor, action string) (map[string]any, error) {
	approvalStateMu.Lock()
	defer approvalStateMu.Unlock()
	state, err := f.readApprovalState(taskID)
	if err != nil {
		return nil, err
	}
	if optionalString(state["status"]) != "pending" {
		return nil, errors.New("approval is not pending: " + taskID)
	}
	reasons := stringsFromAny(state["reasons"])
	expiresAt := optionalString(state["expires_at"])
	if approvalExpired(expiresAt) {
		if err := f.writeApprovalState(taskID, "expired", reasons, "", nil, expiresAt); err != nil {
			return nil, err
		}
		return nil, errors.New("approval expired: " + taskID)
	}
	if action == "deny" {
		if err := f.writeApprovalState(taskID, "denied", reasons, actor, nil, expiresAt); err != nil {
			return nil, err
		}
		return map[string]any{"task_id": taskID, "status": "denied", "by": actor, "reasons": stringsAny(reasons), "expires_at": expiresAt}, nil
	}
	grant := f.approvalGrant(taskID, reasons, actor)
	if err := f.writeApprovalState(taskID, "approved", reasons, actor, grant, expiresAt); err != nil {
		return nil, err
	}
	return grant, nil
}

func approvalExpired(expiresAt string) bool {
	if expiresAt == "" {
		return false
	}
	parsed, err := time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil {
		return true
	}
	return !time.Now().UTC().Before(parsed)
}

func (f Fixture) waitForApproval(ctx context.Context, taskID string) (map[string]any, error) {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		state, err := f.readApprovalState(taskID)
		if err == nil {
			switch optionalString(state["status"]) {
			case "approved":
				approval, _ := state["approval"].(map[string]any)
				if approval == nil {
					return nil, errors.New("approved task missing approval grant: " + taskID)
				}
				return approval, nil
			case "denied":
				return nil, errors.New("approval denied: " + taskID)
			case "pending":
				if approvalExpired(optionalString(state["expires_at"])) {
					approvalStateMu.Lock()
					if writeErr := f.writeApprovalState(taskID, "expired", stringsFromAny(state["reasons"]), "", nil, optionalString(state["expires_at"])); writeErr != nil {
						approvalStateMu.Unlock()
						return nil, writeErr
					}
					approvalStateMu.Unlock()
					return nil, errors.New("approval expired: " + taskID)
				}
			case "expired":
				return nil, errors.New("approval expired: " + taskID)
			}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}
