package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const taskStateTransitionFormat = "agnet-task-state-transition/v1"

type taskStateFaultPoint string

const (
	taskStateFaultWrite        taskStateFaultPoint = "write"
	taskStateFaultFileSync     taskStateFaultPoint = "file_sync"
	taskStateFaultParentSync   taskStateFaultPoint = "parent_sync"
	taskStateFaultTruncate     taskStateFaultPoint = "truncate"
	taskStateFaultRollbackSync taskStateFaultPoint = "rollback_sync"
)

type taskStateFaultInjector func(taskStateFaultPoint, map[string]any) error

func (f Fixture) writeTaskState(taskID, status string, worker *Worker, extra map[string]any) error {
	_, err := f.transitionTaskState(taskID, status, optionalString(worker.Descriptor["aid"]), extra)
	return err
}

func (f Fixture) readTaskState(taskID string) (map[string]any, error) {
	release, err := acquireTaskStateLock(f.TaskStateDir, taskID)
	if err != nil {
		return nil, err
	}
	defer release()
	transitions, err := readTaskStateTransitions(taskStateJournalPath(f.TaskStateDir, taskID))
	if err == nil && len(transitions) > 0 {
		return projectTaskState(transitions), nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return readTaskStateProjection(taskStateProjectionPath(f.TaskStateDir, taskID))
}

func (f Fixture) transitionTaskState(taskID, next, worker string, extra map[string]any) (map[string]any, error) {
	if f.TaskStateDir == "" {
		return nil, errors.New("task state unavailable")
	}
	release, err := acquireTaskStateLock(f.TaskStateDir, taskID)
	if err != nil {
		return nil, err
	}
	defer release()

	journalPath := taskStateJournalPath(f.TaskStateDir, taskID)
	transitions, err := readTaskStateTransitions(journalPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	current := map[string]any{"task_id": taskID, "status": "", "revision": float64(0), "state_hash": ""}
	if len(transitions) > 0 {
		current = projectTaskState(transitions)
	} else {
		legacy, legacyErr := readTaskStateProjection(taskStateProjectionPath(f.TaskStateDir, taskID))
		if legacyErr == nil {
			legacyStatus := optionalString(legacy["status"])
			if optionalString(legacy["task_id"]) != taskID || legacyStatus == "" || !taskStateTransitionAllowed("", legacyStatus) {
				return nil, errors.New("legacy task state invalid")
			}
			legacyExtra := map[string]any{}
			for key, value := range legacy {
				switch key {
				case "task_id", "status", "revision", "state_hash", "worker":
					continue
				}
				legacyExtra[key] = value
			}
			genesis := map[string]any{
				"format":                  taskStateTransitionFormat,
				"task_id":                 taskID,
				"revision":                float64(1),
				"from":                    "",
				"to":                      legacyStatus,
				"worker":                  legacy["worker"],
				"extra":                   legacyExtra,
				"previous_hash":           "",
				"migration_source_digest": digestHex(legacy),
				"recorded_at":             time.Now().UTC().Format(time.RFC3339Nano),
			}
			genesis["transition_hash"] = digestHex(genesis)
			if err := f.appendTaskStateTransition(journalPath, genesis); err != nil {
				return nil, err
			}
			transitions = append(transitions, genesis)
			current = projectTaskState(transitions)
			if err := writeJSONStateFile(taskStateProjectionPath(f.TaskStateDir, taskID), current); err != nil {
				return nil, err
			}
		} else if !errors.Is(legacyErr, os.ErrNotExist) {
			return nil, legacyErr
		}
	}
	from := optionalString(current["status"])
	if from == next {
		unchanged := true
		for key, value := range extra {
			if digestHex(current[key]) != digestHex(value) {
				unchanged = false
				break
			}
		}
		if unchanged {
			return current, nil
		}
	}
	if !taskStateTransitionAllowedForProjection(current, next, extra) {
		return nil, errors.New("task state transition invalid: " + from + " -> " + next)
	}
	revision := intFromMap(current, "revision") + 1
	transition := map[string]any{
		"format":        taskStateTransitionFormat,
		"task_id":       taskID,
		"revision":      float64(revision),
		"from":          from,
		"to":            next,
		"worker":        worker,
		"extra":         extra,
		"previous_hash": optionalString(current["state_hash"]),
		"recorded_at":   time.Now().UTC().Format(time.RFC3339Nano),
	}
	transition["transition_hash"] = digestHex(transition)
	if err := f.appendTaskStateTransition(journalPath, transition); err != nil {
		return nil, err
	}
	transitions = append(transitions, transition)
	projection := projectTaskState(transitions)
	if err := writeJSONStateFile(taskStateProjectionPath(f.TaskStateDir, taskID), projection); err != nil {
		return nil, err
	}
	return projection, nil
}

func taskStateTransitionAllowedForProjection(current map[string]any, to string, extra map[string]any) bool {
	from := optionalString(current["status"])
	if taskStateTransitionAllowed(from, to) {
		return true
	}
	if from != "claimed" || to != "claimed" || optionalString(current["lease_owner"]) != "product://local" || optionalString(extra["lease_owner"]) != "product://local" {
		return false
	}
	oldLeaseID := optionalString(current["lease_id"])
	newLeaseID := optionalString(extra["lease_id"])
	if oldLeaseID == "" || newLeaseID == "" || oldLeaseID == newLeaseID {
		return false
	}
	if _, err := time.Parse(time.RFC3339Nano, optionalString(extra["lease_expires_at"])); err != nil {
		return false
	}
	if len(extra) != 3 {
		return false
	}
	return true
}

func taskStateTransitionAllowed(from, to string) bool {
	if from == to && (to == "failed" || to == "completed" || to == "cancelled") {
		return true
	}
	if from == "" {
		switch to {
		case "queued", "claimed", "running", "completing", "cancelling", "failing", "completed", "cancelled", "failed":
			return true
		}
	}
	switch from {
	case "queued":
		return to == "claimed" || to == "running" || to == "cancelling" || to == "failing" || to == "failed"
	case "claimed":
		return to == "running" || to == "cancelling" || to == "failing" || to == "failed"
	case "running":
		return to == "completing" || to == "cancelling" || to == "failing" || to == "failed"
	case "completing":
		return to == "completed" || to == "failing" || to == "failed"
	case "cancelling":
		return to == "cancelled" || to == "failed"
	case "failing":
		return to == "failed"
	}
	return false
}

func readTaskStateTransitions(path string) ([]map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	verifiedEnd := len(data)
	unterminated := len(data) > 0 && data[len(data)-1] != '\n'
	if unterminated {
		verifiedEnd = bytes.LastIndexByte(data, '\n') + 1
	}
	complete := data[:verifiedEnd]
	lines := bytes.Split(complete, []byte{'\n'})
	transitions := make([]map[string]any, 0, len(lines))
	previousState := ""
	previousHash := ""
	current := map[string]any{"status": ""}
	for index, line := range lines {
		if len(line) == 0 {
			if index == len(lines)-1 {
				continue
			}
			return nil, errors.New("task state journal invalid")
		}
		var transition map[string]any
		if err := json.Unmarshal(line, &transition); err != nil {
			return nil, errors.New("task state journal invalid")
		}
		if transition["format"] != taskStateTransitionFormat || optionalString(transition["task_id"]) == "" {
			return nil, errors.New("task state transition invalid")
		}
		if intFromMap(transition, "revision") != len(transitions)+1 || optionalString(transition["from"]) != previousState || optionalString(transition["previous_hash"]) != previousHash {
			return nil, errors.New("task state transition chain invalid")
		}
		transitionHash := optionalString(transition["transition_hash"])
		body := map[string]any{}
		for key, value := range transition {
			if key != "transition_hash" {
				body[key] = value
			}
		}
		if transitionHash == "" || digestHex(body) != transitionHash {
			return nil, errors.New("task state transition hash invalid")
		}
		extra, ok := transition["extra"].(map[string]any)
		if !ok || !taskStateTransitionAllowedForProjection(current, optionalString(transition["to"]), extra) {
			return nil, errors.New("task state transition invalid")
		}
		transitions = append(transitions, transition)
		current["status"] = transition["to"]
		for key, value := range extra {
			current[key] = value
		}
		previousState = optionalString(transition["to"])
		previousHash = transitionHash
	}
	if unterminated {
		file, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			return nil, err
		}
		if err := file.Truncate(int64(verifiedEnd)); err != nil {
			_ = file.Close()
			return nil, err
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			return nil, err
		}
		if err := file.Close(); err != nil {
			return nil, err
		}
	}
	return transitions, nil
}

func projectTaskState(transitions []map[string]any) map[string]any {
	projection := map[string]any{}
	for _, transition := range transitions {
		projection["task_id"] = transition["task_id"]
		projection["status"] = transition["to"]
		projection["worker"] = transition["worker"]
		projection["revision"] = transition["revision"]
		projection["state_hash"] = transition["transition_hash"]
		extra, _ := transition["extra"].(map[string]any)
		for key, value := range extra {
			projection[key] = value
		}
	}
	return projection
}

func (f Fixture) injectTaskStateFault(point taskStateFaultPoint, transition map[string]any) error {
	if f.taskStateFault == nil {
		return nil
	}
	return f.taskStateFault(point, transition)
}

func (f Fixture) appendTaskStateTransition(path string, transition map[string]any) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	created := false
	if _, err := os.Stat(path); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		created = true
	}
	encoded, err := json.Marshal(transition)
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			_ = file.Close()
		}
	}()
	priorOffset, err := file.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}
	rollback := func(cause error) error {
		var rollbackErr error
		if faultErr := f.injectTaskStateFault(taskStateFaultTruncate, transition); faultErr != nil {
			rollbackErr = fmt.Errorf("truncate task state append: %w", faultErr)
		} else if truncateErr := file.Truncate(priorOffset); truncateErr != nil {
			rollbackErr = fmt.Errorf("truncate task state append: %w", truncateErr)
		}
		if faultErr := f.injectTaskStateFault(taskStateFaultRollbackSync, transition); faultErr != nil {
			rollbackErr = errors.Join(rollbackErr, fmt.Errorf("sync task state rollback: %w", faultErr))
		} else if syncErr := file.Sync(); syncErr != nil {
			rollbackErr = errors.Join(rollbackErr, fmt.Errorf("sync task state rollback: %w", syncErr))
		}
		if closeErr := file.Close(); closeErr != nil {
			rollbackErr = errors.Join(rollbackErr, fmt.Errorf("close task state rollback: %w", closeErr))
		}
		closed = true
		if created {
			if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				rollbackErr = errors.Join(rollbackErr, fmt.Errorf("remove failed task state journal: %w", removeErr))
			}
		}
		return errors.Join(cause, rollbackErr)
	}
	if err := f.injectTaskStateFault(taskStateFaultWrite, transition); err != nil {
		return rollback(err)
	}
	written, err := file.Write(encoded)
	if err == nil && written != len(encoded) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return rollback(fmt.Errorf("write task state transition: %w", err))
	}
	if err := f.injectTaskStateFault(taskStateFaultFileSync, transition); err != nil {
		return rollback(err)
	}
	if err := file.Sync(); err != nil {
		return rollback(fmt.Errorf("sync task state journal: %w", err))
	}
	if created {
		parent, err := os.Open(dir)
		if err != nil {
			return rollback(fmt.Errorf("open task state parent directory: %w", err))
		}
		err = f.injectTaskStateFault(taskStateFaultParentSync, transition)
		if err == nil {
			err = parent.Sync()
		}
		if err != nil {
			closeErr := parent.Close()
			return rollback(errors.Join(fmt.Errorf("sync task state parent directory: %w", err), closeErr))
		}
		if err := parent.Close(); err != nil {
			return rollback(fmt.Errorf("close task state parent directory: %w", err))
		}
	}
	if err := file.Close(); err != nil {
		closed = true
		return fmt.Errorf("close task state journal: %w", err)
	}
	closed = true
	return nil
}

func acquireTaskStateLock(stateDir, taskID string) (func(), error) {
	lockRoot := filepath.Join(stateDir, ".task-state-locks")
	if err := os.MkdirAll(lockRoot, 0o700); err != nil {
		return nil, err
	}
	return acquireUnixFileLock(filepath.Join(lockRoot, taskID+".lock"))
}

func taskStateJournalPath(stateDir, taskID string) string {
	return filepath.Join(stateDir, taskID+".journal.jsonl")
}

func taskStateProjectionPath(stateDir, taskID string) string {
	return filepath.Join(stateDir, taskID+".json")
}

func readTaskStateProjection(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var state map[string]any
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	return state, nil
}
