package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

const (
	taskStateTransitionFormat = "agnet-task-state-transition/v1"
	taskStateLockTimeout      = 5 * time.Second
	taskStateLockStaleAfter   = 30 * time.Second
)

func (f Fixture) writeTaskState(taskID, status string, worker *Worker, extra map[string]any) error {
	_, err := f.transitionTaskState(taskID, status, optionalString(worker.Descriptor["aid"]), extra)
	return err
}

func (f Fixture) readTaskState(taskID string) (map[string]any, error) {
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
			if err := appendTaskStateTransition(journalPath, genesis); err != nil {
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
	if !taskStateTransitionAllowed(from, next) {
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
	if err := appendTaskStateTransition(journalPath, transition); err != nil {
		return nil, err
	}
	transitions = append(transitions, transition)
	projection := projectTaskState(transitions)
	if err := writeJSONStateFile(taskStateProjectionPath(f.TaskStateDir, taskID), projection); err != nil {
		return nil, err
	}
	return projection, nil
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
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	transitions := []map[string]any{}
	previousState := ""
	previousHash := ""
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		var transition map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &transition); err != nil {
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
		if !taskStateTransitionAllowed(previousState, optionalString(transition["to"])) {
			return nil, errors.New("task state transition invalid")
		}
		transitions = append(transitions, transition)
		previousState = optionalString(transition["to"])
		previousHash = transitionHash
	}
	if err := scanner.Err(); err != nil {
		return nil, err
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

func appendTaskStateTransition(path string, transition map[string]any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	encoded, err := json.Marshal(transition)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(append(encoded, '\n')); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func acquireTaskStateLock(stateDir, taskID string) (func(), error) {
	lockRoot := filepath.Join(stateDir, ".task-state-locks")
	if err := os.MkdirAll(lockRoot, 0o700); err != nil {
		return nil, err
	}
	lockPath := filepath.Join(lockRoot, taskID+".lock")
	deadline := time.Now().Add(taskStateLockTimeout)
	for {
		if err := os.Mkdir(lockPath, 0o700); err == nil {
			return func() { _ = os.Remove(lockPath) }, nil
		} else if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		if info, err := os.Stat(lockPath); err == nil && time.Since(info.ModTime()) > taskStateLockStaleAfter {
			_ = os.Remove(lockPath)
			continue
		}
		if !time.Now().Before(deadline) {
			return nil, errors.New("task state lock timeout")
		}
		time.Sleep(5 * time.Millisecond)
	}
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
