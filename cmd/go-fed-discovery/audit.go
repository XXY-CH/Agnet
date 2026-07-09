package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func (f Fixture) auditProof(taskID string) (map[string]any, error) {
	if f.Audit == nil {
		return nil, errors.New("audit log unavailable")
	}
	entries, err := readAuditEntries(f.Audit.Path)
	if err != nil {
		return nil, err
	}
	// ponytail: linear scan is enough for local v4.5 proof; add an index when remote audit query has real volume.
	for _, entry := range entries {
		record, _ := entry["record"].(map[string]any)
		if record["kind"] != "go_fed_receipt" {
			continue
		}
		receipt, _ := record["receipt"].(map[string]any)
		if receipt["task_id"] == taskID {
			record["audit_hash"] = entry["hash"]
			return record, nil
		}
	}
	return nil, errors.New("audit proof not found: " + taskID)
}

func (f Fixture) countCompletedReceipts(workerAID string) (int, string, int, int, bool) {
	if f.Audit == nil || f.Audit.Path == "" {
		return 0, "", 0, 0, false
	}
	entries, err := readAuditEntries(f.Audit.Path)
	if err != nil {
		return 0, "", 0, 0, false
	}
	count := 0
	lastCompletedAt := ""
	var lastCompletedTime time.Time
	for _, entry := range entries {
		record, _ := entry["record"].(map[string]any)
		if record["kind"] != "go_fed_receipt" {
			continue
		}
		receipt, _ := record["receipt"].(map[string]any)
		if receipt["to"] != workerAID || receipt["status"] != "completed" {
			continue
		}
		count++
		if completedAt := receiptTimestamp(record, receipt); completedAt != "" {
			completedTime, err := time.Parse(time.RFC3339Nano, completedAt)
			if err == nil && (lastCompletedAt == "" || completedTime.After(lastCompletedTime)) {
				lastCompletedAt = completedAt
				lastCompletedTime = completedTime
			}
		}
		if count >= 1000 {
			break
		}
	}
	availabilityStarted := 0
	availabilityCompleted := 0
	availabilityHasAuditData := false
	lastEntries := entries
	if len(lastEntries) > 50 {
		lastEntries = lastEntries[len(lastEntries)-50:]
	}
	for _, entry := range lastEntries {
		record, _ := entry["record"].(map[string]any)
		if !auditRecordForWorker(record, workerAID) {
			continue
		}
		if auditRecordIsStarted(record) {
			availabilityStarted++
		}
		if auditRecordIsCompleted(record) {
			availabilityCompleted++
		}
		availabilityHasAuditData = true
	}
	return count, lastCompletedAt, availabilityStarted, availabilityCompleted, availabilityHasAuditData
}

func auditRecordForWorker(record map[string]any, workerAID string) bool {
	switch optionalString(record["kind"]) {
	case "go_fed_receipt":
		receipt, _ := record["receipt"].(map[string]any)
		return optionalString(receipt["to"]) == workerAID
	case "go_fed_event":
		event, _ := record["event"].(map[string]any)
		return optionalString(event["by"]) == workerAID
	default:
		return false
	}
}

func auditRecordIsStarted(record map[string]any) bool {
	if optionalString(record["kind"]) != "go_fed_event" {
		return false
	}
	event, _ := record["event"].(map[string]any)
	return optionalString(event["type"]) == "task.started"
}

func auditRecordIsCompleted(record map[string]any) bool {
	switch optionalString(record["kind"]) {
	case "go_fed_receipt":
		receipt, _ := record["receipt"].(map[string]any)
		return optionalString(receipt["status"]) == "completed"
	case "go_fed_event":
		event, _ := record["event"].(map[string]any)
		return optionalString(event["type"]) == "task.completed"
	default:
		return false
	}
}

func receiptTimestamp(record, receipt map[string]any) string {
	for _, key := range []string{"completed_at", "timestamp"} {
		if value := optionalString(record[key]); value != "" {
			return value
		}
		if value := optionalString(receipt[key]); value != "" {
			return value
		}
	}
	return ""
}

func (f Fixture) artifactReadProof(taskID, uri string) (map[string]any, error) {
	if taskID == "" || uri == "" {
		return nil, errors.New("artifact read task_id and uri required")
	}
	record, err := f.auditProof(taskID)
	if err != nil {
		return nil, err
	}
	receipt, _ := record["receipt"].(map[string]any)
	manifest, err := receiptArtifactManifest(receipt, uri)
	if err != nil {
		return nil, err
	}
	if err := verifyArtifactManifests(receipt, f.ArtifactStoreDir); err != nil {
		return nil, err
	}
	path, err := localArtifactPath(uri)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"type":           "FED_ARTIFACT",
		"task_id":        taskID,
		"uri":            uri,
		"audit_hash":     record["audit_hash"],
		"receipt_digest": digestHex(receipt),
		"manifest":       manifest,
		"bytes_b64":      base64.RawURLEncoding.EncodeToString(data),
	}, nil
}

func (f Fixture) requireCheckpoint(checkpointID string) error {
	_, err := f.checkpointByID(checkpointID)
	return err
}

func (f Fixture) checkpointByID(checkpointID string) (map[string]any, error) {
	if f.Audit == nil {
		return nil, errors.New("audit log unavailable")
	}
	entries, err := readAuditEntries(f.Audit.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("resume checkpoint not found: " + checkpointID)
	}
	if err != nil {
		return nil, err
	}
	// ponytail: linear scan keeps resume evidence honest; add an index when checkpoint lookup has real volume.
	for _, entry := range entries {
		record, _ := entry["record"].(map[string]any)
		event, _ := record["event"].(map[string]any)
		checkpoint, _ := event["checkpoint"].(map[string]any)
		if checkpoint["checkpoint_id"] == checkpointID {
			return checkpoint, nil
		}
		receipt, _ := record["receipt"].(map[string]any)
		if _, err := receiptCheckpointRefs(receipt["checkpoint_refs"]); err != nil {
			return nil, err
		}
		checkpoints, err := receiptCheckpoints(receipt["checkpoints"])
		if err != nil {
			return nil, err
		}
		for _, checkpoint := range checkpoints {
			if checkpoint["checkpoint_id"] == checkpointID {
				return checkpoint, nil
			}
		}
	}
	return nil, errors.New("resume checkpoint not found: " + checkpointID)
}

func (f Fixture) sendTaskEvent(send sendFunc, event map[string]any) error {
	if err := f.appendAudit(map[string]any{"kind": "go_fed_event", "event": event}); err != nil {
		return err
	}
	send(map[string]any{"type": "FED_TASK_EVENT", "event": event})
	return nil
}

func (f Fixture) appendAudit(record map[string]any) error {
	if f.Audit == nil {
		return nil
	}
	return f.Audit.Append(record)
}

func writeJSONStateFile(path string, body any) error {
	data, err := json.MarshalIndent(body, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(path, append(data, '\n'), 0o644)
}

func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return err
	}
	tempPath := file.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tempPath)
		}
	}()
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Chmod(perm); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	if dirFile, err := os.Open(dir); err == nil {
		_ = dirFile.Sync()
		_ = dirFile.Close()
	}
	cleanup = false
	return nil
}

func writeArtifact(uri, text, artifactStoreDir string) (map[string]any, error) {
	return writeArtifactBytes(uri, []byte(text), "text/markdown; charset=utf-8", artifactStoreDir)
}

func writeArtifactBytes(uri string, data []byte, mediaType, artifactStoreDir string) (map[string]any, error) {
	path, err := localArtifactPath(uri)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return nil, err
	}
	sha := digestBytesHex(data)
	body := map[string]any{
		"uri":        uri,
		"sha256":     sha,
		"size":       float64(len(data)),
		"media_type": mediaType,
	}
	body["afp"] = "afp:sha256:" + sha
	body["manifest_hash"] = digestHex(body)
	sidecar, err := json.MarshalIndent(body, "", "  ")
	if err != nil {
		return nil, err
	}
	sidecar = append(sidecar, '\n')
	if err := os.WriteFile(path+".manifest.json", sidecar, 0o644); err != nil {
		return nil, err
	}
	digestRoots := []string{"artifacts"}
	if artifactStoreDir != "" {
		digestRoots = append(digestRoots, artifactStoreDir)
	}
	for _, root := range digestRoots {
		digestPath := filepath.Join(root, "by-sha256", sha)
		if err := os.MkdirAll(filepath.Dir(digestPath), 0o755); err != nil {
			return nil, err
		}
		if err := os.WriteFile(digestPath, data, 0o644); err != nil {
			return nil, err
		}
		if err := os.WriteFile(digestPath+".manifest.json", sidecar, 0o644); err != nil {
			return nil, err
		}
		if root == artifactStoreDir {
			if err := appendArtifactStoreIndex(root, body); err != nil {
				return nil, err
			}
		}
	}
	return body, nil
}

func appendArtifactStoreIndex(root string, manifest map[string]any) error {
	if root == "" {
		return nil
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return err
	}
	file, err := os.OpenFile(filepath.Join(root, "objects.ndjson"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()
	return json.NewEncoder(file).Encode(map[string]any{
		"uri":           manifest["uri"],
		"sha256":        manifest["sha256"],
		"size":          manifest["size"],
		"media_type":    manifest["media_type"],
		"afp":           manifest["afp"],
		"manifest_hash": manifest["manifest_hash"],
	})
}

func localArtifactPath(uri string) (string, error) {
	const prefix = "artifact://local/"
	if !strings.HasPrefix(uri, prefix) {
		return "", errors.New("unsupported artifact uri: " + uri)
	}
	raw := strings.TrimPrefix(uri, prefix)
	normalized := strings.ReplaceAll(raw, "\\", "/")
	if normalized == "" || strings.HasPrefix(normalized, "/") {
		return "", errors.New("invalid artifact uri path: " + uri)
	}
	parts := strings.Split(normalized, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return "", errors.New("invalid artifact uri path: " + uri)
		}
	}
	return filepath.Join(append([]string{"artifacts"}, parts...)...), nil
}

const auditZeroHash = "0000000000000000000000000000000000000000000000000000000000000000"

func openAuditLog(path string) (*AuditLog, error) {
	audit := &AuditLog{Path: path, Head: auditZeroHash}
	entries, err := readAuditEntries(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return audit, nil
		}
		return nil, err
	}
	head, err := auditHead(entries)
	if err != nil {
		return nil, err
	}
	audit.Head = head
	return audit, nil
}

func (a *AuditLog) Append(record map[string]any) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(a.Path), 0o755); err != nil {
		return err
	}
	lock, err := os.OpenFile(a.Path+".lock", os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	entries, err := readAuditEntries(a.Path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	} else {
		head, err := auditHead(entries)
		if err != nil {
			return err
		}
		a.Head = head
	}
	entry, err := auditEntry(a.Head, record)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(a.Path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(file, string(data)); err != nil {
		return err
	}
	a.Head = fmt.Sprint(entry["hash"])
	return nil
}

func auditHead(entries []map[string]any) (string, error) {
	prev := auditZeroHash
	for _, entry := range entries {
		if err := verifyAuditEntry(entry, prev); err != nil {
			return "", err
		}
		prev = fmt.Sprint(entry["hash"])
	}
	return prev, nil
}

func verifyAuditFile(path, artifactStoreDir string) error {
	entries, err := readAuditEntries(path)
	if err != nil {
		return err
	}
	prev := auditZeroHash
	swarmManifests := map[string]map[string]any{}
	swarmOrder := map[string][]string{}
	closedSwarms := map[string]bool{}
	for _, entry := range entries {
		if err := verifyAuditEntry(entry, prev); err != nil {
			return err
		}
		record, ok := entry["record"].(map[string]any)
		if !ok {
			return errors.New("audit record missing")
		}
		if record["kind"] == "go_fed_receipt" {
			if err := verifyReceiptRecord(record, artifactStoreDir); err != nil {
				return err
			}
			receipt, _ := record["receipt"].(map[string]any)
			if err := verifySwarmReceiptDependencies(receipt, swarmManifests, swarmOrder); err != nil {
				return err
			}
		}
		if record["kind"] == "go_swarm_close" {
			if err := verifySwarmCloseProof(record, swarmManifests, swarmOrder, closedSwarms); err != nil {
				return err
			}
		}
		prev = fmt.Sprint(entry["hash"])
	}
	return nil
}

func verifyReceiptFile(path, artifactStoreDir string, taskPath ...string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var record map[string]any
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, err
	}
	var tasks []map[string]any
	if len(taskPath) > 0 && taskPath[0] != "" {
		taskData, err := os.ReadFile(taskPath[0])
		if err != nil {
			return nil, err
		}
		var task map[string]any
		if err := json.Unmarshal(taskData, &task); err != nil {
			return nil, err
		}
		tasks = append(tasks, task)
	}
	if err := verifyReceiptRecord(record, artifactStoreDir, tasks...); err != nil {
		return nil, err
	}
	receipt, _ := record["receipt"].(map[string]any)
	return map[string]any{"go_receipt_verify": "ok", "task_id": receipt["task_id"]}, nil
}

func planArtifactStoreGC(auditPath, artifactStoreDir string) (map[string]any, error) {
	if artifactStoreDir == "" {
		return nil, errors.New("artifact-store is required for gc plan")
	}
	if err := verifyAuditFile(auditPath, artifactStoreDir); err != nil {
		return nil, err
	}
	entries, err := readAuditEntries(auditPath)
	if err != nil {
		return nil, err
	}
	referenced := map[string]bool{}
	for _, entry := range entries {
		record, _ := entry["record"].(map[string]any)
		if record["kind"] != "go_fed_receipt" {
			continue
		}
		receipt, _ := record["receipt"].(map[string]any)
		for _, manifest := range mapsFromAny(receipt["artifact_manifests"]) {
			referenced[fmt.Sprint(manifest["sha256"])] = true
		}
	}
	index, err := readArtifactStoreIndex(filepath.Join(artifactStoreDir, "objects.ndjson"))
	if err != nil {
		return nil, err
	}
	var orphans []map[string]any
	for _, entry := range index {
		if !referenced[fmt.Sprint(entry["sha256"])] {
			orphans = append(orphans, entry)
		}
	}
	return map[string]any{"artifact_store_gc_plan": "ok", "orphans": orphans}, nil
}

func applyArtifactStoreGC(auditPath, artifactStoreDir string) (map[string]any, error) {
	plan, err := planArtifactStoreGC(auditPath, artifactStoreDir)
	if err != nil {
		return nil, err
	}
	orphans := mapsFromAny(plan["orphans"])
	var deleted []map[string]any
	for _, orphan := range orphans {
		sha := fmt.Sprint(orphan["sha256"])
		if sha == "" {
			continue
		}
		path := filepath.Join(artifactStoreDir, "by-sha256", sha)
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if err := os.Remove(path + ".manifest.json"); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		deleted = append(deleted, orphan)
	}
	return map[string]any{"artifact_store_gc_apply": "ok", "deleted": deleted}, nil
}

func readAuditEntries(path string) ([]map[string]any, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	out := []map[string]any{}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			return nil, err
		}
		out = append(out, entry)
	}
	if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return out, nil
}

func verifyAuditEntry(entry map[string]any, prev string) error {
	record, ok := entry["record"].(map[string]any)
	if !ok {
		return errors.New("audit record missing")
	}
	if entry["prev_hash"] != prev {
		return errors.New("audit prev_hash mismatch")
	}
	expected, err := auditEntry(prev, record)
	if err != nil {
		return err
	}
	if entry["hash"] != expected["hash"] {
		return errors.New("audit hash mismatch")
	}
	return nil
}

func auditEntry(prev string, record map[string]any) (map[string]any, error) {
	body := map[string]any{"prev_hash": prev, "record": record}
	data, err := canonicalJSON(body)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(data)
	return map[string]any{"prev_hash": prev, "record": record, "hash": hex.EncodeToString(hash[:])}, nil
}
