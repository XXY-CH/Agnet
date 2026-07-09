package main

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func serveHumanGateway(listener net.Listener, auditPath string, fixture Fixture, humanToken string, listenHost string) {
	taskStateDir := taskStateDirForAudit(auditPath)
	queueDir := queueDirForAudit(auditPath)
	approvalDir := approvalDirForAudit(auditPath)
	mux := http.NewServeMux()
	requireWriteToken := func(w http.ResponseWriter, r *http.Request) bool {
		if humanToken == "" {
			return true
		}
		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			http.Error(w, "human gateway token required", http.StatusUnauthorized)
			return false
		}
		got := strings.TrimPrefix(header, "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(humanToken)) != 1 {
			http.Error(w, "human gateway token required", http.StatusUnauthorized)
			return false
		}
		return true
	}
	runQueueAction := func(action map[string]any) (map[string]any, int, error) {
		if err := fixture.requireQueueActionGrant(action); err != nil {
			if auditErr := fixture.recordQueueAction(action, nil, err); auditErr != nil {
				return nil, http.StatusInternalServerError, auditErr
			}
			return nil, http.StatusBadRequest, err
		}
		result, err := fixture.applyQueueAction(action)
		if err != nil {
			if auditErr := fixture.recordQueueAction(action, nil, err); auditErr != nil {
				return nil, http.StatusInternalServerError, auditErr
			}
			return nil, http.StatusBadRequest, err
		}
		if err := fixture.recordQueueAction(action, result, nil); err != nil {
			return nil, http.StatusInternalServerError, err
		}
		return result, http.StatusOK, nil
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		entries, err := readAuditEntriesOrEmpty(auditPath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		tasks, err := readTaskStates(taskStateDir)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		queue, err := readTaskStates(queueDir)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		approvals, err := readTaskStates(approvalDir)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		rebindings, err := readRequesterRebindingHistory()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		requesterRegistry, err := readRequesterRegistry()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprint(w, renderHumanGateway(entries, tasks, queue, approvals, rebindings, requesterRegistryAgents(requesterRegistry)))
	})
	mux.HandleFunc("/api/audit", func(w http.ResponseWriter, r *http.Request) {
		if taskID := r.URL.Query().Get("task_id"); taskID != "" {
			record, err := fixture.auditProof(taskID)
			if err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"zone":         record["zone"],
				"worker":       record["worker"],
				"zone_binding": record["zone_binding"],
				"receipt":      record["receipt"],
				"audit_hash":   record["audit_hash"],
				"task_id":      taskID,
			})
			return
		}
		entries, err := readAuditEntriesOrEmpty(auditPath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"entries": entries})
	})
	mux.HandleFunc("/api/tasks", func(w http.ResponseWriter, r *http.Request) {
		tasks, err := readTaskStates(taskStateDir)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"tasks": tasks})
	})
	mux.HandleFunc("/api/queue", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		queue, err := readTaskStates(queueDir)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"queue": queue})
	})
	mux.HandleFunc("/api/security", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"listen_host":          listenHost,
			"write_token_required": humanToken != "",
			"public_transport":     isPublicListenHost(listenHost),
		})
	})
	mux.HandleFunc("/api/session", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		actor := fixture.approvalSessionActor(r)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"authenticated":        actor != "",
			"approval_actor":       actor,
			"approval_actions":     fixture.approvalActionsFor(actor),
			"write_token_required": humanToken != "",
		})
	})
	mux.HandleFunc("/api/approvals", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		approvals, err := readTaskStates(approvalDir)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"approvals": approvals})
	})
	mux.HandleFunc("/api/approvals/actions", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !requireWriteToken(w, r) {
			return
		}
		var action map[string]any
		if err := json.NewDecoder(r.Body).Decode(&action); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		actionName := optionalString(action["action"])
		if actionName != "approve" && actionName != "deny" {
			http.Error(w, "unsupported approval action", http.StatusBadRequest)
			return
		}
		taskID := optionalString(action["task_id"])
		actor := optionalString(action["actor"])
		sessionActor := fixture.approvalSessionActor(r)
		if actor != "" && sessionActor != "" && actor != sessionActor {
			http.Error(w, "approval actor session mismatch", http.StatusBadRequest)
			return
		}
		if actor == "" {
			actor = sessionActor
		}
		if taskID == "" || actor == "" || !strings.HasPrefix(actor, "human://") {
			http.Error(w, "approval task_id and human actor required", http.StatusBadRequest)
			return
		}
		if !fixture.approvalActorAllowed(actor, actionName) {
			http.Error(w, "approval actor policy denied", http.StatusBadRequest)
			return
		}
		approval, err := fixture.applyApprovalAction(taskID, actor, actionName)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "approval": approval})
	})
	mux.HandleFunc("/api/requester/registry", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		registry, err := readRequesterRegistry()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(registry)
	})
	mux.HandleFunc("/api/queue/actions", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !requireWriteToken(w, r) {
			return
		}
		var action map[string]any
		if err := json.NewDecoder(r.Body).Decode(&action); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		result, status, err := runQueueAction(action)
		if err != nil {
			http.Error(w, err.Error(), status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(result)
	})
	mux.HandleFunc("/api/queue/drafts", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !requireWriteToken(w, r) {
			return
		}
		var draft map[string]any
		if err := json.NewDecoder(r.Body).Decode(&draft); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if requester, ok := draft["requester"].(map[string]any); ok {
			signedTask, ok := draft["task"].(map[string]any)
			if !ok {
				http.Error(w, "external draft task is required", http.StatusBadRequest)
				return
			}
			taskID := optionalString(signedTask["task_id"])
			if taskID == "" {
				http.Error(w, "external draft task_id is required", http.StatusBadRequest)
				return
			}
			action := map[string]any{
				"action":                 "enqueue",
				"origin_zone":            fixture.Authority,
				"requester":              requester,
				"requester_zone_binding": fixture.zoneBindingForDescriptor(requester),
				"task":                   signedTask,
				"actor":                  "human://local",
				"action_grant":           fixture.queueActionGrant("enqueue", taskID, signedTask),
			}
			result, status, err := runQueueAction(action)
			if err != nil {
				http.Error(w, err.Error(), status)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "requester": requester, "task": signedTask, "enqueue": result})
			return
		}
		taskID := optionalString(draft["task_id"])
		to := optionalString(draft["to"])
		intent := optionalString(draft["intent"])
		if taskID == "" || to == "" || intent == "" {
			http.Error(w, "draft task_id, to, and intent are required", http.StatusBadRequest)
			return
		}
		requester, err := fixture.humanGatewayRequester()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		task := map[string]any{
			"task_id": taskID,
			"from":    requester["aid"],
			"to":      to,
			"intent":  intent,
			"scope":   draft["scope"],
			"budget":  draft["budget"],
		}
		signedTask := signBody(fixture.AuthorityPrivateKey, task)
		action := map[string]any{
			"action":                 "enqueue",
			"origin_zone":            fixture.Authority,
			"requester":              requester,
			"requester_zone_binding": fixture.zoneBindingForDescriptor(requester),
			"task":                   signedTask,
			"actor":                  "human://local",
			"action_grant":           fixture.queueActionGrant("enqueue", taskID, signedTask),
		}
		result, status, err := runQueueAction(action)
		if err != nil {
			http.Error(w, err.Error(), status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "requester": requester, "task": signedTask, "enqueue": result})
	})
	mux.HandleFunc("/api/requester/rebindings", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			rebindings, err := readRequesterRebindingHistory()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"rebindings": rebindings})
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !requireWriteToken(w, r) {
			return
		}
		var request map[string]any
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		previous, ok := request["previous_descriptor"].(map[string]any)
		if !ok {
			http.Error(w, "previous_descriptor is required", http.StatusBadRequest)
			return
		}
		next, ok := request["next_descriptor"].(map[string]any)
		if !ok {
			http.Error(w, "next_descriptor is required", http.StatusBadRequest)
			return
		}
		rotationProof, ok := request["rotation_proof"].(map[string]any)
		if !ok {
			http.Error(w, "rotation_proof is required", http.StatusBadRequest)
			return
		}
		proof, err := fixture.requesterAliasRebindingProof(previous, next, rotationProof)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := fixture.writeRequesterRegistry(next); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := fixture.appendRequesterRebindingHistory(proof); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "authority_descriptor": fixture.Authority, "alias_rebinding_proof": proof})
	})
	mux.HandleFunc("/api/artifacts/manifest", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		uri := r.URL.Query().Get("uri")
		if uri == "" {
			http.Error(w, "artifact uri is required", http.StatusBadRequest)
			return
		}
		if taskID := r.URL.Query().Get("task_id"); taskID != "" {
			record, err := fixture.auditProof(taskID)
			if err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			receipt, _ := record["receipt"].(map[string]any)
			manifest, err := receiptArtifactManifest(receipt, uri)
			if err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			if err := verifyArtifactManifests(receipt, fixture.ArtifactStoreDir); err != nil {
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Agent-Space-Audit-Hash", fmt.Sprint(record["audit_hash"]))
			w.Header().Set("X-Agent-Space-Receipt-Digest", digestHex(receipt))
			w.Header().Set("X-Agent-Space-Artifact-SHA256", fmt.Sprint(manifest["sha256"]))
			w.Header().Set("X-Agent-Space-Artifact-Manifest-Hash", fmt.Sprint(manifest["manifest_hash"]))
			if r.Method == http.MethodHead {
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"task_id": taskID, "uri": uri, "audit_hash": record["audit_hash"], "receipt_digest": digestHex(receipt), "manifest": manifest})
			return
		}
		if r.Method == http.MethodHead {
			http.Error(w, "task_id is required for artifact manifest HEAD", http.StatusBadRequest)
			return
		}
		path, err := localArtifactPath(uri)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		data, err := os.ReadFile(path + ".manifest.json")
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				http.NotFound(w, r)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	})
	mux.HandleFunc("/api/artifacts/verify", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		taskID := r.URL.Query().Get("task_id")
		uri := r.URL.Query().Get("uri")
		if taskID == "" || uri == "" {
			http.Error(w, "task_id and artifact uri are required", http.StatusBadRequest)
			return
		}
		record, err := fixture.auditProof(taskID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		receipt, _ := record["receipt"].(map[string]any)
		manifest, err := receiptArtifactManifest(receipt, uri)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		if err := verifyArtifactManifests(receipt, fixture.ArtifactStoreDir); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "task_id": taskID, "uri": uri, "audit_hash": record["audit_hash"], "receipt_digest": digestHex(receipt), "manifest": manifest})
	})
	mux.HandleFunc("/api/artifacts/read", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		taskID := r.URL.Query().Get("task_id")
		uri := r.URL.Query().Get("uri")
		if taskID == "" || uri == "" {
			http.Error(w, "task_id and artifact uri are required", http.StatusBadRequest)
			return
		}
		record, err := fixture.auditProof(taskID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		receipt, _ := record["receipt"].(map[string]any)
		manifest, err := receiptArtifactManifest(receipt, uri)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		if err := verifyArtifactManifests(receipt, fixture.ArtifactStoreDir); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		w.Header().Set("Content-Type", fmt.Sprint(manifest["media_type"]))
		w.Header().Set("Content-Length", fmt.Sprint(manifest["size"]))
		w.Header().Set("X-Agent-Space-Audit-Hash", fmt.Sprint(record["audit_hash"]))
		w.Header().Set("X-Agent-Space-Receipt-Digest", digestHex(receipt))
		w.Header().Set("X-Agent-Space-Artifact-SHA256", fmt.Sprint(manifest["sha256"]))
		w.Header().Set("X-Agent-Space-Artifact-Manifest-Hash", fmt.Sprint(manifest["manifest_hash"]))
		if r.Method == http.MethodHead {
			return
		}
		path, err := localArtifactPath(uri)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		data, err := os.ReadFile(path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(data)
	})
	mux.HandleFunc("/api/transcripts/stream", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		taskID := r.URL.Query().Get("task_id")
		if taskID == "" {
			http.Error(w, "task_id is required", http.StatusBadRequest)
			return
		}
		record, err := fixture.auditProof(taskID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		receipt, _ := record["receipt"].(map[string]any)
		sandbox, _ := receipt["sandbox"].(map[string]any)
		uri := optionalString(sandbox["tool_transcript_ref"])
		if uri == "" {
			http.Error(w, "task transcript not found", http.StatusNotFound)
			return
		}
		manifest, err := receiptArtifactManifest(receipt, uri)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		if err := verifyArtifactManifests(receipt, fixture.ArtifactStoreDir); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		path, err := localArtifactPath(uri)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		data, err := os.ReadFile(path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !json.Valid(data) {
			http.Error(w, "task transcript is not json", http.StatusConflict)
			return
		}
		w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
		w.Header().Set("X-Agent-Space-Audit-Hash", fmt.Sprint(record["audit_hash"]))
		w.Header().Set("X-Agent-Space-Receipt-Digest", digestHex(receipt))
		w.Header().Set("X-Agent-Space-Transcript-SHA256", fmt.Sprint(manifest["sha256"]))
		w.Header().Set("X-Agent-Space-Transcript-Manifest-Hash", fmt.Sprint(manifest["manifest_hash"]))
		_ = json.NewEncoder(w).Encode(map[string]any{"type": "transcript.chunk", "task_id": taskID, "uri": uri, "transcript": json.RawMessage(data)})
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
	})
	mux.HandleFunc("/api/transcripts/live", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		taskID := r.URL.Query().Get("task_id")
		if taskID == "" {
			http.Error(w, "task_id is required", http.StatusBadRequest)
			return
		}
		data, err := os.ReadFile(filepath.Join(fixture.LiveTranscriptDir, url.PathEscape(taskID)+".ndjson"))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				http.NotFound(w, r)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
		_, _ = w.Write(data)
	})
	mux.Handle("/artifacts/", http.StripPrefix("/artifacts/", http.FileServer(http.Dir("artifacts"))))
	_ = http.Serve(listener, mux)
}

func readAuditEntriesOrEmpty(path string) ([]map[string]any, error) {
	entries, err := readAuditEntries(path)
	if errors.Is(err, os.ErrNotExist) {
		return []map[string]any{}, nil
	}
	return entries, err
}

func taskStateDirForAudit(auditPath string) string {
	return strings.TrimSuffix(auditPath, filepath.Ext(auditPath)) + "-tasks"
}

func queueDirForAudit(auditPath string) string {
	return strings.TrimSuffix(auditPath, filepath.Ext(auditPath)) + "-queue"
}

func approvalDirForAudit(auditPath string) string {
	return strings.TrimSuffix(auditPath, filepath.Ext(auditPath)) + "-approvals"
}

func liveTranscriptDirForAudit(auditPath string) string {
	return strings.TrimSuffix(auditPath, filepath.Ext(auditPath)) + "-live-transcripts"
}

func queueGrantDirForAudit(auditPath string) string {
	return strings.TrimSuffix(auditPath, filepath.Ext(auditPath)) + "-queue-grants"
}

func readTaskStates(dir string) ([]map[string]any, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return []map[string]any{}, nil
	}
	if err != nil {
		return nil, err
	}
	tasks := []map[string]any{}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		var task map[string]any
		if err := json.Unmarshal(data, &task); err != nil {
			return nil, err
		}
		tasks = append(tasks, task)
	}
	sort.Slice(tasks, func(i, j int) bool {
		return optionalString(tasks[i]["task_id"]) < optionalString(tasks[j]["task_id"])
	})
	return tasks, nil
}
