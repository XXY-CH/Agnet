package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHumanGatewayDurable(t *testing.T) {
	t.Chdir(t.TempDir())
	journal := newTestSwarmJournal(t)
	if _, err := OpenVerifiedSwarm(journal, reducerTestDurableSpec(t), swarmJournalTestTime); err != nil {
		t.Fatal(err)
	}
	materializer, err := NewSwarmMaterializer(journal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := materializer.Rebuild(); err != nil {
		t.Fatal(err)
	}

	auditPath := filepath.Join(t.TempDir(), "audit.log")
	if err := writeJSONStateFile(filepath.Join(taskStateDirForAudit(auditPath), "forged.json"), map[string]any{"task_id": "forged-task", "status": "completed"}); err != nil {
		t.Fatal(err)
	}
	if err := writeJSONStateFile(filepath.Join(queueDirForAudit(auditPath), "forged.json"), map[string]any{"task_id": "forged-task", "status": "completed"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(journal.Path), "views", "swarm.json"), []byte(`{"swarm_id":"forged","version":999,"status":"completed"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	mux := newHumanGatewayMux(auditPath, Fixture{}, "", "127.0.0.1", journal)
	for _, path := range []string{"/api/tasks", "/api/queue"} {
		t.Run(path, func(t *testing.T) {
			response := httptest.NewRecorder()
			mux.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
			if response.Code != http.StatusOK {
				t.Fatalf("%s status = %d; body=%s", path, response.Code, response.Body.String())
			}
			if strings.Contains(response.Body.String(), "forged-task") || strings.Contains(response.Body.String(), `"completed"`) {
				t.Fatalf("%s trusted a forged legacy or derived view: %s", path, response.Body.String())
			}
		})
	}
	if err := os.Remove(filepath.Join(filepath.Dir(journal.Path), "views", "queue.json")); err != nil {
		t.Fatal(err)
	}
	deletedResponse := httptest.NewRecorder()
	mux.ServeHTTP(deletedResponse, httptest.NewRequest(http.MethodGet, "/api/queue", nil))
	if deletedResponse.Code != http.StatusOK || strings.Contains(deletedResponse.Body.String(), "forged-task") || strings.Contains(deletedResponse.Body.String(), `"completed"`) {
		t.Fatalf("deleted queue projection did not rebuild from the journal: status=%d body=%s", deletedResponse.Code, deletedResponse.Body.String())
	}

	response := httptest.NewRecorder()
	mux.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/tasks", nil))
	var body map[string][]map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body["tasks"]) != 1 || body["tasks"][0]["task_id"] != "prepare" || body["tasks"][0]["status"] != "pending" {
		t.Fatalf("durable tasks = %#v", body["tasks"])
	}
}

func TestLegacyAuditCannotAdvanceDurableState(t *testing.T) {
	journal := newTestSwarmJournal(t)
	if _, err := OpenVerifiedSwarm(journal, reducerTestDurableSpec(t), swarmJournalTestTime); err != nil {
		t.Fatal(err)
	}
	materializer, err := NewSwarmMaterializer(journal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := materializer.Rebuild(); err != nil {
		t.Fatal(err)
	}
	entriesBefore := mustReplaySwarm(t, journal)

	audit, err := openAuditLog(filepath.Join(t.TempDir(), "legacy-audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	fixture := Fixture{Audit: audit}
	if err := fixture.appendAudit(map[string]any{"kind": "go_fed_event", "event": map[string]any{"type": "task.completed", "task_id": "prepare"}}); err != nil {
		t.Fatal(err)
	}
	if entriesAfter := mustReplaySwarm(t, journal); len(entriesAfter) != len(entriesBefore) {
		t.Fatalf("legacy audit append changed durable journal entries: before=%d after=%d", len(entriesBefore), len(entriesAfter))
	}

	view, err := ReadSwarmView(journal)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), `"completed"`) {
		t.Fatalf("legacy audit advanced durable swarm view: %s", encoded)
	}
}

func TestHumanGatewayConfiguredJournal(t *testing.T) {
	t.Chdir(t.TempDir())
	journal := newTestSwarmJournal(t)
	spec := reducerTestDurableSpec(t)
	if _, err := OpenVerifiedSwarm(journal, spec, swarmJournalTestTime); err != nil {
		t.Fatal(err)
	}

	root := filepath.Dir(filepath.Dir(journal.Path))
	configured, err := openHumanGatewayJournal(root, spec.SwarmID)
	if err != nil {
		t.Fatal(err)
	}
	if configured == nil || configured.Path != journal.Path {
		t.Fatalf("configured journal = %#v, want %q", configured, journal.Path)
	}

	mux := newHumanGatewayServer(filepath.Join(t.TempDir(), "audit.log"), Fixture{}, "", "127.0.0.1", configured)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/tasks", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"task_id":"prepare"`) {
		t.Fatalf("configured production mux omitted durable task: %s", response.Body.String())
	}
}

func TestOpenHumanGatewayJournalRejectsInvalidConfiguration(t *testing.T) {
	journal := newTestSwarmJournal(t)
	spec := reducerTestDurableSpec(t)
	if _, err := OpenVerifiedSwarm(journal, spec, swarmJournalTestTime); err != nil {
		t.Fatal(err)
	}
	root := filepath.Dir(filepath.Dir(journal.Path))

	for _, configuration := range []struct {
		name        string
		storageRoot string
		swarmID     string
	}{
		{name: "storage root only", storageRoot: root},
		{name: "swarm id only", swarmID: spec.SwarmID},
		{name: "missing exact journal", storageRoot: root, swarmID: "swarm://test/missing"},
	} {
		t.Run(configuration.name, func(t *testing.T) {
			if _, err := openHumanGatewayJournal(configuration.storageRoot, configuration.swarmID); err == nil {
				t.Fatal("invalid configured journal accepted")
			}
		})
	}

	if err := os.WriteFile(journal.Path, []byte("invalid journal\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openHumanGatewayJournal(root, spec.SwarmID); err == nil {
		t.Fatal("invalid journal seed accepted")
	}
}

func TestHumanGatewayRequiresTokenWhenEnabled(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		port    string
		token   string
		wantErr bool
	}{
		{name: "disabled", port: "", token: "", wantErr: false},
		{name: "missing", port: "0", token: "", wantErr: true},
		{name: "blank", port: "0", token: "  ", wantErr: true},
		{name: "configured", port: "0", token: "product-secret", wantErr: false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			err := validateHumanGatewayConfiguration(testCase.port, testCase.token)
			if (err != nil) != testCase.wantErr {
				t.Fatalf("validateHumanGatewayConfiguration(%q, %q) error=%v", testCase.port, testCase.token, err)
			}
		})
	}
}
