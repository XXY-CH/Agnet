package main

import (
	"agnet/internal/managedkey"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type promotionDockerAdapter struct {
	result DockerRunResult
	err    error
}

func (a promotionDockerAdapter) Run(_ context.Context, _ DockerRunRequest) (DockerRunResult, error) {
	if a.err != nil {
		return DockerRunResult{}, a.err
	}
	return a.result, nil
}

func containerPromotionFixture(t *testing.T, runtimeKind string, adapter DockerAdapter) (Fixture, *Worker, map[string]any, map[string]any) {
	t.Helper()
	t.Setenv("AGNET_CONTAINER_RUNTIME", runtimeKind)
	fixturePath, runtimeKeys := managedRuntimeFixture(t, managedkey.KeyTypeSeed)
	fixture, err := loadManagedFixture(fixturePath, runtimeKeys)
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir())
	profile := validDockerWorkerProfile()
	fixture.Workers[0].Profile = WorkerProfile{
		Alias:        fixture.Workers[0].Profile.Alias,
		Tool:         "container.test",
		SandboxClaim: "container-namespace",
		Docker:       &profile,
		Transports:   fixture.Workers[0].Profile.Transports,
		Capabilities: fixture.Workers[0].Profile.Capabilities,
		Policy:       fixture.Workers[0].Profile.Policy,
	}
	fixture.ContainerAdapter = adapter
	fixture.Runtime = &TaskRuntime{running: map[string]context.CancelFunc{}, cancelled: map[string]bool{}}
	fixture.ArtifactStoreDir = filepath.Join(t.TempDir(), "store")
	fixture.TaskStateDir = filepath.Join(t.TempDir(), "tasks")
	audit, err := openAuditLog(filepath.Join(t.TempDir(), "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	fixture.Audit = audit
	task := map[string]any{
		"task_id": "docker_promotion_task",
		"from":    "agent://test/requester",
		"to":      fixture.Workers[0].Descriptor["alias"],
		"intent":  "promote staged container result",
		"scope":   map[string]any{"network": false},
	}
	return fixture, &fixture.Workers[0], task, map[string]any{"zid": "zone://origin"}
}

func dockerPromotionFixture(t *testing.T, adapter DockerAdapter) (Fixture, *Worker, map[string]any, map[string]any) {
	return containerPromotionFixture(t, "docker", adapter)

}

func testContainerRuntimeIdentity(runtime, image, imageID string) map[string]any {
	if runtime == "docker" {
		return map[string]any{
			"runtime": runtime, "image": image, "image_id": imageID, "image_descriptor_digest": imageID,
			"command_path": dockerCommandPath, "socket_path": dockerLocalUnixSocket, "socket_device": "1", "socket_inode": "2", "socket_mode": "495", "socket_uid": "0",
			"binary_digest": strings.Repeat("a", 64), "client_version": "24.0.0", "client_api_version": "1.43", "daemon_id": "daemon-id", "daemon_version": "24.0.0", "daemon_api_version": "1.43",
		}
	}
	return map[string]any{
		"runtime": runtime, "image": image, "image_id": imageID, "image_descriptor_digest": imageID,
		"binary_path": appleContainerBinaryPath, "binary_digest": strings.Repeat("a", 64), "cli_version": "1.0.0", "cli_commit": "cli-commit", "api_server_version": "1.0.0", "api_server_commit": "api-commit", "app_root": "/Users/test/Library/Containers/com.apple.container",
	}
}

func verifiedContainerAdapterEvidence(runtime string, request DockerRunRequest) map[string]any {
	_, imageID, _ := strings.Cut(request.Image, "@sha256:")
	containerID := dockerLifecycleID
	if runtime == "apple-container" {
		containerID = appleLifecycleTestContainerID
	}
	runtimeIdentity := testContainerRuntimeIdentity(runtime, request.Image, imageID)
	constraints := containerAdapterConstraints(request)
	return map[string]any{
		"format": containerAdapterEvidenceFormat, "runtime": runtime, "image": request.Image, "image_id": imageID, "container_id": containerID,
		"runtime_identity": runtimeIdentity, "runtime_identity_digest": digestHex(runtimeIdentity), "constraints": constraints, "configuration_digest": digestHex(constraints), "observed": map[string]any{"exit_code": float64(0)},
	}
}

func verifiedDockerResult() DockerRunResult {
	request, err := validateDockerWorkerProfile(validDockerWorkerProfile())
	if err != nil {
		panic(err)
	}
	return DockerRunResult{
		Result: []byte("container result"), MediaType: "text/plain", Transcript: []byte(`{"stdout_b64":"","stderr_b64":""}`), TranscriptMediaType: "application/json", Evidence: verifiedContainerAdapterEvidence("docker", request),
	}
}

func forgedContainerResult(runtime string, mutate func(map[string]any)) DockerRunResult {
	result := verifiedDockerResult()
	request, err := validateDockerWorkerProfile(validDockerWorkerProfile())
	if err != nil {
		panic(err)
	}
	result.Evidence = verifiedContainerAdapterEvidence(runtime, request)
	mutate(result.Evidence)
	return result
}

func forgedDockerResult(mutate func(map[string]any)) DockerRunResult {
	return forgedContainerResult("docker", mutate)
}

func TestDockerPromotionBindsVerifiedStagedEvidence(t *testing.T) {
	adapterResult := verifiedDockerResult()
	fixture, worker, task, origin := dockerPromotionFixture(t, promotionDockerAdapter{result: adapterResult})
	frames := []map[string]any{}
	var callbackReceipt map[string]any
	if err := fixture.executeTask(func(frame map[string]any) { frames = append(frames, frame) }, origin, worker, task, nil, "", nil, false, nil, func(receipt map[string]any) error {
		callbackReceipt = receipt
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if callbackReceipt == nil {
		t.Fatal("promotion callback was not invoked")
	}
	if err := verifyReceiptRecord(map[string]any{
		"kind":         "go_fed_receipt",
		"zone":         fixture.Authority,
		"worker":       worker.Descriptor,
		"zone_binding": fixture.zoneBinding(worker),
		"receipt":      callbackReceipt,
	}, fixture.ArtifactStoreDir, task); err != nil {
		t.Fatalf("promoted container receipt did not verify: %v", err)
	}
	sandbox, _ := callbackReceipt["sandbox"].(map[string]any)
	evidence, _ := sandbox["container_evidence"].(map[string]any)
	if evidence["format"] != "agnet-container-evidence/v2" || evidence["runtime"] != "docker" {
		t.Fatalf("container evidence = %#v", evidence)
	}
	if !reflect.DeepEqual(evidence["constraints"], adapterResult.Evidence["constraints"]) || evidence["configuration_digest"] != adapterResult.Evidence["configuration_digest"] {
		t.Fatalf("receipt did not copy verified adapter constraints: receipt=%#v adapter=%#v", evidence, adapterResult.Evidence)
	}
	if evidence["task_digest"] != digestHex(task) || evidence["profile_digest"] != digestHex(callbackReceipt["container_profile"]) || evidence["generation_digest"] != callbackReceipt["container_generation_digest"] {
		t.Fatalf("container binding = %#v receipt=%#v", evidence, callbackReceipt)
	}
	result, _ := callbackReceipt["result_artifact"].(map[string]any)
	if evidence["result_digest"] != result["sha256"] {
		t.Fatalf("result digest = %v, want %v", evidence["result_digest"], result["sha256"])
	}
	proof, _ := callbackReceipt["sandbox_proof"].(map[string]any)
	proofSandbox, _ := proof["sandbox"].(map[string]any)
	if digestHex(proofSandbox["container_evidence"]) != digestHex(evidence) {
		t.Fatalf("sandbox proof evidence differs: %#v %#v", proofSandbox, evidence)
	}
	if frames[len(frames)-2]["type"] != "FED_RECEIPT" || frames[len(frames)-1]["type"] != "FED_TASK_CLOSE" {
		t.Fatalf("promotion frames = %#v", frames)
	}
}

func TestContainerPromotionAppleRuntime(t *testing.T) {
	result := verifiedDockerResult()
	profile := validDockerWorkerProfile()
	request, err := validateDockerWorkerProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	result.Evidence = verifiedContainerAdapterEvidence("apple-container", request)
	result.Evidence["container_id"] = "agnet-00000000000000000000000000000000"
	fixture, worker, task, origin := containerPromotionFixture(t, "apple-container", promotionDockerAdapter{result: result})
	var receipt map[string]any
	if err := fixture.executeTask(func(map[string]any) {}, origin, worker, task, nil, "", nil, false, nil, func(candidate map[string]any) error {
		receipt = candidate
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := verifyReceiptRecord(map[string]any{
		"kind":         "go_fed_receipt",
		"zone":         fixture.Authority,
		"worker":       worker.Descriptor,
		"zone_binding": fixture.zoneBinding(worker),
		"receipt":      receipt,
	}, fixture.ArtifactStoreDir, task); err != nil {
		t.Fatalf("promoted Apple container receipt did not verify: %v", err)
	}
	sandbox, _ := receipt["sandbox"].(map[string]any)
	evidence, _ := sandbox["container_evidence"].(map[string]any)
	if evidence["runtime"] != "apple-container" || evidence["runtime_identity_digest"] != result.Evidence["runtime_identity_digest"] {
		t.Fatalf("apple evidence = %#v", evidence)
	}
}

func TestDockerFailureDoesNotPublishAfterAdapterOrEvidenceFailure(t *testing.T) {
	tests := []struct {
		name        string
		runtimeKind string
		adapter     DockerAdapter
		wantCode    string
	}{
		{name: "adapter", adapter: promotionDockerAdapter{err: errors.New("adapter exploded")}, wantCode: "container_adapter_failed"},
		{name: "limit", adapter: promotionDockerAdapter{err: errors.New("output limit exceeded")}, wantCode: "container_adapter_failed"},
		{name: "timeout", adapter: promotionDockerAdapter{err: errors.New("container timed out")}, wantCode: "container_adapter_failed"},
		{name: "remove", adapter: promotionDockerAdapter{err: errors.New("container remove failed")}, wantCode: "container_adapter_failed"},
		{name: "result copy", adapter: promotionDockerAdapter{err: errors.New("result copy failed")}, wantCode: "container_adapter_failed"},
		{name: "generic runtime evidence", adapter: promotionDockerAdapter{result: DockerRunResult{Result: []byte("bad"), MediaType: "text/plain", Evidence: map[string]any{"runtime": "self-declared"}}}, wantCode: "container_evidence_invalid"},
		{name: "missing constraint evidence", adapter: promotionDockerAdapter{result: forgedDockerResult(func(e map[string]any) { delete(e, "constraints") })}, wantCode: "container_evidence_invalid"},
		{name: "forged constraint evidence", adapter: promotionDockerAdapter{result: forgedDockerResult(func(e map[string]any) { e["constraints"].(map[string]any)["network"] = "host" })}, wantCode: "container_evidence_invalid"},
		{name: "apple forged constraint evidence", runtimeKind: "apple-container", adapter: promotionDockerAdapter{result: forgedContainerResult("apple-container", func(e map[string]any) { e["constraints"].(map[string]any)["network"] = "host" })}, wantCode: "container_evidence_invalid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runtimeKind := tt.runtimeKind
			if runtimeKind == "" {
				runtimeKind = "docker"
			}
			fixture, worker, task, origin := containerPromotionFixture(t, runtimeKind, tt.adapter)
			frames := []map[string]any{}
			callbacks := 0
			err := fixture.executeTask(func(frame map[string]any) { frames = append(frames, frame) }, origin, worker, task, nil, "", nil, false, nil, func(map[string]any) error {
				callbacks++
				return nil
			})
			if err == nil || err.Error() != tt.wantCode {
				t.Fatalf("executeTask() error = %v, want %s", err, tt.wantCode)
			}
			if callbacks != 0 {
				t.Fatalf("callback count = %d", callbacks)
			}
			for _, frame := range frames {
				if frame["type"] == "FED_RECEIPT" || frame["type"] == "FED_TASK_CLOSE" {
					t.Fatalf("promoted frame after failure: %#v", frame)
				}
				event, _ := frame["event"].(map[string]any)
				if event["type"] == "artifact.created" || event["type"] == "task.completed" {
					t.Fatalf("success event after failure: %#v", frame)
				}
			}
			if _, err := os.Stat(filepath.Join("artifacts", task["task_id"].(string), "go-summary.md.manifest.json")); !os.IsNotExist(err) {
				t.Fatalf("result manifest exists after failure: %v", err)
			}
			if _, err := os.Stat(filepath.Join(fixture.ArtifactStoreDir, "by-sha256")); !os.IsNotExist(err) {
				t.Fatalf("artifact store manifest exists after failure: %v", err)
			}
		})
	}
}

func TestDockerFailureDoesNotPublishAfterCallbackFailure(t *testing.T) {
	fixture, worker, task, origin := dockerPromotionFixture(t, promotionDockerAdapter{result: verifiedDockerResult()})
	frames := []map[string]any{}
	err := fixture.executeTask(func(frame map[string]any) { frames = append(frames, frame) }, origin, worker, task, nil, "", nil, false, nil, func(map[string]any) error {
		return errors.New("callback failed")
	})
	if err == nil || err.Error() != "promotion_callback_failed" {
		t.Fatalf("executeTask() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join("artifacts", task["task_id"].(string), "go-summary.md.manifest.json")); !os.IsNotExist(err) {
		t.Fatalf("result manifest exists after callback failure: %v", err)
	}
	for _, frame := range frames {
		if frame["type"] == "FED_RECEIPT" || frame["type"] == "FED_TASK_CLOSE" {
			t.Fatalf("promoted frame after callback failure: %#v", frame)
		}
	}
}

func TestDockerFailureDoesNotPublishAfterArtifactReadinessFailure(t *testing.T) {
	fixture, worker, task, origin := dockerPromotionFixture(t, promotionDockerAdapter{result: verifiedDockerResult()})
	if err := os.WriteFile(fixture.ArtifactStoreDir, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	callbacks := 0
	err := fixture.executeTask(func(map[string]any) {}, origin, worker, task, nil, "", nil, false, nil, func(map[string]any) error {
		callbacks++
		return nil
	})
	if err == nil || callbacks != 0 {
		t.Fatalf("executeTask() = %v, callbacks = %d", err, callbacks)
	}
	if _, err := os.Stat(filepath.Join("artifacts", task["task_id"].(string), "go-summary.md.manifest.json")); !os.IsNotExist(err) {
		t.Fatalf("result manifest exists after artifact readiness failure: %v", err)
	}
}
