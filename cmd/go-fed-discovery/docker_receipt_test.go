package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func dockerReceiptEvidence(profile DockerWorkerProfile, runtime string) map[string]any {
	constraints := dockerReceiptConstraints(profile)
	imageID := strings.Repeat("a", 64)
	runtimeIdentity := testContainerRuntimeIdentity(runtime, profile.Image, imageID)
	evidence := map[string]any{
		"format":                  "agnet-container-evidence/v2",
		"runtime":                 runtime,
		"image":                   profile.Image,
		"image_id":                strings.Repeat("a", 64),
		"container_id":            strings.Repeat("b", 64),
		"runtime_identity":        runtimeIdentity,
		"runtime_identity_digest": digestHex(runtimeIdentity),
		"constraints":             constraints,
		"configuration_digest":    digestHex(constraints),
		"observed": map[string]any{
			"exit_code":        float64(0),
			"result_bytes":     float64(11),
			"transcript_bytes": float64(13),
			"artifact_count":    float64(2),
		},
		"task_id":           "task-container-receipt",
		"task_digest":       strings.Repeat("c", 64),
		"generation_digest": strings.Repeat("d", 64),
		"result_digest":     strings.Repeat("e", 64),
		"transcript_digest": strings.Repeat("f", 64),
		"profile_digest":    dockerReceiptProfileDigest(profile),
	}
	if runtime == "apple-container" {
		evidence["container_id"] = "agnet-" + strings.Repeat("b", 32)
	}
	return evidence
}

func testDockerReceiptProfile() DockerWorkerProfile {
	return DockerWorkerProfile{
		Image:   "example.test/receipt:latest@sha256:" + strings.Repeat("1", 64),
		Command: []string{"/bin/receipt", "--verify"},
		Limits: DockerLimits{
			CPUMillis:            500,
			MemoryBytes:          64 << 20,
			TimeoutMillis:        15_000,
			MaxOutputBytes:       1 << 20,
			MaxScratchInputBytes: 1 << 10,
			MaxScratchBytes:      1 << 12,
		},
	}
}

func TestDockerSandboxEvidenceAcceptsExactContainerRuntimes(t *testing.T) {
	profile := testDockerReceiptProfile()
	for _, runtime := range []string{"docker", "apple-container"} {
		t.Run(runtime, func(t *testing.T) {
			if err := verifyDockerSandboxEvidence(dockerReceiptEvidence(profile, runtime), profile); err != nil {
				t.Fatalf("verifyDockerSandboxEvidence() error = %v", err)
			}
		})
	}
}

func TestDockerSandboxEvidenceRejectsInvalidOrForgedBindings(t *testing.T) {
	profile := testDockerReceiptProfile()
	cases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "generic runtime", mutate: func(e map[string]any) { e["runtime"] = "container" }},
		{name: "unknown field", mutate: func(e map[string]any) { e["forged"] = true }},
		{name: "missing configuration digest", mutate: func(e map[string]any) { delete(e, "configuration_digest") }},
		{name: "image mutation", mutate: func(e map[string]any) { e["image"] = "example.test/other:latest@sha256:" + strings.Repeat("2", 64) }},
		{name: "runtime identity digest", mutate: func(e map[string]any) { e["runtime_identity_digest"] = strings.Repeat("0", 64) }},
		{name: "configuration digest", mutate: func(e map[string]any) { e["configuration_digest"] = strings.Repeat("0", 64) }},
		{name: "missing constraints", mutate: func(e map[string]any) { delete(e, "constraints") }},
		{name: "forged constraints", mutate: func(e map[string]any) { e["constraints"].(map[string]any)["network"] = "host" }},
		{name: "forged count", mutate: func(e map[string]any) { e["observed"].(map[string]any)["result_bytes"] = "12" }},
		{name: "result digest", mutate: func(e map[string]any) { e["result_digest"] = "not-a-digest" }},
		{name: "transcript digest", mutate: func(e map[string]any) { e["transcript_digest"] = "not-a-digest" }},
		{name: "profile binding", mutate: func(e map[string]any) { e["profile_digest"] = strings.Repeat("0", 64) }},
		{name: "task binding", mutate: func(e map[string]any) { e["task_id"] = "" }},
		{name: "generation binding", mutate: func(e map[string]any) { e["generation_digest"] = "not-a-digest" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			evidence := dockerReceiptEvidence(profile, "docker")
			tc.mutate(evidence)
			if err := verifyDockerSandboxEvidence(evidence, profile); err == nil {
				t.Fatal("verifyDockerSandboxEvidence() unexpectedly accepted forged evidence")
			}
		})
	}
}

func TestDockerReceiptVerifiesBothContainerRuntimes(t *testing.T) {
	for _, runtime := range []string{"docker", "apple-container"} {
		t.Run(runtime, func(t *testing.T) {
			record, store := signedContainerReceiptRecord(t, runtime)
			if err := verifyReceiptRecord(record, store); err != nil {
				t.Fatalf("verifyReceiptRecord() error = %v", err)
			}
		})
	}
}

func TestDockerReceiptRejectsForgedContainerBindings(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(receipt, evidence map[string]any)
	}{
		{name: "generic runtime", mutate: func(_ map[string]any, e map[string]any) { e["runtime"] = "generic" }},
		{name: "unknown evidence field", mutate: func(_ map[string]any, e map[string]any) { e["unexpected"] = true }},
		{name: "image", mutate: func(_ map[string]any, e map[string]any) { e["image"] = "example.test/forged:latest@sha256:" + strings.Repeat("9", 64) }},
		{name: "runtime identity", mutate: func(_ map[string]any, e map[string]any) { e["runtime_identity_digest"] = strings.Repeat("0", 64) }},
		{name: "configuration", mutate: func(_ map[string]any, e map[string]any) { e["configuration_digest"] = strings.Repeat("0", 64) }},
		{name: "result digest", mutate: func(_ map[string]any, e map[string]any) { e["result_digest"] = strings.Repeat("0", 64) }},
		{name: "transcript digest", mutate: func(_ map[string]any, e map[string]any) { e["transcript_digest"] = strings.Repeat("0", 64) }},
		{name: "result count", mutate: func(_ map[string]any, e map[string]any) { e["observed"].(map[string]any)["result_bytes"] = float64(0) }},
		{name: "artifact count", mutate: func(_ map[string]any, e map[string]any) { e["observed"].(map[string]any)["artifact_count"] = float64(1) }},
		{name: "missing constraints", mutate: func(_ map[string]any, e map[string]any) { delete(e, "constraints") }},
		{name: "forged constraints", mutate: func(_ map[string]any, e map[string]any) { e["constraints"].(map[string]any)["network"] = "host" }},
		{name: "generic claim without evidence", mutate: func(receipt map[string]any, _ map[string]any) { delete(receipt["sandbox"].(map[string]any), "container_evidence"); delete(receipt, "container_profile"); delete(receipt, "container_generation_digest") }},
		{name: "task", mutate: func(_ map[string]any, e map[string]any) { e["task_id"] = "other-task" }},
		{name: "profile", mutate: func(_ map[string]any, e map[string]any) { e["profile_digest"] = strings.Repeat("0", 64) }},
		{name: "generation", mutate: func(_ map[string]any, e map[string]any) { e["generation_digest"] = strings.Repeat("0", 64) }},
		{name: "proof copied evidence", mutate: func(receipt map[string]any, _ map[string]any) { receipt["sandbox_proof"].(map[string]any)["sandbox"].(map[string]any)["container_evidence"] = map[string]any{} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			record, _ := signedContainerReceiptRecord(t, "docker")
			receipt := record["receipt"].(map[string]any)
			evidence := receipt["sandbox"].(map[string]any)["container_evidence"].(map[string]any)
			tc.mutate(receipt, evidence)
			if err := verifyContainerReceiptEvidence(receipt, receipt["sandbox"].(map[string]any), receipt["sandbox_proof"].(map[string]any)); err == nil {
				t.Fatal("verifyContainerReceiptEvidence() unexpectedly accepted forged receipt")
			}
		})
	}
}

func signedContainerReceiptRecord(t *testing.T, runtime string) (map[string]any, string) {
	t.Helper()
	t.Chdir(t.TempDir())
	store := filepath.Join(t.TempDir(), "artifact-store")
	result := []byte("container result")
	transcript := []byte(`{"stdout_b64":"","stderr_b64":""}`)
	resultManifest, err := writeArtifactBytes("artifact://local/container-receipt/result", result, "text/plain", store)
	if err != nil {
		t.Fatal(err)
	}
	transcriptManifest, err := writeArtifactBytes("artifact://local/container-receipt/transcript", transcript, "application/json", store)
	if err != nil {
		t.Fatal(err)
	}
	zone, zoneKey := testZoneDescriptor(t, "zone://container-receipt")
	_, workerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := workerDescriptor(WorkerProfile{
		Alias:        "agent://container-receipt/worker",
		Transports:   []string{"go-test"},
		Capabilities: []string{"test"},
		Policy:       map[string]any{"network": false},
	}, workerKey)
	if err != nil {
		t.Fatal(err)
	}
	profile := testDockerReceiptProfile()
	profileMap := dockerReceiptProfileMap(t, profile)
	if digestHex(profileMap) != dockerReceiptProfileDigest(profile) {
		t.Fatal("profile canonical digest changed between receipt map and profile")
	}
	taskID := "container_receipt_task"
	taskDigest := digestHex(map[string]any{"task_id": taskID})
	containerID := strings.Repeat("b", 64)
	if runtime == "apple-container" {
		containerID = "agnet-" + strings.Repeat("b", 32)
	}
	constraints := dockerReceiptConstraints(profile)
	runtimeIdentity := testContainerRuntimeIdentity(runtime, profile.Image, strings.Repeat("a", 64))
	evidence := map[string]any{
		"format":                  "agnet-container-evidence/v2",
		"runtime":                 runtime,
		"image":                   profile.Image,
		"image_id":                strings.Repeat("a", 64),
		"container_id":            containerID,
		"runtime_identity":        runtimeIdentity,
		"runtime_identity_digest": digestHex(runtimeIdentity),
		"constraints":             constraints,
		"configuration_digest":    digestHex(constraints),
		"observed": map[string]any{
			"exit_code":        float64(0),
			"result_bytes":     resultManifest["size"],
			"transcript_bytes": transcriptManifest["size"],
			"artifact_count":    float64(2),
		},
		"task_id":           taskID,
		"task_digest":       taskDigest,
		"profile_digest":    dockerReceiptProfileDigest(profile),
		"generation_digest": strings.Repeat("d", 64),
		"result_digest":     resultManifest["sha256"],
		"transcript_digest": transcriptManifest["sha256"],
	}
	sandbox := map[string]any{
		"mode":                     "container-namespace",
		"container_evidence":       evidence,
		"tool_transcript_ref":      transcriptManifest["uri"],
		"tool_transcript_manifest": transcriptManifest,
	}
	policyScope := map[string]any{"network": false, "write": []string{}, "tools": []string{}, "data_domains": []string{}, "approval_required": []string{}, "expires_at": ""}
	proof := signBodyWithKey(zoneKey, map[string]any{
		"proof_type": "local.sandbox.v1", "task_id": taskID, "authority": zone["zid"], "worker": worker["aid"], "policy_digest": digestHex(policyScope), "sandbox": sandbox, "sandbox_claim": "container-namespace",
	}, "sandbox_signature")
	receipt := testSignedReceipt(t, zone, zoneKey, worker, workerKey, taskID, []map[string]any{resultManifest, transcriptManifest}, map[string]any{
		"artifact_refs":                []string{fmt.Sprint(resultManifest["uri"]), fmt.Sprint(transcriptManifest["uri"])},
		"artifact_manifests":           []map[string]any{resultManifest, transcriptManifest},
		"result_artifact":              map[string]any{"uri": resultManifest["uri"], "sha256": resultManifest["sha256"], "manifest_hash": resultManifest["manifest_hash"]},
		"tool_output_digest":           resultManifest["sha256"],
		"sandbox":                      sandbox,
		"sandbox_proof":                proof,
		"sandbox_claim":                "container-namespace",
		"container_profile":            profileMap,
		"container_generation_digest":  strings.Repeat("d", 64),
	})
	return map[string]any{
		"zone":         zone,
		"worker":       worker,
		"zone_binding": signBodyWithKey(zoneKey, map[string]any{"zone": zone["zid"], "alias": worker["alias"], "aid": worker["aid"]}, "signature"),
		"receipt":      receipt,
	}, store
}

func dockerReceiptProfileMap(t *testing.T, profile DockerWorkerProfile) map[string]any {
	t.Helper()
	encoded, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	var profileMap map[string]any
	if err := json.Unmarshal(encoded, &profileMap); err != nil {
		t.Fatal(err)
	}
	return profileMap
}
