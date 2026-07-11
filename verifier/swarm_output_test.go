package verifier

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"strings"
	"testing"
	"time"
)

type swarmOutputFixture struct {
	trustFixture   trustFixture
	trust          TrustInputs
	coordinator    map[string]any
	coordinatorKey ed25519.PrivateKey
	worker         map[string]any
	workerKey      ed25519.PrivateKey
	evidence       OutputEvidence
	proof          map[string]any
	artifactURI    string
	artifactBytes  []byte
}

func newSwarmOutputFixture(t *testing.T) swarmOutputFixture {
	t.Helper()
	trustFixture := newTrustFixture(t)
	trust, err := NewTrustInputsForTest(trustFixture.allowlist, trustFixture.trustedZones, trustFixture.revocations)
	if err != nil {
		t.Fatal(err)
	}
	zonePub, zoneKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	workerPub, workerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	coordinator := signedDescriptor(t, zoneKey, "zone_signature", map[string]any{
		"name":            "zone://u5-output/go-coordinator",
		"zid":             zidFromSPKI(spkiBytes(t, zonePub)),
		"public_key_spki": spki(t, zonePub),
	})
	worker := signedDescriptor(t, workerKey, "descriptor_signature", map[string]any{
		"alias":           "agent://u5-output/go-worker",
		"aid":             aidFromSPKI(spkiBytes(t, workerPub)),
		"did_key":         mustDidKey(t, spki(t, workerPub)),
		"public_key_spki": spki(t, workerPub),
		"transports":      []any{"asp+local://u5-go"},
		"capabilities":    []any{"summarize.text"},
		"policy":          map[string]any{"allow_network": false, "write_prefixes": []any{"artifact://local/"}},
	})
	steps := []any{map[string]any{"step_id": "summary", "capability": "summarize.text", "depends_on": []any{}}}
	intent := "Produce a Go Swarm result."
	planDigest := digestNodeCanonical(map[string]any{"intent": intent, "steps": steps})
	planBody := map[string]any{"swarm_id": "swarm://u5-output/go-positive", "intent": intent, "steps": steps, "policy_digest": strings.Repeat("a", 64), "plan_digest": planDigest}
	planFrame := map[string]any{"type": "FED_SWARM_PLAN", "zone": coordinator, "plan": signNodeCanonical(t, zoneKey, "plan_signature", planBody)}
	taskBody := map[string]any{"task_id": "u5_go_summary", "from": worker["aid"], "to": worker["alias"], "intent": "Complete summary."}
	signedTask := signNodeCanonical(t, workerKey, "signature", taskBody)
	bindingSteps := []any{map[string]any{"step_id": "summary", "depends_on": []any{}, "capability": "summarize.text", "task_digest": digestNodeCanonical(signedTask)}}
	graphDigest := digestNodeCanonical(map[string]any{"swarm_id": planBody["swarm_id"], "plan_digest": planDigest, "steps": bindingSteps})
	bindingBody := map[string]any{"format": "asp-swarm-execution-binding/v1", "swarm_id": planBody["swarm_id"], "plan_digest": planDigest, "steps": bindingSteps, "execution_graph_digest": graphDigest}
	binding := signNodeCanonical(t, zoneKey, "binding_signature", bindingBody)
	artifactBytes := []byte("go u5 output bytes\n")
	artifactHash := sha256.Sum256(artifactBytes)
	artifactSHA := hex.EncodeToString(artifactHash[:])
	artifactURI := "artifact://local/u5-go/result.txt"
	manifestBody := map[string]any{"uri": artifactURI, "sha256": artifactSHA, "size": float64(len(artifactBytes)), "media_type": "text/plain", "afp": "afp:sha256:" + artifactSHA}
	manifest := cloneJSONMap(t, manifestBody)
	manifest["manifest_hash"] = digestNodeCanonical(manifestBody)
	resultArtifact := map[string]any{"uri": artifactURI, "sha256": artifactSHA, "manifest_hash": manifest["manifest_hash"]}
	receiptBody := map[string]any{
		"task_id":            signedTask["task_id"],
		"task_digest":        digestNodeCanonical(signedTask),
		"origin_zone":        coordinator["zid"],
		"executing_zone":     coordinator["zid"],
		"to":                 worker["aid"],
		"artifact_refs":      []any{artifactURI},
		"artifact_manifests": []any{manifest},
		"result_artifact":    resultArtifact,
		"swarm":              map[string]any{"swarm_id": planBody["swarm_id"], "step_id": "summary", "after": []any{}, "plan_digest": planDigest, "execution_graph_digest": graphDigest, "capability": "summarize.text", "task_digest": digestNodeCanonical(signedTask)},
	}
	signedReceipt := signNodeCanonical(t, workerKey, "signature", receiptBody)
	receiptFrame := map[string]any{"type": "FED_RECEIPT", "zone": coordinator, "worker": worker, "zone_binding": signNodeCanonical(t, zoneKey, "signature", map[string]any{"zone": coordinator["zid"], "alias": worker["alias"], "aid": worker["aid"]}), "receipt": signedReceipt}
	signedReceiptDigest, err := SignedReceiptDigest(signedReceipt)
	if err != nil {
		t.Fatal(err)
	}
	finalOutput := map[string]any{"step_id": "summary", "task_id": signedTask["task_id"], "signed_receipt_digest": signedReceiptDigest, "artifact": resultArtifact, "selection_rule": "single-terminal-result"}
	closeBody := map[string]any{"format": "asp-swarm-close/v2", "swarm_id": planBody["swarm_id"], "plan_digest": planDigest, "execution_graph_digest": graphDigest, "step_receipts": []any{map[string]any{"step_id": "summary", "task_id": signedTask["task_id"], "signed_receipt_digest": signedReceiptDigest}}, "final_output": finalOutput}
	closeFrame := map[string]any{"type": "FED_SWARM_CLOSE", "swarm_id": planBody["swarm_id"], "zone": coordinator, "close": signNodeCanonical(t, zoneKey, "close_signature", closeBody)}
	closeDigest := digestNodeCanonical(closeFrame["close"])
	proofBody := map[string]any{
		"format":                 "asp-swarm-output-verification/v1",
		"verification_id":        "u5-go-positive",
		"verified_at":            "2026-07-11T11:59:00Z",
		"swarm_id":               planBody["swarm_id"],
		"plan_digest":            planDigest,
		"execution_graph_digest": graphDigest,
		"close_digest":           closeDigest,
		"final_output":           finalOutput,
		"verifier_aid":           trustFixture.verifier["aid"],
		"verifier_zone":          trustFixture.zone["zid"],
		"trust_inputs_digest":    trust.TrustInputsDigest,
	}
	proof := map[string]any{"type": "FED_SWARM_OUTPUT_VERIFICATION", "verifier": trustFixture.verifier, "verifier_zone": trustFixture.zone, "verifier_zone_binding": trustFixture.allowlist["verifiers"].([]any)[0].(map[string]any)["zone_binding"], "proof": signNodeCanonical(t, trustFixture.verifierKey, "proof_signature", proofBody)}
	evidence := OutputEvidence{
		Proof:            proof,
		PlanFrame:        planFrame,
		ExecutionBinding: binding,
		ExecutableSteps:  []map[string]any{{"step_id": "summary", "depends_on": []any{}, "task": signedTask}},
		ResolvedWorkers:  []map[string]any{worker},
		CloseFrame:       closeFrame,
		ReceiptFrames:    []map[string]any{receiptFrame},
		TrustedZones:     map[string]map[string]any{coordinator["zid"].(string): coordinator},
		ArtifactBytes:    func(artifact map[string]any) ([]byte, error) { return artifactBytes, nil },
	}
	return swarmOutputFixture{trustFixture: trustFixture, trust: trust, coordinator: coordinator, coordinatorKey: zoneKey, worker: worker, workerKey: workerKey, evidence: evidence, proof: proof, artifactURI: artifactURI, artifactBytes: artifactBytes}
}

func newTwoStepSwarmOutputFixture(t *testing.T) swarmOutputFixture {
	t.Helper()
	trustFixture := newTrustFixture(t)
	trust, err := NewTrustInputsForTest(trustFixture.allowlist, trustFixture.trustedZones, trustFixture.revocations)
	if err != nil {
		t.Fatal(err)
	}
	zonePub, zoneKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	workerPub, workerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	coordinator := signedDescriptor(t, zoneKey, "zone_signature", map[string]any{"name": "zone://u5-output/go-two-step", "zid": zidFromSPKI(spkiBytes(t, zonePub)), "public_key_spki": spki(t, zonePub)})
	worker := signedDescriptor(t, workerKey, "descriptor_signature", map[string]any{"alias": "agent://u5-output/go-two-step-worker", "aid": aidFromSPKI(spkiBytes(t, workerPub)), "did_key": mustDidKey(t, spki(t, workerPub)), "public_key_spki": spki(t, workerPub), "transports": []any{"asp+local://u5-go"}, "capabilities": []any{"summarize.text"}, "policy": map[string]any{"allow_network": false, "write_prefixes": []any{"artifact://local/"}}})
	steps := []any{map[string]any{"step_id": "draft", "capability": "summarize.text", "depends_on": []any{}}, map[string]any{"step_id": "final", "capability": "summarize.text", "depends_on": []any{"draft"}}}
	intent := "Produce a two-step Go Swarm result."
	planDigest := digestNodeCanonical(map[string]any{"intent": intent, "steps": steps})
	planBody := map[string]any{"swarm_id": "swarm://u5-output/go-two-step", "intent": intent, "steps": steps, "policy_digest": strings.Repeat("a", 64), "plan_digest": planDigest}
	planFrame := map[string]any{"type": "FED_SWARM_PLAN", "zone": coordinator, "plan": signNodeCanonical(t, zoneKey, "plan_signature", planBody)}
	taskBodies := []map[string]any{{"task_id": "u5_go_draft", "from": worker["aid"], "to": worker["alias"], "intent": "Complete draft."}, {"task_id": "u5_go_final", "from": worker["aid"], "to": worker["alias"], "intent": "Complete final."}}
	signedTasks := []map[string]any{signNodeCanonical(t, workerKey, "signature", taskBodies[0]), signNodeCanonical(t, workerKey, "signature", taskBodies[1])}
	bindingSteps := []any{map[string]any{"step_id": "draft", "depends_on": []any{}, "capability": "summarize.text", "task_digest": digestNodeCanonical(signedTasks[0])}, map[string]any{"step_id": "final", "depends_on": []any{"draft"}, "capability": "summarize.text", "task_digest": digestNodeCanonical(signedTasks[1])}}
	graphDigest := digestNodeCanonical(map[string]any{"swarm_id": planBody["swarm_id"], "plan_digest": planDigest, "steps": bindingSteps})
	bindingBody := map[string]any{"format": "asp-swarm-execution-binding/v1", "swarm_id": planBody["swarm_id"], "plan_digest": planDigest, "steps": bindingSteps, "execution_graph_digest": graphDigest}
	binding := signNodeCanonical(t, zoneKey, "binding_signature", bindingBody)
	artifactBytes := []byte("go u5 final output bytes\n")
	artifactBytesByStep := map[string][]byte{"draft": []byte("go u5 draft output bytes\n"), "final": artifactBytes}
	receiptFrames := make([]map[string]any, 0, 2)
	completed := map[string]map[string]any{}
	for index, stepID := range []string{"draft", "final"} {
		bytesForStep := artifactBytesByStep[stepID]
		artifactHash := sha256.Sum256(bytesForStep)
		artifactSHA := hex.EncodeToString(artifactHash[:])
		artifactURI := "artifact://local/u5-go/" + stepID + ".txt"
		manifestBody := map[string]any{"uri": artifactURI, "sha256": artifactSHA, "size": float64(len(bytesForStep)), "media_type": "text/plain", "afp": "afp:sha256:" + artifactSHA}
		manifest := cloneJSONMap(t, manifestBody)
		manifest["manifest_hash"] = digestNodeCanonical(manifestBody)
		resultArtifact := map[string]any{"uri": artifactURI, "sha256": artifactSHA, "manifest_hash": manifest["manifest_hash"]}
		after := []any{}
		inputArtifacts := []any{}
		if stepID == "final" {
			draftReceipt := completed["draft"]
			draftDigest, err := SignedReceiptDigest(draftReceipt)
			if err != nil {
				t.Fatal(err)
			}
			draftArtifact := draftReceipt["result_artifact"].(map[string]any)
			after = []any{"draft"}
			inputArtifacts = append(inputArtifacts, map[string]any{"step_id": "draft", "uri": draftArtifact["uri"], "sha256": draftArtifact["sha256"], "manifest_hash": draftArtifact["manifest_hash"], "signed_receipt_digest": draftDigest})
		}
		swarm := map[string]any{"swarm_id": planBody["swarm_id"], "step_id": stepID, "after": after, "plan_digest": planDigest, "execution_graph_digest": graphDigest, "capability": "summarize.text", "task_digest": digestNodeCanonical(signedTasks[index])}
		if len(inputArtifacts) > 0 {
			swarm["input_artifacts"] = inputArtifacts
		}
		receiptBody := map[string]any{"task_id": signedTasks[index]["task_id"], "task_digest": digestNodeCanonical(signedTasks[index]), "origin_zone": coordinator["zid"], "executing_zone": coordinator["zid"], "to": worker["aid"], "artifact_refs": []any{artifactURI}, "artifact_manifests": []any{manifest}, "result_artifact": resultArtifact, "swarm": swarm}
		signedReceipt := signNodeCanonical(t, workerKey, "signature", receiptBody)
		receiptFrames = append(receiptFrames, map[string]any{"type": "FED_RECEIPT", "zone": coordinator, "worker": worker, "zone_binding": signNodeCanonical(t, zoneKey, "signature", map[string]any{"zone": coordinator["zid"], "alias": worker["alias"], "aid": worker["aid"]}), "receipt": signedReceipt})
		completed[stepID] = signedReceipt
	}
	finalOutput, err := DeriveSwarmFinalOutput(binding, completed)
	if err != nil {
		t.Fatal(err)
	}
	stepReceipts := []any{}
	for _, stepID := range []string{"draft", "final"} {
		digest, err := SignedReceiptDigest(completed[stepID])
		if err != nil {
			t.Fatal(err)
		}
		stepReceipts = append(stepReceipts, map[string]any{"step_id": stepID, "task_id": completed[stepID]["task_id"], "signed_receipt_digest": digest})
	}
	closeBody := map[string]any{"format": "asp-swarm-close/v2", "swarm_id": planBody["swarm_id"], "plan_digest": planDigest, "execution_graph_digest": graphDigest, "step_receipts": stepReceipts, "final_output": finalOutput}
	closeFrame := map[string]any{"type": "FED_SWARM_CLOSE", "swarm_id": planBody["swarm_id"], "zone": coordinator, "close": signNodeCanonical(t, zoneKey, "close_signature", closeBody)}
	proofBody := map[string]any{"format": "asp-swarm-output-verification/v1", "verification_id": "u5-go-two-step", "verified_at": "2026-07-11T11:59:00Z", "swarm_id": planBody["swarm_id"], "plan_digest": planDigest, "execution_graph_digest": graphDigest, "close_digest": digestNodeCanonical(closeFrame["close"]), "final_output": finalOutput, "verifier_aid": trustFixture.verifier["aid"], "verifier_zone": trustFixture.zone["zid"], "trust_inputs_digest": trust.TrustInputsDigest}
	proof := map[string]any{"type": "FED_SWARM_OUTPUT_VERIFICATION", "verifier": trustFixture.verifier, "verifier_zone": trustFixture.zone, "verifier_zone_binding": trustFixture.allowlist["verifiers"].([]any)[0].(map[string]any)["zone_binding"], "proof": signNodeCanonical(t, trustFixture.verifierKey, "proof_signature", proofBody)}
	evidence := OutputEvidence{Proof: proof, PlanFrame: planFrame, ExecutionBinding: binding, ExecutableSteps: []map[string]any{{"step_id": "draft", "depends_on": []any{}, "task": signedTasks[0]}, {"step_id": "final", "depends_on": []any{"draft"}, "task": signedTasks[1]}}, ResolvedWorkers: []map[string]any{worker, worker}, CloseFrame: closeFrame, ReceiptFrames: receiptFrames, TrustedZones: map[string]map[string]any{coordinator["zid"].(string): coordinator}, ArtifactBytes: func(artifact map[string]any) ([]byte, error) {
		return artifactBytesByStep[strings.TrimSuffix(strings.TrimPrefix(artifact["uri"].(string), "artifact://local/u5-go/"), ".txt")], nil
	}}
	return swarmOutputFixture{trustFixture: trustFixture, trust: trust, coordinator: coordinator, coordinatorKey: zoneKey, worker: worker, workerKey: workerKey, evidence: evidence, proof: proof, artifactURI: "artifact://local/u5-go/final.txt", artifactBytes: artifactBytes}
}

func resignSwarmOutputCloseAndProof(t *testing.T, fixture *swarmOutputFixture, mutateClose func(map[string]any)) {
	t.Helper()
	closeBody := cloneJSONMap(t, fixture.evidence.CloseFrame["close"].(map[string]any))
	delete(closeBody, "close_signature")
	mutateClose(closeBody)
	signedClose := signNodeCanonical(t, fixture.coordinatorKey, "close_signature", closeBody)
	fixture.evidence.CloseFrame = map[string]any{"type": "FED_SWARM_CLOSE", "swarm_id": closeBody["swarm_id"], "zone": fixture.coordinator, "close": signedClose}
	proofBody := cloneJSONMap(t, fixture.evidence.Proof["proof"].(map[string]any))
	delete(proofBody, "proof_signature")
	proofBody["close_digest"] = digestNodeCanonical(signedClose)
	proofBody["final_output"] = closeBody["final_output"]
	fixture.evidence.Proof["proof"] = signNodeCanonical(t, fixture.trustFixture.verifierKey, "proof_signature", proofBody)
}

func TestVerifySwarmOutputCloseStepReceiptsExactSet(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{"extra phantom close receipt", func(close map[string]any) {
			close["step_receipts"] = append(close["step_receipts"].([]any), map[string]any{"step_id": "phantom", "task_id": "u5_go_phantom", "signed_receipt_digest": strings.Repeat("0", 64)})
		}, "close signed receipt"},
		{"omitted dependency close receipt", func(close map[string]any) {
			kept := []any{}
			for _, item := range close["step_receipts"].([]any) {
				if item.(map[string]any)["step_id"] != "draft" {
					kept = append(kept, item)
				}
			}
			close["step_receipts"] = kept
		}, "close signed receipt"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newTwoStepSwarmOutputFixture(t)
			resignSwarmOutputCloseAndProof(t, &fixture, tc.mutate)
			_, err := VerifySwarmOutput(fixture.evidence, fixture.trust, time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC))
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tc.want)) {
				t.Fatalf("error=%v, want %q", err, tc.want)
			}
		})
	}
}

func TestVerifySwarmOutputTimestampGrammarParity(t *testing.T) {
	accepted := []string{"2026-07-11T11:59:00Z", "2026-07-11T11:59:00.1Z", "2026-07-11T11:59:00.12Z", "2026-07-11T11:59:00.123Z"}
	for _, verifiedAt := range accepted {
		t.Run("accept "+verifiedAt, func(t *testing.T) {
			fixture := newSwarmOutputFixture(t)
			proofBody := fixture.evidence.Proof["proof"].(map[string]any)
			proofBody["verified_at"] = verifiedAt
			delete(proofBody, "proof_signature")
			fixture.evidence.Proof["proof"] = signNodeCanonical(t, fixture.trustFixture.verifierKey, "proof_signature", proofBody)
			if _, err := VerifySwarmOutput(fixture.evidence, fixture.trust, time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)); err != nil {
				t.Fatal(err)
			}
		})
	}
	rejected := []string{"2026-07-11T11:59:00+00:00", "2026-07-11T11:59:00z", "2026-07-11T11:59:00.1234Z", "2026-07-11T12:05:01Z"}
	for _, verifiedAt := range rejected {
		t.Run("reject "+verifiedAt, func(t *testing.T) {
			fixture := newSwarmOutputFixture(t)
			proofBody := fixture.evidence.Proof["proof"].(map[string]any)
			proofBody["verified_at"] = verifiedAt
			delete(proofBody, "proof_signature")
			fixture.evidence.Proof["proof"] = signNodeCanonical(t, fixture.trustFixture.verifierKey, "proof_signature", proofBody)
			_, err := VerifySwarmOutput(fixture.evidence, fixture.trust, time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC))
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), "verified_at") {
				t.Fatalf("error=%v, want verified_at", err)
			}
		})
	}
}

func TestVerifySwarmOutputProofSchemaCanonicalFields(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{"empty verification id", func(proof map[string]any) { proof["verification_id"] = "" }, "verification_id"},
		{"noncanonical verification id", func(proof map[string]any) { proof["verification_id"] = "u5\u2028bad" }, "canonical string domain"},
		{"empty swarm id", func(proof map[string]any) { proof["swarm_id"] = "" }, "swarm_id"},
		{"nul swarm id", func(proof map[string]any) { proof["swarm_id"] = "swarm://bad\x00id" }, "swarm_id"},
		{"non object final output", func(proof map[string]any) { proof["final_output"] = "not-object" }, "final_output"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newSwarmOutputFixture(t)
			proofBody := fixture.evidence.Proof["proof"].(map[string]any)
			tc.mutate(proofBody)
			delete(proofBody, "proof_signature")
			fixture.evidence.Proof["proof"] = signNodeCanonical(t, fixture.trustFixture.verifierKey, "proof_signature", proofBody)
			_, err := VerifySwarmOutput(fixture.evidence, fixture.trust, time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC))
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tc.want)) {
				t.Fatalf("error=%v, want %q", err, tc.want)
			}
		})
	}
}

func TestNonnegativeIntegralNumberSafeIntegerParity(t *testing.T) {
	const jsMaxSafeInteger int64 = 9007199254740991
	cases := []struct {
		name  string
		value any
		want  bool
	}{
		{"float64 zero", float64(0), true},
		{"float64 max safe", float64(jsMaxSafeInteger), true},
		{"float64 over max safe", float64(jsMaxSafeInteger + 1), false},
		{"float64 negative", float64(-1), false},
		{"float64 fractional", 1.5, false},
		{"float64 nan", math.NaN(), false},
		{"float64 positive infinity", math.Inf(1), false},
		{"float64 negative infinity", math.Inf(-1), false},
		{"int max safe", int(jsMaxSafeInteger), true},
		{"int over max safe", int(jsMaxSafeInteger + 1), false},
		{"int negative", int(-1), false},
		{"int64 max safe", jsMaxSafeInteger, true},
		{"int64 over max safe", jsMaxSafeInteger + 1, false},
		{"int64 negative", int64(-1), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := nonnegativeIntegralNumber(tc.value); got != tc.want {
				t.Fatalf("nonnegativeIntegralNumber(%T(%v)) = %v, want %v", tc.value, tc.value, got, tc.want)
			}
		})
	}
}

func TestVerifySwarmOutputCloseAuxiliaryEvidence(t *testing.T) {
	validMicroContract := func(t *testing.T, fixture *swarmOutputFixture, step map[string]any) map[string]any {
		t.Helper()
		body := map[string]any{"micro_contract": "ok", "swarm_id": fixture.evidence.CloseFrame["close"].(map[string]any)["swarm_id"], "step_id": step["step_id"], "worker": fixture.worker, "cost_estimate": map[string]any{"tokens": float64(1), "seconds": float64(1)}, "capability_proof": "local-capability", "policy_digest": strings.Repeat("a", 64)}
		contract := signNodeCanonical(t, fixture.workerKey, "signature", body)
		contract["contract_digest"] = digestNodeCanonical(body)
		return contract
	}
	microContractWithCost := func(t *testing.T, fixture *swarmOutputFixture, step map[string]any, field string, value any) map[string]any {
		t.Helper()
		body := mapWithoutKeys(validMicroContract(t, fixture, step), "contract_digest", "signature")
		body["cost_estimate"].(map[string]any)[field] = value
		contract := signNodeCanonical(t, fixture.workerKey, "signature", body)
		contract["contract_digest"] = digestNodeCanonical(body)
		return contract
	}
	validResolution := func(t *testing.T, fixture *swarmOutputFixture) map[string]any {
		t.Helper()
		body := map[string]any{"swarm_id": fixture.evidence.CloseFrame["close"].(map[string]any)["swarm_id"], "artifact_ref": "artifact://local/u5-go/conflict.txt", "candidate_step_ids": []any{"draft", "final"}, "chosen_step_id": "final", "chosen_worker": fixture.worker, "reason": "alias_tiebreak"}
		resolution := signNodeCanonical(t, fixture.coordinatorKey, "signature", body)
		resolution["resolution_digest"] = digestNodeCanonical(body)
		return resolution
	}
	cases := []struct {
		name   string
		base   func(*testing.T) swarmOutputFixture
		mutate func(*testing.T, *swarmOutputFixture, map[string]any)
		want   string
	}{
		{"bad scheduler mode", newTwoStepSwarmOutputFixture, func(t *testing.T, f *swarmOutputFixture, close map[string]any) {
			close["scheduler"] = map[string]any{"mode": "serial", "step_order": []any{"draft", "final"}}
		}, "scheduler mode"},
		{"bad scheduler step order", newTwoStepSwarmOutputFixture, func(t *testing.T, f *swarmOutputFixture, close map[string]any) {
			close["scheduler"] = map[string]any{"mode": "ready-dag", "step_order": []any{"draft", "missing"}}
		}, "scheduler step missing"},
		{"bad migration log", newSwarmOutputFixture, func(t *testing.T, f *swarmOutputFixture, close map[string]any) {
			close["migration_log"] = []any{map[string]any{"step_id": "summary", "original_worker_aid": f.worker["aid"], "migrated_to_worker_aid": f.worker["aid"], "reason": "test", "migration_at": "2026-07-11T11:59:00+00:00"}}
		}, "migration_at"},
		{"bad micro contract digest", newSwarmOutputFixture, func(t *testing.T, f *swarmOutputFixture, close map[string]any) {
			step := close["step_receipts"].([]any)[0].(map[string]any)
			step["worker"] = f.worker
			contract := validMicroContract(t, f, step)
			contract["contract_digest"] = strings.Repeat("b", 64)
			close["micro_contracts"] = []any{contract}
		}, "micro-contract digest"},
		{"bad micro contract signature", newSwarmOutputFixture, func(t *testing.T, f *swarmOutputFixture, close map[string]any) {
			step := close["step_receipts"].([]any)[0].(map[string]any)
			step["worker"] = f.worker
			contract := validMicroContract(t, f, step)
			contract["signature"] = "bad"
			close["micro_contracts"] = []any{contract}
		}, "micro-contract signature"},
		{"bad conflict candidates", newTwoStepSwarmOutputFixture, func(t *testing.T, f *swarmOutputFixture, close map[string]any) {
			for _, item := range close["step_receipts"].([]any) {
				if item.(map[string]any)["step_id"] == "final" {
					item.(map[string]any)["worker"] = f.worker
				}
			}
			resolution := validResolution(t, f)
			resolution["candidate_step_ids"] = []any{"final"}
			close["conflict_resolutions"] = []any{resolution}
		}, "conflict resolution candidates"},
		{"bad conflict signature", newTwoStepSwarmOutputFixture, func(t *testing.T, f *swarmOutputFixture, close map[string]any) {
			for _, item := range close["step_receipts"].([]any) {
				if item.(map[string]any)["step_id"] == "final" {
					item.(map[string]any)["worker"] = f.worker
				}
			}
			resolution := validResolution(t, f)
			resolution["signature"] = "bad"
			close["conflict_resolutions"] = []any{resolution}
		}, "conflict resolution signature"},
		{"bad micro contract over max safe cost", newSwarmOutputFixture, func(t *testing.T, f *swarmOutputFixture, close map[string]any) {
			step := close["step_receipts"].([]any)[0].(map[string]any)
			step["worker"] = f.worker
			close["micro_contracts"] = []any{microContractWithCost(t, f, step, "tokens", float64(9007199254740992))}
		}, "micro-contract cost"},
		{"bad micro contract negative cost", newSwarmOutputFixture, func(t *testing.T, f *swarmOutputFixture, close map[string]any) {
			step := close["step_receipts"].([]any)[0].(map[string]any)
			step["worker"] = f.worker
			close["micro_contracts"] = []any{microContractWithCost(t, f, step, "tokens", float64(-1))}
		}, "micro-contract cost"},
		{"bad micro contract fractional cost", newSwarmOutputFixture, func(t *testing.T, f *swarmOutputFixture, close map[string]any) {
			step := close["step_receipts"].([]any)[0].(map[string]any)
			step["worker"] = f.worker
			close["micro_contracts"] = []any{microContractWithCost(t, f, step, "seconds", 1.5)}
		}, "micro-contract cost"},
		{"bad micro contract int over max safe cost", newSwarmOutputFixture, func(t *testing.T, f *swarmOutputFixture, close map[string]any) {
			step := close["step_receipts"].([]any)[0].(map[string]any)
			step["worker"] = f.worker
			close["micro_contracts"] = []any{microContractWithCost(t, f, step, "tokens", int(9007199254740992))}
		}, "micro-contract cost"},
		{"bad micro contract int64 over max safe cost", newSwarmOutputFixture, func(t *testing.T, f *swarmOutputFixture, close map[string]any) {
			step := close["step_receipts"].([]any)[0].(map[string]any)
			step["worker"] = f.worker
			close["micro_contracts"] = []any{microContractWithCost(t, f, step, "seconds", int64(9007199254740992))}
		}, "micro-contract cost"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := tc.base(t)
			resignSwarmOutputCloseAndProof(t, &fixture, func(close map[string]any) { tc.mutate(t, &fixture, close) })
			_, err := VerifySwarmOutput(fixture.evidence, fixture.trust, time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC))
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tc.want)) {
				t.Fatalf("error=%v, want %q", err, tc.want)
			}
		})
	}
}
func TestVerifySwarmOutputRecomputesProofAndRejectsMismatchMatrix(t *testing.T) {
	fixture := newSwarmOutputFixture(t)
	verified, err := VerifySwarmOutput(fixture.evidence, fixture.trust, time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if verified.CloseDigest != digestNodeCanonical(fixture.evidence.CloseFrame["close"]) || verified.ProofDigest != digestNodeCanonical(fixture.proof["proof"]) || verified.TrustInputsDigest != fixture.trust.TrustInputsDigest {
		t.Fatalf("unexpected digests: %#v", verified)
	}
	if len(verified.CloseBytes) == 0 || len(verified.ProofBytes) == 0 || verified.FinalOutput["selection_rule"] != "single-terminal-result" {
		t.Fatalf("unexpected verified output: %#v", verified)
	}

	cases := []struct {
		name   string
		mutate func(*swarmOutputFixture)
		want   string
	}{
		{"plan mismatch", func(f *swarmOutputFixture) { f.evidence.PlanFrame["plan"].(map[string]any)["intent"] = "tampered" }, "swarm plan"},
		{"binding mismatch", func(f *swarmOutputFixture) {
			f.evidence.ExecutionBinding["steps"].([]any)[0].(map[string]any)["task_digest"] = strings.Repeat("b", 64)
		}, "execution binding"},
		{"graph mismatch", func(f *swarmOutputFixture) {
			f.evidence.ExecutionBinding["execution_graph_digest"] = strings.Repeat("c", 64)
		}, "execution binding"},
		{"close mismatch", func(f *swarmOutputFixture) {
			f.evidence.CloseFrame["close"].(map[string]any)["plan_digest"] = strings.Repeat("d", 64)
		}, "swarm close signature verification failed"},
		{"receipt mismatch", func(f *swarmOutputFixture) {
			f.evidence.ReceiptFrames[0]["receipt"].(map[string]any)["signature"] = "bad"
		}, "receipt"},
		{"result uri mismatch", func(f *swarmOutputFixture) {
			receipt := f.evidence.ReceiptFrames[0]["receipt"].(map[string]any)
			old := receipt["result_artifact"].(map[string]any)
			receipt["result_artifact"] = map[string]any{"uri": "artifact://local/u5-go/missing.txt", "sha256": old["sha256"], "manifest_hash": old["manifest_hash"]}
			delete(receipt, "signature")
			f.evidence.ReceiptFrames[0]["receipt"] = signNodeCanonical(t, f.workerKey, "signature", receipt)
		}, "result artifact"},
		{"manifest mismatch", func(f *swarmOutputFixture) {
			receipt := f.evidence.ReceiptFrames[0]["receipt"].(map[string]any)
			receipt["artifact_manifests"].([]any)[0].(map[string]any)["manifest_hash"] = strings.Repeat("e", 64)
			delete(receipt, "signature")
			f.evidence.ReceiptFrames[0]["receipt"] = signNodeCanonical(t, f.workerKey, "signature", receipt)
		}, "artifact manifest hash mismatch"},
		{"bytes mismatch", func(f *swarmOutputFixture) {
			f.evidence.ArtifactBytes = func(map[string]any) ([]byte, error) { return bytes.Repeat([]byte("a"), len(f.artifactBytes)), nil }
		}, "artifact bytes digest mismatch"},
		{"trust digest mismatch", func(f *swarmOutputFixture) {
			proofBody := f.evidence.Proof["proof"].(map[string]any)
			proofBody["trust_inputs_digest"] = strings.Repeat("f", 64)
			delete(proofBody, "proof_signature")
			f.evidence.Proof["proof"] = signNodeCanonical(t, f.trustFixture.verifierKey, "proof_signature", proofBody)
		}, "trust inputs digest mismatch"},
		{"bad signature", func(f *swarmOutputFixture) { f.evidence.Proof["proof"].(map[string]any)["proof_signature"] = "bad" }, "proof signature"},
		{"future timestamp", func(f *swarmOutputFixture) {
			proofBody := f.evidence.Proof["proof"].(map[string]any)
			proofBody["verified_at"] = "2026-07-11T12:06:01Z"
			delete(proofBody, "proof_signature")
			f.evidence.Proof["proof"] = signNodeCanonical(t, f.trustFixture.verifierKey, "proof_signature", proofBody)
		}, "verified_at"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fresh := newSwarmOutputFixture(t)
			tc.mutate(&fresh)
			_, err := VerifySwarmOutput(fresh.evidence, fresh.trust, time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC))
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tc.want)) {
				t.Fatalf("error=%v, want %q", err, tc.want)
			}
		})
	}
}

type replayTestStore struct {
	records map[string]VerificationReplayRecord
	tracer  []string
	put     func(VerificationReplayRecord) (VerificationReplayRecord, bool, error)
}

func newReplayTestStore() *replayTestStore {
	return &replayTestStore{records: map[string]VerificationReplayRecord{}}
}

func (s *replayTestStore) LookupVerificationReplay(verificationID string) (VerificationReplayRecord, bool, error) {
	s.tracer = append(s.tracer, "lookup")
	record, ok := s.records[verificationID]
	if !ok {
		return VerificationReplayRecord{}, false, nil
	}
	clone, err := CloneVerificationReplayRecord(record)
	if err != nil {
		return VerificationReplayRecord{}, false, err
	}
	return clone, true, nil
}

func (s *replayTestStore) PutVerificationReplayIfAbsent(record VerificationReplayRecord) (VerificationReplayRecord, bool, error) {
	s.tracer = append(s.tracer, "put")
	if s.put != nil {
		return s.put(record)
	}
	if existing, ok := s.records[record.VerificationID]; ok {
		clone, err := CloneVerificationReplayRecord(existing)
		if err != nil {
			return VerificationReplayRecord{}, false, err
		}
		return clone, false, nil
	}
	stored, err := CloneVerificationReplayRecord(record)
	if err != nil {
		return VerificationReplayRecord{}, false, err
	}
	s.records[record.VerificationID] = stored
	clone, err := CloneVerificationReplayRecord(stored)
	if err != nil {
		return VerificationReplayRecord{}, false, err
	}
	return clone, true, nil
}

func TestApplySwarmOutputVerificationReplay(t *testing.T) {
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	fixture := newSwarmOutputFixture(t)
	verified, err := VerifySwarmOutput(fixture.evidence, fixture.trust, now)
	if err != nil {
		t.Fatal(err)
	}
	store := newReplayTestStore()

	accepted, err := ApplySwarmOutputVerification(fixture.evidence, fixture.trust, store, now, verified.CloseDigest)
	if err != nil {
		t.Fatal(err)
	}
	if accepted.ReplayDecision != "accepted" || !accepted.StoreMutated || accepted.VerificationID != "u5-go-positive" {
		t.Fatalf("accepted=%+v", accepted)
	}
	if accepted.CanonicalProofSHA256 != digestBytesHex(verified.ProofBytes) || accepted.StoredCloseDigest != verified.CloseDigest || accepted.ProofCloseDigest != verified.CloseDigest {
		t.Fatalf("unexpected replay digests: %+v", accepted)
	}
	if accepted.CloseDigest != verified.CloseDigest || accepted.ProofDigest != verified.ProofDigest || accepted.TrustInputsDigest != verified.TrustInputsDigest {
		t.Fatalf("unexpected scheduler digests: %+v", accepted)
	}
	if !bytes.Equal(accepted.CloseBytes, verified.CloseBytes) || !bytes.Equal(accepted.ProofBytes, verified.ProofBytes) || accepted.FinalOutput["selection_rule"] != "single-terminal-result" || !accepted.CompletionGate {
		t.Fatalf("unexpected scheduler completion: %+v", accepted)
	}
	if strings.Join(store.tracer, ",") != "put" {
		t.Fatalf("mutation ordering = %v", store.tracer)
	}

	formattingOnly := cloneJSONMap(t, fixture.evidence.Proof)
	fixture.evidence.Proof = formattingOnly
	idempotent, err := ApplySwarmOutputVerification(fixture.evidence, fixture.trust, store, now, verified.CloseDigest)
	if err != nil {
		t.Fatal(err)
	}
	if idempotent.ReplayDecision != "idempotent" || idempotent.StoreMutated || idempotent.CanonicalProofSHA256 != accepted.CanonicalProofSHA256 {
		t.Fatalf("idempotent=%+v", idempotent)
	}

	changed := fixture
	changed.evidence.Proof = cloneJSONMap(t, fixture.proof)
	proofBody := cloneJSONMap(t, changed.evidence.Proof["proof"].(map[string]any))
	delete(proofBody, "proof_signature")
	proofBody["verified_at"] = "2026-07-11T11:58:59Z"
	changed.evidence.Proof["proof"] = signNodeCanonical(t, fixture.trustFixture.verifierKey, "proof_signature", proofBody)
	conflict, err := ApplySwarmOutputVerification(changed.evidence, changed.trust, store, now, verified.CloseDigest)
	if err != nil {
		t.Fatal(err)
	}
	if conflict.ReplayDecision != "conflict" || conflict.StoreMutated || conflict.CompletionGate || len(store.records) != 1 {
		t.Fatalf("conflict=%+v records=%d", conflict, len(store.records))
	}

	for _, storedCloseDigest := range []string{"", strings.Repeat("0", 64)} {
		corruptStore := newReplayTestStore()
		if _, err := ApplySwarmOutputVerification(fixture.evidence, fixture.trust, corruptStore, now, verified.CloseDigest); err != nil {
			t.Fatal(err)
		}
		corrupt := corruptStore.records["u5-go-positive"]
		corrupt.StoredCloseDigest = storedCloseDigest
		corruptStore.records["u5-go-positive"] = corrupt
		completion, err := ApplySwarmOutputVerification(fixture.evidence, fixture.trust, corruptStore, now, verified.CloseDigest)
		if err != nil {
			t.Fatal(err)
		}
		if completion.ReplayDecision != "conflict" || completion.StoreMutated || completion.CompletionGate {
			t.Fatalf("stored_close_digest %q completion=%+v", storedCloseDigest, completion)
		}
	}

	recordFixture := newSwarmOutputFixture(t)
	recordVerified, err := VerifySwarmOutput(recordFixture.evidence, recordFixture.trust, now)
	if err != nil {
		t.Fatal(err)
	}
	replayProofBody := recordFixture.evidence.Proof["proof"].(map[string]any)
	replayProofBody["verification_id"] = "mutated-after-verify"
	replayProofBody["verified_at"] = "2020-01-01T00:00:00Z"
	replayProofBody["verifier_aid"] = "aid:ed25519:mutated"
	replayProofBody["verifier_zone"] = "zid:mutated"
	replayProofBody["proof_signature"] = "mutated-signature"
	snapshotRecord, err := verificationReplayRecord(recordVerified)
	if err != nil {
		t.Fatal(err)
	}
	if snapshotRecord.VerificationID != "u5-go-positive" || snapshotRecord.VerifiedAt != "2026-07-11T11:59:00Z" || snapshotRecord.VerifierAID != recordFixture.trustFixture.verifier["aid"] || snapshotRecord.VerifierZone != recordFixture.trustFixture.zone["zid"] || !bytes.Equal(snapshotRecord.CanonicalProofBytes, recordVerified.ProofBytes) || bytes.Contains(snapshotRecord.CanonicalProofBytes, []byte("mutated-signature")) {
		t.Fatalf("record re-read mutable proof after verify: %+v", snapshotRecord)
	}

	aliasStore := newReplayTestStore()
	aliasRecord, err := verificationReplayRecord(verified)
	if err != nil {
		t.Fatal(err)
	}
	if _, inserted, err := aliasStore.PutVerificationReplayIfAbsent(aliasRecord); err != nil || !inserted {
		t.Fatalf("put inserted=%v err=%v", inserted, err)
	}
	aliasRecord.CanonicalProofBytes[0] ^= 0xff
	aliasRecord.CanonicalCloseBytes[0] ^= 0xff
	aliasRecord.FinalOutput["selection_rule"] = "mutated-original"
	lookupAlias, ok, err := aliasStore.LookupVerificationReplay("u5-go-positive")
	if err != nil || !ok {
		t.Fatalf("lookup ok=%v err=%v", ok, err)
	}
	lookupAlias.CanonicalProofBytes[0] ^= 0xff
	lookupAlias.CanonicalCloseBytes[0] ^= 0xff
	lookupAlias.FinalOutput["selection_rule"] = "mutated-lookup"
	lookupAgain, ok, err := aliasStore.LookupVerificationReplay("u5-go-positive")
	if err != nil || !ok {
		t.Fatalf("second lookup ok=%v err=%v", ok, err)
	}
	if !bytes.Equal(lookupAgain.CanonicalProofBytes, verified.ProofBytes) || !bytes.Equal(lookupAgain.CanonicalCloseBytes, verified.CloseBytes) || lookupAgain.FinalOutput["selection_rule"] != "single-terminal-result" {
		t.Fatalf("lookup aliased mutable state: %+v", lookupAgain)
	}
	aliasAccepted, err := ApplySwarmOutputVerification(fixture.evidence, fixture.trust, aliasStore, now, verified.CloseDigest)
	if err != nil {
		t.Fatal(err)
	}
	if aliasAccepted.ReplayDecision != "idempotent" || !aliasAccepted.CompletionGate {
		t.Fatalf("alias idempotent=%+v", aliasAccepted)
	}
	aliasAccepted.CloseBytes[0] ^= 0xff
	aliasAccepted.ProofBytes[0] ^= 0xff
	aliasAccepted.FinalOutput["selection_rule"] = "mutated-return"
	aliasReturn, err := ApplySwarmOutputVerification(fixture.evidence, fixture.trust, aliasStore, now, verified.CloseDigest)
	if err != nil {
		t.Fatal(err)
	}
	if aliasReturn.ReplayDecision != "idempotent" || !aliasReturn.CompletionGate || aliasReturn.FinalOutput["selection_rule"] != "single-terminal-result" {
		t.Fatalf("alias return=%+v", aliasReturn)
	}

	mismatchStore := newReplayTestStore()
	_, err = ApplySwarmOutputVerification(fixture.evidence, fixture.trust, mismatchStore, now, strings.Repeat("f", 64))
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "close digest mismatch") || len(mismatchStore.records) != 0 {
		t.Fatalf("mismatch err=%v records=%d", err, len(mismatchStore.records))
	}
	otherClose := newTwoStepSwarmOutputFixture(t)
	otherVerified, err := VerifySwarmOutput(otherClose.evidence, otherClose.trust, now)
	if err != nil {
		t.Fatal(err)
	}
	otherCloseStore := newReplayTestStore()
	_, err = ApplySwarmOutputVerification(fixture.evidence, fixture.trust, otherCloseStore, now, otherVerified.CloseDigest)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "close digest mismatch") || len(otherCloseStore.records) != 0 {
		t.Fatalf("other close err=%v records=%d", err, len(otherCloseStore.records))
	}

	invalidStore := newReplayTestStore()
	invalid := newSwarmOutputFixture(t)
	invalid.evidence.Proof["proof"].(map[string]any)["proof_signature"] = "bad"
	_, err = ApplySwarmOutputVerification(invalid.evidence, invalid.trust, invalidStore, now, digestNodeCanonical(invalid.evidence.CloseFrame["close"]))
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "proof signature") || len(invalidStore.records) != 0 {
		t.Fatalf("invalid err=%v records=%d", err, len(invalidStore.records))
	}

	raceStore := newReplayTestStore()
	raceStore.put = func(record VerificationReplayRecord) (VerificationReplayRecord, bool, error) {
		existing := record
		existing.CanonicalProofSHA256 = strings.Repeat("0", 64)
		existing.CanonicalProofBytes = []byte("different")
		raceStore.records[record.VerificationID] = existing
		return existing, false, nil
	}
	race, err := ApplySwarmOutputVerification(fixture.evidence, fixture.trust, raceStore, now, verified.CloseDigest)
	if err != nil {
		t.Fatal(err)
	}
	if race.ReplayDecision != "conflict" || race.StoreMutated {
		t.Fatalf("race=%+v", race)
	}
}

type u7FrozenSwarmOutputVector struct {
	Format       string `json:"format"`
	VectorOrigin string `json:"vector_origin"`
	Timestamps   struct {
		Now string `json:"now"`
	} `json:"timestamps"`
	Seeds struct {
		CoordinatorZone string `json:"coordinator_zone"`
		VerifierAgent   string `json:"verifier_agent"`
	} `json:"seeds"`
	Trust struct {
		Allowlist    map[string]any `json:"allowlist"`
		TrustedZones map[string]any `json:"trusted_zones"`
		Revocations  map[string]any `json:"revocations"`
	} `json:"trust"`
	Evidence struct {
		PlanFrame        map[string]any            `json:"plan_frame"`
		ExecutionBinding map[string]any            `json:"execution_binding"`
		ExecutableSteps  []map[string]any          `json:"executable_steps"`
		ResolvedWorkers  []map[string]any          `json:"resolved_workers"`
		CloseFrame       map[string]any            `json:"close_frame"`
		ReceiptFrames    []map[string]any          `json:"receipt_frames"`
		TrustedZones     map[string]map[string]any `json:"trusted_zones"`
		Artifacts        map[string]string         `json:"artifacts"`
	} `json:"evidence"`
	ProofFrame map[string]any `json:"proof_frame"`
	Expected   struct {
		CloseDigest       string `json:"close_digest"`
		ProofDigest       string `json:"proof_digest"`
		TrustInputsDigest string `json:"trust_inputs_digest"`
		CanonicalClose    string `json:"canonical_close"`
		CanonicalProof    string `json:"canonical_proof"`
	} `json:"expected"`
}

func loadU7FrozenVector(t *testing.T, path string) (u7FrozenSwarmOutputVector, TrustInputs, OutputEvidence, time.Time) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var vector u7FrozenSwarmOutputVector
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	if vector.Format != "asp-swarm-output-vector/v1" {
		t.Fatalf("unexpected vector format: %s", vector.Format)
	}
	trust, evidence, now := u7FrozenVectorInputs(t, vector)
	return vector, trust, evidence, now
}

func u7FrozenVectorInputs(t *testing.T, vector u7FrozenSwarmOutputVector) (TrustInputs, OutputEvidence, time.Time) {
	t.Helper()
	trust, err := NewTrustInputsForTest(vector.Trust.Allowlist, vector.Trust.TrustedZones, vector.Trust.Revocations)
	if err != nil {
		t.Fatal(err)
	}
	now, err := time.Parse(time.RFC3339Nano, vector.Timestamps.Now)
	if err != nil {
		t.Fatal(err)
	}
	evidence := OutputEvidence{
		Proof:            vector.ProofFrame,
		PlanFrame:        vector.Evidence.PlanFrame,
		ExecutionBinding: vector.Evidence.ExecutionBinding,
		ExecutableSteps:  vector.Evidence.ExecutableSteps,
		ResolvedWorkers:  vector.Evidence.ResolvedWorkers,
		CloseFrame:       vector.Evidence.CloseFrame,
		ReceiptFrames:    vector.Evidence.ReceiptFrames,
		TrustedZones:     vector.Evidence.TrustedZones,
		ArtifactBytes: func(artifact map[string]any) ([]byte, error) {
			return base64.RawURLEncoding.DecodeString(vector.Evidence.Artifacts[artifact["uri"].(string)])
		},
	}
	return trust, evidence, now
}

func cloneU7FrozenVector(t *testing.T, vector u7FrozenSwarmOutputVector) u7FrozenSwarmOutputVector {
	t.Helper()
	data, err := json.Marshal(vector)
	if err != nil {
		t.Fatal(err)
	}
	var clone u7FrozenSwarmOutputVector
	if err := json.Unmarshal(data, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}

func u7PrivateKeyFromSeed(t *testing.T, seedHex string) ed25519.PrivateKey {
	t.Helper()
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		t.Fatal(err)
	}
	if len(seed) != ed25519.SeedSize {
		t.Fatalf("seed size = %d, want %d", len(seed), ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func resignU7Close(t *testing.T, vector *u7FrozenSwarmOutputVector, mutate func(map[string]any)) {
	t.Helper()
	body := cloneJSONMap(t, vector.Evidence.CloseFrame["close"].(map[string]any))
	delete(body, "close_signature")
	mutate(body)
	vector.Evidence.CloseFrame["close"] = signNodeCanonical(t, u7PrivateKeyFromSeed(t, vector.Seeds.CoordinatorZone), "close_signature", body)
}

func resignU7Proof(t *testing.T, vector *u7FrozenSwarmOutputVector, mutate func(map[string]any)) {
	t.Helper()
	body := cloneJSONMap(t, vector.ProofFrame["proof"].(map[string]any))
	delete(body, "proof_signature")
	mutate(body)
	vector.ProofFrame["proof"] = signNodeCanonical(t, u7PrivateKeyFromSeed(t, vector.Seeds.VerifierAgent), "proof_signature", body)
}

func assertU7FrozenVectorVerifies(t *testing.T, path, origin string) VerifiedSwarmOutput {
	t.Helper()
	vector, trust, evidence, now := loadU7FrozenVector(t, path)
	if vector.VectorOrigin != origin {
		t.Fatalf("vector origin = %s, want %s", vector.VectorOrigin, origin)
	}
	verified, err := VerifySwarmOutput(evidence, trust, now)
	if err != nil {
		t.Fatal(err)
	}
	if verified.CloseDigest != vector.Expected.CloseDigest || string(verified.CloseBytes) != vector.Expected.CanonicalClose {
		t.Fatalf("close canonical mismatch for %s", path)
	}
	if verified.ProofDigest != vector.Expected.ProofDigest || string(verified.ProofBytes) != vector.Expected.CanonicalProof {
		t.Fatalf("proof canonical mismatch for %s", path)
	}
	if verified.TrustInputsDigest != vector.Expected.TrustInputsDigest {
		t.Fatalf("trust digest = %s, want %s", verified.TrustInputsDigest, vector.Expected.TrustInputsDigest)
	}
	if !strings.Contains(vector.Expected.CanonicalProof, "<>&") || !strings.Contains(vector.Expected.CanonicalClose, "<>&") {
		t.Fatal("vector canonical bytes must include literal <>&")
	}
	return verified
}

func TestU7FrozenSwarmOutputVectorsVerifyInVerifier(t *testing.T) {
	assertU7FrozenVectorVerifies(t, "../test-vectors/asp-u7-node-created-swarm-output.json", "node-created")
	assertU7FrozenVectorVerifies(t, "../test-vectors/asp-u7-go-created-swarm-output.json", "go-created")
}

func TestU7FrozenSwarmOutputVectorMutationParity(t *testing.T) {
	vector, _, _, _ := loadU7FrozenVector(t, "../test-vectors/asp-u7-node-created-swarm-output.json")
	tests := []struct {
		name   string
		mutate func(*u7FrozenSwarmOutputVector)
		want   string
	}{
		{name: "unknown close field", mutate: func(candidate *u7FrozenSwarmOutputVector) {
			resignU7Close(t, candidate, func(body map[string]any) { body["unexpected"] = true })
		}, want: "swarm close v2 fields invalid"},
		{name: "duplicate step receipt", mutate: func(candidate *u7FrozenSwarmOutputVector) {
			resignU7Close(t, candidate, func(body map[string]any) {
				receipts := body["step_receipts"].([]any)
				body["step_receipts"] = []any{receipts[0], receipts[0]}
			})
		}, want: "swarm close duplicate step receipt"},
		{name: "missing close format", mutate: func(candidate *u7FrozenSwarmOutputVector) {
			resignU7Close(t, candidate, func(body map[string]any) { delete(body, "format") })
		}, want: "swarm close v2 fields invalid"},
		{name: "v2 stripped into v1", mutate: func(candidate *u7FrozenSwarmOutputVector) {
			resignU7Close(t, candidate, func(body map[string]any) { body["format"] = "asp-swarm-close/v1" })
		}, want: "swarm close v2 format invalid"},
		{name: "graph mutation", mutate: func(candidate *u7FrozenSwarmOutputVector) {
			resignU7Close(t, candidate, func(body map[string]any) { body["execution_graph_digest"] = strings.Repeat("0", 64) })
		}, want: "close execution graph digest mismatch"},
		{name: "result mutation", mutate: func(candidate *u7FrozenSwarmOutputVector) {
			resignU7Close(t, candidate, func(body map[string]any) {
				body["final_output"].(map[string]any)["artifact"].(map[string]any)["sha256"] = strings.Repeat("1", 64)
			})
		}, want: "final output"},
		{name: "trust mutation", mutate: func(candidate *u7FrozenSwarmOutputVector) {
			resignU7Proof(t, candidate, func(body map[string]any) { body["trust_inputs_digest"] = strings.Repeat("2", 64) })
		}, want: "trust inputs digest mismatch"},
		{name: "timestamp mutation", mutate: func(candidate *u7FrozenSwarmOutputVector) {
			resignU7Proof(t, candidate, func(body map[string]any) { body["verified_at"] = "3026-07-11T00:00:00Z" })
		}, want: "verified_at future skew invalid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			candidate := cloneU7FrozenVector(t, vector)
			tt.mutate(&candidate)
			trust, evidence, now := u7FrozenVectorInputs(t, candidate)
			_, err := VerifySwarmOutput(evidence, trust, now)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestU7FrozenSwarmOutputVectorReplayConflictRejects(t *testing.T) {
	vector, trust, evidence, now := loadU7FrozenVector(t, "../test-vectors/asp-u7-node-created-swarm-output.json")
	store := newReplayTestStore()
	accepted, err := ApplySwarmOutputVerification(evidence, trust, store, now, vector.Expected.CloseDigest)
	if err != nil {
		t.Fatal(err)
	}
	conflicting := cloneU7FrozenVector(t, vector)
	resignU7Proof(t, &conflicting, func(body map[string]any) {
		body["verified_at"] = "2026-07-11T12:34:55Z"
	})
	conflictTrust, conflictEvidence, conflictNow := u7FrozenVectorInputs(t, conflicting)
	replayed, err := ApplySwarmOutputVerification(conflictEvidence, conflictTrust, store, conflictNow, vector.Expected.CloseDigest)
	if err != nil {
		t.Fatal(err)
	}
	if accepted.VerificationID != replayed.VerificationID || replayed.ReplayDecision != "conflict" || replayed.StoreMutated || replayed.CompletionGate {
		t.Fatalf("replay decision = %s mutated=%v gate=%v id=%s, want conflict false false id=%s", replayed.ReplayDecision, replayed.StoreMutated, replayed.CompletionGate, replayed.VerificationID, accepted.VerificationID)
	}
}
