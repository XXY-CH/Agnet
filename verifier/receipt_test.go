package verifier

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyFederatedReceiptVector(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "test-vectors", "asp-v9.25-fed-receipt.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		TrustedZones []map[string]any `json:"trusted_zones"`
		Frame        map[string]any   `json:"frame"`
	}
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	trusted := map[string]map[string]any{}
	for _, zone := range vector.TrustedZones {
		trusted[zone["zid"].(string)] = zone
	}
	if err := VerifyFederatedReceipt(vector.Frame, trusted); err != nil {
		t.Fatal(err)
	}

	wrongTypeFrame := map[string]any{}
	for key, value := range vector.Frame {
		wrongTypeFrame[key] = value
	}
	wrongTypeFrame["type"] = "FED_TASK_OPEN"
	if err := VerifyFederatedReceipt(wrongTypeFrame, trusted); err == nil || !strings.Contains(err.Error(), "expected FED_RECEIPT frame") {
		t.Fatalf("got %v, want expected FED_RECEIPT frame", err)
	}

	receipt := vector.Frame["receipt"].(map[string]any)
	withoutOrigin := map[string]map[string]any{}
	for zid, zone := range trusted {
		withoutOrigin[zid] = zone
	}
	delete(withoutOrigin, receipt["origin_zone"].(string))
	if err := VerifyFederatedReceipt(vector.Frame, withoutOrigin); err == nil || !strings.Contains(err.Error(), "untrusted receipt origin zone") {
		t.Fatalf("got %v, want untrusted receipt origin zone", err)
	}

	withoutTaskDigestReceipt := map[string]any{}
	for key, value := range receipt {
		if key != "task_digest" {
			withoutTaskDigestReceipt[key] = value
		}
	}
	withoutTaskDigestFrame := map[string]any{}
	for key, value := range vector.Frame {
		withoutTaskDigestFrame[key] = value
	}
	withoutTaskDigestFrame["receipt"] = withoutTaskDigestReceipt
	if err := VerifyFederatedReceipt(withoutTaskDigestFrame, trusted); err == nil || !strings.Contains(err.Error(), "receipt task_digest missing") {
		t.Fatalf("got %v, want receipt task_digest missing", err)
	}

	if err := VerifyFederatedReceipt(vector.Frame, trusted, map[string]any{"task_id": receipt["task_id"], "intent": "wrong task"}); err == nil || !strings.Contains(err.Error(), "receipt task_digest mismatch") {
		t.Fatalf("got %v, want receipt task_digest mismatch", err)
	}

	receipt["executing_zone"] = "zid:ed25519:bad"
	if err := VerifyFederatedReceipt(vector.Frame, trusted); err == nil || !strings.Contains(err.Error(), "receipt executing_zone mismatch") {
		t.Fatalf("got %v, want receipt executing_zone mismatch", err)
	}
}

func TestVerifyFederatedReceiptAcceptsNodeCanonicalSpecialChars(t *testing.T) {
	zonePub, zoneKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	workerPub, workerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	zone := signedDescriptor(t, zoneKey, "zone_signature", map[string]any{"zid": zidFromSPKI(spkiBytes(t, zonePub)), "public_key_spki": spki(t, zonePub)})
	worker := signedDescriptor(t, workerKey, "descriptor_signature", map[string]any{"aid": aidFromSPKI(spkiBytes(t, workerPub)), "alias": "worker", "public_key_spki": spki(t, workerPub)})
	binding := signNodeCanonical(t, zoneKey, "signature", map[string]any{"zone": zone["zid"], "alias": worker["alias"], "aid": worker["aid"]})
	signedTask := signNodeCanonical(t, workerKey, "signature", map[string]any{"task_id": "html_chars_task", "intent": "a<b & c>d"})
	receipt := signNodeCanonical(t, workerKey, "signature", map[string]any{
		"task_id":        "html_chars_task",
		"task_digest":    digestNodeCanonical(signedTask),
		"origin_zone":    zone["zid"],
		"executing_zone": zone["zid"],
		"to":             worker["aid"],
		"note":           "a<b & c>d",
	})

	err = VerifyFederatedReceipt(map[string]any{"type": "FED_RECEIPT", "zone": zone, "worker": worker, "zone_binding": binding, "receipt": receipt}, map[string]map[string]any{zone["zid"].(string): zone}, signedTask)
	if err != nil {
		t.Fatal(err)
	}
}

func signedDescriptor(t *testing.T, key ed25519.PrivateKey, signatureKey string, body map[string]any) map[string]any {
	t.Helper()
	return signNodeCanonical(t, key, signatureKey, body)
}

func signNodeCanonical(t *testing.T, key ed25519.PrivateKey, signatureKey string, body map[string]any) map[string]any {
	t.Helper()
	out := map[string]any{}
	for k, v := range body {
		out[k] = v
	}
	out[signatureKey] = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, nodeCanonicalJSON(t, body)))
	return out
}

func digestNodeCanonical(value any) string {
	data := nodeCanonicalJSONNoTest(value)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func nodeCanonicalJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := nodeCanonicalJSONBytes(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func nodeCanonicalJSONNoTest(value any) []byte {
	data, err := nodeCanonicalJSONBytes(value)
	if err != nil {
		panic(err)
	}
	return data
}

func nodeCanonicalJSONBytes(value any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

func spki(t *testing.T, key ed25519.PublicKey) string {
	t.Helper()
	return base64.RawURLEncoding.EncodeToString(spkiBytes(t, key))
}

func spkiBytes(t *testing.T, key ed25519.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestVerifySwarmExecutionBinding(t *testing.T) {
	zonePub, zoneKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	zone := signedDescriptor(t, zoneKey, "zone_signature", map[string]any{
		"zid":             zidFromSPKI(spkiBytes(t, zonePub)),
		"public_key_spki": spki(t, zonePub),
	})
	makeWorker := func(alias string, capabilities []any) map[string]any {
		t.Helper()
		workerPub, workerKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return signedDescriptor(t, workerKey, "descriptor_signature", map[string]any{
			"aid":             aidFromSPKI(spkiBytes(t, workerPub)),
			"alias":           alias,
			"public_key_spki": spki(t, workerPub),
			"capabilities":    capabilities,
		})
	}
	originalWorker := makeWorker("agent://swarm-execution-binding/original", []any{"summarize.text"})
	migratedWorker := makeWorker("agent://swarm-execution-binding/migrated", []any{"summarize.text"})
	planSteps := []any{
		map[string]any{"step_id": "draft", "capability": "summarize.text", "depends_on": []any{}},
		map[string]any{"step_id": "final", "capability": "summarize.text", "depends_on": []any{"draft"}},
	}
	intent := "Draft and finalize a summary."
	planDigest := digestNodeCanonical(map[string]any{"intent": intent, "steps": planSteps})
	plan := signNodeCanonical(t, zoneKey, "plan_signature", map[string]any{
		"swarm_id":      "swarm://go-test/execution-binding",
		"intent":        intent,
		"steps":         planSteps,
		"policy_digest": strings.Repeat("a", 64),
		"plan_digest":   planDigest,
	})
	verifiedPlan := map[string]any{"zone": zone, "plan": plan}
	signedTasks := []map[string]any{
		{"task_id": "binding_draft", "intent": "Draft the summary.", "signature": "task-signature-draft"},
		{"task_id": "binding_final", "intent": "Finalize the summary.", "signature": "task-signature-final"},
	}
	executableSteps := []map[string]any{
		{"step_id": "draft", "depends_on": []any{}, "task": signedTasks[0]},
		{"step_id": "final", "depends_on": []any{"draft"}, "task": signedTasks[1]},
	}
	bindingSteps := []any{
		map[string]any{"step_id": "draft", "depends_on": []any{}, "capability": "summarize.text", "task_digest": digestNodeCanonical(signedTasks[0])},
		map[string]any{"step_id": "final", "depends_on": []any{"draft"}, "capability": "summarize.text", "task_digest": digestNodeCanonical(signedTasks[1])},
	}
	bindingFor := func(swarmID, digest string, steps []any) map[string]any {
		graphDigest := digestNodeCanonical(map[string]any{"swarm_id": swarmID, "plan_digest": digest, "steps": steps})
		return signNodeCanonical(t, zoneKey, "binding_signature", map[string]any{
			"format":                 "asp-swarm-execution-binding/v1",
			"swarm_id":               swarmID,
			"plan_digest":            digest,
			"steps":                  steps,
			"execution_graph_digest": graphDigest,
		})
	}
	binding := bindingFor(plan["swarm_id"].(string), planDigest, bindingSteps)
	resolvedWorkers := []map[string]any{originalWorker, migratedWorker}
	gotDigest, err := VerifySwarmExecutionBinding(binding, verifiedPlan, executableSteps, resolvedWorkers)
	if err != nil {
		t.Fatal(err)
	}
	if gotDigest != binding["execution_graph_digest"] {
		t.Fatalf("got digest %q, want %q", gotDigest, binding["execution_graph_digest"])
	}

	cloneMap := func(source map[string]any) map[string]any {
		out := map[string]any{}
		for key, value := range source {
			out[key] = value
		}
		return out
	}
	wantError := func(name string, candidate map[string]any, candidateSteps []map[string]any, workers []map[string]any, message string) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			_, err := VerifySwarmExecutionBinding(candidate, verifiedPlan, candidateSteps, workers)
			if err == nil || !strings.Contains(err.Error(), message) {
				t.Fatalf("got %v, want %q", err, message)
			}
		})
	}
	wantPlanError := func(name string, steps []any, message string) {
		t.Helper()
		planDigest := digestNodeCanonical(map[string]any{"intent": intent, "steps": steps})
		candidatePlan := signNodeCanonical(t, zoneKey, "plan_signature", map[string]any{
			"swarm_id":      plan["swarm_id"],
			"intent":        intent,
			"steps":         steps,
			"policy_digest": plan["policy_digest"],
			"plan_digest":   planDigest,
		})
		candidateVerifiedPlan := map[string]any{"zone": zone, "plan": candidatePlan}
		candidateBinding := bindingFor(plan["swarm_id"].(string), planDigest, bindingSteps)
		t.Run(name, func(t *testing.T) {
			_, err := VerifySwarmExecutionBinding(candidateBinding, candidateVerifiedPlan, executableSteps, resolvedWorkers)
			if err == nil || !strings.Contains(err.Error(), message) {
				t.Fatalf("got %v, want %q", err, message)
			}
		})
	}
	invalidDependsOnSteps := []any{
		map[string]any{"step_id": "draft", "capability": "summarize.text", "depends_on": nil},
		planSteps[1],
	}
	wantPlanError("explicit null plan dependency", invalidDependsOnSteps, "swarm plan step depends_on invalid")
	for _, testCase := range []struct {
		name       string
		constraint any
	}{
		{name: "null", constraint: nil},
		{name: "array", constraint: []any{}},
		{name: "scalar", constraint: "invalid"},
	} {
		invalidConstraintSteps := []any{
			map[string]any{"step_id": "draft", "capability": "summarize.text", "depends_on": []any{}, "constraint": testCase.constraint},
			planSteps[1],
		}
		wantPlanError("malformed plan constraint "+testCase.name, invalidConstraintSteps, "swarm plan step constraint invalid")
	}
	wantError("wrong swarm id", bindingFor("swarm://go-test/substituted", planDigest, bindingSteps), executableSteps, resolvedWorkers, "execution binding swarm_id mismatch")
	wantError("wrong plan digest", bindingFor(plan["swarm_id"].(string), strings.Repeat("b", 64), bindingSteps), executableSteps, resolvedWorkers, "execution binding plan_digest mismatch")
	wantError("reordered steps", bindingFor(plan["swarm_id"].(string), planDigest, []any{bindingSteps[1], bindingSteps[0]}), executableSteps, resolvedWorkers, "execution binding step order mismatch")
	wantError("missing step", bindingFor(plan["swarm_id"].(string), planDigest, bindingSteps[:1]), executableSteps, resolvedWorkers, "execution binding step count mismatch")
	extraStep := map[string]any{"step_id": "extra", "depends_on": []any{"final"}, "capability": "summarize.text", "task_digest": strings.Repeat("c", 64)}
	wantError("extra step", bindingFor(plan["swarm_id"].(string), planDigest, []any{bindingSteps[0], bindingSteps[1], extraStep}), executableSteps, resolvedWorkers, "execution binding step count mismatch")
	duplicateStep := cloneMap(bindingSteps[1].(map[string]any))
	duplicateStep["step_id"] = "draft"
	wantError("duplicate step", bindingFor(plan["swarm_id"].(string), planDigest, []any{bindingSteps[0], duplicateStep}), executableSteps, resolvedWorkers, "execution binding duplicate step_id")
	reconnectedStep := cloneMap(bindingSteps[1].(map[string]any))
	reconnectedStep["depends_on"] = []any{}
	wantError("reconnected step", bindingFor(plan["swarm_id"].(string), planDigest, []any{bindingSteps[0], reconnectedStep}), executableSteps, resolvedWorkers, "execution binding step depends_on mismatch")
	changedCapabilityStep := cloneMap(bindingSteps[1].(map[string]any))
	changedCapabilityStep["capability"] = "translate.text"
	wantError("changed capability", bindingFor(plan["swarm_id"].(string), planDigest, []any{bindingSteps[0], changedCapabilityStep}), executableSteps, resolvedWorkers, "execution binding step capability mismatch")
	malformedDigestStep := cloneMap(bindingSteps[0].(map[string]any))
	malformedDigestStep["task_digest"] = "bad"
	wantError("malformed task digest", bindingFor(plan["swarm_id"].(string), planDigest, []any{malformedDigestStep, bindingSteps[1]}), executableSteps, resolvedWorkers, "execution binding step task_digest invalid")
	duplicateDependencyStep := cloneMap(bindingSteps[1].(map[string]any))
	duplicateDependencyStep["depends_on"] = []any{"draft", "draft"}
	wantError("duplicate dependency", bindingFor(plan["swarm_id"].(string), planDigest, []any{bindingSteps[0], duplicateDependencyStep}), executableSteps, resolvedWorkers, "execution binding duplicate dependency")

	changedTaskSteps := []map[string]any{cloneMap(executableSteps[0]), cloneMap(executableSteps[1])}
	changedTaskSteps[1]["task"] = map[string]any{"task_id": "binding_final", "intent": "Substituted task.", "signature": "task-signature-final"}
	wantError("changed task", binding, changedTaskSteps, resolvedWorkers, "execution binding task_digest mismatch")
	changedDependencySteps := []map[string]any{cloneMap(executableSteps[0]), cloneMap(executableSteps[1])}
	changedDependencySteps[1]["depends_on"] = []any{}
	wantError("changed executable dependency", binding, changedDependencySteps, resolvedWorkers, "execution binding executable depends_on mismatch")
	wrongSignature := cloneMap(binding)
	wrongSignature["binding_signature"] = "bad"
	wantError("wrong coordinator signature", wrongSignature, executableSteps, resolvedWorkers, "execution binding signature verification failed")
	wantError("original worker lacks capability", binding, executableSteps, []map[string]any{makeWorker("agent://swarm-execution-binding/incapable-original", []any{"translate.text"}), migratedWorker}, "execution binding worker capability missing")
	wantError("migrated worker lacks capability", binding, executableSteps, []map[string]any{originalWorker, makeWorker("agent://swarm-execution-binding/incapable-migration", []any{"translate.text"})}, "execution binding worker capability missing")
	wantError("malformed worker capabilities", binding, executableSteps, []map[string]any{makeWorker("agent://swarm-execution-binding/malformed-capabilities", []any{"summarize.text", map[string]any{"bad": true}}), migratedWorker}, "execution binding worker capabilities invalid")
	wantError("duplicate worker capability", binding, executableSteps, []map[string]any{originalWorker, makeWorker("agent://swarm-execution-binding/duplicate-capability", []any{"summarize.text", "summarize.text"})}, "execution binding worker capability duplicate")
	unknownRoot := cloneMap(binding)
	unknownRoot["unexpected"] = true
	wantError("unknown root field", unknownRoot, executableSteps, resolvedWorkers, "execution binding fields invalid")
	unknownStep := cloneMap(bindingSteps[0].(map[string]any))
	unknownStep["unexpected"] = true
	wantError("unknown step field", bindingFor(plan["swarm_id"].(string), planDigest, []any{unknownStep, bindingSteps[1]}), executableSteps, resolvedWorkers, "execution binding step fields invalid")
	missingCapabilityStep := cloneMap(bindingSteps[0].(map[string]any))
	delete(missingCapabilityStep, "capability")
	wantError("missing step field", bindingFor(plan["swarm_id"].(string), planDigest, []any{missingCapabilityStep, bindingSteps[1]}), executableSteps, resolvedWorkers, "execution binding step fields invalid")
}

func TestSignedReceiptDigestIncludesSignature(t *testing.T) {
	signedReceipt := map[string]any{
		"task_id":     "binding_receipt",
		"task_digest": strings.Repeat("d", 64),
		"status":      "completed",
		"signature":   "worker-signature-a",
	}
	changedSignature := map[string]any{}
	for key, value := range signedReceipt {
		changedSignature[key] = value
	}
	changedSignature["signature"] = "worker-signature-b"

	digestA, err := SignedReceiptDigest(signedReceipt)
	if err != nil {
		t.Fatal(err)
	}
	digestB, err := SignedReceiptDigest(changedSignature)
	if err != nil {
		t.Fatal(err)
	}
	if digestA != digestNodeCanonical(signedReceipt) || digestB != digestNodeCanonical(changedSignature) {
		t.Fatal("signed receipt digest did not hash the exact signed receipt")
	}
	if digestA == digestB {
		t.Fatal("changing only the worker signature must change signed receipt digest")
	}
	unsignedReceipt := map[string]any{}
	for key, value := range signedReceipt {
		if key != "signature" {
			unsignedReceipt[key] = value
		}
	}
	if _, err := SignedReceiptDigest(unsignedReceipt); err == nil || !strings.Contains(err.Error(), "signed receipt signature missing") {
		t.Fatalf("got %v, want signed receipt signature missing", err)
	}
}

func TestArtifactManifestAFPMatchesSHA256(t *testing.T) {
	manifest := map[string]any{
		"uri":        "artifact://local/afp-test/out.md",
		"sha256":     strings.Repeat("1", 64),
		"size":       float64(1),
		"media_type": "text/markdown; charset=utf-8",
		"afp":        "afp:sha256:" + strings.Repeat("0", 64),
	}
	manifest["manifest_hash"] = digestHex(manifest)
	err := verifyReceiptArtifactManifests(map[string]any{
		"artifact_refs":      []any{manifest["uri"]},
		"artifact_manifests": []any{manifest},
	})
	if err == nil || !strings.Contains(err.Error(), "artifact manifest afp mismatch") {
		t.Fatalf("got %v, want artifact manifest afp mismatch", err)
	}
}

func TestArtifactManifestRejectsMalformedSHA256(t *testing.T) {
	manifest := map[string]any{
		"uri":        "artifact://local/sha-test/out.md",
		"sha256":     "../evil",
		"size":       float64(1),
		"media_type": "text/markdown; charset=utf-8",
		"afp":        "afp:sha256:../evil",
	}
	manifest["manifest_hash"] = digestHex(manifest)
	err := verifyReceiptArtifactManifests(map[string]any{
		"artifact_refs":      []any{manifest["uri"]},
		"artifact_manifests": []any{manifest},
	})
	if err == nil || !strings.Contains(err.Error(), "artifact manifest sha256 invalid") {
		t.Fatalf("got %v, want artifact manifest sha256 invalid", err)
	}
}

func TestArtifactManifestRejectsMalformedSize(t *testing.T) {
	for _, size := range []float64{-1, 1.5} {
		manifest := map[string]any{
			"uri":        "artifact://local/size-test/out.md",
			"sha256":     strings.Repeat("1", 64),
			"size":       size,
			"media_type": "text/markdown; charset=utf-8",
			"afp":        "afp:sha256:" + strings.Repeat("1", 64),
		}
		manifest["manifest_hash"] = digestHex(manifest)
		err := verifyReceiptArtifactManifests(map[string]any{
			"artifact_refs":      []any{manifest["uri"]},
			"artifact_manifests": []any{manifest},
		})
		if err == nil || !strings.Contains(err.Error(), "artifact manifest size invalid") {
			t.Fatalf("size %v: got %v, want artifact manifest size invalid", size, err)
		}
	}
}

func TestArtifactManifestRejectsMalformedMediaType(t *testing.T) {
	manifest := map[string]any{
		"uri":        "artifact://local/media-type-test/out.md",
		"sha256":     strings.Repeat("2", 64),
		"size":       float64(1),
		"media_type": map[string]any{"type": "text/plain"},
		"afp":        "afp:sha256:" + strings.Repeat("2", 64),
	}
	manifest["manifest_hash"] = digestHex(manifest)
	err := verifyReceiptArtifactManifests(map[string]any{
		"artifact_refs":      []any{manifest["uri"]},
		"artifact_manifests": []any{manifest},
	})
	if err == nil || !strings.Contains(err.Error(), "artifact manifest media_type invalid") {
		t.Fatalf("got %v, want artifact manifest media_type invalid", err)
	}
}

func TestArtifactManifestRejectsMalformedManifestHash(t *testing.T) {
	manifest := map[string]any{
		"uri":           "artifact://local/manifest-hash-test/out.md",
		"sha256":        strings.Repeat("3", 64),
		"size":          float64(1),
		"media_type":    "text/plain",
		"afp":           "afp:sha256:" + strings.Repeat("3", 64),
		"manifest_hash": map[string]any{"hash": strings.Repeat("4", 64)},
	}
	err := verifyReceiptArtifactManifests(map[string]any{
		"artifact_refs":      []any{manifest["uri"]},
		"artifact_manifests": []any{manifest},
	})
	if err == nil || !strings.Contains(err.Error(), "artifact manifest manifest_hash invalid") {
		t.Fatalf("got %v, want artifact manifest manifest_hash invalid", err)
	}
}

func TestArtifactManifestRejectsMalformedURI(t *testing.T) {
	manifest := map[string]any{
		"uri":        map[string]any{"path": "artifact://local/uri-test/out.md"},
		"sha256":     strings.Repeat("4", 64),
		"size":       float64(1),
		"media_type": "text/plain",
		"afp":        "afp:sha256:" + strings.Repeat("4", 64),
	}
	manifest["manifest_hash"] = digestHex(manifest)
	err := verifyReceiptArtifactManifests(map[string]any{
		"artifact_refs":      []any{"artifact://local/uri-test/out.md"},
		"artifact_manifests": []any{manifest},
	})
	if err == nil || !strings.Contains(err.Error(), "artifact manifest uri invalid") {
		t.Fatalf("got %v, want artifact manifest uri invalid", err)
	}
}

func TestArtifactManifestRejectsMalformedAFP(t *testing.T) {
	manifest := map[string]any{
		"uri":        "artifact://local/afp-shape-test/out.md",
		"sha256":     strings.Repeat("4", 64),
		"size":       float64(1),
		"media_type": "text/plain",
		"afp":        map[string]any{"sha256": strings.Repeat("4", 64)},
	}
	manifest["manifest_hash"] = digestHex(manifest)
	err := verifyReceiptArtifactManifests(map[string]any{
		"artifact_refs":      []any{manifest["uri"]},
		"artifact_manifests": []any{manifest},
	})
	if err == nil || !strings.Contains(err.Error(), "artifact manifest afp invalid") {
		t.Fatalf("got %v, want artifact manifest afp invalid", err)
	}
}

func TestArtifactManifestRejectsMalformedListEntries(t *testing.T) {
	manifest := map[string]any{
		"uri":        "artifact://local/list-shape-test/out.md",
		"sha256":     strings.Repeat("5", 64),
		"size":       float64(1),
		"media_type": "text/plain",
		"afp":        "afp:sha256:" + strings.Repeat("5", 64),
	}
	manifest["manifest_hash"] = digestHex(manifest)
	err := verifyReceiptArtifactManifests(map[string]any{
		"artifact_refs":      []any{manifest["uri"], map[string]any{"uri": manifest["uri"]}},
		"artifact_manifests": []any{manifest},
	})
	if err == nil || !strings.Contains(err.Error(), "artifact refs invalid") {
		t.Fatalf("got %v, want artifact refs invalid", err)
	}
}
