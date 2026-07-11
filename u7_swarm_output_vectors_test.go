package agnet

import (
	"agnet/verifier"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"
)

type u7SwarmOutputVector struct {
	Format       string `json:"format"`
	VectorOrigin string `json:"vector_origin"`
	Timestamps   struct {
		Now string `json:"now"`
	} `json:"timestamps"`
	Trust struct {
		Allowlist         map[string]any `json:"allowlist"`
		TrustedZones      map[string]any `json:"trusted_zones"`
		Revocations       map[string]any `json:"revocations"`
		Normalized        map[string]any `json:"normalized"`
		TrustInputsDigest string         `json:"trust_inputs_digest"`
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
		CanonicalBinding      string `json:"canonical_binding"`
		ExecutionGraphDigest  string `json:"execution_graph_digest"`
		SignedReceiptDigest   string `json:"signed_receipt_digest"`
		CanonicalClose        string `json:"canonical_close"`
		CloseDigest           string `json:"close_digest"`
		TrustInputsDigest     string `json:"trust_inputs_digest"`
		CanonicalProof        string `json:"canonical_proof"`
		ProofDigest           string `json:"proof_digest"`
		NormalizedTrustInputs string `json:"normalized_trust_inputs"`
	} `json:"expected"`
}

func loadU7SwarmOutputVector(t *testing.T, path string) u7SwarmOutputVector {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var vector u7SwarmOutputVector
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	if vector.Format != "asp-swarm-output-vector/v1" {
		t.Fatalf("unexpected vector format: %s", vector.Format)
	}
	return vector
}

func canonicalU7JSON(t *testing.T, value any) string {
	t.Helper()
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		t.Fatal(err)
	}
	return string(bytes.TrimSuffix(buf.Bytes(), []byte("\n")))
}

func verifyU7SwarmOutputVectorInGo(t *testing.T, path, origin string) {
	t.Helper()
	vector := loadU7SwarmOutputVector(t, path)
	if vector.VectorOrigin != origin {
		t.Fatalf("vector origin = %s, want %s", vector.VectorOrigin, origin)
	}
	trust, err := verifier.NewTrustInputsForTest(vector.Trust.Allowlist, vector.Trust.TrustedZones, vector.Trust.Revocations)
	if err != nil {
		t.Fatal(err)
	}
	now, err := time.Parse(time.RFC3339Nano, vector.Timestamps.Now)
	if err != nil {
		t.Fatal(err)
	}
	evidence := verifier.OutputEvidence{
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
	verified, err := verifier.VerifySwarmOutput(evidence, trust, now)
	if err != nil {
		t.Fatal(err)
	}
	if canonicalU7JSON(t, vector.Evidence.ExecutionBinding) != vector.Expected.CanonicalBinding {
		t.Fatalf("canonical binding mismatch")
	}
	if vector.Evidence.ExecutionBinding["execution_graph_digest"] != vector.Expected.ExecutionGraphDigest {
		t.Fatalf("execution graph digest = %v, want %s", vector.Evidence.ExecutionBinding["execution_graph_digest"], vector.Expected.ExecutionGraphDigest)
	}
	receiptDigest, err := verifier.SignedReceiptDigest(vector.Evidence.ReceiptFrames[0]["receipt"].(map[string]any))
	if err != nil {
		t.Fatal(err)
	}
	if receiptDigest != vector.Expected.SignedReceiptDigest {
		t.Fatalf("signed receipt digest = %s, want %s", receiptDigest, vector.Expected.SignedReceiptDigest)
	}
	if vector.Trust.TrustInputsDigest != vector.Expected.TrustInputsDigest || canonicalU7JSON(t, vector.Trust.Normalized) != vector.Expected.NormalizedTrustInputs {
		t.Fatalf("normalized trust input mismatch")
	}
	if verified.CloseDigest != vector.Expected.CloseDigest {
		t.Fatalf("close digest = %s, want %s", verified.CloseDigest, vector.Expected.CloseDigest)
	}
	if verified.ProofDigest != vector.Expected.ProofDigest {
		t.Fatalf("proof digest = %s, want %s", verified.ProofDigest, vector.Expected.ProofDigest)
	}
	if verified.TrustInputsDigest != vector.Expected.TrustInputsDigest {
		t.Fatalf("trust digest = %s, want %s", verified.TrustInputsDigest, vector.Expected.TrustInputsDigest)
	}
	if string(verified.CloseBytes) != vector.Expected.CanonicalClose {
		t.Fatalf("canonical close bytes mismatch")
	}
	if string(verified.ProofBytes) != vector.Expected.CanonicalProof {
		t.Fatalf("canonical proof bytes mismatch")
	}
}

func TestNodeCreatedSwarmOutputVectorVerifiesInGo(t *testing.T) {
	verifyU7SwarmOutputVectorInGo(t, "test-vectors/asp-u7-node-created-swarm-output.json", "node-created")
}

func TestGoCreatedSwarmOutputVectorVerifiesInGo(t *testing.T) {
	verifyU7SwarmOutputVectorInGo(t, "test-vectors/asp-u7-go-created-swarm-output.json", "go-created")
}
