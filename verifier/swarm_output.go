package verifier

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"
)

const swarmOutputVerificationFormat = "asp-swarm-output-verification/v1"

type OutputEvidence struct {
	Proof            map[string]any
	PlanFrame        map[string]any
	ExecutionBinding map[string]any
	ExecutableSteps  []map[string]any
	ResolvedWorkers  []map[string]any
	CloseFrame       map[string]any
	ReceiptFrames    []map[string]any
	TrustedZones     map[string]map[string]any
	ArtifactBytes    func(artifact map[string]any) ([]byte, error)
}

type VerifiedSwarmOutput struct {
	CloseDigest       string
	ProofDigest       string
	TrustInputsDigest string
	CloseBytes        []byte
	ProofBytes        []byte
	FinalOutput       map[string]any
	VerificationID    string
	VerifiedAt        string
	VerifierAID       string
	VerifierZone      string
}

type VerificationReplayRecord struct {
	VerificationID       string         `json:"verification_id"`
	CanonicalProofSHA256 string         `json:"canonical_proof_sha256"`
	CanonicalCloseSHA256 string         `json:"canonical_close_sha256"`
	CanonicalProofBytes  []byte         `json:"canonical_proof_bytes"`
	CanonicalCloseBytes  []byte         `json:"canonical_close_bytes"`
	StoredCloseDigest    string         `json:"stored_close_digest"`
	ProofCloseDigest     string         `json:"proof_close_digest"`
	ProofDigest          string         `json:"proof_digest"`
	TrustInputsDigest    string         `json:"trust_inputs_digest"`
	FinalOutput          map[string]any `json:"final_output"`
	VerifiedAt           string         `json:"verified_at"`
	VerifierAID          string         `json:"verifier_aid"`
	VerifierZone         string         `json:"verifier_zone"`
}

type VerificationReplayStore interface {
	LookupVerificationReplay(verificationID string) (VerificationReplayRecord, bool, error)
	PutVerificationReplayIfAbsent(record VerificationReplayRecord) (VerificationReplayRecord, bool, error)
}

type SwarmOutputSchedulerCompletion struct {
	VerificationID       string         `json:"verification_id"`
	CanonicalProofSHA256 string         `json:"canonical_proof_sha256"`
	CanonicalCloseSHA256 string         `json:"canonical_close_sha256"`
	ReplayDecision       string         `json:"replay_decision"`
	StoredCloseDigest    string         `json:"stored_close_digest"`
	ProofCloseDigest     string         `json:"proof_close_digest"`
	StoreMutated         bool           `json:"store_mutated"`
	CloseDigest          string         `json:"closeDigest"`
	ProofDigest          string         `json:"proofDigest"`
	TrustInputsDigest    string         `json:"trustInputsDigest"`
	CloseBytes           []byte         `json:"CloseBytes"`
	ProofBytes           []byte         `json:"ProofBytes"`
	FinalOutput          map[string]any `json:"finalOutput"`
	CompletionGate       bool           `json:"completion_gate"`
}

func ApplySwarmOutputVerification(evidence OutputEvidence, trust TrustInputs, store VerificationReplayStore, now time.Time, expectedCloseDigest string) (SwarmOutputSchedulerCompletion, error) {
	var zero SwarmOutputSchedulerCompletion
	if store == nil {
		return zero, errors.New("verification replay store invalid")
	}
	verified, err := VerifySwarmOutput(evidence, trust, now)
	if err != nil {
		return zero, err
	}
	if expectedCloseDigest != "" {
		if !isHexDigest(expectedCloseDigest) {
			return zero, errors.New("expected close digest invalid")
		}
		if expectedCloseDigest != verified.CloseDigest {
			return zero, errors.New("verification replay close digest mismatch")
		}
	}
	record, err := verificationReplayRecord(verified)
	if err != nil {
		return zero, err
	}
	recordForStore, err := CloneVerificationReplayRecord(record)
	if err != nil {
		return zero, err
	}
	stored, inserted, err := store.PutVerificationReplayIfAbsent(recordForStore)
	if err != nil {
		return zero, err
	}
	stored, err = CloneVerificationReplayRecord(stored)
	if err != nil {
		return zero, err
	}
	decision := "accepted"
	if !inserted {
		decision = classifyVerificationReplay(stored, record)
	}
	return schedulerCompletionFromReplay(verified, record, stored, decision, inserted), nil
}

func verificationReplayRecord(verified VerifiedSwarmOutput) (VerificationReplayRecord, error) {
	finalOutput, err := cloneMap(verified.FinalOutput)
	if err != nil {
		return VerificationReplayRecord{}, err
	}
	return VerificationReplayRecord{
		VerificationID:       verified.VerificationID,
		CanonicalProofSHA256: digestBytesHex(verified.ProofBytes),
		CanonicalCloseSHA256: digestBytesHex(verified.CloseBytes),
		CanonicalProofBytes:  append([]byte(nil), verified.ProofBytes...),
		CanonicalCloseBytes:  append([]byte(nil), verified.CloseBytes...),
		StoredCloseDigest:    verified.CloseDigest,
		ProofCloseDigest:     verified.CloseDigest,
		ProofDigest:          verified.ProofDigest,
		TrustInputsDigest:    verified.TrustInputsDigest,
		FinalOutput:          finalOutput,
		VerifiedAt:           verified.VerifiedAt,
		VerifierAID:          verified.VerifierAID,
		VerifierZone:         verified.VerifierZone,
	}, nil
}

func classifyVerificationReplay(stored, record VerificationReplayRecord) string {
	if stored.CanonicalProofSHA256 == record.CanonicalProofSHA256 && stored.CanonicalCloseSHA256 == record.CanonicalCloseSHA256 && stored.StoredCloseDigest == record.StoredCloseDigest && stored.StoredCloseDigest == record.ProofCloseDigest && stored.ProofCloseDigest == record.ProofCloseDigest && stored.ProofDigest == record.ProofDigest && stored.TrustInputsDigest == record.TrustInputsDigest && bytes.Equal(stored.CanonicalProofBytes, record.CanonicalProofBytes) && bytes.Equal(stored.CanonicalCloseBytes, record.CanonicalCloseBytes) && canonicalAnyEqual(stored.FinalOutput, record.FinalOutput) {
		return "idempotent"
	}
	return "conflict"
}

func schedulerCompletionFromReplay(verified VerifiedSwarmOutput, record, stored VerificationReplayRecord, decision string, inserted bool) SwarmOutputSchedulerCompletion {
	if inserted {
		stored = record
	}
	storedCloseDigest := stored.StoredCloseDigest
	gateDecision := decision == "accepted" || decision == "idempotent"
	finalOutput, _ := cloneMap(verified.FinalOutput)
	return SwarmOutputSchedulerCompletion{
		VerificationID:       record.VerificationID,
		CanonicalProofSHA256: record.CanonicalProofSHA256,
		CanonicalCloseSHA256: record.CanonicalCloseSHA256,
		ReplayDecision:       decision,
		StoredCloseDigest:    storedCloseDigest,
		ProofCloseDigest:     record.ProofCloseDigest,
		StoreMutated:         inserted,
		CloseDigest:          verified.CloseDigest,
		ProofDigest:          verified.ProofDigest,
		TrustInputsDigest:    verified.TrustInputsDigest,
		CloseBytes:           append([]byte(nil), verified.CloseBytes...),
		ProofBytes:           append([]byte(nil), verified.ProofBytes...),
		FinalOutput:          finalOutput,
		CompletionGate:       gateDecision && storedCloseDigest == verified.CloseDigest,
	}
}

func CloneVerificationReplayRecord(record VerificationReplayRecord) (VerificationReplayRecord, error) {
	finalOutput, err := cloneMap(record.FinalOutput)
	if err != nil {
		return VerificationReplayRecord{}, err
	}
	clone := record
	clone.CanonicalProofBytes = append([]byte(nil), record.CanonicalProofBytes...)
	clone.CanonicalCloseBytes = append([]byte(nil), record.CanonicalCloseBytes...)
	clone.FinalOutput = finalOutput
	return clone, nil
}

func cloneMap(value map[string]any) (map[string]any, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func digestBytesHex(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func VerifySwarmOutput(evidence OutputEvidence, trust TrustInputs, now time.Time) (VerifiedSwarmOutput, error) {
	var zero VerifiedSwarmOutput
	if evidence.Proof == nil || evidence.PlanFrame == nil || evidence.ExecutionBinding == nil || evidence.CloseFrame == nil || evidence.TrustedZones == nil {
		return zero, errors.New("swarm output evidence missing")
	}
	verifiedPlan, err := verifySwarmOutputPlan(evidence.PlanFrame, evidence.TrustedZones)
	if err != nil {
		return zero, err
	}
	graphDigest, err := VerifySwarmExecutionBinding(evidence.ExecutionBinding, verifiedPlan, evidence.ExecutableSteps, evidence.ResolvedWorkers)
	if err != nil {
		return zero, err
	}
	close, closeDigest, closeBytes, err := verifySwarmOutputClose(evidence.CloseFrame, evidence.TrustedZones)
	if err != nil {
		return zero, err
	}
	if close["swarm_id"] != evidence.ExecutionBinding["swarm_id"] {
		return zero, errors.New("close swarm_id mismatch")
	}
	if close["plan_digest"] != evidence.ExecutionBinding["plan_digest"] {
		return zero, errors.New("close plan digest mismatch")
	}
	if close["execution_graph_digest"] != graphDigest {
		return zero, errors.New("close execution graph digest mismatch")
	}
	completed, err := verifySwarmOutputReceipts(evidence)
	if err != nil {
		return zero, err
	}
	finalOutput, err := DeriveSwarmFinalOutput(evidence.ExecutionBinding, completed)
	if err != nil {
		return zero, err
	}
	closeFinal, ok := close["final_output"].(map[string]any)
	if !ok || !canonicalAnyEqual(closeFinal, finalOutput) {
		return zero, errors.New("final output mismatch")
	}
	if err := verifySwarmOutputCloseReceiptLinks(close, completed); err != nil {
		return zero, err
	}
	terminalReceipt := completed[fmt.Sprint(finalOutput["step_id"])]
	resultArtifact, err := VerifyResultArtifact(terminalReceipt)
	if err != nil {
		return zero, err
	}
	if !canonicalAnyEqual(resultArtifact, finalOutput["artifact"]) {
		return zero, errors.New("final output artifact mismatch")
	}
	if err := verifySwarmOutputArtifactBytes(finalOutput, terminalReceipt, evidence.ArtifactBytes); err != nil {
		return zero, err
	}
	proofBody, proofDigest, proofBytes, err := verifySwarmOutputProof(evidence.Proof, trust, now)
	if err != nil {
		return zero, err
	}
	if proofBody["trust_inputs_digest"] != trust.TrustInputsDigest {
		return zero, errors.New("trust inputs digest mismatch")
	}
	if proofBody["swarm_id"] != close["swarm_id"] {
		return zero, errors.New("proof swarm_id mismatch")
	}
	if proofBody["plan_digest"] != close["plan_digest"] {
		return zero, errors.New("proof plan digest mismatch")
	}
	if proofBody["execution_graph_digest"] != close["execution_graph_digest"] {
		return zero, errors.New("proof execution graph digest mismatch")
	}
	if proofBody["close_digest"] != closeDigest {
		return zero, errors.New("proof close digest mismatch")
	}
	if !canonicalAnyEqual(proofBody["final_output"], finalOutput) {
		return zero, errors.New("proof final output mismatch")
	}
	return VerifiedSwarmOutput{
		CloseDigest:       closeDigest,
		ProofDigest:       proofDigest,
		TrustInputsDigest: trust.TrustInputsDigest,
		CloseBytes:        closeBytes,
		ProofBytes:        proofBytes,
		FinalOutput:       finalOutput,
		VerificationID:    fmt.Sprint(proofBody["verification_id"]),
		VerifiedAt:        fmt.Sprint(proofBody["verified_at"]),
		VerifierAID:       fmt.Sprint(proofBody["verifier_aid"]),
		VerifierZone:      fmt.Sprint(proofBody["verifier_zone"]),
	}, nil
}

func verifySwarmOutputPlan(frame map[string]any, trusted map[string]map[string]any) (map[string]any, error) {
	if !hasExactMapFields(frame, []string{"type", "zone", "plan"}) || frame["type"] != "FED_SWARM_PLAN" {
		return nil, errors.New("expected FED_SWARM_PLAN frame")
	}
	zone, ok := frame["zone"].(map[string]any)
	if !ok {
		return nil, errors.New("swarm plan zone missing")
	}
	if err := verifyTrustedZone(zone, trusted); err != nil {
		return nil, err
	}
	plan, ok := frame["plan"].(map[string]any)
	if !ok {
		return nil, errors.New("swarm plan body missing")
	}
	verified := map[string]any{"zone": zone, "plan": plan}
	if _, _, _, err := verifyExecutionBindingPlan(verified); err != nil {
		return nil, err
	}
	return verified, nil
}

func verifySwarmOutputClose(frame map[string]any, trusted map[string]map[string]any) (map[string]any, string, []byte, error) {
	if !hasExactMapFields(frame, []string{"type", "swarm_id", "zone", "close"}) || frame["type"] != "FED_SWARM_CLOSE" {
		return nil, "", nil, errors.New("expected FED_SWARM_CLOSE frame")
	}
	zone, ok := frame["zone"].(map[string]any)
	if !ok {
		return nil, "", nil, errors.New("swarm close zone missing")
	}
	if err := verifyTrustedZone(zone, trusted); err != nil {
		return nil, "", nil, err
	}
	closeProof, ok := frame["close"].(map[string]any)
	if !ok {
		return nil, "", nil, errors.New("swarm close proof missing")
	}
	if !hasRequiredAllowedFields(closeProof, []string{"format", "swarm_id", "plan_digest", "execution_graph_digest", "step_receipts", "final_output", "close_signature"}, []string{"micro_contracts", "migration_log", "conflict_resolutions", "scheduler"}) {
		return nil, "", nil, errors.New("swarm close v2 fields invalid")
	}
	if closeProof["format"] != "asp-swarm-close/v2" {
		return nil, "", nil, errors.New("swarm close v2 format invalid")
	}
	if frame["swarm_id"] != closeProof["swarm_id"] {
		return nil, "", nil, errors.New("swarm close frame id mismatch")
	}
	if !isHexDigest(optionalString(closeProof["plan_digest"])) {
		return nil, "", nil, errors.New("swarm close plan digest invalid")
	}
	if !isHexDigest(optionalString(closeProof["execution_graph_digest"])) {
		return nil, "", nil, errors.New("swarm close execution graph digest invalid")
	}
	zoneKey, _, err := publicKey(zone)
	if err != nil {
		return nil, "", nil, err
	}
	if err := verifyMapSignature(zoneKey, closeProof, "close_signature"); err != nil {
		return nil, "", nil, errors.New("swarm close signature verification failed")
	}
	steps, err := strictMapList(closeProof["step_receipts"])
	if err != nil || len(steps) == 0 {
		return nil, "", nil, errors.New("swarm close step receipts missing")
	}
	seen := map[string]bool{}
	stepByID := map[string]map[string]any{}
	for _, step := range steps {
		if !hasRequiredAllowedFields(step, []string{"step_id", "task_id", "signed_receipt_digest"}, []string{"worker"}) {
			return nil, "", nil, errors.New("swarm close v2 step fields invalid")
		}
		stepID, ok := step["step_id"].(string)
		if !ok || stepID == "" || strings.ContainsRune(stepID, '\x00') {
			return nil, "", nil, errors.New("swarm close step identity missing")
		}
		if seen[stepID] {
			return nil, "", nil, errors.New("swarm close duplicate step receipt")
		}
		seen[stepID] = true
		stepByID[stepID] = step
		if _, ok := step["task_id"].(string); !ok || step["task_id"] == "" {
			return nil, "", nil, errors.New("swarm close task missing")
		}
		if !isHexDigest(optionalString(step["signed_receipt_digest"])) {
			return nil, "", nil, errors.New("swarm close signed receipt digest invalid")
		}
		if worker, exists := step["worker"]; exists {
			workerMap, ok := worker.(map[string]any)
			if !ok || workerMap == nil {
				return nil, "", nil, errors.New("swarm close step worker missing")
			}
		}
	}
	if finalOutput, ok := closeProof["final_output"].(map[string]any); !ok || !hasExactMapFields(finalOutput, []string{"step_id", "task_id", "signed_receipt_digest", "artifact", "selection_rule"}) {
		return nil, "", nil, errors.New("swarm close final output fields invalid")
	}
	if err := verifySwarmOutputCloseAuxiliaryEvidence(closeProof, stepByID, zone); err != nil {
		return nil, "", nil, err
	}
	bytesValue, err := canonicalJSON(closeProof)
	if err != nil {
		return nil, "", nil, err
	}
	digestValue, err := canonicalDigest(closeProof)
	if err != nil {
		return nil, "", nil, err
	}
	return closeProof, digestValue, bytesValue, nil
}

func verifySwarmOutputReceipts(evidence OutputEvidence) (map[string]map[string]any, error) {
	if len(evidence.ReceiptFrames) != len(evidence.ExecutableSteps) {
		return nil, errors.New("signed receipt count mismatch")
	}
	tasks := map[string]map[string]any{}
	workers := map[string]map[string]any{}
	for index, step := range evidence.ExecutableSteps {
		stepID, _, task, err := parseExecutableBindingStep(step)
		if err != nil { return nil, err }
		tasks[stepID] = task
		worker := evidence.ResolvedWorkers[index]
		if descriptor, ok := worker["descriptor"].(map[string]any); ok { worker = descriptor }
		workers[stepID] = worker
	}
	completed := map[string]map[string]any{}
	for _, frame := range evidence.ReceiptFrames {
		receipt, ok := frame["receipt"].(map[string]any); if !ok { return nil, errors.New("receipt missing") }
		swarm, ok := receipt["swarm"].(map[string]any)
		stepID := ""
		if receipt["format"] == "agnet-receipt/v2" {
			stepID = optionalString(receipt["step_id"])
			if receipt["task_id"] != tasks[stepID]["task_id"] { return nil, errors.New("receipt v2 task_id mismatch") }
			worker, ok := frame["worker"].(map[string]any); if !ok || !canonicalAnyEqual(worker, workers[stepID]) { return nil, errors.New("receipt v2 frozen worker mismatch") }
		} else {
			if !ok { return nil, errors.New("receipt swarm binding missing") }
			stepID = fmt.Sprint(swarm["step_id"])
		}
		if tasks[stepID] == nil { return nil, errors.New("receipt step unknown") }
		if err := VerifyFederatedReceipt(frame, evidence.TrustedZones, tasks[stepID]); err != nil { return nil, err }
		if completed[stepID] != nil { return nil, errors.New("duplicate signed receipt step") }
		completed[stepID] = receipt
	}
	return completed, nil
}

func verifySwarmOutputCloseReceiptLinks(close map[string]any, receipts map[string]map[string]any) error {
	steps, err := strictMapList(close["step_receipts"])
	if err != nil {
		return err
	}
	if len(steps) != len(receipts) {
		return errors.New("close signed receipt count mismatch")
	}
	closeSteps := map[string]map[string]any{}
	for _, step := range steps {
		stepID := fmt.Sprint(step["step_id"])
		closeSteps[stepID] = step
		if receipts[stepID] == nil {
			return errors.New("close signed receipt missing: " + stepID)
		}
	}
	for stepID := range receipts {
		if closeSteps[stepID] == nil {
			return errors.New("close signed receipt missing: " + stepID)
		}
	}
	for stepID, step := range closeSteps {
		receipt := receipts[stepID]
		if step["task_id"] != receipt["task_id"] {
			return errors.New("close receipt task mismatch")
		}
		digestValue, err := SignedReceiptDigest(receipt)
		if err != nil {
			return err
		}
		if step["signed_receipt_digest"] != digestValue {
			return errors.New("close signed receipt digest mismatch")
		}
	}
	return nil
}

func verifySwarmOutputArtifactBytes(finalOutput, terminalReceipt map[string]any, load func(map[string]any) ([]byte, error)) error {
	if load == nil {
		return errors.New("artifact byte loader missing")
	}
	artifact, ok := finalOutput["artifact"].(map[string]any)
	if !ok {
		return errors.New("final output artifact mismatch")
	}
	if terminalReceipt["format"] == "agnet-receipt/v2" {
		result, ok := terminalReceipt["result"].(map[string]any)
		if !ok || !canonicalAnyEqual(result, artifact) { return errors.New("final output artifact mismatch") }
		bytesValue, err := load(artifact); if err != nil { return err }
		hash := sha256.Sum256(bytesValue)
		if hex.EncodeToString(hash[:]) != artifact["sha256"] { return errors.New("artifact bytes digest mismatch") }
		return nil
	}
	manifests, err := artifactManifestsFromAny(terminalReceipt["artifact_manifests"])
	if err != nil {
		return err
	}
	var manifest map[string]any
	for _, candidate := range manifests {
		if candidate["uri"] == artifact["uri"] && candidate["sha256"] == artifact["sha256"] && candidate["manifest_hash"] == artifact["manifest_hash"] {
			manifest = candidate
		}
	}
	if manifest == nil {
		return errors.New("result artifact manifest mismatch")
	}
	bytesValue, err := load(artifact)
	if err != nil {
		return err
	}
	if float64(len(bytesValue)) != manifest["size"] {
		return errors.New("artifact bytes size mismatch")
	}
	hash := sha256.Sum256(bytesValue)
	if hex.EncodeToString(hash[:]) != artifact["sha256"] {
		return errors.New("artifact bytes digest mismatch")
	}
	return nil
}

func verifySwarmOutputProof(frame map[string]any, trust TrustInputs, now time.Time) (map[string]any, string, []byte, error) {
	if !hasExactMapFields(frame, []string{"type", "verifier", "verifier_zone", "verifier_zone_binding", "proof"}) || frame["type"] != "FED_SWARM_OUTPUT_VERIFICATION" {
		return nil, "", nil, errors.New("expected FED_SWARM_OUTPUT_VERIFICATION frame")
	}
	verifier, ok := frame["verifier"].(map[string]any)
	if !ok {
		return nil, "", nil, errors.New("verifier descriptor exact schema invalid")
	}
	zone, ok := frame["verifier_zone"].(map[string]any)
	if !ok {
		return nil, "", nil, errors.New("trusted zone descriptor exact schema invalid")
	}
	binding, ok := frame["verifier_zone_binding"].(map[string]any)
	if !ok {
		return nil, "", nil, errors.New("verifier zone binding exact schema invalid")
	}
	if err := verifyPinnedOutputVerifier(verifier, zone, binding, trust); err != nil {
		return nil, "", nil, err
	}
	proof, ok := frame["proof"].(map[string]any)
	if !ok || !hasExactMapFields(proof, []string{"format", "verification_id", "verified_at", "swarm_id", "plan_digest", "execution_graph_digest", "close_digest", "final_output", "verifier_aid", "verifier_zone", "trust_inputs_digest", "proof_signature"}) {
		return nil, "", nil, errors.New("swarm output verification proof exact schema has unknown or missing fields")
	}
	if proof["format"] != swarmOutputVerificationFormat {
		return nil, "", nil, errors.New("swarm output verification format invalid")
	}
	for _, field := range []string{"verification_id", "swarm_id"} {
		if err := requireSwarmOutputCanonicalString(proof[field], field); err != nil {
			return nil, "", nil, err
		}
	}
	if _, ok := proof["final_output"].(map[string]any); !ok {
		return nil, "", nil, errors.New("final_output invalid")
	}
	for _, field := range []string{"plan_digest", "execution_graph_digest", "close_digest", "trust_inputs_digest"} {
		if !isHexDigest(optionalString(proof[field])) {
			return nil, "", nil, errors.New(field + " invalid")
		}
	}
	if err := validateProofTimestamp(optionalString(proof["verified_at"]), now); err != nil {
		return nil, "", nil, err
	}
	if proof["verifier_aid"] != verifier["aid"] {
		return nil, "", nil, errors.New("verifier aid mismatch")
	}
	if proof["verifier_zone"] != zone["zid"] {
		return nil, "", nil, errors.New("verifier Zone mismatch")
	}
	key, _, err := publicKey(verifier)
	if err != nil {
		return nil, "", nil, err
	}
	if err := verifyMapSignature(key, proof, "proof_signature"); err != nil {
		return nil, "", nil, errors.New("proof signature verification failed")
	}
	bytesValue, err := canonicalJSON(proof)
	if err != nil {
		return nil, "", nil, err
	}
	digestValue := digestBytesHex(bytesValue)
	body := map[string]any{}
	for k, v := range proof {
		if k != "proof_signature" {
			body[k] = v
		}
	}
	return body, digestValue, bytesValue, nil
}

func verifyPinnedOutputVerifier(verifier, zone, binding map[string]any, trust TrustInputs) error {
	if err := verifyAgentDescriptor(verifier); err != nil {
		return fmt.Errorf("verifier descriptor signature verification failed: %w", err)
	}
	if err := verifyZoneDescriptor(zone); err != nil {
		return fmt.Errorf("zone signature verification failed: %w", err)
	}
	allowedEntries, err := strictMapList(trust.allowlist["verifiers"])
	if err != nil {
		return err
	}
	var allowed map[string]any
	for _, entry := range allowedEntries {
		descriptor, _ := entry["descriptor"].(map[string]any)
		zoneBinding, _ := entry["zone_binding"].(map[string]any)
		if descriptor != nil && zoneBinding != nil && descriptor["aid"] == verifier["aid"] && zoneBinding["zone"] == zone["zid"] {
			allowed = entry
		}
	}
	if allowed == nil {
		return errors.New("verifier allowlist tuple missing")
	}
	if !canonicalAnyEqual(allowed["descriptor"], verifier) {
		return errors.New("verifier descriptor mismatch")
	}
	if !canonicalAnyEqual(allowed["zone_binding"], binding) {
		return errors.New("verifier zone binding mismatch")
	}
	trustedZones, err := strictMapList(trust.trustedZones["zones"])
	if err != nil {
		return err
	}
	foundZone := false
	for _, trustedZone := range trustedZones {
		if trustedZone["zid"] == zone["zid"] && canonicalAnyEqual(trustedZone, zone) {
			foundZone = true
		}
	}
	if !foundZone {
		return errors.New("verifier trusted Zone mismatch")
	}
	return nil
}

var utcTimestampPattern = regexp.MustCompile(`^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?Z$`)

func validateProofTimestamp(value string, now time.Time) error {
	match := utcTimestampPattern.FindStringSubmatch(value)
	if match == nil {
		return errors.New("verified_at invalid")
	}
	layout := "2006-01-02T15:04:05Z"
	if match[7] != "" {
		layout = "2006-01-02T15:04:05." + strings.Repeat("0", len(match[7])) + "Z"
	}
	parsed, err := time.Parse(layout, value)
	if err != nil {
		return errors.New("verified_at invalid")
	}
	if parsed.Sub(now.UTC()) > 5*time.Minute {
		return errors.New("verified_at future skew invalid")
	}
	return nil
}

func requireSwarmOutputCanonicalString(value any, label string) error {
	text, ok := value.(string)
	if !ok || text == "" || strings.ContainsRune(text, '\x00') {
		return errors.New(label + " invalid")
	}
	if err := validateCanonicalStringDomain(text); err != nil {
		return err
	}
	return nil
}

func verifySwarmOutputCloseAuxiliaryEvidence(closeProof map[string]any, stepByID map[string]map[string]any, zone map[string]any) error {
	if migrationLog, exists := closeProof["migration_log"]; exists {
		if err := verifySwarmOutputCloseMigrationLog(migrationLog, stepByID); err != nil {
			return err
		}
	}
	if err := verifySwarmOutputCloseMicroContracts(closeProof, stepByID); err != nil {
		return err
	}
	if err := verifySwarmOutputCloseConflictResolutions(closeProof, stepByID, zone); err != nil {
		return err
	}
	if scheduler, exists := closeProof["scheduler"]; exists {
		return verifySwarmOutputCloseScheduler(scheduler, stepByID)
	}
	return nil
}

func verifySwarmOutputCloseScheduler(value any, stepByID map[string]map[string]any) error {
	scheduler, ok := value.(map[string]any)
	if !ok { return errors.New("swarm close scheduler invalid") }
	if scheduler["mode"] == "parallel-ready-dag" { return verifyParallelReadyDAGScheduler(scheduler, stepByID) }
	if !hasExactMapFields(scheduler, []string{"mode", "step_order"}) || scheduler["mode"] != "ready-dag" { return errors.New("swarm close scheduler mode invalid") }
	order, err := exactStringList(scheduler["step_order"], true, "swarm close scheduler step order invalid", "swarm close scheduler step duplicate"); if err != nil { return err }
	if len(order) != len(stepByID) { return errors.New("swarm close scheduler step order mismatch") }
	seen := map[string]bool{}
	for _, stepID := range order { if stepID == "" || strings.ContainsRune(stepID, '\x00') || seen[stepID] { return errors.New("swarm close scheduler step duplicate") }; seen[stepID] = true; if stepByID[stepID] == nil { return errors.New("swarm close scheduler step missing") } }
	return nil
}

func verifyParallelReadyDAGScheduler(scheduler map[string]any, stepByID map[string]map[string]any) error {
	if !hasExactMapFields(scheduler, []string{"mode", "ready_waves", "dispatch_waves"}) { return errors.New("parallel scheduler fields invalid") }
	ready, err := strictMapList(scheduler["ready_waves"]); if err != nil || len(ready) == 0 { return errors.New("parallel ready waves invalid") }
	dispatch, err := strictMapList(scheduler["dispatch_waves"]); if err != nil || len(dispatch) != len(ready) { return errors.New("parallel dispatch waves invalid") }
	seen := map[string]bool{}
	for index, wave := range ready {
		if !hasExactMapFields(wave, []string{"step_ids", "recorded_at"}) || optionalString(wave["recorded_at"]) == "" { return errors.New("parallel ready wave invalid") }
		stepIDs, err := exactStringList(wave["step_ids"], true, "parallel ready step invalid", "parallel ready step duplicate"); if err != nil || len(stepIDs) == 0 { return errors.New("parallel ready wave invalid") }
		for _, stepID := range stepIDs { if stepByID[stepID] == nil || seen[stepID] { return errors.New("parallel ready coverage invalid") }; seen[stepID] = true }
		dispatchWave := dispatch[index]
		if !hasExactMapFields(dispatchWave, []string{"wave", "attempts"}) || !canonicalAnyEqual(dispatchWave["wave"], wave) { return errors.New("parallel dispatch wave mismatch") }
		attempts, err := strictMapList(dispatchWave["attempts"]); if err != nil || len(attempts) != len(stepIDs) { return errors.New("parallel dispatch attempts invalid") }
		attempted := map[string]bool{}
		for _, attempt := range attempts {
			if !hasExactMapFields(attempt, []string{"step_id", "owner", "fence", "attempt", "candidate_index", "capability", "candidate", "deadline"}) || optionalString(attempt["owner"]) == "" || optionalString(attempt["capability"]) == "" || optionalString(attempt["deadline"]) == "" || !nonnegativeIntegralNumber(attempt["fence"]) || !nonnegativeIntegralNumber(attempt["attempt"]) || !nonnegativeIntegralNumber(attempt["candidate_index"]) { return errors.New("parallel dispatch attempt invalid") }
			stepID := optionalString(attempt["step_id"]); if !containsString(stepIDs, stepID) || attempted[stepID] { return errors.New("parallel dispatch coverage invalid") }; attempted[stepID] = true
			candidate, ok := attempt["candidate"].(map[string]any); if !ok || optionalString(candidate["aid"]) == "" || optionalString(candidate["public_key_spki"]) == "" || !isHexDigest(optionalString(candidate["descriptor_digest"])) { return errors.New("parallel dispatch candidate invalid") }
		}
	}
	if len(seen) != len(stepByID) { return errors.New("parallel ready coverage incomplete") }
	return nil
}

func verifySwarmOutputCloseMigrationLog(value any, stepByID map[string]map[string]any) error {
	items, err := strictMapList(value)
	if err != nil { return errors.New("swarm close migration_log invalid") }
	for _, entry := range items {
		if !hasExactMapFields(entry, []string{"step_id", "original_worker_aid", "migrated_to_worker_aid", "reason", "migration_at"}) { return errors.New("swarm close migration entry invalid") }
		stepID := optionalString(entry["step_id"])
		if stepID == "" || strings.ContainsRune(stepID, '\x00') { return errors.New("swarm close migration step invalid") }
		if stepByID[stepID] == nil { return errors.New("swarm close migration step missing") }
		if optionalString(entry["original_worker_aid"]) == "" { return errors.New("swarm close migration original worker missing") }
		if optionalString(entry["migrated_to_worker_aid"]) == "" { return errors.New("swarm close migration target worker missing") }
		if optionalString(entry["reason"]) == "" { return errors.New("swarm close migration reason missing") }
		if !utcTimestampPattern.MatchString(optionalString(entry["migration_at"])) { return errors.New("swarm close migration_at invalid") }
	}
	return nil
}

func verifySwarmOutputCloseMicroContracts(closeProof map[string]any, stepByID map[string]map[string]any) error {
	value, exists := closeProof["micro_contracts"]
	if !exists {
		return nil
	}
	items, err := strictMapList(value)
	if err != nil || len(items) != len(stepByID) {
		return errors.New("swarm close micro-contracts missing")
	}
	seen := map[string]bool{}
	for _, contract := range items {
		if !hasRequiredAllowedFields(contract, []string{"micro_contract", "swarm_id", "step_id", "worker", "cost_estimate", "capability_proof", "policy_digest", "contract_digest", "signature"}, nil) {
			return errors.New("swarm close micro-contract missing")
		}
		if contract["micro_contract"] != "ok" {
			return errors.New("swarm close micro-contract status invalid")
		}
		if contract["swarm_id"] != closeProof["swarm_id"] {
			return errors.New("swarm close micro-contract swarm mismatch")
		}
		stepID := optionalString(contract["step_id"])
		if stepID == "" || strings.ContainsRune(stepID, '\x00') {
			return errors.New("swarm close micro-contract step invalid")
		}
		if seen[stepID] {
			return errors.New("swarm close duplicate micro-contract")
		}
		seen[stepID] = true
		step := stepByID[stepID]
		if step == nil {
			return errors.New("swarm close micro-contract step missing")
		}
		stepWorker, ok := step["worker"].(map[string]any)
		if !ok || stepWorker == nil {
			return errors.New("swarm close step worker missing")
		}
		contractWorker, ok := contract["worker"].(map[string]any)
		if !ok || contractWorker == nil {
			return errors.New("swarm close micro-contract worker missing")
		}
		if !canonicalAnyEqual(contractWorker, stepWorker) {
			return errors.New("swarm close micro-contract worker mismatch")
		}
		cost, ok := contract["cost_estimate"].(map[string]any)
		if !ok || cost == nil {
			return errors.New("swarm close micro-contract cost missing")
		}
		if !nonnegativeIntegralNumber(cost["tokens"]) || !nonnegativeIntegralNumber(cost["seconds"]) {
			return errors.New("swarm close micro-contract cost invalid")
		}
		if optionalString(contract["capability_proof"]) == "" {
			return errors.New("swarm close micro-contract capability missing")
		}
		if !isHexDigest(optionalString(contract["policy_digest"])) {
			return errors.New("swarm close micro-contract policy invalid")
		}
		body := mapWithoutKeys(contract, "contract_digest", "signature")
		bodyDigest, err := canonicalDigest(body)
		if err != nil {
			return err
		}
		if contract["contract_digest"] != bodyDigest {
			return errors.New("swarm close micro-contract digest invalid")
		}
		workerKey, _, err := publicKey(stepWorker)
		if err != nil {
			return err
		}
		if err := verifySignatureBody(workerKey, body, optionalString(contract["signature"]), "signature"); err != nil {
			return errors.New("micro-contract signature verification failed")
		}
	}
	return nil
}

func verifySwarmOutputCloseConflictResolutions(closeProof map[string]any, stepByID map[string]map[string]any, zone map[string]any) error {
	value, exists := closeProof["conflict_resolutions"]
	if !exists {
		return nil
	}
	items, err := strictMapList(value)
	if err != nil {
		return errors.New("swarm close conflict_resolutions invalid")
	}
	zoneKey, _, err := publicKey(zone)
	if err != nil {
		return err
	}
	for _, resolution := range items {
		if !hasRequiredAllowedFields(resolution, []string{"swarm_id", "artifact_ref", "candidate_step_ids", "chosen_step_id", "chosen_worker", "reason", "resolution_digest", "signature"}, nil) {
			return errors.New("swarm close conflict resolution invalid")
		}
		if resolution["swarm_id"] != closeProof["swarm_id"] {
			return errors.New("swarm close conflict resolution swarm mismatch")
		}
		if optionalString(resolution["artifact_ref"]) == "" {
			return errors.New("swarm close conflict resolution artifact_ref missing")
		}
		candidates, err := exactStringList(resolution["candidate_step_ids"], false, "swarm close conflict resolution candidate invalid", "swarm close conflict resolution candidate duplicate")
		if err != nil {
			return err
		}
		if len(candidates) < 2 {
			return errors.New("swarm close conflict resolution candidates missing")
		}
		candidateSet := map[string]bool{}
		for _, stepID := range candidates {
			if stepID == "" || strings.ContainsRune(stepID, '\x00') {
				return errors.New("swarm close conflict resolution candidate invalid")
			}
			if stepByID[stepID] == nil {
				return errors.New("swarm close conflict resolution candidate missing")
			}
			candidateSet[stepID] = true
		}
		chosenStepID := optionalString(resolution["chosen_step_id"])
		if chosenStepID == "" || strings.ContainsRune(chosenStepID, '\x00') {
			return errors.New("swarm close conflict resolution chosen step invalid")
		}
		if !candidateSet[chosenStepID] {
			return errors.New("swarm close conflict resolution chosen step missing")
		}
		chosenWorker, ok := resolution["chosen_worker"].(map[string]any)
		if !ok || chosenWorker == nil {
			return errors.New("swarm close conflict resolution worker missing")
		}
		stepWorker, ok := stepByID[chosenStepID]["worker"].(map[string]any)
		if !ok || stepWorker == nil {
			return errors.New("swarm close step worker missing")
		}
		if !canonicalAnyEqual(chosenWorker, stepWorker) {
			return errors.New("swarm close conflict resolution worker mismatch")
		}
		if optionalString(resolution["reason"]) == "" {
			return errors.New("swarm close conflict resolution reason missing")
		}
		body := mapWithoutKeys(resolution, "resolution_digest", "signature")
		bodyDigest, err := canonicalDigest(body)
		if err != nil {
			return err
		}
		if resolution["resolution_digest"] != bodyDigest {
			return errors.New("swarm close conflict resolution digest invalid")
		}
		if err := verifySignatureBody(zoneKey, body, optionalString(resolution["signature"]), "signature"); err != nil {
			return errors.New("conflict resolution signature verification failed")
		}
	}
	return nil
}

func mapWithoutKeys(value map[string]any, keys ...string) map[string]any {
	blocked := map[string]bool{}
	for _, key := range keys {
		blocked[key] = true
	}
	out := map[string]any{}
	for key, item := range value {
		if !blocked[key] {
			out[key] = item
		}
	}
	return out
}

func verifySignatureBody(key ed25519.PublicKey, body map[string]any, signature string, signatureKey string) error {
	if signature == "" {
		return errors.New("missing " + signatureKey)
	}
	signed := map[string]any{}
	for k, v := range body {
		signed[k] = v
	}
	signed[signatureKey] = signature
	return verifyMapSignature(key, signed, signatureKey)
}

const jsMaxSafeInteger int64 = 9007199254740991

func nonnegativeIntegralNumber(value any) bool {
	switch typed := value.(type) {
	case float64:
		return !math.IsNaN(typed) && !math.IsInf(typed, 0) && typed >= 0 && typed <= float64(jsMaxSafeInteger) && typed == math.Trunc(typed)
	case int:
		return typed >= 0 && int64(typed) <= jsMaxSafeInteger
	case int64:
		return typed >= 0 && typed <= jsMaxSafeInteger
	default:
		return false
	}
}

func hasRequiredAllowedFields(value map[string]any, required, optional []string) bool {
	if value == nil {
		return false
	}
	allowed := map[string]bool{}
	for _, field := range required {
		allowed[field] = true
		if _, ok := value[field]; !ok {
			return false
		}
	}
	for _, field := range optional {
		allowed[field] = true
	}
	for field := range value {
		if !allowed[field] {
			return false
		}
	}
	return true
}

func canonicalAnyEqual(left, right any) bool {
	leftBytes, leftErr := canonicalJSON(left)
	rightBytes, rightErr := canonicalJSON(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}
