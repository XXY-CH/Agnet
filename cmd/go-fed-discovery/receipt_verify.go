package main

import (
	"agnet/verifier"
	"bufio"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

// VerifyReceiptV2 is the reusable strict verifier for the exact canonical receipt bytes that a
// lease-fenced receipt commitment stores in the authoritative journal.
func VerifyReceiptV2(raw []byte, expected ReceiptExpectation) error {
	return verifyReceiptV2(raw, expected)

}

func verifyReceiptRecord(record map[string]any, artifactStoreDir string, signedTasks ...map[string]any) error {
	zone, ok := record["zone"].(map[string]any)
	if !ok {
		return errors.New("receipt zone missing")
	}
	worker, ok := record["worker"].(map[string]any)
	if !ok {
		return errors.New("receipt worker missing")
	}
	binding, ok := record["zone_binding"].(map[string]any)
	if !ok {
		return errors.New("receipt zone_binding missing")
	}
	receipt, ok := record["receipt"].(map[string]any)
	if !ok {
		return errors.New("receipt missing")
	}
	if err := verifyZoneDescriptor(zone); err != nil {
		return err
	}
	workerKey, _, err := publicKey(worker)
	if err != nil {
		return err
	}
	if err := verifyAgentDescriptor(worker); err != nil {
		return err
	}
	if err := verifyZoneBinding(zone, binding, worker); err != nil {
		return err
	}
	if receipt["executing_zone"] != zone["zid"] {
		return errors.New("receipt executing_zone mismatch")
	}
	if err := validateTaskID(optionalString(receipt["task_id"])); err != nil {
		return err
	}
	if !isHexDigest(optionalString(receipt["task_digest"])) {
		return errors.New("receipt task_digest missing")
	}
	if len(signedTasks) > 0 && digestHex(signedTasks[0]) != optionalString(receipt["task_digest"]) {
		return errors.New("receipt task_digest mismatch")
	}
	if receipt["to"] != worker["aid"] {
		return errors.New("receipt worker mismatch")
	}
	if err := verifyMapSignature(workerKey, receipt, "signature"); err != nil {
		return errors.New("receipt signature verification failed")
	}
	zoneKey, _, err := publicKey(zone)
	if err != nil {
		return err
	}
	if err := verifyApprovalGrants(zoneKey, receipt); err != nil {
		return err
	}
	if err := verifyCheckpoints(workerKey, receipt); err != nil {
		return err
	}
	if err := verifyArtifactManifests(receipt, artifactStoreDir); err != nil {
		return err
	}
	if _, err := verifier.VerifyResultArtifact(receipt); err != nil {
		return err
	}
	if err := verifyPolicyScope(receipt); err != nil {
		return err
	}
	if err := verifySandboxProof(zoneKey, receipt); err != nil {
		return err
	}
	return nil
}

func verifySwarmReceiptDependencies(receipt map[string]any, completed map[string]map[string]any, order map[string][]string) error {
	swarm, ok := receipt["swarm"].(map[string]any)
	if !ok {
		return nil
	}
	swarmID := optionalString(swarm["swarm_id"])
	stepID := optionalString(swarm["step_id"])
	if swarmID == "" || stepID == "" {
		return errors.New("swarm receipt identity missing")
	}
	if hasSwarmDelimiter(swarmID) || hasSwarmDelimiter(stepID) {
		return errors.New("swarm identity contains NUL")
	}
	inputs, err := swarmInputArtifacts(swarm["input_artifacts"])
	if err != nil {
		return err
	}
	after, err := swarmAfterSteps(swarm["after"])
	if err != nil {
		return err
	}
	if len(inputs) != len(after) {
		return errors.New("swarm input artifact count mismatch")
	}
	for i, input := range inputs {
		if !hasRequiredAllowedMapFields(input, []string{"step_id", "uri", "sha256", "manifest_hash", "signed_receipt_digest"}, nil) {
			return errors.New("swarm input artifact fields invalid")
		}
		dependency := optionalString(input["step_id"])
		if hasSwarmDelimiter(dependency) || hasSwarmDelimiter(after[i]) {
			return errors.New("swarm identity contains NUL")
		}
		if dependency != after[i] {
			return errors.New("swarm input artifact step mismatch")
		}
		dependencyReceipt, ok := completed[swarmID+"\x00"+dependency]
		if !ok {
			return errors.New("swarm dependency receipt missing: " + dependency)
		}
		resultArtifact, err := verifier.VerifyResultArtifact(dependencyReceipt)
		if err != nil {
			return err
		}
		if resultArtifact == nil {
			return errors.New("swarm dependency artifact missing: " + dependency)
		}
		if input["uri"] != resultArtifact["uri"] {
			return errors.New("swarm input artifact uri mismatch")
		}
		if input["sha256"] != resultArtifact["sha256"] {
			return errors.New("swarm input artifact digest mismatch")
		}
		if input["manifest_hash"] != resultArtifact["manifest_hash"] {
			return errors.New("swarm input artifact manifest hash mismatch")
		}
		signedDigest, err := verifier.SignedReceiptDigest(dependencyReceipt)
		if err != nil {
			return err
		}
		if input["signed_receipt_digest"] != signedDigest {
			return errors.New("swarm input signed receipt digest mismatch")
		}
	}
	completedKey := swarmID + "\x00" + stepID
	if _, exists := completed[completedKey]; exists {
		return errors.New("duplicate swarm step receipt: " + stepID)
	}
	completed[completedKey] = receipt
	order[swarmID] = append(order[swarmID], stepID)
	return nil
}

func swarmAfterSteps(value any) ([]string, error) {
	if value == nil {
		return []string{}, nil
	}
	if typed, ok := value.([]string); ok {
		return typed, nil
	}
	items, ok := value.([]any)
	if !ok {
		return nil, errors.New("swarm after invalid")
	}
	out := []string{}
	for _, item := range items {
		text, ok := item.(string)
		if !ok {
			return nil, errors.New("swarm after invalid")
		}
		out = append(out, text)
	}
	return out, nil
}

func swarmInputArtifacts(value any) ([]map[string]any, error) {
	if value == nil {
		return nil, nil
	}
	if typed, ok := value.([]map[string]any); ok {
		return typed, nil
	}
	items, ok := value.([]any)
	if !ok {
		return nil, errors.New("swarm input artifact invalid")
	}
	out := []map[string]any{}
	for _, item := range items {
		entry, ok := item.(map[string]any)
		if !ok {
			return nil, errors.New("swarm input artifact invalid")
		}
		out = append(out, entry)
	}
	return out, nil
}

func verifySwarmCloseProof(record map[string]any, completed map[string]map[string]any, order map[string][]string, closed map[string]bool) error {
	zone, ok := record["zone"].(map[string]any)
	if !ok {
		return errors.New("swarm close zone missing")
	}
	closeProof, ok := record["close"].(map[string]any)
	if !ok {
		return errors.New("swarm close proof missing")
	}
	if err := verifyZoneDescriptor(zone); err != nil {
		return err
	}
	zoneKey, _, err := publicKey(zone)
	if err != nil {
		return err
	}
	format, exists := closeProof["format"]
	if !exists {
		return errors.New("swarm close format missing")
	}
	switch format {
	case "asp-swarm-close/v1":
		return verifySwarmCloseProofV1(closeProof, zoneKey, completed, order, closed)
	case "asp-swarm-close/v2":
		return verifySwarmCloseProofV2(closeProof, zoneKey, completed, order, closed)
	default:
		return errors.New("unsupported swarm close format")
	}
}

func verifySwarmCloseProofV1(closeProof map[string]any, zoneKey ed25519.PublicKey, completed map[string]map[string]any, order map[string][]string, closed map[string]bool) error {
	if !hasRequiredAllowedMapFields(closeProof,
		[]string{"format", "swarm_id", "step_receipts", "close_signature"},
		[]string{"plan_digest", "execution_graph_digest", "micro_contracts", "migration_log", "conflict_resolutions", "scheduler"},
	) {
		return errors.New("swarm close v1 fields invalid")
	}
	if err := verifyMapSignature(zoneKey, closeProof, "close_signature"); err != nil {
		return errors.New("swarm close signature verification failed")
	}
	swarmID, expected, err := verifySwarmCloseIdentity(closeProof, completed, closed)
	if err != nil {
		return err
	}
	steps, err := swarmCloseStepReceipts(closeProof["step_receipts"])
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for index, step := range steps {
		if !hasRequiredAllowedMapFields(step, []string{"step_id", "task_id", "receipt_digest"}, []string{"worker"}) {
			return errors.New("swarm close v1 step fields invalid")
		}
		stepID, err := verifySwarmCloseStepIdentity(step, seen)
		if err != nil {
			return err
		}
		if index >= len(order[swarmID]) || stepID != order[swarmID][index] {
			return errors.New("swarm close step order mismatch")
		}
		receipt, ok := completed[swarmID+"\x00"+stepID]
		if !ok {
			return errors.New("swarm close step receipt missing: " + stepID)
		}
		if step["task_id"] != receipt["task_id"] {
			return errors.New("swarm close task mismatch")
		}
		if step["receipt_digest"] != digestHex(receipt) {
			return errors.New("swarm close receipt digest mismatch")
		}
	}
	if len(steps) != expected {
		return errors.New("swarm close step count mismatch")
	}
	scheduler, schedulerPresent := closeProof["scheduler"]
	if err := verifySwarmCloseScheduler(scheduler, schedulerPresent, steps, seen, true, nil); err != nil {
		return err
	}
	if err := verifySwarmMigrationLog(closeProof["migration_log"], seen); err != nil {
		return err
	}
	closed[swarmID] = true
	return nil
}

func verifySwarmCloseProofV2(closeProof map[string]any, zoneKey ed25519.PublicKey, completed map[string]map[string]any, observed map[string][]string, closed map[string]bool) error {
	if !hasRequiredAllowedMapFields(closeProof,
		[]string{"format", "swarm_id", "plan_digest", "execution_graph_digest", "step_receipts", "final_output", "close_signature"},
		[]string{"micro_contracts", "migration_log", "conflict_resolutions", "scheduler"},
	) {
		return errors.New("swarm close v2 fields invalid")
	}
	if !isHexDigest(optionalString(closeProof["plan_digest"])) {
		return errors.New("swarm close plan digest invalid")
	}
	if !isHexDigest(optionalString(closeProof["execution_graph_digest"])) {
		return errors.New("swarm close execution graph digest invalid")
	}
	if err := verifyMapSignature(zoneKey, closeProof, "close_signature"); err != nil {
		return errors.New("swarm close signature verification failed")
	}
	swarmID, expected, err := verifySwarmCloseIdentity(closeProof, completed, closed)
	if err != nil {
		return err
	}
	steps, err := swarmCloseStepReceipts(closeProof["step_receipts"])
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	bindingSteps := make([]map[string]any, 0, len(steps))
	receiptsByStep := make(map[string]map[string]any, len(steps))
	stepReceiptOrder := make([]string, 0, len(steps))
	for _, step := range steps {
		if !hasRequiredAllowedMapFields(step, []string{"step_id", "task_id", "signed_receipt_digest"}, []string{"worker"}) {
			return errors.New("swarm close v2 step fields invalid")
		}
		stepID, err := verifySwarmCloseStepIdentity(step, seen)
		if err != nil {
			return err
		}
		receipt, ok := completed[swarmID+"\x00"+stepID]
		if !ok {
			return errors.New("swarm close step receipt missing: " + stepID)
		}
		if step["task_id"] != receipt["task_id"] {
			return errors.New("swarm close task mismatch")
		}
		signedDigest, err := verifier.SignedReceiptDigest(receipt)
		if err != nil {
			return err
		}
		if step["signed_receipt_digest"] != signedDigest {
			return errors.New("swarm close signed receipt digest mismatch")
		}
		swarm, ok := receipt["swarm"].(map[string]any)
		if !ok || swarm == nil {
			return errors.New("receipt swarm binding missing")
		}
		if swarm["swarm_id"] != swarmID || swarm["step_id"] != stepID {
			return errors.New("swarm close receipt binding mismatch")
		}
		if swarm["plan_digest"] != closeProof["plan_digest"] {
			return errors.New("swarm close plan digest mismatch")
		}
		if swarm["execution_graph_digest"] != closeProof["execution_graph_digest"] {
			return errors.New("swarm close execution graph digest mismatch")
		}
		dependsOn, err := swarmAfterSteps(swarm["after"])
		if err != nil {
			return err
		}
		capability := optionalString(swarm["capability"])
		taskDigest := optionalString(swarm["task_digest"])
		if capability == "" || !isHexDigest(taskDigest) || receipt["task_digest"] != taskDigest {
			return errors.New("swarm close receipt binding mismatch")
		}
		bindingSteps = append(bindingSteps, map[string]any{"step_id": stepID, "depends_on": dependsOn, "capability": capability, "task_digest": taskDigest})
		stepReceiptOrder = append(stepReceiptOrder, stepID)
		receiptsByStep[stepID] = receipt
	}
	if len(steps) != expected {
		return errors.New("swarm close step count mismatch")
	}
	scheduler, schedulerPresent := closeProof["scheduler"]
	if err := verifySwarmCloseScheduler(scheduler, schedulerPresent, steps, seen, false, observed[swarmID]); err != nil {
		return err
	}
	if !schedulerPresent && !sameStepOrder(observed[swarmID], stepReceiptOrder) {
		return errors.New("swarm close scheduler evidence required")
	}
	if err := verifySwarmMigrationLog(closeProof["migration_log"], seen); err != nil {
		return err
	}
	finalOutput, ok := closeProof["final_output"].(map[string]any)
	if !ok || !hasRequiredAllowedMapFields(finalOutput, []string{"step_id", "task_id", "signed_receipt_digest", "artifact", "selection_rule"}, nil) {
		return errors.New("swarm close final output fields invalid")
	}
	artifact, ok := finalOutput["artifact"].(map[string]any)
	if !ok || !hasRequiredAllowedMapFields(artifact, []string{"uri", "sha256", "manifest_hash"}, nil) {
		return errors.New("swarm close final output artifact fields invalid")
	}
	binding := map[string]any{
		"format":                 "asp-swarm-execution-binding/v1",
		"swarm_id":               swarmID,
		"plan_digest":            closeProof["plan_digest"],
		"steps":                  bindingSteps,
		"execution_graph_digest": closeProof["execution_graph_digest"],
		"binding_signature":      "audit-verified-binding",
	}
	derived, err := verifier.DeriveSwarmFinalOutput(binding, receiptsByStep)
	if err != nil {
		if strings.Contains(err.Error(), "execution binding graph digest mismatch") {
			return errors.New("swarm close execution graph digest mismatch")
		}
		return err
	}
	if !reflect.DeepEqual(derived, finalOutput) {
		return errors.New("swarm close final output mismatch")
	}
	closed[swarmID] = true
	return nil
}

func verifySwarmCloseIdentity(closeProof map[string]any, completed map[string]map[string]any, closed map[string]bool) (string, int, error) {
	swarmID := optionalString(closeProof["swarm_id"])
	if swarmID == "" {
		return "", 0, errors.New("swarm close identity missing")
	}
	if hasSwarmDelimiter(swarmID) {
		return "", 0, errors.New("swarm identity contains NUL")
	}
	if closed[swarmID] {
		return "", 0, errors.New("duplicate swarm close proof: " + swarmID)
	}
	expected := 0
	for key := range completed {
		if strings.HasPrefix(key, swarmID+"\x00") {
			expected++
		}
	}
	if expected == 0 {
		return "", 0, errors.New("swarm close proof without receipts: " + swarmID)
	}
	return swarmID, expected, nil
}

func verifySwarmCloseStepIdentity(step map[string]any, seen map[string]bool) (string, error) {
	stepID := optionalString(step["step_id"])
	if stepID == "" {
		return "", errors.New("swarm close step identity missing")
	}
	if hasSwarmDelimiter(stepID) {
		return "", errors.New("swarm identity contains NUL")
	}
	if seen[stepID] {
		return "", errors.New("duplicate swarm close step receipt: " + stepID)
	}
	seen[stepID] = true
	return stepID, nil
}

func verifySwarmCloseScheduler(value any, present bool, steps []map[string]any, seen map[string]bool, requireReceiptOrder bool, observedOrder []string) error {
	if !present {
		return nil
	}
	if value == nil {
		return errors.New("swarm close scheduler invalid")
	}
	scheduler, ok := value.(map[string]any)
	if !ok || !hasRequiredAllowedMapFields(scheduler, []string{"mode", "step_order"}, nil) {
		return errors.New("swarm close scheduler invalid")
	}
	if scheduler["mode"] != "ready-dag" {
		return errors.New("swarm close scheduler mode invalid")
	}
	var order []string
	switch typed := scheduler["step_order"].(type) {
	case []string:
		order = typed
	case []any:
		order = make([]string, 0, len(typed))
		for _, item := range typed {
			stepID, ok := item.(string)
			if !ok {
				return errors.New("swarm close scheduler step invalid")
			}
			order = append(order, stepID)
		}
	default:
		return errors.New("swarm close scheduler step order invalid")
	}
	if len(order) != len(seen) {
		return errors.New("swarm close scheduler step order mismatch")
	}
	scheduled := map[string]bool{}
	for index, stepID := range order {
		if stepID == "" || hasSwarmDelimiter(stepID) {
			return errors.New("swarm close scheduler step invalid")
		}
		if scheduled[stepID] {
			return errors.New("swarm close scheduler step duplicate")
		}
		if !seen[stepID] {
			return errors.New("swarm close scheduler step missing")
		}
		if requireReceiptOrder && optionalString(steps[index]["step_id"]) != stepID {
			return errors.New("swarm close scheduler step_order mismatch")
		}
		scheduled[stepID] = true
	}
	if len(observedOrder) > 0 && !sameStepOrder(order, observedOrder) {
		return errors.New("swarm close scheduler observed order mismatch")
	}
	return nil
}

func sameStepOrder(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func hasRequiredAllowedMapFields(value map[string]any, required, optional []string) bool {
	if value == nil {
		return false
	}
	allowed := make(map[string]bool, len(required)+len(optional))
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

func verifySwarmMigrationLog(value any, seen map[string]bool) error {
	if value == nil {
		return nil
	}
	items, ok := value.([]any)
	if !ok {
		if typed, ok := value.([]map[string]any); ok {
			for _, entry := range typed {
				if err := verifySwarmMigrationEntry(entry, seen); err != nil {
					return err
				}
			}
			return nil
		}
		return errors.New("swarm close migration_log invalid")
	}
	for _, item := range items {
		entry, ok := item.(map[string]any)
		if !ok {
			return errors.New("swarm close migration entry invalid")
		}
		if err := verifySwarmMigrationEntry(entry, seen); err != nil {
			return err
		}
	}
	return nil
}

func verifySwarmMigrationEntry(entry map[string]any, seen map[string]bool) error {
	stepID := optionalString(entry["step_id"])
	if stepID == "" || hasSwarmDelimiter(stepID) {
		return errors.New("swarm close migration step invalid")
	}
	if !seen[stepID] {
		return errors.New("swarm close migration step missing")
	}
	if optionalString(entry["original_worker_aid"]) == "" {
		return errors.New("swarm close migration original worker missing")
	}
	if optionalString(entry["migrated_to_worker_aid"]) == "" {
		return errors.New("swarm close migration target worker missing")
	}
	if optionalString(entry["reason"]) == "" {
		return errors.New("swarm close migration reason missing")
	}
	if _, err := time.Parse(time.RFC3339Nano, optionalString(entry["migration_at"])); err != nil {
		return errors.New("swarm close migration_at invalid")
	}
	return nil
}

func swarmCloseStepReceipts(value any) ([]map[string]any, error) {
	if typed, ok := value.([]map[string]any); ok {
		return typed, nil
	}
	items, ok := value.([]any)
	if !ok {
		return nil, errors.New("swarm close step receipt invalid")
	}
	out := []map[string]any{}
	for _, item := range items {
		entry, ok := item.(map[string]any)
		if !ok {
			return nil, errors.New("swarm close step receipt invalid")
		}
		out = append(out, entry)
	}
	return out, nil
}

func hasSwarmDelimiter(value string) bool {
	return strings.Contains(value, "\x00")
}

func isHexDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') {
			continue
		}
		return false
	}
	return true
}

func verifyApprovalGrants(zoneKey ed25519.PublicKey, receipt map[string]any) error {
	approvals, err := receiptApprovals(receipt["approvals"])
	if err != nil {
		return err
	}
	grants, err := receiptApprovalGrants(receipt["approval_grants"])
	if err != nil {
		return err
	}
	if len(approvals) != len(grants) {
		return errors.New("receipt approval grant count mismatch")
	}
	for _, grant := range grants {
		if grant["task_id"] != receipt["task_id"] {
			return errors.New("approval grant task mismatch")
		}
		if err := verifyMapSignature(zoneKey, grant, "approval_signature"); err != nil {
			return errors.New("approval signature verification failed")
		}
	}
	return nil
}

func receiptApprovals(value any) ([]string, error) {
	if value == nil {
		return nil, nil
	}
	if typed, ok := value.([]string); ok {
		return typed, nil
	}
	items, ok := value.([]any)
	if !ok {
		return nil, errors.New("receipt approval invalid")
	}
	out := []string{}
	for _, item := range items {
		text, ok := item.(string)
		if !ok {
			return nil, errors.New("receipt approval invalid")
		}
		out = append(out, text)
	}
	return out, nil
}

func receiptApprovalGrants(value any) ([]map[string]any, error) {
	if value == nil {
		return nil, nil
	}
	if typed, ok := value.([]map[string]any); ok {
		return typed, nil
	}
	items, ok := value.([]any)
	if !ok {
		return nil, errors.New("approval grant invalid")
	}
	out := []map[string]any{}
	for _, item := range items {
		entry, ok := item.(map[string]any)
		if !ok {
			return nil, errors.New("approval grant invalid")
		}
		out = append(out, entry)
	}
	return out, nil
}

func verifyCheckpoints(workerKey ed25519.PublicKey, receipt map[string]any) error {
	refs, err := receiptCheckpointRefs(receipt["checkpoint_refs"])
	if err != nil {
		return err
	}
	checkpoints, err := receiptCheckpoints(receipt["checkpoints"])
	if err != nil {
		return err
	}
	if len(refs) != len(checkpoints) {
		return errors.New("receipt checkpoint ref count mismatch")
	}
	parent := any(nil)
	if resumedFrom, ok := receipt["resumed_from"]; ok {
		parent = resumedFrom
	}
	for index, checkpoint := range checkpoints {
		if checkpoint["task_id"] != receipt["task_id"] {
			return errors.New("checkpoint task mismatch")
		}
		if checkpoint["checkpoint_id"] != refs[index] {
			return errors.New("checkpoint ref mismatch")
		}
		if checkpoint["parent_checkpoint"] != parent {
			return errors.New("checkpoint parent mismatch")
		}
		if err := verifyMapSignature(workerKey, checkpoint, "checkpoint_signature"); err != nil {
			return errors.New("checkpoint signature verification failed")
		}
		parent = checkpoint["checkpoint_id"]
	}
	return nil
}

func receiptCheckpointRefs(value any) ([]string, error) {
	if value == nil {
		return nil, nil
	}
	if typed, ok := value.([]string); ok {
		return typed, nil
	}
	items, ok := value.([]any)
	if !ok {
		return nil, errors.New("checkpoint ref invalid")
	}
	out := []string{}
	for _, item := range items {
		text, ok := item.(string)
		if !ok {
			return nil, errors.New("checkpoint ref invalid")
		}
		out = append(out, text)
	}
	return out, nil
}

func receiptCheckpoints(value any) ([]map[string]any, error) {
	if value == nil {
		return nil, nil
	}
	if typed, ok := value.([]map[string]any); ok {
		return typed, nil
	}
	items, ok := value.([]any)
	if !ok {
		return nil, errors.New("checkpoint invalid")
	}
	out := []map[string]any{}
	for _, item := range items {
		entry, ok := item.(map[string]any)
		if !ok {
			return nil, errors.New("checkpoint invalid")
		}
		out = append(out, entry)
	}
	return out, nil
}

func verifyArtifactManifests(receipt map[string]any, artifactStoreDir string) error {
	refs, err := artifactRefsFromAny(receipt["artifact_refs"])
	if err != nil {
		return err
	}
	manifests, err := artifactManifestsFromAny(receipt["artifact_manifests"])
	if err != nil {
		return err
	}
	if len(refs) != len(manifests) {
		return errors.New("receipt artifact manifest count mismatch")
	}
	var artifactStoreIndex []map[string]any
	if artifactStoreDir != "" && len(manifests) > 0 {
		index, err := readArtifactStoreIndex(filepath.Join(artifactStoreDir, "objects.ndjson"))
		if err != nil {
			return err
		}
		artifactStoreIndex = index
	}
	for index, manifest := range manifests {
		if _, ok := manifest["uri"].(string); !ok {
			return errors.New("artifact manifest uri invalid")
		}
		if manifest["uri"] != refs[index] {
			return errors.New("artifact manifest uri mismatch")
		}
		for _, field := range []string{"sha256", "media_type", "manifest_hash"} {
			if fmt.Sprint(manifest[field]) == "" {
				return errors.New("artifact manifest " + field + " missing")
			}
		}
		if _, ok := manifest["media_type"].(string); !ok {
			return errors.New("artifact manifest media_type invalid")
		}
		if _, ok := manifest["manifest_hash"].(string); !ok {
			return errors.New("artifact manifest manifest_hash invalid")
		}
		if !isHexDigest(fmt.Sprint(manifest["sha256"])) {
			return errors.New("artifact manifest sha256 invalid")
		}
		if afp, ok := manifest["afp"]; ok {
			afpText, ok := afp.(string)
			if !ok {
				return errors.New("artifact manifest afp invalid")
			}
			if afpText != "afp:sha256:"+fmt.Sprint(manifest["sha256"]) {
				return errors.New("artifact manifest afp mismatch")
			}
		}
		size, ok := manifest["size"].(float64)
		if !ok {
			return errors.New("artifact manifest size missing")
		}
		if size < 0 || size != math.Trunc(size) {
			return errors.New("artifact manifest size invalid")
		}
		path, err := localArtifactPath(refs[index])
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sidecarData, err := os.ReadFile(path + ".manifest.json")
		if err != nil {
			return err
		}
		var sidecar map[string]any
		if err := json.Unmarshal(sidecarData, &sidecar); err != nil {
			return err
		}
		if digestHex(sidecar) != digestHex(manifest) {
			return errors.New("artifact manifest sidecar mismatch")
		}
		digestSidecarData, err := os.ReadFile(filepath.Join("artifacts", "by-sha256", fmt.Sprint(manifest["sha256"])) + ".manifest.json")
		if err != nil {
			return err
		}
		var digestSidecar map[string]any
		if err := json.Unmarshal(digestSidecarData, &digestSidecar); err != nil {
			return err
		}
		if digestHex(digestSidecar) != digestHex(manifest) {
			return errors.New("artifact digest sidecar mismatch")
		}
		if artifactStoreDir != "" {
			mirrorPath := filepath.Join(artifactStoreDir, "by-sha256", fmt.Sprint(manifest["sha256"]))
			mirrorData, err := os.ReadFile(mirrorPath)
			if err != nil {
				return err
			}
			mirrorSidecarData, err := os.ReadFile(mirrorPath + ".manifest.json")
			if err != nil {
				return err
			}
			var mirrorSidecar map[string]any
			if err := json.Unmarshal(mirrorSidecarData, &mirrorSidecar); err != nil {
				return err
			}
			if digestHex(mirrorSidecar) != digestHex(manifest) {
				return errors.New("artifact mirror sidecar mismatch")
			}
			if float64(len(mirrorData)) != manifest["size"] {
				return errors.New("artifact mirror bytes size mismatch")
			}
			if digestBytesHex(mirrorData) != manifest["sha256"] {
				return errors.New("artifact mirror bytes digest mismatch")
			}
			if !artifactStoreIndexContains(artifactStoreIndex, manifest) {
				return errors.New("artifact mirror index entry missing")
			}
		}
		if float64(len(data)) != manifest["size"] {
			return errors.New("artifact bytes size mismatch")
		}
		if digestBytesHex(data) != manifest["sha256"] {
			return errors.New("artifact bytes digest mismatch")
		}
		body := map[string]any{}
		for k, v := range manifest {
			if k != "manifest_hash" {
				body[k] = v
			}
		}
		if manifest["manifest_hash"] != digestHex(body) {
			return errors.New("artifact manifest hash mismatch")
		}
	}
	if digest, ok := receipt["tool_output_digest"]; ok && len(manifests) > 0 && digest != manifests[0]["sha256"] {
		return errors.New("tool output digest mismatch")
	}
	return nil
}

func artifactRefsFromAny(value any) ([]string, error) {
	if value == nil {
		return nil, nil
	}
	if typed, ok := value.([]string); ok {
		return typed, nil
	}
	items, ok := value.([]any)
	if !ok {
		return nil, errors.New("receipt artifact manifest count mismatch")
	}
	out := []string{}
	for _, item := range items {
		text, ok := item.(string)
		if !ok {
			return nil, errors.New("artifact refs invalid")
		}
		out = append(out, text)
	}
	return out, nil
}

func artifactManifestsFromAny(value any) ([]map[string]any, error) {
	if value == nil {
		return nil, nil
	}
	if typed, ok := value.([]map[string]any); ok {
		return typed, nil
	}
	items, ok := value.([]any)
	if !ok {
		return nil, errors.New("receipt artifact manifest count mismatch")
	}
	out := []map[string]any{}
	for _, item := range items {
		entry, ok := item.(map[string]any)
		if !ok {
			return nil, errors.New("artifact manifest missing")
		}
		out = append(out, entry)
	}
	return out, nil
}

func readArtifactStoreIndex(path string) ([]map[string]any, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("artifact mirror index missing")
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	var out []map[string]any
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		entry := map[string]any{}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			return nil, errors.New("artifact mirror index invalid")
		}
		if entry == nil {
			return nil, errors.New("artifact mirror index invalid")
		}
		if !isHexDigest(fmt.Sprint(entry["sha256"])) {
			return nil, errors.New("artifact mirror index invalid")
		}
		if uri, ok := entry["uri"]; ok {
			if _, ok := uri.(string); !ok {
				return nil, errors.New("artifact mirror index invalid")
			}
		}
		if afp, ok := entry["afp"]; ok {
			afpText, ok := afp.(string)
			if !ok {
				return nil, errors.New("artifact mirror index afp invalid")
			}
			if afpText != "afp:sha256:"+fmt.Sprint(entry["sha256"]) {
				return nil, errors.New("artifact mirror index invalid")
			}
		}
		if sizeValue, ok := entry["size"]; ok {
			size, ok := sizeValue.(float64)
			if !ok || size < 0 || size != math.Trunc(size) {
				return nil, errors.New("artifact mirror index invalid")
			}
		}
		if mediaType, exists := entry["media_type"]; exists {
			if _, ok := mediaType.(string); !ok {
				return nil, errors.New("artifact mirror index invalid")
			}
		}
		if manifestHash, ok := entry["manifest_hash"]; ok && !isHexDigest(fmt.Sprint(manifestHash)) {
			return nil, errors.New("artifact mirror index invalid")
		}
		out = append(out, entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func artifactStoreIndexContains(index []map[string]any, manifest map[string]any) bool {
	for _, entry := range index {
		matches := true
		for _, field := range []string{"uri", "sha256", "size", "media_type", "afp", "manifest_hash"} {
			if !reflect.DeepEqual(entry[field], manifest[field]) {
				matches = false
				break
			}
		}
		if matches {
			return true
		}
	}
	return false
}

func receiptArtifactManifest(receipt map[string]any, uri string) (map[string]any, error) {
	refs, err := artifactRefsFromAny(receipt["artifact_refs"])
	if err != nil {
		return nil, err
	}
	manifests, err := artifactManifestsFromAny(receipt["artifact_manifests"])
	if err != nil {
		return nil, err
	}
	for index, ref := range refs {
		if ref == uri && index < len(manifests) {
			return manifests[index], nil
		}
	}
	return nil, errors.New("receipt artifact not found: " + uri)
}

func verifyPolicyScope(receipt map[string]any) error {
	scope, ok := receipt["policy_scope"].(map[string]any)
	if !ok {
		return errors.New("receipt policy scope missing")
	}
	for _, field := range []string{"network", "write", "tools", "data_domains", "approval_required", "expires_at"} {
		if _, ok := scope[field]; !ok {
			return errors.New("policy scope " + field + " missing")
		}
	}
	for _, field := range []string{"write", "tools", "data_domains", "approval_required"} {
		if _, err := policyStringList(scope[field], "policy scope "+field+" invalid"); err != nil {
			return err
		}
	}
	if _, ok := scope["network"].(bool); !ok {
		return errors.New("policy scope network invalid")
	}
	if _, ok := scope["expires_at"].(string); !ok {
		return errors.New("policy scope expires_at invalid")
	}
	if fmt.Sprint(receipt["policy_digest"]) == "" {
		return errors.New("receipt policy digest missing")
	}
	if receipt["policy_digest"] != digestHex(scope) {
		return errors.New("policy digest mismatch")
	}
	return nil
}

// verifyDockerSandboxEvidence validates the complete, receipt-carried evidence
// produced by either supported constrained container runtime. The historical
// name is retained because Docker was the first runtime; generic sandbox
// claims are deliberately not accepted here.
func verifyDockerSandboxEvidence(evidence map[string]any, profile DockerWorkerProfile) error {
	if !hasRequiredAllowedMapFields(evidence,
		[]string{"format", "runtime", "image", "image_id", "container_id", "runtime_identity", "runtime_identity_digest", "constraints", "configuration_digest", "observed", "task_id", "task_digest", "profile_digest", "generation_digest", "result_digest", "transcript_digest"},
		nil,
	) {
		return errors.New("container evidence fields invalid")
	}
	if evidence["format"] != "agnet-container-evidence/v2" {
		return errors.New("container evidence format invalid")
	}
	runtime := optionalString(evidence["runtime"])
	if runtime != "docker" && runtime != "apple-container" {
		return errors.New("container evidence runtime invalid")
	}
	if evidence["image"] != profile.Image || validateDockerImage(profile.Image) != nil {
		return errors.New("container evidence image mismatch")
	}
	imageID := optionalString(evidence["image_id"])
	if !isHexDigest(imageID) {
		return errors.New("container evidence image ID invalid")
	}
	containerID := optionalString(evidence["container_id"])
	if runtime == "docker" && !validDockerContainerID(containerID) {
		return errors.New("docker container evidence identifier invalid")
	}
	if runtime == "apple-container" && validateAppleContainerID(containerID) != nil {
		return errors.New("apple container evidence identifier invalid")
	}
	if err := validateContainerRuntimeIdentity(runtime, profile.Image, imageID, evidence["runtime_identity"], evidence["runtime_identity_digest"]); err != nil {
		return errors.New("container runtime identity mismatch")
	}
	constraints, ok := evidence["constraints"].(map[string]any)
	if !ok || !reflect.DeepEqual(constraints, dockerReceiptConstraints(profile)) || evidence["configuration_digest"] != digestHex(constraints) {
		return errors.New("container configuration mismatch")
	}
	observed, ok := evidence["observed"].(map[string]any)
	if !ok || !hasRequiredAllowedMapFields(observed, []string{"exit_code", "result_bytes", "transcript_bytes", "artifact_count"}, nil) ||
		!nonNegativeWholeNumber(observed["result_bytes"]) || !nonNegativeWholeNumber(observed["transcript_bytes"]) || !nonNegativeWholeNumber(observed["artifact_count"]) || observed["exit_code"] != float64(0) {
		return errors.New("container observed counts invalid")
	}
	if err := validateTaskID(optionalString(evidence["task_id"])); err != nil {
		return errors.New("container evidence task ID invalid")
	}
	for _, field := range []string{"task_digest", "generation_digest", "result_digest", "transcript_digest"} {
		if !isHexDigest(optionalString(evidence[field])) {
			return errors.New("container evidence " + field + " invalid")
		}
	}
	if evidence["profile_digest"] != dockerReceiptProfileDigest(profile) {
		return errors.New("container evidence profile mismatch")
	}
	return nil
}

func dockerReceiptConstraints(profile DockerWorkerProfile) map[string]any {
	request, err := validateDockerWorkerProfile(profile)
	if err != nil {
		return nil
	}
	return containerAdapterConstraints(request)
}

func dockerReceiptProfileDigest(profile DockerWorkerProfile) string {
	encoded, err := json.Marshal(profile)
	if err != nil {
		return ""
	}
	var profileMap map[string]any
	if err := json.Unmarshal(encoded, &profileMap); err != nil {
		return ""
	}
	return digestHex(profileMap)
}

func nonNegativeWholeNumber(value any) bool {
	number, ok := value.(float64)
	return ok && number >= 0 && number == math.Trunc(number)
}
func verifyContainerReceiptEvidence(receipt, sandbox, proof map[string]any) error {
	evidenceValue, evidencePresent := sandbox["container_evidence"]
	profileValue, profilePresent := receipt["container_profile"]
	generationValue, generationPresent := receipt["container_generation_digest"]
	if !evidencePresent && !profilePresent && !generationPresent {
		if receipt["sandbox_claim"] == "container-namespace" || sandbox["runtime"] != nil {
			return errors.New("container receipt evidence missing")
		}
		return nil
	}
	if !evidencePresent || !profilePresent || !generationPresent {
		return errors.New("container receipt binding missing")
	}
	evidence, ok := evidenceValue.(map[string]any)
	if !ok {
		return errors.New("container receipt evidence invalid")
	}
	proofSandbox, ok := proof["sandbox"].(map[string]any)
	if !ok || !reflect.DeepEqual(proofSandbox["container_evidence"], evidence) {
		return errors.New("container receipt proof evidence mismatch")
	}
	profile, err := dockerProfileFromReceipt(profileValue)
	if err != nil {
		return err
	}
	if err := verifyDockerSandboxEvidence(evidence, profile); err != nil {
		return err
	}
	if evidence["profile_digest"] != digestHex(profileValue) {
		return errors.New("container receipt profile digest mismatch")
	}
	if evidence["task_id"] != receipt["task_id"] || evidence["task_digest"] != receipt["task_digest"] || evidence["generation_digest"] != generationValue {
		return errors.New("container receipt task or generation binding mismatch")
	}
	result, ok := receipt["result_artifact"].(map[string]any)
	if !ok || evidence["result_digest"] != result["sha256"] {
		return errors.New("container receipt result binding mismatch")
	}
	resultManifest, err := receiptArtifactManifest(receipt, optionalString(result["uri"]))
	if err != nil || !sameObservedManifestSize(evidence, "result_bytes", resultManifest) {
		return errors.New("container receipt result binding mismatch")
	}
	transcript, ok := sandbox["tool_transcript_manifest"].(map[string]any)
	if !ok || evidence["transcript_digest"] != transcript["sha256"] || !sameObservedManifestSize(evidence, "transcript_bytes", transcript) {
		return errors.New("container receipt transcript binding mismatch")
	}
	manifests, err := artifactManifestsFromAny(receipt["artifact_manifests"])
	if err != nil || !sameObservedManifestSize(evidence, "artifact_count", map[string]any{"size": float64(len(manifests))}) {
		return errors.New("container receipt artifact count mismatch")
	}
	return nil
}

func dockerProfileFromReceipt(value any) (DockerWorkerProfile, error) {
	profileMap, ok := value.(map[string]any)
	if !ok || !hasRequiredAllowedMapFields(profileMap, []string{"image", "command", "limits"}, []string{"scratch_inputs"}) {
		return DockerWorkerProfile{}, errors.New("container receipt profile invalid")
	}
	limits, ok := profileMap["limits"].(map[string]any)
	if !ok || !hasRequiredAllowedMapFields(limits, []string{"cpu_millis", "memory_bytes", "timeout_millis", "max_output_bytes", "max_scratch_input_bytes", "max_scratch_bytes"}, nil) {
		return DockerWorkerProfile{}, errors.New("container receipt profile limits invalid")
	}
	encoded, err := json.Marshal(profileMap)
	if err != nil {
		return DockerWorkerProfile{}, errors.New("container receipt profile invalid")
	}
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.DisallowUnknownFields()
	var profile DockerWorkerProfile
	if err := decoder.Decode(&profile); err != nil || decoder.More() {
		return DockerWorkerProfile{}, errors.New("container receipt profile invalid")
	}
	if _, err := validateDockerWorkerProfile(profile); err != nil {
		return DockerWorkerProfile{}, errors.New("container receipt profile invalid")
	}
	return profile, nil
}

func sameObservedManifestSize(evidence map[string]any, observedField string, manifest map[string]any) bool {
	observed, _ := evidence["observed"].(map[string]any)
	return observed[observedField] == manifest["size"]
}

func verifySandboxProof(zoneKey ed25519.PublicKey, receipt map[string]any) error {
	proof, ok := receipt["sandbox_proof"].(map[string]any)
	if !ok {
		return errors.New("receipt sandbox proof missing")
	}
	sandbox, ok := receipt["sandbox"].(map[string]any)
	if !ok {
		return errors.New("receipt sandbox missing")
	}
	if proof["proof_type"] != "local.sandbox.v1" {
		return errors.New("sandbox proof type mismatch")
	}
	if proof["authority"] != receipt["executing_zone"] {
		return errors.New("sandbox proof authority mismatch")
	}
	if proof["task_id"] != receipt["task_id"] {
		return errors.New("sandbox proof task mismatch")
	}
	if proof["worker"] != receipt["to"] {
		return errors.New("sandbox proof worker mismatch")
	}
	if proof["policy_digest"] != receipt["policy_digest"] {
		return errors.New("sandbox proof policy mismatch")
	}
	if digestHex(proof["sandbox"]) != digestHex(sandbox) {
		return errors.New("sandbox proof evidence mismatch")
	}
	if claim, ok := receipt["sandbox_claim"]; ok && proof["sandbox_claim"] != claim {
		return errors.New("sandbox proof claim mismatch")
	}
	if err := verifyContainerReceiptEvidence(receipt, sandbox, proof); err != nil {
		return err
	}
	if err := verifyMapSignature(zoneKey, proof, "sandbox_signature"); err != nil {
		return errors.New("sandbox proof signature verification failed")
	}
	return nil
}

func verifyZoneBinding(zone, binding, worker map[string]any) error {
	zoneKey, _, err := publicKey(zone)
	if err != nil {
		return err
	}
	expected := map[string]any{"zone": zone["zid"], "alias": worker["alias"], "aid": worker["aid"]}
	if binding["zone"] != expected["zone"] || binding["alias"] != expected["alias"] || binding["aid"] != expected["aid"] {
		return errors.New("zone binding mismatch")
	}
	if err := verifyMapSignature(zoneKey, binding, "signature"); err != nil {
		return errors.New("zone binding signature verification failed")
	}
	return nil
}

func enforcePolicy(worker, task map[string]any) error {
	policy, _ := worker["policy"].(map[string]any)
	scope, _ := task["scope"].(map[string]any)
	if scope["network"] == true && policy["allow_network"] != true {
		return policyError{code: "policy.network_denied", message: "policy denied network access"}
	}
	writeTargets, err := policyStringList(scope["write"], "policy write scope invalid")
	if err != nil {
		return policyError{code: "policy.write_invalid", message: "policy write scope invalid"}
	}
	for _, target := range writeTargets {
		if !hasPrefix(target, stringsFromAny(policy["write_prefixes"])) {
			return policyError{code: "policy.write_denied", message: "policy denied write scope: " + target}
		}
	}
	if _, err := policyStringList(scope["data_domains"], "policy data domains invalid"); err != nil {
		return policyError{code: "policy.data_domains_invalid", message: "policy data domains invalid"}
	}
	if _, err := policyStringList(policy["approval_required"], "policy approval required invalid"); err != nil {
		return policyError{code: "policy.approval_required_invalid", message: "policy approval required invalid"}
	}
	return nil
}
