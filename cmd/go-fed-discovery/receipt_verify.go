package main

import (
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
		dependency := optionalString(input["step_id"])
		if hasSwarmDelimiter(dependency) || hasSwarmDelimiter(after[i]) {
			return errors.New("swarm identity contains NUL")
		}
		if dependency != after[i] {
			return errors.New("swarm input artifact step mismatch")
		}
		manifest, ok := completed[swarmID+"\x00"+dependency]
		if !ok {
			return errors.New("swarm dependency receipt missing: " + dependency)
		}
		if len(manifest) == 0 {
			return errors.New("swarm dependency artifact missing: " + dependency)
		}
		if input["uri"] != manifest["uri"] {
			return errors.New("swarm input artifact uri mismatch")
		}
		if input["sha256"] != manifest["sha256"] {
			return errors.New("swarm input artifact digest mismatch")
		}
		if input["manifest_hash"] != manifest["manifest_hash"] {
			return errors.New("swarm input artifact manifest hash mismatch")
		}
		if input["receipt_digest"] != manifest["receipt_digest"] {
			return errors.New("swarm input receipt digest mismatch")
		}
	}
	completedKey := swarmID + "\x00" + stepID
	if _, exists := completed[completedKey]; exists {
		return errors.New("duplicate swarm step receipt: " + stepID)
	}
	manifests := mapsFromAny(receipt["artifact_manifests"])
	if len(manifests) == 0 {
		completed[completedKey] = map[string]any{"task_id": receipt["task_id"], "receipt_digest": digestHex(receipt)}
		order[swarmID] = append(order[swarmID], stepID)
		return nil
	}
	manifest := map[string]any{}
	for key, value := range manifests[0] {
		manifest[key] = value
	}
	manifest["task_id"] = receipt["task_id"]
	manifest["receipt_digest"] = digestHex(receipt)
	completed[completedKey] = manifest
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
	if err := verifyMapSignature(zoneKey, closeProof, "close_signature"); err != nil {
		return errors.New("swarm close signature verification failed")
	}
	swarmID := optionalString(closeProof["swarm_id"])
	if swarmID == "" {
		return errors.New("swarm close identity missing")
	}
	if hasSwarmDelimiter(swarmID) {
		return errors.New("swarm identity contains NUL")
	}
	if closed[swarmID] {
		return errors.New("duplicate swarm close proof: " + swarmID)
	}
	expected := 0
	for key := range completed {
		if strings.HasPrefix(key, swarmID+"\x00") {
			expected++
		}
	}
	if expected == 0 {
		return errors.New("swarm close proof without receipts: " + swarmID)
	}
	steps, err := swarmCloseStepReceipts(closeProof["step_receipts"])
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, step := range steps {
		stepID := optionalString(step["step_id"])
		if stepID == "" {
			return errors.New("swarm close step identity missing")
		}
		if hasSwarmDelimiter(stepID) {
			return errors.New("swarm identity contains NUL")
		}
		if seen[stepID] {
			return errors.New("duplicate swarm close step receipt: " + stepID)
		}
		seen[stepID] = true
	}
	if err := verifySwarmMigrationLog(closeProof["migration_log"], seen); err != nil {
		return err
	}
	if len(steps) != expected {
		return errors.New("swarm close step count mismatch")
	}
	for index, step := range steps {
		stepID := optionalString(step["step_id"])
		if index >= len(order[swarmID]) || stepID != order[swarmID][index] {
			return errors.New("swarm close step order mismatch")
		}
		completedStep, ok := completed[swarmID+"\x00"+stepID]
		if !ok {
			return errors.New("swarm close step receipt missing: " + stepID)
		}
		if step["task_id"] != completedStep["task_id"] {
			return errors.New("swarm close task mismatch")
		}
		if step["receipt_digest"] != completedStep["receipt_digest"] {
			return errors.New("swarm close receipt digest mismatch")
		}
	}
	closed[swarmID] = true
	return nil
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
