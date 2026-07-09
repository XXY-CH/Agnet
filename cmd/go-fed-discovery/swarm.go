package main

import (
	"errors"
	"sort"
	"strings"
	"time"
)

func (f Fixture) swarmMicroContract(worker *Worker, swarmID, stepID string, task map[string]any) map[string]any {
	policyDigest := digestHex(taskPolicyScope(worker.Profile, worker.Descriptor, task))
	taskJSON, _ := canonicalJSON(task)
	tokenEstimate := (len(taskJSON) + 3) / 4
	if tokenEstimate < 1 {
		tokenEstimate = 1
	}
	seconds := 30
	if budget, ok := task["budget"].(map[string]any); ok {
		if value, ok := budget["time_seconds"].(float64); ok && value >= 0 {
			seconds = int(value)
		}
	}
	capabilityProof := ""
	switch capabilities := worker.Descriptor["capabilities"].(type) {
	case []string:
		capabilityProof = strings.Join(capabilities, ",")
	case []any:
		parts := make([]string, 0, len(capabilities))
		for _, capability := range capabilities {
			if value, ok := capability.(string); ok {
				parts = append(parts, value)
			}
		}
		capabilityProof = strings.Join(parts, ",")
	}
	body := map[string]any{
		"micro_contract":   "ok",
		"swarm_id":         swarmID,
		"step_id":          stepID,
		"worker":           worker.Descriptor,
		"capability_proof": capabilityProof,
		"policy_digest":    policyDigest,
		"cost_estimate":    map[string]any{"tokens": float64(tokenEstimate), "seconds": float64(seconds)},
	}
	signed := signBody(worker.PrivateKey, body)
	signed["contract_digest"] = digestHex(body)
	return signed
}

func (f Fixture) executeSwarm(send sendFunc, origin, frame map[string]any) error {
	return f.executeSwarmWithScheduler(send, origin, frame, nil)
}

func (f Fixture) executeScheduledSwarm(send sendFunc, origin, frame map[string]any) error {
	return f.executeSwarmWithScheduler(send, origin, frame, map[string]any{"mode": "ready-dag"})
}

func capabilitiesFromDescriptor(descriptor map[string]any) []string {
	return stringsFromAny(descriptor["capabilities"])
}

func sharesWorkerCapability(left, right *Worker) bool {
	rightCapabilities := map[string]bool{}
	for _, capability := range capabilitiesFromDescriptor(right.Descriptor) {
		rightCapabilities[capability] = true
	}
	for _, capability := range capabilitiesFromDescriptor(left.Descriptor) {
		if rightCapabilities[capability] {
			return true
		}
	}
	return false
}

func (f Fixture) migrationCandidate(original *Worker) *Worker {
	for i := range f.Workers {
		candidate := &f.Workers[i]
		if optionalString(candidate.Descriptor["aid"]) == optionalString(original.Descriptor["aid"]) {
			continue
		}
		if sharesWorkerCapability(original, candidate) {
			return candidate
		}
	}
	return nil
}

func migrationLogEntry(stepID string, original *Worker, reason string, migrated *Worker) map[string]any {
	return map[string]any{
		"step_id":                stepID,
		"original_worker_aid":    original.Descriptor["aid"],
		"reason":                 reason,
		"migrated_to_worker_aid": migrated.Descriptor["aid"],
		"migration_at":           time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
	}
}

func (f Fixture) swarmWorkerAgentScore(descriptor map[string]any) int {
	aid := optionalString(descriptor["aid"])
	for i := range f.Workers {
		worker := &f.Workers[i]
		if optionalString(worker.Descriptor["aid"]) != aid {
			continue
		}
		capabilities := capabilitiesFromDescriptor(worker.Descriptor)
		if len(capabilities) == 0 {
			return 0
		}
		match := f.queryMatch(worker, capabilities[0], "", nil)
		if match == nil {
			return 0
		}
		evidence, _ := match["discovery_evidence"].(map[string]any)
		reputation, _ := evidence["reputation"].(map[string]any)
		agentScore, _ := reputation["agent_score"].(map[string]any)
		return intFromMap(agentScore, "total")
	}
	return 0
}

func (f Fixture) conflictResolutionForGroup(swarmID, artifactRef string, entries []map[string]any) map[string]any {
	sorted := append([]map[string]any{}, entries...)
	sort.SliceStable(sorted, func(i, j int) bool {
		leftScore := f.swarmWorkerAgentScore(sorted[i]["worker"].(map[string]any))
		rightScore := f.swarmWorkerAgentScore(sorted[j]["worker"].(map[string]any))
		if leftScore != rightScore {
			return leftScore > rightScore
		}
		return optionalString(sorted[i]["alias"]) < optionalString(sorted[j]["alias"])
	})
	chosen := sorted[0]
	runnerUp := sorted[1]
	reason := "alias_tiebreak"
	if f.swarmWorkerAgentScore(chosen["worker"].(map[string]any)) > f.swarmWorkerAgentScore(runnerUp["worker"].(map[string]any)) {
		reason = "higher_reputation"
	}
	candidateStepIDs := []string{}
	for _, entry := range entries {
		candidateStepIDs = append(candidateStepIDs, optionalString(entry["step_id"]))
	}
	body := map[string]any{
		"swarm_id":           swarmID,
		"artifact_ref":       artifactRef,
		"candidate_step_ids": candidateStepIDs,
		"chosen_step_id":     chosen["step_id"],
		"chosen_worker":      chosen["worker"],
		"reason":             reason,
	}
	signed := signBodyWithKey(f.AuthorityPrivateKey, body, "signature")
	signed["resolution_digest"] = digestHex(body)
	return signed
}

func (f Fixture) swarmConflictResolutions(swarmID string, completed map[string]map[string]any, stepReceipts []map[string]any) []map[string]any {
	byArtifact := map[string][]map[string]any{}
	for _, step := range stepReceipts {
		stepID := optionalString(step["step_id"])
		receipt := completed[stepID]
		for _, manifest := range mapsFromAny(receipt["artifact_manifests"]) {
			uri := optionalString(manifest["uri"])
			sha := optionalString(manifest["sha256"])
			if uri == "" || sha == "" {
				continue
			}
			worker, _ := step["worker"].(map[string]any)
			byArtifact[uri] = append(byArtifact[uri], map[string]any{"step_id": stepID, "worker": worker, "alias": optionalString(worker["alias"]), "sha256": sha})
		}
	}
	refs := make([]string, 0, len(byArtifact))
	for ref := range byArtifact {
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	resolutions := []map[string]any{}
	for _, ref := range refs {
		entries := byArtifact[ref]
		stepIDs := map[string]bool{}
		digests := map[string]bool{}
		for _, entry := range entries {
			stepIDs[optionalString(entry["step_id"])] = true
			digests[optionalString(entry["sha256"])] = true
		}
		if len(stepIDs) >= 2 && len(digests) >= 2 {
			resolutions = append(resolutions, f.conflictResolutionForGroup(swarmID, ref, entries))
		}
	}
	return resolutions
}

func (f Fixture) executeSwarmWithScheduler(send sendFunc, origin, frame map[string]any, scheduler map[string]any) error {
	requester, ok := frame["requester"].(map[string]any)
	if !ok {
		return errors.New("swarm requester missing")
	}
	binding, ok := frame["requester_zone_binding"].(map[string]any)
	if !ok {
		return errors.New("requester zone binding missing")
	}
	if err := verifyZoneBinding(origin, binding, requester); err != nil {
		return err
	}
	swarm, ok := frame["swarm"].(map[string]any)
	if !ok {
		return errors.New("swarm body missing")
	}
	swarmID := optionalString(swarm["swarm_id"])
	if swarmID == "" {
		return errors.New("swarm_id missing")
	}
	if hasSwarmDelimiter(swarmID) {
		return errors.New("swarm identity contains NUL")
	}
	steps, ok := swarm["steps"].([]any)
	if !ok || len(steps) == 0 {
		return errors.New("swarm steps missing")
	}
	var err error
	if scheduler != nil {
		var stepOrder []string
		steps, stepOrder, err = scheduleSwarmSteps(steps)
		if err != nil {
			return err
		}
		scheduler["step_order"] = stepOrder
	}
	completed := map[string]map[string]any{}
	stepReceipts := []map[string]any{}
	microContracts := []map[string]any{}
	migrationLog := []map[string]any{}
	for _, item := range steps {
		step, ok := item.(map[string]any)
		if !ok {
			return errors.New("swarm step invalid")
		}
		stepID := optionalString(step["step_id"])
		if stepID == "" {
			return errors.New("swarm step_id missing")
		}
		if hasSwarmDelimiter(stepID) {
			return errors.New("swarm identity contains NUL")
		}
		if _, exists := completed[stepID]; exists {
			return errors.New("duplicate swarm step: " + stepID)
		}
		after, err := swarmAfterSteps(step["after"])
		if err != nil {
			return err
		}
		inputArtifacts := []map[string]any{}
		for _, dependency := range after {
			if hasSwarmDelimiter(dependency) {
				return errors.New("swarm identity contains NUL")
			}
			receipt, ok := completed[dependency]
			if !ok {
				return errors.New("swarm dependency not completed: " + dependency)
			}
			manifests := mapsFromAny(receipt["artifact_manifests"])
			if len(manifests) == 0 {
				return errors.New("swarm dependency artifact missing: " + dependency)
			}
			manifest := manifests[0]
			inputArtifacts = append(inputArtifacts, map[string]any{
				"step_id":        dependency,
				"uri":            manifest["uri"],
				"sha256":         manifest["sha256"],
				"manifest_hash":  manifest["manifest_hash"],
				"receipt_digest": digestHex(receipt),
			})
		}
		task, ok := step["task"].(map[string]any)
		if !ok {
			return errors.New("swarm step task missing")
		}
		worker, task, err := f.verifyTaskOpen(map[string]any{"type": "FED_TASK_OPEN", "requester": requester, "task": task})
		if err != nil {
			return err
		}
		proof := map[string]any{
			"swarm_id":        swarmID,
			"step_id":         stepID,
			"after":           after,
			"input_artifacts": inputArtifacts,
		}
		microContract := f.swarmMicroContract(worker, swarmID, stepID, task)
		if err := f.sendTaskEvent(send, microContract); err != nil {
			return err
		}
		executeErr := f.executeTask(send, origin, worker, task, nil, "", nil, false, map[string]any{"swarm": proof}, func(receipt map[string]any) error {
			completed[stepID] = receipt
			stepReceipts = append(stepReceipts, map[string]any{"step_id": stepID, "task_id": receipt["task_id"], "receipt_digest": digestHex(receipt), "worker": worker.Descriptor})
			return nil
		})
		if executeErr == nil {
			microContracts = append(microContracts, microContract)
			continue
		}
		migratedWorker := f.migrationCandidate(worker)
		if migratedWorker == nil {
			return executeErr
		}
		migratedMicroContract := f.swarmMicroContract(migratedWorker, swarmID, stepID, task)
		if err := f.sendTaskEvent(send, migratedMicroContract); err != nil {
			return err
		}
		if err := f.executeTask(send, origin, migratedWorker, task, nil, "", nil, false, map[string]any{"swarm": proof}, func(receipt map[string]any) error {
			completed[stepID] = receipt
			stepReceipts = append(stepReceipts, map[string]any{"step_id": stepID, "task_id": receipt["task_id"], "receipt_digest": digestHex(receipt), "worker": migratedWorker.Descriptor})
			return nil
		}); err != nil {
			return err
		}
		microContracts = append(microContracts, migratedMicroContract)
		migrationLog = append(migrationLog, migrationLogEntry(stepID, worker, executeErr.Error(), migratedWorker))
	}
	conflictResolutions := f.swarmConflictResolutions(swarmID, completed, stepReceipts)
	for _, resolution := range conflictResolutions {
		if err := f.sendTaskEvent(send, resolution); err != nil {
			return err
		}
	}
	closeBody := map[string]any{"swarm_id": swarmID, "step_receipts": stepReceipts, "micro_contracts": microContracts, "migration_log": migrationLog}
	if len(conflictResolutions) > 0 {
		closeBody["conflict_resolutions"] = conflictResolutions
	}
	if scheduler != nil {
		closeBody["scheduler"] = scheduler
	}
	closeProof := signBodyWithKey(f.AuthorityPrivateKey, closeBody, "close_signature")
	if err := f.appendAudit(map[string]any{"kind": "go_swarm_close", "zone": f.Authority, "close": closeProof}); err != nil {
		return err
	}
	send(map[string]any{"type": "FED_SWARM_CLOSE", "swarm_id": swarmID, "zone": f.Authority, "close": closeProof})
	return nil
}

func scheduleSwarmSteps(items []any) ([]any, []string, error) {
	pending := map[string]map[string]any{}
	afterByStep := map[string][]string{}
	inputOrder := []string{}
	for _, item := range items {
		step, ok := item.(map[string]any)
		if !ok {
			return nil, nil, errors.New("swarm step invalid")
		}
		stepID := optionalString(step["step_id"])
		if stepID == "" {
			return nil, nil, errors.New("swarm step_id missing")
		}
		if hasSwarmDelimiter(stepID) {
			return nil, nil, errors.New("swarm identity contains NUL")
		}
		if _, exists := pending[stepID]; exists {
			return nil, nil, errors.New("duplicate swarm step: " + stepID)
		}
		after, err := swarmAfterSteps(step["after"])
		if err != nil {
			return nil, nil, err
		}
		pending[stepID] = step
		afterByStep[stepID] = after
		inputOrder = append(inputOrder, stepID)
	}
	done := map[string]bool{}
	ordered := []any{}
	stepOrder := []string{}
	for len(pending) > 0 {
		progressed := false
		for _, stepID := range inputOrder {
			step, ok := pending[stepID]
			if !ok {
				continue
			}
			ready := true
			for _, dependency := range afterByStep[stepID] {
				if hasSwarmDelimiter(dependency) {
					return nil, nil, errors.New("swarm identity contains NUL")
				}
				if !done[dependency] {
					ready = false
					break
				}
			}
			if !ready {
				continue
			}
			ordered = append(ordered, step)
			stepOrder = append(stepOrder, stepID)
			done[stepID] = true
			delete(pending, stepID)
			progressed = true
		}
		if !progressed {
			return nil, nil, errors.New("swarm schedule dependency unresolved")
		}
	}
	return ordered, stepOrder, nil
}
