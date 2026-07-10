package main

import (
	"agnet/verifier"
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

func workerAdvertisesCapability(worker *Worker, capability string) bool {
	for _, advertised := range capabilitiesFromDescriptor(worker.Descriptor) {
		if advertised == capability {
			return true
		}
	}
	return false
}

func (f Fixture) migrationCandidate(original *Worker, capability, stepID string) (*Worker, error) {
	foundSharedCapability := false
	for i := range f.Workers {
		candidate := &f.Workers[i]
		if optionalString(candidate.Descriptor["aid"]) == optionalString(original.Descriptor["aid"]) {
			continue
		}
		if !sharesWorkerCapability(original, candidate) {
			continue
		}
		foundSharedCapability = true
		if workerAdvertisesCapability(candidate, capability) {
			return candidate, nil
		}
	}
	if foundSharedCapability {
		return nil, errors.New("execution binding migration worker capability missing: " + stepID)
	}
	return nil, nil
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

type verifiedSwarmStep struct {
	stepID              string
	after               []string
	capability          string
	taskDigest          string
	signedTask          map[string]any
	originalWorker      *Worker
	migrationWorker     *Worker
	originalPolicyError error
}

type verifiedSwarmExecution struct {
	swarmID              string
	planDigest           string
	executionGraphDigest string
	binding              map[string]any
	signedOrder          []string
	executionSteps       []*verifiedSwarmStep
	scheduler            map[string]any
}

func normalizeExecutableSwarmSteps(items []any) ([]map[string]any, error) {
	normalized := make([]map[string]any, 0, len(items))
	for _, item := range items {
		step, ok := item.(map[string]any)
		if !ok {
			return nil, errors.New("swarm step invalid")
		}
		stepID := optionalString(step["step_id"])
		if stepID == "" {
			return nil, errors.New("swarm step_id missing")
		}
		if hasSwarmDelimiter(stepID) {
			return nil, errors.New("swarm identity contains NUL")
		}
		after, err := swarmAfterSteps(step["after"])
		if err != nil {
			return nil, err
		}
		task, ok := step["task"].(map[string]any)
		if !ok {
			return nil, errors.New("swarm step task missing")
		}
		normalized = append(normalized, map[string]any{"step_id": stepID, "depends_on": after, "task": task})
	}
	return normalized, nil
}

func verifySwarmPlanOrigin(planFrame, origin map[string]any) error {
	if planFrame["type"] != "FED_SWARM_PLAN" {
		return errors.New("expected FED_SWARM_PLAN frame")
	}
	planZone, ok := planFrame["zone"].(map[string]any)
	if !ok {
		return errors.New("swarm plan zone missing")
	}
	if planZone["zid"] != origin["zid"] || planZone["public_key_spki"] != origin["public_key_spki"] {
		return errors.New("swarm plan origin mismatch")
	}
	return nil
}

func validateOrderedSwarmDependencies(steps []*verifiedSwarmStep) error {
	completed := map[string]bool{}
	for _, step := range steps {
		for _, dependency := range step.after {
			if !completed[dependency] {
				return errors.New("swarm dependency not completed: " + dependency)
			}
		}
		completed[step.stepID] = true
	}
	return nil
}

func (f Fixture) preflightSwarmExecution(origin, frame map[string]any, readyDAG bool) (*verifiedSwarmExecution, error) {
	requester, ok := frame["requester"].(map[string]any)
	if !ok {
		return nil, errors.New("swarm requester missing")
	}
	requesterBinding, ok := frame["requester_zone_binding"].(map[string]any)
	if !ok {
		return nil, errors.New("requester zone binding missing")
	}
	if err := verifyZoneBinding(origin, requesterBinding, requester); err != nil {
		return nil, err
	}
	swarm, ok := frame["swarm"].(map[string]any)
	if !ok {
		return nil, errors.New("swarm body missing")
	}
	swarmID := optionalString(swarm["swarm_id"])
	if swarmID == "" {
		return nil, errors.New("swarm_id missing")
	}
	if hasSwarmDelimiter(swarmID) {
		return nil, errors.New("swarm identity contains NUL")
	}
	items, ok := swarm["steps"].([]any)
	if !ok || len(items) == 0 {
		return nil, errors.New("swarm steps missing")
	}
	planFrame, ok := swarm["plan"].(map[string]any)
	if !ok {
		return nil, errors.New("swarm plan missing")
	}
	if err := verifySwarmPlanOrigin(planFrame, origin); err != nil {
		return nil, err
	}
	binding, ok := swarm["execution_binding"].(map[string]any)
	if !ok {
		return nil, errors.New("execution binding missing")
	}
	normalized, err := normalizeExecutableSwarmSteps(items)
	if err != nil {
		return nil, err
	}
	evidence := make([]*verifiedTaskOpenEvidence, 0, len(normalized))
	originalWorkers := make([]map[string]any, 0, len(normalized))
	for _, step := range normalized {
		verifiedTask, err := f.verifyTaskOpenEvidence(map[string]any{
			"type":                   "FED_TASK_OPEN",
			"origin_zone":            origin,
			"requester":              requester,
			"requester_zone_binding": requesterBinding,
			"task":                   step["task"],
		})
		if err != nil {
			return nil, err
		}
		evidence = append(evidence, verifiedTask)
		originalWorkers = append(originalWorkers, verifiedTask.Worker.Descriptor)
	}
	graphDigest, err := verifier.VerifySwarmExecutionBinding(binding, planFrame, normalized, originalWorkers)
	if err != nil {
		return nil, err
	}
	if binding["swarm_id"] != swarmID {
		return nil, errors.New("execution binding swarm_id mismatch")
	}
	boundSteps := mapsFromAny(binding["steps"])
	verifiedSteps := make([]*verifiedSwarmStep, 0, len(normalized))
	migrationWorkers := make([]map[string]any, 0, len(normalized))
	hasMigrationWorker := false
	signedOrder := make([]string, 0, len(normalized))
	for index, step := range normalized {
		boundStep := boundSteps[index]
		stepID := optionalString(boundStep["step_id"])
		capability := optionalString(boundStep["capability"])
		var originalPolicyError error
		if err := enforcePolicy(evidence[index].Worker.Descriptor, evidence[index].SignedTask); err != nil {
			originalPolicyError = err
		}
		migrationWorker, err := f.migrationCandidate(evidence[index].Worker, capability, stepID)
		if err != nil {
			return nil, err
		}
		if migrationWorker != nil {
			if err := enforcePolicy(migrationWorker.Descriptor, evidence[index].SignedTask); err != nil {
				return nil, err
			}
			hasMigrationWorker = true
			migrationWorkers = append(migrationWorkers, migrationWorker.Descriptor)
		} else {
			if originalPolicyError != nil {
				return nil, originalPolicyError
			}
			migrationWorkers = append(migrationWorkers, evidence[index].Worker.Descriptor)
		}
		verifiedSteps = append(verifiedSteps, &verifiedSwarmStep{
			stepID:              stepID,
			after:               append([]string{}, step["depends_on"].([]string)...),
			capability:          capability,
			taskDigest:          optionalString(boundStep["task_digest"]),
			signedTask:          evidence[index].SignedTask,
			originalWorker:      evidence[index].Worker,
			migrationWorker:     migrationWorker,
			originalPolicyError: originalPolicyError,
		})
		signedOrder = append(signedOrder, stepID)
	}
	if hasMigrationWorker {
		if _, err := verifier.VerifySwarmExecutionBinding(binding, planFrame, normalized, migrationWorkers); err != nil {
			return nil, err
		}
	}

	executionSteps := verifiedSteps
	var scheduler map[string]any
	if readyDAG {
		ordered, stepOrder, err := scheduleSwarmSteps(items)
		if err != nil {
			return nil, err
		}
		byStepID := map[string]*verifiedSwarmStep{}
		for _, step := range verifiedSteps {
			byStepID[step.stepID] = step
		}
		executionSteps = make([]*verifiedSwarmStep, 0, len(ordered))
		for _, item := range ordered {
			step := item.(map[string]any)
			verifiedStep := byStepID[optionalString(step["step_id"])]
			if verifiedStep == nil {
				return nil, errors.New("swarm schedule dependency unresolved")
			}
			executionSteps = append(executionSteps, verifiedStep)
		}
		scheduler = map[string]any{"mode": "ready-dag", "step_order": stepOrder}
	} else if err := validateOrderedSwarmDependencies(verifiedSteps); err != nil {
		return nil, err
	}
	return &verifiedSwarmExecution{
		swarmID:              swarmID,
		planDigest:           optionalString(binding["plan_digest"]),
		executionGraphDigest: graphDigest,
		binding:              binding,
		signedOrder:          signedOrder,
		executionSteps:       executionSteps,
		scheduler:            scheduler,
	}, nil
}

func (f Fixture) executeSwarmWithScheduler(send sendFunc, origin, frame map[string]any, scheduler map[string]any) error {
	context, err := f.preflightSwarmExecution(origin, frame, scheduler != nil)
	if err != nil {
		return err
	}
	completed := map[string]map[string]any{}
	completedWorkers := map[string]map[string]any{}
	microContracts := []map[string]any{}
	migrationLog := []map[string]any{}
	for _, step := range context.executionSteps {
		inputArtifacts := []map[string]any{}
		for _, dependency := range step.after {
			receipt, ok := completed[dependency]
			if !ok {
				return errors.New("swarm dependency not completed: " + dependency)
			}
			manifest, err := verifier.VerifyResultArtifact(receipt)
			if err != nil {
				return err
			}
			if manifest == nil {
				return errors.New("swarm dependency artifact missing: " + dependency)
			}
			signedDependencyDigest, err := verifier.SignedReceiptDigest(receipt)
			if err != nil {
				return err
			}
			inputArtifacts = append(inputArtifacts, map[string]any{
				"step_id":               dependency,
				"uri":                   manifest["uri"],
				"sha256":                manifest["sha256"],
				"manifest_hash":         manifest["manifest_hash"],
				"signed_receipt_digest": signedDependencyDigest,
			})
		}
		proof := map[string]any{
			"swarm_id":               context.swarmID,
			"step_id":                step.stepID,
			"after":                  step.after,
			"input_artifacts":        inputArtifacts,
			"plan_digest":            context.planDigest,
			"execution_graph_digest": context.executionGraphDigest,
			"capability":             step.capability,
			"task_digest":            step.taskDigest,
		}
		var executeErr error = step.originalPolicyError
		if executeErr == nil {
			microContract := f.swarmMicroContract(step.originalWorker, context.swarmID, step.stepID, step.signedTask)
			if err := f.sendTaskEvent(send, microContract); err != nil {
				return err
			}
			executeErr = f.executeTask(send, origin, step.originalWorker, step.signedTask, nil, "", nil, false, map[string]any{"swarm": proof}, func(receipt map[string]any) error {
				completed[step.stepID] = receipt
				completedWorkers[step.stepID] = step.originalWorker.Descriptor
				return nil
			})
			if executeErr == nil {
				microContracts = append(microContracts, microContract)
				continue
			}
		}
		if step.migrationWorker == nil {
			return executeErr
		}
		migratedMicroContract := f.swarmMicroContract(step.migrationWorker, context.swarmID, step.stepID, step.signedTask)
		if err := f.sendTaskEvent(send, migratedMicroContract); err != nil {
			return err
		}
		if err := f.executeTask(send, origin, step.migrationWorker, step.signedTask, nil, "", nil, false, map[string]any{"swarm": proof}, func(receipt map[string]any) error {
			completed[step.stepID] = receipt
			completedWorkers[step.stepID] = step.migrationWorker.Descriptor
			return nil
		}); err != nil {
			return err
		}
		microContracts = append(microContracts, migratedMicroContract)
		migrationLog = append(migrationLog, migrationLogEntry(step.stepID, step.originalWorker, executeErr.Error(), step.migrationWorker))
	}
	stepReceipts := make([]map[string]any, 0, len(context.signedOrder))
	for _, stepID := range context.signedOrder {
		receipt := completed[stepID]
		worker := completedWorkers[stepID]
		if receipt == nil || worker == nil {
			return errors.New("swarm completed receipt missing: " + stepID)
		}
		receiptDigest, err := verifier.SignedReceiptDigest(receipt)
		if err != nil {
			return err
		}
		stepReceipts = append(stepReceipts, map[string]any{"step_id": stepID, "task_id": receipt["task_id"], "signed_receipt_digest": receiptDigest, "worker": worker})
	}
	finalOutput, err := verifier.DeriveSwarmFinalOutput(context.binding, completed)
	if err != nil {
		return err
	}
	conflictResolutions := f.swarmConflictResolutions(context.swarmID, completed, stepReceipts)
	for _, resolution := range conflictResolutions {
		if err := f.sendTaskEvent(send, resolution); err != nil {
			return err
		}
	}
	closeBody := map[string]any{
		"format":                 "asp-swarm-close/v2",
		"swarm_id":               context.swarmID,
		"plan_digest":            context.planDigest,
		"execution_graph_digest": context.executionGraphDigest,
		"step_receipts":          stepReceipts,
		"final_output":           finalOutput,
		"micro_contracts":        microContracts,
		"migration_log":          migrationLog,
	}
	if len(conflictResolutions) > 0 {
		closeBody["conflict_resolutions"] = conflictResolutions
	}
	if context.scheduler != nil {
		closeBody["scheduler"] = context.scheduler
	}
	closeProof := signBodyWithKey(f.AuthorityPrivateKey, closeBody, "close_signature")
	if err := f.appendAudit(map[string]any{"kind": "go_swarm_close", "zone": f.Authority, "close": closeProof}); err != nil {
		return err
	}
	send(map[string]any{"type": "FED_SWARM_CLOSE", "swarm_id": context.swarmID, "zone": f.Authority, "close": closeProof})
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
