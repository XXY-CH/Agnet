package main

import (
	"agnet/verifier"
	"encoding/base64"
	"encoding/json"
	"errors"
)

// maxLocalSwarmReadyWaveWidth is the conservative, fixed process and goroutine
// fanout limit for one durable Kahn layer. Phase A rejects larger signed swarms
// rather than truncating or queuing any part of a claimed wave.
const maxLocalSwarmReadyWaveWidth = 32

// maxLocalSwarmStepCount keeps all durable local execution bounded by the same
// limit as its launcher pool.
const maxLocalSwarmStepCount = maxLocalSwarmReadyWaveWidth

// executeSwarm and executeScheduledSwarm remain only as compatibility test
// seams while legacy callers migrate to LocalSwarmCoordinator. They never
// execute a Swarm.
func (f Fixture) executeSwarm(send sendFunc, origin, frame map[string]any) error {
	return errors.New("legacy serial swarm execution removed")
}

func (f Fixture) executeScheduledSwarm(send sendFunc, origin, frame map[string]any) error {
	return errors.New("legacy serial swarm execution removed")
}

// durableSwarmResponseFrames emits only values replayed from a journal-synced
// durable view. A child process result is never an outbound authority.
func durableSwarmResponseFrames(journal *SwarmJournal, expected SwarmView) ([]map[string]any, error) {
	if journal == nil || expected.SwarmID == "" { return nil, errors.New("durable swarm response journal required") }
	var stableClose *StoredSwarmClose
	var disband *StoredSwarmDisband
	if expected.Status == SwarmStatusCompleted || expected.Status == SwarmStatusClosing {
		stored, err := EnsureStableClose(journal); if err != nil { return nil, err }
		stableClose = &stored
	}
	if expected.Status == SwarmStatusCompleted {
		entries, err := journal.Replay(); if err != nil { return nil, err }
		state, err := ReduceSwarmEntries(entries); if err != nil { return nil, err }
		if state.OutputVerification != nil {
			stored, err := EnsureDisband(journal); if err != nil { return nil, err }
			disband = &stored
		}
	}
	view, err := ReadSwarmView(journal); if err != nil { return nil, err }
	if view.SwarmID != expected.SwarmID { return nil, errors.New("durable swarm response identity mismatch") }
	if stableClose == nil && (view.JournalHead != expected.JournalHead || view.Version != expected.Version) { return nil, errors.New("durable swarm state changed before response sync") }
	entries, err := journal.Replay(); if err != nil { return nil, err }
	if len(entries) == 0 || entries[len(entries)-1].Hash != view.JournalHead { return nil, errors.New("durable swarm response journal head mismatch") }
	state, err := ReduceSwarmEntries(entries); if err != nil { return nil, err }
	zone := cloneFrozenMap(state.Spec.LocalAuthority)
	if zone == nil { return nil, errors.New("durable swarm local authority missing") }
	frames := []map[string]any{{"type": "FED_SWARM_STATE", "zone": zone, "swarm": view}}
	for _, entry := range entries {
		if entry.Kind != "receipt.committed" { continue }
		var payload receiptCommittedPayload
		if err := decodeStrictSwarmPayload(entry.Payload, &payload); err != nil || payload.validateCanonical() != nil { return nil, errors.New("durable swarm committed receipt invalid") }
		raw, err := base64.RawURLEncoding.DecodeString(payload.Receipt); if err != nil || !json.Valid(raw) { return nil, errors.New("durable swarm committed receipt invalid") }
		worker, err := frozenAgentDescriptor(payload.Claim.Candidate.Descriptor); if err != nil { return nil, errors.New("durable swarm committed worker invalid") }
		binding, err := frozenZoneBinding(payload.Claim.Candidate.ZoneBinding); if err != nil || verifyZoneBinding(zone, binding, worker) != nil { return nil, errors.New("durable swarm committed worker binding invalid") }
		frames = append(frames, map[string]any{"type": "FED_RECEIPT", "zone": cloneFrozenMap(zone), "worker": worker, "zone_binding": binding, "receipt": json.RawMessage(append([]byte(nil), raw...))})
	}
	if stableClose == nil && state.StoredClose.Digest != "" {
		stored := state.StoredClose
		stableClose = &stored
	}
	if stableClose != nil {
		if !json.Valid(stableClose.Bytes) { return nil, errors.New("durable swarm close invalid") }
		frames = append(frames, map[string]any{"type": "FED_SWARM_CLOSE", "swarm_id": view.SwarmID, "zone": cloneFrozenMap(zone), "close": json.RawMessage(append([]byte(nil), stableClose.Bytes...))})
	}
	if disband == nil && state.Status == SwarmStatusDisbanded {
		stored := state.StoredDisband
		disband = &stored
	}
	if disband != nil {
		if !json.Valid(disband.Bytes) { return nil, errors.New("durable swarm disband invalid") }
		frames = append(frames, map[string]any{"type": "FED_SWARM_DISBAND", "swarm_id": view.SwarmID, "zone": cloneFrozenMap(zone), "disband": json.RawMessage(append([]byte(nil), disband.Bytes...))})
	}
	return frames, nil
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

func validateVerifiedSwarmBounds(steps []*verifiedSwarmStep) error {
	if len(steps) > maxLocalSwarmStepCount {
		return errors.New("swarm step count exceeds maximum 32")
	}
	completed := make(map[string]bool, len(steps))
	for len(completed) < len(steps) {
		ready := 0
		for _, step := range steps {
			if completed[step.stepID] {
				continue
			}
			dependenciesComplete := true
			for _, dependency := range step.after {
				if !completed[dependency] {
					dependenciesComplete = false
					break
				}
			}
			if dependenciesComplete {
				ready++
			}
		}
		if ready == 0 {
			return errors.New("swarm dependency graph has no ready wave")
		}
		if ready > maxLocalSwarmReadyWaveWidth {
			return errors.New("swarm ready wave width exceeds maximum 32")
		}
		for _, step := range steps {
			if completed[step.stepID] {
				continue
			}
			dependenciesComplete := true
			for _, dependency := range step.after {
				if !completed[dependency] {
					dependenciesComplete = false
					break
				}
			}
			if dependenciesComplete {
				completed[step.stepID] = true
			}
		}
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
	if len(normalized) > maxLocalSwarmStepCount {
		return nil, errors.New("swarm step count exceeds maximum 32")
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

	if readyDAG {
		return nil, errors.New("legacy swarm scheduler removed")
	}
	if err := validateOrderedSwarmDependencies(verifiedSteps); err != nil {
		return nil, err
	}
	if err := validateVerifiedSwarmBounds(verifiedSteps); err != nil {
		return nil, err
	}
	executionSteps := verifiedSteps
	var scheduler map[string]any
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


