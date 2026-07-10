package main

import (
	"context"
	"errors"
	"fmt"
)

func (f Fixture) transportProof() map[string]any {
	if f.Transport == "" {
		return nil
	}
	return map[string]any{
		"transport":        f.Transport,
		"listen_host":      f.ListenHost,
		"port":             f.ListenPort,
		"public_transport": f.PublicTransport,
	}
}

type verifiedTaskOpenEvidence struct {
	Worker     *Worker
	SignedTask map[string]any
}

func (f Fixture) verifyTaskOpenEvidence(frame map[string]any) (*verifiedTaskOpenEvidence, error) {
	if frame["type"] != "FED_TASK_OPEN" {
		return nil, errors.New("expected FED_TASK_OPEN frame")
	}
	requester, ok := frame["requester"].(map[string]any)
	if !ok {
		return nil, errors.New("missing requester")
	}
	if err := verifyAgentDescriptor(requester); err != nil {
		return nil, err
	}
	if origin, ok := frame["origin_zone"].(map[string]any); ok {
		binding, ok := frame["requester_zone_binding"].(map[string]any)
		if !ok {
			return nil, errors.New("requester zone binding missing")
		}
		if err := verifyZoneBinding(origin, binding, requester); err != nil {
			return nil, err
		}
	}
	task, ok := frame["task"].(map[string]any)
	if !ok {
		return nil, errors.New("missing task")
	}
	if err := validateTaskID(optionalString(task["task_id"])); err != nil {
		return nil, err
	}
	if task["from"] != requester["aid"] {
		return nil, errors.New("task sender does not match requester descriptor")
	}
	worker := f.workerByAlias(fmt.Sprint(task["to"]))
	if worker == nil {
		return nil, errors.New("task target does not match worker alias")
	}
	requesterKey, _, err := publicKey(requester)
	if err != nil {
		return nil, err
	}
	if err := verifyMapSignature(requesterKey, task, "signature"); err != nil {
		return nil, errors.New("task signature verification failed")
	}
	return &verifiedTaskOpenEvidence{Worker: worker, SignedTask: task}, nil
}

func (f Fixture) verifyTaskOpen(frame map[string]any) (*Worker, map[string]any, error) {
	evidence, err := f.verifyTaskOpenEvidence(frame)
	if err != nil {
		return nil, nil, err
	}
	if err := enforcePolicy(evidence.Worker.Descriptor, evidence.SignedTask); err != nil {
		return nil, nil, err
	}
	return evidence.Worker, evidence.SignedTask, nil
}

func taskOpenFrameForVerification(frame map[string]any) map[string]any {
	return map[string]any{
		"type":                   "FED_TASK_OPEN",
		"origin_zone":            frame["origin_zone"],
		"requester":              frame["requester"],
		"requester_zone_binding": frame["requester_zone_binding"],
		"task":                   frame["task"],
	}
}

func (f Fixture) verifyTaskCancel(frame map[string]any) (*Worker, map[string]any, map[string]any, error) {
	requester, ok := frame["requester"].(map[string]any)
	if !ok {
		return nil, nil, nil, errors.New("missing requester")
	}
	if err := verifyAgentDescriptor(requester); err != nil {
		return nil, nil, nil, err
	}
	cancel, ok := frame["cancel"].(map[string]any)
	if !ok {
		return nil, nil, nil, errors.New("missing cancel")
	}
	if cancel["from"] != requester["aid"] {
		return nil, nil, nil, errors.New("cancel sender does not match requester descriptor")
	}
	worker := f.workerByAlias(fmt.Sprint(cancel["to"]))
	if worker == nil {
		return nil, nil, nil, errors.New("cancel target does not match worker alias")
	}
	if fmt.Sprint(cancel["task_id"]) == "" {
		return nil, nil, nil, errors.New("cancel task_id missing")
	}
	if err := validateTaskID(optionalString(cancel["task_id"])); err != nil {
		return nil, nil, nil, err
	}
	requesterKey, _, err := publicKey(requester)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := verifyMapSignature(requesterKey, cancel, "signature"); err != nil {
		return nil, nil, nil, errors.New("cancel signature verification failed")
	}
	return worker, requester, cancel, nil
}

func taskArtifactURI(task map[string]any, fallback string) (string, error) {
	value, exists := task["artifact_ref"]
	if !exists {
		return fallback, nil
	}
	uri := optionalString(value)
	if uri == "" || hasSwarmDelimiter(uri) {
		return "", errors.New("task artifact_ref invalid")
	}
	return uri, nil
}

func (f Fixture) executeTask(send sendFunc, origin map[string]any, worker *Worker, task map[string]any, parentCheckpoint any, restoredStateDigest string, retryOf any, requireHumanApproval bool, receiptExtra map[string]any, onReceipt func(map[string]any) error) error {
	taskID := fmt.Sprint(task["task_id"])
	ctx, cancelRun := context.WithCancel(context.Background())
	f.Runtime.Register(taskID, cancelRun)
	defer cancelRun()
	defer f.Runtime.Unregister(taskID)
	if err := f.sendTaskEvent(send, map[string]any{"type": "task.accepted", "task_id": taskID, "by": worker.Descriptor["aid"], "zone": f.Authority["zid"]}); err != nil {
		return err
	}
	if err := validateSandboxClaim(worker.Profile); err != nil {
		extra := map[string]any{"error": err.Error()}
		var claimErr sandboxClaimError
		if errors.As(err, &claimErr) {
			extra["sandbox_probe"] = claimErr.probe
		}
		_ = f.writeTaskState(taskID, "failed", worker, extra)
		return err
	}
	approvals := toolApprovalReasons(worker.Profile)
	approvalGrants := []map[string]any{}
	if len(approvals) > 0 {
		if requireHumanApproval {
			if err := f.writeApprovalState(taskID, "pending", approvals, "", nil, approvalExpiresAt(task)); err != nil {
				return err
			}
		}
		if err := f.sendTaskEvent(send, map[string]any{"type": "approval.required", "task_id": taskID, "reasons": approvals}); err != nil {
			return err
		}
		grant := f.approvalGrant(taskID, approvals, "human://go-gateway/operator")
		if requireHumanApproval {
			var err error
			grant, err = f.waitForApproval(ctx, taskID)
			if err != nil {
				return err
			}
		}
		approvalGrants = append(approvalGrants, grant)
		if err := f.sendTaskEvent(send, map[string]any{"type": "approval.granted", "task_id": taskID, "by": grant["by"], "reasons": approvals, "grant": grant}); err != nil {
			return err
		}
	}
	if err := f.sendTaskEvent(send, map[string]any{"type": "task.started", "task_id": taskID, "by": worker.Descriptor["aid"], "zone": f.Authority["zid"]}); err != nil {
		return err
	}
	if err := f.writeTaskState(taskID, "running", worker, map[string]any{}); err != nil {
		return err
	}
	policyScope := taskPolicyScope(worker.Profile, worker.Descriptor, task)
	policyDigest := digestHex(policyScope)
	checkpoint := worker.checkpoint(task, parentCheckpoint, restoredStateDigest, 3+len(approvals)*2, policyDigest)
	if err := f.sendTaskEvent(send, map[string]any{"type": "checkpoint.created", "task_id": taskID, "checkpoint": checkpoint}); err != nil {
		return err
	}

	artifactURI, err := taskArtifactURI(task, "artifact://local/"+taskID+"/go-summary.md")
	if err != nil {
		return err
	}
	toolName, artifactText, sandbox, err := runTool(ctx, worker.Profile, task, origin, f.ArtifactStoreDir, f.LiveTranscriptDir)
	if err != nil {
		if f.Runtime.WasCancelled(taskID) {
			return err
		}
		_ = f.writeTaskState(taskID, "failed", worker, map[string]any{"error": err.Error()})
		return err
	}
	sandboxClaim := worker.Profile.SandboxClaim
	if sandboxClaim != "" && sandbox["mode"] != sandboxClaim {
		return errors.New("sandbox claim mismatch")
	}
	artifactManifest, err := writeArtifact(artifactURI, artifactText, f.ArtifactStoreDir)
	if err != nil {
		return err
	}
	artifactRefs := []string{artifactURI}
	artifactManifests := []map[string]any{artifactManifest}
	if transcriptRef := optionalString(sandbox["tool_transcript_ref"]); transcriptRef != "" {
		transcriptManifest, ok := sandbox["tool_transcript_manifest"].(map[string]any)
		if !ok {
			return errors.New("tool transcript manifest missing")
		}
		artifactRefs = append(artifactRefs, transcriptRef)
		artifactManifests = append(artifactManifests, transcriptManifest)
	}
	if err := f.sendTaskEvent(send, map[string]any{"type": "artifact.created", "task_id": taskID, "uri": artifactURI, "manifest": artifactManifest}); err != nil {
		return err
	}
	if err := f.sendTaskEvent(send, map[string]any{"type": "task.completed", "task_id": taskID, "by": worker.Descriptor["aid"], "zone": f.Authority["zid"]}); err != nil {
		return err
	}
	sandboxProof := f.sandboxProof(taskID, worker, sandbox, policyDigest, sandboxClaim)

	receipt := map[string]any{
		"task_id":            taskID,
		"task_digest":        digestHex(task),
		"from":               task["from"],
		"origin_zone":        origin["zid"],
		"executing_zone":     f.Authority["zid"],
		"to":                 worker.Descriptor["aid"],
		"artifact_refs":      artifactRefs,
		"artifact_manifests": artifactManifests,
		"result_artifact":    map[string]any{"uri": artifactManifest["uri"], "sha256": artifactManifest["sha256"], "manifest_hash": artifactManifest["manifest_hash"]},
		"tool_output_digest": artifactManifest["sha256"],
		"event_count":        float64(5 + len(approvals)*2),
		"approvals":          approvals,
		"approval_grants":    approvalGrants,
		"checkpoint_refs":    []string{fmt.Sprint(checkpoint["checkpoint_id"])},
		"checkpoints":        []map[string]any{checkpoint},
		"policy_scope":       policyScope,
		"policy_digest":      policyDigest,
		"sandbox":            sandbox,
		"sandbox_proof":      sandboxProof,
		"tool":               toolName,
	}
	if transportProof := f.transportProof(); transportProof != nil {
		receipt["transport_proof"] = transportProof
	}
	if sandboxClaim != "" {
		receipt["sandbox_claim"] = sandboxClaim
	}
	if parentCheckpoint != nil {
		receipt["resumed_from"] = parentCheckpoint
	}
	if restoredStateDigest != "" {
		receipt["restored_state_digest"] = restoredStateDigest
	}
	if retryOf != nil {
		receipt["retry_of"] = retryOf
	}
	for key, value := range receiptExtra {
		receipt[key] = value
	}
	signedReceipt := signBody(worker.PrivateKey, receipt)
	receiptRecord := map[string]any{
		"kind":         "go_fed_receipt",
		"zone":         f.Authority,
		"worker":       worker.Descriptor,
		"zone_binding": f.zoneBinding(worker),
		"receipt":      signedReceipt,
	}
	if err := f.appendAudit(receiptRecord); err != nil {
		return err
	}
	if err := f.writeTaskState(taskID, "completed", worker, map[string]any{"receipt_digest": digestHex(signedReceipt)}); err != nil {
		return err
	}
	if onReceipt != nil {
		if err := onReceipt(signedReceipt); err != nil {
			return err
		}
	}
	send(map[string]any{
		"type":         "FED_RECEIPT",
		"zone":         receiptRecord["zone"],
		"worker":       receiptRecord["worker"],
		"zone_binding": receiptRecord["zone_binding"],
		"receipt":      receiptRecord["receipt"],
	})
	send(map[string]any{"type": "FED_TASK_CLOSE", "task_id": taskID})
	return nil
}

func (f Fixture) cancelTask(send sendFunc, origin map[string]any, worker *Worker, requester, cancel map[string]any) error {
	taskID := fmt.Sprint(cancel["task_id"])
	reason := fmt.Sprint(cancel["reason"])
	f.Runtime.Cancel(taskID)
	if err := f.sendTaskEvent(send, map[string]any{
		"type":    "task.cancelled",
		"task_id": taskID,
		"by":      requester["aid"],
		"worker":  worker.Descriptor["aid"],
		"reason":  reason,
	}); err != nil {
		return err
	}
	policyScope := map[string]any{
		"network":           false,
		"write":             []string{},
		"tools":             []string{},
		"data_domains":      []string{},
		"approval_required": []string{},
		"expires_at":        "",
	}
	policyDigest := digestHex(policyScope)
	sandbox := map[string]any{"mode": "not-started"}
	receipt := map[string]any{
		"task_id":            taskID,
		"task_digest":        digestHex(cancel),
		"from":               requester["aid"],
		"origin_zone":        origin["zid"],
		"executing_zone":     f.Authority["zid"],
		"to":                 worker.Descriptor["aid"],
		"status":             "cancelled",
		"cancel":             cancel,
		"artifact_refs":      []string{},
		"artifact_manifests": []map[string]any{},
		"event_count":        float64(1),
		"approvals":          []string{},
		"approval_grants":    []map[string]any{},
		"checkpoint_refs":    []string{},
		"checkpoints":        []map[string]any{},
		"policy_scope":       policyScope,
		"policy_digest":      policyDigest,
		"sandbox":            sandbox,
		"sandbox_proof":      f.sandboxProof(taskID, worker, sandbox, policyDigest, ""),
		"tool":               "none",
	}
	if transportProof := f.transportProof(); transportProof != nil {
		receipt["transport_proof"] = transportProof
	}
	signedReceipt := signBody(worker.PrivateKey, receipt)
	receiptRecord := map[string]any{
		"kind":         "go_fed_receipt",
		"zone":         f.Authority,
		"worker":       worker.Descriptor,
		"zone_binding": f.zoneBinding(worker),
		"receipt":      signedReceipt,
	}
	if err := f.appendAudit(receiptRecord); err != nil {
		return err
	}
	if err := f.writeTaskState(taskID, "cancelled", worker, map[string]any{"receipt_digest": digestHex(signedReceipt)}); err != nil {
		return err
	}
	send(map[string]any{
		"type":         "FED_RECEIPT",
		"zone":         receiptRecord["zone"],
		"worker":       receiptRecord["worker"],
		"zone_binding": receiptRecord["zone_binding"],
		"receipt":      receiptRecord["receipt"],
	})
	send(map[string]any{"type": "FED_CANCEL_CLOSE", "task_id": taskID})
	return nil
}

func (w *Worker) checkpoint(task map[string]any, parent any, restoredStateDigest string, eventIndex int, policyDigest string) map[string]any {
	taskID := fmt.Sprint(task["task_id"])
	body := map[string]any{
		"task_id":           taskID,
		"parent_checkpoint": parent,
		"event_index":       float64(eventIndex),
		"state_digest":      digestHex(map[string]any{"task": task, "worker": w.Descriptor["aid"]}),
		"artifact_refs":     []string{},
		"policy_digest":     policyDigest,
		"created_by":        w.Descriptor["aid"],
	}
	if restoredStateDigest != "" {
		body["restored_state_digest"] = restoredStateDigest
	}
	body["checkpoint_id"] = "checkpoint:sha256:" + digestHex(body)
	return signBodyWithKey(w.PrivateKey, body, "checkpoint_signature")
}

func (f Fixture) approvalGrant(taskID string, reasons []string, by string) map[string]any {
	return signBodyWithKey(f.AuthorityPrivateKey, map[string]any{
		"task_id":   taskID,
		"authority": f.Authority["zid"],
		"by":        by,
		"method":    "local.signed",
		"reasons":   reasons,
	}, "approval_signature")
}

func (f Fixture) sandboxProof(taskID string, worker *Worker, sandbox map[string]any, policyDigest, sandboxClaim string) map[string]any {
	body := map[string]any{
		"proof_type":    "local.sandbox.v1",
		"authority":     f.Authority["zid"],
		"task_id":       taskID,
		"worker":        worker.Descriptor["aid"],
		"policy_digest": policyDigest,
		"sandbox":       sandbox,
	}
	if sandboxClaim != "" {
		body["sandbox_claim"] = sandboxClaim
	}
	return signBodyWithKey(f.AuthorityPrivateKey, body, "sandbox_signature")
}

func toolApprovalReasons(profile WorkerProfile) []string {
	required := stringsFromAny(profile.Policy["approval_required"])
	for _, item := range required {
		if item == "tool" && (profile.Tool == "external.stdio" || profile.Tool == "mcp.stdio") {
			return []string{"tool"}
		}
	}
	return []string{}
}

func taskPolicyScope(profile WorkerProfile, worker, task map[string]any) map[string]any {
	scope, _ := task["scope"].(map[string]any)
	policy, _ := worker["policy"].(map[string]any)
	tool := profile.Tool
	if tool == "" {
		tool = "text.echo"
	}
	return map[string]any{
		"network":           scope["network"] == true,
		"write":             stringsFromAny(scope["write"]),
		"tools":             []string{tool},
		"data_domains":      stringsFromAny(scope["data_domains"]),
		"approval_required": stringsFromAny(policy["approval_required"]),
		"expires_at":        optionalString(scope["expires_at"]),
	}
}
