package main

import (
	"context"
	"errors"
	"fmt"
	"os"
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

func containerProfileReceipt(profile DockerWorkerProfile) map[string]any {
	limits := map[string]any{
		"cpu_millis": float64(profile.Limits.CPUMillis),
		"memory_bytes": float64(profile.Limits.MemoryBytes),
		"timeout_millis": float64(profile.Limits.TimeoutMillis),
		"max_output_bytes": float64(profile.Limits.MaxOutputBytes),
		"max_scratch_input_bytes": float64(profile.Limits.MaxScratchInputBytes),
		"max_scratch_bytes": float64(profile.Limits.MaxScratchBytes),
	}
	result := map[string]any{"image": profile.Image, "command": append([]string(nil), profile.Command...), "limits": limits}
	if len(profile.ScratchInputs) > 0 {
		inputs := make([]map[string]any, 0, len(profile.ScratchInputs))
		for _, input := range profile.ScratchInputs {
			inputs = append(inputs, map[string]any{"path": input.Path, "bytes_b64": input.BytesB64})
		}
		result["scratch_inputs"] = inputs
	}
	return result
}

func containerPromotionEvidence(worker *Worker, task map[string]any, result ToolResult, artifactManifest, transcriptManifest map[string]any) (map[string]any, map[string]any, error) {
	if worker.Profile.Docker == nil {
		return nil, nil, errors.New("container_profile_missing")
	}
	request, err := validateDockerWorkerProfile(*worker.Profile.Docker)
	if err != nil {
		return nil, nil, errors.New("container_profile_invalid")
	}
	runtimeKind := optionalString(result.Evidence["runtime"])
	if err := validateContainerAdapterEvidence(request, runtimeKind, result.Evidence); err != nil {
		return nil, nil, errors.New("container_evidence_invalid")
	}
	constraints := result.Evidence["constraints"].(map[string]any)
	runtimeIdentity := result.Evidence["runtime_identity"].(map[string]any)
	adapterObserved := result.Evidence["observed"].(map[string]any)
	profile := containerProfileReceipt(*worker.Profile.Docker)
	transcriptDigest := ""
	transcriptBytes := float64(0)
	artifactCount := float64(1)
	if transcriptManifest != nil {
		transcriptDigest = optionalString(transcriptManifest["sha256"])
		transcriptBytes, _ = transcriptManifest["size"].(float64)
		artifactCount++
	}
	evidence := map[string]any{
		"format":                  "agnet-container-evidence/v2",
		"runtime":                 runtimeKind,
		"image":                   result.Evidence["image"],
		"image_id":                result.Evidence["image_id"],
		"container_id":            result.Evidence["container_id"],
		"runtime_identity":        runtimeIdentity,
		"runtime_identity_digest": result.Evidence["runtime_identity_digest"],
		"configuration_digest":    result.Evidence["configuration_digest"],
		"constraints":             constraints,
		"observed": map[string]any{
			"exit_code":        adapterObserved["exit_code"],
			"result_bytes":     artifactManifest["size"],
			"transcript_bytes": transcriptBytes,
			"artifact_count":    artifactCount,
		},
		"task_id":           task["task_id"],
		"task_digest":       digestHex(task),
		"profile_digest":    digestHex(profile),
		"generation_digest": digestHex(worker.GenerationRef),
		"result_digest":     artifactManifest["sha256"],
		"transcript_digest": transcriptDigest,
	}
	return evidence, profile, nil
}

func stagedArtifactManifest(uri string, data []byte, mediaType string) map[string]any {
	sha := digestBytesHex(data)
	manifest := map[string]any{
		"uri": uri,
		"sha256": sha,
		"size": float64(len(data)),
		"media_type": mediaType,
		"afp": "afp:sha256:" + sha,
	}
	manifest["manifest_hash"] = digestHex(manifest)
	return manifest
}

func artifactPublicationReady(artifactStoreDir string) bool {
	for _, root := range []string{"artifacts", artifactStoreDir} {
		if root == "" {
			continue
		}
		info, err := os.Stat(root)
		if err == nil && !info.IsDir() {
			return false
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return false
		}
	}
	return true
	}

func (f Fixture) executeTask(send sendFunc, origin map[string]any, worker *Worker, task map[string]any, parentCheckpoint any, restoredStateDigest string, retryOf any, requireHumanApproval bool, receiptExtra map[string]any, onReceipt func(map[string]any) error) error {
	taskID := fmt.Sprint(task["task_id"])
	ctx, cancelRun := context.WithCancel(context.Background())
	f.Runtime.Register(taskID, cancelRun)
	defer cancelRun()
	defer f.Runtime.Unregister(taskID)
	if err := worker.reloadPinnedGeneration(); err != nil {
		return err
	}
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
	toolName, toolResult, sandbox, err := runToolWithContainerAdapter(ctx, f.ContainerAdapter, worker.Profile, task, origin, f.ArtifactStoreDir, f.LiveTranscriptDir)
	if err != nil {
		if f.Runtime.WasCancelled(taskID) {
			return err
		}
		_ = f.writeTaskState(taskID, "failed", worker, map[string]any{"error": err.Error()})
		return err
	}
	if toolResult.MediaType == "" {
		return errors.New("tool result media type missing")
	}
	if len(toolResult.Transcript) > 0 && toolResult.TranscriptMediaType == "" {
		return errors.New("tool transcript media type missing")
	}
	if worker.Profile.SandboxClaim != "container-namespace" {
		for key, value := range toolResult.Evidence {
			if key == "mode" {
				return errors.New("tool result evidence cannot override sandbox mode")
			}
			sandbox[key] = value
		}
	}
	sandboxClaim := worker.Profile.SandboxClaim
	if sandboxClaim != "" && sandbox["mode"] != sandboxClaim {
		return errors.New("sandbox claim mismatch")
	}
	if !artifactPublicationReady(f.ArtifactStoreDir) {
		return errors.New("artifact_publication_unavailable")
	}
	artifactManifest := stagedArtifactManifest(artifactURI, toolResult.Result, toolResult.MediaType)
	artifactRefs := []string{artifactURI}
	artifactManifests := []map[string]any{artifactManifest}
	var transcriptManifest map[string]any
	if len(toolResult.Transcript) > 0 {
		transcriptURI := "artifact://local/" + taskID + "/tool-transcript.json"
		transcriptManifest = stagedArtifactManifest(transcriptURI, toolResult.Transcript, toolResult.TranscriptMediaType)
		sandbox["tool_transcript_ref"] = transcriptURI
		sandbox["tool_transcript_manifest"] = transcriptManifest
		artifactRefs = append(artifactRefs, transcriptURI)
		artifactManifests = append(artifactManifests, transcriptManifest)
	}
	var containerEvidence map[string]any
	var containerProfile map[string]any
	if sandboxClaim == "container-namespace" {
		containerEvidence, containerProfile, err = containerPromotionEvidence(worker, task, toolResult, artifactManifest, transcriptManifest)
		if err != nil {
			return err
		}
		sandbox["container_evidence"] = containerEvidence
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
	if containerEvidence != nil {
		receipt["container_profile"] = containerProfile
		receipt["container_generation_digest"] = containerEvidence["generation_digest"]
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
	if onReceipt != nil {
		if err := onReceipt(signedReceipt); err != nil {
			return errors.New("promotion_callback_failed")
		}
	}
	publishedResult, err := writeArtifactBytes(artifactURI, toolResult.Result, toolResult.MediaType, f.ArtifactStoreDir)
	if err != nil || digestHex(publishedResult) != digestHex(artifactManifest) {
		return errors.New("artifact_publication_failed")
	}
	if transcriptManifest != nil {
		publishedTranscript, writeErr := writeArtifactBytes(optionalString(transcriptManifest["uri"]), toolResult.Transcript, toolResult.TranscriptMediaType, f.ArtifactStoreDir)
		if writeErr != nil || digestHex(publishedTranscript) != digestHex(transcriptManifest) {
			return errors.New("transcript_publication_failed")
		}
	}
	if err := f.sendTaskEvent(send, map[string]any{"type": "artifact.created", "task_id": taskID, "uri": artifactURI, "manifest": artifactManifest}); err != nil {
		return err
	}
	if err := f.sendTaskEvent(send, map[string]any{"type": "task.completed", "task_id": taskID, "by": worker.Descriptor["aid"], "zone": f.Authority["zid"]}); err != nil {
		return err
	}
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
