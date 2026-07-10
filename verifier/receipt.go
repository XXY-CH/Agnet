package verifier

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strings"
)

const base58BTCAlphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

var ed25519MultikeyPrefix = []byte{0xed, 0x01}

func VerifyFederatedReceipt(frame map[string]any, trusted map[string]map[string]any, signedTasks ...map[string]any) error {
	if frame["type"] != "FED_RECEIPT" {
		return errors.New("expected FED_RECEIPT frame")
	}
	zone, ok := frame["zone"].(map[string]any)
	if !ok {
		return errors.New("receipt zone missing")
	}
	if err := verifyTrustedZone(zone, trusted); err != nil {
		return err
	}
	worker, ok := frame["worker"].(map[string]any)
	if !ok {
		return errors.New("receipt worker missing")
	}
	if err := verifyAgentDescriptor(worker); err != nil {
		return err
	}
	binding, ok := frame["zone_binding"].(map[string]any)
	if !ok {
		return errors.New("receipt zone binding missing")
	}
	if err := verifyZoneBinding(zone, binding, worker); err != nil {
		return err
	}
	receipt, ok := frame["receipt"].(map[string]any)
	if !ok {
		return errors.New("receipt missing")
	}
	if receipt["executing_zone"] != zone["zid"] {
		return errors.New("receipt executing_zone mismatch")
	}
	if trusted[fmt.Sprint(receipt["origin_zone"])] == nil {
		return errors.New("untrusted receipt origin zone: " + fmt.Sprint(receipt["origin_zone"]))
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
	workerKey, _, err := publicKey(worker)
	if err != nil {
		return err
	}
	if err := verifyMapSignature(workerKey, receipt, "signature"); err != nil {
		return errors.New("remote receipt signature verification failed")
	}
	return verifyReceiptArtifactManifests(receipt)
}

type swarmExecutionPlanStep struct {
	stepID     string
	dependsOn  []string
	capability string
}

type swarmExecutionBindingStep struct {
	raw        map[string]any
	stepID     string
	dependsOn  []string
	capability string
	taskDigest string
}

func SignedReceiptDigest(signedReceipt map[string]any) (string, error) {
	if signedReceipt == nil {
		return "", errors.New("signed receipt missing")
	}
	if signature, ok := signedReceipt["signature"].(string); !ok || signature == "" {
		return "", errors.New("signed receipt signature missing")
	}
	return canonicalDigest(signedReceipt)
}

func VerifySwarmExecutionBinding(binding, verifiedPlan map[string]any, executableSteps, resolvedWorkers []map[string]any) (string, error) {
	boundSteps, err := validateSwarmExecutionBinding(binding)
	if err != nil {
		return "", err
	}
	zone, plan, planSteps, err := verifyExecutionBindingPlan(verifiedPlan)
	if err != nil {
		return "", err
	}
	if binding["swarm_id"] != plan["swarm_id"] {
		return "", errors.New("execution binding swarm_id mismatch")
	}
	if binding["plan_digest"] != plan["plan_digest"] {
		return "", errors.New("execution binding plan_digest mismatch")
	}
	if len(boundSteps) != len(planSteps) || len(executableSteps) != len(planSteps) || len(resolvedWorkers) != len(planSteps) {
		return "", errors.New("execution binding step count mismatch")
	}

	for index, planStep := range planSteps {
		boundStep := boundSteps[index]
		executableStepID, executableDependsOn, signedTask, err := parseExecutableBindingStep(executableSteps[index])
		if err != nil {
			return "", err
		}
		if boundStep.stepID != planStep.stepID {
			return "", errors.New("execution binding step order mismatch")
		}
		if executableStepID != planStep.stepID {
			return "", errors.New("execution binding executable step order mismatch")
		}
		if !sameStringSlice(boundStep.dependsOn, planStep.dependsOn) {
			return "", errors.New("execution binding step depends_on mismatch")
		}
		if !sameStringSlice(executableDependsOn, planStep.dependsOn) {
			return "", errors.New("execution binding executable depends_on mismatch")
		}
		if boundStep.capability != planStep.capability {
			return "", errors.New("execution binding step capability mismatch")
		}
		taskDigest, err := canonicalDigest(signedTask)
		if err != nil {
			return "", err
		}
		if boundStep.taskDigest != taskDigest {
			return "", errors.New("execution binding task_digest mismatch")
		}
	}

	graphDigest, err := canonicalDigest(map[string]any{
		"swarm_id":    binding["swarm_id"],
		"plan_digest": binding["plan_digest"],
		"steps":       binding["steps"],
	})
	if err != nil {
		return "", err
	}
	if binding["execution_graph_digest"] != graphDigest {
		return "", errors.New("execution binding graph digest mismatch")
	}
	zoneKey, _, err := publicKey(zone)
	if err != nil {
		return "", err
	}
	if err := verifyMapSignature(zoneKey, binding, "binding_signature"); err != nil {
		return "", errors.New("execution binding signature verification failed")
	}

	for index, workerEntry := range resolvedWorkers {
		descriptor := workerEntry
		if nested, ok := workerEntry["descriptor"].(map[string]any); ok {
			descriptor = nested
		}
		if err := verifyAgentDescriptor(descriptor); err != nil {
			return "", fmt.Errorf("execution binding worker invalid: %w", err)
		}
		capabilities, err := exactStringList(descriptor["capabilities"], false, "execution binding worker capabilities invalid", "execution binding worker capability duplicate")
		if err != nil {
			return "", err
		}
		if !containsString(capabilities, planSteps[index].capability) {
			return "", errors.New("execution binding worker capability missing: " + planSteps[index].stepID)
		}
	}
	return graphDigest, nil
}

func validateSwarmExecutionBinding(binding map[string]any) ([]swarmExecutionBindingStep, error) {
	rootFields := []string{"format", "swarm_id", "plan_digest", "steps", "execution_graph_digest", "binding_signature"}
	if !hasExactMapFields(binding, rootFields) {
		return nil, errors.New("execution binding fields invalid")
	}
	if binding["format"] != "asp-swarm-execution-binding/v1" {
		return nil, errors.New("execution binding format invalid")
	}
	swarmID, ok := binding["swarm_id"].(string)
	if !ok || swarmID == "" || strings.ContainsRune(swarmID, '\x00') {
		return nil, errors.New("execution binding swarm_id invalid")
	}
	if !isHexDigest(optionalString(binding["plan_digest"])) {
		return nil, errors.New("execution binding plan_digest invalid")
	}
	stepMaps, err := strictMapList(binding["steps"])
	if err != nil || len(stepMaps) == 0 {
		return nil, errors.New("execution binding steps missing")
	}
	seenStepIDs := map[string]struct{}{}
	steps := make([]swarmExecutionBindingStep, 0, len(stepMaps))
	for _, step := range stepMaps {
		if !hasExactMapFields(step, []string{"step_id", "depends_on", "capability", "task_digest"}) {
			return nil, errors.New("execution binding step fields invalid")
		}
		stepID, ok := step["step_id"].(string)
		if !ok || stepID == "" || strings.ContainsRune(stepID, '\x00') {
			return nil, errors.New("execution binding step_id invalid")
		}
		if _, exists := seenStepIDs[stepID]; exists {
			return nil, errors.New("execution binding duplicate step_id")
		}
		seenStepIDs[stepID] = struct{}{}
		dependsOn, err := exactStringList(step["depends_on"], true, "execution binding step depends_on invalid", "execution binding duplicate dependency")
		if err != nil {
			return nil, err
		}
		capability, ok := step["capability"].(string)
		if !ok || capability == "" || strings.ContainsRune(capability, '\x00') {
			return nil, errors.New("execution binding step capability invalid")
		}
		taskDigest, ok := step["task_digest"].(string)
		if !ok || !isHexDigest(taskDigest) {
			return nil, errors.New("execution binding step task_digest invalid")
		}
		steps = append(steps, swarmExecutionBindingStep{raw: step, stepID: stepID, dependsOn: dependsOn, capability: capability, taskDigest: taskDigest})
	}
	if !isHexDigest(optionalString(binding["execution_graph_digest"])) {
		return nil, errors.New("execution binding graph digest invalid")
	}
	if signature, ok := binding["binding_signature"].(string); !ok || signature == "" {
		return nil, errors.New("execution binding signature missing")
	}
	return steps, nil
}

func verifyExecutionBindingPlan(verifiedPlan map[string]any) (map[string]any, map[string]any, []swarmExecutionPlanStep, error) {
	if verifiedPlan == nil {
		return nil, nil, nil, errors.New("verified swarm plan missing")
	}
	zone, ok := verifiedPlan["zone"].(map[string]any)
	if !ok {
		return nil, nil, nil, errors.New("verified swarm plan missing")
	}
	plan, ok := verifiedPlan["plan"].(map[string]any)
	if !ok {
		return nil, nil, nil, errors.New("verified swarm plan missing")
	}
	if err := verifyZoneDescriptor(zone); err != nil {
		return nil, nil, nil, err
	}
	swarmID, ok := plan["swarm_id"].(string)
	if !ok || swarmID == "" || strings.ContainsRune(swarmID, '\x00') {
		return nil, nil, nil, errors.New("swarm plan swarm_id invalid")
	}
	intent, ok := plan["intent"].(string)
	if !ok || intent == "" {
		return nil, nil, nil, errors.New("swarm plan intent invalid")
	}
	stepMaps, err := strictMapList(plan["steps"])
	if err != nil || len(stepMaps) == 0 {
		return nil, nil, nil, errors.New("swarm plan steps missing")
	}
	seenStepIDs := map[string]struct{}{}
	steps := make([]swarmExecutionPlanStep, 0, len(stepMaps))
	for _, step := range stepMaps {
		stepID, ok := step["step_id"].(string)
		if !ok || stepID == "" || strings.ContainsRune(stepID, '\x00') {
			return nil, nil, nil, errors.New("swarm plan step invalid")
		}
		if _, exists := seenStepIDs[stepID]; exists {
			return nil, nil, nil, errors.New("execution binding duplicate plan step_id")
		}
		seenStepIDs[stepID] = struct{}{}
		capability, ok := step["capability"].(string)
		if !ok || capability == "" || strings.ContainsRune(capability, '\x00') {
			return nil, nil, nil, errors.New("swarm plan step capability invalid")
		}
		if constraint, present := step["constraint"]; present {
			constraintMap, ok := constraint.(map[string]any)
			if !ok || constraintMap == nil {
				return nil, nil, nil, errors.New("swarm plan step constraint invalid")
			}
		}
		dependsOnValue, present := step["depends_on"]
		if !present {
			dependsOnValue = []any{}
		}
		dependsOn, err := exactStringList(dependsOnValue, true, "swarm plan step depends_on invalid", "execution binding duplicate dependency")
		if err != nil {
			return nil, nil, nil, err
		}
		steps = append(steps, swarmExecutionPlanStep{stepID: stepID, dependsOn: dependsOn, capability: capability})
	}
	if !isHexDigest(optionalString(plan["policy_digest"])) {
		return nil, nil, nil, errors.New("swarm plan policy digest invalid")
	}
	computedPlanDigest, err := canonicalDigest(map[string]any{"intent": intent, "steps": plan["steps"]})
	if err != nil {
		return nil, nil, nil, err
	}
	if plan["plan_digest"] != computedPlanDigest {
		return nil, nil, nil, errors.New("swarm plan digest invalid")
	}
	zoneKey, _, err := publicKey(zone)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := verifyMapSignature(zoneKey, plan, "plan_signature"); err != nil {
		return nil, nil, nil, errors.New("swarm plan signature verification failed")
	}
	return zone, plan, steps, nil
}

func parseExecutableBindingStep(step map[string]any) (string, []string, map[string]any, error) {
	if step == nil {
		return "", nil, nil, errors.New("execution binding executable step invalid")
	}
	stepID, ok := step["step_id"].(string)
	if !ok || stepID == "" || strings.ContainsRune(stepID, '\x00') {
		return "", nil, nil, errors.New("execution binding executable step invalid")
	}
	dependsOn, err := exactStringList(step["depends_on"], true, "execution binding step depends_on invalid", "execution binding duplicate dependency")
	if err != nil {
		return "", nil, nil, err
	}
	signedTask, ok := step["task"].(map[string]any)
	if !ok {
		return "", nil, nil, errors.New("execution binding signed task missing")
	}
	if signature, ok := signedTask["signature"].(string); !ok || signature == "" {
		return "", nil, nil, errors.New("execution binding signed task missing")
	}
	return stepID, dependsOn, signedTask, nil
}

func hasExactMapFields(value map[string]any, expected []string) bool {
	if value == nil || len(value) != len(expected) {
		return false
	}
	for _, field := range expected {
		if _, ok := value[field]; !ok {
			return false
		}
	}
	return true
}

func strictMapList(value any) ([]map[string]any, error) {
	if typed, ok := value.([]map[string]any); ok {
		return typed, nil
	}
	items, ok := value.([]any)
	if !ok {
		return nil, errors.New("expected object list")
	}
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		entry, ok := item.(map[string]any)
		if !ok {
			return nil, errors.New("expected object list")
		}
		out = append(out, entry)
	}
	return out, nil
}

func exactStringList(value any, allowEmpty bool, invalidMessage, duplicateMessage string) ([]string, error) {
	var out []string
	switch items := value.(type) {
	case []string:
		out = append([]string(nil), items...)
	case []any:
		out = make([]string, 0, len(items))
		for _, item := range items {
			text, ok := item.(string)
			if !ok {
				return nil, errors.New(invalidMessage)
			}
			out = append(out, text)
		}
	default:
		return nil, errors.New(invalidMessage)
	}
	if !allowEmpty && len(out) == 0 {
		return nil, errors.New(invalidMessage)
	}
	seen := map[string]struct{}{}
	for _, item := range out {
		if item == "" || strings.ContainsRune(item, '\x00') {
			return nil, errors.New(invalidMessage)
		}
		if _, exists := seen[item]; exists {
			return nil, errors.New(duplicateMessage)
		}
		seen[item] = struct{}{}
	}
	return out, nil
}

func sameStringSlice(left, right []string) bool {
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

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func canonicalDigest(value any) (string, error) {
	data, err := canonicalJSON(value)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

func verifyTrustedZone(zone map[string]any, trusted map[string]map[string]any) error {
	if err := verifyZoneDescriptor(zone); err != nil {
		return err
	}
	known := trusted[fmt.Sprint(zone["zid"])]
	if known == nil || known["public_key_spki"] != zone["public_key_spki"] {
		return errors.New("untrusted zone: " + fmt.Sprint(zone["zid"]))
	}
	return nil
}

func verifyZoneDescriptor(zone map[string]any) error {
	key, der, err := publicKey(zone)
	if err != nil {
		return err
	}
	if zidFromSPKI(der) != zone["zid"] {
		return errors.New("zone id mismatch")
	}
	return verifyMapSignature(key, zone, "zone_signature")
}

func verifyAgentDescriptor(agent map[string]any) error {
	key, der, err := publicKey(agent)
	if err != nil {
		return err
	}
	if aidFromSPKI(der) != agent["aid"] {
		return errors.New("agent id mismatch")
	}
	if didKey := optionalString(agent["did_key"]); didKey != "" {
		expected, err := didKeyFromPublicKeySPKI(optionalString(agent["public_key_spki"]))
		if err != nil {
			return err
		}
		if didKey != expected {
			return errors.New("agent did:key mismatch")
		}
	}
	return verifyMapSignature(key, agent, "descriptor_signature")
}

func verifyZoneBinding(zone, binding, worker map[string]any) error {
	zoneKey, _, err := publicKey(zone)
	if err != nil {
		return err
	}
	if binding["zone"] != zone["zid"] || binding["alias"] != worker["alias"] || binding["aid"] != worker["aid"] {
		return errors.New("zone binding mismatch")
	}
	if err := verifyMapSignature(zoneKey, binding, "signature"); err != nil {
		return errors.New("zone binding signature verification failed")
	}
	return nil
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

func verifyReceiptArtifactManifests(receipt map[string]any) error {
	raw, ok := receipt["artifact_manifests"]
	if !ok {
		return nil
	}
	refs, err := artifactRefsFromAny(receipt["artifact_refs"])
	if err != nil {
		return err
	}
	manifests, err := artifactManifestsFromAny(raw)
	if err != nil {
		return err
	}
	if len(refs) != len(manifests) {
		return errors.New("receipt artifact manifest count mismatch")
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

func publicKey(value map[string]any) (ed25519.PublicKey, []byte, error) {
	encoded, ok := value["public_key_spki"].(string)
	if !ok {
		return nil, nil, errors.New("missing public_key_spki")
	}
	der, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, nil, err
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, nil, err
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, nil, errors.New("expected ed25519 public key")
	}
	return key, der, nil
}

func verifyMapSignature(key ed25519.PublicKey, value map[string]any, signatureKey string) error {
	signature, ok := value[signatureKey].(string)
	if !ok {
		return errors.New("missing " + signatureKey)
	}
	body := map[string]any{}
	for k, v := range value {
		if k != signatureKey {
			body[k] = v
		}
	}
	data, err := canonicalJSON(body)
	if err != nil {
		return err
	}
	decoded, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return err
	}
	if !ed25519.Verify(key, data, decoded) {
		return errors.New("signature verification failed")
	}
	return nil
}

func stringsFromAny(value any) []string {
	items, _ := value.([]any)
	out := []string{}
	for _, item := range items {
		if text, ok := item.(string); ok {
			out = append(out, text)
		}
	}
	return out
}

func mapsFromAny(value any) []map[string]any {
	if typed, ok := value.([]map[string]any); ok {
		return typed
	}
	items, _ := value.([]any)
	out := []map[string]any{}
	for _, item := range items {
		if entry, ok := item.(map[string]any); ok {
			out = append(out, entry)
		}
	}
	return out
}

func optionalString(value any) string {
	text, _ := value.(string)
	return text
}

func digestHex(value any) string {
	data, _ := canonicalJSON(value)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func canonicalJSON(value any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

func aidFromSPKI(der []byte) string {
	hash := sha256.New()
	hash.Write([]byte("asp-agent-id-v1\x00"))
	hash.Write(der)
	return "aid:ed25519:" + base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
}

func zidFromSPKI(der []byte) string {
	hash := sha256.New()
	hash.Write([]byte("asp-zone-id-v1\x00"))
	hash.Write(der)
	return "zid:ed25519:" + base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
}

func didKeyFromPublicKeySPKI(encoded string) (string, error) {
	der, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return "", err
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return "", errors.New("expected ed25519 public key")
	}
	return "did:key:z" + base58BTCEncode(append(append([]byte{}, ed25519MultikeyPrefix...), key...)), nil
}

func base58BTCEncode(bytesValue []byte) string {
	n := new(big.Int).SetBytes(bytesValue)
	base := big.NewInt(58)
	zero := big.NewInt(0)
	mod := new(big.Int)
	out := []byte{}
	for n.Cmp(zero) > 0 {
		n.DivMod(n, base, mod)
		out = append([]byte{base58BTCAlphabet[mod.Int64()]}, out...)
	}
	for _, b := range bytesValue {
		if b != 0 {
			break
		}
		out = append([]byte{'1'}, out...)
	}
	if len(out) == 0 {
		return "1"
	}
	return string(out)
}
