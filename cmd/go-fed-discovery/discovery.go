package main

import (
	"math"
	"strings"
	"time"
)

func costSignal(policy map[string]any) (int, bool) {
	cost, ok := intSignal(policy["cost_tokens_per_task"])
	if !ok {
		return 5, false
	}
	return max(0, min(10, 10-int(math.Floor(float64(cost)/100)))), true
}

func latencySignal(policy map[string]any) (int, bool) {
	latency, ok := intSignal(policy["latency_ms_p95"])
	if !ok {
		return 5, false
	}
	if latency <= 100 {
		return 10, true
	}
	if latency <= 500 {
		return 7, true
	}
	if latency <= 2000 {
		return 4, true
	}
	return 1, true
}

func availabilitySignal(started, completed int, hasAuditData bool) (int, bool) {
	if !hasAuditData {
		return 5, false
	}
	denominator := started
	if denominator <= 0 {
		denominator = 1
	}
	if completed < 0 {
		completed = 0
	}
	return max(0, min(10, int(math.Floor((float64(completed)/float64(denominator))*10)))), true
}

func policyMatchSignal(policy, taskScope map[string]any) (int, bool) {
	if taskScope == nil {
		return 5, false
	}
	_, hasNetworkConstraint := taskScope["network"].(bool)
	writeTargets := stringsFromAny(taskScope["write"])
	used := hasNetworkConstraint || len(writeTargets) > 0
	if !used {
		return 5, false
	}
	if taskScope["network"] == true && policy["allow_network"] != true {
		return 0, true
	}
	for _, target := range writeTargets {
		if !hasPrefix(target, stringsFromAny(policy["write_prefixes"])) {
			return 0, true
		}
	}
	return 10, true
}

func riskMatchSignal(hasCredentialClaims bool, active bool, completedReceipts, revocationCount int) (int, bool) {
	used := hasCredentialClaims || revocationCount > 0
	if !used {
		return 5, false
	}
	score := 5
	if active {
		score += 3
	} else {
		score -= 2
	}
	if completedReceipts > 0 {
		score += 2
	}
	score -= min(revocationCount*5, 10)
	return max(0, min(10, score)), true
}

func routingSignals(worker *Worker, taskScope map[string]any, active bool, completedReceipts, revocationCount, availabilityStarted, availabilityCompleted int, availabilityHasAuditData bool, hasCredentialClaims bool) map[string]any {
	costScore, costUsed := costSignal(worker.Profile.Policy)
	latencyScore, latencyUsed := latencySignal(worker.Profile.Policy)
	availabilityScore, availabilityUsed := availabilitySignal(availabilityStarted, availabilityCompleted, availabilityHasAuditData)
	policyScore, policyUsed := policyMatchSignal(worker.Profile.Policy, taskScope)
	riskScore, riskUsed := riskMatchSignal(hasCredentialClaims, active, completedReceipts, revocationCount)
	signalsUsed := 0
	for _, used := range []bool{costUsed, latencyUsed, availabilityUsed, policyUsed, riskUsed} {
		if used {
			signalsUsed++
		}
	}
	return map[string]any{"cost_score": costScore, "latency_score": latencyScore, "availability_score": availabilityScore, "policy_match": policyScore, "risk_match": riskScore, "signals_used": signalsUsed}
}

func intSignal(value any) (int, bool) {
	switch item := value.(type) {
	case int:
		return item, true
	case float64:
		if math.Trunc(item) == item {
			return int(item), true
		}
	}
	return 0, false
}

func computeAgentScore(completedReceipts int, lastCompletedAt string, revocationCount int, active bool, costScore, latencyScore, availabilityScore, policyMatch, riskMatch int) map[string]any {
	receiptScore := min(completedReceipts, 20) * 2
	credentialScore := 0
	if active {
		credentialScore = 30
	}
	freshnessScore := 0
	if lastCompletedAt != "" {
		completedAt, err := time.Parse(time.RFC3339Nano, lastCompletedAt)
		if err == nil {
			delta := time.Since(completedAt)
			if delta <= time.Hour {
				freshnessScore = 10
			} else if delta <= 24*time.Hour {
				freshnessScore = 5
			}
		}
	}
	revocationPenalty := min(revocationCount*10, receiptScore+credentialScore+freshnessScore)
	total := receiptScore + credentialScore + freshnessScore + costScore + latencyScore + availabilityScore + policyMatch + riskMatch - revocationPenalty
	if total < 0 {
		total = 0
	}
	if total > 100 {
		total = 100
	}
	return map[string]any{
		"total":              total,
		"receipt_score":      receiptScore,
		"credential_score":   credentialScore,
		"freshness_score":    freshnessScore,
		"cost_score":         costScore,
		"latency_score":      latencyScore,
		"availability_score": availabilityScore,
		"policy_match":       policyMatch,
		"risk_match":         riskMatch,
		"revocation_penalty": revocationPenalty,
	}
}

func (f Fixture) credentialStatus(credential map[string]any, status string) map[string]any {
	return signBodyWithKey(f.AuthorityPrivateKey, map[string]any{
		"issuer":        f.Authority["zid"],
		"credential_id": credentialID(credential),
		"subject":       credential["subject"],
		"status":        status,
	}, "status_signature")
}

func (f Fixture) queryMatch(worker *Worker, capability, intent string, taskScope map[string]any) map[string]any {
	exact := hasCapability(worker.Descriptor, capability)
	semantic := semanticScore(intent, worker.Descriptor)
	if !exact && semantic == 0 {
		return nil
	}
	credentials := []any{}
	statuses := []any{}
	completedReceipts := 0
	lastCompletedAt := ""
	availabilityStarted := 0
	availabilityCompleted := 0
	availabilityHasAuditData := false
	active := false
	workerAID := optionalString(worker.Descriptor["aid"])
	workerAlias := optionalString(worker.Descriptor["alias"])
	revocationCount := countRevocationsForWorker(f.Revocations, workerAID, workerAlias, f.Authority)
	if exact {
		credential := f.capabilityCredential(worker, capability)
		credentials = append(credentials, credential)
		statuses = append(statuses, f.credentialStatus(credential, "active"))
		completedReceipts, lastCompletedAt, availabilityStarted, availabilityCompleted, availabilityHasAuditData = f.countCompletedReceipts(workerAID)
		active = isCredentialActive(credential) && revocationCount == 0
	}
	reasons := []string{}
	if exact {
		reasons = append(reasons, "capability_exact")
	}
	if semantic > 0 {
		reasons = append(reasons, "semantic_match")
	}
	if active {
		reasons = append(reasons, "credential_active")
	}
	if completedReceipts > 0 {
		reasons = append(reasons, "reputation_receipts")
	}
	hasCredentialClaims := exact
	routing := routingSignals(worker, taskScope, active, completedReceipts, revocationCount, availabilityStarted, availabilityCompleted, availabilityHasAuditData, hasCredentialClaims)
	if intFromMap(routing, "policy_match") > 5 {
		reasons = append(reasons, "policy_match")
	}
	if intFromMap(routing, "risk_match") > 5 {
		reasons = append(reasons, "risk_match")
	}
	agentScore := computeAgentScore(completedReceipts, lastCompletedAt, revocationCount, active, intFromMap(routing, "cost_score"), intFromMap(routing, "latency_score"), intFromMap(routing, "availability_score"), intFromMap(routing, "policy_match"), intFromMap(routing, "risk_match"))
	score := intFromMap(agentScore, "total") + semantic
	if exact {
		score += 50
	}
	return map[string]any{
		"worker":              worker.Descriptor,
		"zone_binding":        f.zoneBinding(worker),
		"credentials":         credentials,
		"credential_statuses": statuses,
		"discovery_evidence": map[string]any{
			"identity": map[string]any{
				"zone":  f.Authority["zid"],
				"aid":   worker.Descriptor["aid"],
				"alias": worker.Descriptor["alias"],
			},
			"capability": map[string]any{"exact": exact, "semantic": semantic > 0},
			"credential": map[string]any{"trusted": len(credentials) > 0, "active": active},
			"reputation": map[string]any{"completed_receipts": completedReceipts, "last_completed_at": lastCompletedAt, "revocation_count": revocationCount, "agent_score": agentScore},
			"routing":    routing,
		},
		"ranking": map[string]any{"score": score, "reasons": reasons},
	}
}

func credentialID(credential map[string]any) string {
	body := map[string]any{
		"issuer":     credential["issuer"],
		"subject":    credential["subject"],
		"capability": credential["capability"],
		"claims":     credential["claims"],
	}
	return "credential:sha256:" + digestHex(body)
}

func tokenize(value string) map[string]bool {
	items := map[string]bool{}
	for _, item := range strings.FieldsFunc(strings.ToLower(value), func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9')
	}) {
		items[item] = true
	}
	return items
}

func semanticScore(intent string, descriptor map[string]any) int {
	intentTokens := tokenize(intent)
	if len(intentTokens) == 0 {
		return 0
	}
	candidate := optionalString(descriptor["alias"])
	for _, item := range stringsFromAny(descriptor["capabilities"]) {
		candidate += " " + item
	}
	candidateTokens := tokenize(candidate)
	score := 0
	for token := range intentTokens {
		if candidateTokens[token] {
			score++
		}
	}
	return score
}
