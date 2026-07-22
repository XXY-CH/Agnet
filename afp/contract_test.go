package afp

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type vectorCrypto struct {
	PublicKeySPKI string `json:"public_key_spki"`
	AID           string `json:"aid"`
}
type vectorCorpus struct {
	Format    string          `json:"format"`
	Schema    string          `json:"schema_version"`
	Protocol  string          `json:"protocol_version"`
	Cases     []vectorCase    `json:"cases"`
	Inventory vectorInventory `json:"inventory"`
	Crypto    vectorCrypto    `json:"crypto"`
}

type vectorCase struct {
	ID       string          `json:"id"`
	Category string          `json:"category"`
	Input    json.RawMessage `json:"input"`
	Expect   vectorExpect    `json:"expect"`
}

type vectorExpect struct {
	Code                   string `json:"code"`
	Canonical              string `json:"canonical"`
	CanonicalBody          string `json:"canonical_body"`
	SigningPreimageHex     string `json:"signing_preimage_hex"`
	DigestHex              string `json:"digest_hex"`
	Signature              string `json:"signature"`
	SelectedVersion        string `json:"selected_version"`
	IdempotencyPreimageHex string `json:"idempotency_preimage_hex"`
	IdempotencyKey         string `json:"idempotency_key"`
	Disposition            string `json:"disposition"`
}

type vectorInventory struct {
	SignedPositiveEnvelopes      int            `json:"signed_positive_envelopes"`
	CanonicalJSONCases           int            `json:"canonical_json_cases"`
	NegotiationCases             int            `json:"negotiation_cases"`
	AuthorityAndRouteCases       int            `json:"authority_and_route_cases"`
	CapabilityCases              int            `json:"capability_cases"`
	CustodyCases                 int            `json:"custody_cases"`
	SettlementCases              int            `json:"settlement_cases"`
	ASPCompatibilityDispositions int            `json:"asp_compatibility_dispositions"`
	ReceiptFenceCases            int            `json:"receipt_fence_cases"`
	EnvelopeShapeCases           int            `json:"envelope_shape_cases"`
	VerificationPipelineCases    int            `json:"verification_pipeline_cases"`
	TotalCases                   int            `json:"total_cases"`
	CategoryCounts               map[string]int `json:"category_counts"`
}

func TestAF0Vectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "test-vectors", "afp-v1-af0.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus vectorCorpus
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.Format != "afp-af0-v1" || corpus.Schema != "afp-v1-af0-test-vectors/1.1" || corpus.Protocol != "1.0" || corpus.Crypto.PublicKeySPKI == "" || corpus.Crypto.AID == "" {
		t.Fatalf("unexpected corpus identity")
	}
	assertInventory(t, corpus)
	if len(corpus.Cases) != corpus.Inventory.TotalCases {
		t.Fatalf("case count = %d; want %d", len(corpus.Cases), corpus.Inventory.TotalCases)
	}

	kindVectors := map[string]bool{}
	categoryCounts := map[string]int{}
	aspDispositionCount := 0
	for _, tc := range corpus.Cases {
		categoryCounts[tc.Category]++
		if strings.HasPrefix(tc.ID, "asp.") {
			aspDispositionCount++
		}
		var input struct {
			Body struct {
				Kind string `json:"kind"`
			} `json:"body"`
		}
		if err := json.Unmarshal(tc.Input, &input); err != nil {
			t.Fatalf("%s: decode input: %v", tc.ID, err)
		}
		if kinds[input.Body.Kind] {
			kindVectors[input.Body.Kind] = true
		}

		t.Run(tc.ID, func(t *testing.T) {
			result := EvaluateAF0VectorCase(tc.Input, VectorContext{Crypto: VectorCrypto{PublicKeySPKI: corpus.Crypto.PublicKeySPKI, AID: corpus.Crypto.AID}})
			if string(result.Code) != tc.Expect.Code {
				t.Fatalf("code = %s; want %s", result.Code, tc.Expect.Code)
			}
			assertDerived(t, result, tc.Expect)
		})
	}
	if len(kindVectors) != 17 {
		t.Fatalf("signed kind vectors = %d; want 17", len(kindVectors))
	}
	assertCaseInventory(t, categoryCounts, aspDispositionCount, corpus.Inventory)
	for _, kind := range []string{
		"afp.agent-descriptor", "afp.capability-advertisement", "afp.intent-query", "afp.offer", "afp.capability-grant",
		"afp.task-open", "afp.task-claim", "afp.task-event", "afp.checkpoint", "afp.artifact-manifest",
		"afp.mailbox-envelope", "afp.custody-receipt", "afp.receipt-commit", "afp.assurance-evidence", "afp.route-binding",
		"afp.direct-swarm-charter", "afp.settlement-commit",
	} {
		if !kindVectors[kind] {
			t.Errorf("missing signed crypto vector for %s", kind)
		}
	}
}

func assertInventory(t *testing.T, corpus vectorCorpus) {
	t.Helper()
	want := vectorInventory{SignedPositiveEnvelopes: 17, CanonicalJSONCases: 11, NegotiationCases: 13, AuthorityAndRouteCases: 9, CapabilityCases: 12, CustodyCases: 8, SettlementCases: 12, ASPCompatibilityDispositions: 13, ReceiptFenceCases: 6, EnvelopeShapeCases: 2, VerificationPipelineCases: 16, TotalCases: 121}
	if corpus.Inventory.SignedPositiveEnvelopes != want.SignedPositiveEnvelopes ||
		corpus.Inventory.CanonicalJSONCases != want.CanonicalJSONCases ||
		corpus.Inventory.NegotiationCases != want.NegotiationCases ||
		corpus.Inventory.AuthorityAndRouteCases != want.AuthorityAndRouteCases ||
		corpus.Inventory.CapabilityCases != want.CapabilityCases ||
		corpus.Inventory.CustodyCases != want.CustodyCases ||
		corpus.Inventory.SettlementCases != want.SettlementCases ||
		corpus.Inventory.ASPCompatibilityDispositions != want.ASPCompatibilityDispositions ||
		corpus.Inventory.ReceiptFenceCases != want.ReceiptFenceCases ||
		corpus.Inventory.EnvelopeShapeCases != want.EnvelopeShapeCases ||
		corpus.Inventory.VerificationPipelineCases != want.VerificationPipelineCases ||
		corpus.Inventory.TotalCases != want.TotalCases {
		t.Fatalf("inventory = %+v; want %+v", corpus.Inventory, want)
	}
}

func assertCaseInventory(t *testing.T, counts map[string]int, aspDispositionCount int, inventory vectorInventory) {
	t.Helper()
	if len(counts) != len(inventory.CategoryCounts) {
		t.Fatalf("category counts = %+v; want %+v", counts, inventory.CategoryCounts)
	}
	for category, want := range inventory.CategoryCounts {
		if counts[category] != want {
			t.Fatalf("category %q = %d; want %d", category, counts[category], want)
		}
	}
	if aspDispositionCount != inventory.ASPCompatibilityDispositions {
		t.Fatalf("ASP dispositions = %d; want %d", aspDispositionCount, inventory.ASPCompatibilityDispositions)
	}
}

func assertDerived(t *testing.T, got AF0Result, want vectorExpect) {
	t.Helper()
	checks := []struct {
		name string
		got  string
		want string
	}{
		{"canonical", got.Canonical, want.Canonical},
		{"canonical body", got.CanonicalBody, want.CanonicalBody},
		{"signing preimage", got.SigningPreimageHex, want.SigningPreimageHex},
		{"digest", got.DigestHex, want.DigestHex},
		{"signature", got.Signature, want.Signature},
		{"selected version", got.SelectedVersion, want.SelectedVersion},
		{"idempotency preimage", got.IdempotencyPreimageHex, want.IdempotencyPreimageHex},
		{"idempotency key", got.IdempotencyKey, want.IdempotencyKey},
		{"disposition", got.Disposition, want.Disposition},
	}
	for _, check := range checks {
		if check.want != "" && check.got != check.want {
			t.Errorf("%s = %q; want %q", check.name, check.got, check.want)
		}
	}
}

func TestPublicAF0Refusals(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "test-vectors", "afp-v1-af0.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus vectorCorpus
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	crypto := VectorCrypto{PublicKeySPKI: corpus.Crypto.PublicKeySPKI, AID: corpus.Crypto.AID}
	caseInput := func(id string) map[string]any {
		t.Helper()
		for _, tc := range corpus.Cases {
			if tc.ID == id {
				value, code := parseJSON(tc.Input)
				if code != OK {
					t.Fatalf("%s: %s", id, code)
				}
				return value.(map[string]any)
			}
		}
		t.Fatalf("missing %s", id)
		return nil
	}
	canonicalEnvelope := func(input map[string]any) ([]byte, EnvelopeBody) {
		t.Helper()
		body, code := envelopeBody(objectField(input, "body"))
		if code != OK {
			t.Fatal(code)
		}
		raw, code := marshalCanonical(map[string]any{"body": body.value(), "signature": objectField(input, "signature")})
		if code != OK {
			t.Fatal(code)
		}
		return raw, body
	}
	wrongKey := caseInput("pipeline.wrong-signing-key")
	raw, body := canonicalEnvelope(wrongKey)
	if got := VerifyEnvelope(raw, verificationContextForVector(wrongKey, crypto, body)); got != KeyResolutionFailed {
		t.Fatalf("wrong key = %s", got)
	}
	profile := caseInput("afp.capability-advertisement.positive")
	raw, body = canonicalEnvelope(profile)
	ctx := verificationContextForVector(profile, crypto, body)
	ctx.VerifiedRouteBinding.Profile = "governed"
	if got := VerifyEnvelope(raw, ctx); got != NegotiationBindingMismatch {
		t.Fatalf("route/profile mismatch = %s", got)
	}
	timeCtx := verificationContextForVector(profile, crypto, body)
	timeCtx.Negotiation = nil
	timeCtx.VerificationTime = time.Time{}
	if got := VerifyEnvelope(raw, timeCtx); got != VerificationTimeRequired {
		t.Fatalf("verification time before negotiation = %s", got)
	}
	invalidTimeCtx := verificationContextForVector(profile, crypto, body)
	invalidTimeCtx.Negotiation = nil
	invalidTimeCtx.VerificationTime = invalidTimeCtx.VerificationTime.Add(time.Nanosecond)
	if got := VerifyEnvelope(raw, invalidTimeCtx); got != InvalidTimestamp {
		t.Fatalf("inexact verification time = %s", got)
	}
	capability := caseInput("capability.signed-strict-child-intersection")
	parent := objectField(objectField(capability, "parent_envelope"), "body")["payload"].(map[string]any)
	child := objectField(objectField(capability, "child_envelope"), "body")["payload"].(map[string]any)
	delete(parent, "revocation_proof")
	if got := ValidateCapabilityAttenuation(parent, child); got != RevocationProofRejected {
		t.Fatalf("missing revocation = %s", got)
	}
	if got := ValidateCustodyLineage(nil, ""); got != CustodyLineageInvalid {
		t.Fatalf("empty custody = %s", got)
	}
	facts := objectsFieldStrict(caseInput("custody.unique-root-uncontested"), "facts")
	fork := map[string]any{"sequence": int64(2), "predecessor_digest": facts[0]["fact_digest"], "state": "custody-accepted", "fact_digest": "5B2FnSGve9fNHJ2sDWe9k5BqtxkCmyo5PX1Wg9uQe9I"}
	if got := ValidateCustodyLineage(append(facts, fork), ""); got != CustodyContested {
		t.Fatalf("custody fork = %s", got)
	}
	if got := ValidateReceiptExpectation(map[string]any{"task_id": "task", "attempt": int64(1), "fence": int64(1), "lineage_digest": "BxPxNuoxbI8-J01VAS478Q0FtSY4Nxh6OVk_8NiDjfo"}, "OqQBXR7F4d6tvPnebFIDZgNDNcvynrbCu9zN829X13I", ReceiptExpectation{TaskID: "task", Attempt: 1, ReceiptFence: 1, CurrentFence: 2, Sequence: 3, PredecessorSequence: 2, ReceiptDigest: "OqQBXR7F4d6tvPnebFIDZgNDNcvynrbCu9zN829X13I", CustodyDigest: "S_96I0URzZ_jhvB-cNar2IcLsZ6hs99KuXiQ1Bm_DBY", LineageDigest: "BxPxNuoxbI8-J01VAS478Q0FtSY4Nxh6OVk_8NiDjfo", VerifiedReferences: map[string]bool{"OqQBXR7F4d6tvPnebFIDZgNDNcvynrbCu9zN829X13I": true, "S_96I0URzZ_jhvB-cNar2IcLsZ6hs99KuXiQ1Bm_DBY": true, "BxPxNuoxbI8-J01VAS478Q0FtSY4Nxh6OVk_8NiDjfo": true}}); got != ReceiptFenceViolation {
		t.Fatalf("receipt fence = %s", got)
	}
	descriptor := caseInput("afp.agent-descriptor.positive")
	raw, body = canonicalEnvelope(descriptor)
	ctx = verificationContextForVector(descriptor, crypto, body)
	ctx.RevocationEvidence = nil
	if got := VerifyEnvelope(raw, ctx); got != RevocationProofRejected {
		t.Fatalf("descriptor without revocation evidence = %s", got)
	}
	bootstrapCtx := verificationContextForVector(descriptor, crypto, body)
	bootstrapCtx.ResolveIssuerKey = nil
	if got := VerifyEnvelope(raw, bootstrapCtx); got != OK {
		t.Fatalf("descriptor bootstrap = %s", got)
	}
	receipt := caseInput("afp.receipt-commit.positive")
	raw, body = canonicalEnvelope(receipt)
	ctx = verificationContextForVector(receipt, crypto, body)
	ctx.Receipt = nil
	if got := VerifyEnvelope(raw, ctx); got != ReceiptFenceViolation {
		t.Fatalf("receipt without expectation = %s", got)
	}
	settlementEnvelope := caseInput("afp.settlement-commit.positive")
	raw, body = canonicalEnvelope(settlementEnvelope)
	ctx = verificationContextForVector(settlementEnvelope, crypto, body)
	ctx.Settlement = nil
	if got := VerifyEnvelope(raw, ctx); got != SettlementRefused {
		t.Fatalf("settlement without expectation = %s", got)
	}
	if got := ValidateProfileTransition("unknown", "direct", false, ProfileTransitionEvidence{}); got != InvalidProfile {
		t.Fatalf("invalid profile = %s", got)
	}
	if got := ValidateProfileTransition("direct", "governed", false, ProfileTransitionEvidence{NewTranscriptVerified: true}); got != ProfileDowngradeRejected {
		t.Fatalf("incomplete profile evidence = %s", got)
	}
	if got := ValidateProfileTransition("a2a-afp", "a2a-baseline", true, ProfileTransitionEvidence{PriorSessionID: "session://a2a-afp/001", SuccessorSessionID: "session://a2a-baseline/002", NewTranscriptVerified: true, NewRouteBindingVerified: true, LocalPolicyVerified: true}); got != ProfileRetryRejected {
		t.Fatalf("failed stronger-to-weaker retry = %s", got)
	}
	if got := ValidateProfileTransition("direct", "governed", false, ProfileTransitionEvidence{PriorSessionID: "session://direct/001", SuccessorSessionID: "session://governed/002", NewTranscriptVerified: true, NewRouteBindingVerified: true, LocalPolicyVerified: true}); got != OK {
		t.Fatalf("verified distinct profile transition = %s", got)
	}
	gapFacts := []map[string]any{
		{"sequence": int64(1), "predecessor_digest": nil, "state": "submitted", "fact_digest": "H0ju0lBi9o_Z_qGwdh2nYY86DlQHdCwAOb0Nxp5rzE4"},
		{"sequence": int64(3), "predecessor_digest": "H0ju0lBi9o_Z_qGwdh2nYY86DlQHdCwAOb0Nxp5rzE4", "state": "delivered", "fact_digest": "S_96I0URzZ_jhvB-cNar2IcLsZ6hs99KuXiQ1Bm_DBY"},
	}
	if got := ValidateCustodyLineage(gapFacts, ""); got != OK {
		t.Fatalf("strictly greater custody sequence = %s", got)
	}
	if got := verifyCustodyFacts(gapFacts, map[string]bool{}); got != ReferenceInvalid {
		t.Fatalf("unverified custody predecessor = %s", got)
	}
	executionAuthority := ExecutionAuthorityEvidence{Verified: true, TaskID: "task://vector/001", Attempt: 1, Issuer: crypto.AID, Fence: 1}
	if got := ValidateCustodyExecution(gapFacts, "task://vector/001", 1, crypto.AID, 1, executionAuthority); got != OK {
		t.Fatalf("verified custody execution authority = %s", got)
	}
	executionAuthority.Fence = 2
	if got := ValidateCustodyExecution(gapFacts, "task://vector/001", 1, crypto.AID, 1, executionAuthority); got != CustodyExecutionUnauthorized {
		t.Fatalf("mismatched custody execution authority = %s", got)
	}
	receiptExpectation := ReceiptExpectation{TaskID: "task", Attempt: 1, ReceiptFence: 1, CurrentFence: 1, Sequence: 3, PredecessorSequence: 2, ReceiptDigest: "OqQBXR7F4d6tvPnebFIDZgNDNcvynrbCu9zN829X13I", CustodyDigest: "S_96I0URzZ_jhvB-cNar2IcLsZ6hs99KuXiQ1Bm_DBY", LineageDigest: "BxPxNuoxbI8-J01VAS478Q0FtSY4Nxh6OVk_8NiDjfo", VerifiedReferences: map[string]bool{"OqQBXR7F4d6tvPnebFIDZgNDNcvynrbCu9zN829X13I": true, "S_96I0URzZ_jhvB-cNar2IcLsZ6hs99KuXiQ1Bm_DBY": true, "BxPxNuoxbI8-J01VAS478Q0FtSY4Nxh6OVk_8NiDjfo": true}}
	if got := ValidateReceiptExpectation(map[string]any{"task_id": "task", "attempt": int64(1), "fence": int64(1), "lineage_digest": receiptExpectation.LineageDigest}, "BxPxNuoxbI8-J01VAS478Q0FtSY4Nxh6OVk_8NiDjfo", receiptExpectation); got != ReceiptFenceViolation {
		t.Fatalf("receipt digest binding = %s", got)
	}
	settlement := caseInput("settlement.committed-storage")
	status := objectField(settlement, "verified_status")
	status["committed"] = false
	if got := ValidateSettlementCommit(settlement, SettlementExpectation{VerifiedStatus: map[string]bool{"committed": false}, VerifiedReferences: map[string]bool{stringOr(settlement, "budget_authorization_digest"): true, stringOr(settlement, "receipt_or_custody_digest"): true}}); got != SettlementRefused {
		t.Fatalf("settlement refusal = %s", got)
	}
	if got := ValidateSettlementCommit(settlement, SettlementExpectation{VerifiedStatus: map[string]bool{"committed": false}, VerifiedReferences: map[string]bool{stringOr(settlement, "receipt_or_custody_digest"): true}}); got != BudgetAuthorizationRequired {
		t.Fatalf("budget authorization ordering = %s", got)
	}
	charter := caseInput("afp.direct-swarm-charter.positive")
	raw, body = canonicalEnvelope(charter)
	ctx = verificationContextForVector(charter, crypto, body)
	ctx.VerificationTime, _ = parseTimestamp(stringOr(objectFieldFromAny(body.Payload), "expiry"))
	if got := VerifyEnvelope(raw, ctx); got != InvalidTimestamp {
		t.Fatalf("expired charter = %s", got)
	}
}

func TestVerifyEnvelopeRequiresCurrentRevocationEvidence(t *testing.T) {
	privateKey, issuer := testEnvelopeSigner(t)
	verificationTime := testVerificationTime(t)
	raw, proofDigest := testSignedDescriptor(t, privateKey, issuer)
	context := VerifyContext{
		VerificationTime:   verificationTime,
		LocalPolicy:        true,
		VerifiedReferences: map[string]bool{},
		RevocationEvidence: []RevocationEvidence{{
			Digest: proofDigest, Unrevoked: true, CurrentAt: verificationTime,
		}},
	}
	if got := VerifyEnvelope(raw, context); got != OK {
		t.Fatalf("current revocation evidence = %s; want %s", got, OK)
	}

	for _, tc := range []struct {
		name      string
		currentAt time.Time
	}{
		{name: "zero"},
		{name: "earlier", currentAt: verificationTime.Add(-time.Second)},
		{name: "later", currentAt: verificationTime.Add(time.Second)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stale := context
			stale.RevocationEvidence = []RevocationEvidence{{Digest: proofDigest, Unrevoked: true, CurrentAt: tc.currentAt}}
			if got := VerifyEnvelope(raw, stale); got != RevocationProofRejected {
				t.Fatalf("stale revocation evidence = %s; want %s", got, RevocationProofRejected)
			}
		})
	}
}

func TestVerifyEnvelopeValidatesLocalProfileTransition(t *testing.T) {
	privateKey, issuer := testEnvelopeSigner(t)
	verificationTime := testVerificationTime(t)
	raw, proofDigest := testSignedDescriptor(t, privateKey, issuer)
	context := VerifyContext{
		VerificationTime:   verificationTime,
		LocalPolicy:        true,
		PreviousProfile:    "direct",
		VerifiedReferences: map[string]bool{},
		RevocationEvidence: []RevocationEvidence{{
			Digest: proofDigest, Unrevoked: true, CurrentAt: verificationTime,
		}},
	}
	if got := VerifyEnvelope(raw, context); got != ProfileDowngradeRejected {
		t.Fatalf("local successor without transition evidence = %s; want %s", got, ProfileDowngradeRejected)
	}

	context.ProfileTransition = ProfileTransitionEvidence{
		PriorSessionID:          "session://direct/001",
		SuccessorSessionID:      "session://local/002",
		NewTranscriptVerified:   true,
		NewRouteBindingVerified: true,
		LocalPolicyVerified:     true,
	}
	if got := VerifyEnvelope(raw, context); got != OK {
		t.Fatalf("local successor with distinct verified evidence = %s; want %s", got, OK)
	}
}

func TestVerifyEnvelopeExecutionExpiryEvidence(t *testing.T) {
	privateKey, issuer := testEnvelopeSigner(t)
	verificationTime := testVerificationTime(t)
	raw, context := testExecutingEvent(t, privateKey, issuer, verificationTime)

	for _, tc := range []struct {
		name     string
		evidence []CustodyExpiryEvidence
		want     Code
	}{
		{
			name:     "expiry at verification time",
			evidence: []CustodyExpiryEvidence{{Kind: "delivery", ExpiresAt: verificationTime, Verified: true}},
			want:     CustodyExpired,
		},
		{
			name:     "verification before expiry",
			evidence: []CustodyExpiryEvidence{{Kind: "lease", ExpiresAt: verificationTime.Add(time.Second), Verified: true}},
			want:     OK,
		},
		{
			name:     "unverified expiry ignored",
			evidence: []CustodyExpiryEvidence{{Kind: "delivery", ExpiresAt: verificationTime, Verified: false}},
			want:     OK,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			expiryContext := context
			expiryContext.CustodyExpiryEvidence = tc.evidence
			if got := VerifyEnvelope(raw, expiryContext); got != tc.want {
				t.Fatalf("VerifyEnvelope expiry result = %s; want %s", got, tc.want)
			}
		})
	}
}

func testExecutingEvent(t *testing.T, privateKey ed25519.PrivateKey, issuer string, verificationTime time.Time) ([]byte, VerifyContext) {
	t.Helper()
	rootDigest := testDigest("custody-root")
	deliveredDigest := testDigest("custody-delivered")
	predecessorDigest := testDigest("event-predecessor")
	authorityDigest := testDigest("execution-authority")
	body := EnvelopeBody{
		Kind:        "afp.task-event",
		SpecVersion: protocolVersion,
		Profile:     "local",
		Issuer:      issuer,
		Audience:    issuer,
		Nonce:       "test-executing-event-nonce",
		IssuedAt:    "2030-01-02T03:04:05Z",
		ExpiresAt:   "2030-01-02T04:04:05Z",
		Payload: map[string]any{
			"task_id":                   "task://test/001",
			"attempt":                   int64(1),
			"event_id":                  "event://test/001",
			"event":                     "executing",
			"sequence":                  int64(3),
			"predecessor_digest":        predecessorDigest,
			"fence":                     int64(1),
			"facts":                     []any{rootDigest, deliveredDigest},
			"authority_evidence_digest": authorityDigest,
		},
	}
	_, spki, code := AgentIDFromEd25519Key(base64.RawURLEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey)))
	if code != OK {
		t.Fatalf("derive test issuer SPKI = %s", code)
	}
	return testSignedEnvelope(t, body, privateKey), VerifyContext{
		VerificationTime: verificationTime,
		LocalPolicy:      true,
		ResolveIssuerKey: func(request string) (string, bool) { return spki, request == issuer },
		VerifiedReferences: map[string]bool{
			rootDigest:        true,
			deliveredDigest:   true,
			predecessorDigest: true,
		},
		AuthorityEvidence: []AuthorityEvidence{{
			Digest: authorityDigest, Issuer: issuer, Subject: issuer, PermittedEvents: []string{"executing"},
		}},
		CustodyFacts: []map[string]any{
			{"sequence": int64(1), "predecessor_digest": nil, "state": "submitted", "fact_digest": rootDigest},
			{"sequence": int64(2), "predecessor_digest": rootDigest, "state": "delivered", "fact_digest": deliveredDigest},
		},
		ExecutionAuthority: &ExecutionAuthorityEvidence{Verified: true, TaskID: "task://test/001", Attempt: 1, Issuer: issuer, Fence: 1},
	}
}

func testEnvelopeSigner(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	issuer, _, code := AgentIDFromEd25519Key(base64.RawURLEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey)))
	if code != OK {
		t.Fatalf("derive test issuer = %s", code)
	}
	return privateKey, issuer
}

func testVerificationTime(t *testing.T) time.Time {
	t.Helper()
	verificationTime, code := parseTimestamp("2030-01-02T03:14:05Z")
	if code != OK {
		t.Fatalf("parse verification time = %s", code)
	}
	return verificationTime
}

func testSignedDescriptor(t *testing.T, privateKey ed25519.PrivateKey, issuer string) ([]byte, string) {
	t.Helper()
	proofDigest := testDigest("revocation-proof")
	body := EnvelopeBody{
		Kind:        "afp.agent-descriptor",
		SpecVersion: protocolVersion,
		Profile:     "local",
		Issuer:      issuer,
		Audience:    issuer,
		Nonce:       "test-descriptor-nonce",
		IssuedAt:    "2030-01-02T03:04:05Z",
		ExpiresAt:   "2030-01-02T04:04:05Z",
		Payload: map[string]any{
			"aid":              issuer,
			"descriptor_id":    "descriptor://test/001",
			"signing_key":      base64.RawURLEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey)),
			"capabilities":     []any{"test"},
			"route_hints":      []any{"local"},
			"revocation_proof": map[string]any{"digest": proofDigest, "status": "unrevoked"},
		},
	}
	return testSignedEnvelope(t, body, privateKey), proofDigest
}

func testSignedEnvelope(t *testing.T, body EnvelopeBody, privateKey ed25519.PrivateKey) []byte {
	t.Helper()
	preimage, code := SigningPreimage(body)
	if code != OK {
		t.Fatalf("build signing preimage = %s", code)
	}
	raw, code := marshalCanonical(map[string]any{
		"body": body.value(),
		"signature": map[string]any{
			"alg":   "Ed25519",
			"value": base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, preimage)),
		},
	})
	if code != OK {
		t.Fatalf("marshal signed envelope = %s", code)
	}
	return raw
}

func testDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}
