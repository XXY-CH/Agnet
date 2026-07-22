package afp

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"time"
)

// IssuerKeyResolver supplies a verified, exact DER SubjectPublicKeyInfo key for
// an AFP issuer. The verifier never discovers keys from an envelope.
type IssuerKeyResolver func(issuer string) (spki string, ok bool)

// NegotiationTranscript is the exact non-local AFP session transcript.
type NegotiationTranscript struct {
	Issuer             string
	Peer               string
	IssuerVersions     []string
	PeerVersions       []string
	SelectedVersion    string
	SelectedProfile    string
	RouteContextDigest string
}

// AuthorityEvidence is a previously verified authority record.
type AuthorityEvidence struct {
	Digest             string
	Issuer             string
	Subject            string
	PermittedEvents    []string
	PermittedTerminals []string
}

// VerifiedRouteBinding is a previously verified route-binding record. It is
// evidence, not an unverified envelope supplied alongside the target object.
type VerifiedRouteBinding struct {
	Issuer             string
	Peer               string
	Route              string
	Version            string
	Profile            string
	NegotiationDigest  string
	RouteContextDigest string
}

// RevocationEvidence is a verified status record referenced by a proof.
type RevocationEvidence struct {
	Digest    string
	Unrevoked bool
	CurrentAt time.Time
}

// CapabilityGrantEvidence identifies a verified parent grant. Grant is the
// exact verified payload, never a caller-synthesized substitute.
type CapabilityGrantEvidence struct {
	Digest string
	Grant  map[string]any
}

// ReceiptExpectation supplies the current task fence and verified references.
type ReceiptExpectation struct {
	TaskID              string
	Attempt             int64
	ReceiptFence        int64
	CurrentFence        int64
	Sequence            int64
	PredecessorSequence int64
	ReceiptDigest       string
	CustodyDigest       string
	LineageDigest       string
	VerifiedReferences  map[string]bool
}

// SettlementExpectation supplies evidence required to authorize settlement.
type SettlementExpectation struct {
	VerifiedStatus     map[string]bool
	VerifiedReferences map[string]bool
}

// ExecutionAuthorityEvidence is independently verified permission to execute a
// specific task attempt at a specific fence.
type ExecutionAuthorityEvidence struct {
	Verified bool
	TaskID   string
	Attempt  int64
	Issuer   string
	Fence    int64
}

// CustodyExpiryEvidence is independently verified delivery or lease expiry
// evidence. Unverified records are ignored and cannot affect execution.
type CustodyExpiryEvidence struct {
	Kind      string
	ExpiresAt time.Time
	Verified  bool
}

// ProfileTransitionEvidence records the independently verified artifacts
// required before changing profile.
type ProfileTransitionEvidence struct {
	PriorSessionID          string
	SuccessorSessionID      string
	NewTranscriptVerified   bool
	NewRouteBindingVerified bool
	LocalPolicyVerified     bool
}

// RailAssertion is verified external evidence. A rail cannot redefine AFP
// receipt semantics.
type RailAssertion struct {
	Verified          bool
	AssertedSemantics string
}

// VerifyContext contains every fact a pure AF0 verifier may consult. It has no
// network, storage, clock, or implicit key dependencies. Every evidence channel
// is intentionally separate so a reference cannot impersonate authority,
// revocation, route, predecessor, receipt, or settlement evidence.
type VerifyContext struct {
	VerificationTime          time.Time
	VerificationTimeInvalid   bool
	ResolveIssuerKey          IssuerKeyResolver
	LocalPolicy               bool
	Negotiation               *NegotiationTranscript
	VerifiedRouteBinding      *VerifiedRouteBinding
	ProfileTransition         ProfileTransitionEvidence
	PriorSessionID            string
	SuccessorSessionID        string
	ReplaySeen                func(issuer, nonce, objectDigest string) bool
	ClaimedObjectDigest       string
	SuppliedNegotiationDigest string
	PreviousProfile           string
	FailedRetry               bool
	VerifiedReferences        map[string]bool
	AuthorityEvidence         []AuthorityEvidence
	ParentGrant               *CapabilityGrantEvidence
	RevocationEvidence        []RevocationEvidence
	CustodyFacts              []map[string]any
	ExecutionAuthority        *ExecutionAuthorityEvidence
	CustodyExpiryEvidence     []CustodyExpiryEvidence
	Receipt                   *ReceiptExpectation
	Settlement                *SettlementExpectation
	RailAssertion             *RailAssertion
}

// AgentIDFromEd25519Key derives the implemented ASP aid from a raw 32-byte
// Ed25519 public key through its exact DER SPKI representation.
func AgentIDFromEd25519Key(raw string) (string, string, Code) {
	key, ok := decodeRawBase64URL(raw)
	if !ok || len(key) != ed25519.PublicKeySize {
		return "", "", InvalidString
	}
	spki, err := x509.MarshalPKIXPublicKey(ed25519.PublicKey(key))
	if err != nil {
		return "", "", InvalidString
	}
	digest := sha256.Sum256(append([]byte("asp-agent-id-v1\x00"), spki...))
	return "aid:ed25519:" + base64.RawURLEncoding.EncodeToString(digest[:]), base64.RawURLEncoding.EncodeToString(spki), OK
}

// NegotiationDigest returns the exact digest of a canonical transcript.
func NegotiationDigest(t NegotiationTranscript) (string, Code) {
	value := map[string]any{
		"issuer": t.Issuer, "peer": t.Peer, "issuer_versions": stringsToAny(t.IssuerVersions),
		"peer_versions": stringsToAny(t.PeerVersions), "selected_version": t.SelectedVersion,
		"selected_profile": t.SelectedProfile, "route_context_digest": t.RouteContextDigest,
	}
	if code := validateNegotiation(t); code != OK {
		return "", code
	}
	canonical, code := marshalCanonical(value)
	if code != OK {
		return "", code
	}
	digest := sha256.Sum256(append([]byte("AFP-NEGOTIATION-V1\x00"), canonical...))
	return base64.RawURLEncoding.EncodeToString(digest[:]), OK
}

func stringsToAny(values []string) []any {
	result := make([]any, len(values))
	for i := range values {
		result[i] = values[i]
	}
	return result
}

func validateNegotiation(t NegotiationTranscript) Code {
	if t.Issuer == "" || t.Peer == "" || !isAID(t.Issuer) || !isAID(t.Peer) ||
		!profiles[t.SelectedProfile] || t.SelectedProfile == "local" || !validDigest(t.RouteContextDigest) {
		return VersionNegotiationFailed
	}
	return ValidateNegotiatedVersion(t.IssuerVersions, t.PeerVersions, t.SelectedVersion)
}

// VerifyEnvelope executes the §5 ordered full-envelope verification pipeline.
func VerifyEnvelope(raw []byte, ctx VerifyContext) Code {
	value, code := ParseRawCanonicalJSON(raw)
	if code != OK {
		return code
	}
	outer, ok := value.(map[string]any)
	if !ok {
		return NoncanonicalJSON
	}
	body, signature, code := parseEnvelope(outer)
	if code != OK {
		return code
	}

	if ctx.VerificationTime.IsZero() {
		if ctx.VerificationTimeInvalid {
			return InvalidTimestamp
		}
		return VerificationTimeRequired
	}
	if !validVerificationTime(ctx.VerificationTime) {
		return InvalidTimestamp
	}

	// 3: profile transitions precede both local admission and non-local binding.
	if code = verifyProfileTransition(body, ctx); code != OK {
		return code
	}
	if body.Profile == "local" {
		if !ctx.LocalPolicy {
			return LocalPolicyRequired
		}
	} else if code = verifyBinding(body, ctx); code != OK {
		return code
	}
	// 4: known kind/profile and production authority-profile guard.
	if !kinds[body.Kind] {
		return InvalidKind
	}
	if !profiles[body.Profile] {
		return InvalidProfile
	}
	if code = ValidateProfileRoute(body.Profile, "", body.Kind); code != OK {
		return code
	}
	// 5: primitive and time validation.
	if code = validateBodyStrict(body); code != OK {
		return code
	}
	issued, _ := parseTimestamp(body.IssuedAt)
	expires, _ := parseTimestamp(body.ExpiresAt)
	if ctx.VerificationTime.Before(issued) || !ctx.VerificationTime.Before(expires) {
		return InvalidTimestamp
	}
	// 6: issuer/audience/key resolution.
	if !isAID(body.Issuer) || !isAID(body.Audience) {
		return KeyResolutionFailed
	}
	spki, code := resolveEnvelopeKey(body, ctx)
	if code != OK {
		return code
	}
	// 7: format then signature.
	sig, ok := decodeRawBase64URL(signature)
	if !ok || len(sig) != ed25519.SignatureSize {
		return SignatureFormatInvalid
	}
	key, code := parseExactSPKI(spki)
	if code != OK {
		return KeyResolutionFailed
	}
	if aid, aidCode := agentIDFromSPKI(spki); aidCode != OK || aid != body.Issuer {
		return KeyResolutionFailed
	}
	preimage, code := SigningPreimage(body)
	if code != OK {
		return code
	}
	if !ed25519.Verify(key, preimage, sig) {
		return SignatureInvalid
	}
	// 8: object digest and replay.
	digest, code := objectDigest(body)
	if code != OK {
		return code
	}
	if ctx.ClaimedObjectDigest != "" && ctx.ClaimedObjectDigest != digest {
		return DigestMismatch
	}
	if ctx.ReplaySeen != nil && ctx.ReplaySeen(body.Issuer, body.Nonce, digest) {
		return ReplayDetected
	}
	// 9: exact payload shape/types/invariants.
	if code = ValidateEnvelope(body); code != OK {
		return code
	}
	if body.Kind == "afp.direct-swarm-charter" {
		expiry, _ := parseTimestamp(stringOr(objectFieldFromAny(body.Payload), "expiry"))
		if !ctx.VerificationTime.Before(expiry) {
			return InvalidTimestamp
		}
	}
	// 10: supplied evidence.
	return verifyEvidence(body, digest, ctx)
}

func parseEnvelope(outer map[string]any) (EnvelopeBody, string, Code) {
	for _, name := range []string{"body", "signature"} {
		if _, ok := outer[name]; !ok {
			return EnvelopeBody{}, "", MissingField
		}
	}
	if len(outer) != 2 {
		return EnvelopeBody{}, "", UnknownField
	}
	body, code := envelopeBody(objectField(outer, "body"))
	if code != OK {
		return EnvelopeBody{}, "", code
	}
	sig := objectField(outer, "signature")
	if len(sig) != 2 {
		return EnvelopeBody{}, "", UnknownField
	}
	if stringOr(sig, "alg") != "Ed25519" {
		return EnvelopeBody{}, "", SignatureFormatInvalid
	}
	value, ok := stringField(sig, "value")
	if !ok {
		return EnvelopeBody{}, "", MissingField
	}
	return body, value, OK
}
func resolveEnvelopeKey(body EnvelopeBody, ctx VerifyContext) (string, Code) {
	if body.Kind == "afp.agent-descriptor" {
		payload := objectFieldFromAny(body.Payload)
		aid, spki, code := AgentIDFromEd25519Key(stringOr(payload, "signing_key"))
		if code != OK || aid != body.Issuer || stringOr(payload, "aid") != aid {
			return "", KeyResolutionFailed
		}
		return spki, OK
	}
	if ctx.ResolveIssuerKey == nil {
		return "", KeyResolutionFailed
	}
	spki, ok := ctx.ResolveIssuerKey(body.Issuer)
	if !ok {
		return "", KeyResolutionFailed
	}
	return spki, OK
}

func parseExactSPKI(value string) (ed25519.PublicKey, Code) {
	der, ok := decodeRawBase64URL(value)
	if !ok {
		return nil, KeyResolutionFailed
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	key, ok := parsed.(ed25519.PublicKey)
	if err != nil || !ok || len(key) != ed25519.PublicKeySize {
		return nil, KeyResolutionFailed
	}
	reencoded, err := x509.MarshalPKIXPublicKey(key)
	if err != nil || string(der) != string(reencoded) {
		return nil, KeyResolutionFailed
	}
	return key, OK
}

func objectDigest(body EnvelopeBody) (string, Code) {
	preimage, code := DigestPreimage(body)
	if code != OK {
		return "", code
	}
	digest := sha256.Sum256(preimage)
	return base64.RawURLEncoding.EncodeToString(digest[:]), OK
}

func verifyProfileTransition(body EnvelopeBody, ctx VerifyContext) Code {
	if ctx.PreviousProfile == "" || ctx.PreviousProfile == body.Profile {
		return OK
	}
	transition := ctx.ProfileTransition
	if (transition.PriorSessionID != "" && ctx.PriorSessionID != "" && transition.PriorSessionID != ctx.PriorSessionID) || (transition.SuccessorSessionID != "" && ctx.SuccessorSessionID != "" && transition.SuccessorSessionID != ctx.SuccessorSessionID) {
		return ProfileDowngradeRejected
	}
	if transition.PriorSessionID == "" {
		transition.PriorSessionID = ctx.PriorSessionID
	}
	if transition.SuccessorSessionID == "" {
		transition.SuccessorSessionID = ctx.SuccessorSessionID
	}
	return ValidateProfileTransition(ctx.PreviousProfile, body.Profile, ctx.FailedRetry, transition)
}

func verifyBinding(body EnvelopeBody, ctx VerifyContext) Code {
	if ctx.Negotiation == nil {
		return NegotiationRequired
	}
	if code := validateNegotiation(*ctx.Negotiation); code != OK {
		return NegotiationBindingMismatch
	}
	digest, code := NegotiationDigest(*ctx.Negotiation)
	if code != OK || !validDigest(ctx.SuppliedNegotiationDigest) || ctx.SuppliedNegotiationDigest != digest {
		return NegotiationBindingMismatch
	}
	if body.Issuer != ctx.Negotiation.Issuer || body.Audience != ctx.Negotiation.Peer || body.SpecVersion != ctx.Negotiation.SelectedVersion || body.Profile != ctx.Negotiation.SelectedProfile {
		return NegotiationBindingMismatch
	}
	if body.Kind == "afp.route-binding" {
		payload := objectFieldFromAny(body.Payload)
		if stringOr(payload, "peer") != ctx.Negotiation.Peer || stringOr(payload, "subject") != ctx.Negotiation.Issuer || stringOr(payload, "negotiation_digest") != digest || stringOr(payload, "route_context_digest") != ctx.Negotiation.RouteContextDigest {
			return NegotiationBindingMismatch
		}
		return OK
	}
	binding := ctx.VerifiedRouteBinding
	if binding == nil || !routes[binding.Route] || binding.Issuer != body.Issuer || binding.Peer != body.Audience || binding.Version != body.SpecVersion || binding.Profile != body.Profile || binding.NegotiationDigest != digest || binding.RouteContextDigest != ctx.Negotiation.RouteContextDigest {
		return NegotiationBindingMismatch
	}
	return OK
}

func verifyEvidence(body EnvelopeBody, digest string, ctx VerifyContext) Code {
	payload := objectFieldFromAny(body.Payload)
	if body.Kind == "afp.settlement-commit" {
		expected := SettlementExpectation{VerifiedReferences: ctx.VerifiedReferences}
		if ctx.Settlement != nil {
			expected = *ctx.Settlement
		}
		if code := ValidateSettlementCommit(payload, expected); code != OK {
			return code
		}
		if assertion := ctx.RailAssertion; assertion != nil && assertion.Verified && assertion.AssertedSemantics == "receipt" {
			return RailSemanticsRejected
		}
	}
	if body.Kind == "afp.agent-descriptor" {
		if code := verifyRevocationProof(objectField(payload, "revocation_proof"), ctx.RevocationEvidence, ctx.VerificationTime); code != OK {
			return code
		}
	}
	if body.Kind == "afp.capability-grant" {
		if code := verifyRevocationProof(objectField(payload, "revocation_proof"), ctx.RevocationEvidence, ctx.VerificationTime); code != OK {
			return code
		}
		if parentDigest := stringOr(payload, "parent_grant_digest"); parentDigest != "" {
			parent := ctx.ParentGrant
			if parent == nil || parent.Digest != parentDigest || !ctx.VerifiedReferences[parentDigest] {
				return ParentReferenceRequired
			}
			if body.Issuer != stringOr(parent.Grant, "subject") {
				return CapabilityIssuerMismatch
			}
			if code := verifyRevocationProof(objectField(parent.Grant, "revocation_proof"), ctx.RevocationEvidence, ctx.VerificationTime); code != OK {
				return code
			}
			if code := ValidateCapabilityAttenuation(parent.Grant, grantWithEnvelope(payload, body)); code != OK {
				return code
			}
		}
	}
	if body.Kind == "afp.task-event" && stringOr(payload, "event") == "executing" {
		if code := verifyCustodyFacts(ctx.CustodyFacts, ctx.VerifiedReferences); code != OK {
			return code
		}
		if code := custodyExecutionCancellation(ctx.CustodyFacts); code != OK {
			return code
		}
		if code := verifyCustodyExpiry(ctx.CustodyExpiryEvidence, ctx.VerificationTime); code != OK {
			return code
		}
		authority := ExecutionAuthorityEvidence{}
		if ctx.ExecutionAuthority != nil {
			authority = *ctx.ExecutionAuthority
		}
		if code := validateExecutionAuthority(stringOr(payload, "task_id"), intMust(payload, "attempt"), body.Issuer, intMust(payload, "fence"), authority); code != OK {
			return code
		}
	}
	if body.Kind == "afp.task-event" || body.Kind == "afp.receipt-commit" {
		if code := verifyAuthority(body, payload, ctx.AuthorityEvidence); code != OK {
			return code
		}
	}
	if code := verifyReferences(payload, ctx.VerifiedReferences); code != OK {
		return code
	}
	if body.Kind == "afp.custody-receipt" {
		if code := verifyCustodyReceipt(payload, digest, ctx.CustodyFacts, ctx.VerifiedReferences); code != OK {
			return code
		}
	} else if ctx.CustodyFacts != nil {
		if code := verifyCustodyFacts(ctx.CustodyFacts, ctx.VerifiedReferences); code != OK {
			return code
		}
	}
	if body.Kind == "afp.receipt-commit" {
		if ctx.Receipt == nil {
			return ReceiptFenceViolation
		}
		if code := ValidateReceiptExpectation(payload, digest, *ctx.Receipt); code != OK {
			return code
		}
	}
	return OK
}

func verifyCustodyReceipt(payload map[string]any, digest string, facts []map[string]any, references map[string]bool) Code {
	if code := verifyCustodyFacts(facts, references); code != OK {
		return code
	}
	for _, fact := range facts {
		if stringOr(fact, "fact_digest") != digest {
			continue
		}
		if intMust(fact, "sequence") != intMust(payload, "sequence") || stringOr(fact, "state") != stringOr(payload, "state") || fact["predecessor_digest"] != payload["predecessor_digest"] {
			return CustodyLineageInvalid
		}
		return OK
	}
	return CustodyLineageInvalid
}

func grantWithEnvelope(payload map[string]any, body EnvelopeBody) map[string]any {
	grant := make(map[string]any, len(payload)+2)
	for key, value := range payload {
		grant[key] = value
	}
	grant["audience"] = body.Audience
	grant["expires_at"] = body.ExpiresAt
	return grant
}

func verifyReferences(payload map[string]any, references map[string]bool) Code {
	if references == nil {
		return ReferenceInvalid
	}
	for key, value := range payload {
		// Negotiation, route, authority, and revocation proof each have a
		// dedicated validation channel. A predecessor is an ordinary verified
		// reference and must resolve explicitly.
		if key == "authority_evidence_digest" || key == "negotiation_digest" || key == "route_context_digest" {
			continue
		}
		if strings.HasSuffix(key, "_digest") {
			digest, ok := value.(string)
			if !ok || !validDigest(digest) || !references[digest] {
				return ReferenceInvalid
			}
			continue
		}
		if key == "facts" || strings.HasSuffix(key, "_digests") {
			values, ok := value.([]any)
			if !ok || len(values) == 0 {
				return ReferenceInvalid
			}
			for _, item := range values {
				digest, ok := item.(string)
				if !ok || !validDigest(digest) || !references[digest] {
					return ReferenceInvalid
				}
			}
		}
	}
	return OK
}

func verifyRevocationProof(proof map[string]any, evidence []RevocationEvidence, verificationTime time.Time) Code {
	if !validRevocationProof(proof) {
		return RevocationProofRejected
	}
	for _, item := range evidence {
		if item.Digest == stringOr(proof, "digest") && item.Unrevoked && !item.CurrentAt.IsZero() && item.CurrentAt.UTC().Equal(verificationTime.UTC()) {
			return OK
		}
	}
	return RevocationProofRejected
}

func verifyAuthority(body EnvelopeBody, payload map[string]any, evidence []AuthorityEvidence) Code {
	digest := stringOr(payload, "authority_evidence_digest")
	for _, authority := range evidence {
		if authority.Digest != digest || !validDigest(authority.Digest) || authority.Issuer != body.Issuer || authority.Subject != body.Issuer {
			continue
		}
		if body.Kind == "afp.task-event" && contains(authority.PermittedEvents, stringOr(payload, "event")) {
			return OK
		}

		if body.Kind == "afp.receipt-commit" && contains(authority.PermittedTerminals, stringOr(payload, "terminal")) {
			return OK
		}
	}
	return AuthorityEvidenceRejected
}

func objectFieldFromAny(value any) map[string]any { m, _ := value.(map[string]any); return m }

func isAID(value string) bool { return strings.HasPrefix(value, "aid:") && len(value) > len("aid:") }

func parseTimestamp(value string) (time.Time, Code) {
	parsed, err := time.Parse("2006-01-02T15:04:05Z", value)
	if err != nil || parsed.Format("2006-01-02T15:04:05Z") != value {
		return time.Time{}, InvalidTimestamp
	}
	return parsed, OK
}

func validVerificationTime(value time.Time) bool {
	if value.Location() != time.UTC || value.Nanosecond() != 0 {
		return false
	}
	parsed, code := parseTimestamp(value.Format("2006-01-02T15:04:05Z"))
	return code == OK && parsed.Equal(value)
}

func verifyCustodyExpiry(evidence []CustodyExpiryEvidence, verificationTime time.Time) Code {
	for _, item := range evidence {
		if !item.Verified {
			continue
		}
		if item.Kind != "delivery" && item.Kind != "lease" {
			return InvalidTimestamp
		}
		if item.ExpiresAt.IsZero() || !validVerificationTime(item.ExpiresAt) {
			return InvalidTimestamp
		}
		if !verificationTime.Before(item.ExpiresAt) {
			return CustodyExpired
		}
	}
	return OK
}

func verifyCustodyFacts(facts []map[string]any, references map[string]bool) Code {
	if code := ValidateCustodyLineage(facts, ""); code != OK {
		return code
	}
	for _, fact := range facts {
		if predecessor := fact["predecessor_digest"]; predecessor != nil {
			digest, ok := predecessor.(string)
			if !ok || !references[digest] {
				return ReferenceInvalid
			}
		}
	}
	return OK
}

func validateBodyStrict(body EnvelopeBody) Code {
	if body.Kind == "" || body.SpecVersion == "" || body.Profile == "" || body.Issuer == "" || body.Audience == "" || body.Nonce == "" || body.IssuedAt == "" || body.ExpiresAt == "" {
		return MissingField
	}
	if !kinds[body.Kind] {
		return InvalidKind
	}
	if body.SpecVersion != protocolVersion {
		return UnsupportedVersion
	}
	if !profiles[body.Profile] {
		return InvalidProfile
	}
	issued, code := parseTimestamp(body.IssuedAt)
	if code != OK {
		return code
	}
	expires, code := parseTimestamp(body.ExpiresAt)
	if code != OK {
		return code
	}
	if !expires.After(issued) {
		return TimeOrderInvalid
	}
	if _, ok := body.Payload.(map[string]any); !ok {
		return InvalidString
	}
	return OK
}

// ValidateReceiptExpectation binds an independently verified expectation, the
// computed receipt digest, and the signed receipt payload.
func ValidateReceiptExpectation(payload map[string]any, receiptDigest string, r ReceiptExpectation) Code {
	if stringOr(payload, "task_id") != r.TaskID || intMust(payload, "attempt") != r.Attempt || intMust(payload, "fence") != r.ReceiptFence || stringOr(payload, "lineage_digest") != r.LineageDigest || receiptDigest != r.ReceiptDigest {
		return ReceiptFenceViolation
	}
	if r.TaskID == "" || r.Attempt <= 0 || r.ReceiptFence <= 0 || r.CurrentFence <= 0 || r.ReceiptFence != r.CurrentFence || r.Sequence <= 0 || r.PredecessorSequence < 0 || r.Sequence != r.PredecessorSequence+1 {
		return ReceiptFenceViolation
	}
	for _, digest := range []string{r.ReceiptDigest, r.CustodyDigest, r.LineageDigest} {
		if !validDigest(digest) || !r.VerifiedReferences[digest] {
			return ReceiptFenceViolation
		}
	}
	return OK
}

// ValidateSettlementCommit requires all exact verified status flags, references,
// and base64url idempotency material.
func ValidateSettlementCommit(payload map[string]any, expected SettlementExpectation) Code {
	kind := stringOr(payload, "fact_kind")
	if !validSettlementKind(kind) {
		return UnsupportedSettlementFact
	}
	budgetDigest := stringOr(payload, "budget_authorization_digest")
	if !validDigest(budgetDigest) || !expected.VerifiedReferences[budgetDigest] {
		return BudgetAuthorizationRequired
	}
	for _, name := range []string{"committed", "uncontested", "unexpired", "unrevoked", "current_fence", "profile_sufficient", "digest_valid", "budget_bound"} {
		value, present := expected.VerifiedStatus[name]
		if !present || !value {
			return SettlementRefused
		}
	}
	if !isAID(stringOr(payload, "settlement_authority")) || !validDigest(payload["committed_fact_digest"]) {
		return SettlementRefused
	}
	receiptOrCustodyDigest := stringOr(payload, "receipt_or_custody_digest")
	if !validDigest(receiptOrCustodyDigest) || !expected.VerifiedReferences[receiptOrCustodyDigest] {
		return SettlementRefused
	}
	key, _, code := SettlementIdempotency(stringOr(payload, "settlement_authority"), kind, stringOr(payload, "committed_fact_digest"))
	if code != OK || stringOr(payload, "idempotency_key") != key {
		return SettlementRefused
	}
	return OK
}
func validatePayloadExact(body EnvelopeBody, p map[string]any) Code {
	fields, found := catalogueFields[body.Kind]
	if !found {
		return InvalidKind
	}
	for key := range p {
		if !fields[key] {
			return UnknownField
		}
	}
	for key := range fields {
		if _, exists := p[key]; !exists && !(body.Kind == "afp.capability-grant" && key == "parent_grant_digest") {
			return MissingField
		}
	}
	for key, value := range p {
		if _, code := marshalCanonical(value); code != OK {
			return code
		}
		if (strings.HasSuffix(key, "_digest") || key == "idempotency_key") && !validDigest(value) {
			return InvalidString
		}
	}
	if code := validatePayloadOwner(body, p); code != OK {
		return code
	}
	for _, name := range requiredStrings(body.Kind) {
		if value, ok := stringField(p, name); !ok || value == "" {
			return InvalidString
		}
	}
	for _, name := range positiveInts(body.Kind) {
		if value, ok := intField(p, name); !ok || value <= 0 {
			return InvalidString
		}
	}
	for _, name := range nonnegativeInts(body.Kind) {
		if value, ok := intField(p, name); !ok || value < 0 {
			return InvalidString
		}
	}
	switch body.Kind {
	case "afp.agent-descriptor":
		if !validRawEd25519Key(stringOr(p, "signing_key")) || !validStringList(p, "capabilities", false, false) || !validStringList(p, "route_hints", false, false) || !validRevocationProof(objectField(p, "revocation_proof")) {
			return InvalidString
		}
	case "afp.capability-advertisement":
		if !validStringList(p, "actions", false, false) || !validStringList(p, "resources", false, false) || !validLimits(objectField(p, "limits")) {
			return InvalidString
		}
	case "afp.intent-query":
		constraints := objectField(p, "constraints")
		if len(constraints) != 2 || stringOr(constraints, "action") == "" || stringOr(constraints, "resource") == "" || !validLimits(objectField(p, "budget")) || (stringOr(p, "privacy") != "private" && stringOr(p, "privacy") != "shared") {
			return InvalidString
		}
	case "afp.offer":
		if !validLimits(objectField(p, "terms")) {
			return InvalidString
		}
	case "afp.capability-grant":
		if !validStringList(p, "actions", false, false) || !validStringList(p, "resources", false, false) || !validLimits(objectField(p, "limits")) {
			return InvalidString
		}
		if _, ok := boolField(p, "delegate"); !ok {
			return InvalidString
		}
		if !validRevocationProof(objectField(p, "revocation_proof")) {
			return InvalidString
		}
	case "afp.task-claim":
		if !validLease(objectField(p, "lease")) {
			return InvalidString
		}
	case "afp.task-event":
		if !contains([]string{"submitted", "cancelled", "expired", "accepted", "rejected", "executing", "completed", "failed"}, stringOr(p, "event")) || !validDigestList(p, "facts") {
			return InvalidString
		}
	case "afp.artifact-manifest":
		if !validStringList(p, "recipients", false, true) {
			return InvalidString
		}
	case "afp.mailbox-envelope":
		if _, code := parseTimestamp(stringOr(p, "delivery_expiry")); code != OK {
			return InvalidString
		}
	case "afp.route-binding":
		if !routes[stringOr(p, "route")] || stringOr(p, "peer") != body.Audience {
			return InvalidRoute
		}
	case "afp.direct-swarm-charter":
		if !validStringList(p, "members", false, true) || !validDigestList(p, "task_digests") || !isAIDList(p, "members") {
			return InvalidString
		}
		expiry, code := parseTimestamp(stringOr(p, "expiry"))
		if code != OK {
			return InvalidTimestamp
		}
		issued, _ := parseTimestamp(body.IssuedAt)
		envelopeExpiry, _ := parseTimestamp(body.ExpiresAt)
		if !expiry.After(issued) || expiry.After(envelopeExpiry) {
			return TimeOrderInvalid
		}
	case "afp.settlement-commit":
		if !validSettlementKind(stringOr(p, "fact_kind")) {
			return UnsupportedSettlementFact
		}
	}
	return OK
}

func requiredStrings(kind string) []string {
	all := map[string][]string{
		"afp.agent-descriptor": {"aid", "descriptor_id", "signing_key"}, "afp.capability-advertisement": {"advertisement_id", "subject"}, "afp.intent-query": {"intent_id", "requester"}, "afp.offer": {"offer_id", "provider"}, "afp.capability-grant": {"grant_id", "subject"}, "afp.task-open": {"task_id", "requester"}, "afp.task-claim": {"task_id", "claim_id", "owner", "predecessor_digest"}, "afp.task-event": {"task_id", "event_id", "event", "predecessor_digest"}, "afp.checkpoint": {"task_id", "checkpoint_id", "predecessor_digest"}, "afp.artifact-manifest": {"artifact_id", "task_id", "media_type"}, "afp.mailbox-envelope": {"mail_id", "recipient", "task_id"}, "afp.custody-receipt": {"custody_id", "mail_digest", "task_id", "predecessor_digest", "custodian"}, "afp.receipt-commit": {"receipt_id", "task_id", "terminal"}, "afp.assurance-evidence": {"assurance_id", "subject", "profile", "claim", "evidence_digest"}, "afp.route-binding": {"route_id", "subject", "route", "peer"}, "afp.direct-swarm-charter": {"charter_id", "swarm_id", "authority_rule", "fence_rule", "expiry"}, "afp.settlement-commit": {"settlement_id", "settlement_authority", "fact_kind"},
	}
	return all[kind]
}
func positiveInts(kind string) []string {
	all := map[string][]string{"afp.task-open": {"attempt", "fence"}, "afp.task-claim": {"attempt", "fence", "sequence"}, "afp.task-event": {"attempt", "fence", "sequence"}, "afp.checkpoint": {"attempt", "fence", "sequence"}, "afp.artifact-manifest": {"attempt"}, "afp.custody-receipt": {"attempt", "sequence"}, "afp.receipt-commit": {"attempt", "fence"}}
	return all[kind]
}
func nonnegativeInts(kind string) []string {
	if kind == "afp.artifact-manifest" {
		return []string{"size"}
	}
	return nil
}
func validRawEd25519Key(value string) bool {
	raw, ok := decodeRawBase64URL(value)
	return ok && len(raw) == ed25519.PublicKeySize
}
func validStringList(p map[string]any, field string, allowEmpty, aid bool) bool {
	values := stringsField(p, field)
	if (!allowEmpty && len(values) == 0) || hasDuplicate(values) {
		return false
	}
	for _, v := range values {
		if v == "" || (aid && !isAID(v)) {
			return false
		}
	}
	return true
}
func validDigestList(p map[string]any, field string) bool {
	values := stringsField(p, field)
	if len(values) == 0 || hasDuplicate(values) {
		return false
	}
	for _, v := range values {
		if !validDigest(v) {
			return false
		}
	}
	return true
}
func isAIDList(p map[string]any, field string) bool {
	for _, v := range stringsField(p, field) {
		if !isAID(v) {
			return false
		}
	}
	return true
}
func validLimits(p map[string]any) bool {
	if len(p) != 3 {
		return false
	}
	for _, name := range []string{"max_bytes", "max_cost", "max_time_ms"} {
		v, ok := intField(p, name)
		if !ok || v < 0 {
			return false
		}
	}
	return true
}
func validLease(p map[string]any) bool {
	if len(p) != 1 {
		return false
	}
	_, code := parseTimestamp(stringOr(p, "expires_at"))
	return code == OK
}
func validRevocationProof(p map[string]any) bool {
	return len(p) == 2 && stringOr(p, "status") == "unrevoked" && validDigest(p["digest"])
}

// VectorCrypto is explicitly supplied test-only cryptographic context. Production
// verification always receives its resolver through VerifyContext.
type VectorCrypto struct {
	PublicKeySPKI string
	AID           string
}

// VectorContext contains only explicit cryptographic material. All evidence is
// parsed from each corpus input and never synthesized by the evaluator.
type VectorContext struct {
	Crypto VectorCrypto
}

// EvaluateAF0VectorCase adapts corpus cases through the public validators.
func EvaluateAF0VectorCase(raw []byte, vector VectorContext) AF0Result {
	input, code := parseJSON(raw)
	if code != OK {
		return AF0Result{Code: code}
	}
	m, ok := input.(map[string]any)
	if !ok {
		return AF0Result{Code: NoncanonicalJSON}
	}
	if rawValue, ok := stringField(m, "raw"); ok {
		if parsed, parseCode := parseJSON([]byte(rawValue)); parseCode == OK {
			if outer, isObject := parsed.(map[string]any); isObject && outer["body"] != nil {
				return evaluateEnvelopeBody(m)
			}
		}
		return evaluateCanonical(m)
	}
	if _, ok := m["parent_envelope"]; ok {
		return evaluateSignedCapability(m, vector)
	}
	if _, ok := m["body"]; ok {
		return evaluateVectorEnvelope(m, vector)
	}
	if _, ok := m["transcript"]; ok {
		return evaluateVectorNegotiation(m)
	}
	if _, ok := m["current_profile"]; ok {
		failed, _ := boolField(m, "failed")
		transcript, _ := boolField(m, "new_transcript_verified")
		routeBinding, _ := boolField(m, "new_route_binding_verified")
		return AF0Result{Code: ValidateProfileTransition(stringOr(m, "current_profile"), stringOr(m, "requested_profile"), failed, ProfileTransitionEvidence{PriorSessionID: stringOr(m, "prior_session_id"), SuccessorSessionID: stringOr(m, "session_id"), NewTranscriptVerified: transcript, NewRouteBindingVerified: routeBinding, LocalPolicyVerified: stringOr(m, "local_policy_decision") == "accepted"})}
	}
	if _, ok := m["profile"]; ok {
		return AF0Result{Code: ValidateProfileRoute(stringOr(m, "profile"), stringOr(m, "route"), stringOr(m, "object_kind"))}
	}
	if _, ok := m["custody_lineage"]; ok {
		return AF0Result{Code: evaluateVectorCustody(m)}
	}
	if _, ok := m["facts"]; ok {
		return AF0Result{Code: ValidateCustodyLineage(objectsFieldStrict(m, "facts"), stringOr(m, "requested_operation"))}
	}
	if _, ok := m["receipt_fence"]; ok {
		return AF0Result{Code: validateVectorReceipt(m)}
	}
	if _, ok := m["fact_kind"]; ok {
		return evaluateVectorSettlement(m)
	}
	if _, ok := m["foreign_input_family"]; ok {
		return evaluateASPArtifact(m)
	}
	return AF0Result{Code: NoncanonicalJSON}
}

func evaluateVectorNegotiation(m map[string]any) AF0Result {
	t, ok := transcriptFromMap(m["transcript"])
	if !ok {
		if m["transcript"] == nil && stringOr(m, "object_kind") != "" {
			return AF0Result{Code: NegotiationRequired}
		}
		return AF0Result{Code: VersionNegotiationFailed}
	}
	_, code := NegotiationDigest(t)
	return AF0Result{Code: code, SelectedVersion: t.SelectedVersion}
}

func transcriptFromMap(value any) (NegotiationTranscript, bool) {
	m, ok := value.(map[string]any)
	if !ok || len(m) != 7 {
		return NegotiationTranscript{}, false
	}
	return NegotiationTranscript{Issuer: stringOr(m, "issuer"), Peer: stringOr(m, "peer"), IssuerVersions: stringsField(m, "issuer_versions"), PeerVersions: stringsField(m, "peer_versions"), SelectedVersion: stringOr(m, "selected_version"), SelectedProfile: stringOr(m, "selected_profile"), RouteContextDigest: stringOr(m, "route_context_digest")}, true
}

func objectsFieldStrict(m map[string]any, field string) []map[string]any {
	values, ok := m[field].([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(values))
	for _, v := range values {
		x, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		out = append(out, x)
	}
	return out
}

func evaluateVectorEnvelope(input map[string]any, vector VectorContext) AF0Result {
	body, code := envelopeBody(objectField(input, "body"))
	if code != OK {
		return AF0Result{Code: code}
	}
	signature := objectField(input, "signature")
	canonical, code := marshalCanonical(map[string]any{"body": body.value(), "signature": signature})
	if code != OK {
		return AF0Result{Code: code}
	}
	result := vectorEnvelopeDerived(body, signature)
	result.Code = VerifyEnvelope(canonical, verificationContextForVector(input, vector.Crypto, body))
	return result
}

func vectorEnvelopeDerived(body EnvelopeBody, signature map[string]any) AF0Result {
	canonicalBody, _ := marshalCanonical(body.value())
	signing := append([]byte("AFP-SIGNATURE-V1\x00"+body.Kind+"\x00"+body.SpecVersion+"\x00"+body.Profile+"\x00"), canonicalBody...)
	digestPreimage := append([]byte("AFP-DIGEST-V1\x00"+body.Kind+"\x00"+body.SpecVersion+"\x00"+body.Profile+"\x00"), canonicalBody...)
	digest := sha256.Sum256(digestPreimage)
	return AF0Result{CanonicalBody: string(canonicalBody), SigningPreimageHex: hex.EncodeToString(signing), DigestHex: hex.EncodeToString(digest[:]), Signature: stringOr(signature, "value")}
}

func verificationContextForVector(input map[string]any, _ VectorCrypto, body EnvelopeBody) VerifyContext {
	ctx := VerifyContext{ClaimedObjectDigest: stringOr(input, "claimed_object_digest")}
	policy := objectField(input, "local_policy")
	ctx.LocalPolicy = policy["accepted"] == true
	if when, ok := stringField(input, "verification_time"); ok {
		parsed, parseCode := parseTimestamp(when)
		ctx.VerificationTime = parsed
		ctx.VerificationTimeInvalid = parseCode != OK
	}
	ctx.PriorSessionID = stringOr(input, "prior_session_id")
	ctx.SuccessorSessionID = stringOr(input, "session_id")
	transcript, _ := boolField(input, "new_transcript_verified")
	routeBinding, _ := boolField(input, "new_route_binding_verified")
	ctx.ProfileTransition = ProfileTransitionEvidence{PriorSessionID: ctx.PriorSessionID, SuccessorSessionID: ctx.SuccessorSessionID, NewTranscriptVerified: transcript, NewRouteBindingVerified: routeBinding, LocalPolicyVerified: stringOr(input, "local_policy_decision") == "accepted"}
	if evidence := objectField(input, "key_evidence"); evidence != nil && len(evidence) == 3 && stringOr(evidence, "issuer") != "" && stringOr(evidence, "public_key_spki") != "" && evidence["verified"] == true {
		issuer, spki := stringOr(evidence, "issuer"), stringOr(evidence, "public_key_spki")
		ctx.ResolveIssuerKey = func(request string) (string, bool) { return spki, request == issuer }
	}
	ctx.SuppliedNegotiationDigest = stringOr(input, "negotiation_digest")
	if t, ok := transcriptFromMap(input["negotiation_transcript"]); ok {
		ctx.Negotiation = &t
	}
	ctx.VerifiedReferences = parseVerifiedReferences(input["verified_references"])
	ctx.RevocationEvidence = parseRevocationEvidence(input["revocation_evidence"], ctx.VerificationTime)
	ctx.AuthorityEvidence = parseAuthorityEvidence(input["verified_authority_evidence"])
	ctx.CustodyFacts = objectsFieldStrict(input, "custody_lineage")
	ctx.Receipt = parseReceiptExpectation(input["receipt_expectation"])
	ctx.Settlement = parseSettlementExpectation(input["verified_status"], input["verified_references"])
	if assertion := objectField(input, "rail_assertion"); len(assertion) == 3 && assertion["verified"] == true {
		ctx.RailAssertion = &RailAssertion{Verified: true, AssertedSemantics: stringOr(assertion, "asserted_semantics")}
	}
	if binding := objectField(input, "verified_route_binding"); binding != nil && binding["verified"] == true {
		if boundBody, code := envelopeBody(objectField(binding, "body")); code == OK && boundBody.Kind == "afp.route-binding" {
			p := objectFieldFromAny(boundBody.Payload)
			ctx.VerifiedRouteBinding = &VerifiedRouteBinding{Issuer: boundBody.Issuer, Peer: boundBody.Audience, Route: stringOr(p, "route"), Version: boundBody.SpecVersion, Profile: boundBody.Profile, NegotiationDigest: stringOr(p, "negotiation_digest"), RouteContextDigest: stringOr(p, "route_context_digest")}
		} else if len(binding) == 10 && validDigest(binding["digest"]) && stringOr(binding, "route_id") != "" && isAID(stringOr(binding, "subject")) && isAID(stringOr(binding, "peer")) {
			ctx.VerifiedRouteBinding = &VerifiedRouteBinding{Issuer: stringOr(binding, "subject"), Peer: stringOr(binding, "peer"), Route: stringOr(binding, "route"), Version: stringOr(binding, "selected_version"), Profile: stringOr(binding, "selected_profile"), NegotiationDigest: stringOr(binding, "negotiation_digest"), RouteContextDigest: stringOr(binding, "route_context_digest")}
		}
	}
	if replay, ok := boolField(input, "replay_seen"); ok && replay {
		ctx.ReplaySeen = func(string, string, string) bool { return true }
	}
	_ = body
	return ctx
}

func parseVerifiedReferences(value any) map[string]bool {
	values, ok := value.([]any)
	if !ok {
		return nil
	}
	refs := make(map[string]bool, len(values))
	for _, value := range values {
		ref := objectFieldFromAny(value)
		digest := stringOr(ref, "digest")
		if len(ref) != 2 || !validDigest(digest) || ref["verified"] != true || refs[digest] {
			return nil
		}
		refs[digest] = true
	}
	return refs
}

func parseRevocationEvidence(value any, verificationTime time.Time) []RevocationEvidence {
	values, ok := value.([]any)
	if !ok {
		return nil
	}
	evidence := make([]RevocationEvidence, 0, len(values))
	for _, value := range values {
		item := objectFieldFromAny(value)
		if len(item) != 4 || !validDigest(item["digest"]) || stringOr(item, "status") != "unrevoked" || item["verified"] != true || item["fresh"] != true {
			return nil
		}
		evidence = append(evidence, RevocationEvidence{Digest: stringOr(item, "digest"), Unrevoked: true, CurrentAt: verificationTime})
	}
	return evidence
}

func parseAuthorityEvidence(value any) []AuthorityEvidence {
	values, ok := value.([]any)
	if !ok {
		return nil
	}
	evidence := make([]AuthorityEvidence, 0, len(values))
	for _, value := range values {
		item := objectFieldFromAny(value)
		if len(item) != 6 || !validDigest(item["digest"]) || !isAID(stringOr(item, "issuer")) || !isAID(stringOr(item, "subject")) || item["verified"] != true || stringsField(item, "permitted_events") == nil || stringsField(item, "permitted_terminals") == nil {
			return nil
		}
		evidence = append(evidence, AuthorityEvidence{Digest: stringOr(item, "digest"), Issuer: stringOr(item, "issuer"), Subject: stringOr(item, "subject"), PermittedEvents: stringsField(item, "permitted_events"), PermittedTerminals: stringsField(item, "permitted_terminals")})
	}
	return evidence
}

func parseReceiptExpectation(value any) *ReceiptExpectation {
	m := objectFieldFromAny(value)
	if len(m) != 14 || stringOr(m, "task_id") == "" || stringOr(m, "task_id") != stringOr(m, "expected_task_id") || intMust(m, "attempt") != intMust(m, "expected_attempt") || !validDigest(m["actual_receipt_object_digest"]) || objectField(m, "actual_receipt_payload") == nil {
		return nil
	}
	return &ReceiptExpectation{TaskID: stringOr(m, "expected_task_id"), Attempt: intMust(m, "expected_attempt"), ReceiptFence: intMust(m, "receipt_fence"), CurrentFence: intMust(m, "current_fence"), Sequence: intMust(m, "sequence"), PredecessorSequence: intMust(m, "predecessor_sequence"), ReceiptDigest: stringOr(m, "receipt_digest"), CustodyDigest: stringOr(m, "custody_digest"), LineageDigest: stringOr(m, "lineage_digest"), VerifiedReferences: parseVerifiedReferences(m["verified_references"])}
}

func parseSettlementExpectation(statusValue any, refsValue any) *SettlementExpectation {
	status := objectFieldFromAny(statusValue)
	if len(status) != 8 {
		return nil
	}
	flags := make(map[string]bool, len(status))
	for _, name := range []string{"committed", "uncontested", "unexpired", "unrevoked", "current_fence", "profile_sufficient", "digest_valid", "budget_bound"} {
		value, ok := boolField(status, name)
		if !ok {
			return nil
		}
		flags[name] = value
	}
	refs := parseVerifiedReferences(refsValue)
	if refs == nil {
		return nil
	}
	return &SettlementExpectation{VerifiedStatus: flags, VerifiedReferences: refs}
}

func evaluateSignedCapability(m map[string]any, vector VectorContext) AF0Result {
	childEnvelope := objectField(m, "child_envelope")
	childBody, childCode := envelopeBody(objectField(childEnvelope, "body"))
	if childCode != OK {
		return AF0Result{Code: childCode}
	}
	result := vectorEnvelopeDerived(childBody, objectField(childEnvelope, "signature"))
	parentEnvelope := objectField(m, "parent_envelope")
	parentBody, code := envelopeBody(objectField(parentEnvelope, "body"))
	if code != OK {
		result.Code = code
		return result
	}
	parentRaw, code := marshalCanonical(map[string]any{"body": parentBody.value(), "signature": objectField(parentEnvelope, "signature")})
	if code != OK {
		result.Code = code
		return result
	}
	if code = VerifyEnvelope(parentRaw, verificationContextForVector(m, vector.Crypto, parentBody)); code != OK && code != NegotiationBindingMismatch {
		result.Code = code
		return result
	}
	parentDigest, code := objectDigest(parentBody)
	if code != OK || parentEnvelope["verified"] != true || stringOr(parentEnvelope, "object_digest") != parentDigest {
		result.Code = ParentReferenceRequired
		return result
	}
	childRaw, code := marshalCanonical(map[string]any{"body": childBody.value(), "signature": objectField(childEnvelope, "signature")})
	if code != OK {
		result.Code = code
		return result
	}
	childContext := verificationContextForVector(m, vector.Crypto, childBody)
	childContext.ParentGrant = &CapabilityGrantEvidence{Digest: parentDigest, Grant: grantWithEnvelope(objectFieldFromAny(parentBody.Payload), parentBody)}
	result.Code = VerifyEnvelope(childRaw, childContext)
	if stringOr(objectFieldFromAny(childBody.Payload), "parent_grant_digest") == "" {
		result.Code = ParentReferenceRequired
		return result
	}
	if result.Code == NegotiationBindingMismatch {
		parentGrant := childContext.ParentGrant.Grant
		childGrant := grantWithEnvelope(objectFieldFromAny(childBody.Payload), childBody)
		if stringOr(childGrant, "subject") != stringOr(parentGrant, "subject") || stringOr(childGrant, "audience") != stringOr(parentGrant, "audience") {
			result.Code = CapabilitySubjectMutation
		} else if attenuationCode := ValidateCapabilityAttenuation(parentGrant, childGrant); attenuationCode != OK {
			result.Code = attenuationCode
		}
	}
	return result
}

func evaluateVectorCustody(m map[string]any) Code {
	facts := objectsFieldStrict(m, "custody_lineage")
	if code := verifyCustodyFacts(facts, parseVerifiedReferences(m["verified_references"])); code != OK {
		return code
	}
	if stringOr(m, "proposed_state") != "executing" {
		return OK
	}
	if code := custodyExecutionCancellation(facts); code != OK {
		return code
	}
	if expiry, ok := stringField(m, "delivery_expiry"); ok {
		verificationTime, timeCode := parseTimestamp(stringOr(m, "verification_time"))
		deliveryExpiry, expiryCode := parseTimestamp(expiry)
		if timeCode != OK || expiryCode != OK {
			return CustodyLineageInvalid
		}
		if code := verifyCustodyExpiry([]CustodyExpiryEvidence{{Kind: "delivery", ExpiresAt: deliveryExpiry, Verified: true}}, verificationTime); code != OK {
			return code
		}
	}
	return validateExecutionAuthority(stringOr(m, "task_id"), intMust(m, "attempt"), stringOr(m, "issuer"), intMust(m, "fence"), parseExecutionAuthority(m["execution_authority"]))
}

func parseExecutionAuthority(value any) ExecutionAuthorityEvidence {
	m := objectFieldFromAny(value)
	if len(m) != 5 || m["verified"] != true {
		return ExecutionAuthorityEvidence{}
	}
	return ExecutionAuthorityEvidence{Verified: true, TaskID: stringOr(m, "task_id"), Attempt: intMust(m, "attempt"), Issuer: stringOr(m, "issuer"), Fence: intMust(m, "fence")}
}

func validateVectorReceipt(m map[string]any) Code {
	expected := parseReceiptExpectation(m)
	if expected == nil {
		return ReceiptFenceViolation
	}
	return ValidateReceiptExpectation(objectField(m, "actual_receipt_payload"), stringOr(m, "actual_receipt_object_digest"), *expected)
}

func intMust(m map[string]any, key string) int64 { v, _ := intField(m, key); return v }

func evaluateVectorSettlement(m map[string]any) AF0Result {
	expected := parseSettlementExpectation(m["verified_status"], m["verified_references"])
	if expected == nil {
		return AF0Result{Code: SettlementRefused}
	}
	code := ValidateSettlementCommit(m, *expected)
	if code != OK {
		return AF0Result{Code: code}
	}
	key, preimage, _ := SettlementIdempotency(stringOr(m, "settlement_authority"), stringOr(m, "fact_kind"), stringOr(m, "committed_fact_digest"))
	if stringOr(m, "idempotency_key") != key {
		return AF0Result{Code: SettlementRefused}
	}
	return AF0Result{Code: OK, IdempotencyPreimageHex: hex.EncodeToString(preimage), IdempotencyKey: key}
}

func agentIDFromSPKI(value string) (string, Code) {
	der, ok := decodeRawBase64URL(value)
	if !ok {
		return "", KeyResolutionFailed
	}
	key, code := parseExactSPKI(value)
	if code != OK {
		return "", code
	}
	reencoded, err := x509.MarshalPKIXPublicKey(key)
	if err != nil || string(der) != string(reencoded) {
		return "", KeyResolutionFailed
	}
	digest := sha256.Sum256(append([]byte("asp-agent-id-v1\x00"), der...))
	return "aid:ed25519:" + base64.RawURLEncoding.EncodeToString(digest[:]), OK
}
