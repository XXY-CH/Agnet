// Package afp implements the AFP v1 AF0 pure-verifier boundary.
package afp

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type Code string

const (
	OK                           Code = "AFP_OK"
	NoncanonicalJSON             Code = "AFP_NONCANONICAL_JSON"
	DuplicateKey                 Code = "AFP_DUPLICATE_KEY"
	TrailingData                 Code = "AFP_TRAILING_DATA"
	InvalidString                Code = "AFP_INVALID_STRING"
	UnknownField                 Code = "AFP_UNKNOWN_FIELD"
	MissingField                 Code = "AFP_MISSING_FIELD"
	UnsupportedVersion           Code = "AFP_UNSUPPORTED_VERSION"
	VersionNegotiationFailed     Code = "AFP_VERSION_NEGOTIATION_FAILED"
	NegotiationRequired          Code = "AFP_NEGOTIATION_REQUIRED"
	InvalidProfile               Code = "AFP_INVALID_PROFILE"
	InvalidRoute                 Code = "AFP_INVALID_ROUTE"
	ProfileDowngradeRejected     Code = "AFP_PROFILE_DOWNGRADE_REJECTED"
	ProfileRetryRejected         Code = "AFP_PROFILE_RETRY_REJECTED"
	NegotiationBindingMismatch   Code = "AFP_NEGOTIATION_BINDING_MISMATCH"
	InvalidKind                  Code = "AFP_INVALID_KIND"
	InvalidTimestamp             Code = "AFP_INVALID_TIMESTAMP"
	TimeOrderInvalid             Code = "AFP_TIME_ORDER_INVALID"
	KeyResolutionFailed          Code = "AFP_KEY_RESOLUTION_FAILED"
	SignatureFormatInvalid       Code = "AFP_SIGNATURE_FORMAT_INVALID"
	SignatureInvalid             Code = "AFP_SIGNATURE_INVALID"
	DigestMismatch               Code = "AFP_DIGEST_MISMATCH"
	ReplayDetected               Code = "AFP_REPLAY_DETECTED"
	ReferenceInvalid             Code = "AFP_REFERENCE_INVALID"
	AuthorityEvidenceRejected    Code = "AFP_AUTHORITY_EVIDENCE_REJECTED"
	ParentReferenceRequired      Code = "AFP_PARENT_REFERENCE_REQUIRED"
	DelegationForbidden          Code = "AFP_DELEGATION_FORBIDDEN"
	CapabilityActionExpansion    Code = "AFP_CAPABILITY_ACTION_EXPANSION"
	CapabilityResourceExpansion  Code = "AFP_CAPABILITY_RESOURCE_EXPANSION"
	CapabilityLimitExpansion     Code = "AFP_CAPABILITY_LIMIT_EXPANSION"
	CapabilityExpiryExpansion    Code = "AFP_CAPABILITY_EXPIRY_EXPANSION"
	CapabilitySubjectMutation    Code = "AFP_CAPABILITY_SUBJECT_MUTATION"
	RevocationProofRejected      Code = "AFP_REVOCATION_PROOF_REJECTED"
	CapabilityIssuerMismatch     Code = "AFP_CAPABILITY_ISSUER_MISMATCH"
	ReceiptAuthorityUnavailable  Code = "AFP_RECEIPT_AUTHORITY_UNAVAILABLE"
	CustodyLineageInvalid        Code = "AFP_CUSTODY_LINEAGE_INVALID"
	CustodyContested             Code = "AFP_CUSTODY_CONTESTED"
	CustodyCancelled             Code = "AFP_CUSTODY_CANCELLED"
	CustodyExpired               Code = "AFP_CUSTODY_EXPIRED"
	CustodyExecutionUnauthorized Code = "AFP_CUSTODY_EXECUTION_UNAUTHORIZED"
	ReceiptFenceViolation        Code = "AFP_RECEIPT_FENCE_VIOLATION"
	SettlementContested          Code = "AFP_SETTLEMENT_CONTESTED"
	SettlementRefused            Code = "AFP_SETTLEMENT_REFUSED"
	UnsupportedSettlementFact    Code = "AFP_UNSUPPORTED_SETTLEMENT_FACT"
	BudgetAuthorizationRequired  Code = "AFP_BUDGET_AUTHORIZATION_REQUIRED"
	RailSemanticsRejected        Code = "AFP_RAIL_SEMANTICS_REJECTED"
	LocalPolicyRequired          Code = "AFP_LOCAL_POLICY_REQUIRED"
	VerificationTimeRequired     Code = "AFP_VERIFICATION_TIME_REQUIRED"
	ASPFrameRejected             Code = "AFP_ASP_FRAME_REJECTED"
	ASPVectorRejected            Code = "AFP_ASP_VECTOR_REJECTED"
	ASPLegacyFieldRejected       Code = "AFP_ASP_LEGACY_FIELD_REJECTED"
)

const protocolVersion = "1.0"

var kinds = map[string]bool{
	"afp.agent-descriptor": true, "afp.capability-advertisement": true,
	"afp.intent-query": true, "afp.offer": true, "afp.capability-grant": true,
	"afp.task-open": true, "afp.task-claim": true, "afp.task-event": true,
	"afp.checkpoint": true, "afp.artifact-manifest": true,
	"afp.mailbox-envelope": true, "afp.custody-receipt": true,
	"afp.receipt-commit": true, "afp.assurance-evidence": true,
	"afp.route-binding": true, "afp.direct-swarm-charter": true,
	"afp.settlement-commit": true,
}

var profiles = map[string]bool{"local": true, "direct": true, "governed": true, "a2a-baseline": true, "a2a-afp": true}
var routes = map[string]bool{"local": true, "direct": true, "relayed": true, "store-forward": true}

// AF0Result contains the single deterministic conformance code and any requested
// derived value. Explicit `*Hex` fields are lowercase hexadecimal strings.
type AF0Result struct {
	Code                   Code
	Canonical              string
	CanonicalBody          string
	SigningPreimageHex     string
	DigestHex              string
	Signature              string
	SelectedVersion        string
	IdempotencyPreimageHex string
	IdempotencyKey         string
	Disposition            string
}

// EnvelopeBody is the fixed AFP v1 signed body. Payload remains a canonical JSON
// object because AF0 does not fetch or execute referenced evidence.
type EnvelopeBody struct {
	Kind        string
	SpecVersion string
	Profile     string
	Issuer      string
	Audience    string
	Nonce       string
	IssuedAt    string
	ExpiresAt   string
	Payload     any
}

// ParseRawCanonicalJSON parses exactly one AFP JSON value and rejects any raw
// representation that differs from AFP canonical bytes.
func ParseRawCanonicalJSON(raw []byte) (any, Code) {
	value, code := parseJSON(raw)
	if code != OK {
		return nil, code
	}
	canonical, code := marshalCanonical(value)
	if code != OK {
		return nil, code
	}
	if !bytes.Equal(raw, canonical) {
		return nil, NoncanonicalJSON
	}
	return value, OK
}

// CanonicalizeJSON validates one JSON value and returns its AFP canonical bytes.
// Unlike ParseRawCanonicalJSON, it permits a noncanonical source representation.
func CanonicalizeJSON(raw []byte) ([]byte, Code) {
	value, code := parseJSON(raw)
	if code != OK {
		return nil, code
	}
	return marshalCanonical(value)
}

// SigningPreimage builds the exact AFP signature preimage for a typed body.
func SigningPreimage(body EnvelopeBody) ([]byte, Code) {
	return bodyPreimage("AFP-SIGNATURE-V1\x00", body)
}

// DigestPreimage builds the exact AFP object-digest preimage for a typed body.
func DigestPreimage(body EnvelopeBody) ([]byte, Code) { return bodyPreimage("AFP-DIGEST-V1\x00", body) }

func bodyPreimage(domain string, body EnvelopeBody) ([]byte, Code) {
	if code := validateBody(body); code != OK {
		return nil, code
	}
	canonical, code := marshalCanonical(body.value())
	if code != OK {
		return nil, code
	}
	preimage := make([]byte, 0, len(domain)+len(body.Kind)+len(body.SpecVersion)+len(body.Profile)+len(canonical)+3)
	preimage = append(preimage, domain...)
	preimage = append(preimage, body.Kind...)
	preimage = append(preimage, 0)
	preimage = append(preimage, body.SpecVersion...)
	preimage = append(preimage, 0)
	preimage = append(preimage, body.Profile...)
	preimage = append(preimage, 0)
	return append(preimage, canonical...), OK
}

func (body EnvelopeBody) value() map[string]any {
	return map[string]any{"kind": body.Kind, "spec_version": body.SpecVersion, "profile": body.Profile,
		"issuer": body.Issuer, "audience": body.Audience, "nonce": body.Nonce,
		"issued_at": body.IssuedAt, "expires_at": body.ExpiresAt, "payload": body.Payload}
}

// VerifyEd25519SPKI verifies a raw unpadded-base64url Ed25519 signature using an
// exact DER SubjectPublicKeyInfo public key, rejecting alternate encodings.
func VerifyEd25519SPKI(spki, signature string, message []byte) Code {
	der, ok := decodeRawBase64URL(spki)
	if !ok {
		return NoncanonicalJSON
	}
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return NoncanonicalJSON
	}
	public, ok := key.(ed25519.PublicKey)
	if !ok || len(public) != ed25519.PublicKeySize {
		return NoncanonicalJSON
	}
	reencoded, err := x509.MarshalPKIXPublicKey(public)
	if err != nil || !bytes.Equal(der, reencoded) {
		return NoncanonicalJSON
	}
	sig, ok := decodeRawBase64URL(signature)
	if !ok || len(sig) != ed25519.SignatureSize || !ed25519.Verify(public, message, sig) {
		return NoncanonicalJSON
	}
	return OK
}

func NegotiateVersions(issuer, peer []string) (string, Code) {
	if len(issuer) == 0 || len(peer) == 0 || hasDuplicate(issuer) || hasDuplicate(peer) {
		return "", VersionNegotiationFailed
	}
	for _, version := range issuer {
		if version == protocolVersion && contains(peer, version) {
			return version, OK
		}
	}
	if hasUnsupportedMajor(issuer) || hasUnsupportedMajor(peer) {
		return "", UnsupportedVersion
	}
	return "", VersionNegotiationFailed
}

// ValidateNegotiatedVersion additionally enforces the exact selected version
// found in both canonical negotiation offers.
func ValidateNegotiatedVersion(issuer, peer []string, selected string) Code {
	version, code := NegotiateVersions(issuer, peer)
	if code != OK || selected != version {
		if code != OK {
			return code
		}
		return VersionNegotiationFailed
	}
	return OK
}

// ValidateProfileRoute enforces the separate AFP authority-profile and route domains.
func ValidateProfileRoute(profile, route, kind string) Code {
	if !profiles[profile] {
		return InvalidProfile
	}
	if route != "" && !routes[route] {
		return InvalidRoute
	}
	if profile == "a2a-baseline" && (kind == "afp.custody-receipt" || kind == "afp.task-claim" || kind == "afp.task-event" || kind == "afp.checkpoint" || kind == "afp.receipt-commit" || kind == "afp.settlement-commit") {
		return ReceiptAuthorityUnavailable
	}
	return OK
}

// ValidateProfileTransition requires distinct, explicit sessions plus a verified
// transcript, route binding, and local policy for every profile change.
func ValidateProfileTransition(current, next string, failed bool, evidence ProfileTransitionEvidence) Code {
	if !profiles[current] || !profiles[next] {
		return InvalidProfile
	}
	if current == next {
		return OK
	}
	if failed && profileStrength(next) < profileStrength(current) {
		return ProfileRetryRejected
	}
	if evidence.PriorSessionID != "" && evidence.SuccessorSessionID != "" && evidence.PriorSessionID != evidence.SuccessorSessionID && evidence.NewTranscriptVerified && evidence.NewRouteBindingVerified && evidence.LocalPolicyVerified {
		return OK
	}
	return ProfileDowngradeRejected
}

func profileStrength(profile string) int {
	switch profile {
	case "local":
		return 0
	case "direct":
		return 1
	case "a2a-baseline":
		return 2
	case "governed", "a2a-afp":
		return 3
	default:
		return -1
	}
}

// ValidateCapabilityAttenuation enforces child grant intersection and strict
// grant shape invariants; verified revocation status is checked by VerifyEnvelope.
func ValidateCapabilityAttenuation(parent, child map[string]any) Code {
	parentRef := stringOr(child, "parent_grant_digest")
	if !validDigest(parentRef) {
		return ParentReferenceRequired
	}
	if !validRevocationProof(objectField(parent, "revocation_proof")) || !validRevocationProof(objectField(child, "revocation_proof")) {
		return RevocationProofRejected
	}
	delegate, ok := boolField(parent, "delegate")
	if !ok || !delegate {
		return DelegationForbidden
	}
	if !subset(stringsField(child, "actions"), stringsField(parent, "actions")) || len(stringsField(child, "actions")) == 0 {
		return CapabilityActionExpansion
	}
	if !subset(stringsField(child, "resources"), stringsField(parent, "resources")) || len(stringsField(child, "resources")) == 0 {
		return CapabilityResourceExpansion
	}
	parentLimits, childLimits := objectField(parent, "limits"), objectField(child, "limits")
	for _, name := range []string{"max_bytes", "max_cost", "max_time_ms"} {
		p, okp := intField(parentLimits, name)
		c, okc := intField(childLimits, name)
		if !okp || !okc || p < 0 || c < 0 || c > p {
			return CapabilityLimitExpansion
		}
	}
	parentExpiry, childExpiry := stringOr(parent, "expires_at"), stringOr(child, "expires_at")
	if parentExpiry != "" || childExpiry != "" {
		parentTime, parentCode := parseTimestamp(parentExpiry)
		childTime, childCode := parseTimestamp(childExpiry)
		if parentExpiry == "" || childExpiry == "" || parentCode != OK || childCode != OK || childTime.After(parentTime) {
			return CapabilityExpiryExpansion
		}
	}
	if stringOr(child, "subject") != stringOr(parent, "subject") || stringOr(child, "audience") != stringOr(parent, "audience") {
		return CapabilitySubjectMutation
	}
	return OK
}

// ValidateCustodyLineage accepts one unbranched custody chain whose successor
// sequence is strictly greater than its predecessor sequence.
func ValidateCustodyLineage(facts []map[string]any, requestedOperation string) Code {
	if len(facts) == 0 {
		return CustodyLineageInvalid
	}
	byDigest := make(map[string]map[string]any, len(facts))
	children := make(map[string]int, len(facts))
	roots := 0
	for _, fact := range facts {
		if len(fact) != 4 {
			return CustodyLineageInvalid
		}
		digest := stringOr(fact, "fact_digest")
		sequence, sequenceOK := intField(fact, "sequence")
		predecessor, hasPredecessor := fact["predecessor_digest"]
		state, stateOK := stringField(fact, "state")
		if !validDigest(digest) || !sequenceOK || sequence <= 0 || !hasPredecessor || !stateOK || !contains([]string{"submitted", "custody-accepted", "delivered", "executing", "completed", "cancelled", "expired"}, state) {
			return CustodyLineageInvalid
		}
		if _, exists := byDigest[digest]; exists {
			return CustodyLineageInvalid
		}
		byDigest[digest] = fact
		if predecessor == nil {
			if sequence != 1 {
				return CustodyLineageInvalid
			}
			roots++
			continue
		}
		predecessorDigest, ok := predecessor.(string)
		if !ok || !validDigest(predecessorDigest) {
			return CustodyLineageInvalid
		}
		children[predecessorDigest]++
	}
	if roots != 1 {
		return CustodyLineageInvalid
	}
	terminals := 0
	for digest, fact := range byDigest {
		predecessor := fact["predecessor_digest"]
		state := stringOr(fact, "state")
		if predecessor != nil {
			parent, exists := byDigest[predecessor.(string)]
			if !exists {
				return CustodyLineageInvalid
			}
			sequence, _ := intField(fact, "sequence")
			parentSequence, _ := intField(parent, "sequence")
			if sequence <= parentSequence {
				return CustodyLineageInvalid
			}
		}
		if children[digest] > 1 {
			return CustodyContested
		}
		if isCustodyTerminal(state) {
			terminals++
			if children[digest] != 0 {
				return CustodyContested
			}
		}
	}
	if terminals > 1 {
		return CustodyContested
	}
	if requestedOperation == "execute" {
		return CustodyExecutionUnauthorized
	}
	return OK
}

// ValidateCustodyExecution authorizes an execution transition only with
// explicit, independently verified evidence bound to the task attempt and
// fence being executed.
func ValidateCustodyExecution(facts []map[string]any, taskID string, attempt int64, issuer string, fence int64, authority ExecutionAuthorityEvidence) Code {
	if code := ValidateCustodyLineage(facts, ""); code != OK {
		return code
	}
	if code := custodyExecutionCancellation(facts); code != OK {
		return code
	}
	return validateExecutionAuthority(taskID, attempt, issuer, fence, authority)
}

func custodyExecutionCancellation(facts []map[string]any) Code {
	for _, fact := range facts {
		switch stringOr(fact, "state") {
		case "cancelled":
			return CustodyCancelled
		case "expired":
			return CustodyExpired
		}
	}
	return OK
}

func validateExecutionAuthority(taskID string, attempt int64, issuer string, fence int64, authority ExecutionAuthorityEvidence) Code {
	if taskID == "" || attempt <= 0 || !isAID(issuer) || fence <= 0 || !authority.Verified || authority.TaskID != taskID || authority.Attempt != attempt || authority.Issuer != issuer || authority.Fence != fence {
		return CustodyExecutionUnauthorized
	}
	return OK
}

func isCustodyTerminal(state string) bool {
	return state == "completed" || state == "cancelled" || state == "expired"
}

// ValidateReceiptFence requires the receipt sequence to be a strict successor.
func ValidateReceiptFence(predecessorSequence, sequence int64) Code {
	if sequence != predecessorSequence+1 {
		return ReceiptFenceViolation
	}
	return OK
}

// SettlementIdempotency builds the exact unpadded-base64url SHA-256 key required
// by the AFP contract.
func SettlementIdempotency(authority, factKind, committedFactDigest string) (string, []byte, Code) {
	if !validSettlementKind(factKind) {
		return "", nil, UnsupportedSettlementFact
	}
	if authority == "" || committedFactDigest == "" {
		return "", nil, BudgetAuthorizationRequired
	}
	preimage := []byte("AFP-SETTLEMENT-IDEMPOTENCY-V1\x00" + authority + "\x00" + factKind + "\x00" + committedFactDigest)
	digest := sha256.Sum256(preimage)
	return base64.RawURLEncoding.EncodeToString(digest[:]), preimage, OK
}

// ValidateSettlementFact is the strict settlement validation entry point.
func ValidateSettlementFact(payload map[string]any, expected SettlementExpectation) Code {
	return ValidateSettlementCommit(payload, expected)
}

func evaluateCanonical(m map[string]any) AF0Result {
	raw, _ := stringField(m, "raw")
	canonical, code := CanonicalizeJSON([]byte(raw))
	if code != OK {
		return AF0Result{Code: code}
	}
	if !bytes.Equal(canonical, []byte(raw)) {
		return AF0Result{Code: NoncanonicalJSON}
	}
	return AF0Result{Code: OK, Canonical: string(canonical)}
}

func evaluateEnvelopeBody(m map[string]any) AF0Result {
	raw, _ := stringField(m, "raw")
	value, code := ParseRawCanonicalJSON([]byte(raw))
	if code != OK {
		return AF0Result{Code: code}
	}
	_, _, code = parseEnvelope(objectFieldFromAny(value))
	return AF0Result{Code: code}
}

func evaluateASPArtifact(m map[string]any) AF0Result {
	if _, ok := stringField(m, "foreign_field_name"); ok {
		return AF0Result{Code: ASPLegacyFieldRejected, Disposition: "ASP_ONLY_REJECT_AS_AFP"}
	}
	family := stringOr(m, "foreign_input_family")
	if strings.Contains(family, "afp:sha256:") {
		return AF0Result{Code: ASPLegacyFieldRejected, Disposition: "ASP_ONLY_REJECT_AS_AFP"}
	}
	if strings.Contains(family, "asp-v") {
		return AF0Result{Code: ASPVectorRejected, Disposition: "ASP_ONLY_REJECT_AS_AFP"}
	}
	return AF0Result{Code: ASPFrameRejected, Disposition: "ASP_ONLY_REJECT_AS_AFP"}
}

func validateBody(body EnvelopeBody) Code {
	if !kinds[body.Kind] || body.SpecVersion != protocolVersion || !profiles[body.Profile] {
		if !profiles[body.Profile] {
			return InvalidProfile
		}
		return UnsupportedVersion
	}
	for _, s := range []string{body.Kind, body.SpecVersion, body.Profile, body.Issuer, body.Audience, body.Nonce, body.IssuedAt, body.ExpiresAt} {
		if s == "" {
			return MissingField
		}
	}
	if _, code := marshalCanonical(body.Payload); code != OK {
		return code
	}
	issued, err := time.Parse("2006-01-02T15:04:05Z", body.IssuedAt)
	if err != nil || issued.Format("2006-01-02T15:04:05Z") != body.IssuedAt {
		return InvalidString
	}
	expires, err := time.Parse("2006-01-02T15:04:05Z", body.ExpiresAt)
	if err != nil || expires.Format("2006-01-02T15:04:05Z") != body.ExpiresAt || !expires.After(issued) {
		return InvalidString
	}
	if _, code := marshalCanonical(body.value()); code != OK {
		return code
	}
	return OK
}

// ValidateEnvelope verifies the full AF0 object catalogue after callers have
// parsed the fixed envelope body. Preimage builders intentionally accept a
// typed body alone, while this verifier rejects unknown or missing nested
// payload fields at the object boundary.
func ValidateEnvelope(body EnvelopeBody) Code {
	if code := validateBodyStrict(body); code != OK {
		return code
	}
	payload, ok := body.Payload.(map[string]any)
	if !ok {
		return InvalidString
	}
	return validatePayloadExact(body, payload)
}

func validatePayloadOwner(body EnvelopeBody, payload map[string]any) Code {
	equalIssuer := map[string]string{"afp.agent-descriptor": "aid", "afp.capability-advertisement": "subject", "afp.intent-query": "requester", "afp.offer": "provider", "afp.task-open": "requester", "afp.task-claim": "owner", "afp.custody-receipt": "custodian", "afp.route-binding": "subject", "afp.settlement-commit": "settlement_authority"}
	if field, constrained := equalIssuer[body.Kind]; constrained && stringOr(payload, field) != body.Issuer {
		return InvalidString
	}
	if body.Kind == "afp.capability-grant" && stringOr(payload, "subject") != body.Audience {
		return InvalidString
	}
	if body.Kind == "afp.mailbox-envelope" && stringOr(payload, "recipient") != body.Audience {
		return InvalidString
	}
	if body.Kind == "afp.assurance-evidence" && (stringOr(payload, "profile") != body.Profile || stringOr(payload, "subject") != body.Audience) {
		return InvalidString
	}
	if body.Kind == "afp.route-binding" && !routes[stringOr(payload, "route")] {
		return InvalidRoute
	}
	return OK
}

var catalogueFields = map[string]map[string]bool{
	"afp.agent-descriptor":         payloadFields("aid", "descriptor_id", "signing_key", "capabilities", "route_hints", "revocation_proof"),
	"afp.capability-advertisement": payloadFields("advertisement_id", "subject", "actions", "resources", "limits", "provenance_digest"),
	"afp.intent-query":             payloadFields("intent_id", "requester", "constraints", "budget", "privacy", "idempotency_key"),
	"afp.offer":                    payloadFields("offer_id", "intent_digest", "provider", "advertisement_digest", "terms", "assurance_digest"),
	"afp.capability-grant":         payloadFields("grant_id", "subject", "actions", "resources", "limits", "delegate", "revocation_proof", "parent_grant_digest"),
	"afp.task-open":                payloadFields("task_id", "requester", "intent_digest", "offer_digest", "grant_digest", "budget_authorization_digest", "idempotency_key", "attempt", "fence"),
	"afp.task-claim":               payloadFields("task_id", "attempt", "claim_id", "owner", "lease", "fence", "sequence", "predecessor_digest"),
	"afp.task-event":               payloadFields("task_id", "attempt", "event_id", "event", "sequence", "predecessor_digest", "fence", "facts", "authority_evidence_digest"),
	"afp.checkpoint":               payloadFields("task_id", "attempt", "checkpoint_id", "state_digest", "sequence", "predecessor_digest", "fence"),
	"afp.artifact-manifest":        payloadFields("artifact_id", "task_id", "attempt", "bytes_digest", "size", "media_type", "recipients", "access_grant_digest"),
	"afp.mailbox-envelope":         payloadFields("mail_id", "route_binding_digest", "recipient", "ciphertext_digest", "delivery_expiry", "task_id"),
	"afp.custody-receipt":          payloadFields("custody_id", "mail_digest", "task_id", "attempt", "state", "sequence", "predecessor_digest", "custodian"),
	"afp.receipt-commit":           payloadFields("receipt_id", "task_id", "attempt", "terminal", "fence", "lineage_digest", "artifact_manifest_digests", "verification_digest", "authority_evidence_digest"),
	"afp.assurance-evidence":       payloadFields("assurance_id", "subject", "profile", "claim", "evidence_digest", "scope"),
	"afp.route-binding":            payloadFields("route_id", "subject", "route", "peer", "negotiation_digest", "route_context_digest"),
	"afp.direct-swarm-charter":     payloadFields("charter_id", "swarm_id", "members", "authority_rule", "task_digests", "fence_rule", "expiry"),
	"afp.settlement-commit":        payloadFields("settlement_id", "settlement_authority", "fact_kind", "committed_fact_digest", "budget_authorization_digest", "receipt_or_custody_digest", "idempotency_key"),
}

func payloadFields(names ...string) map[string]bool {
	result := make(map[string]bool, len(names))
	for _, name := range names {
		result[name] = true
	}
	return result
}

func validDigest(value any) bool {
	text, ok := value.(string)
	if !ok {
		return false
	}
	decoded, ok := decodeRawBase64URL(text)
	return ok && len(decoded) == sha256.Size
}

func validateBodyMap(value any) Code {
	m, ok := value.(map[string]any)
	if !ok {
		return NoncanonicalJSON
	}
	_, code := envelopeBody(m)
	return code
}

func envelopeBody(m map[string]any) (EnvelopeBody, Code) {
	fields := map[string]bool{"kind": true, "spec_version": true, "profile": true, "issuer": true, "audience": true, "nonce": true, "issued_at": true, "expires_at": true, "payload": true}
	for key := range m {
		if !fields[key] {
			return EnvelopeBody{}, UnknownField
		}
	}
	for key := range fields {
		if _, exists := m[key]; !exists {
			return EnvelopeBody{}, MissingField
		}
	}
	payload, ok := m["payload"].(map[string]any)
	if !ok {
		return EnvelopeBody{}, NoncanonicalJSON
	}
	body := EnvelopeBody{stringOr(m, "kind"), stringOr(m, "spec_version"), stringOr(m, "profile"), stringOr(m, "issuer"), stringOr(m, "audience"), stringOr(m, "nonce"), stringOr(m, "issued_at"), stringOr(m, "expires_at"), payload}
	return body, OK
}

func parseJSON(raw []byte) (any, Code) {
	p := jsonParser{raw: raw}
	p.skipSpace()
	value, code := p.value()
	if code != OK {
		return nil, code
	}
	p.skipSpace()
	if p.index != len(p.raw) {
		return nil, TrailingData
	}
	return value, OK
}

type jsonParser struct {
	raw   []byte
	index int
}

func (p *jsonParser) skipSpace() {
	for p.index < len(p.raw) && (p.raw[p.index] == ' ' || p.raw[p.index] == '\n' || p.raw[p.index] == '\r' || p.raw[p.index] == '\t') {
		p.index++
	}
}
func (p *jsonParser) value() (any, Code) {
	if p.index >= len(p.raw) {
		return nil, NoncanonicalJSON
	}
	switch p.raw[p.index] {
	case '{':
		return p.object()
	case '[':
		return p.array()
	case '"':
		return p.string()
	case 't':
		if p.literal("true") {
			return true, OK
		}
	case 'f':
		if p.literal("false") {
			return false, OK
		}
	case 'n':
		if p.literal("null") {
			return nil, OK
		}
	default:
		if p.raw[p.index] == '-' || (p.raw[p.index] >= '0' && p.raw[p.index] <= '9') {
			return p.number()
		}
	}
	return nil, NoncanonicalJSON
}
func (p *jsonParser) literal(literal string) bool {
	if strings.HasPrefix(string(p.raw[p.index:]), literal) {
		p.index += len(literal)
		return true
	}
	return false
}
func (p *jsonParser) object() (any, Code) {
	p.index++
	p.skipSpace()
	object := map[string]any{}
	if p.index < len(p.raw) && p.raw[p.index] == '}' {
		p.index++
		return object, OK
	}
	for {
		p.skipSpace()
		keyValue, code := p.string()
		if code != OK {
			return nil, code
		}
		key := keyValue.(string)
		if _, exists := object[key]; exists {
			return nil, DuplicateKey
		}
		p.skipSpace()
		if p.index >= len(p.raw) || p.raw[p.index] != ':' {
			return nil, NoncanonicalJSON
		}
		p.index++
		p.skipSpace()
		value, code := p.value()
		if code != OK {
			return nil, code
		}
		object[key] = value
		p.skipSpace()
		if p.index >= len(p.raw) {
			return nil, NoncanonicalJSON
		}
		if p.raw[p.index] == '}' {
			p.index++
			return object, OK
		}
		if p.raw[p.index] != ',' {
			return nil, NoncanonicalJSON
		}
		p.index++
	}
}
func (p *jsonParser) array() (any, Code) {
	p.index++
	p.skipSpace()
	array := []any{}
	if p.index < len(p.raw) && p.raw[p.index] == ']' {
		p.index++
		return array, OK
	}
	for {
		p.skipSpace()
		value, code := p.value()
		if code != OK {
			return nil, code
		}
		array = append(array, value)
		p.skipSpace()
		if p.index >= len(p.raw) {
			return nil, NoncanonicalJSON
		}
		if p.raw[p.index] == ']' {
			p.index++
			return array, OK
		}
		if p.raw[p.index] != ',' {
			return nil, NoncanonicalJSON
		}
		p.index++
	}
}
func (p *jsonParser) string() (any, Code) {
	if p.index >= len(p.raw) || p.raw[p.index] != '"' {
		return nil, NoncanonicalJSON
	}
	p.index++
	var b strings.Builder
	for p.index < len(p.raw) {
		ch := p.raw[p.index]
		if ch == '"' {
			p.index++
			value := b.String()
			if invalidAFPString(value) {
				return nil, InvalidString
			}
			return value, OK
		}
		if ch < 0x20 {
			return nil, InvalidString
		}
		if ch == '\\' {
			p.index++
			if p.index >= len(p.raw) {
				return nil, InvalidString
			}
			escape := p.raw[p.index]
			p.index++
			switch escape {
			case '"', '\\', '/':
				b.WriteByte(map[byte]byte{'"': '"', '\\': '\\', '/': '/'}[escape])
			case 'b':
				b.WriteByte('\b')
			case 'f':
				b.WriteByte('\f')
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			case 'u':
				r, ok := p.hexRune()
				if !ok {
					return nil, InvalidString
				}
				if r >= 0xD800 && r <= 0xDBFF {
					if p.index+2 > len(p.raw) || p.raw[p.index] != '\\' || p.raw[p.index+1] != 'u' {
						return nil, InvalidString
					}
					p.index += 2
					low, ok := p.hexRune()
					if !ok || low < 0xDC00 || low > 0xDFFF {
						return nil, InvalidString
					}
					r = 0x10000 + (r-0xD800)*0x400 + (low - 0xDC00)
				} else if r >= 0xDC00 && r <= 0xDFFF {
					return nil, InvalidString
				}
				b.WriteRune(r)
			default:
				return nil, InvalidString
			}
			continue
		}
		r, width := utf8.DecodeRune(p.raw[p.index:])
		if r == utf8.RuneError && width == 1 {
			return nil, InvalidString
		}
		b.WriteRune(r)
		p.index += width
	}
	return nil, InvalidString
}
func (p *jsonParser) hexRune() (rune, bool) {
	if p.index+4 > len(p.raw) {
		return 0, false
	}
	number, err := strconv.ParseUint(string(p.raw[p.index:p.index+4]), 16, 16)
	p.index += 4
	return rune(number), err == nil
}
func (p *jsonParser) number() (any, Code) {
	start := p.index
	if p.raw[p.index] == '-' {
		p.index++
		if p.index >= len(p.raw) {
			return nil, NoncanonicalJSON
		}
	}
	if p.raw[p.index] == '0' {
		p.index++
	} else if p.raw[p.index] >= '1' && p.raw[p.index] <= '9' {
		for p.index < len(p.raw) && p.raw[p.index] >= '0' && p.raw[p.index] <= '9' {
			p.index++
		}
	} else {
		return nil, NoncanonicalJSON
	}
	if p.index < len(p.raw) && (p.raw[p.index] == '.' || p.raw[p.index] == 'e' || p.raw[p.index] == 'E') {
		return nil, NoncanonicalJSON
	}
	text := string(p.raw[start:p.index])
	if text == "-0" {
		return nil, NoncanonicalJSON
	}
	number, err := strconv.ParseInt(text, 10, 64)
	if err != nil || number < -9007199254740991 || number > 9007199254740991 {
		return nil, NoncanonicalJSON
	}
	return number, OK
}

func marshalCanonical(value any) ([]byte, Code) {
	var b bytes.Buffer
	if code := appendCanonical(&b, value); code != OK {
		return nil, code
	}
	return b.Bytes(), OK
}
func appendCanonical(b *bytes.Buffer, value any) Code {
	switch v := value.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if v {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		if invalidAFPString(v) {
			return InvalidString
		}
		appendJSONString(b, v)
	case int64:
		if v < -9007199254740991 || v > 9007199254740991 {
			return NoncanonicalJSON
		}
		b.WriteString(strconv.FormatInt(v, 10))
	case int:
		return appendCanonical(b, int64(v))
	case []any:
		b.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				b.WriteByte(',')
			}
			if code := appendCanonical(b, item); code != OK {
				return code
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			if invalidAFPString(key) {
				return InvalidString
			}
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool { return bytes.Compare([]byte(keys[i]), []byte(keys[j])) < 0 })
		b.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			appendJSONString(b, key)
			b.WriteByte(':')
			if code := appendCanonical(b, v[key]); code != OK {
				return code
			}
		}
		b.WriteByte('}')
	default:
		return NoncanonicalJSON
	}
	return OK
}
func appendJSONString(b *bytes.Buffer, value string) {
	b.WriteByte('"')
	for _, r := range value {
		switch r {
		case '"':
			b.WriteString("\\\"")
		case '\\':
			b.WriteString("\\\\")
		case '\b':
			b.WriteString("\\b")
		case '\f':
			b.WriteString("\\f")
		case '\n':
			b.WriteString("\\n")
		case '\r':
			b.WriteString("\\r")
		case '\t':
			b.WriteString("\\t")
		default:
			if r < 0x20 {
				b.WriteString("\\u00")
				b.WriteString(hex.EncodeToString([]byte{byte(r)}))
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}
func invalidAFPString(value string) bool {
	if !utf8.ValidString(value) {
		return true
	}
	for _, r := range value {
		if r == 0x2028 || r == 0x2029 || (r >= 0xD800 && r <= 0xDFFF) {
			return true
		}
	}
	return false
}

func decodeRawBase64URL(value string) ([]byte, bool) {
	if value == "" || strings.ContainsAny(value, "= \t\r\n") {
		return nil, false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, false
	}
	return decoded, true
}
func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
func hasUnsupportedMajor(values []string) bool {
	for _, version := range values {
		if strings.SplitN(version, ".", 2)[0] != "1" {
			return true
		}
	}
	return false
}

func hasDuplicate(values []string) bool {
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		if seen[value] {
			return true
		}
		seen[value] = true
	}
	return false
}
func validSettlementKind(kind string) bool {
	return kind == "custody" || kind == "storage" || kind == "execution" || kind == "verification"
}
func stringField(m map[string]any, field string) (string, bool) {
	value, ok := m[field]
	if !ok {
		return "", false
	}
	s, ok := value.(string)
	return s, ok
}
func stringOr(m map[string]any, field string) string { value, _ := stringField(m, field); return value }
func boolField(m map[string]any, field string) (bool, bool) {
	value, ok := m[field]
	if !ok {
		return false, false
	}
	b, ok := value.(bool)
	return b, ok
}
func intField(m map[string]any, field string) (int64, bool) {
	value, ok := m[field]
	if !ok {
		return 0, false
	}
	number, ok := value.(int64)
	return number, ok
}
func stringsField(m map[string]any, field string) []string {
	values, ok := m[field].([]any)
	if !ok {
		return nil
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		s, ok := value.(string)
		if !ok {
			return nil
		}
		result = append(result, s)
	}
	return result
}
func objectField(m map[string]any, field string) map[string]any {
	value, _ := m[field].(map[string]any)
	return value
}
func objectsField(m map[string]any, field string) []map[string]any {
	values, _ := m[field].([]any)
	result := make([]map[string]any, 0, len(values))
	for _, value := range values {
		if object, ok := value.(map[string]any); ok {
			result = append(result, object)
		}
	}
	return result
}
func subset(child, parent []string) bool {
	for _, item := range child {
		if !contains(parent, item) {
			return false
		}
	}
	return true
}
