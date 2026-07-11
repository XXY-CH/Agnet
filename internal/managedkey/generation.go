package managedkey

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
)

const (
	GenerationFormat          = "agnet-key-generation/v1"
	GenerationRebindingFormat = "agnet-key-generation-rebinding/v1"
	GenerationMigrate         = "migrate"
	GenerationRewrap          = "rewrap"
	GenerationRotate          = "rotate"
	generationActive          = "active"
)

var generationZeroDigest = string(bytes.Repeat([]byte{'0'}, 64))

type GenerationBody struct {
	Format               string `json:"format"`
	IdentityKind         string `json:"identity_kind"`
	IdentityValue        string `json:"identity_value"`
	Generation           int    `json:"generation"`
	Operation            string `json:"operation"`
	EnvelopeSHA256       string `json:"envelope_sha256"`
	DescriptorDigest     string `json:"descriptor_digest"`
	PreviousGeneration   int    `json:"previous_generation"`
	PreviousRecordDigest string `json:"previous_record_digest"`
	ActivationState      string `json:"activation_state"`
}

type GenerationRecord struct {
	Body                GenerationBody `json:"body"`
	RecordDigest        string         `json:"record_digest"`
	IdentitySignature   string         `json:"identity_signature,omitempty"`
	PreviousDescriptor  map[string]any `json:"previous_descriptor,omitempty"`
	NextDescriptor      map[string]any `json:"next_descriptor,omitempty"`
	AgentRotationProof  map[string]any `json:"agent_rotation_proof,omitempty"`
	GenerationRebinding map[string]any `json:"generation_rebinding,omitempty"`
}

type GenerationBodyOptions struct {
	Identity        Identity
	Generation      int
	Operation       string
	EnvelopeBytes   []byte
	Descriptor      map[string]any
	PreviousRecord  *GenerationRecord
	ActivationState string
}

type GenerationPointer struct {
	Generation   int    `json:"generation"`
	RecordDigest string `json:"record_digest"`
}

type GenerationVerificationContext struct {
	EnvelopeBytes      []byte
	Descriptor         map[string]any
	PreviousRecord     *GenerationRecord
	PreviousDescriptor map[string]any
	ZoneDescriptor     map[string]any
	ActivePointer      *GenerationPointer
}

type GenerationChainContext struct {
	Descriptors         []map[string]any
	PreviousDescriptors []map[string]any
	ZoneDescriptors     []map[string]any
	ActivePointer       *GenerationPointer
}

type GenerationRebindingContext struct {
	ZoneDescriptor     map[string]any
	PreviousDescriptor map[string]any
	NextDescriptor     map[string]any
	Generation         int
	RecordDigest       string
}

func digestCanonical(value any) (string, error) {
	data, err := canonicalJSON(value)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

func generationBodyMap(body GenerationBody) map[string]any {
	return map[string]any{
		"format":                 body.Format,
		"identity_kind":          body.IdentityKind,
		"identity_value":         body.IdentityValue,
		"generation":             body.Generation,
		"operation":              body.Operation,
		"envelope_sha256":        body.EnvelopeSHA256,
		"descriptor_digest":      body.DescriptorDigest,
		"previous_generation":    body.PreviousGeneration,
		"previous_record_digest": body.PreviousRecordDigest,
		"activation_state":       body.ActivationState,
	}
}

func validateGenerationBody(body GenerationBody) error {
	if body.Format != GenerationFormat {
		return errors.New("generation format invalid")
	}
	if err := validateIdentity(Identity{Kind: body.IdentityKind, Value: body.IdentityValue}); err != nil {
		return err
	}
	if body.Generation < 1 {
		return errors.New("generation invalid")
	}
	if body.Operation != GenerationMigrate && body.Operation != GenerationRewrap && body.Operation != GenerationRotate {
		return errors.New("generation operation invalid")
	}
	if !isGenerationDigest(body.EnvelopeSHA256) {
		return errors.New("generation envelope digest invalid")
	}
	if !isGenerationDigest(body.DescriptorDigest) {
		return errors.New("generation descriptor digest invalid")
	}
	if body.PreviousGeneration < 0 {
		return errors.New("previous generation invalid")
	}
	if !isGenerationDigest(body.PreviousRecordDigest) {
		return errors.New("previous record digest invalid")
	}
	if body.ActivationState != generationActive {
		return errors.New("generation activation state invalid")
	}
	return nil
}

func isGenerationDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

func RecordDigest(body GenerationBody) string {
	if err := validateGenerationBody(body); err != nil {
		return ""
	}
	digest, _ := digestCanonical(generationBodyMap(body))
	return digest
}

func descriptorPublicKey(descriptor map[string]any, identity Identity) (ed25519.PublicKey, error) {
	encoded, ok := descriptor["public_key_spki"].(string)
	if !ok {
		return nil, errors.New("generation descriptor public key missing")
	}
	der, err := decodeBase64URLExact(encoded, "generation descriptor public key")
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	publicKey, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("generation descriptor key is not Ed25519")
	}
	actual := generationIdentityValueFromSPKI(identity.Kind, der)
	if actual != identity.Value {
		return nil, errors.New("generation descriptor identity mismatch")
	}
	identityField := "aid"
	signatureField := "descriptor_signature"
	if identity.Kind == IdentityZID {
		identityField = "zid"
		signatureField = "zone_signature"
	}
	if descriptor[identityField] != identity.Value {
		return nil, errors.New("generation descriptor identity mismatch")
	}
	signature, ok := descriptor[signatureField].(string)
	if !ok {
		return nil, errors.New("generation descriptor signature missing")
	}
	body := cloneGenerationMap(descriptor)
	delete(body, signatureField)
	if err := verifyGenerationSignature(publicKey, body, signature); err != nil {
		return nil, errors.New("generation descriptor signature invalid")
	}
	return publicKey, nil
}

func generationIdentityValueFromSPKI(kind string, spki []byte) string {
	domain := "asp-agent-id-v1\x00"
	prefix := "aid:ed25519:"
	if kind == IdentityZID {
		domain = "asp-zone-id-v1\x00"
		prefix = "zid:ed25519:"
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(domain))
	_, _ = hash.Write(spki)
	return prefix + base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
}

func cloneGenerationMap(value map[string]any) map[string]any {
	data, err := canonicalJSON(value)
	if err != nil {
		return nil
	}
	decoded, err := decodeExactJSON(data)
	if err != nil {
		return nil
	}
	clone, _ := decoded.(map[string]any)
	return clone
}

func BuildGenerationBody(options GenerationBodyOptions) (GenerationBody, error) {
	var zero GenerationBody
	if options.Generation < 1 {
		return zero, errors.New("generation invalid")
	}
	if options.Operation != GenerationMigrate && options.Operation != GenerationRewrap && options.Operation != GenerationRotate {
		return zero, errors.New("generation operation invalid")
	}
	if err := validateIdentity(options.Identity); err != nil {
		return zero, err
	}
	envelope, err := ParseEnvelope(options.EnvelopeBytes)
	if err != nil {
		return zero, err
	}
	if envelope.Identity != options.Identity {
		return zero, errors.New("envelope identity mismatch")
	}
	if _, err := descriptorPublicKey(options.Descriptor, options.Identity); err != nil {
		return zero, err
	}
	if options.Generation == 1 {
		if options.Operation != GenerationMigrate || options.PreviousRecord != nil {
			return zero, errors.New("first generation must migrate")
		}
	} else {
		if options.Operation == GenerationMigrate || options.PreviousRecord == nil {
			return zero, errors.New("generation predecessor missing")
		}
		if options.PreviousRecord.Body.Generation+1 != options.Generation {
			return zero, errors.New("generation must be contiguous")
		}
	}
	envelopeHash := sha256.Sum256(options.EnvelopeBytes)
	descriptorDigest, err := digestCanonical(options.Descriptor)
	if err != nil {
		return zero, err
	}
	activationState := options.ActivationState
	if activationState == "" {
		activationState = generationActive
	}
	body := GenerationBody{
		Format: GenerationFormat, IdentityKind: options.Identity.Kind, IdentityValue: options.Identity.Value,
		Generation: options.Generation, Operation: options.Operation, EnvelopeSHA256: hex.EncodeToString(envelopeHash[:]), DescriptorDigest: descriptorDigest,
		PreviousGeneration: 0, PreviousRecordDigest: generationZeroDigest, ActivationState: activationState,
	}
	if options.PreviousRecord != nil {
		body.PreviousGeneration = options.PreviousRecord.Body.Generation
		body.PreviousRecordDigest = options.PreviousRecord.RecordDigest
	}
	if err := validateGenerationBody(body); err != nil {
		return zero, err
	}
	return body, nil
}

func generationSignaturePayload(body GenerationBody, digest string) map[string]any {
	return map[string]any{"body": generationBodyMap(body), "record_digest": digest}
}

func signGenerationValue(key ed25519.PrivateKey, value any) (string, error) {
	data, err := canonicalJSON(value)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, data)), nil
}

func verifyGenerationSignature(key ed25519.PublicKey, value any, encoded string) error {
	signature, err := decodeBase64URLExact(encoded, "generation signature")
	if err != nil {
		return err
	}
	if len(signature) != ed25519.SignatureSize {
		return errors.New("generation signature length invalid")
	}
	data, err := canonicalJSON(value)
	if err != nil {
		return err
	}
	if !ed25519.Verify(key, data, signature) {
		return errors.New("generation signature invalid")
	}
	return nil
}

func NewSignedGenerationRecord(body GenerationBody, privateKey ed25519.PrivateKey) (GenerationRecord, error) {
	var zero GenerationRecord
	if err := validateGenerationBody(body); err != nil {
		return zero, err
	}
	if body.Operation == GenerationRotate {
		return zero, errors.New("rotate generation requires rotation authorization")
	}
	digest := RecordDigest(body)
	signature, err := signGenerationValue(privateKey, generationSignaturePayload(body, digest))
	if err != nil {
		return zero, err
	}
	return GenerationRecord{Body: body, RecordDigest: digest, IdentitySignature: signature}, nil
}

func generationRotationBody(previousDescriptor, nextDescriptor map[string]any) map[string]any {
	return map[string]any{"previous_aid": previousDescriptor["aid"], "next_aid": nextDescriptor["aid"]}
}

func newAgentRotationProof(previousDescriptor, nextDescriptor map[string]any, previousKey, nextKey ed25519.PrivateKey) (map[string]any, error) {
	body := generationRotationBody(previousDescriptor, nextDescriptor)
	previousSignature, err := signGenerationValue(previousKey, body)
	if err != nil {
		return nil, err
	}
	nextSignature, err := signGenerationValue(nextKey, body)
	if err != nil {
		return nil, err
	}
	return map[string]any{"previous_aid": body["previous_aid"], "next_aid": body["next_aid"], "previous_signature": previousSignature, "next_signature": nextSignature}, nil
}

func generationRebindingBody(context GenerationRebindingContext) (map[string]any, error) {
	alias, ok := context.PreviousDescriptor["alias"].(string)
	if !ok || alias == "" || context.NextDescriptor["alias"] != alias {
		return nil, errors.New("generation rebinding requires matching aliases")
	}
	return map[string]any{
		"format": GenerationRebindingFormat, "zone": context.ZoneDescriptor["zid"], "alias": alias,
		"previous_aid": context.PreviousDescriptor["aid"], "next_aid": context.NextDescriptor["aid"],
		"generation": context.Generation, "record_digest": context.RecordDigest,
	}, nil
}

func NewRotationGenerationRecord(body GenerationBody, previousDescriptor, nextDescriptor map[string]any, previousKey, nextKey ed25519.PrivateKey, zoneDescriptor map[string]any, zoneKey ed25519.PrivateKey) (GenerationRecord, error) {
	var zero GenerationRecord
	if err := validateGenerationBody(body); err != nil {
		return zero, err
	}
	if body.Operation != GenerationRotate || body.IdentityKind != IdentityAID || body.IdentityValue != nextDescriptor["aid"] {
		return zero, errors.New("rotate generation identity mismatch")
	}
	digest := RecordDigest(body)
	rotationProof, err := newAgentRotationProof(previousDescriptor, nextDescriptor, previousKey, nextKey)
	if err != nil {
		return zero, err
	}
	context := GenerationRebindingContext{ZoneDescriptor: zoneDescriptor, PreviousDescriptor: previousDescriptor, NextDescriptor: nextDescriptor, Generation: body.Generation, RecordDigest: digest}
	rebindingBody, err := generationRebindingBody(context)
	if err != nil {
		return zero, err
	}
	zoneSignature, err := signGenerationValue(zoneKey, rebindingBody)
	if err != nil {
		return zero, err
	}
	rebinding := cloneGenerationMap(rebindingBody)
	rebinding["zone_signature"] = zoneSignature
	return GenerationRecord{Body: body, RecordDigest: digest, PreviousDescriptor: cloneGenerationMap(previousDescriptor), NextDescriptor: cloneGenerationMap(nextDescriptor), AgentRotationProof: rotationProof, GenerationRebinding: rebinding}, nil
}

func generationBodyFromMap(value any) (GenerationBody, error) {
	var zero GenerationBody
	object, err := exactObject(value, []string{"format", "identity_kind", "identity_value", "generation", "operation", "envelope_sha256", "descriptor_digest", "previous_generation", "previous_record_digest", "activation_state"}, "generation body")
	if err != nil {
		return zero, err
	}
	body := GenerationBody{}
	body.Format, err = exactString(object["format"], "generation format")
	if err != nil {
		return zero, err
	}
	body.IdentityKind, err = exactString(object["identity_kind"], "generation identity kind")
	if err != nil {
		return zero, err
	}
	body.IdentityValue, err = exactString(object["identity_value"], "generation identity value")
	if err != nil {
		return zero, err
	}
	body.Generation, err = exactInteger(object["generation"], "generation")
	if err != nil {
		return zero, errors.New("generation invalid")
	}
	body.Operation, err = exactString(object["operation"], "generation operation")
	if err != nil {
		return zero, err
	}
	body.EnvelopeSHA256, err = exactString(object["envelope_sha256"], "generation envelope digest")
	if err != nil {
		return zero, err
	}
	body.DescriptorDigest, err = exactString(object["descriptor_digest"], "generation descriptor digest")
	if err != nil {
		return zero, err
	}
	body.PreviousGeneration, err = exactInteger(object["previous_generation"], "previous generation")
	if err != nil {
		return zero, err
	}
	body.PreviousRecordDigest, err = exactString(object["previous_record_digest"], "previous record digest")
	if err != nil {
		return zero, err
	}
	body.ActivationState, err = exactString(object["activation_state"], "generation activation state")
	if err != nil {
		return zero, err
	}
	if err := validateGenerationBody(body); err != nil {
		return zero, err
	}
	return body, nil
}

func parseExactGenerationMap(value any, fields []string, label string) (map[string]any, error) {
	object, err := exactObject(value, fields, label)
	if err != nil {
		return nil, err
	}
	return cloneGenerationMap(object), nil
}

func ParseGenerationRecord(data []byte) (GenerationRecord, error) {
	var zero GenerationRecord
	decoded, err := decodeExactJSON(data)
	if err != nil {
		return zero, err
	}
	root, ok := decoded.(map[string]any)
	if !ok {
		return zero, errors.New("generation record fields invalid")
	}
	body, err := generationBodyFromMap(root["body"])
	if err != nil {
		return zero, err
	}
	recordDigest, err := exactString(root["record_digest"], "record digest")
	if err != nil || !isGenerationDigest(recordDigest) {
		return zero, errors.New("record digest invalid")
	}
	if body.Operation != GenerationRotate {
		if _, err := exactObject(root, []string{"body", "record_digest", "identity_signature"}, "generation record"); err != nil {
			return zero, err
		}
		identitySignature, err := exactString(root["identity_signature"], "generation identity signature")
		if err != nil {
			return zero, err
		}
		if _, err := decodeBase64URLExact(identitySignature, "generation identity signature"); err != nil {
			return zero, err
		}
		return GenerationRecord{Body: body, RecordDigest: recordDigest, IdentitySignature: identitySignature}, nil
	}
	if _, err := exactObject(root, []string{"body", "record_digest", "previous_descriptor", "next_descriptor", "agent_rotation_proof", "generation_rebinding"}, "generation record"); err != nil {
		return zero, err
	}
	previousDescriptor, err := parseExactGenerationMap(root["previous_descriptor"], generationDescriptorFields(root["previous_descriptor"], false), "previous descriptor")
	if err != nil {
		return zero, err
	}
	nextDescriptor, err := parseExactGenerationMap(root["next_descriptor"], generationDescriptorFields(root["next_descriptor"], false), "next descriptor")
	if err != nil {
		return zero, err
	}
	rotationProof, err := parseExactGenerationMap(root["agent_rotation_proof"], []string{"previous_aid", "next_aid", "previous_signature", "next_signature"}, "agent rotation proof")
	if err != nil {
		return zero, err
	}
	rebinding, err := parseExactGenerationMap(root["generation_rebinding"], []string{"format", "zone", "alias", "previous_aid", "next_aid", "generation", "record_digest", "zone_signature"}, "generation rebinding")
	if err != nil {
		return zero, err
	}
	return GenerationRecord{Body: body, RecordDigest: recordDigest, PreviousDescriptor: previousDescriptor, NextDescriptor: nextDescriptor, AgentRotationProof: rotationProof, GenerationRebinding: rebinding}, nil
}

func generationDescriptorFields(value any, zone bool) []string {
	object, _ := value.(map[string]any)
	fields := make([]string, 0, len(object))
	for field := range object {
		fields = append(fields, field)
	}
	return fields
}

func generationRecordMap(record GenerationRecord) map[string]any {
	value := map[string]any{"body": generationBodyMap(record.Body), "record_digest": record.RecordDigest}
	if record.Body.Operation == GenerationRotate {
		value["previous_descriptor"] = record.PreviousDescriptor
		value["next_descriptor"] = record.NextDescriptor
		value["agent_rotation_proof"] = record.AgentRotationProof
		value["generation_rebinding"] = record.GenerationRebinding
	} else {
		value["identity_signature"] = record.IdentitySignature
	}
	return value
}

func CanonicalGenerationRecord(record GenerationRecord) ([]byte, error) {
	return canonicalJSON(generationRecordMap(record))
}

func verifyAgentRotationProof(proof, previousDescriptor, nextDescriptor map[string]any) error {
	if _, err := exactObject(proof, []string{"previous_aid", "next_aid", "previous_signature", "next_signature"}, "agent rotation proof"); err != nil {
		return err
	}
	previousIdentity, ok := previousDescriptor["aid"].(string)
	if !ok {
		return errors.New("rotation previous aid missing")
	}
	nextIdentity, ok := nextDescriptor["aid"].(string)
	if !ok {
		return errors.New("rotation next aid missing")
	}
	previousAID, err := exactString(proof["previous_aid"], "rotation proof previous aid")
	if err != nil {
		return err
	}
	nextAID, err := exactString(proof["next_aid"], "rotation proof next aid")
	if err != nil {
		return err
	}
	if previousAID != previousIdentity || nextAID != nextIdentity {
		return errors.New("rotation proof aid mismatch")
	}
	previousSignature, err := exactString(proof["previous_signature"], "rotation proof previous signature")
	if err != nil {
		return err
	}
	nextSignature, err := exactString(proof["next_signature"], "rotation proof next signature")
	if err != nil {
		return err
	}
	previousKey, err := descriptorPublicKey(previousDescriptor, Identity{Kind: IdentityAID, Value: previousIdentity})
	if err != nil {
		return err
	}
	nextKey, err := descriptorPublicKey(nextDescriptor, Identity{Kind: IdentityAID, Value: nextIdentity})
	if err != nil {
		return err
	}
	body := generationRotationBody(previousDescriptor, nextDescriptor)
	if err := verifyGenerationSignature(previousKey, body, previousSignature); err != nil {
		return err
	}
	return verifyGenerationSignature(nextKey, body, nextSignature)
}
func VerifyGenerationRebinding(proof map[string]any, context GenerationRebindingContext) error {
	if _, err := exactObject(proof, []string{"format", "zone", "alias", "previous_aid", "next_aid", "generation", "record_digest", "zone_signature"}, "generation rebinding"); err != nil {
		return err
	}
	if proof["format"] != GenerationRebindingFormat {
		return errors.New("generation rebinding format invalid")
	}
	body, err := generationRebindingBody(context)
	if err != nil {
		return err
	}
	actualBody := make(map[string]any, len(body))
	for name := range body {
		actualBody[name] = proof[name]
	}
	if !generationMapsEqual(actualBody, body) {
		return errors.New("generation rebinding body mismatch")
	}
	zoneIdentity, ok := context.ZoneDescriptor["zid"].(string)
	if !ok {
		return errors.New("generation rebinding zone missing")
	}
	zoneKey, err := descriptorPublicKey(context.ZoneDescriptor, Identity{Kind: IdentityZID, Value: zoneIdentity})
	if err != nil {
		return err
	}
	signature, ok := proof["zone_signature"].(string)
	if !ok {
		return errors.New("generation rebinding signature missing")
	}
	return verifyGenerationSignature(zoneKey, body, signature)
}

func VerifyGenerationRecord(record GenerationRecord, context GenerationVerificationContext) (GenerationRecord, error) {
	var zero GenerationRecord
	canonicalRecord, err := CanonicalGenerationRecord(record)
	if err != nil {
		return zero, err
	}
	normalized, err := ParseGenerationRecord(canonicalRecord)
	if err != nil {
		return zero, err
	}
	if RecordDigest(normalized.Body) != normalized.RecordDigest {
		return zero, errors.New("record digest mismatch")
	}
	envelopeHash := sha256.Sum256(context.EnvelopeBytes)
	if hex.EncodeToString(envelopeHash[:]) != normalized.Body.EnvelopeSHA256 {
		return zero, errors.New("generation envelope digest mismatch")
	}
	envelope, err := ParseEnvelope(context.EnvelopeBytes)
	if err != nil {
		return zero, err
	}
	identity := Identity{Kind: normalized.Body.IdentityKind, Value: normalized.Body.IdentityValue}
	if envelope.Identity != identity {
		return zero, errors.New("envelope identity mismatch")
	}
	descriptorKey, err := descriptorPublicKey(context.Descriptor, identity)
	if err != nil {
		return zero, err
	}
	descriptorDigest, err := digestCanonical(context.Descriptor)
	if err != nil {
		return zero, err
	}
	if descriptorDigest != normalized.Body.DescriptorDigest {
		return zero, errors.New("descriptor digest mismatch")
	}
	if normalized.Body.Generation == 1 {
		if normalized.Body.Operation != GenerationMigrate || normalized.Body.PreviousGeneration != 0 || normalized.Body.PreviousRecordDigest != generationZeroDigest || context.PreviousRecord != nil {
			return zero, errors.New("first generation predecessor invalid")
		}
	} else {
		if context.PreviousRecord == nil {
			return zero, errors.New("generation predecessor missing")
		}
		previous := context.PreviousRecord
		if RecordDigest(previous.Body) != previous.RecordDigest {
			return zero, errors.New("previous record digest mismatch")
		}
		if normalized.Body.Operation == GenerationMigrate {
			return zero, errors.New("migrate operation only valid for first generation")
		}
		if normalized.Body.Generation != previous.Body.Generation+1 || normalized.Body.PreviousGeneration != previous.Body.Generation {
			return zero, errors.New("generation must be contiguous")
		}
		if normalized.Body.PreviousRecordDigest != previous.RecordDigest {
			return zero, errors.New("previous record digest mismatch")
		}
		if normalized.Body.Operation == GenerationRewrap && (normalized.Body.IdentityKind != previous.Body.IdentityKind || normalized.Body.IdentityValue != previous.Body.IdentityValue) {
			return zero, errors.New("rewrap identity drift")
		}
	}
	if context.ActivePointer != nil && (context.ActivePointer.Generation != normalized.Body.Generation || context.ActivePointer.RecordDigest != normalized.RecordDigest) {
		return zero, errors.New("active pointer mismatch")
	}
	if normalized.Body.Operation != GenerationRotate {
		if err := verifyGenerationSignature(descriptorKey, generationSignaturePayload(normalized.Body, normalized.RecordDigest), normalized.IdentitySignature); err != nil {
			return zero, errors.New("generation identity signature invalid")
		}
		return normalized, nil
	}
	previous := context.PreviousRecord
	if previous == nil || previous.Body.IdentityKind != IdentityAID {
		return zero, errors.New("rotation previous identity mismatch")
	}
	if normalized.Body.IdentityValue == previous.Body.IdentityValue {
		return zero, errors.New("rotation must change agent identity")
	}
	if !generationMapsEqual(normalized.PreviousDescriptor, context.PreviousDescriptor) || !generationMapsEqual(normalized.NextDescriptor, context.Descriptor) {
		return zero, errors.New("rotation descriptor substitution")
	}
	if context.PreviousDescriptor["aid"] != previous.Body.IdentityValue {
		return zero, errors.New("rotation previous identity mismatch")
	}
	previousDescriptorDigest, err := digestCanonical(context.PreviousDescriptor)
	if err != nil {
		return zero, err
	}
	if previousDescriptorDigest != previous.Body.DescriptorDigest {
		return zero, errors.New("previous descriptor digest mismatch")
	}
	if context.PreviousDescriptor["alias"] != context.Descriptor["alias"] {
		return zero, errors.New("rotation alias mismatch")
	}
	if err := verifyAgentRotationProof(normalized.AgentRotationProof, context.PreviousDescriptor, context.Descriptor); err != nil {
		return zero, err
	}
	if err := VerifyGenerationRebinding(normalized.GenerationRebinding, GenerationRebindingContext{ZoneDescriptor: context.ZoneDescriptor, PreviousDescriptor: context.PreviousDescriptor, NextDescriptor: context.Descriptor, Generation: normalized.Body.Generation, RecordDigest: normalized.RecordDigest}); err != nil {
		return zero, err
	}
	return normalized, nil
}

func generationMapsEqual(left, right map[string]any) bool {
	leftBytes, leftErr := canonicalJSON(left)
	rightBytes, rightErr := canonicalJSON(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}

func VerifyGenerationChain(records []GenerationRecord, envelopes [][]byte, context GenerationChainContext) ([]GenerationRecord, error) {
	if len(records) == 0 || len(records) != len(envelopes) || len(records) != len(context.Descriptors) {
		return nil, errors.New("generation chain inputs invalid")
	}
	verified := make([]GenerationRecord, 0, len(records))
	seen := map[string]bool{}
	for index := range records {
		verificationContext := GenerationVerificationContext{EnvelopeBytes: envelopes[index], Descriptor: context.Descriptors[index]}
		if index > 0 {
			verificationContext.PreviousRecord = &verified[index-1]
		}
		if index < len(context.PreviousDescriptors) {
			verificationContext.PreviousDescriptor = context.PreviousDescriptors[index]
		}
		if index < len(context.ZoneDescriptors) {
			verificationContext.ZoneDescriptor = context.ZoneDescriptors[index]
		}
		if index == len(records)-1 {
			verificationContext.ActivePointer = context.ActivePointer
		}
		record, err := VerifyGenerationRecord(records[index], verificationContext)
		if err != nil {
			return nil, err
		}
		if seen[record.RecordDigest] {
			return nil, errors.New("generation replay detected")
		}
		seen[record.RecordDigest] = true
		verified = append(verified, record)
	}
	return verified, nil
}
