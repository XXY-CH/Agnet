package verifier

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	swarmOutputAllowlistFormat     = "asp-swarm-output-verifier-allowlist/v1"
	swarmOutputTrustedZonesFormat  = "asp-swarm-output-trusted-zones/v1"
	swarmOutputRevocationsFormat   = "asp-swarm-output-revocations/v1"
	swarmOutputVerifyAuthorization = "swarm.output.verify"
)

type TrustInputPaths struct {
	Allowlist    string
	TrustedZones string
	Revocations  string
}

type TrustInputEvidence struct {
	Allowlist    TrustInputFileEvidence
	TrustedZones TrustInputFileEvidence
	Revocations  TrustInputFileEvidence
}

type TrustInputs struct {
	TrustInputsDigest string
	Evidence          TrustInputEvidence
	allowlist         map[string]any
	trustedZones      map[string]any
	revocations       map[string]any
}

func LoadSwarmOutputTrustInputs(paths TrustInputPaths) (TrustInputs, error) {
	var zero TrustInputs
	if paths.Allowlist == "" || paths.TrustedZones == "" || paths.Revocations == "" {
		return zero, errors.New("trust input paths invalid")
	}
	allowlist, allowlistEvidence, err := SafeOpenOwnedJSON(paths.Allowlist)
	if err != nil {
		return zero, err
	}
	trustedZones, trustedZonesEvidence, err := SafeOpenOwnedJSON(paths.TrustedZones)
	if err != nil {
		return zero, err
	}
	revocations, revocationsEvidence, err := SafeOpenOwnedJSON(paths.Revocations)
	if err != nil {
		return zero, err
	}
	trust, err := buildTrustInputs(allowlist, trustedZones, revocations)
	if err != nil {
		return zero, err
	}
	allowlistEvidence.SchemaFormat = swarmOutputAllowlistFormat
	allowlistEvidence.SnapshotDigest, err = canonicalDigest(trust.allowlist)
	if err != nil {
		return zero, err
	}
	trustedZonesEvidence.SchemaFormat = swarmOutputTrustedZonesFormat
	trustedZonesEvidence.SnapshotDigest, err = canonicalDigest(trust.trustedZones)
	if err != nil {
		return zero, err
	}
	revocationsEvidence.SchemaFormat = swarmOutputRevocationsFormat
	revocationsEvidence.SnapshotDigest, err = canonicalDigest(trust.revocations)
	if err != nil {
		return zero, err
	}
	trust.Evidence = TrustInputEvidence{
		Allowlist:    allowlistEvidence,
		TrustedZones: trustedZonesEvidence,
		Revocations:  revocationsEvidence,
	}
	return trust, nil
}

// NewTrustInputsForTest is the only in-memory constructor. Production callers must load paths.
func NewTrustInputsForTest(allowlist, trustedZones, revocations map[string]any) (TrustInputs, error) {
	return buildTrustInputs(allowlist, trustedZones, revocations)
}

func buildTrustInputs(allowlistInput, trustedZonesInput, revocationsInput map[string]any) (TrustInputs, error) {
	var zero TrustInputs
	trustedZones, trustedByZid, err := normalizeTrustZones(trustedZonesInput)
	if err != nil {
		return zero, err
	}
	allowlist, verifierIdentities, err := normalizeTrustAllowlist(allowlistInput, trustedByZid)
	if err != nil {
		return zero, err
	}
	revocations, err := normalizeTrustRevocations(revocationsInput, trustedByZid, verifierIdentities)
	if err != nil {
		return zero, err
	}
	digest, err := canonicalDigest(map[string]any{
		"allowlist":     allowlist,
		"trusted_zones": trustedZones,
		"revocations":   revocations,
	})
	if err != nil {
		return zero, err
	}
	return TrustInputs{
		TrustInputsDigest: digest,
		allowlist:         allowlist,
		trustedZones:      trustedZones,
		revocations:       revocations,
	}, nil
}

func normalizeTrustZones(input map[string]any) (map[string]any, map[string]map[string]any, error) {
	if !hasExactMapFields(input, []string{"format", "zones"}) {
		return nil, nil, errors.New("trusted zones exact schema has unknown or missing fields")
	}
	if input["format"] != swarmOutputTrustedZonesFormat {
		return nil, nil, errors.New("trusted zones format invalid")
	}
	zones, err := trustMapList(input["zones"], false, "trusted zones list invalid")
	if err != nil {
		return nil, nil, err
	}
	seen := map[string]struct{}{}
	trusted := map[string]map[string]any{}
	normalized := make([]any, 0, len(zones))
	for _, zone := range zones {
		value, err := normalizeTrustZoneDescriptor(zone)
		if err != nil {
			return nil, nil, err
		}
		zid := value["zid"].(string)
		if _, exists := seen[zid]; exists {
			return nil, nil, fmt.Errorf("duplicate trusted zone: %s", zid)
		}
		seen[zid] = struct{}{}
		if err := verifyZoneDescriptor(value); err != nil {
			return nil, nil, fmt.Errorf("zone signature verification failed: %w", err)
		}
		trusted[zid] = value
		normalized = append(normalized, value)
	}
	sort.Slice(normalized, func(left, right int) bool {
		return normalized[left].(map[string]any)["zid"].(string) < normalized[right].(map[string]any)["zid"].(string)
	})
	return map[string]any{"format": swarmOutputTrustedZonesFormat, "zones": normalized}, trusted, nil
}

func normalizeTrustAllowlist(input map[string]any, trustedByZid map[string]map[string]any) (map[string]any, map[string]string, error) {
	if !hasExactMapFields(input, []string{"format", "verifiers"}) {
		return nil, nil, errors.New("allowlist exact schema has unknown or missing fields")
	}
	if input["format"] != swarmOutputAllowlistFormat {
		return nil, nil, errors.New("allowlist format invalid")
	}
	entries, err := trustMapList(input["verifiers"], false, "allowlist verifier list invalid")
	if err != nil {
		return nil, nil, err
	}
	tuples := map[string]struct{}{}
	identities := map[string]string{}
	normalized := make([]any, 0, len(entries))
	for _, entry := range entries {
		if !hasExactMapFields(entry, []string{"authorizations", "descriptor", "zone_binding"}) {
			return nil, nil, errors.New("allowlist verifier exact schema has unknown or missing fields")
		}
		descriptorMap, ok := entry["descriptor"].(map[string]any)
		if !ok {
			return nil, nil, errors.New("verifier descriptor exact schema invalid")
		}
		descriptor, err := normalizeTrustAgentDescriptor(descriptorMap)
		if err != nil {
			return nil, nil, err
		}
		bindingMap, ok := entry["zone_binding"].(map[string]any)
		if !ok {
			return nil, nil, errors.New("verifier zone binding exact schema invalid")
		}
		binding, err := normalizeTrustZoneBinding(bindingMap)
		if err != nil {
			return nil, nil, err
		}
		authorizations, err := trustStringList(entry["authorizations"], false, "verifier authorizations invalid")
		if err != nil {
			return nil, nil, err
		}
		if !containsString(authorizations, swarmOutputVerifyAuthorization) {
			return nil, nil, errors.New("verifier missing exact swarm.output.verify authorization")
		}
		aid := descriptor["aid"].(string)
		alias := descriptor["alias"].(string)
		zoneID := binding["zone"].(string)
		for _, identity := range []string{aid, alias} {
			if _, exists := identities[identity]; exists {
				return nil, nil, fmt.Errorf("duplicate verifier identity: %s", identity)
			}
			identities[identity] = zoneID
		}
		for _, authorization := range authorizations {
			tuple := aid + "\x00" + zoneID + "\x00" + authorization
			if _, exists := tuples[tuple]; exists {
				return nil, nil, fmt.Errorf("duplicate verifier authorization tuple: %s", aid)
			}
			tuples[tuple] = struct{}{}
		}
		if err := verifyAgentDescriptor(descriptor); err != nil {
			return nil, nil, fmt.Errorf("verifier descriptor signature verification failed: %w", err)
		}
		zone := trustedByZid[zoneID]
		if zone == nil {
			return nil, nil, fmt.Errorf("untrusted verifier zone: %s", zoneID)
		}
		if err := verifyZoneBinding(zone, binding, descriptor); err != nil {
			return nil, nil, fmt.Errorf("zone binding signature verification failed: %w", err)
		}
		authorizationValues := make([]any, len(authorizations))
		for index, authorization := range authorizations {
			authorizationValues[index] = authorization
		}
		normalized = append(normalized, map[string]any{
			"descriptor":     descriptor,
			"zone_binding":   binding,
			"authorizations": authorizationValues,
		})
	}
	sort.Slice(normalized, func(left, right int) bool {
		return normalized[left].(map[string]any)["descriptor"].(map[string]any)["aid"].(string) < normalized[right].(map[string]any)["descriptor"].(map[string]any)["aid"].(string)
	})
	return map[string]any{"format": swarmOutputAllowlistFormat, "verifiers": normalized}, identities, nil
}

func normalizeTrustRevocations(input map[string]any, trustedByZid map[string]map[string]any, verifierZoneByIdentity map[string]string) (map[string]any, error) {
	if !hasExactMapFields(input, []string{"format", "revocations"}) {
		return nil, errors.New("revocations exact schema has unknown or missing fields")
	}
	if input["format"] != swarmOutputRevocationsFormat {
		return nil, errors.New("revocations format invalid")
	}
	entries, err := trustMapList(input["revocations"], true, "revocations list invalid")
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	revokedByZone := map[string]map[string]struct{}{}
	normalized := make([]any, 0, len(entries))
	for _, entry := range entries {
		revocation, err := normalizeTrustRevocation(entry)
		if err != nil {
			return nil, err
		}
		zoneID := revocation["zone"].(string)
		subject := revocation["subject"].(string)
		tuple := zoneID + "\x00" + subject
		if _, exists := seen[tuple]; exists {
			return nil, fmt.Errorf("duplicate revocation identity: %s/%s", zoneID, subject)
		}
		seen[tuple] = struct{}{}
		zone := trustedByZid[zoneID]
		if zone == nil {
			return nil, fmt.Errorf("untrusted revocation zone: %s", zoneID)
		}
		if err := verifyTrustRevocation(revocation, zone); err != nil {
			return nil, fmt.Errorf("revocation signature verification failed: %w", err)
		}
		if verifierZone, exists := verifierZoneByIdentity[subject]; exists && verifierZone != zoneID {
			return nil, fmt.Errorf("out-of-scope revocation for verifier: %s/%s", zoneID, subject)
		}
		if _, isZone := trustedByZid[subject]; isZone && subject != zoneID {
			return nil, fmt.Errorf("out-of-scope revocation for Zone: %s/%s", zoneID, subject)
		}
		if revokedByZone[zoneID] == nil {
			revokedByZone[zoneID] = map[string]struct{}{}
		}
		revokedByZone[zoneID][subject] = struct{}{}
		normalized = append(normalized, revocation)
	}
	for zid := range trustedByZid {
		if _, revoked := revokedByZone[zid][zid]; revoked {
			return nil, fmt.Errorf("trusted zone revoked: %s", zid)
		}
	}
	for identity, zoneID := range verifierZoneByIdentity {
		if _, revoked := revokedByZone[zoneID][identity]; revoked {
			return nil, fmt.Errorf("verifier revoked: %s", identity)
		}
	}
	sort.Slice(normalized, func(left, right int) bool {
		leftMap := normalized[left].(map[string]any)
		rightMap := normalized[right].(map[string]any)
		return leftMap["zone"].(string)+"\x00"+leftMap["subject"].(string) < rightMap["zone"].(string)+"\x00"+rightMap["subject"].(string)
	})
	return map[string]any{"format": swarmOutputRevocationsFormat, "revocations": normalized}, nil
}

func normalizeTrustAgentDescriptor(descriptor map[string]any) (map[string]any, error) {
	if !hasExactMapFields(descriptor, []string{"aid", "alias", "capabilities", "descriptor_signature", "did_key", "policy", "public_key_spki", "transports"}) {
		return nil, errors.New("verifier descriptor exact schema has unknown or missing fields")
	}
	alias, err := trustString(descriptor["alias"], "verifier alias invalid")
	if err != nil {
		return nil, err
	}
	aid, err := trustString(descriptor["aid"], "verifier aid invalid")
	if err != nil {
		return nil, err
	}
	didKey, err := trustString(descriptor["did_key"], "verifier did_key invalid")
	if err != nil {
		return nil, err
	}
	publicKeySPKI, err := trustBase64URLString(descriptor["public_key_spki"], "verifier public key spki invalid")
	if err != nil {
		return nil, err
	}
	signature, err := trustBase64URLString(descriptor["descriptor_signature"], "verifier descriptor signature invalid")
	if err != nil {
		return nil, err
	}
	transports, err := trustStringList(descriptor["transports"], true, "verifier transports invalid")
	if err != nil {
		return nil, err
	}
	capabilities, err := trustStringList(descriptor["capabilities"], true, "verifier capabilities invalid")
	if err != nil {
		return nil, err
	}
	policy, ok := descriptor["policy"].(map[string]any)
	if !ok {
		return nil, errors.New("verifier policy exact schema invalid")
	}
	normalizedPolicy, err := normalizeTrustPolicy(policy)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"alias":                alias,
		"aid":                  aid,
		"did_key":              didKey,
		"public_key_spki":      publicKeySPKI,
		"transports":           stringsToAny(transports),
		"capabilities":         stringsToAny(capabilities),
		"policy":               normalizedPolicy,
		"descriptor_signature": signature,
	}, nil
}

func normalizeTrustPolicy(policy map[string]any) (map[string]any, error) {
	allowed := map[string]struct{}{"allow_network": {}, "approval_required": {}, "write_prefixes": {}}
	for key := range policy {
		if _, ok := allowed[key]; !ok {
			return nil, errors.New("verifier policy exact schema has unknown fields")
		}
	}
	normalized := map[string]any{}
	if value, exists := policy["allow_network"]; exists {
		boolean, ok := value.(bool)
		if !ok {
			return nil, errors.New("verifier policy allow_network invalid")
		}
		normalized["allow_network"] = boolean
	}
	for _, field := range []string{"approval_required", "write_prefixes"} {
		if value, exists := policy[field]; exists {
			items, err := trustStringList(value, true, "verifier policy "+field+" invalid")
			if err != nil {
				return nil, err
			}
			normalized[field] = stringsToAny(items)
		}
	}
	return normalized, nil
}

func normalizeTrustZoneBinding(binding map[string]any) (map[string]any, error) {
	if !hasExactMapFields(binding, []string{"aid", "alias", "signature", "zone"}) {
		return nil, errors.New("verifier zone binding exact schema has unknown or missing fields")
	}
	out, err := normalizedStringMap(binding, []string{"zone", "alias", "aid", "signature"}, "verifier zone binding")
	if err != nil {
		return nil, err
	}
	if _, err := decodeBase64URLExact(out["signature"].(string), "verifier zone binding signature"); err != nil {
		return nil, err
	}
	return out, nil
}

func normalizeTrustZoneDescriptor(zone map[string]any) (map[string]any, error) {
	if !hasExactMapFields(zone, []string{"name", "public_key_spki", "zid", "zone_signature"}) {
		return nil, errors.New("trusted zone descriptor exact schema has unknown or missing fields")
	}
	out, err := normalizedStringMap(zone, []string{"name", "zid", "public_key_spki", "zone_signature"}, "trusted zone descriptor")
	if err != nil {
		return nil, err
	}
	if _, err := decodeBase64URLExact(out["public_key_spki"].(string), "trusted zone public_key_spki"); err != nil {
		return nil, err
	}
	if _, err := decodeBase64URLExact(out["zone_signature"].(string), "trusted zone signature"); err != nil {
		return nil, err
	}
	return out, nil
}

func normalizeTrustRevocation(revocation map[string]any) (map[string]any, error) {
	if !hasExactMapFields(revocation, []string{"reason", "signature", "subject", "zone"}) {
		return nil, errors.New("revocation entry exact schema has unknown or missing fields")
	}
	out, err := normalizedStringMap(revocation, []string{"zone", "subject", "reason", "signature"}, "revocation")
	if err != nil {
		return nil, err
	}
	if _, err := decodeBase64URLExact(out["signature"].(string), "revocation signature"); err != nil {
		return nil, err
	}
	return out, nil
}

func normalizedStringMap(input map[string]any, fields []string, label string) (map[string]any, error) {
	out := map[string]any{}
	for _, field := range fields {
		value, err := trustString(input[field], label+" "+field+" invalid")
		if err != nil {
			return nil, err
		}
		out[field] = value
	}
	return out, nil
}

func verifyTrustRevocation(revocation, zone map[string]any) error {
	if revocation["zone"] != zone["zid"] {
		return errors.New("revocation zone mismatch")
	}
	key, _, err := publicKey(zone)
	if err != nil {
		return err
	}
	return verifyMapSignature(key, revocation, "signature")
}

func trustMapList(value any, allowEmpty bool, message string) ([]map[string]any, error) {
	items, ok := value.([]any)
	if !ok || (!allowEmpty && len(items) == 0) {
		return nil, errors.New(message)
	}
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		entry, ok := item.(map[string]any)
		if !ok {
			return nil, errors.New(message)
		}
		out = append(out, entry)
	}
	return out, nil
}

func trustString(value any, message string) (string, error) {
	text, ok := value.(string)
	if !ok || text == "" || strings.ContainsRune(text, '\x00') {
		return "", errors.New(message)
	}
	if !utf8.ValidString(text) {
		return "", errors.New(message + ": canonical string domain requires Unicode scalar values")
	}
	if strings.ContainsRune(text, '\u2028') || strings.ContainsRune(text, '\u2029') {
		return "", errors.New(message + ": canonical string domain excludes U+2028/U+2029")
	}
	return text, nil
}

func trustBase64URLString(value any, message string) (string, error) {
	text, err := trustString(value, message)
	if err != nil {
		return "", err
	}
	if _, err := decodeBase64URLExact(text, message); err != nil {
		return "", err
	}
	return text, nil
}

func trustStringList(value any, allowEmpty bool, message string) ([]string, error) {
	items, ok := value.([]any)
	if !ok || (!allowEmpty && len(items) == 0) {
		return nil, errors.New(message)
	}
	out := make([]string, 0, len(items))
	seen := map[string]struct{}{}
	for _, item := range items {
		text, err := trustString(item, message)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[text]; exists {
			return nil, errors.New(message + " duplicate value")
		}
		seen[text] = struct{}{}
		out = append(out, text)
	}
	return out, nil
}

func stringsToAny(values []string) []any {
	out := make([]any, len(values))
	for index, value := range values {
		out[index] = value
	}
	return out
}
