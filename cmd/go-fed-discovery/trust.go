package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

func (f Fixture) zoneBinding(worker *Worker) map[string]any {
	return f.zoneBindingForDescriptor(worker.Descriptor)
}

func (f Fixture) zoneBindingForDescriptor(descriptor map[string]any) map[string]any {
	return signBody(f.AuthorityPrivateKey, map[string]any{
		"zone":  f.Authority["zid"],
		"alias": descriptor["alias"],
		"aid":   descriptor["aid"],
	})
}

func (f Fixture) capabilityCredential(worker *Worker, capability string) map[string]any {
	return signBody(f.AuthorityPrivateKey, map[string]any{
		"issuer":     f.Authority["zid"],
		"subject":    worker.Descriptor["aid"],
		"capability": capability,
		"claims":     f.Credential["claims"],
	})
}

func isCredentialActive(credential map[string]any) bool {
	claims, ok := credential["claims"].(map[string]any)
	if !ok {
		return true
	}
	validUntil, ok := claims["valid_until"]
	if !ok {
		return true
	}
	validUntilText, ok := validUntil.(string)
	if !ok || !credentialValidUntilRegexp.MatchString(validUntilText) {
		return false
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, validUntilText)
	if err != nil {
		return false
	}
	return !time.Now().UTC().After(expiresAt)
}

func verifyZoneRevocation(revocation, zoneDescriptor map[string]any) bool {
	if revocation["zone"] != zoneDescriptor["zid"] {
		return false
	}
	key, _, err := publicKey(zoneDescriptor)
	if err != nil {
		return false
	}
	return verifyMapSignature(key, revocation, "signature") == nil
}

func isRevoked(revocations []any, workerAID string, zoneDescriptor map[string]any) bool {
	if workerAID == "" {
		return false
	}
	for _, item := range revocations {
		revocation, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if revocation["subject"] == workerAID && verifyZoneRevocation(revocation, zoneDescriptor) {
			return true
		}
	}
	return false
}

func countRevocationsForWorker(revocations []any, workerAID, alias string, zoneDescriptor map[string]any) int {
	count := 0
	for _, item := range revocations {
		revocation, ok := item.(map[string]any)
		if !ok {
			continue
		}
		subject := optionalString(revocation["subject"])
		if subject != workerAID && subject != alias {
			continue
		}
		if verifyZoneRevocation(revocation, zoneDescriptor) {
			count++
		}
	}
	return count
}

func loadTrustedZones(path string) (map[string]map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var store TrustStore
	if err := json.Unmarshal(data, &store); err != nil {
		return nil, err
	}
	out := map[string]map[string]any{}
	for _, zone := range store.Zones {
		if err := verifyZoneDescriptor(zone); err != nil {
			return nil, err
		}
		entry := map[string]any{}
		for key, value := range zone {
			entry[key] = value
		}
		var revocations []any
		for _, revocation := range store.Revocations {
			if revocation["zone"] == zone["zid"] {
				revocations = append(revocations, revocation)
			}
		}
		if len(revocations) > 0 {
			entry["revocations"] = revocations
			if err := verifyZoneRevocations(entry, ""); err != nil {
				return nil, err
			}
		}
		out[fmt.Sprint(zone["zid"])] = entry
	}
	return out, nil
}

func verifyTrustedZone(zone map[string]any, trusted map[string]map[string]any) error {
	if err := verifyZoneDescriptor(zone); err != nil {
		return err
	}
	known := trusted[fmt.Sprint(zone["zid"])]
	if known == nil || known["public_key_spki"] != zone["public_key_spki"] {
		return errors.New("untrusted zone: " + fmt.Sprint(zone["zid"]))
	}
	if err := verifyZoneRevocations(known, fmt.Sprint(zone["zid"])); err != nil {
		return err
	}
	return nil
}

func verifyZoneRevocations(zone map[string]any, subject string) error {
	revocations, _ := zone["revocations"].([]any)
	for _, item := range revocations {
		revocation, ok := item.(map[string]any)
		if !ok {
			return errors.New("zone revocation invalid")
		}
		if revocation["zone"] != zone["zid"] {
			return errors.New("zone revocation issuer mismatch")
		}
		key, _, err := publicKey(zone)
		if err != nil {
			return err
		}
		if err := verifyMapSignature(key, revocation, "signature"); err != nil {
			return errors.New("zone revocation signature verification failed")
		}
		if revocation["subject"] == subject {
			return errors.New("zone revoked: " + subject)
		}
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

func verifyAgentRotationProof(proof, previous, next map[string]any) error {
	if err := verifyAgentDescriptor(previous); err != nil {
		return err
	}
	if err := verifyAgentDescriptor(next); err != nil {
		return err
	}
	body := map[string]any{
		"previous_aid": previous["aid"],
		"next_aid":     next["aid"],
	}
	if proof["previous_aid"] != body["previous_aid"] || proof["next_aid"] != body["next_aid"] {
		return errors.New("rotation proof aid mismatch")
	}
	previousKey, _, err := publicKey(previous)
	if err != nil {
		return err
	}
	nextKey, _, err := publicKey(next)
	if err != nil {
		return err
	}
	previousSigned := map[string]any{
		"previous_aid":       body["previous_aid"],
		"next_aid":           body["next_aid"],
		"previous_signature": proof["previous_signature"],
	}
	if err := verifyMapSignature(previousKey, previousSigned, "previous_signature"); err != nil {
		return err
	}
	nextSigned := map[string]any{
		"previous_aid":   body["previous_aid"],
		"next_aid":       body["next_aid"],
		"next_signature": proof["next_signature"],
	}
	return verifyMapSignature(nextKey, nextSigned, "next_signature")
}
