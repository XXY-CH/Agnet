package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
)

const swarmDisbandFormat = "asp-swarm-disband/v1"

var ErrSwarmDisbanded = errors.New("swarm is disbanded")

type StoredSwarmDisband struct {
	Bytes  []byte `json:"-"`
	Digest string `json:"digest"`
}

type swarmDisbandWire struct {
	Format                   string `json:"format"`
	SwarmID                  string `json:"swarm_id"`
	PlanDigest               string `json:"plan_digest"`
	ExecutionGraphDigest     string `json:"execution_graph_digest"`
	CloseDigest              string `json:"close_digest"`
	OutputVerificationDigest string `json:"output_verification_digest"`
	DisbandedAt              string `json:"disbanded_at"`
	DisbandSignature         string `json:"disband_signature"`
}

type swarmDisbandStoredPayload struct {
	SchemaVersion uint64 `json:"schema_version"`
	Disband       string `json:"disband"`
	Digest        string `json:"digest"`
}

func swarmMutationAllowed(state SwarmState) error {
	if state.Status == SwarmStatusDisbanded {
		return ErrSwarmDisbanded
	}
	return nil
}

func BuildSwarmDisband(journal *SwarmJournal) (StoredSwarmDisband, error) {
	if journal == nil {
		return StoredSwarmDisband{}, errors.New("swarm journal is required")
	}
	var result StoredSwarmDisband
	err := journal.WithLockedReplay(func(entries []SwarmJournalEntry) error {
		state, err := ReduceSwarmEntries(entries)
		if err != nil {
			return err
		}
		result, err = buildSwarmDisbandLocked(state)
		return err
	})
	return result, err
}

func buildSwarmDisbandLocked(state SwarmState) (StoredSwarmDisband, error) {
	if state.Version == 0 || state.Status != SwarmStatusCompleted || state.OutputVerification == nil || state.StoredClose.Digest == "" {
		return StoredSwarmDisband{}, errors.New("swarm disband requires completed output verification")
	}
	planDigest, graphDigest, err := swarmCloseBindingDigests(state.Spec)
	if err != nil {
		return StoredSwarmDisband{}, err
	}
	if !isHexDigest(state.OutputVerification.Digest) || state.OutputVerification.CloseDigest != state.StoredClose.Digest || state.OutputVerification.CompletedAt == "" {
		return StoredSwarmDisband{}, errors.New("swarm disband output verification invalid")
	}
	body := swarmDisbandBody(swarmDisbandWire{Format: swarmDisbandFormat, SwarmID: state.Spec.SwarmID, PlanDigest: planDigest, ExecutionGraphDigest: graphDigest, CloseDigest: state.StoredClose.Digest, OutputVerificationDigest: state.OutputVerification.Digest, DisbandedAt: state.OutputVerification.CompletedAt})
	key, err := pinnedCloseAuthorityKey(state.Spec)
	if err != nil {
		return StoredSwarmDisband{}, errors.New("swarm disband authority unavailable")
	}
	defer clear(key)
	signed := signBodyWithKey(key, body, "disband_signature")
	raw, err := canonicalJSON(signed)
	if err != nil {
		return StoredSwarmDisband{}, err
	}
	if err := verifySwarmDisbandAgainstState(raw, state); err != nil {
		return StoredSwarmDisband{}, err
	}
	return StoredSwarmDisband{Bytes: raw, Digest: digestBytesHex(raw)}, nil
}

func EnsureDisband(journal *SwarmJournal) (StoredSwarmDisband, error) {
	if journal == nil {
		return StoredSwarmDisband{}, errors.New("swarm journal is required")
	}
	var result StoredSwarmDisband
	err := journal.WithLockedReplay(func(entries []SwarmJournalEntry) error {
		state, err := ReduceSwarmEntries(entries)
		if err != nil {
			return err
		}
		for index, entry := range entries {
			if entry.Kind != "swarm.disbanded" {
				continue
			}
			stored, err := storedSwarmDisbandFromEntry(entry)
			if err != nil {
				return err
			}
			prior, err := ReduceSwarmEntries(entries[:index])
			if err != nil {
				return err
			}
			candidate, err := buildSwarmDisbandLocked(prior)
			if err != nil {
				return err
			}
			if !bytes.Equal(stored.Bytes, candidate.Bytes) || stored.Digest != candidate.Digest {
				return errors.New("swarm disband conflicts with stored disband")
			}
			result = stored
			return nil
		}
		if err := swarmMutationAllowed(state); err != nil {
			return err
		}
		candidate, err := buildSwarmDisbandLocked(state)
		if err != nil {
			return err
		}
		if state.Version == math.MaxUint64 || len(entries) == 0 {
			return errors.New("swarm disband state invalid")
		}
		payload, err := canonicalSwarmPayload(swarmDisbandStoredPayload{SchemaVersion: swarmStateSchemaVersion, Disband: base64.RawURLEncoding.EncodeToString(candidate.Bytes), Digest: candidate.Digest})
		if err != nil {
			return err
		}
		entry := SwarmJournalEntry{Format: swarmJournalFormat, Sequence: uint64(len(entries) + 1), PriorStateVersion: state.Version, StateVersion: state.Version + 1, Kind: "swarm.disbanded", Payload: payload, Timestamp: state.OutputVerification.CompletedAt, PrevHash: entries[len(entries)-1].Hash}
		entry.Hash, err = swarmJournalEntryHash(entry)
		if err != nil {
			return err
		}
		next, err := ReduceSwarmEntry(state, entry)
		if err != nil {
			return err
		}
		if err := journal.validateTypedStateIdentity(next); err != nil {
			return err
		}
		if err := journal.appendLocked(entry); err != nil {
			return err
		}
		result = candidate
		return nil
	})
	return result, err
}

func VerifySwarmDisband(raw []byte, journal *SwarmJournal) error {
	if journal == nil {
		return errors.New("swarm journal is required")
	}
	return journal.WithLockedReplay(func(entries []SwarmJournalEntry) error {
		for index, entry := range entries {
			if entry.Kind != "swarm.disbanded" {
				continue
			}
			stored, err := storedSwarmDisbandFromEntry(entry)
			if err != nil {
				return err
			}
			if !bytes.Equal(raw, stored.Bytes) {
				return errors.New("swarm disband bytes differ from stored record")
			}
			prior, err := ReduceSwarmEntries(entries[:index])
			if err != nil {
				return err
			}
			return verifySwarmDisbandAgainstState(raw, prior)
		}
		state, err := ReduceSwarmEntries(entries)
		if err != nil {
			return err
		}
		return verifySwarmDisbandAgainstState(raw, state)
	})
}

func storedSwarmDisbandFromEntry(entry SwarmJournalEntry) (StoredSwarmDisband, error) {
	var payload swarmDisbandStoredPayload
	if err := decodeStrictSwarmPayload(entry.Payload, &payload); err != nil || payload.SchemaVersion != swarmStateSchemaVersion || !isHexDigest(payload.Digest) || payload.Disband == "" {
		return StoredSwarmDisband{}, errors.New("stored swarm disband invalid")
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload.Disband)
	if err != nil || base64.RawURLEncoding.EncodeToString(raw) != payload.Disband || digestBytesHex(raw) != payload.Digest {
		return StoredSwarmDisband{}, errors.New("stored swarm disband invalid")
	}
	return StoredSwarmDisband{Bytes: append([]byte(nil), raw...), Digest: payload.Digest}, nil
}

func verifySwarmDisbandAgainstState(raw []byte, state SwarmState) error {
	if state.Version == 0 || state.Status != SwarmStatusCompleted || state.OutputVerification == nil || state.StoredClose.Digest == "" || !json.Valid(raw) || validateSwarmJSONNoDuplicateFields(raw) != nil {
		return errors.New("swarm disband invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var wire swarmDisbandWire
	if err := decoder.Decode(&wire); err != nil || ensureSwarmJSONEOF(decoder) != nil {
		return errors.New("swarm disband invalid")
	}
	var signed map[string]any
	if err := json.Unmarshal(raw, &signed); err != nil {
		return errors.New("swarm disband invalid")
	}
	canonical, err := canonicalJSON(signed)
	if err != nil || !bytes.Equal(canonical, raw) || wire.Format != swarmDisbandFormat || wire.SwarmID != state.Spec.SwarmID || !isHexDigest(wire.PlanDigest) || !isHexDigest(wire.ExecutionGraphDigest) || wire.CloseDigest != state.StoredClose.Digest || wire.OutputVerificationDigest != state.OutputVerification.Digest || wire.DisbandedAt != state.OutputVerification.CompletedAt {
		return errors.New("swarm disband binding invalid")
	}
	if _, err := parseCanonicalSwarmTimestamp(wire.DisbandedAt); err != nil {
		return errors.New("swarm disband timestamp invalid")
	}
	signature, err := base64.RawURLEncoding.DecodeString(wire.DisbandSignature)
	if err != nil || base64.RawURLEncoding.EncodeToString(signature) != wire.DisbandSignature || len(signature) != ed25519.SignatureSize {
		return errors.New("swarm disband signature invalid")
	}
	planDigest, graphDigest, err := swarmCloseBindingDigests(state.Spec)
	if err != nil || wire.PlanDigest != planDigest || wire.ExecutionGraphDigest != graphDigest {
		return errors.New("swarm disband binding invalid")
	}
	if len(state.Spec.LocalAuthority) == 0 || verifyZoneDescriptor(state.Spec.LocalAuthority) != nil {
		return errors.New("swarm disband authority invalid")
	}
	key, _, err := publicKey(state.Spec.LocalAuthority)
	if err != nil {
		return errors.New("swarm disband authority invalid")
	}
	body := swarmDisbandBody(wire)
	body["disband_signature"] = wire.DisbandSignature
	if err := verifyMapSignature(key, body, "disband_signature"); err != nil {
		return errors.New("swarm disband signature invalid")
	}
	return nil
}

func swarmDisbandBody(wire swarmDisbandWire) map[string]any {
	return map[string]any{"format": wire.Format, "swarm_id": wire.SwarmID, "plan_digest": wire.PlanDigest, "execution_graph_digest": wire.ExecutionGraphDigest, "close_digest": wire.CloseDigest, "output_verification_digest": wire.OutputVerificationDigest, "disbanded_at": wire.DisbandedAt}
}
