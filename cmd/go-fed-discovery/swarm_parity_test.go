package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type swarmParityVector struct {
	Format   string              `json:"format"`
	Origin   string              `json:"origin"`
	Journal  []SwarmJournalEntry `json:"journal"`
	Evidence struct {
		Close             string           `json:"close"`
		Proof             string           `json:"proof"`
		Disband           string           `json:"disband"`
		FrozenAuthority   map[string]any   `json:"frozen_authority"`
		FrozenWorkers     []map[string]any `json:"frozen_workers"`
		TrustInputsDigest string           `json:"trust_inputs_digest"`
	} `json:"evidence"`
	Expected struct {
		Head          string `json:"head"`
		StateVersion  uint64 `json:"state_version"`
		SwarmID       string `json:"swarm_id"`
		Status        string `json:"status"`
		CloseDigest   string `json:"close_digest"`
		ProofDigest   string `json:"proof_digest"`
		DisbandDigest string `json:"disband_digest"`
	} `json:"expected"`
}

func TestGoCreatedDurableSwarmVector(t *testing.T) {
	verifyU29Vector(t, loadU29Vector(t, "asp-u29-go-swarm-durable.json"))
}

func TestNodeCreatedDurableSwarmVector(t *testing.T) {
	verifyU29Vector(t, loadU29Vector(t, "asp-u29-node-swarm-durable.json"))
}

func TestU29DurableJournalNodeGoParityVectors(t *testing.T) {
	for _, name := range []string{"asp-u29-go-swarm-durable.json", "asp-u29-node-swarm-durable.json"} {
		t.Run(strings.TrimSuffix(name, ".json"), func(t *testing.T) {
			vector := loadU29Vector(t, name)
			verifyU29Vector(t, vector)
			path := filepath.Join("..", "..", "test-vectors", name)
			output, err := exec.Command("node", "../../asp-verify.mjs", "swarm-journal", path).CombinedOutput()
			if err != nil {
				t.Fatalf("Node rejected %s vector: %v: %s", vector.Origin, err, output)
			}
			var verified struct {
				Result       string `json:"swarm_journal_verify"`
				Head         string `json:"head"`
				StateVersion uint64 `json:"state_version"`
			}
			if err := json.Unmarshal(output, &verified); err != nil {
				t.Fatalf("Node result invalid: %v: %s", err, output)
			}
			if verified.Result != "ok" || verified.Head != vector.Expected.Head || verified.StateVersion != vector.Expected.StateVersion {
				t.Fatalf("Node result mismatch: %#v", verified)
			}
		})
	}
}

func loadU29Vector(t *testing.T, name string) swarmParityVector {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "test-vectors", name))
	if err != nil {
		t.Fatal(err)
	}
	var vector swarmParityVector
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	return vector
}

func verifyU29Vector(t *testing.T, vector swarmParityVector) {
	t.Helper()
	if vector.Format != "asp-swarm-durable-parity-vector/v1" || (vector.Origin != "go" && vector.Origin != "node") || len(vector.Journal) < 2 || vector.Evidence.Close == "" || vector.Evidence.Proof == "" || vector.Evidence.Disband == "" || len(vector.Evidence.FrozenAuthority) == 0 || len(vector.Evidence.FrozenWorkers) == 0 || !isHexDigest(vector.Evidence.TrustInputsDigest) {
		t.Fatalf("incomplete durable vector: %#v", vector)
	}
	previousHash, previousVersion := swarmJournalZeroHash, uint64(0)
	for index, entry := range vector.Journal {
		canonicalPayload, err := canonicalSwarmPayload(entry.Payload)
		if err != nil {
			t.Fatalf("canonical payload %s entry %d: %v", vector.Origin, index+1, err)
		}
		entry.Payload = canonicalPayload
		vector.Journal[index] = entry
		if err := validateSwarmJournalEntry(entry, uint64(index+1), previousVersion, previousHash); err != nil {
			t.Fatalf("Go rejected %s entry %d: %v", vector.Origin, index+1, err)
		}
		previousHash, previousVersion = entry.Hash, entry.StateVersion
	}
	if previousHash != vector.Expected.Head || previousVersion != vector.Expected.StateVersion {
		t.Fatalf("Go replay head/version mismatch: %q/%d", previousHash, previousVersion)
	}
	state, err := ReduceSwarmEntries(vector.Journal)
	if err != nil {
		t.Fatalf("Go reducer rejected %s vector: %v", vector.Origin, err)
	}
	if state.Version != vector.Expected.StateVersion || state.Spec.SwarmID != vector.Expected.SwarmID || string(state.Status) != vector.Expected.Status || state.StoredClose.Digest != vector.Expected.CloseDigest || state.StoredDisband.Digest != vector.Expected.DisbandDigest || state.OutputVerification == nil || state.OutputVerification.ProofDigest != vector.Expected.ProofDigest {
		t.Fatalf("Go reducer state mismatch: %#v", state)
	}
	if !bytes.Equal(state.StoredClose.Bytes, decodeU29B64(t, vector.Evidence.Close)) || !bytes.Equal(state.StoredDisband.Bytes, decodeU29B64(t, vector.Evidence.Disband)) {
		t.Fatal("stored close/disband bytes differ from vector evidence")
	}
	proof := decodeU29B64(t, vector.Evidence.Proof)
	if !bytes.Equal(proof, decodeU29OutputProof(t, vector.Journal)) {
		t.Fatal("stored proof bytes differ from vector evidence")
	}
	if state.OutputVerification.TrustInputsDigest != vector.Evidence.TrustInputsDigest {
		t.Fatal("output verification did not bind frozen trust")
	}
	for index, entry := range vector.Journal {
		switch entry.Kind {
		case "close.stored":
			stored, err := storedSwarmCloseFromEntry(entry)
			if err != nil {
				t.Fatal(err)
			}
			prior, err := ReduceSwarmEntries(vector.Journal[:index])
			if err != nil {
				t.Fatal(err)
			}
			if err := verifyJournalCloseV2(stored.Bytes, prior, vector.Journal[:index]); err != nil {
				t.Fatalf("close verifier rejected %s: %v", vector.Origin, err)
			}
			mutated := append([]byte(nil), stored.Bytes...)
			mutated[len(mutated)-1] ^= 1
			if err := verifyJournalCloseV2(mutated, prior, vector.Journal[:index]); err == nil {
				t.Fatal("close verifier accepted close/proof mismatch")
			}
		case "output.verified":
			var payload outputVerifiedPayload
			if err := decodeStrictSwarmPayload(entry.Payload, &payload); err != nil {
				t.Fatal(err)
			}
			prior, err := ReduceSwarmEntries(vector.Journal[:index])
			if err != nil {
				t.Fatal(err)
			}
			legacy := payload
			legacy.CloseDigest = strings.Repeat("0", 64)
			if _, err := ReduceSwarmEntry(prior, SwarmJournalEntry{Format: swarmJournalFormat, Sequence: entry.Sequence, PriorStateVersion: entry.PriorStateVersion, StateVersion: entry.StateVersion, Kind: entry.Kind, Payload: mustCanonicalU29Payload(t, legacy), Timestamp: entry.Timestamp, PrevHash: entry.PrevHash}); err == nil {
				t.Fatal("reducer accepted legacy digest substitution")
			}
			mutatedTrust := payload
			mutatedTrust.TrustInputsDigest = strings.Repeat("f", 64)
			if _, err := ReduceSwarmEntry(prior, SwarmJournalEntry{Format: swarmJournalFormat, Sequence: entry.Sequence, PriorStateVersion: entry.PriorStateVersion, StateVersion: entry.StateVersion, Kind: entry.Kind, Payload: mustCanonicalU29Payload(t, mutatedTrust), Timestamp: entry.Timestamp, PrevHash: entry.PrevHash}); err == nil {
				t.Fatal("reducer accepted frozen trust mutation")
			}
		case "swarm.disbanded":
			stored, err := storedSwarmDisbandFromEntry(entry)
			if err != nil {
				t.Fatal(err)
			}
			prior, err := ReduceSwarmEntries(vector.Journal[:index])
			if err != nil {
				t.Fatal(err)
			}
			if err := verifySwarmDisbandAgainstState(stored.Bytes, prior); err != nil {
				t.Fatalf("disband verifier rejected %s: %v", vector.Origin, err)
			}
			var wire swarmDisbandWire
			if err := json.Unmarshal(stored.Bytes, &wire); err != nil {
				t.Fatal(err)
			}
			wire.DisbandSignature = strings.Repeat("A", len(wire.DisbandSignature))
			bad, err := canonicalJSON(wire)
			if err != nil {
				t.Fatal(err)
			}
			if err := verifySwarmDisbandAgainstState(bad, prior); err == nil {
				t.Fatal("disband verifier accepted bad signature")
			}
		}
	}
}

func decodeU29B64(t *testing.T, value string) []byte {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(raw) != value {
		t.Fatal("vector evidence base64 invalid")
	}
	return raw
}

func decodeU29OutputProof(t *testing.T, entries []SwarmJournalEntry) []byte {
	t.Helper()
	for _, entry := range entries {
		if entry.Kind == "output.verified" {
			var payload outputVerifiedPayload
			if err := decodeStrictSwarmPayload(entry.Payload, &payload); err != nil {
				t.Fatal(err)
			}
			return decodeU29B64(t, payload.Proof)
		}
	}
	t.Fatal("output.verified missing")
	return nil
}

func mustCanonicalU29Payload(t *testing.T, value any) json.RawMessage {
	t.Helper()
	raw, err := canonicalSwarmPayload(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestGenerateU29DurableVectors(t *testing.T) {
	if os.Getenv("UPDATE_U29_VECTORS") != "1" {
		return
	}
	vector := buildU29Vector(t, "go")
	raw, err := json.MarshalIndent(vector, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("..", "..", "test-vectors", "asp-u29-go-swarm-durable.json"), append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func buildU29Vector(t *testing.T, origin string) swarmParityVector {
	t.Helper()
	journal, spec := newCloseTestJournal(t)
	completeDisbandTestJournal(t, journal, spec)
	if _, err := EnsureDisband(journal); err != nil {
		t.Fatal(err)
	}
	entries := mustReplaySwarm(t, journal)
	normalizeU29OpenEntry(t, entries)
	state, err := ReduceSwarmEntries(entries)
	if err != nil {
		t.Fatal(err)
	}
	var result swarmParityVector
	result.Format, result.Origin, result.Journal = "asp-swarm-durable-parity-vector/v1", origin, entries
	result.Expected.Head, result.Expected.StateVersion, result.Expected.SwarmID, result.Expected.Status = entries[len(entries)-1].Hash, state.Version, state.Spec.SwarmID, string(state.Status)
	result.Expected.CloseDigest, result.Expected.ProofDigest, result.Expected.DisbandDigest = state.StoredClose.Digest, state.OutputVerification.ProofDigest, state.StoredDisband.Digest
	result.Evidence.Close, result.Evidence.Disband = base64.RawURLEncoding.EncodeToString(state.StoredClose.Bytes), base64.RawURLEncoding.EncodeToString(state.StoredDisband.Bytes)
	result.Evidence.Proof, result.Evidence.TrustInputsDigest = base64.RawURLEncoding.EncodeToString(decodeU29OutputProof(t, entries)), state.OutputVerification.TrustInputsDigest
	result.Evidence.FrozenAuthority = state.Spec.LocalAuthority
	for _, step := range state.Spec.Steps {
		for _, candidate := range step.Candidates {
			var descriptor map[string]any
			if err := json.Unmarshal([]byte(candidate.Descriptor), &descriptor); err != nil {
				t.Fatal(err)
			}
			result.Evidence.FrozenWorkers = append(result.Evidence.FrozenWorkers, descriptor)
		}
	}
	return result
}

func normalizeU29OpenEntry(t *testing.T, entries []SwarmJournalEntry) {
	t.Helper()
	if len(entries) == 0 {
		t.Fatal("empty vector journal")
	}
	var opened swarmOpenedPayload
	if err := decodeStrictSwarmPayload(entries[0].Payload, &opened); err != nil {
		t.Fatal(err)
	}
	opened.Spec.AuthorityGeneration.StorePath, opened.Spec.AuthorityGeneration.PassphraseFile = "/u29/frozen-authority", "/u29/frozen-passphrase"
	entries[0].Payload = mustCanonicalU29Payload(t, opened)
	previous := swarmJournalZeroHash
	for index := range entries {
		entries[index].PrevHash = previous
		hash, err := swarmJournalEntryHash(entries[index])
		if err != nil {
			t.Fatal(err)
		}
		entries[index].Hash = hash
		previous = hash
	}
}
