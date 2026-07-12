package managedkey

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type generationIdentityFixture struct {
	Descriptor map[string]any
	Key        ed25519.PrivateKey
}

func signGenerationMap(t *testing.T, key ed25519.PrivateKey, body map[string]any, signatureKey string) map[string]any {
	t.Helper()
	data, err := canonicalJSON(body)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]any{}
	for name, value := range body {
		out[name] = value
	}
	out[signatureKey] = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, data))
	return out
}

func generationAgent(t *testing.T, start byte, alias string) generationIdentityFixture {
	t.Helper()
	key := ed25519.NewKeyFromSeed(testSeed(start))
	spki, err := x509.MarshalPKIXPublicKey(key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	aid := generationIdentityValue(t, IdentityAID, spki)
	body := map[string]any{"alias": alias, "aid": aid, "public_key_spki": base64.RawURLEncoding.EncodeToString(spki)}
	return generationIdentityFixture{Descriptor: signGenerationMap(t, key, body, "descriptor_signature"), Key: key}
}

func generationZone(t *testing.T, start byte, name string) generationIdentityFixture {
	t.Helper()
	key := ed25519.NewKeyFromSeed(testSeed(start))
	spki, err := x509.MarshalPKIXPublicKey(key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	zid := generationIdentityValue(t, IdentityZID, spki)
	body := map[string]any{"name": name, "zid": zid, "public_key_spki": base64.RawURLEncoding.EncodeToString(spki)}
	return generationIdentityFixture{Descriptor: signGenerationMap(t, key, body, "zone_signature"), Key: key}
}

func generationIdentityValue(t *testing.T, kind string, spki []byte) string {
	t.Helper()
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

type generationChainFixture struct {
	Previous     generationIdentityFixture
	Next         generationIdentityFixture
	Zone         generationIdentityFixture
	Envelopes    [][]byte
	Records      []GenerationRecord
	ZoneEnvelope []byte
	ZoneRecord   GenerationRecord
}

func newGenerationChainFixture(t *testing.T) generationChainFixture {
	t.Helper()
	previous := generationAgent(t, 0, "agent://u9/worker")
	next := generationAgent(t, 64, "agent://u9/worker")
	zone := generationZone(t, 128, "zone://u9")
	previousPlaintext := testPKCS8(testSeed(0))
	nextPlaintext := testPKCS8(testSeed(64))
	previousIdentity := Identity{Kind: IdentityAID, Value: previous.Descriptor["aid"].(string)}
	zonePlaintext := testPKCS8(testSeed(128))
	zoneIdentity := Identity{Kind: IdentityZID, Value: zone.Descriptor["zid"].(string)}
	zoneEnvelope, err := SealEnvelope(SealOptions{KeyType: KeyTypePKCS8, Plaintext: zonePlaintext, Identity: zoneIdentity, Passphrase: testPassphrase, Iterations: 100000})
	if err != nil {
		t.Fatal(err)
	}
	zoneBody, err := BuildGenerationBody(GenerationBodyOptions{Identity: zoneIdentity, Generation: 1, Operation: GenerationMigrate, EnvelopeBytes: zoneEnvelope, Descriptor: zone.Descriptor})
	if err != nil {
		t.Fatal(err)
	}
	zoneRecord, err := NewSignedGenerationRecord(zoneBody, zone.Key)
	if err != nil {
		t.Fatal(err)
	}
	nextIdentity := Identity{Kind: IdentityAID, Value: next.Descriptor["aid"].(string)}
	envelope1, err := SealEnvelope(SealOptions{KeyType: KeyTypePKCS8, Plaintext: previousPlaintext, Identity: previousIdentity, Passphrase: testPassphrase, Iterations: 100000})
	if err != nil {
		t.Fatal(err)
	}
	body1, err := BuildGenerationBody(GenerationBodyOptions{Identity: previousIdentity, Generation: 1, Operation: GenerationMigrate, EnvelopeBytes: envelope1, Descriptor: previous.Descriptor})
	if err != nil {
		t.Fatal(err)
	}
	record1, err := NewSignedGenerationRecord(body1, previous.Key)
	if err != nil {
		t.Fatal(err)
	}
	envelope2, err := SealEnvelope(SealOptions{KeyType: KeyTypePKCS8, Plaintext: previousPlaintext, Identity: previousIdentity, Passphrase: testPassphrase, Iterations: 100001})
	if err != nil {
		t.Fatal(err)
	}
	body2, err := BuildGenerationBody(GenerationBodyOptions{Identity: previousIdentity, Generation: 2, Operation: GenerationRewrap, EnvelopeBytes: envelope2, Descriptor: previous.Descriptor, PreviousRecord: &record1})
	if err != nil {
		t.Fatal(err)
	}
	record2, err := NewSignedGenerationRecord(body2, previous.Key)
	if err != nil {
		t.Fatal(err)
	}
	envelope3, err := SealEnvelope(SealOptions{KeyType: KeyTypePKCS8, Plaintext: nextPlaintext, Identity: nextIdentity, Passphrase: testPassphrase, Iterations: 100000})
	if err != nil {
		t.Fatal(err)
	}
	body3, err := BuildGenerationBody(GenerationBodyOptions{Identity: nextIdentity, Generation: 3, Operation: GenerationRotate, EnvelopeBytes: envelope3, Descriptor: next.Descriptor, PreviousRecord: &record2})
	if err != nil {
		t.Fatal(err)
	}
	record3, err := NewRotationGenerationRecord(body3, previous.Descriptor, next.Descriptor, previous.Key, next.Key, zone.Descriptor, zone.Key, KeyGenerationRef{IdentityKind: IdentityZID, IdentityValue: zone.Descriptor["zid"].(string), Generation: 1, RecordDigest: zoneRecord.RecordDigest, EnvelopeSHA256: zoneBody.EnvelopeSHA256, DescriptorDigest: zoneBody.DescriptorDigest})
	if err != nil {
		t.Fatal(err)
	}
	return generationChainFixture{Previous: previous, Next: next, Zone: zone, Envelopes: [][]byte{envelope1, envelope2, envelope3}, Records: []GenerationRecord{record1, record2, record3}, ZoneEnvelope: zoneEnvelope, ZoneRecord: zoneRecord}
}

func generationContext(fixture generationChainFixture, index int) GenerationVerificationContext {
	record := fixture.Records[index]
	context := GenerationVerificationContext{EnvelopeBytes: fixture.Envelopes[index], Descriptor: fixture.Previous.Descriptor, ActivePointer: &GenerationPointer{Generation: record.Body.Generation, RecordDigest: record.RecordDigest}}
	if index > 0 {
		context.PreviousRecord = &fixture.Records[index-1]
	}
	if index == 2 {
		context.Descriptor = fixture.Next.Descriptor
		context.PreviousDescriptor = fixture.Previous.Descriptor
		context.ZoneGeneration = fixture.ZoneRecord.Body.Generation
		context.ZoneRecordDigest = fixture.ZoneRecord.RecordDigest
		context.ZoneDescriptor = fixture.Zone.Descriptor
	}
	return context
}

func TestGenerationAuthenticatesMigrateRewrapRotateChain(t *testing.T) {
	fixture := newGenerationChainFixture(t)
	for index, record := range fixture.Records {
		if RecordDigest(record.Body) != record.RecordDigest {
			t.Fatalf("digest mismatch")
		}
		if _, err := VerifyGenerationRecord(record, generationContext(fixture, index)); err != nil {
			t.Fatal(err)
		}
	}
	verified, err := VerifyGenerationChain(fixture.Records, fixture.Envelopes, GenerationChainContext{
		Descriptors:         []map[string]any{fixture.Previous.Descriptor, fixture.Previous.Descriptor, fixture.Next.Descriptor},
		PreviousDescriptors: []map[string]any{nil, nil, fixture.Previous.Descriptor},
		ZoneDescriptors:     []map[string]any{nil, nil, fixture.Zone.Descriptor},
		ActivePointer:       &GenerationPointer{Generation: 3, RecordDigest: fixture.Records[2].RecordDigest},
	})
	if err != nil || len(verified) != 3 {
		t.Fatalf("verified=%v err=%v", verified, err)
	}
	if err := VerifyGenerationRebinding(fixture.Records[2].GenerationRebinding, GenerationRebindingContext{ZoneDescriptor: fixture.Zone.Descriptor, PreviousDescriptor: fixture.Previous.Descriptor, NextDescriptor: fixture.Next.Descriptor, Generation: 3, RecordDigest: fixture.Records[2].RecordDigest}); err != nil {
		t.Fatal(err)
	}
}

func TestGenerationRejectsMalformedAndSubstitutedChains(t *testing.T) {
	fixture := newGenerationChainFixture(t)
	canonicalRecord, err := CanonicalGenerationRecord(fixture.Records[0])
	if err != nil {
		t.Fatal(err)
	}
	duplicate := bytes.Replace(canonicalRecord, []byte(`"record_digest":`), []byte(`"record_digest":"`+strings.Repeat("0", 64)+`","record_digest":`), 1)
	if _, err := ParseGenerationRecord(duplicate); err == nil || !strings.Contains(err.Error(), "duplicate JSON key: record_digest") {
		t.Fatalf("duplicate err=%v", err)
	}
	var value map[string]any
	if err := json.Unmarshal(canonicalRecord, &value); err != nil {
		t.Fatal(err)
	}
	value["extra"] = true
	unknown, _ := json.Marshal(value)
	if _, err := ParseGenerationRecord(unknown); err == nil || !strings.Contains(err.Error(), "generation record fields invalid") {
		t.Fatalf("unknown err=%v", err)
	}
	for _, generation := range []any{float64(0), 1.5, float64(9007199254740992)} {
		var mutated map[string]any
		if err := json.Unmarshal(canonicalRecord, &mutated); err != nil {
			t.Fatal(err)
		}
		mutated["body"].(map[string]any)["generation"] = generation
		encoded, err := json.Marshal(mutated)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseGenerationRecord(encoded); err == nil {
			t.Fatalf("generation %v accepted", generation)
		}
	}
	wrongPrevious := fixture.Records[0]
	wrongPrevious.RecordDigest = strings.Repeat("0", 64)
	context := generationContext(fixture, 1)
	context.PreviousRecord = &wrongPrevious
	if _, err := VerifyGenerationRecord(fixture.Records[1], context); err == nil || !strings.Contains(err.Error(), "previous record digest mismatch") {
		t.Fatalf("previous err=%v", err)
	}
	context = generationContext(fixture, 1)
	context.ActivePointer = &GenerationPointer{Generation: 1, RecordDigest: fixture.Records[0].RecordDigest}
	if _, err := VerifyGenerationRecord(fixture.Records[1], context); err == nil || !strings.Contains(err.Error(), "active pointer mismatch") {
		t.Fatalf("pointer err=%v", err)
	}
	context = generationContext(fixture, 1)
	context.Descriptor = fixture.Next.Descriptor
	if _, err := VerifyGenerationRecord(fixture.Records[1], context); err == nil {
		t.Fatal("descriptor substitution accepted")
	}
	context = generationContext(fixture, 2)
	substitutedPreviousDescriptor := cloneGenerationMap(fixture.Previous.Descriptor)
	substitutedPreviousDescriptor["policy"] = "substituted"
	delete(substitutedPreviousDescriptor, "descriptor_signature")
	substitutedPreviousDescriptor = signGenerationMap(t, fixture.Previous.Key, substitutedPreviousDescriptor, "descriptor_signature")
	substitutedRotation := fixture.Records[2]
	substitutedRotation.PreviousDescriptor = substitutedPreviousDescriptor
	context.PreviousDescriptor = substitutedPreviousDescriptor
	if _, err := VerifyGenerationRecord(substitutedRotation, context); err == nil || !strings.Contains(err.Error(), "previous descriptor digest mismatch") {
		t.Fatalf("previous descriptor substitution err=%v", err)
	}
	malformedRotationProof := fixture.Records[2]
	malformedRotationProof.AgentRotationProof = cloneGenerationMap(malformedRotationProof.AgentRotationProof)
	malformedRotationProof.AgentRotationProof["previous_signature"] = json.Number("1")
	if _, err := VerifyGenerationRecord(malformedRotationProof, generationContext(fixture, 2)); err == nil {
		t.Fatal("malformed rotation proof signature accepted")
	}
	if _, err := VerifyGenerationChain([]GenerationRecord{fixture.Records[0], fixture.Records[1], fixture.Records[1]}, [][]byte{fixture.Envelopes[0], fixture.Envelopes[1], fixture.Envelopes[1]}, GenerationChainContext{Descriptors: []map[string]any{fixture.Previous.Descriptor, fixture.Previous.Descriptor, fixture.Previous.Descriptor}}); err == nil {
		t.Fatal("replay accepted")
	}
	missing := fixture.Records[0]
	missing.IdentitySignature = ""
	if _, err := VerifyGenerationRecord(missing, generationContext(fixture, 0)); err == nil {
		t.Fatal("missing signature accepted")
	}
	legacy := map[string]any{"zone": fixture.Zone.Descriptor["zid"], "alias": fixture.Previous.Descriptor["alias"], "previous_aid": fixture.Previous.Descriptor["aid"], "next_aid": fixture.Next.Descriptor["aid"], "zone_signature": "bad"}
	if err := VerifyGenerationRebinding(legacy, GenerationRebindingContext{ZoneDescriptor: fixture.Zone.Descriptor, PreviousDescriptor: fixture.Previous.Descriptor, NextDescriptor: fixture.Next.Descriptor, Generation: 3, RecordDigest: fixture.Records[2].RecordDigest}); err == nil {
		t.Fatal("legacy rebinding accepted")
	}
}

type generationVector struct {
	Format string `json:"format"`
	Cases  []struct {
		Origin        string            `json:"origin"`
		ActivePointer GenerationPointer `json:"active_pointer"`
		Records       []struct {
			Canonical          string         `json:"canonical"`
			Envelope           string         `json:"envelope"`
			Descriptor         map[string]any `json:"descriptor"`
			PreviousDescriptor map[string]any `json:"previous_descriptor"`
			ZoneDescriptor     map[string]any `json:"zone_descriptor"`
		} `json:"records"`
	} `json:"cases"`
}

func TestGenerationFrozenNodeAndGoVectorsCrossVerify(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "test-vectors", "agnet-key-generation-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector generationVector
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	if vector.Format != "agnet-key-generation-test-v1" || len(vector.Cases) != 2 || vector.Cases[0].Origin != "node-created" || vector.Cases[1].Origin != "go-created" {
		t.Fatalf("vector header invalid")
	}
	for _, item := range vector.Cases {
		t.Run(item.Origin, func(t *testing.T) {
			records := make([]GenerationRecord, len(item.Records))
			envelopes := make([][]byte, len(item.Records))
			descriptors := make([]map[string]any, len(item.Records))
			previousDescriptors := make([]map[string]any, len(item.Records))
			zoneDescriptors := make([]map[string]any, len(item.Records))
			for index, entry := range item.Records {
				record, err := ParseGenerationRecord([]byte(entry.Canonical))
				if err != nil {
					t.Fatal(err)
				}
				records[index] = record
				envelopes[index], err = base64.RawURLEncoding.DecodeString(entry.Envelope)
				if err != nil {
					t.Fatal(err)
				}
				descriptors[index] = entry.Descriptor
				previousDescriptors[index] = entry.PreviousDescriptor
				zoneDescriptors[index] = entry.ZoneDescriptor
			}
			verified, err := VerifyGenerationChain(records, envelopes, GenerationChainContext{Descriptors: descriptors, PreviousDescriptors: previousDescriptors, ZoneDescriptors: zoneDescriptors, ActivePointer: &item.ActivePointer})
			if err != nil || verified[len(verified)-1].RecordDigest != item.ActivePointer.RecordDigest {
				t.Fatalf("verified=%v err=%v", verified, err)
			}
		})
	}
}

func TestGenerationVectorDigestHelpers(t *testing.T) {
	fixture := newGenerationChainFixture(t)
	data, err := CanonicalGenerationRecord(fixture.Records[2])
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(data)
	if hex.EncodeToString(hash[:]) == "" {
		t.Fatal("empty digest")
	}
}
