package managedkey

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeLifecycleRestricted(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeLifecycleDescriptor(t *testing.T, path string, descriptor map[string]any) {
	t.Helper()
	data, err := canonicalJSON(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	writeLifecycleRestricted(t, path, data)
}

func newLifecycleStore(t *testing.T) *Store {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestMigratePreservesGoSeedAndIdentity(t *testing.T) {
	store := newLifecycleStore(t)
	identity := generationAgent(t, 0, "agent://u11/seed")
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.seed")
	descriptorPath := filepath.Join(dir, "descriptor.json")
	passphrasePath := filepath.Join(dir, "passphrase")
	seed := testSeed(0)
	passphrase := []byte("u11 raw passphrase\n")
	writeLifecycleRestricted(t, keyPath, seed)
	writeLifecycleDescriptor(t, descriptorPath, identity.Descriptor)
	writeLifecycleRestricted(t, passphrasePath, passphrase)

result, err := Migrate(MigrateOptions{Store: store, SourceKeyPath: keyPath, SourceKeyType: KeyTypeSeed, IdentityKind: IdentityAID, DescriptorPath: descriptorPath, PassphrasePath: passphrasePath, Iterations: 100000})
	if err != nil {
		t.Fatal(err)
	}
	if result.Operation != GenerationMigrate || result.Generation != 1 || result.IdentityValue != identity.Descriptor["aid"] {
		t.Fatalf("result=%+v", result)
	}
	loaded, err := store.LoadActive(passphrase)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(loaded.Plaintext)
	if loaded.KeyType != KeyTypeSeed || !bytes.Equal(loaded.Plaintext, seed) || loaded.Identity.Value != result.IdentityValue {
		t.Fatalf("loaded=%+v", loaded.KeyGeneration)
	}
}

func TestMigratePreservesNodePKCS8(t *testing.T) {
	store := newLifecycleStore(t)
	identity := generationAgent(t, 1, "agent://u11/pkcs8")
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.pkcs8")
	descriptorPath := filepath.Join(dir, "descriptor.json")
	passphrasePath := filepath.Join(dir, "passphrase")
	plaintext := testPKCS8(testSeed(1))
	passphrase := []byte("node interop passphrase\n")
	writeLifecycleRestricted(t, keyPath, plaintext)
	writeLifecycleDescriptor(t, descriptorPath, identity.Descriptor)
	writeLifecycleRestricted(t, passphrasePath, passphrase)

result, err := Migrate(MigrateOptions{Store: store, SourceKeyPath: keyPath, SourceKeyType: KeyTypePKCS8, IdentityKind: IdentityAID, DescriptorPath: descriptorPath, PassphrasePath: passphrasePath, Iterations: 100000})
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := store.LoadActive(passphrase)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(loaded.Plaintext)
	if result.IdentityValue != identity.Descriptor["aid"] || loaded.KeyType != KeyTypePKCS8 || !bytes.Equal(loaded.Plaintext, plaintext) {
		t.Fatalf("result=%+v loaded=%+v", result, loaded.KeyGeneration)
	}
}

func TestRewrapPreservesRawKeyAndUsesFreshMaterial(t *testing.T) {
	store := newLifecycleStore(t)
	identity := generationAgent(t, 2, "agent://u11/rewrap")
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.seed")
	descriptorPath := filepath.Join(dir, "descriptor.json")
	oldPassphrasePath := filepath.Join(dir, "old-passphrase")
	newPassphrasePath := filepath.Join(dir, "new-passphrase")
	seed := testSeed(2)
	oldPassphrase := []byte("old raw passphrase\n")
	newPassphrase := []byte("new raw passphrase\n")
	writeLifecycleRestricted(t, keyPath, seed)
	writeLifecycleDescriptor(t, descriptorPath, identity.Descriptor)
	writeLifecycleRestricted(t, oldPassphrasePath, oldPassphrase)
	writeLifecycleRestricted(t, newPassphrasePath, newPassphrase)
	if _, err := Migrate(MigrateOptions{Store: store, SourceKeyPath: keyPath, SourceKeyType: KeyTypeSeed, IdentityKind: IdentityAID, DescriptorPath: descriptorPath, PassphrasePath: oldPassphrasePath, Iterations: 100000}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(storeGenerationFile(store.path, 1, "envelope"))
	if err != nil {
		t.Fatal(err)
	}
	beforeEnvelope, err := ParseEnvelope(before)
	if err != nil {
		t.Fatal(err)
	}

result, err := Rewrap(RewrapOptions{Store: store, IdentityKind: IdentityAID, DescriptorPath: descriptorPath, PassphrasePath: oldPassphrasePath, NewPassphrasePath: newPassphrasePath, Iterations: 100001})
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(storeGenerationFile(store.path, 2, "envelope"))
	if err != nil {
		t.Fatal(err)
	}
	afterEnvelope, err := ParseEnvelope(after)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := store.LoadActive(newPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(loaded.Plaintext)
	if result.Operation != GenerationRewrap || result.Generation != 2 || result.IdentityValue != identity.Descriptor["aid"] || !bytes.Equal(loaded.Plaintext, seed) || loaded.Identity.Value != identity.Descriptor["aid"] {
		t.Fatalf("result=%+v loaded=%+v", result, loaded.KeyGeneration)
	}
	if beforeEnvelope.KDF.Salt == afterEnvelope.KDF.Salt || beforeEnvelope.Cipher.Nonce == afterEnvelope.Cipher.Nonce {
		t.Fatal("rewrap reused KDF material")
	}
	if _, err := store.LoadActive(oldPassphrase); err == nil {
		t.Fatal("old passphrase still opened rewrapped key")
	}
}

func TestMigrateRejectsPopulatedStoreAndDescriptorMismatch(t *testing.T) {
	store := newLifecycleStore(t)
	identity := generationAgent(t, 3, "agent://u11/first")
	other := generationAgent(t, 4, "agent://u11/other")
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.seed")
	descriptorPath := filepath.Join(dir, "descriptor.json")
	passphrasePath := filepath.Join(dir, "passphrase")
	writeLifecycleRestricted(t, keyPath, testSeed(3))
	writeLifecycleRestricted(t, passphrasePath, []byte("passphrase\n"))
	writeLifecycleDescriptor(t, descriptorPath, other.Descriptor)
	if _, err := Migrate(MigrateOptions{Store: store, SourceKeyPath: keyPath, SourceKeyType: KeyTypeSeed, IdentityKind: IdentityAID, DescriptorPath: descriptorPath, PassphrasePath: passphrasePath, Iterations: 100000}); err == nil {
		t.Fatal("descriptor mismatch accepted")
	}
	writeLifecycleDescriptor(t, descriptorPath, identity.Descriptor)
	if _, err := Migrate(MigrateOptions{Store: store, SourceKeyPath: keyPath, SourceKeyType: KeyTypeSeed, IdentityKind: IdentityAID, DescriptorPath: descriptorPath, PassphrasePath: passphrasePath, Iterations: 100000}); err != nil {
		t.Fatal(err)
	}
	if _, err := Migrate(MigrateOptions{Store: store, SourceKeyPath: keyPath, SourceKeyType: KeyTypeSeed, IdentityKind: IdentityAID, DescriptorPath: descriptorPath, PassphrasePath: passphrasePath, Iterations: 100000}); err == nil {
		t.Fatal("populated store accepted migration")
	}
}

func TestRecoverDelegatesWithoutMintingRecord(t *testing.T) {
	store := newLifecycleStore(t)
	identity := generationAgent(t, 5, "agent://u11/recover")
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.seed")
	descriptorPath := filepath.Join(dir, "descriptor.json")
	passphrasePath := filepath.Join(dir, "passphrase")
	passphrase := []byte("recover passphrase\n")
	writeLifecycleRestricted(t, keyPath, testSeed(5))
	writeLifecycleDescriptor(t, descriptorPath, identity.Descriptor)
	writeLifecycleRestricted(t, passphrasePath, passphrase)
	migrated, err := Migrate(MigrateOptions{Store: store, SourceKeyPath: keyPath, SourceKeyType: KeyTypeSeed, IdentityKind: IdentityAID, DescriptorPath: descriptorPath, PassphrasePath: passphrasePath, Iterations: 100000})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(store.path, "active.json")); err != nil {
		t.Fatal(err)
	}
	result, err := Recover(RecoverOptions{Store: store, PassphrasePath: passphrasePath})
	if err != nil {
		t.Fatal(err)
	}
	if result.Operation != "recover" || result.Generation != migrated.Generation || result.RecordDigest != migrated.RecordDigest {
		t.Fatalf("result=%+v migrated=%+v", result, migrated)
	}
	if _, err := os.Stat(storeGenerationFile(store.path, 2, "record")); !os.IsNotExist(err) {
		t.Fatalf("recover minted a record: %v", err)
	}
}

func TestMigrateRejectsCrashPartialStoreWithoutAutoRecovery(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(root, &StoreOptions{Fault: func(point string) error {
		if point == "commit-after-rename" {
			return errors.New("simulated crash")
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	identity := generationAgent(t, 6, "agent://u11/crash")
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.seed")
	descriptorPath := filepath.Join(dir, "descriptor.json")
	passphrasePath := filepath.Join(dir, "passphrase")
	writeLifecycleRestricted(t, keyPath, testSeed(6))
	writeLifecycleDescriptor(t, descriptorPath, identity.Descriptor)
	writeLifecycleRestricted(t, passphrasePath, []byte("crash passphrase\n"))
	options := MigrateOptions{Store: store, SourceKeyPath: keyPath, SourceKeyType: KeyTypeSeed, IdentityKind: IdentityAID, DescriptorPath: descriptorPath, PassphrasePath: passphrasePath, Iterations: 100000}
	if _, err := Migrate(options); err == nil {
		t.Fatal("crashed install accepted")
	}
	cleanStore, err := OpenStore(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	options.Store = cleanStore
	if _, err := Migrate(options); err == nil {
		t.Fatal("partial store was automatically migrated")
	}
	if _, err := Recover(RecoverOptions{Store: cleanStore, PassphrasePath: passphrasePath}); err == nil {
		t.Fatal("incomplete generation recovered")
	}
}

func rotateMigrateFixture(t *testing.T, store *Store, fixture generationIdentityFixture, kind string, seed byte, passphrase []byte) string {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key")
	descriptorPath := filepath.Join(dir, "descriptor.json")
	passphrasePath := filepath.Join(dir, "passphrase")
	writeLifecycleRestricted(t, keyPath, testSeed(seed))
	writeLifecycleDescriptor(t, descriptorPath, fixture.Descriptor)
	writeLifecycleRestricted(t, passphrasePath, passphrase)
	if _, err := Migrate(MigrateOptions{Store: store, SourceKeyPath: keyPath, SourceKeyType: KeyTypeSeed, IdentityKind: kind, DescriptorPath: descriptorPath, PassphrasePath: passphrasePath, Iterations: 100000}); err != nil {
		t.Fatal(err)
	}
	return passphrasePath
}

func TestRotateAgentPreservesProfileAndBindsActiveZoneGeneration(t *testing.T) {
	agentStore := newLifecycleStore(t)
	zoneStore := newLifecycleStore(t)
	agent := generationAgent(t, 20, "agent://u12/rotate")
	agent.Descriptor["transports"] = []any{"asp+local://u12"}
	agent.Descriptor["capabilities"] = []any{"summarize.text"}
	agent.Descriptor["policy"] = map[string]any{"allow_network": false}
	delete(agent.Descriptor, "descriptor_signature")
	agent.Descriptor = signGenerationMap(t, agent.Key, agent.Descriptor, "descriptor_signature")
	zone := generationZone(t, 60, "zone://u12/rotate")
	agentPassphrase := []byte("u12 agent passphrase\n")
	zonePassphrase := []byte("u12 zone passphrase\n")
	agentPassphrasePath := rotateMigrateFixture(t, agentStore, agent, IdentityAID, 20, agentPassphrase)
	zonePassphrasePath := rotateMigrateFixture(t, zoneStore, zone, IdentityZID, 60, zonePassphrase)

	result, err := RotateAgent(RotateAgentOptions{Store: agentStore, ZoneStore: zoneStore, PassphrasePath: agentPassphrasePath, ZonePassphrasePath: zonePassphrasePath, Iterations: 100000, Entropy: bytes.NewReader(testSeed(21))})
	if err != nil {
		t.Fatal(err)
	}
	if result.Operation != GenerationRotate || result.Generation != 2 || result.IdentityValue == agent.Descriptor["aid"] {
		t.Fatalf("result=%+v", result)
	}
	loaded, err := agentStore.LoadActive(agentPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	defer clearLoadedIdentity(&loaded)
	if loaded.Identity.Value != result.IdentityValue || loaded.KeyGeneration.Generation != 2 {
		t.Fatalf("loaded=%+v", loaded)
	}
	active, err := activeStoreGeneration(agentStore, loaded.KeyGeneration)
	if err != nil {
		t.Fatal(err)
	}
	if active.descriptor["alias"] != agent.Descriptor["alias"] || !generationMapsEqual(active.descriptor["policy"].(map[string]any), agent.Descriptor["policy"].(map[string]any)) || !generationMapsEqual(map[string]any{"transports": active.descriptor["transports"], "capabilities": active.descriptor["capabilities"]}, map[string]any{"transports": agent.Descriptor["transports"], "capabilities": agent.Descriptor["capabilities"]}) {
		t.Fatalf("profile drifted: %v", active.descriptor)
	}
	zoneGeneration, err := exactInteger(active.record.GenerationRebinding["zone_generation"], "zone generation")
	if err != nil || zoneGeneration != 1 || active.record.GenerationRebinding["zone_record_digest"] == "" {
		t.Fatalf("rebinding=%v err=%v", active.record.GenerationRebinding, err)
	}
	if _, err := os.Stat(storeGenerationFile(agentStore.path, 2, "zone-record")); err != nil {
		t.Fatalf("persisted Zone authorization record missing: %v", err)
	}
}

func TestRotateAgentRejectsZoneTargetAndReusedAIDWithoutWrites(t *testing.T) {
	agentStore := newLifecycleStore(t)
	zoneStore := newLifecycleStore(t)
	agent := generationAgent(t, 30, "agent://u12/reject")
	zone := generationZone(t, 70, "zone://u12/reject")
	agentPassphrase := []byte("u12 reject agent\n")
	zonePassphrase := []byte("u12 reject zone\n")
	agentPassphrasePath := rotateMigrateFixture(t, agentStore, agent, IdentityAID, 30, agentPassphrase)
	zonePassphrasePath := rotateMigrateFixture(t, zoneStore, zone, IdentityZID, 70, zonePassphrase)
	if _, err := RotateAgent(RotateAgentOptions{Store: zoneStore, ZoneStore: zoneStore, PassphrasePath: zonePassphrasePath, ZonePassphrasePath: zonePassphrasePath, Iterations: 100000}); err == nil {
		t.Fatal("Zone target accepted rotation")
	}
	zoneLoaded, err := zoneStore.LoadActive(zonePassphrase)
	if err != nil {
		t.Fatal(err)
	}
	clearLoadedIdentity(&zoneLoaded)
	if zoneLoaded.KeyGeneration.Generation != 1 {
		t.Fatal("Zone target wrote a generation")
	}
	if _, err := RotateAgent(RotateAgentOptions{Store: agentStore, ZoneStore: zoneStore, PassphrasePath: agentPassphrasePath, ZonePassphrasePath: zonePassphrasePath, Iterations: 100000, Entropy: bytes.NewReader(testSeed(30))}); err == nil {
		t.Fatal("reused AID accepted")
	}
	loaded, err := agentStore.LoadActive(agentPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	defer clearLoadedIdentity(&loaded)
	if loaded.KeyGeneration.Generation != 1 {
		t.Fatal("reused AID wrote a generation")
	}
}

func TestRotateVerificationRejectsSwappedSignaturesAndZoneReference(t *testing.T) {
	fixture := newGenerationChainFixture(t)
	context := generationContext(fixture, 2)
	context.ZoneGeneration = 1
	context.ZoneRecordDigest = strings.Repeat("0", 64)
	missing := fixture.Records[2]
	missing.AgentRotationProof = cloneGenerationMap(missing.AgentRotationProof)
	missing.AgentRotationProof["previous_signature"] = ""
	if _, err := VerifyGenerationRecord(missing, context); err == nil {
		t.Fatal("missing rotation signature accepted")
	}
	swapped := fixture.Records[2]
	swapped.AgentRotationProof = cloneGenerationMap(swapped.AgentRotationProof)
	swapped.AgentRotationProof["previous_signature"], swapped.AgentRotationProof["next_signature"] = swapped.AgentRotationProof["next_signature"], swapped.AgentRotationProof["previous_signature"]
	if _, err := VerifyGenerationRecord(swapped, context); err == nil {
		t.Fatal("swapped rotation signatures accepted")
	}
	wrongZone := context
	wrongZone.ZoneGeneration = 2
	if _, err := VerifyGenerationRecord(fixture.Records[2], wrongZone); err == nil {
		t.Fatal("wrong Zone generation accepted")
	}
	legacy := fixture.Records[2]
	legacy.GenerationRebinding = cloneGenerationMap(legacy.GenerationRebinding)
	delete(legacy.GenerationRebinding, "zone_generation")
	delete(legacy.GenerationRebinding, "zone_record_digest")
	if _, err := VerifyGenerationRecord(legacy, context); err == nil {
		t.Fatal("legacy Zone authorization accepted")
	}
}

func TestRotateAgentRejectsRevokedZoneWithoutAgentWrite(t *testing.T) {
	agentStore := newLifecycleStore(t)
	zoneStore := newLifecycleStore(t)
	agent := generationAgent(t, 40, "agent://u12/revoked")
	zone := generationZone(t, 80, "zone://u12/revoked")
	zone.Descriptor["revoked"] = true
	delete(zone.Descriptor, "zone_signature")
	zone.Descriptor = signGenerationMap(t, zone.Key, zone.Descriptor, "zone_signature")
	agentPassphrase := []byte("u12 revoked agent\n")
	zonePassphrase := []byte("u12 revoked zone\n")
	agentPassphrasePath := rotateMigrateFixture(t, agentStore, agent, IdentityAID, 40, agentPassphrase)
	zonePassphrasePath := rotateMigrateFixture(t, zoneStore, zone, IdentityZID, 80, zonePassphrase)
	if _, err := RotateAgent(RotateAgentOptions{Store: agentStore, ZoneStore: zoneStore, PassphrasePath: agentPassphrasePath, ZonePassphrasePath: zonePassphrasePath, Iterations: 100000}); err == nil {
		t.Fatal("revoked Zone authorized rotation")
	}
	loaded, err := agentStore.LoadActive(agentPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	defer clearLoadedIdentity(&loaded)
	if loaded.KeyGeneration.Generation != 1 {
		t.Fatal("revoked Zone attempt wrote Agent generation")
	}
}

func TestRotateNodeArtifactVerifiesInGo(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "test-vectors", "agnet-key-rotation-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Format string `json:"format"`
		Cases  []struct {
			Origin        string            `json:"origin"`
			ActivePointer GenerationPointer `json:"active_pointer"`
			Zone          struct {
				ActivePointer GenerationPointer `json:"active_pointer"`
				Canonical     string            `json:"canonical"`
				Envelope      string            `json:"envelope"`
				Descriptor    map[string]any    `json:"descriptor"`
			} `json:"zone"`
			Records []struct {
				Canonical          string          `json:"canonical"`
				Envelope           string          `json:"envelope"`
				Descriptor         map[string]any  `json:"descriptor"`
				PreviousDescriptor map[string]any  `json:"previous_descriptor"`
				ZoneDescriptor     map[string]any  `json:"zone_descriptor"`
				ZoneRecord         json.RawMessage `json:"zone_record"`
			} `json:"records"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	if vector.Format != "agnet-key-rotation-test-v1" || len(vector.Cases) != 2 || vector.Cases[0].Origin != "node-created" || vector.Cases[1].Origin != "go-created" {
		t.Fatalf("vector header=%+v", vector)
	}
	for _, item := range vector.Cases {
		zoneEnvelope, err := decodeBase64URLExact(item.Zone.Envelope, "Zone envelope")
		if err != nil {
			t.Fatal(err)
		}
		zoneRecord, err := ParseGenerationRecord([]byte(item.Zone.Canonical))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyGenerationRecord(zoneRecord, GenerationVerificationContext{EnvelopeBytes: zoneEnvelope, Descriptor: item.Zone.Descriptor, ActivePointer: &item.Zone.ActivePointer}); err != nil {
			t.Fatalf("Node Zone record rejected: %v", err)
		}
		var previous *GenerationRecord
		for index, entry := range item.Records {
			envelope, err := decodeBase64URLExact(entry.Envelope, "Agent envelope")
			if err != nil {
				t.Fatal(err)
			}
			record, err := ParseGenerationRecord([]byte(entry.Canonical))
			if err != nil {
				t.Fatal(err)
			}
			context := GenerationVerificationContext{EnvelopeBytes: envelope, Descriptor: entry.Descriptor, PreviousRecord: previous}
			if index == len(item.Records)-1 {
				context.ActivePointer = &item.ActivePointer
			}
			if record.Body.Operation == GenerationRotate {
				zoneRecordFromRotation, err := ParseGenerationRecord(entry.ZoneRecord)
				if err != nil || zoneRecordFromRotation.RecordDigest != item.Zone.ActivePointer.RecordDigest || zoneRecordFromRotation.Body.Generation != item.Zone.ActivePointer.Generation {
					t.Fatalf("Node Zone authorization record mismatch: %v", err)
				}
				context.PreviousDescriptor = entry.PreviousDescriptor
				context.ZoneDescriptor = entry.ZoneDescriptor
				context.ZoneGeneration = item.Zone.ActivePointer.Generation
				context.ZoneRecordDigest = item.Zone.ActivePointer.RecordDigest
			}
			verified, err := VerifyGenerationRecord(record, context)
			if err != nil {
				t.Fatalf("Node Agent record %d rejected: %v", index, err)
			}
			previous = &verified
		}
	}
}
