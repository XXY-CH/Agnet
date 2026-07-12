package managedkey

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func storeItem(fixture generationChainFixture, index int) InstallRequest {
	item := InstallRequest{EnvelopeBytes: fixture.Envelopes[index], Record: fixture.Records[index], Descriptor: fixture.Previous.Descriptor, Passphrase: testPassphrase}
	if index == 2 {
		item.Descriptor = fixture.Next.Descriptor
		item.PreviousDescriptor = fixture.Previous.Descriptor
		item.ZoneDescriptor = fixture.Zone.Descriptor
		item.ZoneRecord = fixture.ZoneRecord
	}
	return item
}

func storeGenerationFile(root string, generation int, suffix string) string {
	return filepath.Join(root, "generations", leftPadGeneration(generation)+"."+suffix+".json")
}

func leftPadGeneration(generation int) string {
	value := ""
	for n := generation; n > 0; n /= 10 {
		value = string(rune('0'+n%10)) + value
	}
	if value == "" {
		value = "0"
	}
	return strings.Repeat("0", 16-len(value)) + value
}

func writeRawStoreGeneration(t *testing.T, root string, request InstallRequest) {
	t.Helper()
	generation := request.Record.Body.Generation
	files := map[string][]byte{"envelope": request.EnvelopeBytes}
	recordBytes, err := CanonicalGenerationRecord(request.Record)
	if err != nil {
		t.Fatal(err)
	}
	files["record"] = recordBytes
	descriptorBytes, err := canonicalJSON(request.Descriptor)
	if err != nil {
		t.Fatal(err)
	}
	files["descriptor"] = descriptorBytes
	if request.PreviousDescriptor != nil {
		previousBytes, err := canonicalJSON(request.PreviousDescriptor)
		if err != nil {
			t.Fatal(err)
		}
		files["previous-descriptor"] = previousBytes
	}
	if request.ZoneDescriptor != nil {
		zoneBytes, err := canonicalJSON(request.ZoneDescriptor)
		if err != nil {
			t.Fatal(err)
		}
		files["zone-descriptor"] = zoneBytes
	}
	if request.ZoneRecord.Body.Generation != 0 {
		zoneRecordBytes, err := CanonicalGenerationRecord(request.ZoneRecord)
		if err != nil {
			t.Fatal(err)
		}
		files["zone-record"] = zoneRecordBytes
	}
	commitBytes, err := canonicalJSON(map[string]any{"format": GenerationCommitFormat, "generation": generation, "record_digest": request.Record.RecordDigest})
	if err != nil {
		t.Fatal(err)
	}
	files["commit"] = commitBytes
	for suffix, data := range files {
		if err := os.WriteFile(storeGenerationFile(root, generation, suffix), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func assertStoreActive(t *testing.T, store *Store, generation int, recordDigest string) LoadedIdentity {
	t.Helper()
	loaded, err := store.LoadActive(testPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.KeyGeneration.Generation != generation || loaded.KeyGeneration.RecordDigest != recordDigest || loaded.Identity.Value != loaded.KeyGeneration.IdentityValue {
		t.Fatalf("loaded generation=%+v identity=%+v", loaded.KeyGeneration, loaded.Identity)
	}
	if len(loaded.PrivateKey) == 0 || len(loaded.Plaintext) == 0 || len(loaded.KeyGeneration.EnvelopeSHA256) != 64 {
		t.Fatalf("loaded missing key metadata: %+v", loaded.KeyGeneration)
	}
	return loaded
}

func assertStoreRecoveryRequired(t *testing.T, store *Store) {
	t.Helper()
	_, err := store.LoadActive(testPassphrase)
	if !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("err=%v want ErrRecoveryRequired", err)
	}
}

func TestStoreActivatesAndLoadsExactLayout(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	unsafeRoot := t.TempDir()
	if err := os.Chmod(unsafeRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(unsafeRoot, nil); err == nil || !strings.Contains(err.Error(), "managed key store mode must be 0700") {
		t.Fatalf("unsafe mode err=%v", err)
	}
	fixture := newGenerationChainFixture(t)
	store, err := OpenStore(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Install(storeItem(fixture, 0))
	if err != nil {
		t.Fatal(err)
	}
	if loaded.KeyGeneration.Generation != 1 || loaded.KeyGeneration.RecordDigest != fixture.Records[0].RecordDigest || loaded.KeyGeneration.DescriptorDigest != fixture.Records[0].Body.DescriptorDigest {
		t.Fatalf("loaded=%+v", loaded.KeyGeneration)
	}
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("store mode=%o", info.Mode().Perm())
	}
	for _, suffix := range []string{"envelope", "record", "descriptor"} {
		info, err := os.Stat(storeGenerationFile(root, 1, suffix))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode=%o", suffix, info.Mode().Perm())
		}
	}
	pointerBytes, err := os.ReadFile(filepath.Join(root, "active.json"))
	if err != nil {
		t.Fatal(err)
	}
	var pointer map[string]any
	if err := json.Unmarshal(pointerBytes, &pointer); err != nil {
		t.Fatal(err)
	}
	if pointer["format"] != ActivePointerFormat || int(pointer["generation"].(float64)) != 1 || pointer["record_digest"] != fixture.Records[0].RecordDigest {
		t.Fatalf("pointer=%v", pointer)
	}
	reopened, err := OpenStore(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	assertStoreActive(t, reopened, 1, fixture.Records[0].RecordDigest)
}

func TestStoreLoadsExactGenerationDespiteActivePointerDrift(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	fixture := newGenerationChainFixture(t)
	store, err := OpenStore(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.Install(storeItem(fixture, 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Install(storeItem(fixture, 1)); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.LoadGeneration(testPassphrase, first.KeyGeneration.RecordDigest)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.KeyGeneration != first.KeyGeneration {
		t.Fatalf("loaded=%+v want=%+v", loaded.KeyGeneration, first.KeyGeneration)
	}
	if _, err := store.LoadGeneration(testPassphrase, strings.Repeat("0", 64)); err == nil {
		t.Fatal("mismatched generation reference accepted")
	}
}

func TestStoreRecoversStrandedExclusivePublicationAndRejectsAdditionalLinks(t *testing.T) {
	t.Run("reload cleans exact stranded temp and retry progresses", func(t *testing.T) {
		root := t.TempDir()
		if err := os.Chmod(root, 0o700); err != nil {
			t.Fatal(err)
		}
		fixture := newGenerationChainFixture(t)
		store, err := OpenStore(root, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Install(storeItem(fixture, 0)); err != nil {
			t.Fatal(err)
		}
		canonical := storeGenerationFile(root, 2, "envelope")
		temp := filepath.Join(filepath.Dir(canonical), "."+filepath.Base(canonical)+".1.1.tmp")
		if err := os.WriteFile(temp, fixture.Envelopes[1], 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(temp, canonical); err != nil {
			t.Fatal(err)
		}
		reopened, err := OpenStore(root, nil)
		if err != nil {
			t.Fatal(err)
		}
		assertStoreActive(t, reopened, 1, fixture.Records[0].RecordDigest)
		if _, err := os.Lstat(temp); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("stranded temp err=%v", err)
		}
		if _, err := reopened.Install(storeItem(fixture, 1)); err != nil {
			t.Fatal(err)
		}
		assertStoreActive(t, reopened, 2, fixture.Records[1].RecordDigest)
	})

	t.Run("additional hard link is not treated as a recovery temp", func(t *testing.T) {
		root := t.TempDir()
		if err := os.Chmod(root, 0o700); err != nil {
			t.Fatal(err)
		}
		fixture := newGenerationChainFixture(t)
		store, err := OpenStore(root, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Install(storeItem(fixture, 0)); err != nil {
			t.Fatal(err)
		}
		canonical := storeGenerationFile(root, 1, "descriptor")
		temp := filepath.Join(filepath.Dir(canonical), "."+filepath.Base(canonical)+".1.1.tmp")
		if err := os.Link(canonical, temp); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(canonical, filepath.Join(root, "descriptor-copy.json")); err != nil {
			t.Fatal(err)
		}
		reopened, err := OpenStore(root, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := reopened.LoadActive(testPassphrase); err == nil || !strings.Contains(err.Error(), "link count") {
			t.Fatalf("err=%v", err)
		}
		if _, err := os.Lstat(temp); err != nil {
			t.Fatalf("recovery temp was removed: %v", err)
		}
	})
}

func TestStoreRejectsSymlinkedAndLinkedAuthoritativeFiles(t *testing.T) {
	fixture := newGenerationChainFixture(t)
	for _, test := range []struct {
		name   string
		mutate func(t *testing.T, root string)
		want   string
	}{
		{
			name: "active pointer symlink",
			mutate: func(t *testing.T, root string) {
				t.Helper()
				pointerPath := filepath.Join(root, "active.json")
				pointer, err := os.ReadFile(pointerPath)
				if err != nil {
					t.Fatal(err)
				}
				target := filepath.Join(root, "replacement-pointer.json")
				if err := os.WriteFile(target, pointer, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(pointerPath); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, pointerPath); err != nil {
					t.Fatal(err)
				}
			},
			want: "symbolic link",
		},
		{
			name: "generation hard link",
			mutate: func(t *testing.T, root string) {
				t.Helper()
				if err := os.Link(storeGenerationFile(root, 1, "descriptor"), filepath.Join(root, "descriptor-copy.json")); err != nil {
					t.Fatal(err)
				}
			},
			want: "link count",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0o700); err != nil {
				t.Fatal(err)
			}
			store, err := OpenStore(root, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.Install(storeItem(fixture, 0)); err != nil {
				t.Fatal(err)
			}
			test.mutate(t, root)
			if _, err := store.LoadActive(testPassphrase); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("err=%v want %q", err, test.want)
			}
		})
	}
}

func TestStoreCrashPointsKeepPointerSemantics(t *testing.T) {
	for _, test := range []struct{ point, want string }{
		{"envelope-after-rename", "old"},
		{"record-after-rename", "old"},
		{"descriptor-after-rename", "old"},
		{"active-before-rename", "recovery"},
		{"active-after-rename", "new"},
		{"active-after-dir-sync", "new"},
	} {
		t.Run(test.point, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0o700); err != nil {
				t.Fatal(err)
			}
			fixture := newGenerationChainFixture(t)
			store, err := OpenStore(root, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.Install(storeItem(fixture, 0)); err != nil {
				t.Fatal(err)
			}
			crashing, err := OpenStore(root, &StoreOptions{Fault: func(point string) error {
				if point == test.point {
					return errors.New("fault:" + point)
				}
				return nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := crashing.Install(storeItem(fixture, 1)); err == nil || !strings.Contains(err.Error(), "fault:"+test.point) {
				t.Fatalf("fault err=%v", err)
			}
			reopened, err := OpenStore(root, nil)
			if err != nil {
				t.Fatal(err)
			}
			switch test.want {
			case "old":
				assertStoreActive(t, reopened, 1, fixture.Records[0].RecordDigest)
			case "recovery":
				assertStoreRecoveryRequired(t, reopened)
			case "new":
				assertStoreActive(t, reopened, 2, fixture.Records[1].RecordDigest)
			}
		})
	}
}

func TestStoreRecoveryRejectsBadCompleteAndPicksHighestAuthorized(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	fixture := newGenerationChainFixture(t)
	store, err := OpenStore(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Install(storeItem(fixture, 0)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "generations", "0000000000000002.record.json.tmp"), []byte("ignored"), 0o600); err != nil {
		t.Fatal(err)
	}
	assertStoreActive(t, store, 1, fixture.Records[0].RecordDigest)
	writeRawStoreGeneration(t, root, storeItem(fixture, 1))
	reopened, err := OpenStore(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	assertStoreRecoveryRequired(t, reopened)
	writeRawStoreGeneration(t, root, storeItem(fixture, 2))
	recovered, err := reopened.Recover(testPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.KeyGeneration.Generation != 3 || recovered.KeyGeneration.RecordDigest != fixture.Records[2].RecordDigest {
		t.Fatalf("recovered=%+v", recovered.KeyGeneration)
	}

	malformedRoot := t.TempDir()
	if err := os.Chmod(malformedRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	malformed, err := OpenStore(malformedRoot, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := malformed.Install(storeItem(fixture, 0)); err != nil {
		t.Fatal(err)
	}
	bad := storeItem(fixture, 1)
	bad.Record.RecordDigest = strings.Repeat("0", 64)
	writeRawStoreGeneration(t, malformedRoot, bad)
	malformed, err = OpenStore(malformedRoot, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := malformed.LoadActive(testPassphrase); err == nil || !(strings.Contains(err.Error(), "record digest mismatch") || strings.Contains(err.Error(), "malformed complete generation")) {
		t.Fatalf("malformed err=%v", err)
	}
}

func TestStoreRejectsRollbackReplayPointerSyncAndSameGenerationRace(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	fixture := newGenerationChainFixture(t)
	store, err := OpenStore(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Install(storeItem(fixture, 0)); err != nil {
		t.Fatal(err)
	}
	syncFail, err := OpenStore(root, &StoreOptions{Fault: func(point string) error {
		if point == "record-file-sync" {
			return errors.New("fault:record-file-sync")
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := syncFail.Install(storeItem(fixture, 1)); err == nil || !strings.Contains(err.Error(), "fault:record-file-sync") {
		t.Fatalf("sync err=%v", err)
	}
	store, err = OpenStore(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	assertStoreActive(t, store, 1, fixture.Records[0].RecordDigest)
	unsafeFileRoot := t.TempDir()
	if err := os.Chmod(unsafeFileRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	unsafeFileStore, _ := OpenStore(unsafeFileRoot, nil)
	if _, err := unsafeFileStore.Install(storeItem(fixture, 0)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(unsafeFileRoot, "active.json"), 0o644); err != nil {
		t.Fatal(err)
	}
	unsafeFileStore, _ = OpenStore(unsafeFileRoot, nil)
	if _, err := unsafeFileStore.LoadActive(testPassphrase); err == nil || !strings.Contains(err.Error(), "active pointer file mode must be 0600") {
		t.Fatalf("unsafe active err=%v", err)
	}
	symlinkFileRoot := t.TempDir()
	if err := os.Chmod(symlinkFileRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	symlinkFileStore, _ := OpenStore(symlinkFileRoot, nil)
	if _, err := symlinkFileStore.Install(storeItem(fixture, 0)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(storeGenerationFile(symlinkFileRoot, 1, "envelope")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(storeGenerationFile(symlinkFileRoot, 1, "descriptor"), storeGenerationFile(symlinkFileRoot, 1, "envelope")); err != nil {
		t.Fatal(err)
	}
	symlinkFileStore, _ = OpenStore(symlinkFileRoot, nil)
	if _, err := symlinkFileStore.LoadActive(testPassphrase); err == nil || !(strings.Contains(err.Error(), "symbolic link") || strings.Contains(err.Error(), "symlink")) {
		t.Fatalf("symlink file err=%v", err)
	}

	staleClaimRoot := t.TempDir()
	if err := os.Chmod(staleClaimRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	staleClaimStore, _ := OpenStore(staleClaimRoot, nil)
	if _, err := staleClaimStore.Install(storeItem(fixture, 0)); err != nil {
		t.Fatal(err)
	}
	claim, _ := canonicalJSON(map[string]any{"format": InstallClaimFormat, "generation": 2, "pid": -1})
	if err := os.WriteFile(filepath.Join(staleClaimRoot, "generations", "0000000000000002.claim.json"), claim, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := staleClaimStore.Install(storeItem(fixture, 1)); err != nil {
		t.Fatal(err)
	}
	assertStoreActive(t, staleClaimStore, 2, fixture.Records[1].RecordDigest)

	rotatePartialRoot := t.TempDir()
	if err := os.Chmod(rotatePartialRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	rotatePartialStore, _ := OpenStore(rotatePartialRoot, nil)
	if _, err := rotatePartialStore.Install(storeItem(fixture, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := rotatePartialStore.Install(storeItem(fixture, 1)); err != nil {
		t.Fatal(err)
	}
	rotateItem := storeItem(fixture, 2)
	for _, suffix := range []string{"envelope", "record", "descriptor"} {
		var data []byte
		if suffix == "envelope" {
			data = rotateItem.EnvelopeBytes
		} else if suffix == "record" {
			data, _ = CanonicalGenerationRecord(rotateItem.Record)
		} else {
			data, _ = canonicalJSON(rotateItem.Descriptor)
		}
		if err := os.WriteFile(storeGenerationFile(rotatePartialRoot, 3, suffix), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rotatePartialStore, _ = OpenStore(rotatePartialRoot, nil)
	assertStoreActive(t, rotatePartialStore, 2, fixture.Records[1].RecordDigest)
	commit, _ := canonicalJSON(map[string]any{"format": GenerationCommitFormat, "generation": 3, "record_digest": fixture.Records[2].RecordDigest})
	if err := os.WriteFile(storeGenerationFile(rotatePartialRoot, 3, "commit"), commit, 0o600); err != nil {
		t.Fatal(err)
	}
	rotatePartialStore, _ = OpenStore(rotatePartialRoot, nil)
	if _, err := rotatePartialStore.LoadActive(testPassphrase); err == nil || !(strings.Contains(err.Error(), "trust material incomplete") || strings.Contains(err.Error(), "malformed complete generation")) {
		t.Fatalf("rotate partial err=%v", err)
	}

	winnerA, _ := OpenStore(root, nil)
	winnerB, _ := OpenStore(root, nil)
	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	go func() { defer wg.Done(); _, errs[0] = winnerA.Install(storeItem(fixture, 1)) }()
	go func() { defer wg.Done(); _, errs[1] = winnerB.Install(storeItem(fixture, 1)) }()
	wg.Wait()
	failed := 0
	for _, err := range errs {
		if err != nil {
			failed++
		}
	}
	if failed != 1 {
		t.Fatalf("race errors=%v", errs)
	}
	store, _ = OpenStore(root, nil)
	assertStoreActive(t, store, 2, fixture.Records[1].RecordDigest)

	pointer, err := canonicalJSON(map[string]any{"format": ActivePointerFormat, "generation": 1, "record_digest": fixture.Records[0].RecordDigest})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "active.json"), pointer, 0o600); err != nil {
		t.Fatal(err)
	}
	store, _ = OpenStore(root, nil)
	assertStoreRecoveryRequired(t, store)
	pointer, _ = canonicalJSON(map[string]any{"format": ActivePointerFormat, "generation": 2, "record_digest": strings.Repeat("0", 64)})
	if err := os.WriteFile(filepath.Join(root, "active.json"), pointer, 0o600); err != nil {
		t.Fatal(err)
	}
	store, _ = OpenStore(root, nil)
	if _, err := store.LoadActive(testPassphrase); err == nil {
		t.Fatal("pointer substitution accepted")
	}

	replayRoot := t.TempDir()
	if err := os.Chmod(replayRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	replay, _ := OpenStore(replayRoot, nil)
	if _, err := replay.Install(storeItem(fixture, 0)); err != nil {
		t.Fatal(err)
	}
	writeRawStoreGeneration(t, replayRoot, storeItem(fixture, 1))
	for _, suffix := range []string{"envelope", "record", "descriptor", "commit"} {
		data, err := os.ReadFile(storeGenerationFile(replayRoot, 2, suffix))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(storeGenerationFile(replayRoot, 3, suffix), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	replay, _ = OpenStore(replayRoot, nil)
	if _, err := replay.Recover(testPassphrase); err == nil || !(strings.Contains(err.Error(), "generation filename mismatch") || strings.Contains(err.Error(), "contiguous") || strings.Contains(err.Error(), "replay")) {
		t.Fatalf("replay err=%v", err)
	}
}

func TestStoreRecoveryAuthenticatesBeforeAdvancingPointer(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	fixture := newGenerationChainFixture(t)
	store, err := OpenStore(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Install(storeItem(fixture, 0)); err != nil {
		t.Fatal(err)
	}
	writeRawStoreGeneration(t, root, storeItem(fixture, 1))
	pointerPath := filepath.Join(root, "active.json")
	before, err := os.ReadFile(pointerPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Recover([]byte("wrong passphrase")); err == nil {
		t.Fatal("recovery with wrong passphrase succeeded")
	}
	after, err := os.ReadFile(pointerPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatalf("active pointer changed after failed recovery: before=%q after=%q", before, after)
	}
}

func TestStoreStaleInstallSentinelDoesNotBlockGeneration(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	fixture := newGenerationChainFixture(t)
	store, err := OpenStore(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Install(storeItem(fixture, 0)); err != nil {
		t.Fatal(err)
	}
	legacyLock := filepath.Join(root, "generations", leftPadGeneration(2)+".lock")
	if err := os.Mkdir(legacyLock, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Install(storeItem(fixture, 1)); err != nil {
		t.Fatalf("stale install sentinel blocked required generation: %v", err)
	}
	assertStoreActive(t, store, 2, fixture.Records[1].RecordDigest)
}

func TestStoreRejectsPinnedDirectoryReplayTrees(t *testing.T) {
	fixture := newGenerationChainFixture(t)
	install := func(t *testing.T, root string, generations int) *Store {
		t.Helper()
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}
		store, err := OpenStore(root, nil)
		if err != nil {
			t.Fatal(err)
		}
		for index := range generations {
			if _, err := store.Install(storeItem(fixture, index)); err != nil {
				t.Fatal(err)
			}
		}
		return store
	}

	t.Run("root replacement rejects reads and mutations", func(t *testing.T) {
		base := t.TempDir()
		root := filepath.Join(base, "store")
		store := install(t, root, 2)
		original := filepath.Join(base, "original")
		if err := os.Rename(root, original); err != nil {
			t.Fatal(err)
		}
		replay := filepath.Join(base, "replay")
		install(t, replay, 1)
		if err := os.Rename(replay, root); err != nil {
			t.Fatal(err)
		}
		if _, err := store.LoadActive(testPassphrase); err == nil {
			t.Error("replayed root accepted by opened store")
		}
		if _, err := store.Install(storeItem(fixture, 1)); err == nil {
			t.Error("opened store mutated replayed root")
		}
		legitimate, err := OpenStore(original, nil)
		if err != nil {
			t.Fatal(err)
		}
		assertStoreActive(t, legitimate, 2, fixture.Records[1].RecordDigest)
	})

	t.Run("generations replacement rejects reads and mutations", func(t *testing.T) {
		base := t.TempDir()
		root := filepath.Join(base, "store")
		store := install(t, root, 2)
		originalGenerations := filepath.Join(base, "original-generations")
		if err := os.Rename(filepath.Join(root, "generations"), originalGenerations); err != nil {
			t.Fatal(err)
		}
		replay := filepath.Join(base, "replay")
		install(t, replay, 1)
		if err := os.Rename(filepath.Join(replay, "generations"), filepath.Join(root, "generations")); err != nil {
			t.Fatal(err)
		}
		if _, err := store.LoadActive(testPassphrase); err == nil {
			t.Error("replayed generations accepted by opened store")
		}
		if _, err := store.Install(storeItem(fixture, 1)); err == nil {
			t.Error("opened store mutated replayed generations")
		}
		if err := os.RemoveAll(filepath.Join(root, "generations")); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(originalGenerations, filepath.Join(root, "generations")); err != nil {
			t.Fatal(err)
		}
		legitimate, err := OpenStore(root, nil)
		if err != nil {
			t.Fatal(err)
		}
		assertStoreActive(t, legitimate, 2, fixture.Records[1].RecordDigest)
	})
}
