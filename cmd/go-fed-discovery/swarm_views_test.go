package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestViewsRebuildIsDeterministicAndRepairsDeletedProjection(t *testing.T) {
	journal, _ := committedViewJournal(t)
	materializer, err := NewSwarmMaterializer(journal)
	if err != nil {
		t.Fatal(err)
	}
	first, err := materializer.Rebuild()
	if err != nil {
		t.Fatal(err)
	}
	paths := materializer.Paths()
	before := readViewFiles(t, paths)
	if err := os.Remove(paths.Swarm); err != nil {
		t.Fatal(err)
	}
	got, err := ReadSwarmView(journal)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, first) {
		t.Fatalf("read view = %#v; want %#v", got, first)
	}
	after := readViewFiles(t, paths)
	for path, want := range before {
		if !bytes.Equal(after[path], want) {
			t.Fatalf("repaired %s differs from deterministic rebuild", path)
		}
	}
	if err := os.WriteFile(paths.Queue, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSwarmView(journal); err != nil {
		t.Fatal(err)
	}
	if repaired := readViewFiles(t, paths)[paths.Queue]; !bytes.Equal(repaired, before[paths.Queue]) {
		t.Fatal("corrupt queue projection was not rebuilt from journal authority")
	}
}

func TestViewFailurePreservesFullPreviousFileAndReportsRepair(t *testing.T) {
	journal, committed := committedViewJournal(t)
	baseline, err := NewSwarmMaterializer(journal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := baseline.Rebuild(); err != nil {
		t.Fatal(err)
	}
	paths := baseline.Paths()
	before := readViewFiles(t, paths)
	for _, crash := range []SwarmViewFaultPoint{SwarmViewFaultCreate, SwarmViewFaultWrite, SwarmViewFaultFileSync, SwarmViewFaultRename, SwarmViewFaultDirectorySync} {
		t.Run(string(crash), func(t *testing.T) {
			injected := errors.New("injected " + string(crash) + " failure")
			materializer, err := NewSwarmMaterializer(journal, func(point SwarmViewFaultPoint) error {
				if point == crash {
					return injected
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := materializer.Rebuild(); !errors.Is(err, injected) || !errors.Is(err, ErrSwarmViewRepairNeeded) {
				t.Fatalf("rebuild failure = %v; want injected repair-needed error", err)
			}
			after := readViewFiles(t, paths)
			for path, want := range before {
				if !bytes.Equal(after[path], want) {
					t.Fatalf("failed %s replacement changed %s", crash, path)
				}
			}
		})
	}
	entries, err := journal.Replay()
	if err != nil || len(entries) == 0 || entries[len(entries)-1].Kind != "receipt.committed" {
		t.Fatalf("projection failure changed authoritative receipt journal: entries=%#v err=%v", entries, err)
	}
	data, err := ReadCommittedArtifact(journal, committed)
	if err != nil || !bytes.Equal(data, []byte("committed view result")) {
		t.Fatalf("projection failure invalidated committed receipt artifact: %q, %v", data, err)
	}
}

func TestMixedViewTriggersReplayAndRebuild(t *testing.T) {
	journal, _ := committedViewJournal(t)
	materializer, err := NewSwarmMaterializer(journal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := materializer.Rebuild(); err != nil {
		t.Fatal(err)
	}
	paths := materializer.Paths()
	mixed, err := os.ReadFile(paths.Swarm)
	if err != nil {
		t.Fatal(err)
	}
	mixed = bytes.Replace(mixed, []byte(`"journal_head"`), []byte(`"wrong_head"`), 1)
	if err := os.WriteFile(paths.Swarm, mixed, 0o600); err != nil {
		t.Fatal(err)
	}
	view, err := ReadSwarmView(journal)
	if err != nil {
		t.Fatal(err)
	}
	if view.Version == 0 || view.JournalHead == "" {
		t.Fatalf("replayed view missing authority stamp: %#v", view)
	}
	repaired, err := os.ReadFile(paths.Swarm)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(repaired, mixed) || !bytes.Contains(repaired, []byte(`"journal_head"`)) {
		t.Fatal("mixed projection was not rebuilt from journal authority")
	}
}

func TestArtifactIndexExcludesUncommittedStageAndIsIdempotent(t *testing.T) {
	journal, committed := committedViewJournal(t)
	staged, err := StageArtifact(journal, []byte("not committed"))
	if err != nil {
		t.Fatal(err)
	}
	materializer, err := NewSwarmMaterializer(journal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := materializer.Rebuild(); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(materializer.Paths().Artifacts)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(first, []byte(committed.SHA256)) || bytes.Contains(first, []byte(staged.SHA256)) {
		t.Fatalf("artifact index leaked an uncommitted stage: %s", first)
	}
	if _, err := materializer.Rebuild(); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(materializer.Paths().Artifacts)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("artifact index changed across idempotent materialization")
	}
}

func TestMaterializerRebuildAllDiscoversJournals(t *testing.T) {
	journal, _ := committedViewJournal(t)
	root := filepath.Dir(filepath.Dir(journal.Path))
	materializer, err := NewSwarmMaterializer(journal)
	if err != nil {
		t.Fatal(err)
	}
	views, err := materializer.RebuildAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(views) != 1 || views[0].SwarmID != "swarm://test/alpha" {
		t.Fatalf("discovered views = %#v", views)
	}
	if _, err := os.Stat(filepath.Join(root, filepath.Base(filepath.Dir(journal.Path)), "views", "audit.ndjson")); err != nil {
		t.Fatal(err)
	}
}

func committedViewJournal(t *testing.T) (*SwarmJournal, StagedArtifact) {
	t.Helper()
	journal := newTestSwarmJournal(t)
	spec := reducerTestDurableSpec(t)
	spec.Steps[0].TaskDigest = strings.Repeat("a", 64)
	spec.Steps[0].Capability = "analysis"
	if _, err := OpenVerifiedSwarm(journal, spec, swarmJournalTestTime); err != nil {
		t.Fatal(err)
	}
	if _, _, err := RecordNextReadyWave(journal, swarmJournalTestTime.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	dispatch, err := ClaimReadyWave(journal, "view-worker", swarmJournalTestTime.Add(time.Minute), swarmJournalTestTime.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	result, err := StageArtifact(journal, []byte("committed view result"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CommitReceipt(journal, ReceiptCommit{Claim: dispatch.Claims[0], Receipt: u22Receipt(t, spec, dispatch.Claims[0], result), Result: result}, swarmJournalTestTime.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	return journal, result
}

func readViewFiles(t *testing.T, paths SwarmViewPaths) map[string][]byte {
	t.Helper()
	out := make(map[string][]byte, 4)
	for _, path := range []string{paths.Swarm, paths.Queue, paths.Artifacts, paths.Audit} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		out[path] = data
	}
	return out
}
