package main

import (
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestTwoProcessesHaveOneClaimWinner(t *testing.T) {
	if os.Getenv("AGNET_SWARM_LEASE_HELPER") == "1" {
		journal, err := OpenSwarmJournal(os.Getenv("AGNET_SWARM_LEASE_ROOT"), "swarm://test/alpha")
		if err != nil {
			t.Fatal(err)
		}
		_, err = ClaimReadyWave(journal, os.Getenv("AGNET_SWARM_LEASE_OWNER"), swarmJournalTestTime.Add(time.Minute), swarmJournalTestTime.Add(2*time.Second))
		if err != nil {
			_, _ = os.Stdout.WriteString("lose\n")
			return
		}
		_, _ = os.Stdout.WriteString("win\n")
		return
	}

	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := OpenSwarmJournal(root, "swarm://test/alpha")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenVerifiedSwarm(journal, reducerTestDurableSpec(t), swarmJournalTestTime); err != nil {
		t.Fatal(err)
	}
	if _, _, err := RecordNextReadyWave(journal, swarmJournalTestTime.Add(time.Second)); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	outputs := make([]string, 2)
	for i := range outputs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cmd := exec.Command(os.Args[0], "-test.run=^TestTwoProcessesHaveOneClaimWinner$", "-test.count=1")
			cmd.Env = append(os.Environ(),
				"AGNET_SWARM_LEASE_HELPER=1",
				"AGNET_SWARM_LEASE_ROOT="+root,
				"AGNET_SWARM_LEASE_OWNER=worker-"+string(rune('a'+i)),
			)
			out, err := cmd.Output()
			if err != nil {
				t.Errorf("claim helper %d: %v", i, err)
				return
			}
			outputs[i] = string(out)
		}(i)
	}
	wg.Wait()
	wins := 0
	for _, output := range outputs {
		if strings.Contains(output, "win") {
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("process claim winners = %d, outputs = %#v; want exactly one", wins, outputs)
	}
}
