package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
)

func loadFixture(path string, authorityKey, workerKey ed25519.PrivateKey) (Fixture, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Fixture{}, err
	}
	var fixture Fixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		return Fixture{}, err
	}
	if err := verifyZoneDescriptor(fixture.Authority); err != nil {
		return Fixture{}, err
	}
	fixture.AuthorityPrivateKey = authorityKey
	if err := fixture.verifyAuthoritySeed(); err != nil {
		return Fixture{}, err
	}
	workers, err := fixture.loadWorkers(workerKey)
	if err != nil {
		return Fixture{}, err
	}
	fixture.Workers = workers
	return fixture, nil
}

func loadHumanActorPolicy(path string) (map[string][]string, map[string][]string, map[string]string, error) {
	if path == "" {
		return nil, nil, nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, nil, err
	}
	var policy struct {
		QueueActions     map[string][]string `json:"queue_actions"`
		ApprovalActions  map[string][]string `json:"approval_actions"`
		ApprovalSessions map[string]string   `json:"approval_sessions"`
	}
	if err := json.Unmarshal(data, &policy); err != nil {
		return nil, nil, nil, err
	}
	return policy.QueueActions, policy.ApprovalActions, policy.ApprovalSessions, nil
}

func loadPrivateKey(path, label string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return privateKeyFromSeedHex(strings.TrimSpace(string(data)), label)
}

func privateKeyFromSeedHex(seedHex, label string) (ed25519.PrivateKey, error) {
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		return nil, err
	}
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New(label + " seed must be 32 bytes")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func (r *TaskRuntime) Register(taskID string, cancel context.CancelFunc) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.running[taskID] = cancel
	if r.cancelled[taskID] {
		cancel()
	}
}

func (r *TaskRuntime) Cancel(taskID string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cancelled[taskID] = true
	if cancel := r.running[taskID]; cancel != nil {
		cancel()
	}
}

func (r *TaskRuntime) Unregister(taskID string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.running, taskID)
}

func (r *TaskRuntime) WasCancelled(taskID string) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cancelled[taskID]
}

func (f Fixture) verifyAuthoritySeed() error {
	publicKey := f.AuthorityPrivateKey.Public().(ed25519.PublicKey)
	encoded, _, err := publicKeySPKI(publicKey)
	if err != nil {
		return err
	}
	if encoded != f.Authority["public_key_spki"] {
		return errors.New("authority seed does not match authority descriptor")
	}
	return nil
}

func (f Fixture) loadWorkers(defaultKey ed25519.PrivateKey) ([]Worker, error) {
	profiles := f.WorkerProfiles
	if len(profiles) == 0 {
		profiles = []WorkerProfile{f.WorkerProfile}
	}
	workers := []Worker{}
	seen := map[string]bool{}
	for _, profile := range profiles {
		key := defaultKey
		var err error
		if profile.KeyFile != "" {
			key, err = loadPrivateKey(profile.KeyFile, "worker")
			if err != nil {
				return nil, err
			}
		}
		descriptor, err := workerDescriptor(profile, key)
		if err != nil {
			return nil, err
		}
		if seen[profile.Alias] {
			return nil, errors.New("duplicate worker alias: " + profile.Alias)
		}
		seen[profile.Alias] = true
		if err := verifyAgentDescriptor(descriptor); err != nil {
			return nil, err
		}
		workers = append(workers, Worker{Profile: profile, Descriptor: descriptor, PrivateKey: key})
	}
	return workers, nil
}

func workerDescriptor(profile WorkerProfile, key ed25519.PrivateKey) (map[string]any, error) {
	if profile.Alias == "" {
		return nil, errors.New("worker profile alias missing")
	}
	if len(profile.Transports) == 0 {
		return nil, errors.New("worker profile transports missing")
	}
	if len(profile.Capabilities) == 0 {
		return nil, errors.New("worker profile capabilities missing")
	}
	publicKey := key.Public().(ed25519.PublicKey)
	encoded, der, err := publicKeySPKI(publicKey)
	if err != nil {
		return nil, err
	}
	policy := profile.Policy
	if policy == nil {
		policy = map[string]any{}
	}
	body := map[string]any{
		"alias":           profile.Alias,
		"aid":             aidFromSPKI(der),
		"did_key":         didKeyFromPublicKey(publicKey),
		"public_key_spki": encoded,
		"transports":      profile.Transports,
		"capabilities":    profile.Capabilities,
		"policy":          policy,
	}
	return signBodyWithKey(key, body, "descriptor_signature"), nil
}

func (f Fixture) workerByAlias(alias string) *Worker {
	for i := range f.Workers {
		if f.Workers[i].Descriptor["alias"] == alias {
			return &f.Workers[i]
		}
	}
	return nil
}

func (f Fixture) humanGatewayRequester() (map[string]any, error) {
	publicKey := f.AuthorityPrivateKey.Public().(ed25519.PublicKey)
	encoded, der, err := publicKeySPKI(publicKey)
	if err != nil {
		return nil, err
	}
	body := map[string]any{
		"alias":           "agent://human-gateway/local",
		"aid":             aidFromSPKI(der),
		"did_key":         didKeyFromPublicKey(publicKey),
		"public_key_spki": encoded,
		"transports":      []string{"human-gateway.local"},
		"capabilities":    []string{"queue.draft"},
		"policy":          map[string]any{"local_proof": true},
	}
	return signBodyWithKey(f.AuthorityPrivateKey, body, "descriptor_signature"), nil
}

func (f Fixture) requesterAliasRebindingProof(previous, next, rotationProof map[string]any) (map[string]any, error) {
	if previous["alias"] != next["alias"] {
		return nil, errors.New("alias rebinding requires matching aliases")
	}
	if err := verifyAgentRotationProof(rotationProof, previous, next); err != nil {
		return nil, err
	}
	body := map[string]any{
		"zone":         f.Authority["zid"],
		"alias":        previous["alias"],
		"previous_aid": previous["aid"],
		"next_aid":     next["aid"],
	}
	proof := signBodyWithKey(f.AuthorityPrivateKey, body, "zone_signature")
	proof["agent_rotation_proof"] = rotationProof
	return proof, nil
}

func (f Fixture) writeRequesterRegistry(descriptor map[string]any) error {
	registry, err := readRequesterRegistry()
	if err != nil {
		return err
	}
	registry["zone"] = f.Authority
	if _, ok := registry["revocations"].([]any); !ok {
		registry["revocations"] = []any{}
	}
	agents, _ := registry["agents"].([]any)
	next := map[string]any{
		"descriptor":   descriptor,
		"zone_binding": f.zoneBindingForDescriptor(descriptor),
	}
	replaced := false
	for index, item := range agents {
		entry, _ := item.(map[string]any)
		existing, _ := entry["descriptor"].(map[string]any)
		if existing["alias"] == descriptor["alias"] {
			agents[index] = next
			replaced = true
			break
		}
	}
	if !replaced {
		agents = append(agents, next)
	}
	registry["agents"] = agents
	return writeJSONStateFile(requesterRegistryPath, registry)
}

func readRequesterRegistry() (map[string]any, error) {
	data, err := os.ReadFile(requesterRegistryPath)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]any{"revocations": []any{}, "agents": []any{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var registry map[string]any
	if err := json.Unmarshal(data, &registry); err != nil {
		return nil, err
	}
	return registry, nil
}

func requesterRegistryAgents(registry map[string]any) []map[string]any {
	items, _ := registry["agents"].([]any)
	agents := []map[string]any{}
	for _, item := range items {
		if entry, ok := item.(map[string]any); ok {
			agents = append(agents, entry)
		}
	}
	return agents
}

func readRequesterRebindingHistory() ([]map[string]any, error) {
	data, err := os.ReadFile(requesterRebindingHistoryPath)
	if errors.Is(err, os.ErrNotExist) {
		return []map[string]any{}, nil
	}
	if err != nil {
		return nil, err
	}
	var rebindings []map[string]any
	if err := json.Unmarshal(data, &rebindings); err != nil {
		return nil, err
	}
	return rebindings, nil
}

func (f Fixture) appendRequesterRebindingHistory(proof map[string]any) error {
	rebindings, err := readRequesterRebindingHistory()
	if err != nil {
		return err
	}
	rebindings = append(rebindings, map[string]any{
		"zone":                  proof["zone"],
		"alias":                 proof["alias"],
		"previous_aid":          proof["previous_aid"],
		"next_aid":              proof["next_aid"],
		"proof_digest":          digestHex(proof),
		"alias_rebinding_proof": proof,
	})
	return writeJSONStateFile(requesterRebindingHistoryPath, rebindings)
}
