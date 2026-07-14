package main

import (
	"agnet/internal/managedkey"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
)

func loadManagedFixture(path string, runtimeKeys ManagedRuntimeConfig) (Fixture, error) {
	authority, err := loadManagedIdentity(runtimeKeys.Authority, managedkey.IdentityZID)
	if err != nil {
		return Fixture{}, err
	}
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
	if err := verifyManagedDescriptor(authority, fixture.Authority, managedkey.IdentityZID); err != nil {
		return Fixture{}, err
	}
	fixture.AuthorityPrivateKey = authority.PrivateKey
	fixture.AuthorityGeneration = authority.KeyGeneration
	fixture.AuthorityGenerationPin = WorkerGenerationPin{StorePath: runtimeKeys.Authority.StorePath, PassphraseFile: runtimeKeys.Authority.PassphraseFile, RecordDigest: authority.KeyGeneration.RecordDigest}
	workers, err := fixture.loadWorkers(runtimeKeys.Worker)
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

func loadManagedIdentity(config ManagedKeyConfig, expectedKind string) (managedkey.LoadedIdentity, error) {
	var zero managedkey.LoadedIdentity
	if config.StorePath == "" || config.PassphraseFile == "" {
		return zero, errors.New("managed key store and passphrase file are required")
	}
	store, err := managedkey.OpenStore(config.StorePath, nil)
	if err != nil {
		return zero, err
	}
	passphrase, err := managedkey.ReadRestrictedFile(config.PassphraseFile, managedkey.RestrictedFileOptions{Label: "managed key passphrase", MaxBytes: 64 * 1024})
	if err != nil {
		return zero, err
	}
	defer clear(passphrase.Bytes)
	var loaded managedkey.LoadedIdentity
	if config.RecordDigest == "" {
		loaded, err = store.LoadActive(passphrase.Bytes)
	} else {
		loaded, err = store.LoadGeneration(passphrase.Bytes, config.RecordDigest)
	}
	if err != nil {
		return zero, err
	}
	clear(loaded.Plaintext)
	if expectedKind != "" && loaded.Identity.Kind != expectedKind {
		clear(loaded.PrivateKey)
		return zero, errors.New("managed key identity kind mismatch")
	}
	return loaded, nil
}

func loadVerifiedKeyGeneration(storePath, recordDigest, passphraseFile string) (managedkey.LoadedIdentity, error) {
	if recordDigest == "" {
		return managedkey.LoadedIdentity{}, errors.New("managed key generation record digest required")
	}
	return loadManagedIdentity(ManagedKeyConfig{StorePath: storePath, PassphraseFile: passphraseFile, RecordDigest: recordDigest}, "")
}

func verifyManagedDescriptor(loaded managedkey.LoadedIdentity, descriptor map[string]any, identityKind string) error {
	if loaded.Identity.Kind != identityKind || descriptor[identityKind] != loaded.Identity.Value {
		return errors.New("managed key identity does not match descriptor")
	}
	if digestHex(descriptor) != loaded.KeyGeneration.DescriptorDigest {
		return errors.New("managed key generation descriptor mismatch")
	}
	publicKey := loaded.PrivateKey.Public().(ed25519.PublicKey)
	encoded, _, err := publicKeySPKI(publicKey)
	if err != nil {
		return err
	}
	if descriptor["public_key_spki"] != encoded {
		return errors.New("managed key public key does not match descriptor")
	}
	return nil
}

func (r *TaskRuntime) Reserve(taskID string) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.running == nil {
		r.running = map[string]context.CancelFunc{}
	}
	if _, exists := r.running[taskID]; exists {
		return false
	}
	if r.cancelled == nil {
		r.cancelled = map[string]bool{}
	}
	r.running[taskID] = nil
	r.cancelled[taskID] = false
	return true
}

func (r *TaskRuntime) Owns(taskID string) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	_, exists := r.running[taskID]
	return exists
}

func (r *TaskRuntime) Release(taskID string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.running, taskID)
	if cancelled, reserved := r.cancelled[taskID]; reserved && !cancelled {
		delete(r.cancelled, taskID)
	}
}

func (r *TaskRuntime) Register(taskID string, cancel context.CancelFunc) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.running == nil {
		r.running = map[string]context.CancelFunc{}
	}
	r.running[taskID] = cancel
	if r.cancelled[taskID] {
		cancel()
	}
}

func (r *TaskRuntime) Cancel(taskID string) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.committing[taskID] || r.completed[taskID] {
		return false
	}
	if r.cancelled == nil {
		r.cancelled = map[string]bool{}
	}
	r.cancelled[taskID] = true
	if cancel := r.running[taskID]; cancel != nil {
		cancel()
	}
	return true
}

func (r *TaskRuntime) BeginCompletion(taskID string) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cancelled[taskID] || r.completed[taskID] || r.committing[taskID] {
		return false
	}
	if r.committing == nil {
		r.committing = map[string]bool{}
	}
	r.committing[taskID] = true
	return true
}

func (r *TaskRuntime) FinishCompletion(taskID string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.committing, taskID)
	if r.completed == nil {
		r.completed = map[string]bool{}
	}
	r.completed[taskID] = true
}

func (r *TaskRuntime) AbortCompletion(taskID string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.committing, taskID)
}

func (r *TaskRuntime) Unregister(taskID string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if cancelled, reserved := r.cancelled[taskID]; reserved && !cancelled {
		r.running[taskID] = nil
		return
	}
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
	loaded := managedkey.LoadedIdentity{PrivateKey: f.AuthorityPrivateKey, KeyGeneration: f.AuthorityGeneration, Identity: managedkey.Identity{Kind: managedkey.IdentityZID, Value: optionalString(f.Authority["zid"])}}
	return verifyManagedDescriptor(loaded, f.Authority, managedkey.IdentityZID)
}

func (f Fixture) loadWorkers(defaultConfig ManagedKeyConfig) ([]Worker, error) {
	profiles := f.WorkerProfiles
	if len(profiles) == 0 {
		profiles = []WorkerProfile{f.WorkerProfile}
	}
	workers := make([]Worker, 0, len(profiles))
	seen := map[string]bool{}
	for _, profile := range profiles {
		config, err := managedWorkerConfig(defaultConfig, profile)
		if err != nil {
			return nil, err
		}
		loaded, err := loadManagedIdentity(config, managedkey.IdentityAID)
		if err != nil {
			return nil, err
		}
		var descriptor map[string]any
		if len(profiles) == 1 && f.WorkerDescriptor != nil {
			descriptor = f.WorkerDescriptor
			if err := verifyWorkerProfileDescriptor(profile, descriptor); err != nil {
				return nil, err
			}
		} else {
			descriptor, err = workerDescriptor(profile, loaded.PrivateKey)
			if err != nil {
				return nil, err
			}
		}
		if seen[profile.Alias] {
			return nil, errors.New("duplicate worker alias: " + profile.Alias)
		}
		seen[profile.Alias] = true
		if err := verifyAgentDescriptor(descriptor); err != nil {
			return nil, err
		}
		if err := verifyManagedDescriptor(loaded, descriptor, managedkey.IdentityAID); err != nil {
			return nil, err
		}
		workers = append(workers, Worker{Profile: profile, Descriptor: descriptor, PrivateKey: loaded.PrivateKey, GenerationRef: loaded.KeyGeneration, WorkerGenerationPin: WorkerGenerationPin{StorePath: config.StorePath, PassphraseFile: config.PassphraseFile, RecordDigest: loaded.KeyGeneration.RecordDigest}})
	}
	return workers, nil
}

func managedWorkerConfig(defaultConfig ManagedKeyConfig, profile WorkerProfile) (ManagedKeyConfig, error) {
	if profile.KeyFile != "" {
		return ManagedKeyConfig{}, errors.New("worker key_file is not supported; use managed key store")
	}
	if profile.KeyStore == "" && profile.PassphraseFile == "" && profile.KeyGeneration.RecordDigest == "" {
		return defaultConfig, nil
	}
	if profile.KeyStore == "" || profile.PassphraseFile == "" {
		return ManagedKeyConfig{}, errors.New("worker managed key store and passphrase file are required")
	}
	return ManagedKeyConfig{StorePath: profile.KeyStore, PassphraseFile: profile.PassphraseFile, RecordDigest: profile.KeyGeneration.RecordDigest}, nil
}

func verifyWorkerProfileDescriptor(profile WorkerProfile, descriptor map[string]any) error {
	policy := profile.Policy
	if policy == nil {
		policy = map[string]any{}
	}
	expected := map[string]any{"alias": profile.Alias, "transports": profile.Transports, "capabilities": profile.Capabilities, "policy": policy}
	actual := map[string]any{"alias": descriptor["alias"], "transports": descriptor["transports"], "capabilities": descriptor["capabilities"], "policy": descriptor["policy"]}
	if digestHex(expected) != digestHex(actual) {
		return errors.New("worker profile does not match fixture descriptor")
	}
	return nil
}

func sameGeneration(left, right managedkey.KeyGenerationRef) bool {
	return left.IdentityKind == right.IdentityKind && left.IdentityValue == right.IdentityValue && left.Generation == right.Generation && left.RecordDigest == right.RecordDigest && left.EnvelopeSHA256 == right.EnvelopeSHA256 && left.DescriptorDigest == right.DescriptorDigest
}

func (worker Worker) reloadPinnedGeneration() error {
	loaded, err := loadVerifiedKeyGeneration(worker.WorkerGenerationPin.StorePath, worker.WorkerGenerationPin.RecordDigest, worker.WorkerGenerationPin.PassphraseFile)
	if err != nil {
		return err
	}
	defer clear(loaded.PrivateKey)
	if !sameGeneration(loaded.KeyGeneration, worker.GenerationRef) {
		return errors.New("worker managed generation record mismatch")
	}
	return verifyManagedDescriptor(loaded, worker.Descriptor, managedkey.IdentityAID)
}

func activeGenerationMatches(pin WorkerGenerationPin, expected managedkey.KeyGenerationRef, identityKind string) error {
	loaded, err := loadManagedIdentity(ManagedKeyConfig{StorePath: pin.StorePath, PassphraseFile: pin.PassphraseFile}, identityKind)
	if err != nil {
		return err
	}
	defer clear(loaded.PrivateKey)
	if !sameGeneration(loaded.KeyGeneration, expected) {
		return errors.New("managed key active generation changed during Swarm")
	}
	return nil
}

func (f Fixture) verifySwarmGenerationPins() error {
	if err := activeGenerationMatches(f.AuthorityGenerationPin, f.AuthorityGeneration, managedkey.IdentityZID); err != nil {
		return err
	}
	for _, worker := range f.Workers {
		if err := activeGenerationMatches(worker.WorkerGenerationPin, worker.GenerationRef, managedkey.IdentityAID); err != nil {
			return err
		}
		if err := worker.reloadPinnedGeneration(); err != nil {
			return err
		}
	}
	return nil
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
