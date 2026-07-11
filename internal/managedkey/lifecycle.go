package managedkey

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"math/big"
)

// LifecycleResult is the non-secret metadata emitted by lifecycle operations.
type LifecycleResult struct {
	Operation      string `json:"operation"`
	IdentityKind   string `json:"identity_kind"`
	IdentityValue  string `json:"identity_value"`
	Generation     int    `json:"generation"`
	RecordDigest   string `json:"record_digest"`
	EnvelopeSHA256 string `json:"envelope_sha256"`
}

// MigrateOptions names only restricted files. Passphrases are never accepted as
// process arguments or environment values.
type MigrateOptions struct {
	Store          *Store
	SourceKeyPath  string
	SourceKeyType  string
	IdentityKind   string
	DescriptorPath string
	PassphrasePath string
	Iterations     int
}

// RewrapOptions names only restricted files. The descriptor must be the exact
// descriptor bound to the active generation.
type RewrapOptions struct {
	Store             *Store
	IdentityKind      string
	DescriptorPath    string
	PassphrasePath    string
	NewPassphrasePath string
	Iterations        int
}


// RotateAgentOptions names the two verified managed stores that participate in
// an Agent rotation. Zone authorization is read from its active generation.
type RotateAgentOptions struct {
	Store              *Store
	ZoneStore          *Store
	PassphrasePath     string
	ZonePassphrasePath string
	Iterations         int
	Entropy            io.Reader
}
// RecoverOptions names the restricted passphrase file used to reopen a store.
type RecoverOptions struct {
	Store          *Store
	PassphrasePath string
}

func lifecycleResult(operation string, loaded LoadedIdentity) LifecycleResult {
	return LifecycleResult{
		Operation:      operation,
		IdentityKind:   loaded.KeyGeneration.IdentityKind,
		IdentityValue:  loaded.KeyGeneration.IdentityValue,
		Generation:     loaded.KeyGeneration.Generation,
		RecordDigest:   loaded.KeyGeneration.RecordDigest,
		EnvelopeSHA256: loaded.KeyGeneration.EnvelopeSHA256,
	}
}

func clearLoadedIdentity(loaded *LoadedIdentity) {
	clear(loaded.Plaintext)
	clear(loaded.PrivateKey)
}

func readLifecycleRestricted(path, label string) ([]byte, error) {
	file, err := ReadRestrictedFile(path, RestrictedFileOptions{Label: label, MaxBytes: maxSecretBytes})
	if err != nil {
		return nil, err
	}
	return file.Bytes, nil
}

func readLifecycleDescriptor(path string) (map[string]any, error) {
	data, err := readLifecycleRestricted(path, "descriptor")
	if err != nil {
		return nil, err
	}
	defer clear(data)
	decoded, err := decodeExactJSON(data)
	if err != nil {
		return nil, errors.New("descriptor JSON invalid")
	}
	descriptor, ok := decoded.(map[string]any)
	if !ok {
		return nil, errors.New("descriptor JSON invalid")
	}
	return descriptor, nil
}

func identityFromDescriptor(descriptor map[string]any, kind string) (Identity, error) {
	if kind != IdentityAID && kind != IdentityZID {
		return Identity{}, errors.New("identity kind invalid")
	}
	value, ok := descriptor[kind].(string)
	if !ok {
		return Identity{}, errors.New("descriptor identity invalid")
	}
	identity := Identity{Kind: kind, Value: value}
	if _, err := descriptorPublicKey(descriptor, identity); err != nil {
		return Identity{}, errors.New("descriptor invalid")
	}
	return identity, nil
}

func ensureStoreEmpty(store *Store) error {
	if store == nil {
		return errors.New("store invalid")
	}
	root, generations, err := store.openVerifiedDirectories()
	if err != nil {
		return err
	}
	defer root.Close()
	defer generations.Close()
	rootEntries, err := readDirAt(root)
	if err != nil {
		return err
	}
	for _, entry := range rootEntries {
		if entry.Name() != "generations" {
			return errors.New("store already populated")
		}
	}
	generationEntries, err := readDirAt(generations)
	if err != nil {
		return err
	}
	if len(generationEntries) != 0 {
		return errors.New("store already populated")
	}
	pointer, active, err := store.readActivePointer(root)
	if err != nil {
		return err
	}
	if active || pointer.Generation != 0 || pointer.RecordDigest != "" {
		return errors.New("store already populated")
	}
	scan, err := store.scanCompleteGenerations(generations)
	if err != nil {
		return err
	}
	if len(scan) != 0 {
		return errors.New("store already populated")
	}
	return nil
}

func activeStoreGeneration(store *Store, expected KeyGenerationRef) (storeGeneration, error) {
	var zero storeGeneration
	if store == nil {
		return zero, errors.New("store invalid")
	}
	root, generations, err := store.openVerifiedDirectories()
	if err != nil {
		return zero, err
	}
	defer root.Close()
	defer generations.Close()
	pointer, active, err := store.readActivePointer(root)
	if err != nil {
		return zero, err
	}
	if !active || pointer.Generation != expected.Generation || pointer.RecordDigest != expected.RecordDigest {
		return zero, errors.New("active generation changed")
	}
	scan, err := store.scanCompleteGenerations(generations)
	if err != nil {
		return zero, err
	}
	if len(scan) == 0 || scan[len(scan)-1].record.Body.Generation > pointer.Generation {
		return zero, ErrRecoveryRequired
	}
	for _, item := range scan {
		if item.record.Body.Generation == pointer.Generation && item.record.RecordDigest == pointer.RecordDigest {
			return item, nil
		}
	}
	return zero, errors.New("active generation missing")
}

// Migrate creates the first store generation from an explicitly declared Go
// seed or Node PKCS8 private-key file and proves it against the descriptor.
func Migrate(options MigrateOptions) (LifecycleResult, error) {
	var zero LifecycleResult
	if err := ensureStoreEmpty(options.Store); err != nil {
		return zero, err
	}
	descriptor, err := readLifecycleDescriptor(options.DescriptorPath)
	if err != nil {
		return zero, err
	}
	identity, err := identityFromDescriptor(descriptor, options.IdentityKind)
	if err != nil {
		return zero, err
	}
	plaintext, err := readLifecycleRestricted(options.SourceKeyPath, "source key")
	if err != nil {
		return zero, err
	}
	defer clear(plaintext)
	privateKey, err := verifyPlaintextIdentity(options.SourceKeyType, plaintext, identity)
	if err != nil {
		return zero, errors.New("source key and descriptor identity mismatch")
	}
	defer clear(privateKey)
	passphrase, err := readLifecycleRestricted(options.PassphrasePath, "passphrase")
	if err != nil {
		return zero, err
	}
	defer clear(passphrase)
	envelope, err := SealEnvelope(SealOptions{KeyType: options.SourceKeyType, Plaintext: plaintext, Identity: identity, Passphrase: passphrase, Iterations: options.Iterations})
	if err != nil {
		return zero, err
	}
	body, err := BuildGenerationBody(GenerationBodyOptions{Identity: identity, Generation: 1, Operation: GenerationMigrate, EnvelopeBytes: envelope, Descriptor: descriptor})
	if err != nil {
		return zero, err
	}
	record, err := NewSignedGenerationRecord(body, privateKey)
	if err != nil {
		return zero, err
	}
	loaded, err := options.Store.Install(InstallRequest{EnvelopeBytes: envelope, Record: record, Descriptor: descriptor, Passphrase: passphrase})
	if err != nil {
		return zero, err
	}
	defer clearLoadedIdentity(&loaded)
	if loaded.KeyType != options.SourceKeyType || loaded.Identity != identity || !bytes.Equal(loaded.Plaintext, plaintext) || loaded.KeyGeneration.Generation != 1 || loaded.KeyGeneration.RecordDigest != record.RecordDigest {
		return zero, errors.New("installed migration identity mismatch")
	}
	return lifecycleResult(GenerationMigrate, loaded), nil
}

// Rewrap seals the active exact key bytes under a new passphrase and appends a
// signed successor generation without changing its identity or descriptor.
func Rewrap(options RewrapOptions) (LifecycleResult, error) {
	var zero LifecycleResult
	if options.Store == nil {
		return zero, errors.New("store invalid")
	}
	currentPassphrase, err := readLifecycleRestricted(options.PassphrasePath, "passphrase")
	if err != nil {
		return zero, err
	}
	defer clear(currentPassphrase)
	loaded, err := options.Store.LoadActive(currentPassphrase)
	if err != nil {
		return zero, err
	}
	defer clearLoadedIdentity(&loaded)
	active, err := activeStoreGeneration(options.Store, loaded.KeyGeneration)
	if err != nil {
		return zero, err
	}
	descriptor, err := readLifecycleDescriptor(options.DescriptorPath)
	if err != nil {
		return zero, err
	}
	identity, err := identityFromDescriptor(descriptor, options.IdentityKind)
	if err != nil {
		return zero, err
	}
	descriptorDigest, err := digestCanonical(descriptor)
	if err != nil || descriptorDigest != loaded.KeyGeneration.DescriptorDigest || identity != loaded.Identity {
		return zero, errors.New("descriptor does not match active generation")
	}
	newPassphrase, err := readLifecycleRestricted(options.NewPassphrasePath, "new passphrase")
	if err != nil {
		return zero, err
	}
	defer clear(newPassphrase)
	envelope, err := SealEnvelope(SealOptions{KeyType: loaded.KeyType, Plaintext: loaded.Plaintext, Identity: loaded.Identity, Passphrase: newPassphrase, Iterations: options.Iterations})
	if err != nil {
		return zero, err
	}
	newEnvelope, err := ParseEnvelope(envelope)
	if err != nil {
		return zero, err
	}
	oldEnvelope, err := ParseEnvelope(active.envelopeBytes)
	if err != nil {
		return zero, err
	}
	if newEnvelope.KDF.Salt == oldEnvelope.KDF.Salt || newEnvelope.Cipher.Nonce == oldEnvelope.Cipher.Nonce {
		return zero, errors.New("rewrap material collision")
	}
	body, err := BuildGenerationBody(GenerationBodyOptions{Identity: loaded.Identity, Generation: active.record.Body.Generation + 1, Operation: GenerationRewrap, EnvelopeBytes: envelope, Descriptor: descriptor, PreviousRecord: &active.record})
	if err != nil {
		return zero, err
	}
	record, err := NewSignedGenerationRecord(body, loaded.PrivateKey)
	if err != nil {
		return zero, err
	}
	reloaded, err := options.Store.Install(InstallRequest{EnvelopeBytes: envelope, Record: record, Descriptor: descriptor, Passphrase: newPassphrase})
	if err != nil {
		return zero, err
	}
	defer clearLoadedIdentity(&reloaded)
	if reloaded.KeyType != loaded.KeyType || reloaded.Identity != loaded.Identity || !bytes.Equal(reloaded.Plaintext, loaded.Plaintext) || reloaded.KeyGeneration.Generation != body.Generation || reloaded.KeyGeneration.RecordDigest != record.RecordDigest {
		return zero, errors.New("rewrapped identity mismatch")
	}
	return lifecycleResult(GenerationRewrap, reloaded), nil
}

// Recover delegates to Store.Recover and deliberately creates no generation.
func Recover(options RecoverOptions) (LifecycleResult, error) {
	var zero LifecycleResult
	if options.Store == nil {
		return zero, errors.New("store invalid")
	}
	passphrase, err := readLifecycleRestricted(options.PassphrasePath, "passphrase")
	if err != nil {
		return zero, err
	}
	defer clear(passphrase)
	loaded, err := options.Store.Recover(passphrase)
	if err != nil {
		return zero, err
	}
	defer clearLoadedIdentity(&loaded)
	return lifecycleResult("recover", loaded), nil
}

func rotateAgentDescriptor(previous map[string]any, privateKey ed25519.PrivateKey) (map[string]any, Identity, error) {
	next := cloneGenerationMap(previous)
	if next == nil {
		return nil, Identity{}, errors.New("agent descriptor invalid")
	}
	delete(next, "aid")
	delete(next, "public_key_spki")
	delete(next, "descriptor_signature")
	publicKey := privateKey.Public().(ed25519.PublicKey)
	spki, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, Identity{}, err
	}
	identity := Identity{Kind: IdentityAID, Value: generationIdentityValueFromSPKI(IdentityAID, spki)}
	next["aid"] = identity.Value
	next["public_key_spki"] = base64.RawURLEncoding.EncodeToString(spki)
	if _, exists := previous["did_key"]; exists {
		next["did_key"] = "did:key:z" + base58Encode(append([]byte{0xed, 0x01}, publicKey...))
	}
	signature, err := signGenerationValue(privateKey, next)
	if err != nil {
		return nil, Identity{}, err
	}
	next["descriptor_signature"] = signature
	if _, err := descriptorPublicKey(next, identity); err != nil {
		return nil, Identity{}, err
	}
	return next, identity, nil
}

func base58Encode(value []byte) string {
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	number := new(big.Int).SetBytes(value)
	base := big.NewInt(58)
	zero := big.NewInt(0)
	modulus := new(big.Int)
	output := make([]byte, 0, len(value)*2)
	for number.Cmp(zero) > 0 {
		number.DivMod(number, base, modulus)
		output = append(output, alphabet[modulus.Int64()])
	}
	for _, item := range value {
		if item != 0 {
			break
		}
		output = append(output, alphabet[0])
	}
	for left, right := 0, len(output)-1; left < right; left, right = left+1, right-1 {
		output[left], output[right] = output[right], output[left]
	}
	if len(output) == 0 {
		return "1"
	}
	return string(output)
}

// RotateAgent creates an Ed25519 successor only for a verified active Agent.
// It binds the dual-signed successor to the exact active Zone generation before
// writing the candidate generation.
func RotateAgent(options RotateAgentOptions) (LifecycleResult, error) {
	var zero LifecycleResult
	if options.Store == nil || options.ZoneStore == nil {
		return zero, errors.New("rotation store invalid")
	}
	passphrase, err := readLifecycleRestricted(options.PassphrasePath, "passphrase")
	if err != nil {
		return zero, err
	}
	defer clear(passphrase)
	loaded, err := options.Store.LoadActive(passphrase)
	if err != nil {
		return zero, err
	}
	defer clearLoadedIdentity(&loaded)
	if loaded.Identity.Kind != IdentityAID {
		return zero, errors.New("only Agent identities may rotate")
	}
	active, err := activeStoreGeneration(options.Store, loaded.KeyGeneration)
	if err != nil {
		return zero, err
	}
	zonePassphrase, err := readLifecycleRestricted(options.ZonePassphrasePath, "zone passphrase")
	if err != nil {
		return zero, err
	}
	defer clear(zonePassphrase)
	zoneLoaded, err := options.ZoneStore.LoadActive(zonePassphrase)
	if err != nil {
		return zero, err
	}
	defer clearLoadedIdentity(&zoneLoaded)
	if zoneLoaded.Identity.Kind != IdentityZID {
		return zero, errors.New("rotation authorization is not a Zone")
	}
	zoneActive, err := activeStoreGeneration(options.ZoneStore, zoneLoaded.KeyGeneration)
	if err != nil {
		return zero, err
	}
	if revoked, _ := zoneActive.descriptor["revoked"].(bool); revoked || zoneActive.descriptor["status"] == "revoked" {
		return zero, errors.New("rotation Zone is revoked")
	}
	entropy := options.Entropy
	if entropy == nil {
		entropy = rand.Reader
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(entropy, seed); err != nil {
		clear(seed)
		return zero, err
	}
	defer clear(seed)
	nextKey := ed25519.NewKeyFromSeed(seed)
	defer clear(nextKey)
	nextDescriptor, nextIdentity, err := rotateAgentDescriptor(active.descriptor, nextKey)
	if err != nil {
		return zero, err
	}
	if nextIdentity == loaded.Identity {
		return zero, errors.New("rotation reused Agent identity")
	}
	envelope, err := SealEnvelope(SealOptions{KeyType: KeyTypeSeed, Plaintext: seed, Identity: nextIdentity, Passphrase: passphrase, Iterations: options.Iterations})
	if err != nil {
		return zero, err
	}
	body, err := BuildGenerationBody(GenerationBodyOptions{Identity: nextIdentity, Generation: active.record.Body.Generation + 1, Operation: GenerationRotate, EnvelopeBytes: envelope, Descriptor: nextDescriptor, PreviousRecord: &active.record})
	if err != nil {
		return zero, err
	}
	record, err := NewRotationGenerationRecord(body, active.descriptor, nextDescriptor, loaded.PrivateKey, nextKey, zoneActive.descriptor, zoneLoaded.PrivateKey, zoneLoaded.KeyGeneration)
	if err != nil {
		return zero, err
	}
	reloaded, err := options.Store.Install(InstallRequest{EnvelopeBytes: envelope, Record: record, Descriptor: nextDescriptor, PreviousDescriptor: active.descriptor, ZoneDescriptor: zoneActive.descriptor, ZoneRecord: zoneActive.record, Passphrase: passphrase})
	if err != nil {
		return zero, err
	}
	defer clearLoadedIdentity(&reloaded)
	if reloaded.Identity != nextIdentity || reloaded.KeyGeneration.Generation != body.Generation || reloaded.KeyGeneration.RecordDigest != record.RecordDigest || !bytes.Equal(reloaded.Plaintext, seed) {
		return zero, errors.New("rotated generation reload mismatch")
	}
	return lifecycleResult(GenerationRotate, reloaded), nil
}
