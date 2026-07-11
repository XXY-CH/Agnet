package managedkey

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	ActivePointerFormat   = "agnet-managed-key-active/v1"
	GenerationCommitFormat = "agnet-managed-key-generation-commit/v1"
	InstallClaimFormat    = "agnet-managed-key-install-claim/v1"
)

var ErrRecoveryRequired = errors.New("managed key recovery required")

type StoreOptions struct {
	Fault durableFault
}

type directoryIdentity struct {
	dev uint64
	ino uint64
}

type verifiedDirectory struct {
	file     *os.File
	path     string
	identity directoryIdentity
}

func (directory *verifiedDirectory) Close() error {
	return directory.file.Close()
}
func (directory *verifiedDirectory) child(name string) string {
	return filepath.Join(directory.path, name)
}

type Store struct {
	path                string
	rootIdentity        directoryIdentity
	generationsIdentity directoryIdentity
	fault               durableFault
}

type InstallRequest struct {
	EnvelopeBytes      []byte
	Record             GenerationRecord
	Descriptor         map[string]any
	PreviousDescriptor map[string]any
	ZoneDescriptor     map[string]any
	ZoneRecord         GenerationRecord
	Passphrase         []byte
}

type KeyGenerationRef struct {
	IdentityKind     string `json:"identity_kind"`
	IdentityValue    string `json:"identity_value"`
	Generation       int    `json:"generation"`
	RecordDigest     string `json:"record_digest"`
	EnvelopeSHA256   string `json:"envelope_sha256"`
	DescriptorDigest string `json:"descriptor_digest"`
}

type LoadedIdentity struct {
	KeyType       string
	Identity      Identity
	Plaintext     []byte
	PrivateKey    ed25519.PrivateKey
	KeyGeneration KeyGenerationRef
}

type activePointer struct {
	Format       string `json:"format"`
	Generation   int    `json:"generation"`
	RecordDigest string `json:"record_digest"`
}

type storeGeneration struct {
	generation         int
	envelopeBytes      []byte
	record             GenerationRecord
	descriptor         map[string]any
	previousDescriptor map[string]any
	zoneDescriptor     map[string]any
	zoneRecord         GenerationRecord
}

func validateOwnedMode(info os.FileInfo, label string, mode os.FileMode, wantDir bool) error {
	if wantDir && !info.IsDir() {
		return fmt.Errorf("%s must be directory", label)
	}
	if !wantDir && !info.Mode().IsRegular() {
		return fmt.Errorf("%s must be regular file", label)
	}
	if info.Mode().Perm() != mode {
		return fmt.Errorf("%s mode must be %04o", label, mode)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) {
		return fmt.Errorf("%s owner must be current uid", label)
	}
	if !wantDir && stat.Nlink != 1 {
		return fmt.Errorf("%s link count must be one", label)
	}
	return nil
}

func openNoFollowAt(directory *verifiedDirectory, leaf, label string) (*os.File, error) {
	fd, err := unix.Openat(int(directory.file.Fd()), leaf, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, fmt.Errorf("%s symbolic link rejected", label)
		}
		return nil, err
	}
	return os.NewFile(uintptr(fd), leaf), nil
}

func readPrivateFileAt(directory *os.File, leaf, label string) ([]byte, error) {
	fd, err := unix.Openat(int(directory.Fd()), leaf, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, fmt.Errorf("%s symbolic link rejected", label)
		}
		return nil, err
	}
	file := os.NewFile(uintptr(fd), leaf)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if err := validateOwnedMode(info, label, 0o600, false); err != nil {
		return nil, err
	}
	return io.ReadAll(file)
}

func readDirAt(directory *verifiedDirectory) ([]os.DirEntry, error) {
	fd, err := unix.Dup(int(directory.file.Fd()))
	if err != nil {
		return nil, err
	}
	copy := os.NewFile(uintptr(fd), "directory copy")
	defer copy.Close()
	return copy.ReadDir(-1)
}

func openNoFollow(path, label string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("%s symbolic link rejected", label)
		}
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func acquireGenerationLock(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o600)
	created := err == nil
	if err != nil && !errors.Is(err, syscall.EEXIST) {
		return nil, err
	}
	if !created {
		fd, err = syscall.Open(path, syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			if errors.Is(err, syscall.ELOOP) {
				return nil, errors.New("generation install lock symbolic link rejected")
			}
			return nil, err
		}
	}
	file := os.NewFile(uintptr(fd), path)
	if created {
		if err := file.Chmod(0o600); err != nil {
			_ = file.Close()
			return nil, err
		}
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := validateOwnedMode(info, "generation install lock", 0o600, false); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, errors.New("generation install already in progress")
		}
		return nil, err
	}
	return file, nil
}

func directoryIdentityFromInfo(info os.FileInfo, label string) (directoryIdentity, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return directoryIdentity{}, fmt.Errorf("%s identity unavailable", label)
	}
	return directoryIdentity{dev: uint64(stat.Dev), ino: uint64(stat.Ino)}, nil
}

func verifyPrivateDirectory(file *os.File, label string, expected *directoryIdentity) (*verifiedDirectory, error) {
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := validateOwnedMode(info, label, 0o700, true); err != nil {
		_ = file.Close()
		return nil, err
	}
	identity, err := directoryIdentityFromInfo(info, label)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if expected != nil && identity != *expected {
		_ = file.Close()
		return nil, fmt.Errorf("%s identity changed", label)
	}
	return &verifiedDirectory{file: file, path: file.Name(), identity: identity}, nil
}

func openVerifiedPrivateDir(path, label string, expected *directoryIdentity) (*verifiedDirectory, error) {
	file, err := openNoFollow(path, label)
	if err != nil {
		return nil, err
	}
	return verifyPrivateDirectory(file, label, expected)
}

func openVerifiedPrivateDirAt(parent *verifiedDirectory, leaf, label string, expected *directoryIdentity) (*verifiedDirectory, error) {
	file, err := openNoFollowAt(parent, leaf, label)
	if err != nil {
		return nil, err
	}
	directory, err := verifyPrivateDirectory(file, label, expected)
	if err != nil {
		return nil, err
	}
	directory.path = filepath.Join(parent.path, leaf)
	return directory, nil
}

func (store *Store) openVerifiedDirectories() (*verifiedDirectory, *verifiedDirectory, error) {
	root, err := openVerifiedPrivateDir(store.path, "managed key store", &store.rootIdentity)
	if err != nil {
		return nil, nil, err
	}
	generations, err := openVerifiedPrivateDirAt(root, "generations", "managed key generations directory", &store.generationsIdentity)
	if err != nil {
		_ = root.Close()
		return nil, nil, err
	}
	return root, generations, nil
}

func ensureExactPrivateDir(path, label string) error {
	linkInfo, err := os.Lstat(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := os.Mkdir(path, 0o700); err != nil {
			return err
		}
		if err := os.Chmod(path, 0o700); err != nil {
			return err
		}
		linkInfo, err = os.Lstat(path)
		if err != nil {
			return err
		}
	}
	if linkInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s symbolic link rejected", label)
	}
	file, err := openNoFollow(path, label)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	return validateOwnedMode(info, label, 0o700, true)
}

func readPrivateFile(path, label string) ([]byte, error) {
	file, err := openNoFollow(path, label)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if err := validateOwnedMode(info, label, 0o600, false); err != nil {
		return nil, err
	}
	return io.ReadAll(file)
}

func validateOwnedRegularFile(info os.FileInfo, label string) (*syscall.Stat_t, error) {
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must be regular file", label)
	}
	if info.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf("%s mode must be 0600", label)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) {
		return nil, fmt.Errorf("%s owner must be current uid", label)
	}
	return stat, nil
}

func isExactDurableTempName(name, leaf string) bool {
	prefix := "." + leaf + "."
	if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".tmp") {
		return false
	}
	parts := strings.Split(strings.TrimSuffix(strings.TrimPrefix(name, prefix), ".tmp"), ".")
	if len(parts) != 2 {
		return false
	}
	for _, part := range parts {
		if part == "" || part[0] == '0' {
			return false
		}
		for _, character := range part {
			if character < '0' || character > '9' {
				return false
			}
		}
	}
	return true
}

func generationFromDurableName(name string) (int, bool) {
	parts := strings.Split(name, ".")
	if len(parts) != 3 || len(parts[0]) != 16 || parts[2] != "json" {
		return 0, false
	}
	generation, err := strconv.Atoi(parts[0])
	if err != nil || generation < 1 {
		return 0, false
	}
	switch parts[1] {
	case "envelope", "record", "descriptor", "previous-descriptor", "zone-descriptor", "zone-record", "commit":
		return generation, true
	default:
		return 0, false
	}
}

func generationFromDurableTempName(name string) (int, bool) {
	if !strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".tmp") {
		return 0, false
	}
	parts := strings.Split(strings.TrimSuffix(strings.TrimPrefix(name, "."), ".tmp"), ".")
	if len(parts) != 5 || parts[2] != "json" {
		return 0, false
	}
	if !isExactDurableTempName(name, strings.Join(parts[:3], ".")) {
		return 0, false
	}
	return generationFromDurableName(strings.Join(parts[:3], "."))
}

func recoverExclusiveHardLink(path, label string) error {
	canonical, err := openNoFollow(path, label)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer canonical.Close()
	canonicalStat, err := canonical.Stat()
	if err != nil {
		return err
	}
	canonicalSystemStat, err := validateOwnedRegularFile(canonicalStat, label)
	if err != nil {
		return err
	}
	if canonicalSystemStat.Nlink == 1 {
		return nil
	}
	if canonicalSystemStat.Nlink != 2 {
		return fmt.Errorf("%s link count must be one", label)
	}
	dir := filepath.Dir(path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	leaf := filepath.Base(path)
	matchedTemp := ""
	for _, entry := range entries {
		if !isExactDurableTempName(entry.Name(), leaf) {
			continue
		}
		tempPath := filepath.Join(dir, entry.Name())
		temp, openErr := openNoFollow(tempPath, label+" temp")
		if openErr != nil {
			continue
		}
		tempStat, statErr := temp.Stat()
		_ = temp.Close()
		if statErr != nil {
			continue
		}
		tempSystemStat, validateErr := validateOwnedRegularFile(tempStat, label+" temp")
		if validateErr != nil || tempSystemStat.Nlink != 2 || tempSystemStat.Dev != canonicalSystemStat.Dev || tempSystemStat.Ino != canonicalSystemStat.Ino {
			continue
		}
		if matchedTemp != "" {
			return fmt.Errorf("%s link count must be one", label)
		}
		matchedTemp = tempPath
	}
	if matchedTemp == "" {
		return fmt.Errorf("%s link count must be one", label)
	}
	currentStat, err := canonical.Stat()
	if err != nil {
		return err
	}
	currentSystemStat, err := validateOwnedRegularFile(currentStat, label)
	if err != nil {
		return err
	}
	if currentSystemStat.Nlink != 2 || currentSystemStat.Dev != canonicalSystemStat.Dev || currentSystemStat.Ino != canonicalSystemStat.Ino {
		return fmt.Errorf("%s link count must be one", label)
	}
	if err := os.Remove(matchedTemp); err != nil {
		return err
	}
	if err := syncDir(dir); err != nil {
		return err
	}
	finalStat, err := canonical.Stat()
	if err != nil {
		return err
	}
	if err := validateOwnedMode(finalStat, label, 0o600, false); err != nil {
		return err
	}
	return nil
}

func recoverExclusiveHardLinkAt(directory *verifiedDirectory, leaf, label string) error {
	canonical, err := openNoFollowAt(directory, leaf, label)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer canonical.Close()
	canonicalStat, err := canonical.Stat()
	if err != nil {
		return err
	}
	canonicalSystemStat, err := validateOwnedRegularFile(canonicalStat, label)
	if err != nil {
		return err
	}
	if canonicalSystemStat.Nlink == 1 {
		return nil
	}
	if canonicalSystemStat.Nlink != 2 {
		return fmt.Errorf("%s link count must be one", label)
	}
	entries, err := readDirAt(directory)
	if err != nil {
		return err
	}
	matchedTemp := ""
	for _, entry := range entries {
		if !isExactDurableTempName(entry.Name(), leaf) {
			continue
		}
		temp, openErr := openNoFollowAt(directory, entry.Name(), label+" temp")
		if openErr != nil {
			continue
		}
		tempStat, statErr := temp.Stat()
		_ = temp.Close()
		if statErr != nil {
			continue
		}
		tempSystemStat, validateErr := validateOwnedRegularFile(tempStat, label+" temp")
		if validateErr != nil || tempSystemStat.Nlink != 2 || tempSystemStat.Dev != canonicalSystemStat.Dev || tempSystemStat.Ino != canonicalSystemStat.Ino {
			continue
		}
		if matchedTemp != "" {
			return fmt.Errorf("%s link count must be one", label)
		}
		matchedTemp = entry.Name()
	}
	if matchedTemp == "" {
		return fmt.Errorf("%s link count must be one", label)
	}
	currentStat, err := canonical.Stat()
	if err != nil {
		return err
	}
	currentSystemStat, err := validateOwnedRegularFile(currentStat, label)
	if err != nil || currentSystemStat.Nlink != 2 || currentSystemStat.Dev != canonicalSystemStat.Dev || currentSystemStat.Ino != canonicalSystemStat.Ino {
		return fmt.Errorf("%s link count must be one", label)
	}
	if err := unix.Unlinkat(int(directory.file.Fd()), matchedTemp, 0); err != nil {
		return err
	}
	if err := directory.file.Sync(); err != nil {
		return err
	}
	finalStat, err := canonical.Stat()
	if err != nil {
		return err
	}
	return validateOwnedMode(finalStat, label, 0o600, false)
}

func (store *Store) recoverGenerationExclusivePublications(generation int) error {
	for _, suffix := range []string{"envelope", "record", "descriptor", "previous-descriptor", "zone-descriptor", "commit"} {
		label := fmt.Sprintf("generation %d %s file", generation, suffix)
		if err := recoverExclusiveHardLink(generationFilePath(store.path, generation, suffix), label); err != nil {
			return err
		}
	}
	return nil
}

func (store *Store) recoverStrandedExclusivePublications(generationsDirectory *verifiedDirectory) error {
	entries, err := readDirAt(generationsDirectory)
	if err != nil {
		return err
	}
	generationSet := map[int]struct{}{}
	for _, entry := range entries {
		if generation, ok := generationFromDurableName(entry.Name()); ok {
			generationSet[generation] = struct{}{}
			continue
		}
		if generation, ok := generationFromDurableTempName(entry.Name()); ok {
			generationSet[generation] = struct{}{}
		}
	}
	generations := make([]int, 0, len(generationSet))
	for generation := range generationSet {
		generations = append(generations, generation)
	}
	sort.Ints(generations)
	for _, generation := range generations {
		lock, err := acquireGenerationLock(generationsDirectory.child(paddedGeneration(generation) + ".install.lock"))
		if err != nil {
			return err
		}
		recoveryErr := store.recoverGenerationExclusivePublications(generation)
		closeErr := lock.Close()
		if recoveryErr != nil {
			return recoveryErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

func OpenStore(path string, options *StoreOptions) (*Store, error) {
	if path == "" {
		return nil, errors.New("store path invalid")
	}
	if err := ensureExactPrivateDir(path, "managed key store"); err != nil {
		return nil, err
	}
	root, err := openVerifiedPrivateDir(path, "managed key store", nil)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	if err := ensureExactPrivateDir(filepath.Join(path, "generations"), "managed key generations directory"); err != nil {
		return nil, err
	}
	generations, err := openVerifiedPrivateDir(filepath.Join(path, "generations"), "managed key generations directory", nil)
	if err != nil {
		return nil, err
	}
	defer generations.Close()
	rootIdentity := root.identity
	generationsIdentity := generations.identity
	var fault durableFault
	if options != nil {
		fault = options.Fault
	}
	return &Store{path: path, rootIdentity: rootIdentity, generationsIdentity: generationsIdentity, fault: fault}, nil
}

func (store *Store) LoadActive(passphrase []byte) (LoadedIdentity, error) {
	var zero LoadedIdentity
	root, generations, err := store.openVerifiedDirectories()
	if err != nil {
		return zero, err
	}
	defer root.Close()
	defer generations.Close()
	if err := store.recoverStrandedExclusivePublications(generations); err != nil {
		return zero, err
	}
	return store.loadActive(root, generations, passphrase)
}

// LoadGeneration reopens the exact verified generation named by record digest.
// Unlike LoadActive, it deliberately does not consult the active pointer so a
// caller holding a record-digest pin can complete a subprocess operation after
// activation has advanced.
func (store *Store) LoadGeneration(passphrase []byte, recordDigest string) (LoadedIdentity, error) {
	var zero LoadedIdentity
	if !isGenerationDigest(recordDigest) {
		return zero, errors.New("generation reference invalid")
	}
	root, generations, err := store.openVerifiedDirectories()
	if err != nil {
		return zero, err
	}
	defer root.Close()
	defer generations.Close()
	if err := store.recoverStrandedExclusivePublications(generations); err != nil {
		return zero, err
	}
	scan, err := store.scanCompleteGenerations(generations)
	if err != nil {
		return zero, err
	}
	for _, item := range scan {
		if item.record.RecordDigest == recordDigest {
			return loadVerifiedGeneration(item, passphrase)
		}
	}
	return zero, errors.New("generation reference mismatch")
}

func (store *Store) loadActive(root, generations *verifiedDirectory, passphrase []byte) (LoadedIdentity, error) {
	var zero LoadedIdentity
	scan, err := store.scanCompleteGenerations(generations)
	if err != nil {
		return zero, err
	}
	pointer, ok, err := store.readActivePointer(root)
	if err != nil {
		return zero, err
	}
	if !ok {
		if len(scan) > 0 {
			return zero, ErrRecoveryRequired
		}
		return zero, errors.New("active pointer missing")
	}
	if pointer.Generation < 1 || pointer.Generation > len(scan) || scan[pointer.Generation-1].record.RecordDigest != pointer.RecordDigest {
		return zero, errors.New("active pointer mismatch")
	}
	highest := scan[len(scan)-1]
	if highest.record.Body.Generation > pointer.Generation {
		return zero, ErrRecoveryRequired
	}
	return loadVerifiedGeneration(scan[pointer.Generation-1], passphrase)
}

func (store *Store) Install(request InstallRequest) (LoadedIdentity, error) {
	var zero LoadedIdentity
	recordBytes, err := CanonicalGenerationRecord(request.Record)
	if err != nil {
		return zero, err
	}
	normalized, err := ParseGenerationRecord(recordBytes)
	if err != nil {
		return zero, err
	}
	root, generations, err := store.openVerifiedDirectories()
	if err != nil {
		return zero, err
	}
	defer root.Close()
	defer generations.Close()
	generation := normalized.Body.Generation
	lock, err := acquireGenerationLock(generations.child(paddedGeneration(generation) + ".install.lock"))
	if err != nil {
		return zero, err
	}
	defer lock.Close()
	if err := store.recoverGenerationExclusivePublications(generation); err != nil {
		return zero, err
	}
	pointer, activeOK, err := store.readActivePointer(root)
	if err != nil {
		return zero, err
	}
	scan, err := store.scanCompleteGenerations(generations)
	if err != nil {
		return zero, err
	}
	if activeOK {
		if len(scan) == 0 || scan[len(scan)-1].record.Body.Generation != pointer.Generation || scan[len(scan)-1].record.RecordDigest != pointer.RecordDigest {
			return zero, ErrRecoveryRequired
		}
		if normalized.Body.Generation != pointer.Generation+1 {
			return zero, errors.New("generation install is not next active generation")
		}
	} else if len(scan) != 0 || normalized.Body.Generation != 1 {
		return zero, ErrRecoveryRequired
	}
	bundle, err := normalizeInstallRequest(request, normalized)
	if err != nil {
		return zero, err
	}
	candidateChain := append(append([]storeGeneration{}, scan...), bundle)
	verified, err := verifyStoreChain(candidateChain, nil)
	if err != nil {
		return zero, err
	}
	if _, err := OpenEnvelope(bundle.envelopeBytes, request.Passphrase); err != nil {
		return zero, err
	}
	files := storeFiles(bundle)
	for _, suffix := range generationFileSuffixes(bundle.record) {
		if err := durableWriteFile(generations.child(generationFileName(generation, suffix)), files[suffix], durableWriteOptions{Mode: 0o600, PointPrefix: suffix, Fault: store.fault, Exclusive: true}); err != nil {
			return zero, err
		}
	}
	reloaded, err := store.scanCompleteGenerations(generations)
	if err != nil {
		return zero, err
	}
	found := false
	for _, item := range reloaded {
		if item.record.Body.Generation == generation && item.record.RecordDigest == verified[len(verified)-1].record.RecordDigest {
			found = true
		}
	}
	if !found {
		return zero, errors.New("installed generation did not reload")
	}
	if err := store.writeActivePointer(root, activePointer{Format: ActivePointerFormat, Generation: generation, RecordDigest: normalized.RecordDigest}); err != nil {
		return zero, err
	}
	return store.loadActive(root, generations, request.Passphrase)
}

func (store *Store) Recover(passphrase []byte) (LoadedIdentity, error) {
	var zero LoadedIdentity
	root, generations, err := store.openVerifiedDirectories()
	if err != nil {
		return zero, err
	}
	defer root.Close()
	defer generations.Close()
	if err := store.recoverStrandedExclusivePublications(generations); err != nil {
		return zero, err
	}
	scan, err := store.scanCompleteGenerations(generations)
	if err != nil {
		return zero, err
	}
	if len(scan) == 0 {
		return zero, errors.New("no complete generation to recover")
	}
	highest := scan[len(scan)-1]
	loaded, err := loadVerifiedGeneration(highest, passphrase)
	if err != nil {
		return zero, err
	}
	if err := store.writeActivePointer(root, activePointer{Format: ActivePointerFormat, Generation: highest.record.Body.Generation, RecordDigest: highest.record.RecordDigest}); err != nil {
		return zero, err
	}
	return loaded, nil
}

func normalizeInstallRequest(request InstallRequest, record GenerationRecord) (storeGeneration, error) {
	descriptorBytes, err := canonicalJSON(request.Descriptor)
	if err != nil {
		return storeGeneration{}, err
	}
	descriptor, err := parseDescriptorBytes(descriptorBytes, false, "descriptor")
	if err != nil {
		return storeGeneration{}, err
	}
	item := storeGeneration{generation: record.Body.Generation, envelopeBytes: append([]byte(nil), request.EnvelopeBytes...), record: record, descriptor: descriptor}
	if record.Body.Operation == GenerationRotate {
		if request.PreviousDescriptor == nil || request.ZoneDescriptor == nil {
			return storeGeneration{}, errors.New("rotate generation requires descriptor trust material")
		}
		previousBytes, err := canonicalJSON(request.PreviousDescriptor)
		if err != nil {
			return storeGeneration{}, err
		}
		item.previousDescriptor, err = parseDescriptorBytes(previousBytes, false, "previous descriptor")
		if err != nil {
			return storeGeneration{}, err
		}
		zoneBytes, err := canonicalJSON(request.ZoneDescriptor)
		if err != nil {
			return storeGeneration{}, err
		}
		item.zoneDescriptor, err = parseDescriptorBytes(zoneBytes, true, "zone descriptor")
		if err != nil {
			return storeGeneration{}, err
		}
		if _, bound := record.GenerationRebinding["zone_generation"]; bound {
			if request.ZoneRecord.Body.Generation == 0 {
				return storeGeneration{}, errors.New("rotate generation requires Zone authorization record")
			}
			zoneRecordBytes, err := CanonicalGenerationRecord(request.ZoneRecord)
			if err != nil {
				return storeGeneration{}, err
			}
			item.zoneRecord, err = ParseGenerationRecord(zoneRecordBytes)
			if err != nil {
				return storeGeneration{}, err
			}
			if err := verifyZoneAuthorizationRecord(item.zoneRecord, item.zoneDescriptor, record.GenerationRebinding); err != nil {
				return storeGeneration{}, err
			}
		}
	}
	return item, nil
}

func verifyZoneAuthorizationRecord(record GenerationRecord, descriptor, rebinding map[string]any) error {
	zoneGeneration, err := exactInteger(rebinding["zone_generation"], "Zone authorization generation")
	if err != nil {
		return err
	}
	zoneDigest, err := exactString(rebinding["zone_record_digest"], "Zone authorization record digest")
	if err != nil {
		return err
	}
	zoneID, ok := descriptor["zid"].(string)
	if !ok || record.Body.IdentityKind != IdentityZID || record.Body.IdentityValue != zoneID || record.Body.Generation != zoneGeneration || record.RecordDigest != zoneDigest {
		return errors.New("Zone authorization record mismatch")
	}
	descriptorDigest, err := digestCanonical(descriptor)
	if err != nil || descriptorDigest != record.Body.DescriptorDigest {
		return errors.New("Zone authorization descriptor mismatch")
	}
	key, err := descriptorPublicKey(descriptor, Identity{Kind: IdentityZID, Value: zoneID})
	if err != nil {
		return err
	}
	if err := verifyGenerationSignature(key, generationSignaturePayload(record.Body, record.RecordDigest), record.IdentitySignature); err != nil {
		return errors.New("Zone authorization record signature invalid")
	}
	return nil
}

func storeFiles(item storeGeneration) map[string][]byte {
	files := map[string][]byte{"envelope": append([]byte(nil), item.envelopeBytes...)}
	recordBytes, _ := CanonicalGenerationRecord(item.record)
	files["record"] = recordBytes
	descriptorBytes, _ := canonicalJSON(item.descriptor)
	files["descriptor"] = descriptorBytes
	if item.record.Body.Operation == GenerationRotate {
		previousBytes, _ := canonicalJSON(item.previousDescriptor)
		zoneBytes, _ := canonicalJSON(item.zoneDescriptor)
		files["previous-descriptor"] = previousBytes
		files["zone-descriptor"] = zoneBytes
		if item.zoneRecord.Body.Generation != 0 {
			zoneRecordBytes, _ := CanonicalGenerationRecord(item.zoneRecord)
			files["zone-record"] = zoneRecordBytes
		}
	}
	commitBytes, _ := canonicalJSON(map[string]any{"format": GenerationCommitFormat, "generation": item.record.Body.Generation, "record_digest": item.record.RecordDigest})
	files["commit"] = commitBytes
	return files
}

func generationFileSuffixes(record GenerationRecord) []string {
	suffixes := []string{"envelope", "record", "descriptor"}
	if record.Body.Operation == GenerationRotate {
		suffixes = append(suffixes, "previous-descriptor", "zone-descriptor")
		if _, bound := record.GenerationRebinding["zone_generation"]; bound {
			suffixes = append(suffixes, "zone-record")
		}
	}
	return append(suffixes, "commit")
}

func (store *Store) readActivePointer(root *verifiedDirectory) (activePointer, bool, error) {
	data, err := readPrivateFile(root.child("active.json"), "active pointer file")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return activePointer{}, false, nil
		}
		return activePointer{}, false, err
	}
	decoded, err := decodeExactJSON(data)
	if err != nil {
		return activePointer{}, false, err
	}
	object, err := exactObject(decoded, []string{"format", "generation", "record_digest"}, "active pointer")
	if err != nil {
		return activePointer{}, false, err
	}
	format, err := exactString(object["format"], "active pointer format")
	if err != nil {
		return activePointer{}, false, err
	}
	generation, err := exactInteger(object["generation"], "active pointer generation")
	if err != nil {
		return activePointer{}, false, err
	}
	digest, err := exactString(object["record_digest"], "active pointer record digest")
	if err != nil {
		return activePointer{}, false, err
	}
	if format != ActivePointerFormat || generation < 1 || !isGenerationDigest(digest) {
		return activePointer{}, false, errors.New("active pointer invalid")
	}
	return activePointer{Format: format, Generation: generation, RecordDigest: digest}, true, nil
}

func (store *Store) writeActivePointer(root *verifiedDirectory, pointer activePointer) error {
	bytes, err := canonicalJSON(map[string]any{"format": ActivePointerFormat, "generation": pointer.Generation, "record_digest": pointer.RecordDigest})
	if err != nil {
		return err
	}
	return durableWriteFile(root.child("active.json"), bytes, durableWriteOptions{Mode: 0o600, PointPrefix: "active", Fault: store.fault, KeepAfterRenameFault: true})
}

func (store *Store) scanCompleteGenerations(generationsDirectory *verifiedDirectory) ([]storeGeneration, error) {
	entries, err := os.ReadDir(generationsDirectory.path)
	if err != nil {
		return nil, err
	}
	groups := map[int]map[string]string{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".tmp") || !strings.HasSuffix(name, ".json") {
			continue
		}
		parts := strings.Split(name, ".")
		if len(parts) != 3 || len(parts[0]) != 16 {
			continue
		}
		generation, err := strconv.Atoi(parts[0])
		if err != nil || generation < 1 {
			return nil, errors.New("generation filename invalid")
		}
		suffix := parts[1]
		if suffix != "envelope" && suffix != "record" && suffix != "descriptor" && suffix != "previous-descriptor" && suffix != "zone-descriptor" && suffix != "zone-record" && suffix != "commit" {
			continue
		}
		if groups[generation] == nil {
			groups[generation] = map[string]string{}
		}
		groups[generation][suffix] = generationsDirectory.child(name)
	}
	generations := make([]int, 0, len(groups))
	for generation := range groups {
		generations = append(generations, generation)
	}
	sort.Ints(generations)
	items := []storeGeneration{}
	for _, generation := range generations {
		files := groups[generation]
		if files["envelope"] == "" || files["record"] == "" || files["descriptor"] == "" || files["commit"] == "" {
			continue
		}
		item, err := readStoreGeneration(generation, files)
		if err != nil {
			return nil, fmt.Errorf("malformed complete generation %d: %w", generation, err)
		}
		items = append(items, item)
	}
	if len(items) == 0 {
		return items, nil
	}
	return verifyStoreChain(items, nil)
}

func readStoreGeneration(generation int, files map[string]string) (storeGeneration, error) {
	envelopeBytes, err := readPrivateFile(files["envelope"], fmt.Sprintf("generation %d envelope file", generation))
	if err != nil {
		return storeGeneration{}, err
	}
	recordBytes, err := readPrivateFile(files["record"], fmt.Sprintf("generation %d record file", generation))
	if err != nil {
		return storeGeneration{}, err
	}
	record, err := ParseGenerationRecord(recordBytes)
	if err != nil {
		return storeGeneration{}, err
	}
	if record.Body.Generation != generation {
		return storeGeneration{}, errors.New("generation filename mismatch")
	}
	commitBytes, err := readPrivateFile(files["commit"], fmt.Sprintf("generation %d commit file", generation))
	if err != nil {
		return storeGeneration{}, err
	}
	if err := verifyGenerationCommit(commitBytes, generation, record.RecordDigest); err != nil {
		return storeGeneration{}, err
	}
	descriptorBytes, err := readPrivateFile(files["descriptor"], fmt.Sprintf("generation %d descriptor file", generation))
	if err != nil {
		return storeGeneration{}, err
	}
	descriptor, err := parseDescriptorBytes(descriptorBytes, false, "descriptor")
	if err != nil {
		return storeGeneration{}, err
	}
	item := storeGeneration{generation: generation, envelopeBytes: envelopeBytes, record: record, descriptor: descriptor}
	if record.Body.Operation == GenerationRotate {
		if files["previous-descriptor"] == "" || files["zone-descriptor"] == "" {
			return storeGeneration{}, errors.New("rotate generation trust material incomplete")
		}
		previousBytes, err := readPrivateFile(files["previous-descriptor"], fmt.Sprintf("generation %d previous descriptor file", generation))
		if err != nil {
			return storeGeneration{}, err
		}
		item.previousDescriptor, err = parseDescriptorBytes(previousBytes, false, "previous descriptor")
		if err != nil {
			return storeGeneration{}, err
		}
		zoneBytes, err := readPrivateFile(files["zone-descriptor"], fmt.Sprintf("generation %d zone descriptor file", generation))
		if err != nil {
			return storeGeneration{}, err
		}
		item.zoneDescriptor, err = parseDescriptorBytes(zoneBytes, true, "zone descriptor")
		if err != nil {
			return storeGeneration{}, err
		}
		if _, bound := record.GenerationRebinding["zone_generation"]; bound {
			if files["zone-record"] == "" {
				return storeGeneration{}, errors.New("rotate generation Zone authorization record missing")
			}
			zoneRecordBytes, err := readPrivateFile(files["zone-record"], fmt.Sprintf("generation %d Zone authorization record file", generation))
			if err != nil {
				return storeGeneration{}, err
			}
			item.zoneRecord, err = ParseGenerationRecord(zoneRecordBytes)
			if err != nil {
				return storeGeneration{}, err
			}
			if err := verifyZoneAuthorizationRecord(item.zoneRecord, item.zoneDescriptor, record.GenerationRebinding); err != nil {
				return storeGeneration{}, err
			}
		}
	}
	return item, nil
}

func verifyGenerationCommit(data []byte, generation int, recordDigest string) error {
	decoded, err := decodeExactJSON(data)
	if err != nil {
		return err
	}
	object, err := exactObject(decoded, []string{"format", "generation", "record_digest"}, "generation commit")
	if err != nil {
		return err
	}
	format, err := exactString(object["format"], "generation commit format")
	if err != nil {
		return err
	}
	committedGeneration, err := exactInteger(object["generation"], "generation commit generation")
	if err != nil {
		return err
	}
	committedDigest, err := exactString(object["record_digest"], "generation commit record digest")
	if err != nil {
		return err
	}
	if format != GenerationCommitFormat || committedGeneration != generation || committedDigest != recordDigest {
		return errors.New("generation commit invalid")
	}
	return nil
}

func parseDescriptorBytes(data []byte, zone bool, label string) (map[string]any, error) {
	decoded, err := decodeExactJSON(data)
	if err != nil {
		return nil, err
	}
	return parseExactGenerationMap(decoded, generationDescriptorFields(decoded, zone), label)
}

func verifyStoreChain(items []storeGeneration, active *GenerationPointer) ([]storeGeneration, error) {
	records := make([]GenerationRecord, 0, len(items))
	envelopes := make([][]byte, 0, len(items))
	descriptors := make([]map[string]any, 0, len(items))
	previousDescriptors := make([]map[string]any, 0, len(items))
	zoneDescriptors := make([]map[string]any, 0, len(items))
	for _, item := range items {
		records = append(records, item.record)
		envelopes = append(envelopes, item.envelopeBytes)
		descriptors = append(descriptors, item.descriptor)
		previousDescriptors = append(previousDescriptors, item.previousDescriptor)
		zoneDescriptors = append(zoneDescriptors, item.zoneDescriptor)
	}
	verified, err := VerifyGenerationChain(records, envelopes, GenerationChainContext{Descriptors: descriptors, PreviousDescriptors: previousDescriptors, ZoneDescriptors: zoneDescriptors, ActivePointer: active})
	if err != nil {
		return nil, err
	}
	out := make([]storeGeneration, 0, len(items))
	for index, item := range items {
		item.record = verified[index]
		out = append(out, item)
	}
	return out, nil
}

func loadVerifiedGeneration(item storeGeneration, passphrase []byte) (LoadedIdentity, error) {
	opened, err := OpenEnvelope(item.envelopeBytes, passphrase)
	if err != nil {
		return LoadedIdentity{}, err
	}
	if opened.Identity.Kind != item.record.Body.IdentityKind || opened.Identity.Value != item.record.Body.IdentityValue {
		return LoadedIdentity{}, errors.New("loaded identity mismatch")
	}
	return LoadedIdentity{
		KeyType:    opened.KeyType,
		Identity:   opened.Identity,
		Plaintext:  opened.Plaintext,
		PrivateKey: opened.PrivateKey,
		KeyGeneration: keyGenerationReference(item.record),
	}, nil
}

func keyGenerationReference(record GenerationRecord) KeyGenerationRef {
	return KeyGenerationRef{
		IdentityKind:     record.Body.IdentityKind,
		IdentityValue:    record.Body.IdentityValue,
		Generation:       record.Body.Generation,
		RecordDigest:     record.RecordDigest,
		EnvelopeSHA256:   record.Body.EnvelopeSHA256,
		DescriptorDigest: record.Body.DescriptorDigest,
	}
}

func generationFileName(generation int, suffix string) string {
	return paddedGeneration(generation) + "." + suffix + ".json"
}

func generationFilePath(root string, generation int, suffix string) string {
	return filepath.Join(root, "generations", generationFileName(generation, suffix))
}

func paddedGeneration(generation int) string {
	return fmt.Sprintf("%016d", generation)
}

func digestBytesHex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
