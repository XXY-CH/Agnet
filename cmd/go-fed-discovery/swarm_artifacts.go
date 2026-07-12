package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

var ErrArtifactNotCommitted = errors.New("staged artifact is not committed")

// ArtifactTriple is the receipt-addressable identity of immutable bytes.
type ArtifactTriple struct {
	URI          string `json:"uri"`
	SHA256       string `json:"sha256"`
	ManifestHash string `json:"manifest_hash"`
}

// StagedArtifact identifies a private CAS object. Its Path is not a publication handle.
type StagedArtifact struct {
	SHA256 string
	Size   uint64
	Path   string
}

func (artifact StagedArtifact) Triple() ArtifactTriple {
	return ArtifactTriple{URI: "artifact://local/sha256/" + artifact.SHA256, SHA256: artifact.SHA256, ManifestHash: artifact.SHA256}
}

// StageArtifact writes immutable bytes into the swarm-private digest CAS. No journal state and no
// result view is created here; a receipt.committed entry is the only publication authority.
func StageArtifact(journal *SwarmJournal, data []byte) (StagedArtifact, error) {
	if journal == nil || len(data) == 0 {
		return StagedArtifact{}, errors.New("swarm journal and nonempty artifact are required")
	}
	digest := sha256.Sum256(data)
	hexDigest := hex.EncodeToString(digest[:])
	dir, err := swarmArtifactObjectsDir(journal)
	if err != nil {
		return StagedArtifact{}, err
	}
	path := filepath.Join(dir, hexDigest)
	if err := createExclusiveArtifact(path, data); err != nil {
		return StagedArtifact{}, err
	}
	return StagedArtifact{SHA256: hexDigest, Size: uint64(len(data)), Path: path}, nil
}

func swarmArtifactObjectsDir(journal *SwarmJournal) (string, error) {
	root := filepath.Dir(journal.Path)
	if err := validatePrivateDirectory(root); err != nil {
		return "", fmt.Errorf("swarm artifact parent: %w", err)
	}
	path := filepath.Join(root, "objects")
	if err := mkdirPrivateDirectory(path); err != nil {
		return "", err
	}
	return path, nil
}

func mkdirPrivateDirectory(path string) error {
	if err := unix.Mkdir(path, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	return validatePrivateDirectory(path)
}

func validatePrivateDirectory(path string) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0o777 != 0o700 || stat.Nlink < 2 || int(stat.Uid) != os.Geteuid() {
		return errors.New("artifact directory is not private and owned")
	}
	return nil
}

func createExclusiveArtifact(path string, data []byte) error {
	if err := validateArtifactName(path); err != nil {
		return err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err == nil {
		file := os.NewFile(uintptr(fd), path)
		defer file.Close()
		return verifyArtifactFile(file, data)
	}
	if !errors.Is(err, unix.ENOENT) {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".stage-")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := verifyArtifactFile(tmp, data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := unix.Link(tmpPath, path); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return openAndVerifyArtifact(path, data)
		}
		return err
	}
	if err := syncSwarmJournalParent(path); err != nil {
		return err
	}
	return nil
}

func openAndVerifyArtifact(path string, data []byte) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	return verifyArtifactFile(file, data)
}

func verifyArtifactFile(file *os.File, want []byte) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || stat.Nlink != 1 || int(stat.Uid) != os.Geteuid() || info.Size() != int64(len(want)) {
		return errors.New("staged artifact file invalid")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	actual, err := io.ReadAll(file)
	if err != nil {
		return err
	}
	if !bytes.Equal(actual, want) {
		return errors.New("staged artifact digest conflicts with existing object")
	}
	return nil
}

func validateArtifactName(path string) error {
	name := filepath.Base(path)
	if len(name) != 64 {
		return errors.New("artifact digest invalid")
	}
	if _, err := hex.DecodeString(name); err != nil {
		return errors.New("artifact digest invalid")
	}
	return nil
}

func readStagedArtifact(journal *SwarmJournal, artifact StagedArtifact) ([]byte, error) {
	if artifact.SHA256 == "" || artifact.Size == 0 || !validArtifactTriple(artifact.Triple()) {
		return nil, errors.New("staged artifact invalid")
	}
	dir, err := swarmArtifactObjectsDir(journal)
	if err != nil {
		return nil, err
	}
	if artifact.Path != filepath.Join(dir, artifact.SHA256) {
		return nil, errors.New("staged artifact path invalid")
	}
	fd, err := unix.Open(artifact.Path, unix.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), artifact.Path)
	defer file.Close()
	data, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}
	if uint64(len(data)) != artifact.Size || digestBytesHex(data) != artifact.SHA256 {
		return nil, errors.New("staged artifact bytes invalid")
	}
	if err := verifyArtifactFile(file, data); err != nil {
		return nil, err
	}
	return data, nil
}

// ReadCommittedArtifact returns bytes only when the exact artifact triple is journal-authorized.
func ReadCommittedArtifact(journal *SwarmJournal, artifact StagedArtifact) ([]byte, error) {
	if journal == nil {
		return nil, errors.New("swarm journal is required")
	}
	var committed bool
	err := journal.WithLockedReplay(func(entries []SwarmJournalEntry) error {
		for _, entry := range entries {
			if entry.Kind != "receipt.committed" {
				continue
			}
			var payload receiptCommittedPayload
			if decodeStrictSwarmPayload(entry.Payload, &payload) == nil && (payload.Result == artifact.Triple() || containsArtifactTriple(payload.Auxiliary, artifact.Triple())) {
				committed = true
				return nil
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !committed {
		return nil, ErrArtifactNotCommitted
	}
	return readStagedArtifact(journal, artifact)
}

func validArtifactTriple(triple ArtifactTriple) bool {
	return triple.URI == "artifact://local/sha256/"+triple.SHA256 && len(triple.SHA256) == 64 && isHexDigest(triple.SHA256) && triple.ManifestHash == triple.SHA256
}

func containsArtifactTriple(values []ArtifactTriple, target ArtifactTriple) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
