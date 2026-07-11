//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd

package managedkey

import "errors"

type RestrictedFileOptions struct {
	Label    string
	MaxBytes int64
}

type RestrictedFileEvidence struct {
	Path   string `json:"path"`
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	UID    uint32 `json:"uid"`
	Mode   uint32 `json:"mode"`
	NLink  uint64 `json:"nlink"`
}

type RestrictedFile struct {
	Bytes    []byte
	Evidence RestrictedFileEvidence
}

func ReadRestrictedFile(string, RestrictedFileOptions) (RestrictedFile, error) {
	return RestrictedFile{}, errors.New("restricted file secure open unsupported on this platform")
}
