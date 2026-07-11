//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd

package verifier

import (
	"errors"
	"runtime"
)

var ErrSecureOwnedJSONUnsupported = errors.New("owned JSON secure open unsupported on " + runtime.GOOS)

func SafeOpenOwnedJSON(string) (map[string]any, TrustInputFileEvidence, error) {
	return nil, TrustInputFileEvidence{}, ErrSecureOwnedJSONUnsupported
}
