//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd

package verifier

import (
	"errors"
	"strings"
	"testing"
)

func TestSafeOpenOwnedJSONUnsupportedPlatformFailsClosed(t *testing.T) {
	value, evidence, err := SafeOpenOwnedJSON("ignored.json")
	if value != nil || evidence != (TrustInputFileEvidence{}) || !errors.Is(err, ErrSecureOwnedJSONUnsupported) || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("value=%v evidence=%+v error=%v", value, evidence, err)
	}
}
