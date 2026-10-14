package targets

import (
	"crypto/ed25519"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestPublicKeys(t *testing.T) {
	keys := PublicKeys()
	if len(keys) == 0 {
		t.Fatal("PublicKeys() is empty")
	}
	seen := map[string]bool{}
	for i, k := range keys {
		if len(k) != ed25519.PublicKeySize {
			t.Errorf("key %d: size %d", i, len(k))
		}
		if seen[string(k)] {
			t.Errorf("key %d is a duplicate", i)
		}
		seen[string(k)] = true
	}
}

// If targets/targets.signed.json exists, it must be signed by one of the
// built-in keys and follow the format. The clock is not checked, so that an
// expired file does not turn CI red for every unrelated change. Run by
// `make sign-check`.
func TestSignedTargetsFile(t *testing.T) {
	data, err := os.ReadFile("../../targets/targets.signed.json")
	if errors.Is(err, os.ErrNotExist) {
		t.Skip("targets/targets.signed.json does not exist")
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(PublicKeys(), data); err != nil {
		t.Fatal(err)
	}
}

// The label that `make release-check` looks for must stay on the test key.
func TestTestKeyIsLabelled(t *testing.T) {
	src, err := os.ReadFile("pubkeys.go")
	if err != nil {
		t.Fatal(err)
	}
	const testKey = "RHWyg49gLrR1LzXlx87zsuGZs6/66I0W+rB0PEPH/5U="
	for _, line := range strings.Split(string(src), "\n") {
		if strings.Contains(line, testKey) && !strings.Contains(line, "// TESTKEY") {
			t.Errorf("the test key has no // TESTKEY label: %q", line)
		}
	}
}
