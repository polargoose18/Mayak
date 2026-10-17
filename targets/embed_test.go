package targets

import (
	"bytes"
	"os"
	"testing"

	list "github.com/polargoose18/mayak/internal/targets"
)

// The copy built into the binary is the file in the repository, and it is
// signed by a key built into the agent.
func TestSignedIsTheCommittedFile(t *testing.T) {
	want, err := os.ReadFile("targets.signed.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(Signed(), want) {
		t.Error("the built-in copy differs from targets.signed.json")
	}
	if _, err := list.Open(list.PublicKeys(), Signed()); err != nil {
		t.Errorf("the built-in copy does not open with the built-in keys: %v", err)
	}
}

// Changing the returned bytes does not change the built-in copy.
func TestSignedReturnsACopy(t *testing.T) {
	a := Signed()
	a[0] ^= 0xff
	if bytes.Equal(a, Signed()) {
		t.Error("Signed returned the built-in bytes themselves")
	}
}
