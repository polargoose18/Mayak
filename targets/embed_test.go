package targets

import (
	"bytes"
	"os"
	"testing"
	"time"

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

// TestFreshEnough covers the freshness guard logic itself: a list expiring
// outside the warning window passes, one expiring inside it or already past
// fails.
func TestFreshEnough(t *testing.T) {
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	warn := 7 * 24 * time.Hour
	cases := []struct {
		name    string
		expires time.Time
		wantErr bool
	}{
		{"28 days left", now.Add(28 * 24 * time.Hour), false},
		{"8 days left", now.Add(8 * 24 * time.Hour), false},
		{"exactly 7 days left", now.Add(7 * 24 * time.Hour), true},
		{"6 days left", now.Add(6 * 24 * time.Hour), true},
		{"already past", now.Add(-1 * time.Hour), true},
		{"zero", time.Time{}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := freshEnough(tc.expires, now, warn)
			if (err != nil) != tc.wantErr {
				t.Errorf("freshEnough(%v, %v, %v) = %v, wantErr %v", tc.expires, now, warn, err, tc.wantErr)
			}
		})
	}
}

// TestEmbeddedListFreshness fails when the built-in signed list expires
// within 7 days of now or is already expired, so the owner re-signs it in
// time. CI runs it as `make targets-expiry` with continue-on-error: a warning,
// not a blocker for unrelated PRs.
func TestEmbeddedListFreshness(t *testing.T) {
	if os.Getenv("MAYAK_TARGETS_EXPIRY_GUARD") != "1" {
		t.Skip("set MAYAK_TARGETS_EXPIRY_GUARD=1 to check the embedded list expiry")
	}
	tl, err := list.Open(list.PublicKeys(), Signed())
	if err != nil {
		t.Fatalf("open embedded signed list: %v", err)
	}
	if err := freshEnough(tl.Expires, time.Now(), 7*24*time.Hour); err != nil {
		t.Fatalf("embedded targets list is about to expire: %v", err)
	}
}
