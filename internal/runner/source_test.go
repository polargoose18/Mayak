package runner

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/polargoose18/mayak/internal/targets"
	builtin "github.com/polargoose18/mayak/targets"
)

func envWith(pub ed25519.PublicKey, now time.Time) Env {
	return Env{PublicKeys: []ed25519.PublicKey{pub}, Clock: &fakeClock{now: now}}
}

// checkMessage checks what the user will read: plain ASCII English, the
// explanation and not a chain of Go errors.
func checkMessage(t *testing.T, err error, wantParts ...string) {
	t.Helper()
	var se *SourceError
	if !errors.As(err, &se) {
		t.Fatalf("err = %v (%T), want *SourceError", err, err)
	}
	msg := err.Error()
	if msg != se.Msg {
		t.Errorf("Error() = %q, want only the message %q", msg, se.Msg)
	}
	for _, r := range msg {
		if r > 0x7e || (r < 0x20) {
			t.Errorf("message has a non-ASCII or control character %q: %q", r, msg)
			break
		}
	}
	for _, part := range wantParts {
		if !strings.Contains(msg, part) {
			t.Errorf("message %q does not mention %q", msg, part)
		}
	}
}

func TestLoadBuiltInList(t *testing.T) {
	// Run the clock one day before the built-in list expires, so that the
	// test keeps passing after the list is signed again.
	l, err := targets.Open(targets.PublicKeys(), builtin.Signed())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	env := Env{Clock: &fakeClock{now: l.Expires.Add(-24 * time.Hour)}} // PublicKeys nil: the built-in keys

	got, err := Source{Dir: dir}.Load(env)
	if err != nil {
		t.Fatal(err)
	}
	if got.Rev != l.Rev || len(got.Items) != len(l.Items) {
		t.Errorf("got rev %s with %d targets, want %s with %d", got.Rev, len(got.Items), l.Rev, len(l.Items))
	}
	if b, _ := os.ReadFile(filepath.Join(dir, RevFile)); string(b) != l.Rev+"\n" {
		t.Errorf("rev file = %q, want the accepted rev", b)
	}
}

func TestLoadTargetsFile(t *testing.T) {
	pub, priv := newKey(t)
	path := signedFile(t, priv, listOf("2026-10-20.2", testNow.Add(14*24*time.Hour), 24))
	got, err := Source{File: path, Dir: t.TempDir()}.Load(envWith(pub, testNow))
	if err != nil {
		t.Fatal(err)
	}
	if got.Rev != "2026-10-20.2" || len(got.Items) != 24 {
		t.Errorf("got %s with %d targets", got.Rev, len(got.Items))
	}
	// The built-in list is not trusted under a test key: the file is used, not it.
	if _, err := (Source{Dir: t.TempDir()}).Load(envWith(pub, testNow)); !errors.Is(err, targets.ErrBadSignature) {
		t.Errorf("built-in list under a test key: err = %v, want ErrBadSignature", err)
	}
}

func TestLoadExpiredList(t *testing.T) {
	pub, priv := newKey(t)
	path := signedFile(t, priv, listOf("2026-10-01.1", testNow.Add(-time.Hour), 24))
	dir := t.TempDir()
	_, err := Source{File: path, Dir: dir}.Load(envWith(pub, testNow))
	if !errors.Is(err, targets.ErrExpired) {
		t.Fatalf("err = %v, want ErrExpired", err)
	}
	checkMessage(t, err, "expired on 2026-10-20", "--targets-file", "update")
	if _, err := os.Stat(filepath.Join(dir, RevFile)); err == nil {
		t.Error("an expired list must not be recorded")
	}
}

func TestLoadRollbackIsRefused(t *testing.T) {
	pub, priv := newKey(t)
	dir := t.TempDir()
	env := envWith(pub, testNow)
	exp := testNow.Add(14 * 24 * time.Hour)
	if _, err := (Source{File: signedFile(t, priv, listOf("2026-10-20.5", exp, 24)), Dir: dir}).Load(env); err != nil {
		t.Fatal(err)
	}
	_, err := Source{File: signedFile(t, priv, listOf("2026-10-20.4", exp, 24)), Dir: dir}.Load(env)
	if !errors.Is(err, targets.ErrRollback) {
		t.Fatalf("err = %v, want ErrRollback", err)
	}
	checkMessage(t, err, "2026-10-20.4", "2026-10-20.5", "older", "newer")
	if b, _ := os.ReadFile(filepath.Join(dir, RevFile)); string(b) != "2026-10-20.5\n" {
		t.Errorf("rev file = %q, it must stay at the newer rev", b)
	}
}

func TestLoadDamagedRevFile(t *testing.T) {
	pub, priv := newKey(t)
	dir := t.TempDir()
	revPath := filepath.Join(dir, RevFile)
	if err := os.WriteFile(revPath, []byte("SECRET-junk\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := signedFile(t, priv, listOf("2026-10-20.1", testNow.Add(24*time.Hour), 24))
	_, err := Source{File: path, Dir: dir}.Load(envWith(pub, testNow))
	if !errors.Is(err, targets.ErrRevStoreDamaged) {
		t.Fatalf("err = %v, want ErrRevStoreDamaged", err)
	}
	checkMessage(t, err, revPath, "damaged", "Delete it only if you trust")
	if strings.Contains(err.Error(), "SECRET") {
		t.Error("the message repeats the file's content")
	}
	if b, _ := os.ReadFile(revPath); string(b) != "SECRET-junk\n" {
		t.Errorf("the damaged file was changed to %q", b)
	}
}

func TestLoadOtherFailures(t *testing.T) {
	pub, priv := newKey(t)
	otherPub, _ := newKey(t)
	good := listOf("2026-10-20.1", testNow.Add(24*time.Hour), 24)

	v2 := good
	v2.V = 2
	v2payload, _ := json.Marshal(v2)
	v2file := filepath.Join(t.TempDir(), "v2.json")
	if err := os.WriteFile(v2file, signRaw(t, priv, v2payload), 0o600); err != nil {
		t.Fatal(err)
	}
	junk := filepath.Join(t.TempDir(), "junk.json")
	if err := os.WriteFile(junk, []byte("not a list"), 0o600); err != nil {
		t.Fatal(err)
	}
	tooFar := listOf("2026-10-20.1", testNow.Add(60*24*time.Hour), 24)
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		src    Source
		env    Env
		target error
		parts  []string
	}{
		{"wrong key", Source{File: signedFile(t, priv, good), Dir: t.TempDir()}, envWith(otherPub, testNow), targets.ErrBadSignature, []string{"not signed by a key"}},
		{"newer format", Source{File: v2file, Dir: t.TempDir()}, envWith(pub, testNow), targets.ErrUnsupportedVersion, []string{"newer version of mayak"}},
		{"not a list", Source{File: junk, Dir: t.TempDir()}, envWith(pub, testNow), targets.ErrInvalid, []string{"not a valid targets list", "clock"}},
		{"expires too far ahead", Source{File: signedFile(t, priv, tooFar), Dir: t.TempDir()}, envWith(pub, testNow), targets.ErrInvalid, []string{"clock"}},
		{"missing file", Source{File: filepath.Join(t.TempDir(), "none.json"), Dir: t.TempDir()}, envWith(pub, testNow), os.ErrNotExist, []string{"cannot read the targets list", "none.json"}},
		{"rev file cannot be written", Source{File: signedFile(t, priv, good), Dir: filepath.Join(blocker, "sub")}, envWith(pub, testNow), nil, []string{"cannot record", "sub"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.src.Load(tc.env)
			if err == nil || got != nil {
				t.Fatalf("got %v, %v; want an error", got, err)
			}
			if tc.target != nil && !errors.Is(err, tc.target) {
				t.Errorf("err = %v, want it to wrap %v", err, tc.target)
			}
			checkMessage(t, err, tc.parts...)
		})
	}
}

func TestLoadNeedsItsSetting(t *testing.T) {
	pub, _ := newKey(t)
	if _, err := (Source{}).Load(envWith(pub, testNow)); err == nil {
		t.Error("no directory: want error")
	}
	if _, err := (Source{Dir: t.TempDir()}).Load(Env{PublicKeys: []ed25519.PublicKey{pub}}); err == nil {
		t.Error("no clock: want error")
	}
}

func TestPickWithinTheCeilings(t *testing.T) {
	dir := t.TempDir()
	l := listOf("2026-10-20.1", testNow.Add(24*time.Hour), 24)
	src := Source{Dir: dir}

	seen := map[string]bool{}
	for range 3 {
		got, err := src.Pick(&l, DefaultLimit)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != DefaultLimit {
			t.Fatalf("picked %d, want %d", len(got), DefaultLimit)
		}
		for _, it := range got {
			seen[it.ID] = true
		}
	}
	if len(seen) != 24 {
		t.Errorf("three runs of 10 covered %d of 24 targets", len(seen))
	}
	if b, _ := os.ReadFile(filepath.Join(dir, RotationFile)); string(b) != "6\n" {
		t.Errorf("rotation file = %q, want 6 (30 picks round a list of 24)", b)
	}

	for _, limit := range []int{MinLimit - 1, MaxLimit + 1, 0, -3} {
		if _, err := src.Pick(&l, limit); err == nil {
			t.Errorf("limit %d is outside %d..%d: want error", limit, MinLimit, MaxLimit)
		}
	}
	if _, err := (Source{}).Pick(&l, DefaultLimit); err == nil {
		t.Error("no directory: want error")
	}
}

func TestPickDamagedRotationFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, RotationFile)
	if err := os.WriteFile(path, []byte("junk\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	l := listOf("2026-10-20.1", testNow.Add(24*time.Hour), 24)
	_, err := Source{Dir: dir}.Pick(&l, DefaultLimit)
	if !errors.Is(err, targets.ErrRotationDamaged) {
		t.Fatalf("err = %v, want ErrRotationDamaged", err)
	}
	checkMessage(t, err, path, "damaged", "Delete")
	if b, _ := os.ReadFile(path); string(b) != "junk\n" {
		t.Errorf("the damaged file was changed to %q", b)
	}
}
