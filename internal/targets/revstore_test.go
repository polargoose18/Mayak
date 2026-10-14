package targets

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// listAt returns a signed list with the given rev.
func listAt(t *testing.T, priv ed25519.PrivateKey, rev string) []byte {
	t.Helper()
	tr := sample()
	tr.Rev = rev
	return mustSign(t, priv, tr)
}

func readRev(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// countingStore wraps a store and counts calls.
type countingStore struct {
	RevStore
	loads, saves int
}

func (c *countingStore) Load() (string, error) { c.loads++; return c.RevStore.Load() }
func (c *countingStore) Save(rev string) error { c.saves++; return c.RevStore.Save(rev) }

func TestAcceptFirstRunRecordsRev(t *testing.T) {
	pub, priv := newKey(t)
	path := filepath.Join(t.TempDir(), "mayak", "targets.rev")
	s := FileRevStore(path)

	got, err := Accept([]ed25519.PublicKey{pub}, listAt(t, priv, "2026-10-13.1"), testNow, s)
	if err != nil {
		t.Fatal(err)
	}
	if got.Rev != "2026-10-13.1" {
		t.Errorf("got %+v", got)
	}
	if rev := readRev(t, path); rev != "2026-10-13.1\n" {
		t.Errorf("file = %q, want the rev and a newline", rev)
	}
}

func TestAcceptSameRevIsFineAndWritesNothing(t *testing.T) {
	pub, priv := newKey(t)
	path := filepath.Join(t.TempDir(), "targets.rev")
	cs := &countingStore{RevStore: FileRevStore(path)}
	pubs := []ed25519.PublicKey{pub}
	data := listAt(t, priv, "2026-10-13.1")

	if _, err := Accept(pubs, data, testNow, cs); err != nil {
		t.Fatal(err)
	}
	if cs.saves != 1 {
		t.Fatalf("saves = %d after the first run", cs.saves)
	}
	if _, err := Accept(pubs, data, testNow, cs); err != nil {
		t.Fatalf("the same list again: %v", err)
	}
	if cs.saves != 1 {
		t.Errorf("saves = %d, the same rev must not be written again", cs.saves)
	}
}

func TestAcceptNewerRevUpdatesTheFile(t *testing.T) {
	pub, priv := newKey(t)
	path := filepath.Join(t.TempDir(), "targets.rev")
	s := FileRevStore(path)
	pubs := []ed25519.PublicKey{pub}

	for _, rev := range []string{"2026-10-13.1", "2026-10-13.2", "2026-10-13.10", "2026-10-14.1"} {
		if _, err := Accept(pubs, listAt(t, priv, rev), testNow, s); err != nil {
			t.Fatalf("%s: %v", rev, err)
		}
		if got := readRev(t, path); got != rev+"\n" {
			t.Errorf("after %s the file holds %q", rev, got)
		}
	}
}

func TestAcceptRollbackIsRefusedAndFileIsUntouched(t *testing.T) {
	pub, priv := newKey(t)
	path := filepath.Join(t.TempDir(), "targets.rev")
	s := FileRevStore(path)
	pubs := []ed25519.PublicKey{pub}
	if _, err := Accept(pubs, listAt(t, priv, "2026-10-13.5"), testNow, s); err != nil {
		t.Fatal(err)
	}

	for _, old := range []string{"2026-10-13.4", "2026-10-12.9", "2025-01-01.1"} {
		got, err := Accept(pubs, listAt(t, priv, old), testNow, s)
		if !errors.Is(err, ErrRollback) || got != nil {
			t.Errorf("%s: got %v, %v; want ErrRollback", old, got, err)
		}
		if rev := readRev(t, path); rev != "2026-10-13.5\n" {
			t.Fatalf("after refusing %s the file holds %q", old, rev)
		}
	}
	// Numbers compare as numbers: .10 is not older than .5.
	if _, err := Accept(pubs, listAt(t, priv, "2026-10-13.10"), testNow, s); err != nil {
		t.Errorf(".10 after .5: %v", err)
	}
}

func TestAcceptDamagedRevFileIsAnErrorNotAReset(t *testing.T) {
	pub, priv := newKey(t)
	pubs := []ed25519.PublicKey{pub}
	data := listAt(t, priv, "2026-10-13.1")

	damaged := map[string]string{
		"garbage":            "SECRET-CONTENT\n",
		"empty":              "",
		"only a newline":     "\n",
		"extra line":         "2026-10-13.1\nextra\n",
		"leading space":      " 2026-10-13.1\n",
		"no such month":      "2026-13-01.1\n",
		"no number":          "2026-10-13.\n",
		"binary":             "\x00\x01\x02\xff",
		"windows newline":    "2026-10-13.1\r\n",
		"very long":          strings.Repeat("9", 10000),
		"two revs on a line": "2026-10-13.1 2026-10-13.2\n",
	}
	for name, content := range damaged {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "targets.rev")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := Accept(pubs, data, testNow, FileRevStore(path))
			if !errors.Is(err, ErrRevStoreDamaged) || got != nil {
				t.Fatalf("got %v, %v; want ErrRevStoreDamaged", got, err)
			}
			if !strings.Contains(err.Error(), path) {
				t.Errorf("the error should name the file: %v", err)
			}
			if strings.Contains(err.Error(), "SECRET-CONTENT") {
				t.Errorf("the error leaks the file: %v", err)
			}
			// Not a silent reset: the file is as it was.
			if b, _ := os.ReadFile(path); string(b) != content {
				t.Errorf("the damaged file was changed to %q", b)
			}
		})
	}
}

func TestAcceptBadSignatureOrExpiredListLeavesTheFileAlone(t *testing.T) {
	pub, priv := newKey(t)
	otherPub, otherPriv := newKey(t)
	_ = otherPub
	pubs := []ed25519.PublicKey{pub}

	for _, existing := range []string{"", "2026-10-13.1\n"} { // no file / a file
		path := filepath.Join(t.TempDir(), "targets.rev")
		if existing != "" {
			if err := os.WriteFile(path, []byte(existing), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		check := func(name string, err error, want error) {
			t.Helper()
			if !errors.Is(err, want) {
				t.Errorf("%s: err = %v, want %v", name, err, want)
			}
			b, rerr := os.ReadFile(path)
			if existing == "" && rerr == nil {
				t.Errorf("%s: a file was created: %q", name, b)
			}
			if existing != "" && string(b) != existing {
				t.Errorf("%s: the file was changed to %q", name, b)
			}
		}
		s := &countingStore{RevStore: FileRevStore(path)}

		// A newer rev, but signed by a key that is not trusted.
		_, err := Accept(pubs, listAt(t, otherPriv, "2026-10-20.1"), testNow, s)
		check("bad signature", err, ErrBadSignature)

		// A newer rev, trusted, but expired.
		tr := sample()
		tr.Rev = "2026-10-20.1"
		tr.Expires = testNow.Add(-time.Second)
		data, err := signBytes(priv, payloadOf(t, tr))
		if err != nil {
			t.Fatal(err)
		}
		_, err = Accept(pubs, data, testNow, s)
		check("expired", err, ErrExpired)

		// A newer rev, trusted, too far ahead.
		tr.Expires = testNow.Add(MaxLifetime + 24*time.Hour)
		data, _ = signBytes(priv, payloadOf(t, tr))
		_, err = Accept(pubs, data, testNow, s)
		check("too far ahead", err, ErrInvalid)

		// Not a list at all.
		_, err = Accept(pubs, []byte("junk"), testNow, s)
		check("junk", err, ErrInvalid)

		if s.saves != 0 {
			t.Errorf("Save was called %d times for lists that must be refused", s.saves)
		}
	}
}

// failingStore fails as told.
type failingStore struct {
	loadErr, saveErr error
	stored           string
}

func (f failingStore) Load() (string, error) { return f.stored, f.loadErr }
func (f failingStore) Save(string) error     { return f.saveErr }

func TestAcceptStoreErrors(t *testing.T) {
	pub, priv := newKey(t)
	pubs := []ed25519.PublicKey{pub}
	data := listAt(t, priv, "2026-10-13.2")
	boom := errors.New("disk on fire")

	if got, err := Accept(pubs, data, testNow, failingStore{loadErr: boom}); !errors.Is(err, boom) || got != nil {
		t.Errorf("Load error: got %v, %v", got, err)
	}
	// If the new rev cannot be recorded, the list is not accepted: the
	// protection against rollbacks would be gone.
	if got, err := Accept(pubs, data, testNow, failingStore{stored: "2026-10-13.1", saveErr: boom}); !errors.Is(err, boom) || got != nil {
		t.Errorf("Save error: got %v, %v", got, err)
	}
	if _, err := Accept(pubs, data, testNow, nil); err == nil {
		t.Error("a nil store: want error")
	}
	// A store that returns a rev that is not valid is damaged.
	if _, err := Accept(pubs, data, testNow, failingStore{stored: "junk"}); err == nil {
		t.Error("a junk stored rev: want error")
	}
}

func TestFileRevStoreFilesAndDirectories(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes are not meaningful on Windows")
	}
	root := t.TempDir()
	dir := filepath.Join(root, "a", "b")
	path := filepath.Join(dir, "targets.rev")
	s := FileRevStore(path)

	if rev, err := s.Load(); err != nil || rev != "" {
		t.Fatalf("Load without a file = %q, %v; want empty and no error", rev, err)
	}
	if err := s.Save("2026-10-13.1"); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("file: %v, %v; want mode 0600", info, err)
	}
	for _, d := range []string{filepath.Join(root, "a"), dir} {
		if info, err := os.Stat(d); err != nil || info.Mode().Perm() != 0o700 {
			t.Errorf("dir %s: %v, %v; want mode 0700", d, info, err)
		}
	}

	// The write is atomic: a temporary file and a rename, nothing left over.
	if err := s.Save("2026-10-13.2"); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || entries[0].Name() != "targets.rev" {
		t.Errorf("directory holds %v, want only targets.rev", entries)
	}
	if rev, err := s.Load(); err != nil || rev != "2026-10-13.2" {
		t.Errorf("Load = %q, %v", rev, err)
	}

	// An existing file with wide permissions is replaced by a 0600 one.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.Save("2026-10-13.3"); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Errorf("mode after a rewrite = %v, want 0600", info.Mode().Perm())
	}
}

// The file never goes back to a smaller rev, whoever calls Save.
func TestFileRevStoreNeverGoesBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.rev")
	s := FileRevStore(path)
	if err := s.Save("2026-10-13.5"); err != nil {
		t.Fatal(err)
	}
	for _, rev := range []string{"2026-10-13.4", "2026-10-12.9"} {
		if err := s.Save(rev); !errors.Is(err, ErrRollback) {
			t.Errorf("Save(%s) = %v, want ErrRollback", rev, err)
		}
	}
	if got := readRev(t, path); got != "2026-10-13.5\n" {
		t.Errorf("file = %q", got)
	}
	// The same rev and a newer one are fine.
	for _, rev := range []string{"2026-10-13.5", "2026-10-13.6"} {
		if err := s.Save(rev); err != nil {
			t.Errorf("Save(%s) = %v", rev, err)
		}
	}
}

func TestFileRevStoreSaveErrors(t *testing.T) {
	root := t.TempDir()

	if err := FileRevStore(filepath.Join(root, "x")).Save("junk"); err == nil {
		t.Error("an invalid rev: want error")
	}

	// The directory cannot be created: a file is in the way.
	blocker := filepath.Join(root, "blocker")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := FileRevStore(filepath.Join(blocker, "sub", "targets.rev")).Save("2026-10-13.1"); err == nil {
		t.Error("an unusable directory: want error")
	}

	// The path is a directory: it cannot be read as a rev, and it is damaged
	// for Save, not overwritten.
	dirPath := filepath.Join(root, "isdir")
	if err := os.Mkdir(dirPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := FileRevStore(dirPath).Load(); err == nil {
		t.Error("a directory as the rev file: want error")
	}
	if err := FileRevStore(dirPath).Save("2026-10-13.1"); err == nil {
		t.Error("Save over a directory: want error")
	}

	// A damaged file is not overwritten by Save either.
	bad := filepath.Join(root, "bad")
	if err := os.WriteFile(bad, []byte("junk\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := FileRevStore(bad).Save("2026-10-13.1"); !errors.Is(err, ErrRevStoreDamaged) {
		t.Errorf("Save over a damaged file = %v, want ErrRevStoreDamaged", err)
	}
	if b, _ := os.ReadFile(bad); string(b) != "junk\n" {
		t.Errorf("the damaged file was changed to %q", b)
	}
}

func TestFileRevStoreDirNotWritable(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("permissions are not enforced here")
	}
	dir := filepath.Join(t.TempDir(), "ro")
	if err := os.Mkdir(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)
	if err := FileRevStore(filepath.Join(dir, "targets.rev")).Save("2026-10-13.1"); err == nil {
		t.Error("a read-only directory: want error")
	}
}
