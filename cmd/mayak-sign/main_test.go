package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/polargoose18/mayak/internal/targets"
)

// testNow is the clock of these tests.
var testNow = time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)

// list returns an unsigned list with the given rev and expiry.
func list(rev string, expires time.Time) string {
	return `{
  "v": 1,
  "rev": "` + rev + `",
  "expires": "` + expires.Format(time.RFC3339) + `",
  "items": [
    {"id": "a", "host": "example.org", "category": "infra", "rationale": "Fictional target number one.", "rev": "` + rev + `"},
    {"id": "b", "host": "example.net", "category": "dev", "rationale": "Fictional target number two.", "rev": "` + rev + `"}
  ]
}
`
}

var okList = list("2026-10-13.1", testNow.Add(14*24*time.Hour))

func runAt(t *testing.T, now time.Time, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	var out, errBuf bytes.Buffer
	cmd := newRootCmdAt(func() time.Time { return now })
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)
	cmd.SetArgs(args)
	err = cmd.Execute()
	return out.String(), errBuf.String(), err
}

func run(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	return runAt(t, testNow, args...)
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// keygen creates a key in dir and returns its public key and file path.
func keygen(t *testing.T, dir string) (pub, keyPath string) {
	t.Helper()
	stdout, _, err := run(t, "keygen", "--out", dir)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(stdout), filepath.Join(dir, keyFileName)
}

func TestKeygenSignVerifyChain(t *testing.T) {
	dir := t.TempDir()
	pub, keyPath := keygen(t, filepath.Join(dir, "keys"))

	raw, err := base64.StdEncoding.DecodeString(pub)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		t.Fatalf("keygen printed %q, want a base64 32-byte key", pub)
	}
	priv, err := readPrivateKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(priv.Public().(ed25519.PublicKey), raw) {
		t.Error("printed public key does not match the private key file")
	}

	in := filepath.Join(dir, "targets.json")
	signed := filepath.Join(dir, "targets.signed.json")
	write(t, in, okList)

	stdout, stderr, err := run(t, "sign", "--key", keyPath, "--in", in, "--out", signed)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "2 targets") || !strings.Contains(stdout, "rev 2026-10-13.1") || !strings.Contains(stdout, "expires 2026-10-27T12:00:00Z") {
		t.Errorf("sign output = %q", stdout)
	}
	if stderr != "" {
		t.Errorf("unexpected stderr: %q", stderr)
	}

	stdout, _, err = run(t, "verify", "--pub", pub, "--in", signed)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "OK") || !strings.Contains(stdout, "2 targets") || !strings.Contains(stdout, "expires 2026-10-27T12:00:00Z") {
		t.Errorf("verify output = %q", stdout)
	}

	// The signed bytes are the input bytes, not a re-serialization.
	data, _ := os.ReadFile(signed)
	payload, _ := targets.StoredRev(data)
	if payload != "2026-10-13.1" {
		t.Errorf("stored rev = %q", payload)
	}
}

func TestKeygenKeyFileMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes are not meaningful on Windows")
	}
	_, keyPath := keygen(t, t.TempDir())
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("key file mode = %v, want 0600", got)
	}
}

func TestKeygenRefusesToOverwrite(t *testing.T) {
	dir := t.TempDir()
	_, keyPath := keygen(t, dir)
	before, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	stdout, _, err := run(t, "keygen", "--out", dir)
	if err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("err = %v, want refusal", err)
	}
	if stdout != "" {
		t.Errorf("printed %q on failure", stdout)
	}
	after, _ := os.ReadFile(keyPath)
	if !bytes.Equal(before, after) {
		t.Error("existing key file was modified")
	}
}

func TestKeygenCreatesNestedDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a", "b")
	keygen(t, dir)
	if _, err := os.Stat(filepath.Join(dir, keyFileName)); err != nil {
		t.Error(err)
	}
}

func TestKeygenOutIsAFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "file")
	write(t, f, "x")
	if _, _, err := run(t, "keygen", "--out", f); err == nil {
		t.Error("want error when --out is a file")
	}
}

func TestKeygenDirNotWritable(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("permissions are not enforced here")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)
	if _, _, err := run(t, "keygen", "--out", dir); err == nil {
		t.Error("want error for read-only dir")
	}
}

// setup makes a key and an input file and returns their paths and the public key.
func setup(t *testing.T, input string) (pub, keyPath, in, out string) {
	t.Helper()
	dir := t.TempDir()
	pub, keyPath = keygen(t, dir)
	in = filepath.Join(dir, "targets.json")
	out = filepath.Join(dir, "targets.signed.json")
	write(t, in, input)
	return pub, keyPath, in, out
}

func TestSignRefusals(t *testing.T) {
	day := 24 * time.Hour
	tests := []struct {
		name  string
		input string
		want  string // part of the error
	}{
		{"expired", list("2026-10-13.1", testNow.Add(-time.Second)), "expired"},
		{"expires now", list("2026-10-13.1", testNow), "expired"},
		{"too far ahead", list("2026-10-13.1", testNow.Add(30*day+time.Second)), "30 days"},
		{"newer format version", strings.Replace(okList, `"v": 1`, `"v": 2`, 1), "version"},
		{"no version", strings.Replace(okList, `"v": 1,`, ``, 1), "v is missing"},
		{"bad rev", list("r1", testNow.Add(14*day)), "rev"},
		{"short rationale", strings.Replace(okList, "Fictional target number one.", "short", 1), "rationale"},
		{"duplicate id", strings.Replace(okList, `"id": "b"`, `"id": "a"`, 1), "duplicate"},
		{"host with scheme", strings.Replace(okList, "example.org", "https://example.org", 1), "host"},
		{"unknown category", strings.Replace(okList, `"infra"`, `"adult"`, 1), "category"},
		{"empty list", `{"v":1,"rev":"2026-10-13.1","expires":"2026-10-20T00:00:00Z","items":[]}`, "empty"},
		{"not json", "nope", "targets"},
		{"unknown field", strings.Replace(okList, `"v": 1,`, `"v": 1, "sig": "x",`, 1), "unknown field"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, keyPath, in, out := setup(t, tc.input)
			_, _, err := run(t, "sign", "--key", keyPath, "--in", in, "--out", out)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
			if _, err := os.Stat(out); err == nil {
				t.Error("output file was created despite the error")
			}
		})
	}
}

func TestSignExpiryBoundary(t *testing.T) {
	_, keyPath, in, out := setup(t, list("2026-10-13.1", testNow.Add(30*24*time.Hour)))
	if _, _, err := run(t, "sign", "--key", keyPath, "--in", in, "--out", out); err != nil {
		t.Errorf("exactly 30 days must be accepted: %v", err)
	}
}

func TestSignKeepsRevsGrowing(t *testing.T) {
	pub, keyPath, in, out := setup(t, list("2026-10-13.5", testNow.Add(14*24*time.Hour)))
	if _, _, err := run(t, "sign", "--key", keyPath, "--in", in, "--out", out); err != nil {
		t.Fatal(err)
	}
	signedBefore, _ := os.ReadFile(out)

	for name, tc := range map[string]struct {
		rev  string
		want string
	}{
		"older":      {"2026-10-13.4", "older"},
		"same rev":   {"2026-10-13.5", "raise the rev"},
		"older date": {"2026-10-12.9", "older"},
	} {
		t.Run(name, func(t *testing.T) {
			write(t, in, list(tc.rev, testNow.Add(14*24*time.Hour)))
			_, _, err := run(t, "sign", "--key", keyPath, "--in", in, "--out", out)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
			after, _ := os.ReadFile(out)
			if !bytes.Equal(signedBefore, after) {
				t.Error("the signed file was modified")
			}
		})
	}

	// Numbers compare as numbers: .10 is newer than .5 (and than .9).
	write(t, in, list("2026-10-13.10", testNow.Add(14*24*time.Hour)))
	if _, _, err := run(t, "sign", "--key", keyPath, "--in", in, "--out", out); err != nil {
		t.Errorf("2026-10-13.10 after .5: %v", err)
	}
	// A newer date wins whatever the number.
	write(t, in, list("2026-10-14.1", testNow.Add(14*24*time.Hour)))
	if _, _, err := run(t, "sign", "--key", keyPath, "--in", in, "--out", out); err != nil {
		t.Errorf("2026-10-14.1: %v", err)
	}
	if stdout, _, err := run(t, "verify", "--pub", pub, "--in", out); err != nil || !strings.Contains(stdout, "rev 2026-10-14.1") {
		t.Errorf("verify = %q, %v", stdout, err)
	}
}

// After a key change the old file is signed by the old key; revs must still
// grow, and the old signature is not needed for that.
func TestSignAfterKeyRotation(t *testing.T) {
	dir := t.TempDir()
	_, oldKey := keygen(t, filepath.Join(dir, "old"))
	newPub, newKey := keygen(t, filepath.Join(dir, "new"))
	in := filepath.Join(dir, "targets.json")
	out := filepath.Join(dir, "signed.json")

	write(t, in, list("2026-10-13.1", testNow.Add(14*24*time.Hour)))
	if _, _, err := run(t, "sign", "--key", oldKey, "--in", in, "--out", out); err != nil {
		t.Fatal(err)
	}
	if _, _, err := run(t, "sign", "--key", newKey, "--in", in, "--out", out); err == nil {
		t.Error("same rev under a new key must still be refused")
	}
	write(t, in, list("2026-10-13.2", testNow.Add(14*24*time.Hour)))
	if _, _, err := run(t, "sign", "--key", newKey, "--in", in, "--out", out); err != nil {
		t.Fatal(err)
	}
	if _, _, err := run(t, "verify", "--pub", newPub, "--in", out); err != nil {
		t.Error(err)
	}
}

func TestSignRefusesToOverwriteAFileThatIsNotASignedList(t *testing.T) {
	_, keyPath, in, out := setup(t, okList)
	write(t, out, "precious notes\n")
	_, _, err := run(t, "sign", "--key", keyPath, "--in", in, "--out", out)
	if err == nil || !strings.Contains(err.Error(), "not a signed targets list") {
		t.Fatalf("err = %v", err)
	}
	if b, _ := os.ReadFile(out); string(b) != "precious notes\n" {
		t.Error("the file was overwritten")
	}
}

func TestSignOutputInADirectoryThatDoesNotExist(t *testing.T) {
	_, keyPath, in, _ := setup(t, okList)
	out := filepath.Join(filepath.Dir(in), "no-dir", "x.json")
	if _, _, err := run(t, "sign", "--key", keyPath, "--in", in, "--out", out); err == nil {
		t.Error("want error")
	}
}

func TestSignOutIsADirectory(t *testing.T) {
	_, keyPath, in, _ := setup(t, okList)
	if _, _, err := run(t, "sign", "--key", keyPath, "--in", in, "--out", filepath.Dir(in)); err == nil {
		t.Error("want error when --out is a directory")
	}
}

func TestSignWarnsAboutKeyMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes are not meaningful on Windows")
	}
	_, keyPath, in, out := setup(t, okList)

	_, stderr, err := run(t, "sign", "--key", keyPath, "--in", in, "--out", out)
	if err != nil || strings.Contains(stderr, "warning") {
		t.Errorf("0600 key: err = %v, stderr = %q", err, stderr)
	}

	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	write(t, in, list("2026-10-13.2", testNow.Add(14*24*time.Hour)))
	_, stderr, err = run(t, "sign", "--key", keyPath, "--in", in, "--out", out)
	if err != nil {
		t.Fatalf("a wide mode is a warning, not an error: %v", err)
	}
	if !strings.Contains(stderr, "warning") || !strings.Contains(stderr, "0644") {
		t.Errorf("stderr = %q, want a mode warning", stderr)
	}
	if strings.Contains(stderr, "SECRET") {
		t.Error("the warning must not leak anything")
	}
}

func TestVerifyFailures(t *testing.T) {
	dir := t.TempDir()
	pub, keyPath := keygen(t, dir)
	otherPub, _ := keygen(t, t.TempDir())
	in := filepath.Join(dir, "targets.json")
	signed := filepath.Join(dir, "signed.json")
	write(t, in, okList)
	if _, _, err := run(t, "sign", "--key", keyPath, "--in", in, "--out", signed); err != nil {
		t.Fatal(err)
	}
	good, _ := os.ReadFile(signed)

	// Change one byte of the payload and keep the signature.
	tampered := filepath.Join(dir, "tampered.json")
	{
		s := string(good)
		i := strings.Index(s, `"payload":"`) + len(`"payload":"`)
		b := []byte(s)
		if b[i+10] == 'A' {
			b[i+10] = 'B'
		} else {
			b[i+10] = 'A'
		}
		write(t, tampered, string(b))
	}
	garbage := filepath.Join(dir, "garbage.json")
	write(t, garbage, "nope")

	tests := []struct {
		name string
		now  time.Time
		args []string
		want string // part of the error, if checked
	}{
		{"wrong key", testNow, []string{"verify", "--pub", otherPub, "--in", signed}, "bad signature"},
		{"tampered payload", testNow, []string{"verify", "--pub", pub, "--in", tampered}, "bad signature"},
		{"garbage file", testNow, []string{"verify", "--pub", pub, "--in", garbage}, ""},
		{"missing file", testNow, []string{"verify", "--pub", pub, "--in", filepath.Join(dir, "none")}, ""},
		{"expired list", testNow.Add(15 * 24 * time.Hour), []string{"verify", "--pub", pub, "--in", signed}, "expired"},
		{"pub not base64", testNow, []string{"verify", "--pub", "!!!", "--in", signed}, ""},
		{"pub wrong size", testNow, []string{"verify", "--pub", base64.StdEncoding.EncodeToString([]byte("short")), "--in", signed}, ""},
		{"missing flag", testNow, []string{"verify", "--pub", pub}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stdout, _, err := runAt(t, tc.now, tc.args...)
			if err == nil {
				t.Fatal("want error")
			}
			if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to mention %q", err, tc.want)
			}
			if strings.Contains(stdout, "OK") {
				t.Errorf("printed OK on failure: %q", stdout)
			}
		})
	}
}

func TestSignMissingInputsAndFlags(t *testing.T) {
	_, keyPath, in, out := setup(t, okList)
	badKey := filepath.Join(filepath.Dir(in), "bad.key")
	write(t, badKey, "not a key\n")

	tests := map[string][]string{
		"bad key file":     {"sign", "--key", badKey, "--in", in, "--out", out},
		"missing key file": {"sign", "--key", filepath.Join(filepath.Dir(in), "none.key"), "--in", in, "--out", out},
		"missing input":    {"sign", "--key", keyPath, "--in", filepath.Join(filepath.Dir(in), "none.json"), "--out", out},
		"missing flags":    {"sign", "--key", keyPath},
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			if _, _, err := run(t, args...); err == nil {
				t.Error("want error")
			}
			if _, err := os.Stat(out); err == nil {
				t.Error("output file was created despite the error")
			}
		})
	}
}

func TestKeyErrorDoesNotLeakContents(t *testing.T) {
	dir := t.TempDir()
	badKey := filepath.Join(dir, "k.key")
	write(t, badKey, "SECRET-CONTENT\n")
	_, err := readPrivateKey(badKey)
	if err == nil || strings.Contains(err.Error(), "SECRET-CONTENT") {
		t.Errorf("err = %v", err)
	}
}

func TestDefaultClockIsUsed(t *testing.T) {
	// The real clock: a list that expires in two weeks from the real now.
	pub, keyPath, in, out := setup(t, list(time.Now().UTC().Format("2006-01-02")+".1", time.Now().Add(14*24*time.Hour)))
	for _, args := range [][]string{
		{"sign", "--key", keyPath, "--in", in, "--out", out},
		{"verify", "--pub", pub, "--in", out},
	} {
		cmd := newRootCmd()
		var buf bytes.Buffer
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)
		cmd.SetArgs(args)
		if err := cmd.Execute(); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
	}
}

func TestPubkeyPrintsWhatKeygenPrinted(t *testing.T) {
	dir := t.TempDir()
	stdout, _, err := run(t, "keygen", "--out", dir)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, keyFileName)

	got, stderr, err := run(t, "pubkey", "--key", keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if got != stdout {
		t.Errorf("pubkey printed %q, keygen printed %q", got, stdout)
	}
	if strings.Count(got, "\n") != 1 || !strings.HasSuffix(got, "\n") {
		t.Errorf("want exactly one line, got %q", got)
	}
	if raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(got)); err != nil || len(raw) != ed25519.PublicKeySize {
		t.Errorf("output is not a base64 32-byte key: %q", got)
	}
	if stderr != "" {
		t.Errorf("a 0600 key file must give no stderr, got %q", stderr)
	}

	// Nothing of the private key is printed: not the seed, not the file.
	secret, _ := os.ReadFile(keyPath)
	seed := strings.TrimSpace(string(secret))
	if strings.Contains(got, seed) || strings.Contains(stderr, seed) {
		t.Error("the private key was printed")
	}
}

func TestPubkeyIsTheKeyThatVerifies(t *testing.T) {
	pub, keyPath, in, out := setup(t, okList)
	if _, _, err := run(t, "sign", "--key", keyPath, "--in", in, "--out", out); err != nil {
		t.Fatal(err)
	}
	fromFile, _, err := run(t, "pubkey", "--key", keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(fromFile) != pub {
		t.Fatalf("pubkey = %q, keygen = %q", fromFile, pub)
	}
	stdout, _, err := run(t, "verify", "--pub", strings.TrimSpace(fromFile), "--in", out)
	if err != nil || !strings.Contains(stdout, "OK") {
		t.Errorf("verify with the pubkey output: %q, %v", stdout, err)
	}
}

func TestPubkeyErrorsDoNotLeakTheFile(t *testing.T) {
	dir := t.TempDir()
	validSeed := base64.StdEncoding.EncodeToString(make([]byte, 31)) // a seed one byte short
	files := map[string]string{
		"garbage":        "SECRET-CONTENT\n",
		"wrong size":     validSeed + "\n",
		"empty":          "",
		"binary":         "\x00\x01SECRET-CONTENT\xff",
		"two lines":      "SECRET-CONTENT\nSECRET-CONTENT\n",
		"base64 garbage": "SECRET-CONTENT==\n",
	}
	for name, content := range files {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name+".key")
			write(t, path, content)
			stdout, stderr, err := run(t, "pubkey", "--key", path)
			if err == nil {
				t.Fatal("want error")
			}
			for what, text := range map[string]string{"error": err.Error(), "stdout": stdout, "stderr": stderr} {
				if strings.Contains(text, "SECRET-CONTENT") || (validSeed != "" && strings.Contains(text, validSeed)) {
					t.Errorf("%s leaks the file: %q", what, text)
				}
			}
			if stdout != "" {
				t.Errorf("printed %q on failure", stdout)
			}
		})
	}

	t.Run("missing file", func(t *testing.T) {
		stdout, _, err := run(t, "pubkey", "--key", filepath.Join(dir, "none.key"))
		if err == nil || stdout != "" {
			t.Errorf("err = %v, stdout = %q", err, stdout)
		}
	})
	t.Run("missing flag", func(t *testing.T) {
		if _, _, err := run(t, "pubkey"); err == nil {
			t.Error("want error")
		}
	})
	t.Run("key path is a directory", func(t *testing.T) {
		if _, _, err := run(t, "pubkey", "--key", dir); err == nil {
			t.Error("want error")
		}
	})
}

func TestPubkeyWarnsAboutKeyMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes are not meaningful on Windows")
	}
	pub, keyPath := keygen(t, t.TempDir())
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, err := run(t, "pubkey", "--key", keyPath)
	if err != nil {
		t.Fatalf("a wide mode is a warning, not an error: %v", err)
	}
	if strings.TrimSpace(stdout) != pub {
		t.Errorf("stdout = %q, want the public key and nothing else", stdout)
	}
	if !strings.Contains(stderr, "warning") || !strings.Contains(stderr, "0644") {
		t.Errorf("stderr = %q, want a mode warning", stderr)
	}
}
