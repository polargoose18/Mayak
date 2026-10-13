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
)

const unsignedList = `{
  "rev": "2026-10-13.1",
  "items": [
    {"id": "a", "host": "example.org", "category": "infra", "rationale": "Fictional target number one.", "rev": "2026-10-13.1"},
    {"id": "b", "host": "example.net", "category": "dev", "rationale": "Fictional target number two.", "rev": "2026-10-13.1"}
  ]
}
`

func run(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	var out, errBuf bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)
	cmd.SetArgs(args)
	err = cmd.Execute()
	return out.String(), errBuf.String(), err
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
	write(t, in, unsignedList)

	stdout, _, err := run(t, "sign", "--key", keyPath, "--in", in, "--out", signed)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "2 targets") {
		t.Errorf("sign output = %q", stdout)
	}

	stdout, _, err = run(t, "verify", "--pub", pub, "--in", signed)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "OK") || !strings.Contains(stdout, "2 targets") {
		t.Errorf("verify output = %q", stdout)
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

func TestVerifyFailures(t *testing.T) {
	dir := t.TempDir()
	pub, keyPath := keygen(t, dir)
	otherPub, _ := keygen(t, t.TempDir())
	in := filepath.Join(dir, "targets.json")
	signed := filepath.Join(dir, "signed.json")
	write(t, in, unsignedList)
	if _, _, err := run(t, "sign", "--key", keyPath, "--in", in, "--out", signed); err != nil {
		t.Fatal(err)
	}
	good, _ := os.ReadFile(signed)

	tampered := filepath.Join(dir, "tampered.json")
	write(t, tampered, strings.Replace(string(good), "example.org", "evil.example", 1))
	garbage := filepath.Join(dir, "garbage.json")
	write(t, garbage, "nope")

	tests := []struct {
		name string
		args []string
	}{
		{"wrong key", []string{"verify", "--pub", otherPub, "--in", signed}},
		{"tampered payload", []string{"verify", "--pub", pub, "--in", tampered}},
		{"garbage file", []string{"verify", "--pub", pub, "--in", garbage}},
		{"missing file", []string{"verify", "--pub", pub, "--in", filepath.Join(dir, "none")}},
		{"pub not base64", []string{"verify", "--pub", "!!!", "--in", signed}},
		{"pub wrong size", []string{"verify", "--pub", base64.StdEncoding.EncodeToString([]byte("short")), "--in", signed}},
		{"missing flag", []string{"verify", "--pub", pub}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stdout, _, err := run(t, tc.args...)
			if err == nil {
				t.Fatal("want error")
			}
			if strings.Contains(stdout, "OK") {
				t.Errorf("printed OK on failure: %q", stdout)
			}
		})
	}
}

func TestSignFailures(t *testing.T) {
	dir := t.TempDir()
	_, keyPath := keygen(t, dir)
	in := filepath.Join(dir, "targets.json")
	out := filepath.Join(dir, "signed.json")

	badKey := filepath.Join(dir, "bad.key")
	write(t, badKey, "not a key\n")

	tests := []struct {
		name    string
		key     string
		content string
	}{
		{"short rationale", keyPath, strings.Replace(unsignedList, "Fictional target number one.", "short", 1)},
		{"duplicate id", keyPath, strings.Replace(unsignedList, `"id": "b"`, `"id": "a"`, 1)},
		{"host with scheme", keyPath, strings.Replace(unsignedList, "example.org", "https://example.org", 1)},
		{"unknown category", keyPath, strings.Replace(unsignedList, `"infra"`, `"adult"`, 1)},
		{"empty list", keyPath, `{"rev":"r","items":[]}`},
		{"not json", keyPath, "nope"},
		{"unknown field", keyPath, strings.Replace(unsignedList, `"rev": "2026-10-13.1",`, `"rev": "2026-10-13.1", "sig": "x",`, 1)},
		{"bad key file", badKey, unsignedList},
		{"missing key file", filepath.Join(dir, "none.key"), unsignedList},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			write(t, in, tc.content)
			if _, _, err := run(t, "sign", "--key", tc.key, "--in", in, "--out", out); err == nil {
				t.Fatal("want error")
			}
			if _, err := os.Stat(out); err == nil {
				t.Error("output file was created despite the error")
			}
		})
	}

	t.Run("missing input", func(t *testing.T) {
		if _, _, err := run(t, "sign", "--key", keyPath, "--in", filepath.Join(dir, "none.json"), "--out", out); err == nil {
			t.Error("want error")
		}
	})
	t.Run("unwritable output", func(t *testing.T) {
		write(t, in, unsignedList)
		if _, _, err := run(t, "sign", "--key", keyPath, "--in", in, "--out", filepath.Join(dir, "no-dir", "x.json")); err == nil {
			t.Error("want error")
		}
	})
	t.Run("missing flags", func(t *testing.T) {
		if _, _, err := run(t, "sign", "--key", keyPath); err == nil {
			t.Error("want error")
		}
	})
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
