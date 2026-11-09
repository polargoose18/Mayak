package main

// Binary-level smoke tests (ADR-006 Q8): the compiled mayak binary itself is
// exercised, not the cobra command tree in process. Each sub-case runs the
// real binary and asserts both the exit code and one plain-English phrase of
// its output.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/polargoose18/mayak/internal/targets"
)

// buildBinary compiles the real mayak binary for a smoke test and returns
// its path.
func buildBinary(t *testing.T, trusted ...ed25519.PublicKey) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not found in PATH; cannot build the binary")
	}
	if testing.Short() {
		t.Skip("skipping the binary smoke test in -short mode")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "mayak")
	// cmd/mayak/smoke_test.go lives two levels below the module root.
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))
	args := []string{"build", "-o", bin}
	if len(trusted) > 0 {
		// Only this smoke build trusts the generated fixture key; the shipped
		// binary and repository trust roots remain unchanged.
		replacement := filepath.Join(dir, "pubkeys.go")
		source := fmt.Sprintf("package targets\nimport \"crypto/ed25519\"\nfunc PublicKeys() []ed25519.PublicKey { return []ed25519.PublicKey{%#v} }\n", []byte(trusted[0]))
		if err := os.WriteFile(replacement, []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
		overlay, err := json.Marshal(map[string]any{"Replace": map[string]string{filepath.Join(root, "internal", "targets", "pubkeys.go"): replacement}})
		if err != nil {
			t.Fatal(err)
		}
		overlayPath := filepath.Join(dir, "overlay.json")
		if err := os.WriteFile(overlayPath, overlay, 0o600); err != nil {
			t.Fatal(err)
		}
		args = append(args, "-overlay", overlayPath)
	}
	args = append(args, "./cmd/mayak")
	cmd := exec.Command("go", args...)
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build ./cmd/mayak: %v\n%s", err, out)
	}
	return bin
}

// runBinary runs the built binary with a private HOME and XDG_CONFIG_HOME so
// it never touches the real user configuration, and returns exit code,
// stdout and stderr.
func runBinary(t *testing.T, bin string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	home := t.TempDir()
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(),
		"HOME="+home,
		"XDG_CONFIG_HOME="+filepath.Join(home, ".config"),
	)
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	t.Logf("surface=real binary invocation=%q", append([]string{bin}, args...))
	err := cmd.Run()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("run %v: %v", args, err)
		}
	}
	t.Logf("exit=%d stdout=%q stderr=%q", code, out.String(), errBuf.String())
	return code, out.String(), errBuf.String()
}

// smokeSignedList writes a signed targets list into dir and returns its path.
// signedAt is the signing time, which may be in the past (an expired list is
// produced by signing it before its expiry passed).
func smokeSignedList(t *testing.T, dir string, expires, signedAt time.Time, priv ed25519.PrivateKey) string {
	t.Helper()
	list := targets.Targets{
		V:       1,
		Rev:     "2026-11-01.1",
		Expires: expires,
		Items: []targets.Target{{
			ID:        "smoke",
			Host:      "example.com",
			Category:  targets.CategoryInfra,
			Rationale: "Fictional target for the smoke test.",
			Rev:       "2026-11-01.1",
		}},
	}
	payload, err := json.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	data, err := targets.Sign(priv, payload, signedAt)
	if err != nil {
		t.Fatalf("sign targets: %v", err)
	}
	path := filepath.Join(dir, "targets.signed.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// freshKey generates an ed25519 key pair of the full 64-byte private size.
func freshKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func TestSmokeVersion(t *testing.T) {
	bin := buildBinary(t)
	code, stdout, stderr := runBinary(t, bin, "version")
	if code != 0 {
		t.Errorf("exit code = %d, want 0 (stderr: %s)", code, stderr)
	}
	if !strings.Contains(stdout, "dev") {
		t.Errorf("stdout = %q, want the version dev", stdout)
	}
}

func TestSmokeExpiredList(t *testing.T) {
	priv := freshKey(t)
	bin := buildBinary(t, priv.Public().(ed25519.PublicKey))
	now := time.Now()
	dir := t.TempDir()
	path := smokeSignedList(t, dir, now.Add(-24*time.Hour), now.Add(-48*time.Hour), priv)
	code, stdout, stderr := runBinary(t, bin, "check", "--targets-file", path)
	if code != 1 {
		t.Errorf("exit code = %d, want 1 (stdout: %s, stderr: %s)", code, stdout, stderr)
	}
	combined := stdout + stderr
	if !strings.Contains(combined, "expired") {
		t.Errorf("output = %q, want the expiry named", combined)
	}
	if !strings.Contains(combined, "--targets-file") {
		t.Errorf("output = %q, want advice on what to do", combined)
	}
}

func TestSmokeForeignKeyList(t *testing.T) {
	bin := buildBinary(t)
	now := time.Now()
	dir := t.TempDir()
	// A structurally valid list signed by a key that is not in
	// targets.PublicKeys().
	path := smokeSignedList(t, dir, now.Add(20*24*time.Hour), now, freshKey(t))
	code, stdout, stderr := runBinary(t, bin, "check", "--targets-file", path)
	if code != 1 {
		t.Errorf("exit code = %d, want 1 (stdout: %s, stderr: %s)", code, stdout, stderr)
	}
	if combined := stdout + stderr; !strings.Contains(combined, "not signed by a key this mayak trusts") {
		t.Errorf("output = %q, want the untrusted-key message", combined)
	}
}

func TestSmokeLimitOutOfRange(t *testing.T) {
	bin := buildBinary(t)
	// Flag validation happens before any state file is touched, so no signed
	// list is needed.
	code, stdout, stderr := runBinary(t, bin, "check", "--limit", "3")
	if code != 1 {
		t.Errorf("exit code = %d, want 1 (stdout: %s, stderr: %s)", code, stdout, stderr)
	}
	if combined := stdout + stderr; !strings.Contains(combined, "--limit must be between") {
		t.Errorf("output = %q, want the limit range message", combined)
	}
}

func TestSmokeLeavesNoStateOutsideTemp(t *testing.T) {
	// The real user configuration must not be touched: every runBinary call
	// points HOME and XDG_CONFIG_HOME at its own t.TempDir(). As a direct
	// check, run a refusal case with XDG_CONFIG_HOME pointed at a directory
	// we can list afterwards and assert nothing appeared in it.
	bin := buildBinary(t)
	home := t.TempDir()
	config := filepath.Join(home, ".config")
	cmd := exec.Command(bin, "check", "--limit", "3")
	cmd.Env = append(os.Environ(), "HOME="+home, "XDG_CONFIG_HOME="+config)
	if err := cmd.Run(); err == nil {
		t.Fatal("check --limit 3 should fail")
	}
	entries, err := os.ReadDir(config)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("the run wrote to XDG_CONFIG_HOME: %v", names)
	}
}
