package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/polargoose18/mayak/internal/report"
	"github.com/polargoose18/mayak/internal/runner"
	"github.com/polargoose18/mayak/internal/targets"
	"github.com/polargoose18/mayak/testbed/mockdpi"
)

// testNow is the clock the tests run at; the signed lists are valid around it.
var testNow = time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)

// testHost is the target host of the test list. It is not in /etc/hosts, so
// the system resolver really asks the mock DNS for it, and the mock
// certificate carries this name.
const testHost = "target.example"

// testClock is a fixed Clock, so Source.Load sees a stable now.
type testClock struct{}

func (testClock) Now() time.Time                         { return testNow }
func (testClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// signedList writes a signed two-target list into dir and returns its path.
func signedList(t *testing.T, dir string, rev string, expires time.Time, priv ed25519.PrivateKey) string {
	t.Helper()
	payload := `{
  "v": 1,
  "rev": "` + rev + `",
  "expires": "` + expires.Format(time.RFC3339) + `",
  "items": [
    {"id": "t1", "host": "` + testHost + `", "category": "infra", "rationale": "Fictional target number one for tests.", "rev": "` + rev + `"},
    {"id": "t2", "host": "second.example", "category": "dev", "rationale": "Fictional target number two for tests.", "rev": "` + rev + `"}
  ]
}`
	signed, err := targets.Sign(priv, []byte(payload), testNow)
	if err != nil {
		t.Fatalf("sign list: %v", err)
	}
	path := filepath.Join(dir, "targets.signed.json")
	if err := os.WriteFile(path, append(signed, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// signedListAt is signedList with an explicit signing time.
func signedListAt(t *testing.T, dir, rev string, expires time.Time, priv ed25519.PrivateKey, signedAt time.Time) string {
	t.Helper()
	payload := `{
  "v": 1,
  "rev": "` + rev + `",
  "expires": "` + expires.Format(time.RFC3339) + `",
  "items": [
    {"id": "t1", "host": "` + testHost + `", "category": "infra", "rationale": "Fictional target number one for tests.", "rev": "` + rev + `"},
    {"id": "t2", "host": "second.example", "category": "dev", "rationale": "Fictional target number two for tests.", "rev": "` + rev + `"}
  ]
}`
	signed, err := targets.Sign(priv, []byte(payload), signedAt)
	if err != nil {
		t.Fatalf("sign list: %v", err)
	}
	path := filepath.Join(dir, "targets.signed.json")
	if err := os.WriteFile(path, append(signed, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// testKey makes a key pair the lists are signed with; the private key is
// kept so the list can be signed.
func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// runCheck runs the check command in-process and returns stdout, stderr and
// the command's error (the exit code travels through *exitError).
func runCheckCmd(t *testing.T, env runner.Env, args ...string) (string, string, error) {
	t.Helper()
	return runCheckCtx(t, context.Background(), env, args...)
}

// runCheckCtx is runCheckCmd with a caller-owned context. Cancelling that
// context is what a SIGINT does to runCheck: signal.NotifyContext turns the
// signal into exactly this cancel, and the run leaves through the same
// interrupt path with the same *exitError.
func runCheckCtx(t *testing.T, ctx context.Context, env runner.Env, args ...string) (string, string, error) {
	t.Helper()
	var out, errBuf bytes.Buffer
	cmd := newRootCmd(env)
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)
	cmd.SetArgs(append([]string{"check"}, args...))
	cmd.SetContext(ctx)
	t.Logf("surface=in-process CLI invocation=mayak check %q", args)
	err := cmd.Execute()
	if err != nil && !errors.Is(err, errInterrupted) {
		// main prints every non-interrupt error; do the same here so the
		// tests see what a user would see.
		var ee *exitError
		if !errors.As(err, &ee) || ee.Err != nil {
			fmt.Fprintln(&errBuf, "error:", err)
		}
	}
	t.Logf("exit=%d stdout=%q stderr=%q", exitCodeOf(t, err), out.String(), errBuf.String())
	return out.String(), errBuf.String(), err
}

// exitCodeOf pulls the exit code out of the command's error.
func exitCodeOf(t *testing.T, err error) int {
	t.Helper()
	if err == nil {
		return 0
	}
	var ee *exitError
	if ok := asExitError(err, &ee); !ok {
		t.Fatalf("error %v is not an *exitError", err)
	}
	return ee.Code
}

func asExitError(err error, target **exitError) bool {
	for err != nil {
		if e, ok := err.(*exitError); ok {
			*target = e
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// checkEnv builds a runner.Env around a mockdpi world and the test control
// node: the system resolver asks the mock DNS, the trusted roots are the mock
// CA, and the target port is the mock TLS server's.
func checkEnv(t *testing.T, m *mockdpi.Env, node *testControl, targetPort uint16) runner.Env {
	t.Helper()
	return runner.Env{
		SystemResolver:  resolverVia(m.ControlDNS),
		ControlResolver: probeDNSServer(mustAddrPort(t, m.ControlDNS)),
		Control:         probeControlClient(node.srv.URL, m.CertPool),
		ControlTLS:      mustAddrPort(t, m.ControlTLS),
		Anchors:         []string{"https://" + m.ControlTLS + "/"},
		NeutralSNI:      "neutral.example",
		TargetPort:      targetPort,
		RootCAs:         m.CertPool,
		Clock:           testClock{},
		Rand:            zeroRand{},
	}
}

func mustAddrPort(t testing.TB, s string) netip.AddrPort {
	t.Helper()
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		t.Fatal(err)
	}
	return ap
}

// setup wires the whole world: mockdpi, the control node, a signed list and
// a fresh agent directory.
func setup(t *testing.T, opts mockdpi.Config, reachable bool) (runner.Env, string, *testControl) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	m := mockdpi.Start(t, opts)
	targetPort := portOfTLS(t, m)
	node := newTestControl(t, []string{testHost, "second.example"}, reachable)
	node.fetchFrom = mustAddrPort(t, m.ControlTLS)
	node.roots = m.CertPool
	dir := t.TempDir()
	pub, priv := testKey(t)
	path := signedList(t, dir, "2026-11-09.1", testNow.Add(14*24*time.Hour), priv)
	env := checkEnv(t, m, node, targetPort)
	env.PublicKeys = []ed25519.PublicKey{pub}
	return env, path, node
}

// agentDir returns the directory the check command keeps its state in
// (targets.rev and rotation); the tests read those files around a run.
func agentDir(t *testing.T) string {
	t.Helper()
	dir, err := userDir()
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestCheckRunOK(t *testing.T) {
	env, path, node := setup(t, mockdpi.Config{Control: true, CertNames: []string{testHost, "second.example"}}, true)
	// The target resolves to the mock's clean address and its TLS server is
	// the control node itself, which answers for any SNI.
	stdout, stderr, err := runCheckCmd(t, env, "--targets-file", path, "--limit", "5")
	code := exitCodeOf(t, err)
	if code != 0 {
		t.Fatalf("exit = %d, stderr: %s", code, stderr)
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want empty", stderr)
	}
	lines := strings.Split(strings.TrimRight(stdout, "\n"), "\n")
	if len(lines) < 3 {
		t.Fatalf("stdout = %q, want at least 3 lines", stdout)
	}
	if !strings.Contains(stdout, "t1  ok  ") || !strings.Contains(stdout, "t2  ok  ") {
		t.Errorf("stdout = %q, want one line per target with ok", stdout)
	}
	if !strings.Contains(stdout, "Nothing was sent.") {
		t.Errorf("stdout = %q, want the sending notice", stdout)
	}
	if got := node.requests.Load(); got == 0 {
		t.Error("the control node got no requests, the run did not happen")
	}
}

func TestCheckNoControlGuard(t *testing.T) {
	env, path, _ := setup(t, mockdpi.Config{Control: true, CertNames: []string{testHost, "second.example"}}, true)
	env.Control.BaseURL = "" // the build without a control node

	stdout, stderr, err := runCheckCmd(t, env, "--targets-file", path)
	if code := exitCodeOf(t, err); code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty", stdout)
	}
	if !strings.Contains(stderr, guardNoControl) {
		t.Errorf("stderr = %q, want the guard sentence", stderr)
	}
}

func TestCheckJSON(t *testing.T) {
	env, path, _ := setup(t, mockdpi.Config{Control: true, CertNames: []string{testHost, "second.example"}}, true)
	stdout, stderr, err := runCheckCmd(t, env, "--targets-file", path, "--json")
	if code := exitCodeOf(t, err); code != 0 {
		t.Fatalf("exit = %d, stderr: %s", code, stderr)
	}
	var docs []report.Report
	if err := json.Unmarshal([]byte(stdout), &docs); err != nil {
		t.Fatalf("stdout is not a JSON array: %v\n%s", err, stdout)
	}
	if len(docs) != 1 {
		t.Fatalf("got %d documents, want 1", len(docs))
	}
	raw, err := json.Marshal(docs[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := report.Validate(raw); err != nil {
		t.Errorf("report does not validate: %v", err)
	}
	if docs[0].TargetsRev != "2026-11-09.1" {
		t.Errorf("targets_rev = %q, want 2026-11-09.1", docs[0].TargetsRev)
	}
	if docs[0].Agent.Ver != version || docs[0].Agent.Source != report.SourceCLI {
		t.Errorf("agent = %+v, want ver %q source %q", docs[0].Agent, version, report.SourceCLI)
	}
}

func TestCheckLimitBounds(t *testing.T) {
	env, path, _ := setup(t, mockdpi.Config{Control: true, CertNames: []string{testHost, "second.example"}}, true)
	for _, limit := range []string{"3", "4", "21"} {
		_, stderr, err := runCheckCmd(t, env, "--targets-file", path, "--limit", limit)
		if code := exitCodeOf(t, err); code != 1 {
			t.Errorf("--limit %s: exit = %d, want 1 (stderr: %s)", limit, code, stderr)
		}
	}
}

func TestCheckBadTargetsKind(t *testing.T) {
	env, path, _ := setup(t, mockdpi.Config{Control: true, CertNames: []string{testHost, "second.example"}}, true)
	_, stderr, err := runCheckCmd(t, env, "--targets-file", path, "--targets", "cat")
	if code := exitCodeOf(t, err); code != 1 {
		t.Fatalf("exit = %d, want 1 (stderr: %s)", code, stderr)
	}
	if !strings.Contains(stderr, "--targets") {
		t.Errorf("stderr = %q, want a message about --targets", stderr)
	}
}

func TestCheckExpiredList(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	m := mockdpi.Start(t, mockdpi.Config{Control: true, CertNames: []string{testHost}})
	node := newTestControl(t, []string{testHost, "second.example"}, true)
	dir := t.TempDir()
	// The list was signed a week ago and expired an hour ago.
	pub, priv := testKey(t)
	path := signedListAt(t, dir, "2026-11-02.1", testNow.Add(-time.Hour), priv, testNow.Add(-7*24*time.Hour))
	env := checkEnv(t, m, node, 443)
	env.PublicKeys = []ed25519.PublicKey{pub}

	stdout, stderr, err := runCheckCmd(t, env, "--targets-file", path)
	if code := exitCodeOf(t, err); code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty", stdout)
	}
	if !strings.Contains(stderr, "expired") {
		t.Errorf("stderr = %q, want a plain-English expiry message", stderr)
	}
}

func TestCheckDeadControlAnchorsDown(t *testing.T) {
	for _, asJSON := range []bool{false, true} {
		t.Run(fmt.Sprintf("json=%v", asJSON), func(t *testing.T) {
			env, path, node := setup(t, mockdpi.Config{Control: true}, true)
			node.pingStatus = http.StatusServiceUnavailable
			env.Anchors = []string{node.srv.URL + "/v1/ping"}
			args := []string{"--targets-file", path}
			if asJSON {
				args = append(args, "--json")
			}
			stdout, stderr, err := runCheckCmd(t, env, args...)
			if code := exitCodeOf(t, err); code != 2 {
				t.Fatalf("exit = %d, want 2; stdout=%q stderr=%q", code, stdout, stderr)
			}
			if node.requests.Load() == 0 {
				t.Fatal("control ping was not attempted")
			}
			if asJSON {
				var docs []report.Report
				if err := json.Unmarshal([]byte(stdout), &docs); err != nil {
					t.Fatal(err)
				}
				if len(docs) != 1 || len(docs[0].Results) != 2 {
					t.Fatalf("unexpected reports: %+v", docs)
				}
				for _, r := range docs[0].Results {
					if r.Verdict != report.VerdictInconclusive {
						t.Fatalf("verdict = %s", r.Verdict)
					}
				}
			} else if !strings.Contains(stdout, "inconclusive") {
				t.Fatalf("stdout = %q", stdout)
			}
		})
	}
}

func TestCheckAllowlistModeExitZero(t *testing.T) {
	env, path, node := setup(t, mockdpi.Config{Control: true}, true)
	node.pingStatus = http.StatusServiceUnavailable
	env.Anchors = []string{node.srv.URL + "/v1/ping"}
	node.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/allowed" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	env.Allowlist = []string{node.srv.URL + "/allowed"}
	stdout, stderr, err := runCheckCmd(t, env, "--targets-file", path)
	if code := exitCodeOf(t, err); code != 0 {
		t.Fatalf("exit = %d, want 0; stdout=%q stderr=%q", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "allowlist_mode") {
		t.Fatalf("stdout = %q", stdout)
	}
}
