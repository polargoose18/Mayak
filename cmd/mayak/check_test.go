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

	"github.com/polargoose18/mayak/internal/probe"
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
		PublicResolvers: []probe.DNSServer{
			{Addr: mustAddrPort(t, m.ControlDoT), Transport: probe.DNSTransportDoT, ServerName: "localhost"},
			probeDNSServer(mustAddrPort(t, m.ControlDNS)),
		},
		Control:    probeControlClient(node.srv.URL, m.CertPool),
		ControlTLS: mustAddrPort(t, m.ControlTLS),
		Anchors:    []string{"https://" + m.ControlTLS + "/"},
		NeutralSNI: "neutral.example",
		TargetPort: targetPort,
		RootCAs:    m.CertPool,
		Clock:      testClock{},
		Rand:       zeroRand{},
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
	t.Setenv("APPDATA", t.TempDir())
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
	t.Setenv("APPDATA", t.TempDir())
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

func TestProductionResolvers(t *testing.T) {
	env := productionEnv()
	want := []probe.DNSServer{
		{Addr: netip.MustParseAddrPort("1.1.1.1:853"), Transport: probe.DNSTransportDoT, ServerName: "cloudflare-dns.com"},
		{Addr: netip.MustParseAddrPort("8.8.8.8:853"), Transport: probe.DNSTransportDoT, ServerName: "dns.google"},
	}
	if len(env.PublicResolvers) != len(want) {
		t.Fatalf("public resolvers = %+v, want %+v", env.PublicResolvers, want)
	}
	for i := range want {
		if env.PublicResolvers[i] != want[i] {
			t.Errorf("resolver %d = %+v, want %+v", i, env.PublicResolvers[i], want[i])
		}
	}
	if env.ControlResolver.Addr.IsValid() {
		t.Fatal("undeployed control resolver must remain empty")
	}
	t.Logf("production resolvers=%+v; undeployed control resolver=%+v", env.PublicResolvers, env.ControlResolver)
}

func TestCheckIncompleteEnvGuard(t *testing.T) {
	for _, field := range []string{"url", "tls", "dns", "public"} {
		t.Run(field, func(t *testing.T) {
			env, path, node := setup(t, mockdpi.Config{Control: true}, true)
			switch field {
			case "url":
				env.Control.BaseURL = ""
			case "tls":
				env.ControlTLS = netip.AddrPort{}
			case "dns":
				env.ControlResolver = probe.DNSServer{}
			case "public":
				env.PublicResolvers = env.PublicResolvers[:1]
			}
			stdout, stderr, err := runCheckCmd(t, env, "--targets-file", path)
			if exitCodeOf(t, err) != 2 || stdout != "" || !strings.Contains(stderr, guardNoControl) {
				t.Fatalf("exit=%d stdout=%q stderr=%q", exitCodeOf(t, err), stdout, stderr)
			}
			if node.requests.Load() != 0 {
				t.Fatal("preflight used the network")
			}
			entries, err := os.ReadDir(agentDir(t))
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("preflight left state: %v", entries)
			}
		})
	}
}

type failedOutput struct{}

func (failedOutput) Write([]byte) (int, error) { return 0, errors.New("stdout closed") }

func TestCheckTextWriteError(t *testing.T) {
	for _, mode := range []string{"normal", "inconclusive", "interrupted"} {
		t.Run(mode, func(t *testing.T) {
			env, path, node := setup(t, mockdpi.Config{Control: true, CertNames: []string{testHost, "second.example"}}, true)
			ctx := context.Background()
			if mode == "inconclusive" {
				node.pingStatus = http.StatusServiceUnavailable
				env.Anchors = []string{node.srv.URL + "/v1/ping"}
			}
			if mode == "interrupted" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			cmd := newRootCmd(env)
			cmd.SetOut(failedOutput{})
			cmd.SetErr(&bytes.Buffer{})
			cmd.SetContext(ctx)
			cmd.SetArgs([]string{"check", "--targets-file", path})
			t.Logf("surface=in-process CLI invocation=mayak check --targets-file %q mode=%s stdout=failedOutput", path, mode)
			err := cmd.Execute()
			if exitCodeOf(t, err) != 1 || !strings.Contains(err.Error(), "stdout closed") {
				t.Fatalf("error=%v want stdout failure exit 1", err)
			}
			t.Logf("exit=1 error=%v", err)
		})
	}
}

func TestCheckMockDPIVerdicts(t *testing.T) {
	for _, verdict := range []report.Verdict{report.VerdictSNIBlock, report.VerdictDNSTamper, report.VerdictHTTPStub, report.VerdictIPBlock} {
		t.Run(string(verdict), func(t *testing.T) {
			t.Setenv("XDG_CONFIG_HOME", t.TempDir())
			t.Setenv("APPDATA", t.TempDir())
			cfg := mockdpi.Config{Control: true, CertNames: []string{testHost, "second.example"}}
			switch verdict {
			case report.VerdictSNIBlock:
				cfg.ResetAfterHello = &mockdpi.ResetAfterHelloConfig{BlockedSNI: []string{testHost, "second.example"}}
			case report.VerdictDNSTamper:
				cfg.DNSSpoof = &mockdpi.DNSSpoofConfig{Names: []string{testHost}}
			case report.VerdictHTTPStub:
				cfg.StubPage = true
			case report.VerdictIPBlock:
				cfg.ClosedPort = true
			}
			m := mockdpi.Start(t, cfg)
			node := newTestControl(t, []string{testHost, "second.example"}, true)
			node.fetchFrom = mustAddrPort(t, m.ControlTLS)
			node.roots = m.CertPool
			env := checkEnv(t, m, node, portOfTLS(t, m))
			switch verdict {
			case report.VerdictSNIBlock:
				env.TargetPort = portOf(t, m.ResetAfterHello)
				env.ControlTLS = mustAddrPort(t, m.ResetAfterHello)
			case report.VerdictDNSTamper:
				env.SystemResolver = resolverVia(m.DNSSpoof)
			case report.VerdictHTTPStub:
				env.TargetPort = portOf(t, m.StubPageTLS)
				stub, err := fetchPage(context.Background(), mustAddrPort(t, m.StubPageTLS), testHost, "/", m.CertPool)
				if err != nil {
					t.Fatal(err)
				}
				env.KnownStubHashes = []string{stub.BodyHash}
			case report.VerdictIPBlock:
				env.TargetPort = portOf(t, m.ClosedPort)
			}
			pub, priv := testKey(t)
			env.PublicKeys = []ed25519.PublicKey{pub}
			path := signedList(t, t.TempDir(), "2026-11-09.1", testNow.Add(24*time.Hour), priv)
			stdout, stderr, err := runCheckCmd(t, env, "--targets-file", path)
			if exitCodeOf(t, err) != 0 || stderr != "" || !strings.Contains(stdout, "t1  "+string(verdict)+"  "+verdictSentence[verdict]) || !strings.Contains(stdout, "Summary: 2 checked") || !strings.Contains(stdout, "Nothing was sent.") {
				t.Fatalf("exit=%d stdout=%q stderr=%q", exitCodeOf(t, err), stdout, stderr)
			}
		})
	}
}

func TestCheckConcurrentPublication(t *testing.T) {
	env, _, node := setup(t, mockdpi.Config{Control: true, CertNames: []string{testHost, "second.example"}}, true)
	pub, priv := testKey(t)
	env.PublicKeys = []ed25519.PublicKey{pub}
	newer := signedList(t, t.TempDir(), "2026-11-09.2", testNow.Add(24*time.Hour), priv)
	older := signedList(t, t.TempDir(), "2026-11-09.1", testNow.Add(24*time.Hour), priv)
	release := make(chan struct{})
	defer close(release)
	clock := &signalGateClock{gateClock: gateClock{parked: make(chan struct{})}, paused: make(chan struct{})}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	// Block only the pause; releasing it completes the newer command normally.
	env.Clock = &publicationClock{signalGateClock: clock, release: release}
	go func() { _, _, err := runCheckCtx(t, ctx, env, "--targets-file", newer); done <- err }()
	select {
	case <-clock.parked:
	case <-ctx.Done():
		t.Fatal("first command did not finish t1")
	}
	select {
	case <-clock.paused:
	case <-ctx.Done():
		t.Fatal("first command did not pause")
	}
	requests := node.requests.Load()
	competing := env
	competing.Clock = testClock{}
	stdout, stderr, err := runCheckCmd(t, competing, "--targets-file", older)
	if exitCodeOf(t, err) != 1 || stdout != "" || !strings.Contains(stderr, "check.lock") || !strings.Contains(stderr, "no mayak check process is running") {
		cancel()
		<-done
		t.Fatalf("competing exit=%d stdout=%q stderr=%q", exitCodeOf(t, err), stdout, stderr)
	}
	if node.requests.Load() != requests {
		cancel()
		<-done
		t.Fatal("competing command reached network")
	}
	release <- struct{}{}
	if err := <-done; err != nil {
		t.Fatalf("first command failed: %v", err)
	}
	before := map[string]string{}
	for _, name := range []string{runner.RevFile, runner.RotationFile} {
		data, err := os.ReadFile(filepath.Join(agentDir(t), name))
		if err != nil {
			t.Fatal(err)
		}
		before[name] = string(data)
	}
	if strings.TrimSpace(before[runner.RevFile]) != "2026-11-09.2" {
		t.Fatalf("accepted rev=%q", before[runner.RevFile])
	}
	_, stderr, err = runCheckCmd(t, competing, "--targets-file", older)
	if exitCodeOf(t, err) != 1 || !strings.Contains(stderr, "older") {
		t.Fatalf("rollback not refused: %v %q", err, stderr)
	}
	for name, want := range before {
		data, err := os.ReadFile(filepath.Join(agentDir(t), name))
		if err != nil || string(data) != want {
			t.Fatalf("%s changed: %q -> %q err=%v", name, want, data, err)
		}
		t.Logf("accepted %s unchanged after rejected competitor and rollback: %q", name, data)
	}
	if _, err := os.Stat(filepath.Join(agentDir(t), "check.lock")); !os.IsNotExist(err) {
		t.Fatalf("lock not released: %v", err)
	}
}

type publicationClock struct {
	*signalGateClock
	release <-chan struct{}
}

func (c *publicationClock) After(time.Duration) <-chan time.Time {
	close(c.paused)
	ch := make(chan time.Time, 1)
	go func() { <-c.release; ch <- testNow }()
	return ch
}
