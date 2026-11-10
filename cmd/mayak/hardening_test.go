package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/polargoose18/mayak/internal/probe"
	"github.com/polargoose18/mayak/internal/report"
	"github.com/polargoose18/mayak/internal/runner"
	"github.com/polargoose18/mayak/testbed/mockdpi"
)

func TestCheckIncompleteResolverFields(t *testing.T) {
	for _, field := range []string{"public-first-address", "public-second-address", "public-port", "public-transport", "public-server-name", "control-port", "control-transport", "control-server-name", "tls-port"} {
		t.Run(field, func(t *testing.T) {
			env, path, node := setup(t, mockdpi.Config{Control: true}, true)
			switch field {
			case "public-first-address":
				env.PublicResolvers[0].Addr = netip.AddrPort{}
			case "public-second-address":
				env.PublicResolvers[1].Addr = netip.AddrPort{}
			case "public-port":
				env.PublicResolvers[1].Addr = netip.MustParseAddrPort("127.0.0.1:0")
			case "public-transport":
				env.PublicResolvers[1].Transport = ""
			case "public-server-name":
				env.PublicResolvers[0].ServerName = ""
			case "control-port":
				env.ControlResolver.Addr = netip.MustParseAddrPort("127.0.0.1:0")
			case "control-transport":
				env.ControlResolver.Transport = ""
			case "control-server-name":
				env.ControlResolver.Transport = probe.DNSTransportDoT
				env.ControlResolver.ServerName = ""
			case "tls-port":
				env.ControlTLS = netip.MustParseAddrPort("127.0.0.1:0")
			}
			stdout, stderr, err := runCheckCmd(t, env, "--targets-file", path)
			if exitCodeOf(t, err) != 2 || stdout != "" || !strings.Contains(stderr, guardNoControl) {
				t.Fatalf("incomplete config: exit=%d stdout=%q stderr=%q", exitCodeOf(t, err), stdout, stderr)
			}
			if got := node.requests.Load(); got != 0 {
				t.Fatalf("incomplete config made %d control requests", got)
			}
			entries, err := os.ReadDir(agentDir(t))
			if err != nil || len(entries) != 0 {
				t.Fatalf("guard left state: %v %v", entries, err)
			}
		})
	}
}

func TestCheckJSONWriteError(t *testing.T) {
	for _, mode := range []string{"normal", "inconclusive", "interrupted"} {
		t.Run(mode, func(t *testing.T) {
			env, path, node := setup(t, mockdpi.Config{Control: true, CertNames: []string{testHost, "second.example"}}, true)
			ctx := context.Background()
			if mode == "inconclusive" {
				node.pingStatus = 503
				env.Anchors = []string{node.srv.URL + "/v1/ping"}
			}
			if mode == "interrupted" {
				release, parked := make(chan struct{}), make(chan struct{})
				env.Clock = &gateClock{release: release, parked: parked}
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 10*time.Second)
				defer cancel()
				go func() { <-parked; cancel(); close(release) }()
			}
			cmd := newRootCmd(env)
			cmd.SetOut(failedOutput{})
			cmd.SetErr(&bytes.Buffer{})
			cmd.SetContext(ctx)
			cmd.SetArgs([]string{"check", "--targets-file", path, "--json"})
			t.Logf("surface=in-process CLI invocation=mayak check --targets-file %q --json mode=%s stdout=failedOutput", path, mode)
			err := cmd.Execute()
			if exitCodeOf(t, err) != 1 || !strings.Contains(err.Error(), "stdout closed") {
				t.Fatalf("error=%v want stdout failure exit 1", err)
			}
			t.Logf("exit=1 error=%v", err)
		})
	}
}

func TestCheckMockDPIJSON(t *testing.T) {
	for _, scenario := range []struct {
		verdict report.Verdict
		test    report.Test
	}{
		{report.VerdictSNIBlock, report.TestTLSSNI},
		{report.VerdictDNSTamper, report.TestDNS},
		{report.VerdictHTTPStub, report.TestHTTP},
		{report.VerdictIPBlock, report.TestTCP},
	} {
		t.Run(string(scenario.verdict), func(t *testing.T) {
			t.Setenv("XDG_CONFIG_HOME", t.TempDir())
			t.Setenv("APPDATA", t.TempDir())
			cfg := mockdpi.Config{Control: true, CertNames: []string{testHost, "second.example"}}
			switch scenario.verdict {
			case report.VerdictSNIBlock:
				cfg.ResetAfterHello = &mockdpi.ResetAfterHelloConfig{BlockedSNI: []string{testHost}}
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
			switch scenario.verdict {
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
			stdout, stderr, err := runCheckCmd(t, env, "--targets-file", path, "--json")
			if exitCodeOf(t, err) != 0 || stderr != "" {
				t.Fatalf("exit=%d stdout=%q stderr=%q", exitCodeOf(t, err), stdout, stderr)
			}
			var docs []json.RawMessage
			if err := json.Unmarshal([]byte(stdout), &docs); err != nil || len(docs) != 1 {
				t.Fatalf("invalid JSON reports: %v %q", err, stdout)
			}
			if _, err := report.Validate(docs[0]); err != nil {
				t.Fatal(err)
			}
			var doc report.Report
			if err := json.Unmarshal(docs[0], &doc); err != nil {
				t.Fatal(err)
			}
			if len(doc.Results) != 2 {
				t.Fatalf("results=%+v", doc.Results)
			}
			got := doc.Results[0]
			if got.Target != "t1" || got.Verdict != scenario.verdict || got.Test != scenario.test {
				t.Fatalf("result=%+v want t1/%s/%s", got, scenario.verdict, scenario.test)
			}
			if node.requests.Load() == 0 {
				t.Fatal("fake control server received no requests")
			}
			t.Logf("validated report: target=%s verdict=%s test=%s control requests=%d", got.Target, got.Verdict, got.Test, node.requests.Load())
		})
	}
}

func TestCheckCrashLockRecovery(t *testing.T) {
	env, path, node := setup(t, mockdpi.Config{Control: true, CertNames: []string{testHost, "second.example"}}, true)
	dir := agentDir(t)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(dir, "check.lock")
	// A crash leaves an exclusive lock. Its age never proves that its owner died.
	if err := os.WriteFile(lock, []byte("crash fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-365 * 24 * time.Hour)
	if err := os.Chtimes(lock, old, old); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, err := runCheckCmd(t, env, "--targets-file", path)
	if exitCodeOf(t, err) != 1 || stdout != "" || !strings.Contains(stderr, "no mayak check process is running") {
		t.Fatalf("exit=%d stdout=%q stderr=%q", exitCodeOf(t, err), stdout, stderr)
	}
	data, readErr := os.ReadFile(lock)
	if readErr != nil || string(data) != "crash fixture\n" || node.requests.Load() != 0 {
		t.Fatalf("lock changed or network used: data=%q err=%v requests=%d", data, readErr, node.requests.Load())
	}
	// The fixture has no live owner; an operator can now explicitly remove it.
	if err := os.Remove(lock); err != nil {
		t.Fatal(err)
	}
	_, stderr, err = runCheckCmd(t, env, "--targets-file", path)
	if err != nil {
		t.Fatalf("explicit recovery failed: %v %s", err, stderr)
	}
	if _, err := os.Stat(lock); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("lock not released: %v", err)
	}
	t.Log("old crash lock preserved without waiting or network; explicit owner-verified removal recovered the command; normal exit released lock")
}

// TestCheckConcurrentProcesses exercises the exclusive lock across two OS
// processes, with a pipe making the overlap deterministic rather than timed.
func TestCheckConcurrentProcesses(t *testing.T) {
	if role := os.Getenv("MAYAK_LOCK_ROLE"); role != "" {
		config, appdata := os.Getenv("MAYAK_LOCK_CONFIG"), os.Getenv("MAYAK_LOCK_APPDATA")
		if config == "" || appdata == "" {
			t.Fatal("helper requires isolated configuration directories")
		}
		env, path, node := setup(t, mockdpi.Config{Control: true, CertNames: []string{testHost, "second.example"}}, true)
		t.Setenv("XDG_CONFIG_HOME", config)
		t.Setenv("APPDATA", appdata)
		if role == "contender" {
			stdout, stderr, err := runCheckCmd(t, env, "--targets-file", path)
			if exitCodeOf(t, err) != 1 || stdout != "" || !strings.Contains(stderr, "check.lock") || node.requests.Load() != 0 {
				t.Fatalf("competing process: exit=%d stdout=%q stderr=%q requests=%d", exitCodeOf(t, err), stdout, stderr, node.requests.Load())
			}
			t.Log("second OS process refused before load/pick/network; live lock preserved")
			return
		}
		pub, priv := testKey(t)
		env.PublicKeys = []ed25519.PublicKey{pub}
		path = signedList(t, t.TempDir(), "2026-11-09.2", testNow.Add(24*time.Hour), priv)
		release := make(chan struct{})
		clock := &signalGateClock{gateClock: gateClock{parked: make(chan struct{})}, paused: make(chan struct{})}
		env.Clock = &publicationClock{signalGateClock: clock, release: release}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		released := make(chan error, 1)
		go func() {
			for _, ready := range []<-chan struct{}{clock.parked, clock.paused} {
				select {
				case <-ready:
				case <-ctx.Done():
					released <- ctx.Err()
					return
				}
			}
			fmt.Println("LOCK_READY")
			_, err := bufio.NewReader(os.Stdin).ReadString('\n')
			close(release)
			released <- err
		}()
		_, stderr, err := runCheckCtx(t, ctx, env, "--targets-file", path, "--json")
		if err != nil {
			t.Fatalf("holder failed: %v %s", err, stderr)
		}
		if err := <-released; err != nil {
			t.Fatal(err)
		}
		t.Log("first OS process published the newer revision and released its lock")
		return
	}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("APPDATA", t.TempDir())
	dir := agentDir(t)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	before := map[string]string{runner.RevFile: "2026-11-08.1\n", runner.RotationFile: "1\n"}
	for name, data := range before {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	childEnv := append(os.Environ(), "MAYAK_LOCK_CONFIG="+os.Getenv("XDG_CONFIG_HOME"), "MAYAK_LOCK_APPDATA="+os.Getenv("APPDATA"))
	holder := exec.CommandContext(ctx, executable, "-test.run=^TestCheckConcurrentProcesses$", "-test.v")
	holder.Env = append(childEnv, "MAYAK_LOCK_ROLE=holder")
	input, err := holder.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := holder.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var holderErr bytes.Buffer
	holder.Stderr = &holderErr
	t.Logf("surface=OS subprocess CLI invocation=%q role=holder XDG_CONFIG_HOME=%q APPDATA=%q", holder.Args, os.Getenv("XDG_CONFIG_HOME"), os.Getenv("APPDATA"))
	if err := holder.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		if !waited {
			_ = holder.Process.Kill()
			_ = holder.Wait()
		}
		_ = input.Close()
	}()
	ready := make(chan struct{})
	transcript := make(chan string, 1)
	go func() {
		var text strings.Builder
		scan := bufio.NewScanner(output)
		for scan.Scan() {
			line := scan.Text()
			fmt.Fprintln(&text, line)
			if line == "LOCK_READY" {
				close(ready)
			}
		}
		if err := scan.Err(); err != nil {
			fmt.Fprintf(&text, "scanner error: %v", err)
		}
		transcript <- text.String()
	}()
	select {
	case <-ready:
	case <-ctx.Done():
		t.Fatal("holder did not reach the locked pause")
	}
	contender := exec.CommandContext(ctx, executable, "-test.run=^TestCheckConcurrentProcesses$", "-test.v")
	contender.Env = append(childEnv, "MAYAK_LOCK_ROLE=contender")
	t.Logf("surface=OS subprocess CLI invocation=%q role=contender", contender.Args)
	out, err := contender.CombinedOutput()
	t.Logf("contender transcript:\n%s", out)
	if err != nil {
		t.Fatalf("contender assertion failed: %v", err)
	}
	for name, want := range before {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || string(data) != want {
			t.Fatalf("live competitor changed %s: %q err=%v", name, data, err)
		}
	}
	if _, err := fmt.Fprintln(input, "release"); err != nil {
		t.Fatal(err)
	}
	text := <-transcript
	err = holder.Wait()
	waited = true
	t.Logf("holder transcript:\n%s\nstderr=%s", text, holderErr.String())
	if err != nil {
		t.Fatalf("holder failed: %v", err)
	}
	for name, want := range map[string]string{runner.RevFile: "2026-11-09.2\n", runner.RotationFile: "1\n"} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || string(data) != want {
			t.Fatalf("publication %s=%q want %q err=%v", name, data, want, err)
		}
		t.Logf("published %s=%q", name, data)
	}
	if _, err := os.Stat(filepath.Join(dir, "check.lock")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("lock remains after process exit: %v", err)
	}
}
