package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/polargoose18/mayak/internal/report"
	"github.com/polargoose18/mayak/internal/runner"
	"github.com/polargoose18/mayak/testbed/mockdpi"
)

// --- interrupt tests --------------------------------------------------------
//
// A SIGINT reaches runCheck as a cancelled context. The pool pauses before
// starting target 2 while target 1 runs concurrently. The third Now call is
// runOne recording target 1's completion (after list loading and its start),
// so cancellation cannot race the unfinished first measurement.
type gateClock struct {
	release chan struct{}
	parked  chan struct{}
	once    sync.Once
	calls   atomic.Int32
}

func (c *gateClock) Now() time.Time {
	if c.calls.Add(1) == 3 {
		c.once.Do(func() { close(c.parked) })
	}
	return testNow
}

func (c *gateClock) After(time.Duration) <-chan time.Time {
	ch := make(chan time.Time, 1)
	go func() {
		<-c.release
		ch <- testNow
	}()
	return ch
}

// runInterrupted drives one check command with the gate clock and cancels
// the context at the moment the run sits in the pause between targets (the
// first target measured). It returns stdout, stderr and the command error.
func runInterrupted(t *testing.T, env runner.Env, args ...string) (string, string, error) {
	t.Helper()
	parked := make(chan struct{})
	release := make(chan struct{})
	env.Clock = &gateClock{release: release, parked: parked, once: sync.Once{}}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-parked       // target 1 measured, the run waits in the pause
		cancel()       // the SIGINT
		close(release) // let the pool wind down on the released pause
	}()
	return runCheckCtx(t, ctx, env, args...)
}

func TestCheckInterruptMidRun(t *testing.T) {
	env, path, _ := setup(t, mockdpi.Config{Control: true, CertNames: []string{testHost, "second.example"}}, true)
	dir := agentDir(t)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, runner.RevFile), []byte("2026-11-08.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, runner.RotationFile), []byte("2\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	revBefore, err := os.ReadFile(filepath.Join(dir, runner.RevFile))
	if err != nil {
		t.Fatalf("read rev before: %v", err)
	}
	rotBefore, err := os.ReadFile(filepath.Join(dir, runner.RotationFile))
	if err != nil {
		t.Fatalf("read rotation before: %v", err)
	}

	// --json: the interrupt path must print a valid array of measured
	// results only.
	stdout, stderr, err := runInterrupted(t, env, "--targets-file", path, "--json")
	if code := exitCodeOf(t, err); code != 130 {
		t.Fatalf("exit = %d, want 130 (stdout: %q, stderr: %q)", code, stdout, stderr)
	}
	var docs []report.Report
	if err := json.Unmarshal([]byte(stdout), &docs); err != nil {
		t.Fatalf("stdout is not a JSON array: %v\n%s", err, stdout)
	}
	if len(docs) != 1 {
		t.Fatalf("got %d documents, want 1 (the one measured target)", len(docs))
	}
	raw, err := json.Marshal(docs[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := report.Validate(raw); err != nil {
		t.Errorf("report does not validate: %v", err)
	}
	if docs[0].Results[0].Target != "t1" {
		t.Errorf("reported target = %q, want t1", docs[0].Results[0].Target)
	}

	revAfter, err := os.ReadFile(filepath.Join(dir, runner.RevFile))
	if err != nil {
		t.Fatalf("read rev after: %v", err)
	}
	rotAfter, err := os.ReadFile(filepath.Join(dir, runner.RotationFile))
	if err != nil {
		t.Fatalf("read rotation after: %v", err)
	}
	if string(revBefore) != string(revAfter) {
		t.Errorf("rev changed: %q -> %q", revBefore, revAfter)
	}
	t.Logf("state before: rev=%q rotation=%q; after: rev=%q rotation=%q", revBefore, rotBefore, revAfter, rotAfter)
	if string(rotBefore) != string(rotAfter) {
		t.Errorf("rotation changed: %q -> %q", rotBefore, rotAfter)
	}
}

func TestCheckInterruptText(t *testing.T) {
	env, path, _ := setup(t, mockdpi.Config{Control: true, CertNames: []string{testHost, "second.example"}}, true)

	stdout, _, err := runInterrupted(t, env, "--targets-file", path)
	if code := exitCodeOf(t, err); code != 130 {
		t.Fatalf("exit = %d, want 130 (stdout: %q)", code, stdout)
	}
	if !containsLine(stdout, "t1  ok  ") {
		t.Errorf("stdout = %q, want the measured target's result line", stdout)
	}
	if !containsLine(stdout, "t2  not measured") {
		t.Errorf("stdout = %q, want an explicit unmeasured target row", stdout)
	}
	if !containsLine(stdout, "Summary: 1 checked") {
		t.Errorf("stdout = %q, want the measured-only summary", stdout)
	}
	if !containsLine(stdout, interruptSentence) {
		t.Errorf("stdout = %q, want the interrupt sentence", stdout)
	}
}

// TestCheckInterruptBeforeStart cancels the run before any target starts:
// the first pause wait has not begun, so Run returns immediately with no
// measured results. Text prints unmeasured rows, --json prints nothing to
// stdout, both exit 130.
func TestCheckInterruptBeforeStart(t *testing.T) {
	env, path, _ := setup(t, mockdpi.Config{Control: true, CertNames: []string{testHost, "second.example"}}, true)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the SIGINT lands before the run begins

	stdout, _, err := runCheckCtx(t, ctx, env, "--targets-file", path)
	if code := exitCodeOf(t, err); code != 130 {
		t.Fatalf("exit = %d, want 130 (stdout: %q)", code, stdout)
	}
	if !containsLine(stdout, interruptSentence) {
		t.Errorf("stdout = %q, want the interrupt sentence", stdout)
	}
	if !containsLine(stdout, "t1  not measured") || !containsLine(stdout, "t2  not measured") || !containsLine(stdout, "Summary: 0 checked") {
		t.Errorf("stdout = %q, want both unmeasured rows and zero checked", stdout)
	}

	jsonOut, _, err := runCheckCtx(t, ctx, env, "--targets-file", path, "--json")
	if code := exitCodeOf(t, err); code != 130 {
		t.Fatalf("json: exit = %d, want 130", code)
	}
	if jsonOut != "" {
		t.Errorf("json stdout = %q, want empty", jsonOut)
	}
	for _, name := range []string{runner.RevFile, runner.RotationFile} {
		if _, err := os.Stat(filepath.Join(agentDir(t), name)); !os.IsNotExist(err) {
			t.Errorf("cancelled run created state %s: %v", name, err)
		}
	}
	entries, err := os.ReadDir(agentDir(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("cancelled run left files: %v", entries)
	}
	t.Log("cancelled before start: no state files or staging directories remain")
}

func containsLine(s, sub string) bool {
	for _, line := range splitLines(s) {
		if len(line) >= len(sub) && contains(line, sub) {
			return true
		}
	}
	return false
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// signalGateClock holds the pool between targets without starting timer
// goroutines. The marker is published only after both completion and pause.
type signalGateClock struct {
	gateClock
	paused chan struct{}
}

func (c *signalGateClock) After(time.Duration) <-chan time.Time {
	close(c.paused)
	return nil
}

func TestCheckInterruptSignal(t *testing.T) {
	validate := func(stdout []byte) {
		t.Helper()
		var docs []json.RawMessage
		if err := json.Unmarshal(stdout, &docs); err != nil {
			t.Fatalf("stdout is not a complete JSON array: %v\n%s", err, stdout)
		}
		if len(docs) != 1 {
			t.Fatalf("got %d reports, want 1", len(docs))
		}
		if _, err := report.Validate(docs[0]); err != nil {
			t.Fatalf("report does not validate: %v", err)
		}
		var doc report.Report
		if err := json.Unmarshal(docs[0], &doc); err != nil {
			t.Fatal(err)
		}
		if len(doc.Results) != 1 || doc.Results[0].Target != "t1" {
			t.Fatalf("results = %+v, want only t1", doc.Results)
		}
	}

	if os.Getenv("MAYAK_SIGNAL_HELPER") == "1" {
		marker := os.Getenv("MAYAK_SIGNAL_MARKER")
		if marker == "" {
			t.Fatal("helper requires MAYAK_SIGNAL_MARKER")
		}
		env, path, _ := setup(t, mockdpi.Config{Control: true, CertNames: []string{testHost, "second.example"}}, true)
		dir := agentDir(t)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		before := map[string][]byte{
			runner.RevFile:      []byte("2026-11-08.1\n"),
			runner.RotationFile: []byte("2\n"),
		}
		for name, data := range before {
			if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		clock := &signalGateClock{
			gateClock: gateClock{parked: make(chan struct{})},
			paused:    make(chan struct{}),
		}
		env.Clock = clock
		done, notified := make(chan struct{}), make(chan struct{})
		go func() {
			defer close(notified)
			for _, ready := range []<-chan struct{}{clock.parked, clock.paused} {
				select {
				case <-ready:
				case <-done:
					return
				}
			}
			if err := os.WriteFile(marker, []byte("t1 complete; pool paused before t2\n"), 0o600); err != nil {
				t.Errorf("publish signal marker: %v", err)
			}
		}()
		defer func() { close(done); <-notified }()

		var out, errBuf bytes.Buffer
		cmd := newRootCmd(env)
		cmd.SetOut(&out)
		cmd.SetErr(&errBuf)
		cmd.SetArgs([]string{"check", "--targets-file", path, "--json"})
		t.Logf("surface=CLI signal.NotifyContext invocation=mayak check --targets-file %q --json", path)
		err := cmd.Execute()
		if code := exitCodeOf(t, err); code != 130 {
			t.Fatalf("exit=%d want 130 stdout=%q stderr=%q", code, out.String(), errBuf.String())
		}
		validate(out.Bytes())
		for name, data := range before {
			after, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(data, after) {
				t.Fatalf("%s changed: %q -> %q", name, data, after)
			}
			t.Logf("state %s byte-identical: before=%q after=%q", name, data, after)
		}
		fmt.Printf("SIGNAL_CHILD_JSON=%s\nSIGNAL_CHILD_EXIT=130\n", bytes.TrimSpace(out.Bytes()))
		t.Logf("stderr=%q", errBuf.String())
		return
	}

	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("APPDATA", t.TempDir())
	marker := filepath.Join(dir, "signal-ready")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestCheckInterruptSignal$", "-test.v")
	cmd.Env = append(os.Environ(), "MAYAK_SIGNAL_HELPER=1", "MAYAK_SIGNAL_MARKER="+marker, "XDG_CONFIG_HOME="+dir, "APPDATA="+dir, "TMPDIR="+dir, "TMP="+dir, "TEMP="+dir)
	var out, errBuf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errBuf
	t.Logf("surface=OS subprocess invocation=%q env=MAYAK_SIGNAL_HELPER=1 MAYAK_SIGNAL_MARKER=%q XDG_CONFIG_HOME=%q", cmd.Args, marker, dir)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
		t.Logf("child stdout:\n%s\nchild stderr:\n%s", out.String(), errBuf.String())
	}()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		data, err := os.ReadFile(marker)
		if err == nil && len(data) > 0 {
			t.Logf("marker=%q", data)
			break
		}
		if err != nil && !os.IsNotExist(err) {
			t.Fatalf("read marker: %v", err)
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatalf("waiting for signal marker: %v", ctx.Err())
		}
	}
	t.Logf("calling cmd.Process.Signal(os.Interrupt) pid=%d", cmd.Process.Pid)
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		if runtime.GOOS == "windows" && (strings.Contains(err.Error(), "not supported") || strings.Contains(err.Error(), "not implemented")) {
			t.Skipf("os.Process.Signal(os.Interrupt) unsupported: %v", err)
		}
		t.Fatalf("send SIGINT: %v", err)
	}
	err = cmd.Wait()
	waited = true
	t.Logf("child test exit=%d", cmd.ProcessState.ExitCode())
	if err != nil {
		t.Fatalf("signal child failed: %v", err)
	}
	if !strings.Contains(out.String(), "\nSIGNAL_CHILD_EXIT=130\n") {
		t.Fatal("child output missing SIGNAL_CHILD_EXIT=130")
	}
	for _, line := range strings.Split(out.String(), "\n") {
		if raw, ok := strings.CutPrefix(line, "SIGNAL_CHILD_JSON="); ok {
			validate([]byte(raw))
			return
		}
	}
	t.Fatal("child output missing captured JSON stdout")
}
