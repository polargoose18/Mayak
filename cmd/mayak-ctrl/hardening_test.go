package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/polargoose18/mayak/internal/probe"
	"github.com/polargoose18/mayak/internal/targets"
)

func TestTargetsRollbackAfterRestart(t *testing.T) {
	if state := os.Getenv("MAYAK_CTRL_RESTART_STATE"); state != "" {
		now, err := time.Parse(time.RFC3339Nano, os.Getenv("MAYAK_CTRL_RESTART_CLOCK"))
		if err != nil {
			t.Fatal(err)
		}
		_, err = loadCtrlTargets("../../targets/targets.signed.json", state, now)
		if !errors.Is(err, targets.ErrRollback) {
			t.Fatalf("restarted process: %v, want rollback", err)
		}
		t.Logf("restarted process rejected still-valid signed list: %v", err)
		return
	}
	path := "../../targets/targets.signed.json"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	list, err := targets.Open(targets.PublicKeys(), data)
	if err != nil {
		t.Fatal(err)
	}
	now := list.Expires.Add(-time.Hour)
	state := filepath.Join(t.TempDir(), "state")
	if _, err := loadCtrlTargets(path, state, now); err != nil {
		t.Fatal(err)
	}
	revPath := filepath.Join(state, "targets.rev")
	stored, err := targets.FileRevStore(revPath).Load()
	if err != nil || stored != list.Rev {
		t.Fatalf("stored rev %q: %v", stored, err)
	}
	for _, tc := range []struct {
		path string
		mode os.FileMode
	}{{state, 0700}, {revPath, 0600}} {
		info, err := os.Stat(tc.path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != tc.mode {
			t.Fatalf("%s mode %o, want %o", tc.path, info.Mode().Perm(), tc.mode)
		}
	}
	// Seed the durable revision as a previous process would after accepting a
	// newer list. The repository fixture still has a valid signature and clock.
	const newer = "2099-01-01.1"
	if err := targets.FileRevStore(revPath).Save(newer); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestTargetsRollbackAfterRestart$", "-test.v")
	cmd.Env = append(os.Environ(), "MAYAK_CTRL_RESTART_STATE="+state, "MAYAK_CTRL_RESTART_CLOCK="+now.Format(time.RFC3339Nano))
	t.Logf("surface=process restart invocation=%q; durable prior revision=%s (seeded)", cmd.Args, newer)
	output, err := cmd.CombinedOutput()
	t.Logf("restart output:\n%s", output)
	if err != nil {
		t.Fatalf("restart: %v", err)
	}
	if got, err := targets.FileRevStore(revPath).Load(); err != nil || got != newer {
		t.Fatalf("rollback changed rev to %q: %v", got, err)
	}
	// Corruption must fail closed rather than reset rollback protection.
	if err := os.WriteFile(revPath, []byte("damaged\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCtrlTargets(path, state, now); !errors.Is(err, targets.ErrRevStoreDamaged) {
		t.Fatalf("damaged store: %v", err)
	}
}

func TestTargetsRejectBadSignature(t *testing.T) {
	data, err := os.ReadFile("../../targets/targets.signed.json")
	if err != nil {
		t.Fatal(err)
	}
	list, err := targets.Open(targets.PublicKeys(), data)
	if err != nil {
		t.Fatal(err)
	}
	// Mutate signed content without updating its signature.
	data = bytes.Replace(data, []byte(`"payload":"`), []byte(`"payload":"AAAA`), 1)
	dir := t.TempDir()
	path := filepath.Join(dir, "tampered.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCtrlTargets(path, filepath.Join(dir, "state"), list.Expires.Add(-time.Hour)); !errors.Is(err, targets.ErrBadSignature) {
		t.Fatalf("tampered signature: %v", err)
	}
}

func TestTargetsRuntimeExpiry(t *testing.T) {
	list := sampleTargets("example.org")
	srv := newCtrlServerWithTargets(&Config{}, &list)
	now := list.Expires.Add(-time.Nanosecond)
	srv.now = func() time.Time { return now }
	if !srv.authorizeHost("EXAMPLE.ORG") {
		t.Fatal("fresh allowed host rejected")
	}
	srv.lookupHost = func(context.Context, string) ([]netip.Addr, error) {
		t.Fatal("expired list reached resolver")
		return nil, nil
	}
	srv.dialContext = func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("expired list reached dial")
		return nil, errors.New("unexpected dial")
	}
	for _, expired := range []time.Time{list.Expires, list.Expires.Add(time.Second)} {
		now = expired
		for _, endpoint := range []string{"/v1/reach?host=example.org", "/v1/fetch?host=example.org&path=/", "/v1/ping"} {
			reply := httptest.NewRecorder()
			srv.http.Handler.ServeHTTP(reply, httptest.NewRequest(http.MethodGet, endpoint, nil))
			want := http.StatusBadRequest
			if endpoint == "/v1/ping" {
				want = http.StatusOK
			}
			t.Logf("fake clock=%s endpoint=%s status=%d; DNS=0 dial=0", now, endpoint, reply.Code)
			if reply.Code != want {
				t.Fatalf("%s at %s: %d, want %d", endpoint, now, reply.Code, want)
			}
		}
	}
}

func TestStateDirConfig(t *testing.T) {
	oldArgs := os.Args
	t.Cleanup(func() { os.Args = oldArgs })
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	os.Args = []string{"mayak-ctrl"}
	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	base, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.StateDir != filepath.Join(base, "mayak-ctrl") {
		t.Fatalf("default state dir %q", cfg.StateDir)
	}
	os.Args = []string{"mayak-ctrl", "--state-dir", t.TempDir()}
	cfg, err = loadConfig()
	if err != nil || cfg.StateDir != os.Args[2] {
		t.Fatalf("explicit state dir: %+v, %v", cfg, err)
	}
}

type privacyListener struct {
	net.Listener
	address string
}
type privacyConn struct {
	net.Conn
	address string
}

func (l privacyListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return privacyConn{c, l.address}, nil
}
func (c privacyConn) RemoteAddr() net.Addr { return privacyAddr(c.address) }

type privacyAddr string

func (a privacyAddr) Network() string { return "tcp" }
func (a privacyAddr) String() string  { return string(a) }

func TestNoClientAddressInLogs(t *testing.T) {
	const address = "203.0.113.219"
	list := sampleTargets("allowed.example")
	srv := newCtrlServerWithTargets(&Config{}, &list)
	if srv.http.ErrorLog == nil || srv.http.ErrorLog.Writer() != io.Discard {
		t.Fatal("HTTP diagnostic logger must discard client-bearing errors")
	}
	// Capture every logging destination: the server logger, the standard logger,
	// and direct stdout/stderr. No tests in this package run in parallel.
	var serverLog, standardLog bytes.Buffer
	srv.http.ErrorLog.SetOutput(&serverLog)
	oldLog := log.Writer()
	log.SetOutput(&standardLog)
	defer log.SetOutput(oldLog)
	output, err := os.CreateTemp(t.TempDir(), "output")
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = output, output
	defer func() { os.Stdout, os.Stderr = oldOut, oldErr }()
	srv.lookupHost = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
	}
	srv.dialContext = func(context.Context, string, string) (net.Conn, error) {
		client, peer := net.Pipe()
		peer.Close()
		return client, nil
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.http.Serve(privacyListener{listener, address + ":54321"}) }()
	defer func() { srv.http.Close(); <-done }()
	for _, endpoint := range []string{"/v1/ping", "/v1/reach?host=allowed.example", "/v1/reach?host=forbidden.example", "/v1/fetch?host=allowed.example&path=/&ip=" + address} {
		args := []string{"-i", "--silent", "--show-error", "--max-time", "3", "http://" + listener.Addr().String() + endpoint}
		t.Logf("surface=HTTP privacy invocation=curl %q", args)
		response, err := exec.Command("curl", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("curl: %v", err)
		}
		want := "HTTP/1.1 400 Bad Request"
		if endpoint == "/v1/ping" || endpoint == "/v1/reach?host=allowed.example" {
			want = "HTTP/1.1 200 OK"
		}
		t.Logf("privacy response:\n%s", response)
		if !strings.HasPrefix(string(response), want+"\r\n") {
			t.Fatalf("unexpected response: %s", response)
		}
	}
	captured, err := os.ReadFile(output.Name())
	if err != nil {
		t.Fatal(err)
	}
	srv.mu.Lock()
	retained := fmt.Sprintf("%+v %+v %+v", srv, srv.targetsList, srv.buckets)
	for key := range srv.buckets {
		if len(key) != 64 {
			t.Errorf("non-hashed rate-limit key %q", key)
		}
	}
	srv.mu.Unlock()
	if len(srv.buckets) != 1 {
		t.Fatalf("retained buckets %d, want one", len(srv.buckets))
	}
	for sink, data := range map[string]string{"HTTP logger": serverLog.String(), "standard logger": standardLog.String(), "stdout/stderr": string(captured), "retained application state": retained} {
		t.Logf("literal client-address search sink=%s bytes=%d found=%t", sink, len(data), strings.Contains(data, address))
		if strings.Contains(data, address) {
			t.Errorf("client address retained in %s: %s", sink, data)
		}
	}
}

func TestProbeTLSSNIAnySNIListener(t *testing.T) {
	const host = "allowed.example"
	const neutral = "neutral.example"
	cert, err := newSelfSignedCertForNames([]string{host, neutral})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); err != nil {
		t.Fatal(err)
	}
	ln, err := anySNIHandler(&Config{TLSAddr: "127.0.0.1:0", TLSCert: certPath, TLSKey: keyPath})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { serveTLSListener(ln); close(done) }()
	defer func() { ln.Close(); <-done }()
	list := sampleTargets(host)
	srv := newCtrlServerWithTargets(&Config{}, &list)
	if !srv.authorizeHost(host) {
		t.Fatal("integration target not allowed")
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert.Leaf)
	addr := ln.Addr().(*net.TCPAddr).AddrPort()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	obs, err := probe.TLSSNI(ctx, probe.TLSSNIRequest{TargetAddr: addr, ControlAddr: addr, Host: host, NeutralSNI: neutral, RootCAs: roots})
	if err != nil {
		t.Fatal(err)
	}
	if obs.TargetSNIViaControl.Outcome != probe.TLSOutcomeOK || obs.TargetSNI.Outcome != probe.TLSOutcomeOK || obs.NeutralSNI.Outcome != probe.TLSOutcomeOK {
		t.Fatalf("trusted any-SNI observation: %+v", obs)
	}
	t.Logf("trusted probe.TLSSNI observation: %+v", obs)
}

// TestControlHTTPWireSurface records raw HTTP responses through curl, including
// the expiry boundary and the health endpoint on the same expired server.
func TestControlHTTPWireSurface(t *testing.T) {
	list := sampleTargets("allowed.example")
	srv := newCtrlServerWithTargets(&Config{}, &list)
	srv.now = func() time.Time { return list.Expires.Add(time.Second) }
	srv.lookupHost = func(context.Context, string) ([]netip.Addr, error) {
		t.Error("expired target reached DNS")
		return nil, errors.New("unexpected lookup")
	}
	srv.dialContext = func(context.Context, string, string) (net.Conn, error) {
		t.Error("expired target reached dial")
		return nil, errors.New("unexpected dial")
	}
	wire := httptest.NewServer(srv.http.Handler)
	defer wire.Close()
	for _, tc := range []struct{ endpoint, status string }{
		{"/v1/ping", "HTTP/1.1 200 OK"},
		{"/v1/reach?host=allowed.example", "HTTP/1.1 400 Bad Request"},
		{"/v1/fetch?host=allowed.example&path=/", "HTTP/1.1 400 Bad Request"},
		{"/v1/reach?host=allowed.example&ip=127.0.0.1", "HTTP/1.1 400 Bad Request"},
	} {
		args := []string{"-i", "--silent", "--show-error", "--max-time", "3", wire.URL + tc.endpoint}
		t.Logf("surface=HTTP invocation=curl %q", args)
		output, err := exec.Command("curl", args...).CombinedOutput()
		t.Logf("raw response:\n%s", output)
		if err != nil {
			t.Fatalf("curl: %v", err)
		}
		if !strings.HasPrefix(string(output), tc.status+"\r\n") {
			t.Fatalf("unexpected response: %s", output)
		}
	}
}
