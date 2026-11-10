package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/polargoose18/mayak/internal/targets"
)

type ctrlTestServer struct {
	server *ctrlServer
	url    string
}

func startCtrlTestServer(t *testing.T, hosts []string) *ctrlTestServer {
	t.Helper()
	tlist := sampleTargets(hosts[0])

	cfg := &Config{
		Addr:    "127.0.0.1:0",
		TLSAddr: "",
	}
	srv := newCtrlServerWithTargets(cfg, &tlist)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().(*net.TCPAddr)
	url := fmt.Sprintf("http://127.0.0.1:%d", addr.Port)

	go srv.http.Serve(listener)
	t.Cleanup(func() { srv.http.Close() })

	return &ctrlTestServer{server: srv, url: url}
}

func sampleTargets(host string) targets.Targets {
	return targets.Targets{
		V:       1,
		Rev:     "2026-10-13.1",
		Expires: time.Now().Add(14 * 24 * time.Hour),
		Items: []targets.Target{
			{ID: "a", Host: host, Category: targets.CategoryInfra, Rationale: "Fictional target number one.", Rev: "2026-10-13.1"},
		},
	}
}

func newSelfSignedCertForNames(names []string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate key: %w", err)
	}
	one := big.NewInt(1)
	serial, err := rand.Int(rand.Reader, big.NewInt(1).Lsh(one, 63))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate serial: %w", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "test"},
		SerialNumber:          serial,
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              names,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse certificate: %w", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

func TestPing(t *testing.T) {
	cts := startCtrlTestServer(t, []string{"example.org"})

	resp, err := http.Get(cts.url + "/v1/ping")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
}

func TestReachTrue(t *testing.T) {
	host := "example.org"
	cts := startCtrlTestServer(t, []string{host})
	cts.server.lookupHost = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
	}
	cts.server.dialContext = func(context.Context, string, string) (net.Conn, error) {
		client, peer := net.Pipe()
		peer.Close()
		return client, nil
	}

	resp, err := http.Get(cts.url + "/v1/reach?host=" + host)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	var reply struct {
		Reachable *bool `json:"reachable"`
	}
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &reply); err != nil {
		t.Fatalf("body = %s, err = %v", body, err)
	}
	if reply.Reachable == nil || !*reply.Reachable {
		t.Fatal("no reachable field")
	}
}

func TestReachFalse(t *testing.T) {
	host := "example.org"
	cts := startCtrlTestServer(t, []string{host})
	cts.server.lookupHost = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
	}
	cts.server.dialContext = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("connection refused")
	}

	resp, err := http.Get(cts.url + "/v1/reach?host=" + host)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	var reply struct {
		Reachable *bool `json:"reachable"`
	}
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &reply); err != nil {
		t.Fatalf("body = %s, err = %v", body, err)
	}
	if reply.Reachable == nil || *reply.Reachable {
		t.Fatal("no reachable field")
	}
}

func TestHostNotInList(t *testing.T) {
	cts := startCtrlTestServer(t, []string{"allowed.example"})

	resp, err := http.Get(cts.url + "/v1/reach?host=evil.example")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", resp.StatusCode)
	}
}

func TestRejectIPParam(t *testing.T) {
	host := "allowed.example"
	cts := startCtrlTestServer(t, []string{host})

	resp, err := http.Get(cts.url + "/v1/reach?host=" + host + "&ip=10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", resp.StatusCode)
	}
}

func TestBadPath(t *testing.T) {
	host := "allowed.example"
	cts := startCtrlTestServer(t, []string{host})

	resp, err := http.Get(cts.url + "/v1/fetch?host=" + host + "&path=/admin")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", resp.StatusCode)
	}
}

func TestRateLimit(t *testing.T) {
	host := "example.org"
	cts := startCtrlTestServer(t, []string{host})

	// Use a single client with keep-alives disabled to ensure each request
	// goes through a separate connection. The rate limiter strips the port
	// and keys by IP only, so all requests from 127.0.0.1 share one bucket.
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	var got429 int32

	for i := 0; i < 25; i++ {
		resp, err := client.Get(cts.url + "/v1/ping")
		if err != nil {
			continue
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			atomic.AddInt32(&got429, 1)
		}
		resp.Body.Close()
	}

	if got429 == 0 {
		t.Fatal("expected at least one 429")
	}
}

func TestAnySNIHanderCert(t *testing.T) {
	_, fingerprint, err := newSelfSignedCert()
	if err != nil {
		t.Fatalf("newSelfSignedCert: %v", err)
	}
	if len(fingerprint) != 64 {
		t.Errorf("fingerprint length %d, want 64 (SHA-256 hex)", len(fingerprint))
	}
}

func TestAnySNIHanderDisabled(t *testing.T) {
	cfg := &Config{
		Addr:    ":8443",
		TLSAddr: "",
	}
	ln, err := anySNIHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if ln != nil {
		t.Error("expected nil listener for empty TLSAddr")
	}
}
func TestAnySNIHandshake(t *testing.T) {
	ln, err := anySNIHandler(&Config{TLSAddr: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { serveTLSListener(ln); close(done) }()
	t.Cleanup(func() { ln.Close(); <-done })
	for _, name := range []string{"target.example", "arbitrary.invalid", ""} {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true, ServerName: name})
		if err != nil {
			t.Fatalf("handshake SNI %q: %v", name, err)
		}
		conn.SetReadDeadline(time.Now().Add(time.Second))
		_, err = conn.Read(make([]byte, 1))
		conn.Close()
		if err != io.EOF {
			t.Fatalf("after handshake: %v, want EOF", err)
		}
	}
}

func TestFetchTimeout(t *testing.T) {
	cts := startCtrlTestServer(t, []string{"example.org"})
	cts.server.dialTimeout = 30 * time.Millisecond
	cts.server.lookupHost = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
	}
	cts.server.dialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		client, peer := net.Pipe()
		go func() { <-ctx.Done(); peer.Close() }()
		return client, nil
	}
	client := &http.Client{Timeout: time.Second}
	resp, err := client.Get(cts.url + "/v1/fetch?host=example.org&path=/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status %d, want 502", resp.StatusCode)
	}
}
