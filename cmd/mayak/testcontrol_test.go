package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/polargoose18/mayak/internal/classify"
	"github.com/polargoose18/mayak/internal/probe"
	"github.com/polargoose18/mayak/testbed/mockdpi"
)

// testControl is a control node for the check-command tests: an
// httptest.Server implementing /v1/ping, /v1/reach and /v1/fetch, styled
// after internal/probe's fakeControl. Its /v1/fetch fetches from a clean
// vantage point (a mockdpi control node), so the reference response the
// classifier reads is genuine. It counts the requests it got.
type testControl struct {
	srv *httptest.Server

	hosts     []string // hosts the node's list admits
	reachable bool

	pingStatus int

	// fetchFrom is the clean vantage /v1/fetch fetches from; invalid means
	// it answers 502, as a node without an outside view would.
	fetchFrom netip.AddrPort
	roots     *x509.CertPool

	requests atomic.Int64 // every request, whatever the path
}

func newTestControl(t *testing.T, hosts []string, reachable bool) *testControl {
	t.Helper()
	f := &testControl{hosts: hosts, reachable: reachable, pingStatus: http.StatusOK}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/ping", func(w http.ResponseWriter, _ *http.Request) {
		f.requests.Add(1)
		w.WriteHeader(f.pingStatus)
	})
	mux.HandleFunc("/v1/reach", func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		if !f.admit(w, r) {
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]bool{"reachable": f.reachable})
	})
	mux.HandleFunc("/v1/fetch", func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		if !f.admit(w, r) {
			return
		}
		if !f.fetchFrom.IsValid() {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		q := r.URL.Query()
		resp, err := fetchPage(r.Context(), f.fetchFrom, q.Get("host"), q.Get("path"), f.roots)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": resp.Status, "size": resp.Size, "body_hash": resp.BodyHash})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// admit applies what the control node requires of a request: no ip, no port
// other than 443, and a host from its list.
func (f *testControl) admit(w http.ResponseWriter, r *http.Request) bool {
	q := r.URL.Query()
	switch {
	case q.Has("ip"):
		http.Error(w, "ip is not accepted", http.StatusBadRequest)
	case q.Has("port") && q.Get("port") != "443":
		http.Error(w, "only port 443", http.StatusBadRequest)
	case !slices.Contains(f.hosts, q.Get("host")):
		http.Error(w, "host is not in the list", http.StatusForbidden)
	default:
		return true
	}
	return false
}

// fetchPage fetches the page from the clean vantage point, the way a real
// node would.
func fetchPage(ctx context.Context, from netip.AddrPort, host, path string, pool *x509.CertPool) (*classify.HTTPResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	obs, err := probe.HTTP(ctx, probe.HTTPRequest{Addr: from, Host: host, Path: path, RootCAs: pool})
	if err != nil {
		return nil, err
	}
	return &obs.Response, nil
}

// resolverVia returns a system-resolver stand-in that sends its queries to
// the given mock DNS server (UDP).
func resolverVia(dnsAddr string) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", dnsAddr)
		},
	}
}

func probeDNSServer(ap netip.AddrPort) probe.DNSServer {
	return probe.DNSServer{Addr: ap, Transport: probe.DNSTransportUDP}
}

func probeControlClient(base string, pool *x509.CertPool) probe.ControlClient {
	return probe.ControlClient{BaseURL: base, RootCAs: pool}
}

// runnerZeroRand is a Rand that always picks the shortest pause, so the
// in-process runs are fast. It satisfies runner.Rand.
type zeroRand struct{}

func (zeroRand) Int64N(int64) int64 { return 0 }

// portOf returns the port of an "ip:port" string.
func portOf(t testing.TB, s string) uint16 {
	t.Helper()
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		t.Fatal(err)
	}
	return ap.Port()
}

// portOfTLS returns the port of the mock's TLS control server, which serves
// any SNI.
func portOfTLS(t testing.TB, m *mockdpi.Env) uint16 {
	return portOf(t, m.ControlTLS)
}
