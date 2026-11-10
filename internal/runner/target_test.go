package runner

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/polargoose18/mayak/internal/classify"
	"github.com/polargoose18/mayak/internal/probe"
	"github.com/polargoose18/mayak/internal/report"
	"github.com/polargoose18/mayak/internal/targets"
	"github.com/polargoose18/mayak/testbed/mockdpi"
)

// The host name used everywhere in these tests. It is not in /etc/hosts, so
// the system resolver really asks the mock DNS for it, and the mock
// certificate is given this name.
const testHost = "target.example"

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

func addrPort(t *testing.T, s string) netip.AddrPort {
	t.Helper()
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		t.Fatal(err)
	}
	return ap
}

func portOf(t *testing.T, s string) uint16 {
	t.Helper()
	ap := addrPort(t, s)
	return ap.Port()
}

// fakeNode is a control node that speaks the protocol of control.go: /v1/ping
// answers, /v1/reach reports what it was told, and /v1/fetch returns the
// reference response. It is not the mockdpi control node: the runner test
// needs to give the reference explicitly.
type fakeNode struct {
	srv       *httptest.Server
	reachable bool
	ref       func(host, path string) (*classify.HTTPResponse, bool)
}

func newFakeNode(t *testing.T, reachable bool, ref func(host, path string) (*classify.HTTPResponse, bool)) *fakeNode {
	t.Helper()
	f := &fakeNode{reachable: reachable, ref: ref}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/ping", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/v1/reach", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]bool{"reachable": f.reachable})
	})
	mux.HandleFunc("/v1/fetch", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		ref, ok := f.ref(q.Get("host"), q.Get("path"))
		if !ok {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": ref.Status, "size": ref.Size, "body_hash": ref.BodyHash})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// fetchRef computes the reference the control node would give for the target:
// the response of the target itself, as seen from a clean vantage point.
func fetchRef(t *testing.T, target netip.AddrPort, host, path string, pool *x509.CertPool) *classify.HTTPResponse {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	obs, err := probe.HTTP(ctx, probe.HTTPRequest{Addr: target, Host: host, Path: path, RootCAs: pool})
	if err != nil || obs.Result != classify.HTTPResponded {
		t.Fatalf("fetch reference: %+v, %v", obs, err)
	}
	return &obs.Response
}

// baseEnv builds the Env of a run against a mockdpi scenario: the system
// resolver and the control resolver answer from the mock DNS, the control
// node is the fake, and the trusted roots are the mock CA.
func baseEnv(t *testing.T, env *mockdpi.Env, node *fakeNode, targetPort uint16) Env {
	t.Helper()
	return Env{
		SystemResolver:  resolverVia(env.ControlDNS),
		ControlResolver: probe.DNSServer{Addr: addrPort(t, env.ControlDNS), Transport: probe.DNSTransportUDP},
		Control:         probe.ControlClient{BaseURL: node.srv.URL, RootCAs: env.CertPool},
		ControlTLS:      addrPort(t, env.ControlTLS),
		Anchors:         []string{"https://" + env.ControlTLS + "/"},
		NeutralSNI:      "neutral.example",
		TargetPort:      targetPort,
		RootCAs:         env.CertPool,
	}
}

func targetOf(host string) targets.Target {
	return targets.Target{ID: "t", Host: host, Category: targets.CategoryInfra, Rationale: "A fictional target for the runner tests."}
}

// TestCheckVerdicts runs one target through the whole pass and checks the
// verdict, the way the plan's B3 acceptance asks (SPEC section 5).
func TestCheckVerdicts(t *testing.T) {
	path := probe.ControlPathRoot

	t.Run("clean target is ok", func(t *testing.T) {
		env := mockdpi.Start(t, mockdpi.Config{Control: true, CertNames: []string{testHost}})
		target := addrPort(t, env.ControlTLS)
		node := newFakeNode(t, true, func(host, p string) (*classify.HTTPResponse, bool) {
			return fetchRef(t, target, host, p, env.CertPool), true
		})
		r := Check(context.Background(), baseEnv(t, env, node, target.Port()), targetOf(testHost))
		if r.Err != nil {
			t.Fatalf("err = %v", r.Err)
		}
		if r.Test != report.TestHTTP {
			t.Errorf("test = %q, want %q", r.Test, report.TestHTTP)
		}
		if r.Verdict != report.VerdictOK {
			t.Errorf("verdict = %q, want ok\nobservation: %+v", r.Verdict, r.Observation)
		}
		if r.Reference == nil {
			t.Error("reference was not recorded")
		}
	})

	t.Run("reset after hello is sni_block", func(t *testing.T) {
		env := mockdpi.Start(t, mockdpi.Config{
			ResetAfterHello: &mockdpi.ResetAfterHelloConfig{BlockedSNI: []string{testHost}},
			Control:         true,
			CertNames:       []string{testHost},
		})
		// The target and the control node are the same filtered path here: the
		// censor resets the target SNI whatever the IP is, so the third
		// handshake fails too and the SNI is proven to be what is filtered.
		target := addrPort(t, env.ResetAfterHello)
		node := newFakeNode(t, true, func(host, p string) (*classify.HTTPResponse, bool) { return nil, false })
		e := baseEnv(t, env, node, target.Port())
		e.ControlTLS = target
		r := Check(context.Background(), e, targetOf(testHost))
		if r.Err != nil {
			t.Fatalf("err = %v", r.Err)
		}
		if r.Test != report.TestTLSSNI {
			t.Errorf("test = %q, want %q", r.Test, report.TestTLSSNI)
		}
		if r.Verdict != report.VerdictSNIBlock {
			t.Errorf("verdict = %q, want sni_block\nobservation: %+v", r.Verdict, r.Observation)
		}
	})

	t.Run("dns_spoof is dns_tamper", func(t *testing.T) {
		env := mockdpi.Start(t, mockdpi.Config{
			Control:   true,
			CertNames: []string{testHost},
			DNSSpoof:  &mockdpi.DNSSpoofConfig{Names: []string{testHost}},
		})
		target := addrPort(t, env.ControlTLS)
		node := newFakeNode(t, true, func(host, p string) (*classify.HTTPResponse, bool) {
			return fetchRef(t, target, host, p, env.CertPool), true
		})
		e := baseEnv(t, env, node, target.Port())
		e.SystemResolver = resolverVia(env.DNSSpoof)
		r := Check(context.Background(), e, targetOf(testHost))
		if r.Err != nil {
			t.Fatalf("err = %v", r.Err)
		}
		if r.Test != report.TestDNS {
			t.Errorf("test = %q, want %q", r.Test, report.TestDNS)
		}
		if r.Verdict != report.VerdictDNSTamper {
			t.Errorf("verdict = %q, want dns_tamper\nobservation: %+v", r.Verdict, r.Observation)
		}
	})

	t.Run("stub page is http_stub", func(t *testing.T) {
		env := mockdpi.Start(t, mockdpi.Config{Control: true, StubPage: true, CertNames: []string{testHost}})
		target := addrPort(t, env.StubPageTLS)
		// The stub's hash is what the operator's known-stub list would hold; the
		// control node's reference is a different, real page.
		stub := fetchRef(t, target, testHost, path, env.CertPool)
		node := newFakeNode(t, true, func(host, p string) (*classify.HTTPResponse, bool) {
			return &classify.HTTPResponse{Status: 200, Size: 4096, BodyHash: "the-real-page"}, true
		})
		e := baseEnv(t, env, node, target.Port())
		e.KnownStubHashes = []string{stub.BodyHash}
		r := Check(context.Background(), e, targetOf(testHost))
		if r.Err != nil {
			t.Fatalf("err = %v", r.Err)
		}
		if r.Test != report.TestHTTP {
			t.Errorf("test = %q, want %q", r.Test, report.TestHTTP)
		}
		if r.Verdict != report.VerdictHTTPStub {
			t.Errorf("verdict = %q, want http_stub\nobservation: %+v", r.Verdict, r.Observation)
		}
	})

	t.Run("closed port is ip_block", func(t *testing.T) {
		env := mockdpi.Start(t, mockdpi.Config{Control: true, ClosedPort: true, CertNames: []string{testHost}})
		closed := addrPort(t, env.ClosedPort)
		node := newFakeNode(t, true, func(host, p string) (*classify.HTTPResponse, bool) { return nil, false })
		// The trusted address answers, but port 443 of it is closed.
		e := baseEnv(t, env, node, closed.Port())
		r := Check(context.Background(), e, targetOf(testHost))
		if r.Err != nil {
			t.Fatalf("err = %v", r.Err)
		}
		if r.Test != report.TestTCP {
			t.Errorf("test = %q, want %q", r.Test, report.TestTCP)
		}
		if r.Verdict != report.VerdictIPBlock {
			t.Errorf("verdict = %q, want ip_block\nobservation: %+v", r.Verdict, r.Observation)
		}
	})

	t.Run("blackhole is timeout_unknown", func(t *testing.T) {
		env := mockdpi.Start(t, mockdpi.Config{Control: true, Blackhole: true, CertNames: []string{testHost}})
		target := addrPort(t, env.Blackhole)
		node := newFakeNode(t, true, func(host, p string) (*classify.HTTPResponse, bool) { return nil, false })
		ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
		defer cancel()
		r := Check(ctx, baseEnv(t, env, node, target.Port()), targetOf(testHost))
		if r.Err != nil {
			t.Fatalf("err = %v", r.Err)
		}
		if r.Test != report.TestTLSSNI {
			t.Errorf("test = %q, want %q", r.Test, report.TestTLSSNI)
		}
		if r.Verdict != report.VerdictTimeoutUnknown {
			t.Errorf("verdict = %q, want timeout_unknown\nobservation: %+v", r.Verdict, r.Observation)
		}
	})
}

// scriptedResolver returns a fixed answer and counts lookups, so a test can
// both script the DNS comparison and prove the target's name is never
// resolved when ctrl failed.
type scriptedResolver struct {
	n     atomic.Int32
	addrs []netip.Addr
}

func (r *scriptedResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	r.n.Add(1)
	return r.addrs, nil
}

// countListener counts accepted connections on host.
func countListener(t *testing.T, host string) (netip.AddrPort, *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatal(err)
	}
	var hits atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			hits.Add(1)
			_ = c.Close()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().(*net.TCPAddr).AddrPort(), &hits
}

// When the system answer shares no address with the trusted one, the pass
// runs the TLS check of the first system address and passes its outcome to
// the classifier. Here that address has no TLS server, so the check proves
// nothing and the verdict is inconclusive, not ok (SPEC section 5, rule 2).
func TestCheckAddrCheckDrivesVerdict(t *testing.T) {
	trusted := netip.MustParseAddr("203.0.113.10") // the control node's view
	system := netip.MustParseAddr("203.0.113.99")  // the system resolver's view
	env := mockdpi.Start(t, mockdpi.Config{Control: true, NormalIP: trusted, CertNames: []string{testHost}})
	res := &scriptedResolver{addrs: []netip.Addr{system}} // shares nothing with trusted

	node := newFakeNode(t, true, func(host, p string) (*classify.HTTPResponse, bool) { return nil, false })
	e := Env{
		SystemResolver:  res,
		ControlResolver: probe.DNSServer{Addr: addrPort(t, env.ControlDNS), Transport: probe.DNSTransportUDP},
		Control:         probe.ControlClient{BaseURL: node.srv.URL, RootCAs: env.CertPool},
		ControlTLS:      addrPort(t, env.ControlTLS),
		Anchors:         []string{"https://" + env.ControlTLS + "/"},
		NeutralSNI:      "neutral.example",
		TargetPort:      portOf(t, env.ControlTLS),
		RootCAs:         env.CertPool,
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	r := Check(ctx, e, targetOf(testHost))
	if r.Err != nil {
		t.Fatalf("err = %v", r.Err)
	}
	if r.Observation.DNS.SystemAddrCheck != classify.AddrCheckUnreachable {
		t.Errorf("SystemAddrCheck = %q, want unreachable", r.Observation.DNS.SystemAddrCheck)
	}
	if r.Verdict != report.VerdictInconclusive {
		t.Errorf("verdict = %q, want inconclusive\nobservation: %+v", r.Verdict, r.Observation)
	}
}

// Without a control node the run is inconclusive and the target's network is
// not touched at all (the plan's B3 acceptance).
func TestCheckCtrlFailedTouchesNothing(t *testing.T) {
	env := mockdpi.Start(t, mockdpi.Config{Control: true, Blackhole: true, CertNames: []string{testHost}})
	target, hits := countListener(t, "127.0.0.1")
	res := &scriptedResolver{addrs: []netip.Addr{target.Addr()}}

	e := Env{
		SystemResolver:  res,
		ControlResolver: probe.DNSServer{Addr: addrPort(t, env.ControlDNS), Transport: probe.DNSTransportUDP},
		Control:         probe.ControlClient{BaseURL: "http://" + env.Blackhole, RootCAs: env.CertPool},
		ControlTLS:      addrPort(t, env.ControlTLS),
		Anchors:         []string{"http://" + env.Blackhole},
		TargetPort:      target.Port(),
		RootCAs:         env.CertPool,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()

	r := Check(ctx, e, targetOf(testHost))
	if r.Err != nil {
		t.Fatalf("err = %v", r.Err)
	}
	if r.Verdict != report.VerdictInconclusive {
		t.Errorf("verdict = %q, want inconclusive", r.Verdict)
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("the target was connected to %d times, want 0", n)
	}
	if n := res.n.Load(); n != 0 {
		t.Errorf("the target's name was resolved %d times, want 0", n)
	}
}
