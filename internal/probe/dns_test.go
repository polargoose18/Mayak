package probe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/polargoose18/mayak/internal/classify"
	"github.com/polargoose18/mayak/testbed/mockdpi"
)

const dnsHost = "target.example"

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

func udp(t *testing.T, a string) DNSServer {
	return DNSServer{Addr: addr(t, a), Transport: DNSTransportUDP}
}

func dot(t *testing.T, a string) DNSServer {
	return DNSServer{Addr: addr(t, a), Transport: DNSTransportDoT, ServerName: "localhost"}
}

func runDNS(t *testing.T, timeout time.Duration, env *mockdpi.Env, req DNSRequest) DNSObservation {
	t.Helper()
	req.roots = env.CertPool
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	obs, err := DNS(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	return obs
}

func addrs(s ...string) []netip.Addr {
	var out []netip.Addr
	for _, v := range s {
		out = append(out, netip.MustParseAddr(v))
	}
	return out
}

func requireResult(t *testing.T, name string, got DNSResult, status classify.DNSStatus, want []netip.Addr) {
	t.Helper()
	if got.Status != status {
		t.Errorf("%s: status = %q, want %q", name, got.Status, status)
	}
	if len(got.Addrs) != len(want) {
		t.Errorf("%s: addrs = %v, want %v", name, got.Addrs, want)
		return
	}
	for i := range want {
		if got.Addrs[i] != want[i] {
			t.Errorf("%s: addrs = %v, want %v", name, got.Addrs, want)
		}
	}
	if got.Ms < 0 {
		t.Errorf("%s: negative ms", name)
	}
}

func TestDNSClean(t *testing.T) {
	env := mockdpi.Start(t, mockdpi.Config{Control: true})
	obs := runDNS(t, generous, env, DNSRequest{
		Host:    dnsHost,
		System:  resolverVia(env.ControlDNS),
		Control: udp(t, env.ControlDNS),
		Public:  []DNSServer{dot(t, env.ControlDoT), udp(t, env.ControlDNS)},
	})
	ok := addrs("127.0.0.1")
	requireResult(t, "system", obs.System, classify.DNSOK, ok)
	requireResult(t, "control", obs.Control, classify.DNSOK, ok)
	if len(obs.Public) != 2 {
		t.Fatalf("public = %v", obs.Public)
	}
	requireResult(t, "public dot", obs.Public[0], classify.DNSOK, ok)
	requireResult(t, "public udp", obs.Public[1], classify.DNSOK, ok)

	c := obs.ForClassifier()
	if c.System.Status != classify.DNSOK || len(c.Public) != 2 || c.Control.Addrs[0] != ok[0] {
		t.Errorf("ForClassifier = %+v", c)
	}
}

func TestDNSSpoofedSystemResolver(t *testing.T) {
	env := mockdpi.Start(t, mockdpi.Config{
		DNSSpoof: &mockdpi.DNSSpoofConfig{Names: []string{dnsHost}},
		Control:  true,
	})
	obs := runDNS(t, generous, env, DNSRequest{
		Host:    dnsHost,
		System:  resolverVia(env.DNSSpoof),
		Control: udp(t, env.ControlDNS),
		Public:  []DNSServer{dot(t, env.ControlDoT)},
	})
	requireResult(t, "system", obs.System, classify.DNSOK, addrs("10.0.0.1"))
	requireResult(t, "control", obs.Control, classify.DNSOK, addrs("127.0.0.1"))
	requireResult(t, "public", obs.Public[0], classify.DNSOK, addrs("127.0.0.1"))
}

// rcodeServer is a DNS server that answers every query with the given rcode.
func rcodeServer(t *testing.T, rcode int) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	srv := &dns.Server{
		PacketConn:        pc,
		NotifyStartedFunc: func() { close(started) },
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetRcode(r, rcode)
			_ = w.WriteMsg(m)
		}),
	}
	done := make(chan struct{})
	go func() { defer close(done); _ = srv.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = srv.Shutdown(); <-done })
	return pc.LocalAddr().String()
}

func TestDNSRcodes(t *testing.T) {
	env := mockdpi.Start(t, mockdpi.Config{Control: true})
	obs := runDNS(t, generous, env, DNSRequest{
		Host:    dnsHost,
		System:  resolverVia(env.ControlDNS),
		Control: udp(t, rcodeServer(t, dns.RcodeNameError)),
		Public:  []DNSServer{udp(t, rcodeServer(t, dns.RcodeServerFailure)), udp(t, rcodeServer(t, dns.RcodeRefused))},
	})
	requireResult(t, "nxdomain", obs.Control, classify.DNSNXDomain, nil)
	requireResult(t, "servfail", obs.Public[0], classify.DNSFailure, nil)
	requireResult(t, "refused", obs.Public[1], classify.DNSFailure, nil)
}

func TestDNSNoDataIsOKWithoutAddresses(t *testing.T) {
	env := mockdpi.Start(t, mockdpi.Config{Control: true})
	obs := runDNS(t, generous, env, DNSRequest{
		Host:    dnsHost,
		System:  resolverVia(env.ControlDNS),
		Control: udp(t, rcodeServer(t, dns.RcodeSuccess)),
	})
	requireResult(t, "empty answer", obs.Control, classify.DNSOK, nil)
}

type stubResolver struct {
	addrs []netip.Addr
	err   error
}

func (s stubResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return s.addrs, s.err
}

func TestDNSSystemResolverResults(t *testing.T) {
	env := mockdpi.Start(t, mockdpi.Config{Control: true})
	tests := []struct {
		name string
		res  Resolver
		want classify.DNSStatus
		ips  []netip.Addr
	}{
		{"answer", stubResolver{addrs: addrs("::ffff:203.0.113.5")}, classify.DNSOK, addrs("203.0.113.5")},
		{"nxdomain", stubResolver{err: &net.DNSError{IsNotFound: true}}, classify.DNSNXDomain, nil},
		{"timeout", stubResolver{err: &net.DNSError{IsTimeout: true}}, classify.DNSFailure, nil},
		{"other error", stubResolver{err: errors.New("boom")}, classify.DNSFailure, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			obs := runDNS(t, generous, env, DNSRequest{Host: dnsHost, System: tc.res, Control: udp(t, env.ControlDNS)})
			requireResult(t, "system", obs.System, tc.want, tc.ips)
		})
	}
}

func TestDNSDefaultSystemResolver(t *testing.T) {
	env := mockdpi.Start(t, mockdpi.Config{Control: true})
	// "localhost" is answered from the hosts file; this only checks that the
	// default resolver is used when System is nil.
	obs := runDNS(t, generous, env, DNSRequest{Host: "localhost", Control: udp(t, env.ControlDNS)})
	requireResult(t, "system", obs.System, classify.DNSOK, addrs("127.0.0.1"))
}

func TestDNSBlackholedAndUntrustedDoT(t *testing.T) {
	env := mockdpi.Start(t, mockdpi.Config{Blackhole: true, Control: true})

	// The blackhole accepts the TCP connection and never answers the TLS
	// handshake.
	obs := runDNS(t, short, env, DNSRequest{
		Host:    dnsHost,
		System:  resolverVia(env.ControlDNS),
		Control: udp(t, env.ControlDNS),
		Public:  []DNSServer{dot(t, env.Blackhole)},
	})
	requireResult(t, "blackholed DoT", obs.Public[0], classify.DNSFailure, nil)
	requireResult(t, "control is not affected", obs.Control, classify.DNSOK, addrs("127.0.0.1"))

	// Without the mock CA the DoT certificate does not verify.
	req := DNSRequest{Host: dnsHost, System: resolverVia(env.ControlDNS), Control: udp(t, env.ControlDNS), Public: []DNSServer{dot(t, env.ControlDoT)}}
	ctx, cancel := context.WithTimeout(context.Background(), generous)
	defer cancel()
	got, err := DNS(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	requireResult(t, "untrusted DoT", got.Public[0], classify.DNSFailure, nil)
}

func TestDNSRequestValidation(t *testing.T) {
	good := DNSRequest{
		Host:    dnsHost,
		Control: DNSServer{Addr: netip.MustParseAddrPort("127.0.0.1:53"), Transport: DNSTransportUDP},
		Public:  []DNSServer{{Addr: netip.MustParseAddrPort("127.0.0.1:853"), Transport: DNSTransportDoT}},
	}
	tests := map[string]func(r *DNSRequest){
		"empty host":        func(r *DNSRequest) { r.Host = "" },
		"zero control":      func(r *DNSRequest) { r.Control.Addr = netip.AddrPort{} },
		"control no port":   func(r *DNSRequest) { r.Control.Addr = netip.AddrPortFrom(r.Control.Addr.Addr(), 0) },
		"unknown transport": func(r *DNSRequest) { r.Public[0].Transport = "doh" },
	}
	for name, edit := range tests {
		t.Run(name, func(t *testing.T) {
			r := good
			r.Public = append([]DNSServer(nil), good.Public...)
			edit(&r)
			if _, err := DNS(context.Background(), r); err == nil {
				t.Error("want error")
			}
		})
	}
}

func TestDNSCancelledContext(t *testing.T) {
	env := mockdpi.Start(t, mockdpi.Config{Control: true})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := DNS(ctx, DNSRequest{Host: dnsHost, System: resolverVia(env.ControlDNS), Control: udp(t, env.ControlDNS)})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestDNSAddrCheck(t *testing.T) {
	env := mockdpi.Start(t, mockdpi.Config{
		ResetAfterHello: &mockdpi.ResetAfterHelloConfig{BlockedSNI: []string{"blocked.example"}},
		Blackhole:       true,
		Control:         true,
		ClosedPort:      true,
		StubPage:        true,
		CertNames:       []string{dnsHost, "blocked.example"},
	})
	tests := []struct {
		name    string
		target  string
		host    string
		timeout time.Duration
		want    classify.AddrCheck
	}{
		{"valid certificate for the name", env.ControlTLS, dnsHost, generous, classify.AddrCheckValidCert},
		{"certificate is for another name", env.ControlTLS, "intercepted.example", generous, classify.AddrCheckBadCert},
		{"reset after the hello", env.ResetAfterHello, "blocked.example", generous, classify.AddrCheckUnreachable},
		{"silent server", env.Blackhole, dnsHost, short, classify.AddrCheckUnreachable},
		{"nothing listens", env.ClosedPort, dnsHost, generous, classify.AddrCheckUnreachable},
		{"not a TLS server", env.StubPage, dnsHost, generous, classify.AddrCheckUnreachable},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), tc.timeout)
			defer cancel()
			got, err := dnsAddrCheck(ctx, addr(t, tc.target), tc.host, env.CertPool)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("check = %q, want %q", got, tc.want)
			}
		})
	}

	// The exported function uses the system roots, which do not know the mock CA.
	ctx, cancel := context.WithTimeout(context.Background(), generous)
	defer cancel()
	if got, err := DNSAddrCheck(ctx, addr(t, env.ControlTLS), dnsHost); err != nil || got != classify.AddrCheckBadCert {
		t.Errorf("DNSAddrCheck without the mock CA = %q, %v; want bad_cert", got, err)
	}
}

func TestDNSAddrCheckValidationAndCancel(t *testing.T) {
	good := netip.MustParseAddrPort("127.0.0.1:443")
	for name, f := range map[string]func() (classify.AddrCheck, error){
		"zero address": func() (classify.AddrCheck, error) {
			return DNSAddrCheck(context.Background(), netip.AddrPort{}, dnsHost)
		},
		"no port": func() (classify.AddrCheck, error) {
			return DNSAddrCheck(context.Background(), netip.AddrPortFrom(good.Addr(), 0), dnsHost)
		},
		"empty host": func() (classify.AddrCheck, error) { return DNSAddrCheck(context.Background(), good, "") },
	} {
		if got, err := f(); err == nil || got != "" {
			t.Errorf("%s: got %q, %v; want an error", name, got, err)
		}
	}

	env := mockdpi.Start(t, mockdpi.Config{Control: true})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := DNSAddrCheck(ctx, addr(t, env.ControlTLS), dnsHost); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}
