// Package mockdpi starts local servers that imitate network blocking, so the
// classifier and the probes can be tested deterministically without a real
// censor (SPEC section 14).
//
// Scenarios:
//
//   - reset_after_hello: TLS server that reads the ClientHello and, if the SNI
//     is blacklisted, aborts the connection with a TCP RST; other SNIs get a
//     normal handshake.
//   - dns_spoof: UDP DNS server that answers a bogon address for listed names
//     and a normal address for the rest.
//   - blackhole: TCP server that accepts connections and never answers.
//   - stub_page: HTTP server that answers every request with a block page.
//   - control: a clean control node (TLS with any SNI, HTTP echo, DNS over
//     UDP and over TLS).
//   - closed port: a port that refuses connections.
//
// Limitation: dropping a SYN (a connect that hangs without any answer from
// the kernel) cannot be emulated without a firewall. The blackhole scenario
// is only an approximation: the TCP handshake succeeds and the server then
// stays silent, which is good enough to test read and handshake timeouts but
// not connect timeouts.
//
// Everything listens on 127.0.0.1 on random ports. The servers keep no
// client addresses and log nothing.
package mockdpi

import (
	"crypto/x509"
	"net"
	"net/netip"
	"testing"
)

// Config selects the scenarios to start. A nil pointer or false means the
// scenario is not started.
type Config struct {
	ResetAfterHello *ResetAfterHelloConfig
	DNSSpoof        *DNSSpoofConfig
	Blackhole       bool
	StubPage        bool
	Control         bool

	// ClosedPort reserves a loopback TCP port with nothing listening on it:
	// connecting gets an immediate RST, like a RST in answer to a SYN.
	ClosedPort bool

	// CertNames are extra DNS names for the self-signed certificate, so that
	// tests can use a host name like "target.example".
	CertNames []string

	// NormalIP is the address returned by dns_spoof for names that are not
	// spoofed and by the control DNS for every name. Default 127.0.0.1.
	NormalIP netip.Addr
}

// ResetAfterHelloConfig configures the reset_after_hello scenario.
type ResetAfterHelloConfig struct {
	// BlockedSNI lists server names (case-insensitive) to reset.
	BlockedSNI []string
}

// DNSSpoofConfig configures the dns_spoof scenario.
type DNSSpoofConfig struct {
	// Names lists the names (case-insensitive) answered with BogonIP.
	Names []string
	// BogonIP is the spoofed answer. Default 10.0.0.1.
	BogonIP netip.Addr
}

// Env holds the addresses ("127.0.0.1:port") of the started scenarios.
// An address is empty if its scenario was not started.
type Env struct {
	ResetAfterHello string // TCP, TLS
	DNSSpoof        string // UDP
	Blackhole       string // TCP
	StubPage        string // TCP, plain HTTP
	StubPageTLS     string // TCP, HTTPS with the same block page, any SNI
	ControlTLS      string // TCP, HTTPS echo, any SNI
	ControlHTTP     string // TCP, plain HTTP echo
	ControlDNS      string // UDP
	ControlDoT      string // TCP, DNS over TLS, same answers as ControlDNS
	ClosedPort      string // TCP, nothing listens

	// CertPool trusts the self-signed certificate of the TLS scenarios. The
	// certificate is valid for "localhost" and 127.0.0.1 only, so clients that
	// connect with another SNI must skip name verification.
	CertPool *x509.CertPool
}

// Start launches the scenarios from cfg and registers their shutdown with
// t.Cleanup. It fails the test on any setup error.
func Start(t testing.TB, cfg Config) *Env {
	t.Helper()

	normal := cfg.NormalIP
	if !normal.IsValid() {
		normal = netip.MustParseAddr("127.0.0.1")
	}
	if !normal.Is4() {
		t.Fatalf("mockdpi: NormalIP %v is not an IPv4 address", normal)
	}

	cert, pool, err := newCert(cfg.CertNames)
	if err != nil {
		t.Fatalf("mockdpi: create certificate: %v", err)
	}
	env := &Env{CertPool: pool}

	if c := cfg.ResetAfterHello; c != nil {
		env.ResetAfterHello = startResetAfterHello(t, cert, c.BlockedSNI)
	}
	if c := cfg.DNSSpoof; c != nil {
		bogon := c.BogonIP
		if !bogon.IsValid() {
			bogon = netip.MustParseAddr("10.0.0.1")
		}
		if !bogon.Is4() {
			t.Fatalf("mockdpi: BogonIP %v is not an IPv4 address", bogon)
		}
		env.DNSSpoof = startDNS(t, newDNSHandler(c.Names, bogon, normal))
	}
	if cfg.Blackhole {
		env.Blackhole = startBlackhole(t)
	}
	if cfg.StubPage {
		env.StubPage, env.StubPageTLS = startStubPage(t, cert)
	}
	if cfg.Control {
		env.ControlTLS, env.ControlHTTP = startControlHTTP(t, cert)
		env.ControlDNS = startDNS(t, newDNSHandler(nil, netip.Addr{}, normal))
		env.ControlDoT = startDoT(t, newDNSHandler(nil, netip.Addr{}, normal), cert)
	}
	if cfg.ClosedPort {
		env.ClosedPort = reserveClosedPort(t)
	}
	return env
}

func listenAddr(l net.Listener) string { return l.Addr().String() }
