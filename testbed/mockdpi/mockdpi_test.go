package mockdpi

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
)

const ioTimeout = 5 * time.Second

func tlsClientConfig(serverName string) *tls.Config {
	// The certificate only covers localhost, so names are not verified here.
	return &tls.Config{ServerName: serverName, InsecureSkipVerify: true}
}

func tlsHandshake(t *testing.T, addr string, cfg *tls.Config) (*tls.Conn, error) {
	t.Helper()
	raw, err := net.DialTimeout("tcp", addr, ioTimeout)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	_ = raw.SetDeadline(time.Now().Add(ioTimeout))
	c := tls.Client(raw, cfg)
	if err := c.Handshake(); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return c, nil
}

func queryA(t *testing.T, addr, name string) *dns.Msg {
	t.Helper()
	return query(t, addr, name, dns.TypeA)
}

func query(t *testing.T, addr, name string, qtype uint16) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	c := &dns.Client{Net: "udp", Timeout: ioTimeout}
	r, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("dns query %s: %v", name, err)
	}
	return r
}

func answerIPs(t *testing.T, r *dns.Msg) []string {
	t.Helper()
	var ips []string
	for _, rr := range r.Answer {
		a, ok := rr.(*dns.A)
		if !ok {
			t.Fatalf("unexpected record %v", rr)
		}
		ips = append(ips, a.A.String())
	}
	return ips
}

func TestResetAfterHello(t *testing.T) {
	env := Start(t, Config{ResetAfterHello: &ResetAfterHelloConfig{BlockedSNI: []string{"blocked.example", "Other.Example."}}})

	for _, sni := range []string{"blocked.example", "BLOCKED.example", "other.example"} {
		t.Run("blocked/"+sni, func(t *testing.T) {
			c, err := tlsHandshake(t, env.ResetAfterHello, tlsClientConfig(sni))
			if err == nil {
				_ = c.Close()
				t.Fatal("handshake succeeded, want connection reset")
			}
			if !errors.Is(err, syscall.ECONNRESET) {
				t.Errorf("err = %v, want ECONNRESET", err)
			}
		})
	}

	t.Run("allowed SNI", func(t *testing.T) {
		c, err := tlsHandshake(t, env.ResetAfterHello, tlsClientConfig("allowed.example"))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if got := c.ConnectionState().ServerName; got != "allowed.example" {
			t.Errorf("server name = %q", got)
		}
	})

	t.Run("no SNI", func(t *testing.T) {
		c, err := tlsHandshake(t, env.ResetAfterHello, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			t.Fatal(err)
		}
		_ = c.Close()
	})

	t.Run("certificate is self-signed and in CertPool", func(t *testing.T) {
		c, err := tlsHandshake(t, env.ResetAfterHello, &tls.Config{ServerName: "localhost", RootCAs: env.CertPool})
		if err != nil {
			t.Fatal(err)
		}
		_ = c.Close()
		if _, err := tlsHandshake(t, env.ResetAfterHello, &tls.Config{ServerName: "localhost"}); err == nil {
			t.Error("handshake without CertPool succeeded, want unknown authority error")
		}
	})
}

func TestDNSSpoof(t *testing.T) {
	env := Start(t, Config{
		DNSSpoof: &DNSSpoofConfig{Names: []string{"blocked.example", "Mixed.Example."}},
		NormalIP: netip.MustParseAddr("192.0.2.7"),
	})

	tests := []struct {
		name string
		want string
	}{
		{"blocked.example.", "10.0.0.1"},
		{"BLOCKED.example.", "10.0.0.1"},
		{"mixed.example.", "10.0.0.1"},
		{"fine.example.", "192.0.2.7"},
		{"sub.blocked.example.", "192.0.2.7"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := queryA(t, env.DNSSpoof, tc.name)
			if r.Rcode != dns.RcodeSuccess {
				t.Fatalf("rcode = %d", r.Rcode)
			}
			if got := answerIPs(t, r); len(got) != 1 || got[0] != tc.want {
				t.Errorf("answer = %v, want [%s]", got, tc.want)
			}
		})
	}

	t.Run("AAAA gets empty answer", func(t *testing.T) {
		r := query(t, env.DNSSpoof, "blocked.example.", dns.TypeAAAA)
		if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 0 {
			t.Errorf("rcode = %d, answers = %v", r.Rcode, r.Answer)
		}
	})
}

func TestDNSSpoofCustomBogon(t *testing.T) {
	env := Start(t, Config{DNSSpoof: &DNSSpoofConfig{Names: []string{"a.example"}, BogonIP: netip.MustParseAddr("192.168.1.1")}})
	if got := answerIPs(t, queryA(t, env.DNSSpoof, "a.example.")); len(got) != 1 || got[0] != "192.168.1.1" {
		t.Errorf("answer = %v", got)
	}
	if got := answerIPs(t, queryA(t, env.DNSSpoof, "b.example.")); len(got) != 1 || got[0] != "127.0.0.1" {
		t.Errorf("default normal IP: answer = %v", got)
	}
}

func TestDNSMalformedQueries(t *testing.T) {
	env := Start(t, Config{DNSSpoof: &DNSSpoofConfig{}})
	c := &dns.Client{Net: "udp", Timeout: ioTimeout}

	m := new(dns.Msg)
	m.SetQuestion("a.example.", dns.TypeA)
	m.Question = append(m.Question, dns.Question{Name: "b.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
	r, _, err := c.Exchange(m, env.DNSSpoof)
	if err != nil {
		t.Fatal(err)
	}
	if r.Rcode != dns.RcodeFormatError {
		t.Errorf("two questions: rcode = %d, want FORMERR", r.Rcode)
	}

	m = new(dns.Msg)
	m.SetQuestion("a.example.", dns.TypeA)
	m.Opcode = dns.OpcodeStatus
	r, _, err = c.Exchange(m, env.DNSSpoof)
	if err != nil {
		t.Fatal(err)
	}
	if r.Rcode != dns.RcodeNotImplemented {
		t.Errorf("status opcode: rcode = %d, want NOTIMP", r.Rcode)
	}
}

func TestBlackhole(t *testing.T) {
	env := Start(t, Config{Blackhole: true})
	c, err := net.DialTimeout("tcp", env.Blackhole, ioTimeout)
	if err != nil {
		t.Fatalf("connect must succeed: %v", err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	n, err := c.Read(make([]byte, 16))
	var ne net.Error
	if n != 0 || !errors.As(err, &ne) || !ne.Timeout() {
		t.Errorf("read = %d bytes, err = %v; want timeout with no data", n, err)
	}

	// A TLS client gets no ServerHello either.
	raw, err := net.DialTimeout("tcp", env.Blackhole, ioTimeout)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(200 * time.Millisecond))
	err = tls.Client(raw, tlsClientConfig("x.example")).Handshake()
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Errorf("handshake err = %v, want timeout", err)
	}
}

func TestStubPage(t *testing.T) {
	env := Start(t, Config{StubPage: true})
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/"},
		{http.MethodGet, "/some/other/path?x=1"},
		{http.MethodPost, "/submit"},
	} {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			req, err := http.NewRequest(tc.method, "http://"+env.StubPage+tc.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Host = "blocked.example"
			body, status := do(t, http.DefaultClient, req)
			if status != http.StatusOK {
				t.Errorf("status = %d", status)
			}
			if !strings.Contains(body, "Доступ ограничен") || !strings.Contains(body, StubBody) {
				t.Errorf("body = %q", body)
			}
		})
	}
}

func do(t *testing.T, c *http.Client, req *http.Request) (string, int) {
	t.Helper()
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b), resp.StatusCode
}

func TestControl(t *testing.T) {
	env := Start(t, Config{Control: true, NormalIP: netip.MustParseAddr("192.0.2.9")})

	t.Run("TLS with any SNI", func(t *testing.T) {
		for _, sni := range []string{"blocked.example", "anything.test", "localhost", ""} {
			c, err := tlsHandshake(t, env.ControlTLS, tlsClientConfig(sni))
			if err != nil {
				t.Errorf("sni %q: %v", sni, err)
				continue
			}
			_ = c.Close()
		}
	})

	t.Run("HTTP echo", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "http://"+env.ControlHTTP+"/echo/path?q=1", nil)
		req.Host = "target.example"
		body, status := do(t, http.DefaultClient, req)
		if status != http.StatusOK {
			t.Fatalf("status = %d", status)
		}
		var got echoReply
		if err := json.Unmarshal([]byte(body), &got); err != nil {
			t.Fatal(err)
		}
		want := echoReply{Method: "GET", Path: "/echo/path", Host: "target.example"}
		if got != want {
			t.Errorf("echo = %+v, want %+v", got, want)
		}
	})

	t.Run("HTTPS echo reports SNI", func(t *testing.T) {
		client := &http.Client{Transport: &http.Transport{
			TLSClientConfig:   tlsClientConfig("blocked.example"),
			DisableKeepAlives: true,
		}}
		req, _ := http.NewRequest(http.MethodGet, "https://"+env.ControlTLS+"/x", nil)
		body, status := do(t, client, req)
		if status != http.StatusOK {
			t.Fatalf("status = %d", status)
		}
		var got echoReply
		if err := json.Unmarshal([]byte(body), &got); err != nil {
			t.Fatal(err)
		}
		if got.SNI != "blocked.example" || got.Path != "/x" {
			t.Errorf("echo = %+v", got)
		}
	})

	t.Run("DNS answers normally", func(t *testing.T) {
		for _, name := range []string{"blocked.example.", "anything.test."} {
			if got := answerIPs(t, queryA(t, env.ControlDNS, name)); len(got) != 1 || got[0] != "192.0.2.9" {
				t.Errorf("%s: answer = %v", name, got)
			}
		}
	})
}

func TestEmptyConfigStartsNothing(t *testing.T) {
	env := Start(t, Config{})
	got := *env
	got.CertPool = nil
	if got != (Env{}) {
		t.Errorf("env = %+v, want only CertPool set", got)
	}
	if env.CertPool == nil {
		t.Error("CertPool is nil")
	}
}

func TestAllScenariosTogether(t *testing.T) {
	env := Start(t, Config{
		ResetAfterHello: &ResetAfterHelloConfig{BlockedSNI: []string{"b.example"}},
		DNSSpoof:        &DNSSpoofConfig{Names: []string{"b.example"}},
		Blackhole:       true,
		StubPage:        true,
		Control:         true,
	})
	addrs := []string{env.ResetAfterHello, env.DNSSpoof, env.Blackhole, env.StubPage, env.ControlTLS, env.ControlHTTP, env.ControlDNS}
	seen := map[string]bool{}
	for _, a := range addrs {
		host, _, err := net.SplitHostPort(a)
		if err != nil || host != "127.0.0.1" {
			t.Errorf("address %q: want 127.0.0.1:port", a)
		}
		if seen[a] {
			t.Errorf("duplicate address %q", a)
		}
		seen[a] = true
	}
}

// Cleanup must close servers and the connections they hold.
func TestCleanupClosesConnections(t *testing.T) {
	var conn net.Conn
	t.Run("scenario", func(t *testing.T) {
		env := Start(t, Config{Blackhole: true})
		c, err := net.DialTimeout("tcp", env.Blackhole, ioTimeout)
		if err != nil {
			t.Fatal(err)
		}
		conn = c
		// Make sure the server has accepted the connection before cleanup.
		if _, err := c.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
	})
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(ioTimeout))
	_, err := conn.Read(make([]byte, 1))
	var ne net.Error
	if err == nil || (errors.As(err, &ne) && ne.Timeout()) {
		t.Errorf("read after cleanup: err = %v, want EOF or reset", err)
	}
}

// failTB turns Fatalf into a recorded message and stops the goroutine, as the
// real testing.T does.
type failTB struct {
	testing.TB
	msg string
}

func (f *failTB) Fatalf(format string, args ...any) {
	f.msg = format
	runtime.Goexit()
}

func TestStartRejectsBadIPs(t *testing.T) {
	v6 := netip.MustParseAddr("::1")
	tests := []struct {
		name string
		cfg  Config
	}{
		{"NormalIP v6", Config{NormalIP: v6}},
		{"BogonIP v6", Config{DNSSpoof: &DNSSpoofConfig{BogonIP: v6}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := &failTB{TB: t}
			done := make(chan struct{})
			go func() {
				defer close(done)
				Start(f, tc.cfg)
			}()
			<-done
			if f.msg == "" {
				t.Error("Start did not fail")
			}
		})
	}
}

// net/http logs "TLS handshake error from <client addr>" unless its ErrorLog
// is silenced. Client addresses must not reach any log (AGENTS.md).
func TestServersDoNotLogClientAddresses(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	env := Start(t, Config{Control: true, StubPage: true})

	// A handshake the server rejects: the client does not trust the certificate.
	raw, err := net.DialTimeout("tcp", env.ControlTLS, ioTimeout)
	if err != nil {
		t.Fatal(err)
	}
	_ = raw.SetDeadline(time.Now().Add(ioTimeout))
	if err := tls.Client(raw, &tls.Config{ServerName: "localhost"}).Handshake(); err == nil {
		t.Fatal("handshake must fail without the CertPool")
	}
	_ = raw.Close()

	// Plain HTTP spoken to the TLS port, and TLS spoken to the plain port.
	for _, addr := range []string{env.ControlTLS, env.StubPage} {
		c, err := net.DialTimeout("tcp", addr, ioTimeout)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = c.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n\x00\x01garbage\r\n\r\n"))
		_ = c.SetReadDeadline(time.Now().Add(ioTimeout))
		_, _ = io.Copy(io.Discard, c)
		_ = c.Close()
	}

	if strings.Contains(buf.String(), "127.0.0.1") {
		t.Errorf("server log contains a client address: %q", buf.String())
	}
}
