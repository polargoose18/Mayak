package probe

import (
	"context"
	"net/netip"
	"testing"

	"github.com/polargoose18/mayak/internal/classify"
	"github.com/polargoose18/mayak/internal/report"
	"github.com/polargoose18/mayak/testbed/mockdpi"
)

// observationWith is a run in which everything is fine except the TLS part,
// which comes from the probe.
func observationWith(tls classify.TLS) classify.Observation {
	ips := []netip.Addr{netip.MustParseAddr("203.0.113.10")}
	page := classify.HTTPResponse{Status: 200, Size: 1000, BodyHash: "page"}
	return classify.Observation{
		Ctrl: classify.Ctrl{ControlAlive: true, AnchorsAlive: true, TargetExternal: classify.ExternalReachable},
		DNS: classify.DNS{
			System:  classify.DNSAnswer{Status: classify.DNSOK, Addrs: ips},
			Control: classify.DNSAnswer{Status: classify.DNSOK, Addrs: ips},
		},
		TCP:  classify.TCPOK,
		TLS:  tls,
		HTTP: classify.HTTP{Result: classify.HTTPResponded, Response: page, Reference: &page},
	}
}

// The probe's result goes into the classifier. The censor is on the path of
// the user's traffic, so for the "sni_block" case the control address is the
// censor too: it resets the target SNI whatever the destination IP is. A
// control node outside the censor is the next test.
func TestProbeToClassify(t *testing.T) {
	tests := []struct {
		name   string
		config mockdpi.Config
		// pick returns the target and control addresses.
		pick func(env *mockdpi.Env) (target, control string)
		want report.Verdict
	}{
		{
			name: "reset_after_hello on the path of both",
			config: mockdpi.Config{
				ResetAfterHello: &mockdpi.ResetAfterHelloConfig{BlockedSNI: []string{targetHost}},
			},
			pick: func(e *mockdpi.Env) (string, string) { return e.ResetAfterHello, e.ResetAfterHello },
			want: report.VerdictSNIBlock,
		},
		{
			name: "nothing blocked",
			config: mockdpi.Config{
				ResetAfterHello: &mockdpi.ResetAfterHelloConfig{BlockedSNI: []string{"other.example"}},
				Control:         true,
			},
			pick: func(e *mockdpi.Env) (string, string) { return e.ResetAfterHello, e.ControlTLS },
			want: report.VerdictOK,
		},
		{
			name:   "blackhole target, clean control node",
			config: mockdpi.Config{Blackhole: true, Control: true},
			pick:   func(e *mockdpi.Env) (string, string) { return e.Blackhole, e.ControlTLS },
			want:   report.VerdictTimeoutUnknown,
		},
		{
			// The clean control node accepts the target SNI, so the filter is
			// not about the SNI alone: the classifier does not claim sni_block.
			name: "reset only towards the target IP",
			config: mockdpi.Config{
				ResetAfterHello: &mockdpi.ResetAfterHelloConfig{BlockedSNI: []string{targetHost}},
				Control:         true,
			},
			pick: func(e *mockdpi.Env) (string, string) { return e.ResetAfterHello, e.ControlTLS },
			want: report.VerdictInconclusive,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := mockdpi.Start(t, tc.config)
			target, control := tc.pick(env)
			timeout := generous
			if tc.config.Blackhole {
				timeout = short
			}
			obs := run(t, timeout, env, request(t, target, control))

			got := classify.Classify(observationWith(obs.Handshakes()))
			if got != tc.want {
				t.Errorf("Classify = %q, want %q (handshakes: %+v)", got, tc.want, obs)
			}
		})
	}
}

// pipeline runs every probe against the mock servers, the way the agent will,
// and hands the result to the classifier.
type pipeline struct {
	config mockdpi.Config
	host   string

	// Where each part of the run goes. They differ per scenario.
	systemDNS  func(e *mockdpi.Env) string // mock DNS used as the system resolver
	target     func(e *mockdpi.Env) string // the target's IP and port
	tlsControl func(e *mockdpi.Env) string // control IP for the third handshake
	controlURL func(e *mockdpi.Env, f *fakeControl) string
	reachable  bool // what the control node says about the target
	ctrlShort  bool // the control node is silent, so use a short deadline

	// addrCheck, if set, is the server that answers the TLS check of the
	// address in the system answer.
	addrCheck func(e *mockdpi.Env) string
	allowlist func(e *mockdpi.Env) []string
}

func (p pipeline) run(t *testing.T) classify.Observation {
	t.Helper()
	cfg := p.config
	cfg.Control, cfg.CertNames = true, []string{dnsHost}
	env := mockdpi.Start(t, cfg)
	host := p.host
	if host == "" {
		host = dnsHost
	}
	target := addr(t, p.target(env))
	ctx := func() (context.Context, context.CancelFunc) {
		return context.WithTimeout(context.Background(), generous)
	}

	// The control node fetches the real page from the clean server.
	ctrl := newFakeControl(t, p.reachable)
	ctrl.fetchFrom, ctrl.roots = addr(t, env.ControlTLS), env.CertPool

	var o classify.Observation

	c, cancel := ctx()
	defer cancel()
	d, err := DNS(c, DNSRequest{
		Host:    host,
		System:  resolverVia(p.systemDNS(env)),
		Control: udp(t, env.ControlDNS),
		Public:  []DNSServer{dot(t, env.ControlDoT)},
		roots:   env.CertPool,
	})
	if err != nil {
		t.Fatal(err)
	}
	o.DNS = d.ForClassifier()
	if p.addrCheck != nil {
		check, err := dnsAddrCheck(c, addr(t, p.addrCheck(env)), host, env.CertPool)
		if err != nil {
			t.Fatal(err)
		}
		o.DNS.SystemAddrCheck = check
	}

	tcp, err := TCP(c, TCPRequest{Addr: target})
	if err != nil {
		t.Fatal(err)
	}
	o.TCP = tcp.ForClassifier()

	tlsObs, err := tlsSNI(c, TLSSNIRequest{
		TargetAddr: target, ControlAddr: addr(t, p.tlsControl(env)), Host: host, NeutralSNI: neutralSNI,
	}, env.CertPool)
	if err != nil {
		t.Fatal(err)
	}
	o.TLS = tlsObs.Handshakes()

	stubs := learnStubHashes(t, env)
	h, err := HTTP(c, HTTPRequest{Addr: target, Host: host, Path: "/page", KnownStubHashes: stubs, roots: env.CertPool})
	if err != nil {
		t.Fatal(err)
	}
	// Without a reference (the node could not fetch the page either) the
	// classifier works with what it has.
	ref, _ := ControlClient{BaseURL: ctrl.srv.URL}.Reference(c, host, "/page")
	o.HTTP = h.ForClassifier(ref)

	ctrlCtx := c
	if p.ctrlShort {
		var cancelShort context.CancelFunc
		ctrlCtx, cancelShort = context.WithTimeout(context.Background(), short)
		defer cancelShort()
	}
	var allow []string
	if p.allowlist != nil {
		allow = p.allowlist(env)
	}
	cr, err := Ctrl(ctrlCtx, CtrlRequest{
		Control:   ControlClient{BaseURL: p.controlURL(env, ctrl), roots: env.CertPool},
		Anchors:   []string{p.anchor(env)},
		Allowlist: allow,
		Host:      host,
		roots:     env.CertPool,
	})
	if err != nil {
		t.Fatal(err)
	}
	o.Ctrl = cr.ForClassifier()
	return o
}

func (p pipeline) anchor(e *mockdpi.Env) string {
	if p.ctrlShort {
		return "http://" + e.Blackhole
	}
	return anchorURL(e)
}

// learnStubHashes returns the hash of the block page, as if it were in the
// curated list of known operator stubs.
func learnStubHashes(t *testing.T, env *mockdpi.Env) []string {
	t.Helper()
	if env.StubPageTLS == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), generous)
	defer cancel()
	obs, err := HTTP(ctx, HTTPRequest{Addr: addr(t, env.StubPageTLS), Host: dnsHost, Path: "/page", roots: env.CertPool})
	if err != nil {
		t.Fatal(err)
	}
	return []string{obs.Response.BodyHash}
}

func TestPipelineVerdicts(t *testing.T) {
	clean := func(e *mockdpi.Env) string { return e.ControlDNS }
	controlTLS := func(e *mockdpi.Env) string { return e.ControlTLS }
	fake := func(_ *mockdpi.Env, f *fakeControl) string { return f.srv.URL }

	base := pipeline{
		systemDNS: clean, target: controlTLS, tlsControl: controlTLS, controlURL: fake, reachable: true,
	}
	with := func(edit func(p *pipeline)) pipeline {
		p := base
		edit(&p)
		return p
	}

	tests := []struct {
		name string
		p    pipeline
		want report.Verdict
	}{
		{"nothing is blocked", base, report.VerdictOK},
		{"system resolver lies", with(func(p *pipeline) {
			p.config.DNSSpoof = &mockdpi.DNSSpoofConfig{Names: []string{dnsHost}}
			p.systemDNS = func(e *mockdpi.Env) string { return e.DNSSpoof }
		}), report.VerdictDNSTamper},
		{"CDN: the system resolver gives another genuine address", with(func(p *pipeline) {
			p.config.DNSSpoof = &mockdpi.DNSSpoofConfig{Names: []string{dnsHost}, BogonIP: netip.MustParseAddr("203.0.113.7")}
			p.systemDNS = func(e *mockdpi.Env) string { return e.DNSSpoof }
			p.addrCheck = controlTLS
		}), report.VerdictOK},
		{"the other address presents a certificate for another name", with(func(p *pipeline) {
			p.host = "intercepted.example"
			p.config.DNSSpoof = &mockdpi.DNSSpoofConfig{Names: []string{"intercepted.example"}, BogonIP: netip.MustParseAddr("203.0.113.7")}
			p.systemDNS = func(e *mockdpi.Env) string { return e.DNSSpoof }
			p.addrCheck = controlTLS
		}), report.VerdictDNSTamper},
		{"the other address cannot be checked", with(func(p *pipeline) {
			p.config.ClosedPort = true
			p.config.DNSSpoof = &mockdpi.DNSSpoofConfig{Names: []string{dnsHost}, BogonIP: netip.MustParseAddr("203.0.113.7")}
			p.systemDNS = func(e *mockdpi.Env) string { return e.DNSSpoof }
			p.addrCheck = func(e *mockdpi.Env) string { return e.ClosedPort }
		}), report.VerdictInconclusive},
		{"the other address is not checked at all", with(func(p *pipeline) {
			p.config.DNSSpoof = &mockdpi.DNSSpoofConfig{Names: []string{dnsHost}, BogonIP: netip.MustParseAddr("203.0.113.7")}
			p.systemDNS = func(e *mockdpi.Env) string { return e.DNSSpoof }
		}), report.VerdictInconclusive},
		{"RST in answer to SYN, target up outside", with(func(p *pipeline) {
			p.config.ClosedPort = true
			p.target = func(e *mockdpi.Env) string { return e.ClosedPort }
		}), report.VerdictIPBlock},
		{"RST in answer to SYN, target down outside too", with(func(p *pipeline) {
			p.config.ClosedPort = true
			p.target = func(e *mockdpi.Env) string { return e.ClosedPort }
			p.reachable = false
		}), report.VerdictVendorDown},
		{"SNI reset on the path", with(func(p *pipeline) {
			p.config.ResetAfterHello = &mockdpi.ResetAfterHelloConfig{BlockedSNI: []string{dnsHost}}
			p.target = func(e *mockdpi.Env) string { return e.ResetAfterHello }
			p.tlsControl = func(e *mockdpi.Env) string { return e.ResetAfterHello }
		}), report.VerdictSNIBlock},
		{"certificate is not for the target", with(func(p *pipeline) {
			p.host = "intercepted.example"
		}), report.VerdictTLSIntercept},
		{"block page behind a good handshake", with(func(p *pipeline) {
			p.config.StubPage = true
			p.target = func(e *mockdpi.Env) string { return e.StubPageTLS }
		}), report.VerdictHTTPStub},
		{"control node and anchors silent, allowlist up", with(func(p *pipeline) {
			p.config.Blackhole = true
			p.ctrlShort = true
			p.controlURL = func(e *mockdpi.Env, _ *fakeControl) string { return "http://" + e.Blackhole }
			p.allowlist = func(e *mockdpi.Env) []string { return []string{anchorURL(e)} }
		}), report.VerdictAllowlistMode},
		{"control node silent", with(func(p *pipeline) {
			p.config.Blackhole = true
			p.ctrlShort = true
			p.controlURL = func(e *mockdpi.Env, _ *fakeControl) string { return "http://" + e.Blackhole }
		}), report.VerdictInconclusive},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			o := tc.p.run(t)
			if got := classify.Classify(o); got != tc.want {
				t.Errorf("Classify = %q, want %q\nobservation: %+v", got, tc.want, o)
			}
		})
	}
}
