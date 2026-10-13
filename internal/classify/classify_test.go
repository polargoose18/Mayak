package classify

import (
	"net/netip"
	"testing"

	"github.com/polargoose18/mayak/internal/report"
)

func ips(s ...string) []netip.Addr {
	out := make([]netip.Addr, len(s))
	for i, v := range s {
		out[i] = netip.MustParseAddr(v)
	}
	return out
}

func answer(s ...string) DNSAnswer { return DNSAnswer{Status: DNSOK, Addrs: ips(s...)} }

// healthy is a run in which nothing is blocked. Every case below changes it.
func healthy() Observation {
	ref := HTTPResponse{Status: 200, Size: 1000, BodyHash: "page"}
	return Observation{
		Ctrl: Ctrl{ControlAlive: true, AnchorsAlive: true, TargetExternal: ExternalReachable},
		DNS: DNS{
			System:  answer("203.0.113.10"),
			Control: answer("203.0.113.10"),
			Public:  []DNSAnswer{answer("203.0.113.10"), answer("203.0.113.10")},
		},
		TCP: TCPOK,
		TLS: TLS{TargetSNI: HandshakeOK, NeutralSNI: HandshakeOK, TargetSNIViaControl: HandshakeOK},
		HTTP: HTTP{
			Result:    HTTPResponded,
			Response:  ref,
			Reference: &ref,
		},
		QUIC: QUIC{Local: QUICOK, Control: QUICOK},
	}
}

// tcpFails makes the TCP connect fail. The tests that need a connection do
// not run after that, as in a real run.
func tcpFails(o *Observation, r TCPResult) {
	o.TCP = r
	o.TLS, o.HTTP, o.QUIC = TLS{}, HTTP{}, QUIC{}
}

func TestClassify(t *testing.T) {
	stub := HTTPResponse{Status: 200, Size: 300, BodyHash: "stub"}

	tests := []struct {
		name   string
		mutate func(o *Observation)
		want   report.Verdict
	}{
		// ok
		{"all tests passed", func(o *Observation) {}, report.VerdictOK},
		{"dynamic page differs in body but status matches", func(o *Observation) {
			o.HTTP.Response = HTTPResponse{Status: 200, Size: 1234, BodyHash: "other-day"}
		}, report.VerdictOK},
		{"vendor refuses cloud IPs the same way for both", func(o *Observation) {
			r := HTTPResponse{Status: 403, Size: 10, BodyHash: "x"}
			o.HTTP.Response, o.HTTP.Reference = r, &r
		}, report.VerdictOK},
		{"no external check and no reference, 200", func(o *Observation) {
			o.Ctrl.TargetExternal = ""
			o.HTTP.Reference = nil
		}, report.VerdictOK},
		{"neutral and control handshakes not run", func(o *Observation) {
			o.TLS.NeutralSNI, o.TLS.TargetSNIViaControl = "", ""
		}, report.VerdictOK},
		{"no QUIC reference: target may lack HTTP/3", func(o *Observation) {
			o.QUIC = QUIC{Local: QUICTimeout, Control: QUICTimeout}
		}, report.VerdictOK},
		{"QUIC not run", func(o *Observation) { o.QUIC = QUIC{} }, report.VerdictOK},
		{"IPv4-mapped system answer equals trusted one", func(o *Observation) {
			o.DNS.System = answer("::ffff:203.0.113.10")
		}, report.VerdictOK},
		{"system resolver shares one address with trusted (CDN)", func(o *Observation) {
			o.DNS.System = answer("203.0.113.10", "203.0.113.99")
		}, report.VerdictOK},
		{"stub flag but body equals the reference", func(o *Observation) {
			o.HTTP.MatchesKnownStub = true
		}, report.VerdictOK},
		{"control says vendor is down but the agent got a full answer", func(o *Observation) {
			o.Ctrl.TargetExternal = ExternalUnreachable
		}, report.VerdictOK},
		{"cert_invalid on the neutral handshake does not matter", func(o *Observation) {
			o.TLS.NeutralSNI = HandshakeCertInvalid
		}, report.VerdictOK},

		// dns_tamper
		{"system answer is private", func(o *Observation) { o.DNS.System = answer("10.0.0.1") }, report.VerdictDNSTamper},
		{"system answer is loopback", func(o *Observation) { o.DNS.System = answer("127.0.0.1") }, report.VerdictDNSTamper},
		{"system answer is CGNAT", func(o *Observation) { o.DNS.System = answer("100.64.1.1") }, report.VerdictDNSTamper},
		{"system answer is disjoint from trusted", func(o *Observation) {
			o.DNS.System = answer("198.51.100.7")
		}, report.VerdictDNSTamper},
		{"system NXDOMAIN, others answer", func(o *Observation) {
			o.DNS.System = DNSAnswer{Status: DNSNXDomain}
		}, report.VerdictDNSTamper},
		{"bogon even when trusted resolvers are down", func(o *Observation) {
			o.DNS.Control, o.DNS.Public = DNSAnswer{Status: DNSFailure}, nil
			o.DNS.System = answer("10.0.0.1")
		}, report.VerdictDNSTamper},
		{"dns tamper wins over a later tcp block", func(o *Observation) {
			o.DNS.System = answer("10.0.0.1")
			tcpFails(o, TCPTimeout)
		}, report.VerdictDNSTamper},

		// ip_block
		{"tcp timeout with live ctrl", func(o *Observation) { tcpFails(o, TCPTimeout) }, report.VerdictIPBlock},
		{"tcp reset on connect", func(o *Observation) { tcpFails(o, TCPReset) }, report.VerdictIPBlock},
		{"tcp timeout, external check did not run", func(o *Observation) {
			tcpFails(o, TCPTimeout)
			o.Ctrl.TargetExternal = ""
		}, report.VerdictIPBlock},

		// sni_block
		{"reset after hello, same SNI also fails to control IP", func(o *Observation) {
			o.TLS = TLS{TargetSNI: HandshakeResetAfterHello, NeutralSNI: HandshakeOK, TargetSNIViaControl: HandshakeResetAfterHello}
		}, report.VerdictSNIBlock},
		{"silent drop after hello, control IP also fails", func(o *Observation) {
			o.TLS = TLS{TargetSNI: HandshakeTimeout, NeutralSNI: HandshakeTimeout, TargetSNIViaControl: HandshakeTimeout}
		}, report.VerdictSNIBlock},
		{"rule 4: control IP not tested, neutral SNI passes", func(o *Observation) {
			o.TLS = TLS{TargetSNI: HandshakeResetAfterHello, NeutralSNI: HandshakeOK}
		}, report.VerdictSNIBlock},
		{"rule 4: neutral SNI gets another cert but handshake completes", func(o *Observation) {
			o.TLS = TLS{TargetSNI: HandshakeResetAfterHello, NeutralSNI: HandshakeCertInvalid}
		}, report.VerdictSNIBlock},

		// tls_intercept
		{"certificate invalid for the target", func(o *Observation) {
			o.TLS.TargetSNI = HandshakeCertInvalid
		}, report.VerdictTLSIntercept},
		{"certificate invalid while the neutral handshake passes", func(o *Observation) {
			o.TLS = TLS{TargetSNI: HandshakeCertInvalid, NeutralSNI: HandshakeOK, TargetSNIViaControl: HandshakeOK}
		}, report.VerdictTLSIntercept},

		// http_stub
		{"known stub with status 200", func(o *Observation) {
			o.HTTP.Response, o.HTTP.MatchesKnownStub = stub, true
		}, report.VerdictHTTPStub},
		{"known stub served with 451", func(o *Observation) {
			o.HTTP.Response, o.HTTP.MatchesKnownStub = HTTPResponse{Status: 451, Size: 300, BodyHash: "stub"}, true
		}, report.VerdictHTTPStub},
		{"known stub without a reference", func(o *Observation) {
			o.HTTP.Response, o.HTTP.MatchesKnownStub, o.HTTP.Reference = stub, true, nil
		}, report.VerdictHTTPStub},
		{"known stub with sizes only", func(o *Observation) {
			o.HTTP.Response = HTTPResponse{Status: 200, Size: 300}
			o.HTTP.Reference = &HTTPResponse{Status: 200, Size: 1000}
			o.HTTP.MatchesKnownStub = true
		}, report.VerdictHTTPStub},

		// quic_block
		{"quic times out, control node succeeds", func(o *Observation) {
			o.QUIC = QUIC{Local: QUICTimeout, Control: QUICOK}
		}, report.VerdictQUICBlock},
		{"quic errors, control node succeeds", func(o *Observation) {
			o.QUIC = QUIC{Local: QUICError, Control: QUICOK}
		}, report.VerdictQUICBlock},

		// vendor_geoblock
		{"403 from the vendor, reference is 200", func(o *Observation) {
			o.HTTP.Response = HTTPResponse{Status: 403, Size: 50, BodyHash: "vendor-403"}
		}, report.VerdictVendorGeoblock},
		{"451 from the vendor, not a known stub", func(o *Observation) {
			o.HTTP.Response = HTTPResponse{Status: 451, Size: 50, BodyHash: "vendor-451"}
		}, report.VerdictVendorGeoblock},

		// vendor_down
		{"tcp timeout and unreachable from outside", func(o *Observation) {
			tcpFails(o, TCPTimeout)
			o.Ctrl.TargetExternal = ExternalUnreachable
		}, report.VerdictVendorDown},
		{"tls fails and unreachable from outside", func(o *Observation) {
			o.TLS.TargetSNI = HandshakeTimeout
			o.Ctrl.TargetExternal = ExternalUnreachable
		}, report.VerdictVendorDown},
		{"http times out and unreachable from outside", func(o *Observation) {
			o.HTTP = HTTP{Result: HTTPTimeout}
			o.Ctrl.TargetExternal = ExternalUnreachable
		}, report.VerdictVendorDown},
		{"http reset and unreachable from outside", func(o *Observation) {
			o.HTTP = HTTP{Result: HTTPReset}
			o.Ctrl.TargetExternal = ExternalUnreachable
		}, report.VerdictVendorDown},

		// allowlist_mode
		{"control and anchors down, allowlist up", func(o *Observation) {
			o.Ctrl = Ctrl{AllowlistAlive: true}
		}, report.VerdictAllowlistMode},
		{"allowlist mode regardless of other observations", func(o *Observation) {
			o.Ctrl = Ctrl{AllowlistAlive: true}
			tcpFails(o, TCPTimeout)
		}, report.VerdictAllowlistMode},

		// timeout_unknown
		{"target handshake times out, control IP accepts the SNI", func(o *Observation) {
			o.TLS = TLS{TargetSNI: HandshakeTimeout, NeutralSNI: HandshakeTimeout, TargetSNIViaControl: HandshakeOK}
		}, report.VerdictTimeoutUnknown},
		{"target handshake times out, nothing else tested", func(o *Observation) {
			o.TLS = TLS{TargetSNI: HandshakeTimeout}
		}, report.VerdictTimeoutUnknown},
		{"http times out after a good handshake", func(o *Observation) {
			o.HTTP = HTTP{Result: HTTPTimeout}
		}, report.VerdictTimeoutUnknown},
		{"system resolver fails, the rest is fine", func(o *Observation) {
			o.DNS.System = DNSAnswer{Status: DNSFailure}
		}, report.VerdictTimeoutUnknown},

		// inconclusive: ctrl
		{"nothing observed", func(o *Observation) { *o = Observation{} }, report.VerdictInconclusive},
		{"control node down", func(o *Observation) { o.Ctrl.ControlAlive = false }, report.VerdictInconclusive},
		{"anchors down", func(o *Observation) { o.Ctrl.AnchorsAlive = false }, report.VerdictInconclusive},
		{"ctrl failed and allowlist down too", func(o *Observation) {
			o.Ctrl = Ctrl{}
		}, report.VerdictInconclusive},
		{"only the control node is down, allowlist up", func(o *Observation) {
			o.Ctrl = Ctrl{AnchorsAlive: true, AllowlistAlive: true}
		}, report.VerdictInconclusive},
		{"ctrl failed although every block would otherwise be seen", func(o *Observation) {
			o.Ctrl = Ctrl{}
			tcpFails(o, TCPTimeout)
			o.DNS.System = answer("10.0.0.1")
		}, report.VerdictInconclusive},

		// inconclusive: contradictions and missing data
		{"tcp timeout but the handshake completed", func(o *Observation) { o.TCP = TCPTimeout }, report.VerdictInconclusive},
		{"tcp reset but the certificate was seen", func(o *Observation) {
			o.TCP = TCPReset
			o.TLS.TargetSNI = HandshakeCertInvalid
		}, report.VerdictInconclusive},
		{"SNI fails to target IP but passes to control IP, neutral passes", func(o *Observation) {
			o.TLS = TLS{TargetSNI: HandshakeResetAfterHello, NeutralSNI: HandshakeOK, TargetSNIViaControl: HandshakeOK}
		}, report.VerdictInconclusive},
		{"reset after hello with nothing to explain it", func(o *Observation) {
			o.TLS = TLS{TargetSNI: HandshakeResetAfterHello}
		}, report.VerdictInconclusive},
		{"reset after hello, neutral SNI also fails", func(o *Observation) {
			o.TLS = TLS{TargetSNI: HandshakeResetAfterHello, NeutralSNI: HandshakeResetAfterHello}
		}, report.VerdictInconclusive},
		{"no trusted DNS answer", func(o *Observation) {
			o.DNS.Control, o.DNS.Public = DNSAnswer{Status: DNSFailure}, []DNSAnswer{{Status: DNSNXDomain}}
		}, report.VerdictInconclusive},
		{"DNS not run at all", func(o *Observation) { o.DNS = DNS{} }, report.VerdictInconclusive},
		{"tcp not run", func(o *Observation) { o.TCP = "" }, report.VerdictInconclusive},
		{"tcp fails for another reason", func(o *Observation) { tcpFails(o, TCPOther) }, report.VerdictInconclusive},
		{"http fails for another reason", func(o *Observation) { o.HTTP = HTTP{Result: HTTPOther} }, report.VerdictInconclusive},
		{"unknown tcp value", func(o *Observation) { o.TCP = "weird" }, report.VerdictInconclusive},
		{"tls not run", func(o *Observation) { o.TLS = TLS{} }, report.VerdictInconclusive},
		{"target handshake fails for another reason", func(o *Observation) {
			o.TLS.TargetSNI = HandshakeOther
		}, report.VerdictInconclusive},
		{"other on the neutral and control handshakes proves nothing", func(o *Observation) {
			o.TLS = TLS{TargetSNI: HandshakeResetAfterHello, NeutralSNI: HandshakeOther, TargetSNIViaControl: HandshakeOther}
		}, report.VerdictInconclusive},
		{"unknown handshake value", func(o *Observation) { o.TLS.TargetSNI = "weird" }, report.VerdictInconclusive},
		{"http not run", func(o *Observation) { o.HTTP = HTTP{} }, report.VerdictInconclusive},
		{"unknown http value", func(o *Observation) { o.HTTP.Result = "weird" }, report.VerdictInconclusive},
		{"http reset, vendor reachable from outside", func(o *Observation) {
			o.HTTP = HTTP{Result: HTTPReset}
		}, report.VerdictInconclusive},
		{"500 where the reference is 200", func(o *Observation) {
			o.HTTP.Response = HTTPResponse{Status: 500}
		}, report.VerdictInconclusive},
		{"403 without a reference", func(o *Observation) {
			o.HTTP.Response, o.HTTP.Reference = HTTPResponse{Status: 403}, nil
		}, report.VerdictInconclusive},
		{"response without a status", func(o *Observation) {
			o.HTTP.Response = HTTPResponse{}
		}, report.VerdictInconclusive},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			o := healthy()
			tc.mutate(&o)
			if got := Classify(o); got != tc.want {
				t.Errorf("Classify = %q, want %q", got, tc.want)
			}
		})
	}

	t.Run("every verdict with rules has at least two cases", func(t *testing.T) {
		count := map[report.Verdict]int{}
		for _, tc := range tests {
			count[tc.want]++
		}
		for _, v := range report.Verdicts() {
			if v == report.VerdictFreezeAfterN || v == report.VerdictThrottled {
				if count[v] != 0 {
					t.Errorf("%s has no rules yet but appears in the table", v)
				}
				continue
			}
			if count[v] < 2 {
				t.Errorf("verdict %q has %d cases, want at least 2", v, count[v])
			}
		}
	})
}

func TestZeroObservationIsInconclusive(t *testing.T) {
	if got := Classify(Observation{}); got != report.VerdictInconclusive {
		t.Errorf("Classify(zero) = %q", got)
	}
}

// Whatever the combination of observations, the verdict must be a known one
// and never one of the verdicts that have no rules yet.
func TestClassifyAlwaysReturnsKnownVerdict(t *testing.T) {
	known := map[report.Verdict]bool{}
	for _, v := range report.Verdicts() {
		known[v] = true
	}

	ctrls := []Ctrl{
		{},
		{AllowlistAlive: true},
		{ControlAlive: true, AnchorsAlive: true},
		{ControlAlive: true, AnchorsAlive: true, TargetExternal: ExternalReachable},
		{ControlAlive: true, AnchorsAlive: true, TargetExternal: ExternalUnreachable},
	}
	dnss := []DNS{
		{},
		healthy().DNS,
		{System: answer("10.0.0.1"), Control: answer("203.0.113.10")},
		{System: DNSAnswer{Status: DNSNXDomain}, Control: answer("203.0.113.10")},
		{System: DNSAnswer{Status: DNSFailure}, Control: answer("203.0.113.10")},
	}
	tcps := []TCPResult{"", TCPOK, TCPTimeout, TCPReset}
	hs := []Handshake{"", HandshakeOK, HandshakeResetAfterHello, HandshakeTimeout, HandshakeCertInvalid}
	ref := HTTPResponse{Status: 200, Size: 1, BodyHash: "a"}
	https := []HTTP{
		{},
		{Result: HTTPTimeout},
		{Result: HTTPReset},
		{Result: HTTPResponded, Response: ref, Reference: &ref},
		{Result: HTTPResponded, Response: HTTPResponse{Status: 403}, Reference: &ref},
		{Result: HTTPResponded, Response: HTTPResponse{Status: 200, BodyHash: "s"}, Reference: &ref, MatchesKnownStub: true},
		{Result: HTTPResponded, Response: ref},
	}
	quics := []QUIC{{}, {Local: QUICOK, Control: QUICOK}, {Local: QUICTimeout, Control: QUICOK}}

	n := 0
	for _, c := range ctrls {
		for _, d := range dnss {
			for _, tcp := range tcps {
				for _, a := range hs {
					for _, b := range hs {
						for _, x := range hs {
							for _, h := range https {
								for _, q := range quics {
									o := Observation{Ctrl: c, DNS: d, TCP: tcp, TLS: TLS{a, b, x}, HTTP: h, QUIC: q}
									v := Classify(o)
									if !known[v] || v == report.VerdictFreezeAfterN || v == report.VerdictThrottled {
										t.Fatalf("Classify(%+v) = %q", o, v)
									}
									n++
								}
							}
						}
					}
				}
			}
		}
	}
	t.Logf("%d combinations", n)
}

func TestIsBogon(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"10.1.2.3", true}, {"172.16.0.1", true}, {"192.168.0.1", true},
		{"127.0.0.1", true}, {"169.254.1.1", true}, {"0.0.0.0", true},
		{"224.0.0.1", true}, {"100.64.0.1", true}, {"100.127.255.255", true},
		{"240.0.0.1", true}, {"::1", true}, {"fc00::1", true}, {"fe80::1", true}, {"::", true},
		{"100.128.0.1", false}, {"8.8.8.8", false}, {"203.0.113.10", false},
		{"2606:4700::1111", false},
	}
	for _, tc := range tests {
		if got := isBogon(netip.MustParseAddr(tc.ip)); got != tc.want {
			t.Errorf("isBogon(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}
	if !isBogon(netip.Addr{}) {
		t.Error("the zero address must be a bogon")
	}
}
