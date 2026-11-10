package runner

import (
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/polargoose18/mayak/internal/classify"
	"github.com/polargoose18/mayak/internal/report"
	"github.com/polargoose18/mayak/internal/targets"
)

// TestReportProvenance exercises observations through classification and JSON
// validation, including verdicts that can originate in several different tests.
func TestReportProvenance(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*classify.Observation)
		verdict report.Verdict
		test    report.Test
	}{
		{"all clear", func(o *classify.Observation) {}, report.VerdictOK, report.TestHTTP},
		{"system DNS failure otherwise green", func(o *classify.Observation) {
			o.DNS.System = classify.DNSAnswer{Status: classify.DNSFailure}
		}, report.VerdictTimeoutUnknown, report.TestDNS},
		{"unexplained target SNI timeout", func(o *classify.Observation) {
			o.TLS = classify.TLS{TargetSNI: classify.HandshakeTimeout, TargetSNIViaControl: classify.HandshakeOK}
			o.HTTP = classify.HTTP{}
		}, report.VerdictTimeoutUnknown, report.TestTLSSNI},
		{"HTTP timeout after good TLS", func(o *classify.Observation) {
			o.HTTP = classify.HTTP{Result: classify.HTTPTimeout}
		}, report.VerdictTimeoutUnknown, report.TestHTTP},
		{"TCP failure external down", func(o *classify.Observation) {
			o.TCP, o.TLS, o.HTTP = classify.TCPTimeout, classify.TLS{}, classify.HTTP{}
			o.Ctrl.TargetExternal = classify.ExternalUnreachable
		}, report.VerdictVendorDown, report.TestTCP},
		{"TLS failure external down", func(o *classify.Observation) {
			o.TLS = classify.TLS{TargetSNI: classify.HandshakeTimeout}
			o.HTTP = classify.HTTP{}
			o.Ctrl.TargetExternal = classify.ExternalUnreachable
		}, report.VerdictVendorDown, report.TestTLSSNI},
		{"HTTP failure external down", func(o *classify.Observation) {
			o.HTTP = classify.HTTP{Result: classify.HTTPReset}
			o.Ctrl.TargetExternal = classify.ExternalUnreachable
		}, report.VerdictVendorDown, report.TestHTTP},
		{"control failure", func(o *classify.Observation) {
			o.Ctrl.ControlAlive = false
		}, report.VerdictInconclusive, report.TestCtrl},
		{"allowlist mode", func(o *classify.Observation) {
			o.Ctrl = classify.Ctrl{AllowlistAlive: true}
		}, report.VerdictAllowlistMode, report.TestCtrl},
		{"DNS tamper precedes TCP failure", func(o *classify.Observation) {
			o.DNS.System = classify.DNSAnswer{Status: classify.DNSNXDomain}
			o.TCP, o.TLS, o.HTTP = classify.TCPTimeout, classify.TLS{}, classify.HTTP{}
		}, report.VerdictDNSTamper, report.TestDNS},
		{"no trusted DNS answer", func(o *classify.Observation) {
			o.DNS.Control = classify.DNSAnswer{Status: classify.DNSFailure}
		}, report.VerdictInconclusive, report.TestDNS},
		{"unverified DNS answer", func(o *classify.Observation) {
			o.DNS.System.Addrs = []netip.Addr{netip.MustParseAddr("198.51.100.7")}
		}, report.VerdictInconclusive, report.TestDNS},
		{"TCP block", func(o *classify.Observation) {
			o.TCP, o.TLS, o.HTTP = classify.TCPReset, classify.TLS{}, classify.HTTP{}
		}, report.VerdictIPBlock, report.TestTCP},
		{"TCP contradiction", func(o *classify.Observation) {
			o.TCP = classify.TCPTimeout
		}, report.VerdictInconclusive, report.TestTCP},
		{"TCP not run", func(o *classify.Observation) {
			o.TCP, o.TLS, o.HTTP = "", classify.TLS{}, classify.HTTP{}
		}, report.VerdictInconclusive, report.TestTCP},
		{"SNI block", func(o *classify.Observation) {
			o.TLS = classify.TLS{TargetSNI: classify.HandshakeResetAfterHello, NeutralSNI: classify.HandshakeOK}
			o.HTTP = classify.HTTP{}
		}, report.VerdictSNIBlock, report.TestTLSSNI},
		{"invalid target certificate", func(o *classify.Observation) {
			o.TLS.TargetSNI = classify.HandshakeCertInvalid
			o.HTTP = classify.HTTP{}
		}, report.VerdictTLSIntercept, report.TestTLSSNI},
		{"TLS unexplained reset", func(o *classify.Observation) {
			o.TLS = classify.TLS{TargetSNI: classify.HandshakeResetAfterHello}
			o.HTTP = classify.HTTP{}
		}, report.VerdictInconclusive, report.TestTLSSNI},
		{"TLS not run", func(o *classify.Observation) {
			o.TLS, o.HTTP = classify.TLS{}, classify.HTTP{}
		}, report.VerdictInconclusive, report.TestTLSSNI},
		{"HTTP stub before geoblock", func(o *classify.Observation) {
			o.HTTP.Response = classify.HTTPResponse{Status: 451, Size: 20, BodyHash: "stub"}
			o.HTTP.MatchesKnownStub = true
		}, report.VerdictHTTPStub, report.TestHTTP},
		{"HTTP geoblock", func(o *classify.Observation) {
			o.HTTP.Response = classify.HTTPResponse{Status: 403, Size: 20, BodyHash: "region"}
		}, report.VerdictVendorGeoblock, report.TestHTTP},
		{"HTTP unexplained reset", func(o *classify.Observation) {
			o.HTTP = classify.HTTP{Result: classify.HTTPReset}
		}, report.VerdictInconclusive, report.TestHTTP},
		{"QUIC block", func(o *classify.Observation) {
			o.QUIC = classify.QUIC{Local: classify.QUICTimeout, Control: classify.QUICOK}
		}, report.VerdictQUICBlock, report.TestQUIC},
		{"DNS system failure defers to TLS", func(o *classify.Observation) {
			o.DNS.System = classify.DNSAnswer{Status: classify.DNSFailure}
			o.TLS = classify.TLS{TargetSNI: classify.HandshakeTimeout}
			o.HTTP = classify.HTTP{}
		}, report.VerdictTimeoutUnknown, report.TestTLSSNI},
		{"DNS system failure defers to QUIC", func(o *classify.Observation) {
			o.DNS.System = classify.DNSAnswer{Status: classify.DNSFailure}
			o.QUIC = classify.QUIC{Local: classify.QUICTimeout, Control: classify.QUICOK}
		}, report.VerdictQUICBlock, report.TestQUIC},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr := netip.MustParseAddr("203.0.113.10")
			ref := classify.HTTPResponse{Status: 200, Size: 1000, BodyHash: "page"}
			o := classify.Observation{
				Ctrl: classify.Ctrl{ControlAlive: true, AnchorsAlive: true, TargetExternal: classify.ExternalReachable},
				DNS: classify.DNS{
					System:  classify.DNSAnswer{Status: classify.DNSOK, Addrs: []netip.Addr{addr}},
					Control: classify.DNSAnswer{Status: classify.DNSOK, Addrs: []netip.Addr{addr}},
				},
				TCP:  classify.TCPOK,
				TLS:  classify.TLS{TargetSNI: classify.HandshakeOK},
				HTTP: classify.HTTP{Result: classify.HTTPResponded, Response: ref, Reference: &ref},
			}
			tc.mutate(&o)
			v, test := classify.ClassifyWithTest(o)
			if v != tc.verdict || test != tc.test {
				t.Fatalf("ClassifyWithTest = (%q, %q), want (%q, %q)", v, test, tc.verdict, tc.test)
			}
			if got := classify.Classify(o); got != v {
				t.Fatalf("Classify wrapper = %q, want %q", got, v)
			}
			meta := ReportMeta{Ver: "1.0", OS: report.OSLinux, Rev: "2026-01-01.1", Now: time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC), IPVer: 4, Resolver: report.ResolverISP}
			built, err := BuildReport(meta, []Result{{Target: targets.Target{ID: "test-target"}, Verdict: v, Test: test, Observation: o}})
			if err != nil {
				t.Fatal(err)
			}
			data, err := json.Marshal(built)
			if err != nil {
				t.Fatal(err)
			}
			validated, err := report.Validate(data)
			if err != nil {
				t.Fatal(err)
			}
			if validated.Results[0].Test != tc.test || validated.Results[0].Verdict != tc.verdict {
				t.Fatalf("validated result = %+v", validated.Results[0])
			}
			t.Logf("validated JSON: %s", data)
		})
	}
}
