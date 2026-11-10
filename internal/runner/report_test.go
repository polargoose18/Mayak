package runner

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/polargoose18/mayak/internal/classify"
	"github.com/polargoose18/mayak/internal/probe"
	"github.com/polargoose18/mayak/internal/report"
	"github.com/polargoose18/mayak/internal/targets"
)

func TestBuildReport(t *testing.T) {
	cases := []struct {
		verdict  report.Verdict
		wantTest report.Test
	}{
		{report.VerdictOK, report.TestHTTP},
	}

	for _, tc := range cases {
		t.Run(string(tc.verdict), func(t *testing.T) {
			meta := ReportMeta{
				Ver:      "1.0",
				OS:       report.OSLinux,
				Rev:      "2026-01-01.1",
				Now:      time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
				IPVer:    4,
				Resolver: report.ResolverISP,
			}
			results := []Result{{
				Target:   targets.Target{ID: "test-target", Host: "example.com"},
				Verdict:  tc.verdict,
				Test:     tc.wantTest,
				Duration: 100 * time.Millisecond,
				Ctrl: probe.CtrlObservation{
					ControlAlive: true,
					Ms:           50,
				},
				DNS: probe.DNSObservation{
					System: probe.DNSResult{Status: classify.DNSOK},
				},
				TCP: probe.TCPObservation{
					Result: classify.TCPOK,
					Ms:     30,
				},
				Observation: classify.Observation{
					TLS: classify.TLS{
						TargetSNI: classify.HandshakeOK,
					},
					HTTP: classify.HTTP{
						Result: classify.HTTPResponded,
						Response: classify.HTTPResponse{
							Status:   200,
							Size:     1024,
							BodyHash: "abc123",
						},
					},
				},
			}}
			r, err := BuildReport(meta, results)
			if err != nil {
				t.Fatalf("BuildReport error: %v", err)
			}
			if r.Schema != report.SchemaID {
				t.Errorf("schema = %q, want %q", r.Schema, report.SchemaID)
			}
			if r.Agent.Ver != meta.Ver {
				t.Errorf("agent.ver = %q, want %q", r.Agent.Ver, meta.Ver)
			}
			if r.Agent.OS != meta.OS {
				t.Errorf("agent.os = %q, want %q", r.Agent.OS, meta.OS)
			}
			if r.Agent.Source != report.SourceCLI {
				t.Errorf("agent.source = %q, want %q", r.Agent.Source, report.SourceCLI)
			}
			if r.Net.IPVer != meta.IPVer {
				t.Errorf("net.ip_ver = %d, want %d", r.Net.IPVer, meta.IPVer)
			}
			if r.Net.Resolver != meta.Resolver {
				t.Errorf("net.resolver = %q, want %q", r.Net.Resolver, meta.Resolver)
			}
			if r.Net.Country != "" {
				t.Errorf("net.country = %q, want empty", r.Net.Country)
			}
			if r.Net.Region != nil {
				t.Errorf("net.region = %v, want nil", r.Net.Region)
			}
			if r.TargetsRev != meta.Rev {
				t.Errorf("targets_rev = %q, want %q", r.TargetsRev, meta.Rev)
			}
			if !r.TS.Equal(meta.Now) {
				t.Errorf("ts = %v, want %v", r.TS, meta.Now)
			}
			if len(r.Results) != 1 {
				t.Fatalf("expected 1 result, got %d", len(r.Results))
			}
			res := r.Results[0]
			if res.Target != "test-target" {
				t.Errorf("target = %q, want %q", res.Target, "test-target")
			}
			if res.Test != tc.wantTest {
				t.Errorf("test = %q, want %q", res.Test, tc.wantTest)
			}
			if res.Verdict != tc.verdict {
				t.Errorf("verdict = %q, want %q", res.Verdict, tc.verdict)
			}
			// Evidence must contain populated fields.
			ev := res.Evidence
			if ev == nil {
				t.Fatalf("evidence is nil")
			}
			if ev["ctrl_alive"] != true {
				t.Errorf("ctrl_alive = %v, want true", ev["ctrl_alive"])
			}
			if ev["dns_system"] != string(classify.DNSOK) {
				t.Errorf("dns_system = %v, want %q", ev["dns_system"], classify.DNSOK)
			}
			if ev["tcp"] != string(classify.TCPOK) {
				t.Errorf("tcp = %v, want %q", ev["tcp"], classify.TCPOK)
			}
			if ev["tls_target_sni"] != string(classify.HandshakeOK) {
				t.Errorf("tls_target_sni = %v, want %q", ev["tls_target_sni"], classify.HandshakeOK)
			}
			if ev["http_result"] != string(classify.HTTPResponded) {
				t.Errorf("http_result = %v, want %q", ev["http_result"], classify.HTTPResponded)
			}
			if ev["http_status"] != 200 {
				t.Errorf("http_status = %v, want 200", ev["http_status"])
			}
			if ev["http_size"] != int64(1024) {
				t.Errorf("http_size = %v, want %d", ev["http_size"], int64(1024))
			}
			if ev["http_hash"] != "abc123" {
				t.Errorf("http_hash = %v, want %q", ev["http_hash"], "abc123")
			}
			if ev["ms"] != int64(100) {
				t.Errorf("ms = %v, want 100", ev["ms"])
			}
		})
	}
}

func TestBuildReportOmitsZeroEvidence(t *testing.T) {
	meta := ReportMeta{
		Ver:      "1.0",
		OS:       report.OSLinux,
		Rev:      "2026-01-01.1",
		Now:      time.Now(),
		IPVer:    4,
		Resolver: report.ResolverISP,
	}
	results := []Result{{
		Target:   targets.Target{ID: "t", Host: "example.com"},
		Verdict:  report.VerdictOK,
		Test:     report.TestHTTP,
		Duration: 0,
	}}
	r, err := BuildReport(meta, results)
	if err != nil {
		t.Fatalf("BuildReport error: %v", err)
	}
	if len(r.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(r.Results))
	}
	// Duration is zero, so ms should be omitted; all other probe fields are
	// zero too, so evidence should be nil.
	if r.Results[0].Evidence != nil {
		t.Errorf("evidence = %v, want nil", r.Results[0].Evidence)
	}
}

func TestBuildReportUnknownVerdict(t *testing.T) {
	meta := ReportMeta{
		Ver:      "1.0",
		OS:       report.OSLinux,
		Rev:      "2026-01-01.1",
		Now:      time.Now(),
		IPVer:    4,
		Resolver: report.ResolverISP,
	}
	results := []Result{{
		Target:   targets.Target{ID: "t", Host: "example.com"},
		Verdict:  "unknown_verdict",
		Test:     report.TestHTTP,
		Duration: 1 * time.Millisecond,
	}}
	_, err := BuildReport(meta, results)
	if err == nil {
		t.Fatal("expected error for unknown verdict")
	}
	if !errors.Is(err, report.ErrInvalid) {
		t.Errorf("error does not wrap ErrInvalid: %v", err)
	}
}

func TestBuildReportTooLarge(t *testing.T) {
	meta := ReportMeta{
		Ver:      "1.0",
		OS:       report.OSLinux,
		Rev:      "2026-01-01.1",
		Now:      time.Now(),
		IPVer:    4,
		Resolver: report.ResolverISP,
	}
	// Inflate each result with a long http_hash so that 200 results exceed
	// the 64 KiB report limit.
	longHash := make([]byte, 200)
	for i := range longHash {
		longHash[i] = 'a'
	}
	results := make([]Result, 200)
	for i := range results {
		results[i] = Result{
			Target:   targets.Target{ID: "test-target", Host: "example.com"},
			Verdict:  report.VerdictOK,
			Test:     report.TestHTTP,
			Duration: 1 * time.Millisecond,
			HTTP: probe.HTTPObservation{
				Result: classify.HTTPResponded,
				Response: classify.HTTPResponse{
					Status:   200,
					Size:     1,
					BodyHash: string(longHash),
				},
			},
		}
	}
	_, err := BuildReport(meta, results)
	if err == nil {
		t.Fatal("expected error for too large report")
	}
	if !errors.Is(err, report.ErrInvalid) {
		t.Errorf("error does not wrap ErrInvalid: %v", err)
	}
}

func TestOSName(t *testing.T) {
	cases := []struct {
		goos string
		want string
	}{
		{"linux", report.OSLinux},
		{"windows", report.OSWindows},
		{"darwin", report.OSDarwin},
		{"android", report.OSAndroid},
		{"ios", report.OSIOS},
		{"freebsd", report.OSOther},
		{"", report.OSOther},
	}
	for _, tc := range cases {
		t.Run(tc.goos, func(t *testing.T) {
			got := OSName(tc.goos)
			if got != tc.want {
				t.Errorf("OSName(%q) = %q, want %q", tc.goos, got, tc.want)
			}
		})
	}
}

func TestIPVersion(t *testing.T) {
	t.Run("ipv4 from trusted addr", func(t *testing.T) {
		results := []Result{{
			Observation: classify.Observation{
				DNS: classify.DNS{
					Control: classify.DNSAnswer{
						Status: classify.DNSOK,
						Addrs:  []netip.Addr{netip.MustParseAddr("192.0.2.1")},
					},
				},
			},
		}}
		if got := IPVersion(results); got != 4 {
			t.Errorf("IPVersion = %d, want 4", got)
		}
	})
	t.Run("ipv6 from trusted addr", func(t *testing.T) {
		results := []Result{{
			Observation: classify.Observation{
				DNS: classify.DNS{
					Control: classify.DNSAnswer{
						Status: classify.DNSOK,
						Addrs:  []netip.Addr{netip.MustParseAddr("2001:db8::1")},
					},
				},
			},
		}}
		if got := IPVersion(results); got != 6 {
			t.Errorf("IPVersion = %d, want 6", got)
		}
	})
	t.Run("no trusted addr defaults to 4", func(t *testing.T) {
		results := []Result{{
			Observation: classify.Observation{
				DNS: classify.DNS{
					Control: classify.DNSAnswer{
						Status: classify.DNSFailure,
					},
				},
			},
		}}
		if got := IPVersion(results); got != 4 {
			t.Errorf("IPVersion = %d, want 4", got)
		}
	})
	t.Run("empty results defaults to 4", func(t *testing.T) {
		if got := IPVersion(nil); got != 4 {
			t.Errorf("IPVersion = %d, want 4", got)
		}
	})
}

func TestBuildReportMissingOrInvalidTest(t *testing.T) {
	meta := ReportMeta{Ver: "1.0", OS: report.OSLinux, Rev: "2026-01-01.1", Now: time.Now(), IPVer: 4, Resolver: report.ResolverISP}
	for _, test := range []report.Test{"", "unknown_test"} {
		t.Run(string(test), func(t *testing.T) {
			_, err := BuildReport(meta, []Result{{Target: targets.Target{ID: "t"}, Verdict: report.VerdictOK, Test: test}})
			if !errors.Is(err, report.ErrInvalid) {
				t.Fatalf("BuildReport(test=%q) error = %v, want ErrInvalid", test, err)
			}
		})
	}
}
