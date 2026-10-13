package probe

import (
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
