package probe

import (
	"context"
	"errors"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/polargoose18/mayak/internal/classify"
	"github.com/polargoose18/mayak/testbed/mockdpi"
)

func runTCP(t *testing.T, a string) TCPObservation {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), generous)
	defer cancel()
	obs, err := TCP(ctx, TCPRequest{Addr: addr(t, a)})
	if err != nil {
		t.Fatal(err)
	}
	if obs.Ms < 0 || obs.Ms > generous.Milliseconds() {
		t.Errorf("ms = %d", obs.Ms)
	}
	return obs
}

func TestTCP(t *testing.T) {
	env := mockdpi.Start(t, mockdpi.Config{Control: true, Blackhole: true, ClosedPort: true})
	tests := []struct {
		name string
		addr string
		want classify.TCPResult
	}{
		{"listening port", env.ControlTLS, classify.TCPOK},
		// The blackhole completes the TCP handshake; it only stays silent after.
		{"blackhole accepts the connection", env.Blackhole, classify.TCPOK},
		{"RST in answer to SYN", env.ClosedPort, classify.TCPReset},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := runTCP(t, tc.addr).ForClassifier(); got != tc.want {
				t.Errorf("result = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestTCPTimeout(t *testing.T) {
	// A SYN that gets no answer cannot be emulated (see mockdpi), so the
	// timeout is produced by an expired deadline.
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	obs, err := TCP(ctx, TCPRequest{Addr: netip.MustParseAddrPort("127.0.0.1:9")})
	if err != nil {
		t.Fatal(err)
	}
	if obs.Result != classify.TCPTimeout {
		t.Errorf("result = %q, want timeout", obs.Result)
	}
}

func TestTCPResultMapping(t *testing.T) {
	tests := []struct {
		err  error
		want classify.TCPResult
	}{
		{nil, classify.TCPOK},
		{context.DeadlineExceeded, classify.TCPTimeout},
		{syscall.ECONNREFUSED, classify.TCPReset},
		{syscall.ECONNRESET, classify.TCPReset},
		{syscall.ENETUNREACH, classify.TCPOther},
		{syscall.EHOSTUNREACH, classify.TCPOther},
		{errors.New("boom"), classify.TCPOther},
	}
	for _, tc := range tests {
		if got := tcpResult(tc.err); got != tc.want {
			t.Errorf("tcpResult(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}

func TestTCPValidationAndCancel(t *testing.T) {
	for _, a := range []netip.AddrPort{{}, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 0)} {
		if _, err := TCP(context.Background(), TCPRequest{Addr: a}); err == nil {
			t.Errorf("%v: want error", a)
		}
	}
	env := mockdpi.Start(t, mockdpi.Config{Control: true})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := TCP(ctx, TCPRequest{Addr: addr(t, env.ControlTLS)}); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}
