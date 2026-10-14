package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/polargoose18/mayak/internal/classify"
	"github.com/polargoose18/mayak/testbed/mockdpi"
)

const (
	// The mock certificate is valid for localhost only, so the target host in
	// these tests is "localhost" and the neutral SNI is another name.
	targetHost = "localhost"
	neutralSNI = "neutral.example"

	generous = 10 * time.Second // for handshakes that must finish
	short    = 300 * time.Millisecond
)

func addr(t *testing.T, s string) netip.AddrPort {
	t.Helper()
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		t.Fatal(err)
	}
	return ap
}

func request(t *testing.T, target, control string) TLSSNIRequest {
	t.Helper()
	return TLSSNIRequest{TargetAddr: addr(t, target), ControlAddr: addr(t, control), Host: targetHost, NeutralSNI: neutralSNI}
}

func run(t *testing.T, timeout time.Duration, env *mockdpi.Env, req TLSSNIRequest) TLSObservation {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	obs, err := tlsSNI(ctx, req, env.CertPool)
	if err != nil {
		t.Fatal(err)
	}
	for name, h := range map[string]TLSHandshake{"target": obs.TargetSNI, "neutral": obs.NeutralSNI, "control": obs.TargetSNIViaControl} {
		if h.Ms < 0 || h.Ms > timeout.Milliseconds()+2000 {
			t.Errorf("%s: ms = %d, out of range", name, h.Ms)
		}
	}
	return obs
}

func outcomes(o TLSObservation) [3]TLSOutcome {
	return [3]TLSOutcome{o.TargetSNI.Outcome, o.NeutralSNI.Outcome, o.TargetSNIViaControl.Outcome}
}

func TestTLSSNIResetAfterHello(t *testing.T) {
	env := mockdpi.Start(t, mockdpi.Config{
		ResetAfterHello: &mockdpi.ResetAfterHelloConfig{BlockedSNI: []string{targetHost}},
		Control:         true,
	})
	// The neutral SNI gets a certificate for another name, which is
	// cert_invalid: the handshake itself went through. The clean control node
	// accepts the target SNI.
	obs := run(t, generous, env, request(t, env.ResetAfterHello, env.ControlTLS))
	want := [3]TLSOutcome{TLSOutcomeResetAfterHello, TLSOutcomeCertInvalid, TLSOutcomeOK}
	if got := outcomes(obs); got != want {
		t.Errorf("outcomes = %v, want %v", got, want)
	}
}

func TestTLSSNIControl(t *testing.T) {
	env := mockdpi.Start(t, mockdpi.Config{Control: true})
	obs := run(t, generous, env, request(t, env.ControlTLS, env.ControlTLS))
	want := [3]TLSOutcome{TLSOutcomeOK, TLSOutcomeCertInvalid, TLSOutcomeOK}
	if got := outcomes(obs); got != want {
		t.Errorf("outcomes = %v, want %v", got, want)
	}
}

func TestTLSSNIBlackhole(t *testing.T) {
	env := mockdpi.Start(t, mockdpi.Config{Blackhole: true, Control: true})
	obs := run(t, short, env, request(t, env.Blackhole, env.ControlTLS))
	want := [3]TLSOutcome{TLSOutcomeTimeout, TLSOutcomeTimeout, TLSOutcomeOK}
	if got := outcomes(obs); got != want {
		t.Errorf("outcomes = %v, want %v", got, want)
	}
	// A timeout takes about as long as the deadline.
	if ms := obs.TargetSNI.Ms; ms < short.Milliseconds()/2 {
		t.Errorf("timeout reported after %d ms, deadline is %v", ms, short)
	}
}

func TestTLSSNINotATLSServer(t *testing.T) {
	env := mockdpi.Start(t, mockdpi.Config{StubPage: true, Control: true})
	obs := run(t, generous, env, request(t, env.StubPage, env.ControlTLS))
	want := [3]TLSOutcome{TLSOutcomeOther, TLSOutcomeOther, TLSOutcomeOK}
	if got := outcomes(obs); got != want {
		t.Errorf("outcomes = %v, want %v", got, want)
	}
}

func TestTLSSNIUntrustedCertificate(t *testing.T) {
	env := mockdpi.Start(t, mockdpi.Config{Control: true})
	// Without the mock CA in the roots the same server is cert_invalid.
	ctx, cancel := context.WithTimeout(context.Background(), generous)
	defer cancel()
	obs, err := TLSSNI(ctx, request(t, env.ControlTLS, env.ControlTLS))
	if err != nil {
		t.Fatal(err)
	}
	if got := outcomes(obs); got != [3]TLSOutcome{TLSOutcomeCertInvalid, TLSOutcomeCertInvalid, TLSOutcomeCertInvalid} {
		t.Errorf("outcomes = %v", got)
	}
}

func TestTLSSNIResultHasNoCertificateData(t *testing.T) {
	// The result type holds an outcome and milliseconds only.
	h := TLSHandshake{}
	if fmt.Sprintf("%+v", h) != "{Outcome: Ms:0}" {
		t.Errorf("TLSHandshake has unexpected fields: %+v", h)
	}
}

func TestTLSSNIRequestValidation(t *testing.T) {
	good := TLSSNIRequest{
		TargetAddr:  netip.MustParseAddrPort("127.0.0.1:443"),
		ControlAddr: netip.MustParseAddrPort("127.0.0.1:443"),
		Host:        "example.org",
		NeutralSNI:  "neutral.example",
	}
	tests := map[string]func(r *TLSSNIRequest){
		"zero target":     func(r *TLSSNIRequest) { r.TargetAddr = netip.AddrPort{} },
		"target no port":  func(r *TLSSNIRequest) { r.TargetAddr = netip.AddrPortFrom(r.TargetAddr.Addr(), 0) },
		"zero control":    func(r *TLSSNIRequest) { r.ControlAddr = netip.AddrPort{} },
		"control no port": func(r *TLSSNIRequest) { r.ControlAddr = netip.AddrPortFrom(r.ControlAddr.Addr(), 0) },
		"empty host":      func(r *TLSSNIRequest) { r.Host = "" },
		"empty neutral":   func(r *TLSSNIRequest) { r.NeutralSNI = "" },
	}
	for name, edit := range tests {
		t.Run(name, func(t *testing.T) {
			r := good
			edit(&r)
			if _, err := TLSSNI(context.Background(), r); err == nil {
				t.Error("want error")
			}
		})
	}
}

func TestTLSSNICancelledContext(t *testing.T) {
	env := mockdpi.Start(t, mockdpi.Config{Blackhole: true})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	_, err := tlsSNI(ctx, request(t, env.Blackhole, env.Blackhole), env.CertPool)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestHandshakeOutcome(t *testing.T) {
	opErr := func(err error) error {
		return &net.OpError{Op: "read", Net: "tcp", Err: os.NewSyscallError("read", err)}
	}
	tests := []struct {
		name string
		err  error
		want TLSOutcome
	}{
		{"nil", nil, TLSOutcomeOK},
		{"verification error", &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}, TLSOutcomeCertInvalid},
		{"wrapped verification error", fmt.Errorf("handshake: %w", &tls.CertificateVerificationError{}), TLSOutcomeCertInvalid},
		{"unknown authority", x509.UnknownAuthorityError{}, TLSOutcomeCertInvalid},
		{"hostname error", x509.HostnameError{Host: "x"}, TLSOutcomeCertInvalid},
		{"invalid certificate", x509.CertificateInvalidError{Reason: x509.Expired}, TLSOutcomeCertInvalid},
		{"context deadline", context.DeadlineExceeded, TLSOutcomeTimeout},
		{"wrapped context deadline", fmt.Errorf("x: %w", context.DeadlineExceeded), TLSOutcomeTimeout},
		{"os deadline", os.ErrDeadlineExceeded, TLSOutcomeTimeout},
		{"net timeout", &net.OpError{Op: "read", Err: timeoutErr{}}, TLSOutcomeTimeout},
		{"connection reset", opErr(syscall.ECONNRESET), TLSOutcomeResetAfterHello},
		{"bare ECONNRESET", syscall.ECONNRESET, TLSOutcomeResetAfterHello},
		{"clean close", io.EOF, TLSOutcomeOther},
		{"unexpected EOF", io.ErrUnexpectedEOF, TLSOutcomeOther},
		{"connection refused", opErr(syscall.ECONNREFUSED), TLSOutcomeOther},
		{"broken pipe", opErr(syscall.EPIPE), TLSOutcomeOther},
		{"cancelled", context.Canceled, TLSOutcomeOther},
		{"tls record header", tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"}, TLSOutcomeOther},
		{"anything else", errors.New("boom"), TLSOutcomeOther},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := handshakeOutcome(tc.err); got != tc.want {
				t.Errorf("handshakeOutcome(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestDialFailureOutcome(t *testing.T) {
	// A dial that cannot succeed immediately: the port of a closed listener.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ap := ln.Addr().(*net.TCPAddr).AddrPort()
	ln.Close()

	got := handshake(context.Background(), ap, "localhost", nil)
	if got.Outcome != TLSOutcomeOther {
		t.Errorf("outcome = %q, want other (connection refused)", got.Outcome)
	}
}

func TestDialTimeoutOutcome(t *testing.T) {
	// A deadline that has already passed fails the connect as a timeout.
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	got := handshake(ctx, netip.MustParseAddrPort("127.0.0.1:9"), "localhost", nil)
	if got.Outcome != TLSOutcomeTimeout {
		t.Errorf("outcome = %q, want timeout", got.Outcome)
	}
}

func TestHandshakesConversion(t *testing.T) {
	tests := []struct {
		in   TLSOutcome
		want classify.Handshake
	}{
		{TLSOutcomeOK, classify.HandshakeOK},
		{TLSOutcomeResetAfterHello, classify.HandshakeResetAfterHello},
		{TLSOutcomeTimeout, classify.HandshakeTimeout},
		{TLSOutcomeCertInvalid, classify.HandshakeCertInvalid},
		{TLSOutcomeOther, classify.HandshakeOther},
		{"", classify.HandshakeOther},
	}
	for _, tc := range tests {
		got := TLSObservation{TargetSNI: TLSHandshake{Outcome: tc.in}}.Handshakes().TargetSNI
		if got != tc.want {
			t.Errorf("%q -> %q, want %q", tc.in, got, tc.want)
		}
	}
	o := TLSObservation{
		TargetSNI:           TLSHandshake{Outcome: TLSOutcomeOK},
		NeutralSNI:          TLSHandshake{Outcome: TLSOutcomeTimeout},
		TargetSNIViaControl: TLSHandshake{Outcome: TLSOutcomeResetAfterHello},
	}
	want := classify.TLS{TargetSNI: classify.HandshakeOK, NeutralSNI: classify.HandshakeTimeout, TargetSNIViaControl: classify.HandshakeResetAfterHello}
	if got := o.Handshakes(); got != want {
		t.Errorf("Handshakes = %+v, want %+v", got, want)
	}
}
