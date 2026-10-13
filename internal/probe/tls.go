// Package probe implements the network tests of the agent.
package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/polargoose18/mayak/internal/classify"
)

const (
	// TLSPort is the port of the tls_sni test in production.
	TLSPort = 443

	// testTimeout is the ceiling for one test (SPEC section 5). A shorter
	// deadline on the caller's context wins.
	testTimeout = 8 * time.Second
)

// TLSOutcome is the result of one TLS handshake.
type TLSOutcome string

// TLS outcomes.
const (
	TLSOutcomeOK              TLSOutcome = "ok"
	TLSOutcomeResetAfterHello TLSOutcome = "reset_after_hello"
	TLSOutcomeTimeout         TLSOutcome = "timeout"
	TLSOutcomeCertInvalid     TLSOutcome = "cert_invalid"
	TLSOutcomeOther           TLSOutcome = "other"
)

// TLSSNIRequest describes one tls_sni test. The addresses carry the port
// (TLSPort in production) so that tests can use random ports.
type TLSSNIRequest struct {
	TargetAddr  netip.AddrPort // trusted IP of the target
	ControlAddr netip.AddrPort // IP of the control node, which accepts any SNI
	Host        string         // the target's host name, used as SNI
	NeutralSNI  string         // a harmless server name
}

// TLSHandshake is the result of one handshake. It holds no certificate data.
type TLSHandshake struct {
	Outcome TLSOutcome `json:"outcome"`
	Ms      int64      `json:"ms"`
}

// TLSObservation holds the three handshakes of the tls_sni test.
type TLSObservation struct {
	TargetSNI           TLSHandshake `json:"target_sni"`             // target SNI to the target IP
	NeutralSNI          TLSHandshake `json:"neutral_sni"`            // neutral SNI to the target IP
	TargetSNIViaControl TLSHandshake `json:"target_sni_via_control"` // target SNI to the control IP
}

// Handshakes converts the observation to the classifier's input.
func (o TLSObservation) Handshakes() classify.TLS {
	return classify.TLS{
		TargetSNI:           o.TargetSNI.Outcome.handshake(),
		NeutralSNI:          o.NeutralSNI.Outcome.handshake(),
		TargetSNIViaControl: o.TargetSNIViaControl.Outcome.handshake(),
	}
}

func (o TLSOutcome) handshake() classify.Handshake {
	switch o {
	case TLSOutcomeOK:
		return classify.HandshakeOK
	case TLSOutcomeResetAfterHello:
		return classify.HandshakeResetAfterHello
	case TLSOutcomeTimeout:
		return classify.HandshakeTimeout
	case TLSOutcomeCertInvalid:
		return classify.HandshakeCertInvalid
	}
	return classify.HandshakeOther
}

// TLSSNI runs the three TLS 1.3 handshakes of the tls_sni test: the target
// SNI to the target IP, a neutral SNI to the target IP, and the target SNI to
// the control node. They run concurrently under one 8 second deadline, so the
// whole test takes at most 8 seconds. A failed handshake is an outcome, not
// an error; the error is for a bad request or a cancelled context.
func TLSSNI(ctx context.Context, req TLSSNIRequest) (TLSObservation, error) {
	return tlsSNI(ctx, req, nil)
}

// tlsSNI is TLSSNI with the trusted roots overridable for tests (nil means
// the system roots).
func tlsSNI(ctx context.Context, req TLSSNIRequest, roots *x509.CertPool) (TLSObservation, error) {
	if err := req.validate(); err != nil {
		return TLSObservation{}, fmt.Errorf("tls_sni: %w", err)
	}

	runCtx, cancel := context.WithTimeout(ctx, testTimeout)
	defer cancel()

	jobs := []struct {
		addr netip.AddrPort
		sni  string
	}{
		{req.TargetAddr, req.Host},
		{req.TargetAddr, req.NeutralSNI},
		{req.ControlAddr, req.Host},
	}
	var res [3]TLSHandshake
	var wg sync.WaitGroup
	for i, j := range jobs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res[i] = handshake(runCtx, j.addr, j.sni, roots)
		}()
	}
	wg.Wait()

	// Results of a cancelled run say nothing about the network. A deadline
	// on the caller's context is different: it just makes handshakes time out.
	if errors.Is(ctx.Err(), context.Canceled) {
		return TLSObservation{}, fmt.Errorf("tls_sni: %w", ctx.Err())
	}
	return TLSObservation{TargetSNI: res[0], NeutralSNI: res[1], TargetSNIViaControl: res[2]}, nil
}

func (r TLSSNIRequest) validate() error {
	switch {
	case !r.TargetAddr.IsValid() || r.TargetAddr.Port() == 0:
		return errors.New("invalid target address")
	case !r.ControlAddr.IsValid() || r.ControlAddr.Port() == 0:
		return errors.New("invalid control address")
	case r.Host == "":
		return errors.New("empty host")
	case r.NeutralSNI == "":
		return errors.New("empty neutral SNI")
	}
	return nil
}

// handshake connects to addr and performs a TLS 1.3 handshake with the given
// SNI, verifying the certificate against sni. Only the outcome and the time
// are kept.
func handshake(ctx context.Context, addr netip.AddrPort, sni string, roots *x509.CertPool) TLSHandshake {
	start := time.Now()
	done := func(o TLSOutcome) TLSHandshake {
		return TLSHandshake{Outcome: o, Ms: time.Since(start).Milliseconds()}
	}

	var d net.Dialer
	raw, err := d.DialContext(ctx, "tcp", addr.String())
	if err != nil {
		// The connect itself is the tcp test's business: a timeout is a
		// timeout, anything else (refused, unreachable) is "other".
		if isTimeout(err) {
			return done(TLSOutcomeTimeout)
		}
		return done(TLSOutcomeOther)
	}
	defer raw.Close()

	conn := tls.Client(raw, &tls.Config{
		ServerName: sni,
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		RootCAs:    roots,
	})
	return done(handshakeOutcome(conn.HandshakeContext(ctx)))
}

// handshakeOutcome maps a handshake error to an outcome by error type, never
// by message text.
func handshakeOutcome(err error) TLSOutcome {
	var (
		verify  *tls.CertificateVerificationError
		unknown x509.UnknownAuthorityError
		host    x509.HostnameError
		invalid x509.CertificateInvalidError
	)
	switch {
	case err == nil:
		return TLSOutcomeOK
	case errors.As(err, &verify), errors.As(err, &unknown),
		errors.As(err, &host), errors.As(err, &invalid):
		return TLSOutcomeCertInvalid
	case isTimeout(err):
		return TLSOutcomeTimeout
	case errors.Is(err, syscall.ECONNRESET):
		// The connection was established and the ClientHello was sent, so a
		// reset here is a reset after the hello.
		return TLSOutcomeResetAfterHello
	}
	// Includes a clean close (io.EOF): without an RST it is not proven to be
	// a reset, so it is not reported as one.
	return TLSOutcomeOther
}

func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
