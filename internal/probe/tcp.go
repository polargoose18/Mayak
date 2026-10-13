package probe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"

	"github.com/polargoose18/mayak/internal/classify"
)

// TCPRequest describes one tcp test: a connect to the trusted IP of the
// target (the address from a trusted DNS answer, port TLSPort in production).
type TCPRequest struct {
	Addr netip.AddrPort
}

// TCPObservation is the result of the tcp test.
type TCPObservation struct {
	Result classify.TCPResult `json:"result"`
	Ms     int64              `json:"ms"`
}

// ForClassifier returns the result for the classifier.
func (o TCPObservation) ForClassifier() classify.TCPResult { return o.Result }

// TCP connects to the address and closes the connection at once. A failed
// connect is a result; the error is for a bad request or a cancelled context.
func TCP(ctx context.Context, req TCPRequest) (TCPObservation, error) {
	if !req.Addr.IsValid() || req.Addr.Port() == 0 {
		return TCPObservation{}, errors.New("tcp: invalid address")
	}
	runCtx, cancel := context.WithTimeout(ctx, testTimeout)
	defer cancel()

	elapsed := start()
	var d net.Dialer
	conn, err := d.DialContext(runCtx, "tcp", req.Addr.String())
	obs := TCPObservation{Result: tcpResult(err), Ms: elapsed()}
	if err == nil {
		_ = conn.Close()
	}
	if err := cancelled("tcp", ctx); err != nil {
		return TCPObservation{}, err
	}
	return obs, nil
}

// tcpResult maps a connect error to a result by error type. A refused
// connection is the RST that comes in answer to a SYN.
func tcpResult(err error) classify.TCPResult {
	switch {
	case err == nil:
		return classify.TCPOK
	case isTimeout(err):
		return classify.TCPTimeout
	case errors.Is(err, syscall.ECONNREFUSED), errors.Is(err, syscall.ECONNRESET):
		return classify.TCPReset
	}
	return classify.TCPOther
}
