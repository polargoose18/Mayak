package classify

import "net/netip"

// Observation is the raw result of one run against one target. The zero
// value means "nothing was observed" and classifies as inconclusive.
type Observation struct {
	Ctrl Ctrl
	DNS  DNS
	TCP  TCPResult
	TLS  TLS
	HTTP HTTP
	QUIC QUIC
}

// Ctrl is the result of the ctrl test plus the control node's view of the
// target.
type Ctrl struct {
	ControlAlive   bool // the control node answered
	AnchorsAlive   bool // the reference sites that are always up answered
	AllowlistAlive bool // allowlist sites answered; only read when ControlAlive and AnchorsAlive are both false

	// TargetExternal is the control node's own check of the target.
	TargetExternal External
}

// External is the outcome of the control node's check of the target.
type External string

// External outcomes. The empty value means the check did not run.
const (
	ExternalReachable   External = "reachable"
	ExternalUnreachable External = "unreachable"
)

// DNS holds the answers of the resolvers for the target host.
type DNS struct {
	System  DNSAnswer   // the system resolver
	Control DNSAnswer   // the control node's resolver
	Public  []DNSAnswer // public DoH/DoT resolvers
}

// DNSAnswer is one resolver's answer.
type DNSAnswer struct {
	Status DNSStatus
	Addrs  []netip.Addr
}

// DNSStatus is the outcome of a DNS query. The empty value means the
// resolver was not asked.
type DNSStatus string

// DNS statuses.
const (
	DNSOK       DNSStatus = "ok"
	DNSNXDomain DNSStatus = "nxdomain"
	DNSFailure  DNSStatus = "failure" // timeout, SERVFAIL, etc.
)

// TCPResult is the outcome of the TCP connect to the target IP, port 443.
// The IP is the trusted one when the system resolver was tampered with. The
// empty value means the test did not run.
type TCPResult string

// TCP results.
const (
	TCPOK      TCPResult = "ok"
	TCPTimeout TCPResult = "timeout"
	TCPReset   TCPResult = "reset" // RST in answer to the SYN (connection refused)

	// TCPOther is any other failure (network unreachable, etc.). No rule is
	// based on it.
	TCPOther TCPResult = "other"
)

// Handshake is the outcome of one TLS handshake. The empty value means the
// handshake was not attempted.
type Handshake string

// Handshake outcomes.
const (
	HandshakeOK              Handshake = "ok"
	HandshakeResetAfterHello Handshake = "reset_after_hello"
	HandshakeTimeout         Handshake = "timeout"
	HandshakeCertInvalid     Handshake = "cert_invalid"

	// HandshakeOther is any other failure (TLS alert, not a TLS server,
	// connection refused). It is neither a clear block nor a completed
	// handshake, so no rule is based on it.
	HandshakeOther Handshake = "other"
)

// TLS holds the handshakes of the tls_sni test.
type TLS struct {
	TargetSNI           Handshake // target SNI to the target IP: what the user does
	NeutralSNI          Handshake // neutral SNI to the target IP
	TargetSNIViaControl Handshake // target SNI to the control node IP (it accepts any SNI)
}

// HTTP is the outcome of the http test.
type HTTP struct {
	Result   HTTPResult
	Response HTTPResponse // set when Result is HTTPResponded

	// Reference is the control node's response for the same request; nil if
	// there is none.
	Reference *HTTPResponse

	// MatchesKnownStub is set when the body matches a known operator stub.
	MatchesKnownStub bool
}

// HTTPResult is the outcome of the HTTP request. The empty value means the
// test did not run.
type HTTPResult string

// HTTP results.
const (
	HTTPResponded HTTPResult = "responded"
	HTTPTimeout   HTTPResult = "timeout"
	HTTPReset     HTTPResult = "reset"

	// HTTPOther is any other failure (bad certificate, protocol error). No
	// rule is based on it.
	HTTPOther HTTPResult = "other"
)

// HTTPResponse describes a response by status, body size and body hash.
type HTTPResponse struct {
	Status   int
	Size     int64
	BodyHash string
}

// QUIC holds the quic test: a QUIC Initial to UDP/443 of the target, sent
// from the agent and from the control node.
type QUIC struct {
	Local   QUICResult
	Control QUICResult
}

// QUICResult is the outcome of one QUIC attempt. The empty value means the
// test did not run.
type QUICResult string

// QUIC results.
const (
	QUICOK      QUICResult = "ok"
	QUICTimeout QUICResult = "timeout"
	QUICError   QUICResult = "error"
)
