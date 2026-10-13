// Package classify turns raw observations of one run into a verdict. It is a
// pure function: no network, no clock, no randomness.
//
// # Order of rules
//
// Classify applies the stages below in this order and returns the verdict of
// the first stage that decides (SPEC section 5, rules 1-7, amended by
// section 19). The order goes from "the measurement itself is unreliable" to
// "the lower network layer" to "the higher one", because a failure on a lower
// layer makes the higher layers meaningless:
//
//  1. ctrl (rule 1). If the control node or the reference sites are not
//     reachable, nothing else can be trusted. With both down and the allowlist
//     sites up the verdict is allowlist_mode, otherwise inconclusive. First,
//     because every other comparison needs the control node.
//  2. DNS (rule 2). A tampered answer comes before everything else because
//     the later tests are only meaningful against the trusted IP. If there is
//     no trusted answer at all there is no IP to test: inconclusive.
//  3. TCP (rule 3). Timeout or RST on connect is ip_block, unless the control
//     node cannot reach the target either: then vendor_down (section 19).
//  4. TLS (rules 4 and 5). An invalid certificate is tls_intercept. A failed
//     handshake with the target SNI is sni_block when it is explained by the
//     SNI: the same SNI fails towards the clean control IP, or (if that was
//     not tested) a neutral SNI passes towards the target IP. Otherwise the
//     failure is unexplained. External unreachability gives vendor_down.
//  5. HTTP (rules 6 and 7). A known operator stub is http_stub; it is checked
//     before the geoblock because operators also serve stubs with 403 or 451.
//     403 or 451 that is not a known stub and differs from the reference is
//     vendor_geoblock.
//  6. QUIC. quic_block only when everything over TCP is fine, so a problem
//     with UDP is not hidden behind, and does not hide, a TCP-level verdict.
//  7. A failed system resolver with everything else fine is timeout_unknown,
//     otherwise ok.
//
// One verdict is returned per run, so when several layers are broken the
// lowest one wins. The per-test details stay in the report evidence.
//
// # Contradictions
//
// Contradictory observations never produce a block verdict. Examples: TCP
// failed but a handshake completed; the target SNI fails towards the target
// IP but passes towards the clean control IP. The result is inconclusive. One
// exception is deliberate: if the control node says the target is down but
// the agent got a complete answer, the local evidence wins, because the user
// can reach the service.
//
// # Known limits
//
// DNS tamper detection compares addresses, so a CDN that gives different
// resolvers disjoint address sets can look like a tamper. Missing
// observations make the verdict inconclusive, never ok.
//
// freeze_after_n and throttled have no rules yet.
package classify

import (
	"net/netip"

	"github.com/polargoose18/mayak/internal/report"
)

// Classify returns the verdict for one run against one target.
func Classify(o Observation) report.Verdict {
	if !o.Ctrl.ControlAlive || !o.Ctrl.AnchorsAlive {
		return classifyCtrlFailure(o.Ctrl)
	}

	dns := analyzeDNS(o.DNS)
	switch dns {
	case dnsTampered:
		return report.VerdictDNSTamper
	case dnsNoTrustedAnswer:
		return report.VerdictInconclusive
	}

	if v, ok := classifyTransport(o); ok {
		return v
	}
	if v, ok := classifyHTTP(o); ok {
		return v
	}
	if quicBlocked(o.QUIC) {
		return report.VerdictQUICBlock
	}
	if dns == dnsSystemFailed {
		return report.VerdictTimeoutUnknown
	}
	return report.VerdictOK
}

// classifyCtrlFailure handles rule 1 and its section 19 amendment.
func classifyCtrlFailure(c Ctrl) report.Verdict {
	if !c.ControlAlive && !c.AnchorsAlive && c.AllowlistAlive {
		return report.VerdictAllowlistMode
	}
	return report.VerdictInconclusive
}

type dnsState int

const (
	dnsConsistent dnsState = iota
	dnsTampered
	dnsNoTrustedAnswer
	dnsSystemFailed
)

// analyzeDNS implements rule 2. The trusted set is every address returned by
// the control node and the public resolvers. The system answer is tampered
// with if it holds a bogon that is not in the trusted set, is NXDOMAIN while
// trusted resolvers have addresses, or shares no address with the trusted set.
// "Shares no address" rather than "has an extra address" is deliberately
// conservative: it avoids flagging CDNs that return partly different sets.
func analyzeDNS(d DNS) dnsState {
	trusted := make(map[netip.Addr]bool)
	for _, a := range append([]DNSAnswer{d.Control}, d.Public...) {
		if a.Status != DNSOK {
			continue
		}
		for _, ip := range a.Addrs {
			trusted[ip.Unmap()] = true
		}
	}

	sys := d.System
	if sys.Status == DNSOK {
		for _, ip := range sys.Addrs {
			if ip = ip.Unmap(); isBogon(ip) && !trusted[ip] {
				return dnsTampered
			}
		}
	}
	if len(trusted) == 0 {
		return dnsNoTrustedAnswer
	}

	switch sys.Status {
	case DNSNXDomain:
		return dnsTampered
	case DNSFailure:
		return dnsSystemFailed
	case DNSOK:
		if len(sys.Addrs) > 0 && !anyIn(sys.Addrs, trusted) {
			return dnsTampered
		}
	}
	return dnsConsistent
}

func anyIn(addrs []netip.Addr, set map[netip.Addr]bool) bool {
	for _, a := range addrs {
		if set[a.Unmap()] {
			return true
		}
	}
	return false
}

// isBogon reports whether ip cannot be a legitimate public address of a
// service: private, loopback, link-local, multicast, unspecified, carrier
// grade NAT (100.64.0.0/10) or reserved (240.0.0.0/4). Documentation ranges
// are not treated as bogons, so they can be used in tests as "public".
func isBogon(ip netip.Addr) bool {
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsMulticast() {
		return true
	}
	return netip.MustParsePrefix("100.64.0.0/10").Contains(ip) ||
		netip.MustParsePrefix("240.0.0.0/4").Contains(ip)
}

// classifyTransport implements rules 3, 4 and 5 (and vendor_down).
func classifyTransport(o Observation) (report.Verdict, bool) {
	a := o.TLS.TargetSNI
	vendorDown := o.Ctrl.TargetExternal == ExternalUnreachable

	switch o.TCP {
	case TCPTimeout, TCPReset:
		switch {
		case completed(a):
			return report.VerdictInconclusive, true // TCP failed yet TLS completed
		case vendorDown:
			return report.VerdictVendorDown, true
		}
		return report.VerdictIPBlock, true
	case TCPOK:
	default: // not run or unknown
		return report.VerdictInconclusive, true
	}

	switch {
	case a == HandshakeCertInvalid:
		return report.VerdictTLSIntercept, true
	case failed(a):
		if vendorDown {
			return report.VerdictVendorDown, true
		}
		return classifyTargetSNIFailure(o.TLS), true
	case a == HandshakeOK:
		return "", false
	}
	return report.VerdictInconclusive, true // not run or unknown
}

// classifyTargetSNIFailure explains a failed handshake with the target SNI.
// For the neutral SNI and the control IP, cert_invalid counts as a completed
// handshake: only whether the handshake went through matters there.
func classifyTargetSNIFailure(t TLS) report.Verdict {
	switch {
	case failed(t.TargetSNIViaControl):
		// The same SNI fails towards a clean IP: the SNI is what is filtered.
		return report.VerdictSNIBlock
	case completed(t.TargetSNIViaControl):
		// The clean IP accepts this SNI, so SNI filtering does not explain it.
	case completed(t.NeutralSNI):
		// Not tested via the control node: rule 4 as written.
		return report.VerdictSNIBlock
	}
	if t.TargetSNI == HandshakeTimeout {
		return report.VerdictTimeoutUnknown
	}
	return report.VerdictInconclusive
}

func failed(h Handshake) bool {
	return h == HandshakeResetAfterHello || h == HandshakeTimeout
}

func completed(h Handshake) bool {
	return h == HandshakeOK || h == HandshakeCertInvalid
}

// classifyHTTP implements rules 6 and 7.
func classifyHTTP(o Observation) (report.Verdict, bool) {
	h := o.HTTP
	switch h.Result {
	case HTTPResponded:
	case HTTPTimeout, HTTPReset:
		switch {
		case o.Ctrl.TargetExternal == ExternalUnreachable:
			return report.VerdictVendorDown, true
		case h.Result == HTTPTimeout:
			return report.VerdictTimeoutUnknown, true
		}
		return report.VerdictInconclusive, true
	default: // not run or unknown
		return report.VerdictInconclusive, true
	}

	ref := h.Reference
	// A stub flag is ignored if the body equals the reference: that is the
	// real page.
	if h.MatchesKnownStub && (ref == nil || !sameBody(h.Response, *ref)) {
		return report.VerdictHTTPStub, true
	}

	status := h.Response.Status
	if ref == nil {
		if status >= 200 && status < 400 {
			return "", false
		}
		return report.VerdictInconclusive, true // no reference to compare with
	}
	switch {
	case status == ref.Status:
		return "", false
	case status == 403 || status == 451:
		return report.VerdictVendorGeoblock, true
	}
	return report.VerdictInconclusive, true
}

// sameBody compares by hash when both sides have one, otherwise by size.
func sameBody(a, b HTTPResponse) bool {
	if a.BodyHash != "" && b.BodyHash != "" {
		return a.BodyHash == b.BodyHash
	}
	return a.Size == b.Size
}

// quicBlocked: the local QUIC attempt fails while the control node's succeeds.
// If the control node fails too, the target just has no HTTP/3.
func quicBlocked(q QUIC) bool {
	return (q.Local == QUICTimeout || q.Local == QUICError) && q.Control == QUICOK
}
