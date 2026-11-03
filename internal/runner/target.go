package runner

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/polargoose18/mayak/internal/classify"
	"github.com/polargoose18/mayak/internal/probe"
	"github.com/polargoose18/mayak/internal/targets"
)

// Check runs the probes of `mayak check` against one target and returns its
// verdict, in the order of SPEC section 5: ctrl, dns (with the TLS check of a
// system address where the classifier needs it), tcp on a trusted address,
// tls_sni, http with the control node's reference, and the control node's own
// view of the target (which the ctrl test asks for through ControlClient.Reach).
//
// The pass stops as soon as a lower layer decides the verdict, so a target
// that cannot be reached costs one timeout instead of four: the higher layers
// could not change the verdict, and SPEC section 5 sets the load ceilings, so
// their network cost is not spent without a reason. A network failure is a
// result, not an error; Err is set only for a bad request or a cancelled run
// (ADR-006, B3).
func Check(ctx context.Context, env Env, t targets.Target) Result {
	r := Result{Target: t}
	if t.Host == "" {
		r.Err = errors.New("check target: empty host")
		return r
	}

	// 1. ctrl: can the measurement itself be trusted?
	ctrlObs, err := probe.Ctrl(ctx, probe.CtrlRequest{
		Control:   env.Control,
		Anchors:   env.Anchors,
		Allowlist: env.Allowlist,
		Host:      t.Host,
		RootCAs:   env.RootCAs,
	})
	if err != nil {
		r.Err = fmt.Errorf("check %s: %w", t.ID, err)
		return r
	}
	r.Ctrl = ctrlObs
	r.Observation.Ctrl = ctrlObs.ForClassifier()
	if !r.Observation.Ctrl.ControlAlive || !r.Observation.Ctrl.AnchorsAlive {
		// Nothing else can be trusted, so the target's network is not touched.
		r.Verdict = classify.Classify(r.Observation)
		return r
	}

	// 2. dns.
	dnsObs, err := probe.DNS(ctx, probe.DNSRequest{
		Host:    t.Host,
		System:  env.SystemResolver,
		Control: env.ControlResolver,
		Public:  env.PublicResolvers,
		RootCAs: env.RootCAs,
	})
	if err != nil {
		r.Err = fmt.Errorf("check %s: %w", t.ID, err)
		return r
	}
	r.DNS = dnsObs
	r.Observation.DNS = dnsObs.ForClassifier()

	// The classifier reads the TLS check of a system address only when the
	// system answer shares no address with the trusted ones; make it exactly
	// then. The check itself, not the difference, is what tells a genuine CDN
	// answer from a stand-in.
	if classify.NeedsAddrCheck(r.Observation.DNS) {
		sysAddr := r.Observation.DNS.System.Addrs[0]
		check, err := probe.DNSAddrCheckRoots(ctx, env.targetAddr(sysAddr), t.Host, env.RootCAs)
		if err != nil {
			r.Err = fmt.Errorf("check %s: %w", t.ID, err)
			return r
		}
		r.Observation.DNS.SystemAddrCheck = check
	}

	// The tcp, tls_sni and http tests run against a trusted address, never
	// the system answer (SPEC section 5, rule 2).
	trusted, ok := trustedAddr(r.Observation.DNS)
	if !ok {
		// No trusted IP to test: the classifier has no address to work with.
		r.Verdict = classify.Classify(r.Observation)
		return r
	}
	addr := env.targetAddr(trusted)

	// 3. tcp.
	tcpObs, err := probe.TCP(ctx, probe.TCPRequest{Addr: addr})
	if err != nil {
		r.Err = fmt.Errorf("check %s: %w", t.ID, err)
		return r
	}
	r.TCP = tcpObs
	r.Observation.TCP = tcpObs.ForClassifier()
	if tcpObs.Result != classify.TCPOK {
		// A failed connect decides the verdict (ip_block, vendor_down or
		// inconclusive); a handshake cannot complete on a refused address.
		r.Verdict = classify.Classify(r.Observation)
		return r
	}

	// 4. tls_sni.
	tlsObs, err := probe.TLSSNI(ctx, probe.TLSSNIRequest{
		TargetAddr:  addr,
		ControlAddr: env.ControlTLS,
		Host:        t.Host,
		NeutralSNI:  env.NeutralSNI,
		RootCAs:     env.RootCAs,
	})
	if err != nil {
		r.Err = fmt.Errorf("check %s: %w", t.ID, err)
		return r
	}
	r.TLS = tlsObs
	r.Observation.TLS = tlsObs.Handshakes()
	if r.Observation.TLS.TargetSNI != classify.HandshakeOK {
		// A failed or intercepted handshake decides the verdict; the http
		// test is not reached.
		r.Verdict = classify.Classify(r.Observation)
		return r
	}

	// 5. http, with the control node's reference for the same request. The
	// reference is fetched only when the target answered, because the
	// classifier reads it only then.
	httpObs, err := probe.HTTP(ctx, probe.HTTPRequest{
		Addr:            addr,
		Host:            t.Host,
		Path:            probe.ControlPathRoot,
		KnownStubHashes: env.KnownStubHashes,
		RootCAs:         env.RootCAs,
	})
	if err != nil {
		r.Err = fmt.Errorf("check %s: %w", t.ID, err)
		return r
	}
	r.HTTP = httpObs

	var ref *classify.HTTPResponse
	if httpObs.Result == classify.HTTPResponded {
		ref, err = env.Control.Reference(ctx, t.Host, probe.ControlPathRoot)
		switch {
		case err == nil:
			r.Reference = ref
		case errors.Is(err, probe.ErrBadControlPath):
			r.Err = fmt.Errorf("check %s: %w", t.ID, err)
			return r
		case errors.Is(err, context.Canceled):
			r.Err = fmt.Errorf("check %s: %w", t.ID, err)
			return r
		default:
			ref = nil // the node could not fetch it; classify without it
		}
	}
	r.Observation.HTTP = httpObs.ForClassifier(ref)

	r.Verdict = classify.Classify(r.Observation)
	return r
}

// targetAddr returns the target IP with the HTTPS port of the run: the one
// from Env, or probe.TLSPort (443) in production.
func (e Env) targetAddr(ip netip.Addr) netip.AddrPort {
	port := e.TargetPort
	if port == 0 {
		port = probe.TLSPort
	}
	return netip.AddrPortFrom(ip.Unmap(), port)
}

// trustedAddr picks the address the tcp and tls_sni tests run against: the
// first address of the control node's answer, then of a public resolver's.
// Those answers are outside the filtered zone, so they are the trusted side
// of rule 2 (SPEC section 5).
func trustedAddr(d classify.DNS) (netip.Addr, bool) {
	for _, a := range append([]classify.DNSAnswer{d.Control}, d.Public...) {
		if a.Status != classify.DNSOK {
			continue
		}
		for _, ip := range a.Addrs {
			return ip.Unmap(), true
		}
	}
	return netip.Addr{}, false
}
