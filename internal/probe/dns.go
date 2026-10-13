package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/miekg/dns"

	"github.com/polargoose18/mayak/internal/classify"
)

// DNSTransport is how a resolver is reached.
type DNSTransport string

// DNS transports.
const (
	DNSTransportUDP DNSTransport = "udp"
	DNSTransportDoT DNSTransport = "dot" // DNS over TLS
)

// Resolver is the system resolver; *net.Resolver implements it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// DNSServer is a resolver the test queries directly.
type DNSServer struct {
	Addr       netip.AddrPort
	Transport  DNSTransport
	ServerName string // certificate name for DoT
}

// DNSRequest describes one dns test: the same A query to the system
// resolver, the control node's resolver and the public resolvers.
type DNSRequest struct {
	Host    string
	System  Resolver // nil means net.DefaultResolver
	Control DNSServer
	Public  []DNSServer

	roots *x509.CertPool // test override for DoT certificates
}

// DNSResult is one resolver's answer. The addresses are the public addresses
// of the target, never the client's.
type DNSResult struct {
	Status classify.DNSStatus `json:"status"`
	Addrs  []netip.Addr       `json:"addrs,omitempty"`
	Ms     int64              `json:"ms"`
}

// DNSObservation holds the answers of the dns test.
type DNSObservation struct {
	System  DNSResult   `json:"system"`
	Control DNSResult   `json:"control"`
	Public  []DNSResult `json:"public"`
}

// ForClassifier converts the observation to the classifier's input.
func (o DNSObservation) ForClassifier() classify.DNS {
	d := classify.DNS{System: o.System.answer(), Control: o.Control.answer()}
	for _, p := range o.Public {
		d.Public = append(d.Public, p.answer())
	}
	return d
}

func (r DNSResult) answer() classify.DNSAnswer {
	return classify.DNSAnswer{Status: r.Status, Addrs: r.Addrs}
}

// DNS asks for the A records of the host at every resolver, concurrently
// under one 8 second deadline. Only IPv4 is asked. A failed query is a
// result; the error is for a bad request or a cancelled context.
func DNS(ctx context.Context, req DNSRequest) (DNSObservation, error) {
	if err := req.validate(); err != nil {
		return DNSObservation{}, fmt.Errorf("dns: %w", err)
	}
	system := req.System
	if system == nil {
		system = net.DefaultResolver
	}

	runCtx, cancel := context.WithTimeout(ctx, testTimeout)
	defer cancel()

	obs := DNSObservation{Public: make([]DNSResult, len(req.Public))}
	var wg sync.WaitGroup
	run := func(dst *DNSResult, f func() DNSResult) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			*dst = f()
		}()
	}
	run(&obs.System, func() DNSResult { return lookupSystem(runCtx, system, req.Host) })
	run(&obs.Control, func() DNSResult { return queryServer(runCtx, req.Control, req.Host, req.roots) })
	for i, srv := range req.Public {
		run(&obs.Public[i], func() DNSResult { return queryServer(runCtx, srv, req.Host, req.roots) })
	}
	wg.Wait()

	if err := cancelled("dns", ctx); err != nil {
		return DNSObservation{}, err
	}
	return obs, nil
}

func (r DNSRequest) validate() error {
	if r.Host == "" {
		return errors.New("empty host")
	}
	for _, s := range append([]DNSServer{r.Control}, r.Public...) {
		if !s.Addr.IsValid() || s.Addr.Port() == 0 {
			return errors.New("invalid resolver address")
		}
		if s.Transport != DNSTransportUDP && s.Transport != DNSTransportDoT {
			return fmt.Errorf("unknown transport %q", s.Transport)
		}
	}
	return nil
}

func lookupSystem(ctx context.Context, r Resolver, host string) DNSResult {
	elapsed := start()
	addrs, err := r.LookupNetIP(ctx, "ip4", host)
	res := DNSResult{Ms: elapsed()}
	var dnsErr *net.DNSError
	switch {
	case err == nil:
		res.Status = classify.DNSOK
		for _, a := range addrs {
			res.Addrs = append(res.Addrs, a.Unmap())
		}
	case errors.As(err, &dnsErr) && dnsErr.IsNotFound:
		res.Status = classify.DNSNXDomain
	default:
		res.Status = classify.DNSFailure
	}
	return res
}

func queryServer(ctx context.Context, srv DNSServer, host string, roots *x509.CertPool) DNSResult {
	elapsed := start()
	c := &dns.Client{Net: "udp"}
	if srv.Transport == DNSTransportDoT {
		c.Net = "tcp-tls"
		c.TLSConfig = &tls.Config{ServerName: srv.ServerName, RootCAs: roots, MinVersion: tls.VersionTLS12}
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeA)

	resp, _, err := c.ExchangeContext(ctx, m, srv.Addr.String())
	res := DNSResult{Status: classify.DNSFailure}
	if err == nil {
		switch resp.Rcode {
		case dns.RcodeSuccess:
			res.Status = classify.DNSOK
			for _, rr := range resp.Answer {
				if a, ok := rr.(*dns.A); ok {
					if ip, ok := netip.AddrFromSlice(a.A); ok {
						res.Addrs = append(res.Addrs, ip.Unmap())
					}
				}
			}
		case dns.RcodeNameError:
			res.Status = classify.DNSNXDomain
		}
	}
	res.Ms = elapsed()
	return res
}
