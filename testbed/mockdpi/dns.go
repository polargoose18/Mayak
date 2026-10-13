package mockdpi

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
)

const dnsTTL = 60

// dnsHandler answers A queries: bogon for spoofed names, normal otherwise.
// Other query types get an empty NOERROR answer.
type dnsHandler struct {
	spoofed map[string]bool
	bogon   netip.Addr
	normal  netip.Addr
}

func newDNSHandler(spoofed []string, bogon, normal netip.Addr) *dnsHandler {
	h := &dnsHandler{spoofed: make(map[string]bool, len(spoofed)), bogon: bogon, normal: normal}
	for _, name := range spoofed {
		h.spoofed[dns.CanonicalName(name)] = true
	}
	return h
}

func (h *dnsHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	switch {
	case r.Opcode != dns.OpcodeQuery:
		m.Rcode = dns.RcodeNotImplemented
	case len(r.Question) != 1:
		m.Rcode = dns.RcodeFormatError
	case r.Question[0].Qtype == dns.TypeA && r.Question[0].Qclass == dns.ClassINET:
		q := r.Question[0]
		ip := h.normal
		if h.spoofed[dns.CanonicalName(q.Name)] {
			ip = h.bogon
		}
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: dnsTTL},
			A:   net.IP(ip.AsSlice()),
		})
	}
	// A failed write means the client is gone; nothing to do about it.
	_ = w.WriteMsg(m)
}

// startDNS starts a UDP DNS server on a random loopback port and shuts it
// down in t.Cleanup.
func startDNS(t testing.TB, h dns.Handler) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("mockdpi: listen udp: %v", err)
	}
	started := make(chan struct{})
	done := make(chan error, 1)
	srv := &dns.Server{PacketConn: pc, Handler: h, NotifyStartedFunc: func() { close(started) }}
	go func() { done <- srv.ActivateAndServe() }()

	select {
	case <-started:
	case err := <-done:
		_ = pc.Close()
		t.Fatalf("mockdpi: dns server failed to start: %v", err)
	case <-time.After(5 * time.Second):
		_ = pc.Close()
		t.Fatalf("mockdpi: dns server did not start in time")
	}
	t.Cleanup(func() {
		if err := srv.Shutdown(); err != nil {
			t.Errorf("mockdpi: dns shutdown: %v", err)
		}
		<-done
	})
	return pc.LocalAddr().String()
}
