package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	mrand "math/rand/v2"
	"net/netip"

	"github.com/polargoose18/mayak/internal/probe"
	"github.com/polargoose18/mayak/internal/runner"
)

// Compile-time deployment values; see ADR-006.
//
// All three are empty for now: no control node is deployed yet, so `mayak check`
// refuses to measure (exit 2) until the project ships a build with a real
// node. Control DNS is a separate resolver on the control host, not an HTTP endpoint.
const (
	defaultControlURL  = ""
	defaultControlAddr = ""
	defaultControlDNS  = ""
)

// productionEnv builds the Env of the real binary: the system resolver, the
// control node of this build, the project's anchors and a randomly seeded
// generator for the pauses between checks.
func productionEnv() runner.Env {
	env := runner.Env{
		// nil means net.DefaultResolver, which is what the user's programs
		// use.
		SystemResolver: nil,

		// The control node is the deployed one; these stay zero until a node
		// exists (see the constants above).
		Control: probe.ControlClient{BaseURL: defaultControlURL},
		PublicResolvers: []probe.DNSServer{
			{Addr: netip.MustParseAddrPort("1.1.1.1:853"), Transport: probe.DNSTransportDoT, ServerName: "cloudflare-dns.com"},
			{Addr: netip.MustParseAddrPort("8.8.8.8:853"), Transport: probe.DNSTransportDoT, ServerName: "dns.google"},
		},
	}
	if defaultControlAddr != "" {
		ap, err := netip.ParseAddrPort(defaultControlAddr)
		if err != nil {
			// A build with a broken constant must not ship; fail loudly
			// before any measurement happens.
			panic(fmt.Sprintf("bad defaultControlAddr %q: %v", defaultControlAddr, err))
		}
		env.ControlTLS = ap
	}
	if defaultControlDNS != "" {
		ap, err := netip.ParseAddrPort(defaultControlDNS)
		if err != nil {
			panic(fmt.Sprintf("bad defaultControlDNS %q: %v", defaultControlDNS, err))
		}
		env.ControlResolver = probe.DNSServer{Addr: ap, Transport: probe.DNSTransportUDP}
	}
	env.Anchors = []string{"https://example.com/", "https://www.iana.org/"}
	env.NeutralSNI = "example.net"
	env.Clock = runner.SystemClock{}

	// The pauses between checks are random; the seed comes from crypto/rand
	// so two runs never share a rhythm.
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		// crypto/rand failing on a healthy system is effectively impossible;
		// there is no sensible way to keep measuring without randomness.
		panic(fmt.Sprintf("seed the pause generator: %v", err))
	}
	env.Rand = mrand.New(mrand.NewPCG(
		binary.LittleEndian.Uint64(seed[:8]),
		binary.LittleEndian.Uint64(seed[8:16]),
	))
	return env
}
