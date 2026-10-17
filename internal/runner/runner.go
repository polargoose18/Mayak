// Package runner runs the checks of `mayak check`: it picks targets from the
// signed list, runs the probes within the load ceilings of SPEC section 5 and
// classifies each target (ADR-006).
//
// This file holds only the shared types. The logic comes in later steps.
package runner

import (
	"crypto/ed25519"
	"crypto/x509"
	"net/netip"
	"time"

	"github.com/polargoose18/mayak/internal/classify"
	"github.com/polargoose18/mayak/internal/probe"
	"github.com/polargoose18/mayak/internal/report"
	"github.com/polargoose18/mayak/internal/targets"
)

// Load ceilings of SPEC section 5. They are the only place these numbers live.
const (
	MinLimit       = 5                      // fewest targets per run
	MaxLimit       = 20                     // most targets per run
	DefaultLimit   = 10                     // targets per run without --limit (ADR-006, Q3)
	MaxConcurrency = 4                      // checks running at the same time
	PauseMin       = 200 * time.Millisecond // shortest pause between two starts
	PauseMax       = 800 * time.Millisecond // longest pause between two starts
	TestTimeout    = 8 * time.Second        // ceiling for one test
)

// Env is everything a run takes from the world outside the process. The
// command builds it from the real network; tests build it from
// testbed/mockdpi (ADR-006, Q8). It carries no test hooks of its own: the
// production command simply never fills it with test values.
type Env struct {
	// SystemResolver is the resolver the user's programs use; nil means
	// net.DefaultResolver.
	SystemResolver probe.Resolver
	// ControlResolver is the control node's resolver, queried directly.
	ControlResolver probe.DNSServer
	// PublicResolvers are the public DoT resolvers, queried directly.
	PublicResolvers []probe.DNSServer

	// Control is the control node's API (SPEC section 21.1).
	Control probe.ControlClient
	// ControlTLS is the control node's IP and port for the tls_sni handshake
	// with the target's name (SPEC section 19). Where it comes from in
	// production is decided in steps B3 and B8 (ADR-006).
	ControlTLS netip.AddrPort
	// Anchors are URLs of sites that are always up, for the ctrl test.
	Anchors []string
	// Allowlist are URLs of sites that stay reachable in allowlist mode.
	Allowlist []string

	// RootCAs are the trusted certificate authorities; nil means the system
	// roots.
	RootCAs *x509.CertPool
	// PublicKeys are the keys the targets list must be signed with; nil means
	// targets.PublicKeys().
	PublicKeys []ed25519.PublicKey

	// Clock gives the time and waits; the pauses between checks use it.
	Clock Clock
	// Rand picks the pauses between checks.
	Rand Rand
}

// Clock is the time source of a run.
type Clock interface {
	Now() time.Time
	// After returns a channel that receives once d has passed.
	After(d time.Duration) <-chan time.Time
}

// Rand is the randomness of a run; *math/rand/v2.Rand satisfies it.
type Rand interface {
	// Int64N returns a number in [0, n).
	Int64N(n int64) int64
}

// Options are the limits of one run. They may only be tighter than the
// ceilings above, never looser.
type Options struct {
	Limit       int           // targets per run, MinLimit..MaxLimit
	Concurrency int           // checks at the same time, at most MaxConcurrency
	PauseMin    time.Duration // shortest pause between two starts
	PauseMax    time.Duration // longest pause between two starts
	Timeout     time.Duration // ceiling for one test, at most TestTimeout
}

// Result is the outcome of the checks of one target.
type Result struct {
	Target  targets.Target
	Verdict report.Verdict

	// Observation is what the classifier was given.
	Observation classify.Observation

	// The probes' own results, for the report evidence and the output. A
	// probe that did not run (for example because ctrl failed) is zero.
	Ctrl      probe.CtrlObservation
	DNS       probe.DNSObservation
	TCP       probe.TCPObservation
	TLS       probe.TLSObservation
	HTTP      probe.HTTPObservation
	Reference *classify.HTTPResponse // the control node's response, nil if none

	Started  time.Time
	Duration time.Duration

	// Err is set when the target could not be checked for a reason that is
	// not a network result (a bad request, a cancelled run). Network failures
	// are results, not errors.
	Err error
}
