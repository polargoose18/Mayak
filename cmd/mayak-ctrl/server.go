package main

import (
	"context"
	"crypto/x509"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/polargoose18/mayak/internal/targets"
)

// ctrlServer holds the state of the control node.
type ctrlServer struct {
	targetsList *targets.Targets
	now         func() time.Time
	http        *http.Server

	// Ключ карты — хеш адреса клиента, сам адрес нигде не хранится
	// и не логируется (правило приватности из AGENTS.md).
	mu      sync.Mutex
	buckets map[string]tokenBucket

	dialTimeout time.Duration

	// lookupHost и dialContext — точки подмены для тестов: в бою это DNS и
	// TCP, в тестах локальные слушатели на документационных адресах.
	lookupHost  func(ctx context.Context, host string) ([]netip.Addr, error)
	dialContext func(ctx context.Context, network, address string) (net.Conn, error)

	// rootCAs — доверенные корни для HTTPS к цели; nil = системные (ADR-006).
	rootCAs *x509.CertPool
}

// newCtrlServerWithTargets creates a ctrlServer around an already-parsed
// targets list; tlist may be nil, in which case every host is rejected.
func newCtrlServerWithTargets(cfg *Config, tlist *targets.Targets) *ctrlServer {
	srv := &ctrlServer{
		targetsList: tlist,
		now:         time.Now,
		buckets:     make(map[string]tokenBucket),
		dialTimeout: 8 * time.Second,
	}
	srv.lookupHost = func(ctx context.Context, host string) ([]netip.Addr, error) {
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		addrs := make([]netip.Addr, 0, len(ips))
		for _, ip := range ips {
			a, ok := netip.AddrFromSlice(ip)
			if !ok || !a.IsValid() {
				continue
			}
			addrs = append(addrs, a.Unmap())
		}
		return addrs, nil
	}
	srv.dialContext = defaultDialContext(srv.dialTimeout)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/ping", srv.ping)
	mux.HandleFunc("GET /v1/reach", srv.reach)
	mux.HandleFunc("GET /v1/fetch", srv.fetch)

	srv.http = &http.Server{
		Addr: cfg.Addr,
		// net/http diagnostics include client addresses on panic and TLS errors.
		ErrorLog:          log.New(io.Discard, "", 0),
		Handler:           srv.rateLimitMiddleware(mux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	return srv
}
