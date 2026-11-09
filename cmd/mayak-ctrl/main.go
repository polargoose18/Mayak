// Command mayak-ctrl is the control node (SPEC section 21.1).
//
// It serves three endpoints:
//
//	GET /v1/ping                     -> 200, empty body
//	GET /v1/reach?host=<host>        -> {"reachable": bool}
//	GET /v1/fetch?host=<host>&path=<path>
//	                                 -> {"status": int, "size": int, "body_hash": "<hex>"}
//
// It serves a host only if the host is in its own signed targets list, it
// refuses query keys other than host/path (never ip or port), it never dials
// a bogon address, it rate-limits per client, and it never logs a client
// address.
//
// A second TLS listener (--tls-addr) accepts any SNI and closes the
// connection immediately after the handshake, so the agent can observe
// whether an arbitrary handshake completes from outside.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/polargoose18/mayak/internal/classify"
	"github.com/polargoose18/mayak/internal/probe"
	"github.com/polargoose18/mayak/internal/targets"
)

const (
	// rateLimitBucketSize is the number of requests one client may make per
	// rateLimitWindow.
	rateLimitBucketSize = 20

	// rateLimitWindow is the token bucket refill interval.
	rateLimitWindow = 1 * time.Minute

	// maxRateBuckets bounds the per-client bucket map; when it is full,
	// expired buckets are swept before a new client is admitted.
	maxRateBuckets = 10000
)

// tokenBucket is the rate-limit state of one client key.
type tokenBucket struct {
	tokens int
	reset  time.Time
}

// ctrlServer holds the state of the control node.
type ctrlServer struct {
	targetsList *targets.Targets
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

// Config holds command-line configuration for the control node.
type Config struct {
	Addr    string
	TLSAddr string
	TLSCert string
	TLSKey  string
	Targets string
}

// newSelfSignedCert generates an ephemeral ECDSA P-256 self-signed
// certificate for the any-SNI listener. It returns the certificate and the
// SHA-256 fingerprint of the DER-encoded certificate as hex.
func newSelfSignedCert() (tls.Certificate, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 63))
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("generate serial: %w", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Mayak Control Node (ephemeral)"},
		SerialNumber:          serial,
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("create certificate: %w", err)
	}
	sum := sha256.Sum256(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, hex.EncodeToString(sum[:]), nil
}

// loadConfig parses command-line flags.
func loadConfig() (*Config, error) {
	cfg := &Config{
		Addr:    ":8443",
		TLSAddr: ":443",
	}
	args := os.Args[1:]
	value := func(i *int, name string) (string, error) {
		*i++
		if *i >= len(args) {
			return "", fmt.Errorf("%s needs a value", name)
		}
		return args[*i], nil
	}
	for i := 0; i < len(args); i++ {
		var err error
		switch args[i] {
		case "--addr":
			cfg.Addr, err = value(&i, "--addr")
		case "--tls-addr":
			cfg.TLSAddr, err = value(&i, "--tls-addr")
		case "--tls-cert":
			cfg.TLSCert, err = value(&i, "--tls-cert")
		case "--tls-key":
			cfg.TLSKey, err = value(&i, "--tls-key")
		case "--targets":
			cfg.Targets, err = value(&i, "--targets")
		default:
			return nil, fmt.Errorf("unknown flag: %s", args[i])
		}
		if err != nil {
			return nil, err
		}
	}
	return cfg, nil
}

// refuseBogonDial is a net.Dialer.Control hook: it re-checks the address the
// node is actually connecting to and refuses bogons, whatever DNS said.
func refuseBogonDial(network, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("dial control: %w", err)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("dial control: parse %s: %w", network, err)
	}
	if classify.IsBogon(ip.Unmap()) {
		return errors.New("dial control: bogon address refused")
	}
	return nil
}

// defaultDialContext dials TCP with a bogon re-check on the real address.
func defaultDialContext(timeout time.Duration) func(context.Context, string, string) (net.Conn, error) {
	d := &net.Dialer{Timeout: timeout, Control: refuseBogonDial}
	return d.DialContext
}

// newCtrlServerWithTargets creates a ctrlServer around an already-parsed
// targets list; tlist may be nil, in which case every host is rejected.
func newCtrlServerWithTargets(cfg *Config, tlist *targets.Targets) *ctrlServer {
	srv := &ctrlServer{
		targetsList: tlist,
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
		Addr:              cfg.Addr,
		Handler:           srv.rateLimitMiddleware(mux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	return srv
}

// newCtrlServer creates a ctrlServer from a Config, loading the signed
// targets list from the file named by --targets. Without --targets the node
// rejects every host.
func newCtrlServer(cfg *Config) (*ctrlServer, error) {
	var tlist *targets.Targets
	if cfg.Targets != "" {
		var err error
		tlist, err = loadCtrlTargets(cfg.Targets, time.Now())
		if err != nil {
			return nil, err
		}
	}
	return newCtrlServerWithTargets(cfg, tlist), nil
}

// loadCtrlTargets loads the node's trusted list at the supplied clock time.
func loadCtrlTargets(path string, now time.Time) (*targets.Targets, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read targets %s: %w", path, err)
	}
	list, err := targets.Verify(targets.PublicKeys(), data, now)
	if err != nil {
		return nil, fmt.Errorf("verify targets %s: %w", path, err)
	}
	return list, nil
}

// ping responds to GET /v1/ping with 200 and an empty body.
func (s *ctrlServer) ping(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// validateQuery checks that only the allowed query keys are present and that
// host (and path, for /v1/fetch) are well-formed. The reply never repeats a
// parameter name or value from the request: an unknown key may carry
// anything, including an address the client should not have sent.
func (s *ctrlServer) validateQuery(q url.Values, allowPath bool) error {
	for k, values := range q {
		if k == "host" || (allowPath && k == "path") {
			if len(values) != 1 {
				return errors.New("query parameters must appear once")
			}
			continue
		}
		return errors.New("only host (and path for /v1/fetch) are accepted")
	}
	if q.Get("host") == "" {
		return errors.New("host is required")
	}
	if allowPath {
		switch p := q.Get("path"); p {
		case probe.ControlPathRoot, probe.ControlPathRobots:
		default:
			return errors.New("path must be / or /robots.txt")
		}
	}
	return nil
}

// authorizeHost reports whether the host is in the signed targets list,
// compared case-insensitively.
func (s *ctrlServer) authorizeHost(host string) bool {
	if s.targetsList == nil {
		return false
	}
	for _, item := range s.targetsList.Items {
		if strings.EqualFold(item.Host, host) {
			return true
		}
	}
	return false
}

// rateLimitMiddleware enforces a per-client token bucket of
// rateLimitBucketSize requests per rateLimitWindow. The map key is the
// SHA-256 of the client address, so the address itself is never stored or
// logged.
func (s *ctrlServer) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.allow(r.RemoteAddr) {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// allow consumes one token for the client behind remoteAddr.
func (s *ctrlServer) allow(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	sum := sha256.Sum256([]byte(host))
	key := hex.EncodeToString(sum[:])

	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.buckets[key]
	if !ok {
		if len(s.buckets) >= maxRateBuckets {
			s.sweepExpired(now)
			if len(s.buckets) >= maxRateBuckets {
				return false // карта полна: не допускаем клиента без учёта лимита
			}
		}
		s.buckets[key] = tokenBucket{tokens: rateLimitBucketSize - 1, reset: now.Add(rateLimitWindow)}
		return true
	}
	if now.After(b.reset) {
		b.tokens, b.reset = rateLimitBucketSize, now.Add(rateLimitWindow)
	}
	if b.tokens <= 0 {
		return false
	}
	b.tokens--
	s.buckets[key] = b
	return true
}

// sweepExpired removes buckets whose window has ended.
func (s *ctrlServer) sweepExpired(now time.Time) {
	for k, b := range s.buckets {
		if now.After(b.reset) {
			delete(s.buckets, k)
		}
	}
}

// resolvePublic resolves host and refuses the request if any candidate
// address is a bogon.
func (s *ctrlServer) resolvePublic(ctx context.Context, host string) ([]netip.Addr, error) {
	addrs, err := s.lookupHost(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve host: %w", err)
	}
	if len(addrs) == 0 {
		return nil, errors.New("resolve host: no addresses")
	}
	for _, ip := range addrs {
		if classify.IsBogon(ip.Unmap()) {
			return nil, errors.New("host resolves to a non-public address")
		}
	}
	return addrs, nil
}

// reach responds to GET /v1/reach?host=<host>: it tries a TCP connect to the
// host on port 443.
func (s *ctrlServer) reach(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), s.dialTimeout)
	defer cancel()
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		http.Error(w, "invalid query encoding", http.StatusBadRequest)
		return
	}
	if err := s.validateQuery(q, false); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	host := q.Get("host")
	if !s.authorizeHost(host) {
		http.Error(w, "host is not in the targets list", http.StatusBadRequest)
		return
	}
	addrs, err := s.resolvePublic(ctx, host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	reachable := false
	for _, ip := range addrs {
		c, err := s.dialContext(ctx, "tcp", netip.AddrPortFrom(ip, 443).String())
		if err == nil {
			c.Close()
			reachable = true
			break
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"reachable": reachable})
}

// fetch responds to GET /v1/fetch?host=<host>&path=<path>: it makes the same
// request the http probe makes (HTTPS to port 443, SNI host, no redirects,
// at most probe.MaxBody bytes) and reports status, size and body hash.
func (s *ctrlServer) fetch(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), s.dialTimeout)
	defer cancel()
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		http.Error(w, "invalid query encoding", http.StatusBadRequest)
		return
	}
	if err := s.validateQuery(q, true); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	host := q.Get("host")
	if !s.authorizeHost(host) {
		http.Error(w, "host is not in the targets list", http.StatusBadRequest)
		return
	}
	path := q.Get("path")

	addrs, err := s.resolvePublic(ctx, host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var resp *classify.HTTPResponse
	for _, ip := range addrs {
		target := netip.AddrPortFrom(ip, 443).String()
		tr := &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return s.dialContext(ctx, network, target)
			},
			TLSClientConfig:   &tls.Config{ServerName: host, RootCAs: s.rootCAs, MinVersion: tls.VersionTLS12},
			DisableKeepAlives: true,
		}
		client := &http.Client{
			Transport:     tr,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
		u := url.URL{Scheme: "https", Host: host}
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, u.String()+path, nil)
		if reqErr != nil {
			tr.CloseIdleConnections()
			continue
		}
		req.Header.Set("User-Agent", "mayak")
		httpResp, doErr := client.Do(req)
		if doErr != nil {
			tr.CloseIdleConnections()
			continue
		}
		h := sha256.New()
		n, copyErr := io.Copy(h, io.LimitReader(httpResp.Body, probe.MaxBody))
		httpResp.Body.Close()
		tr.CloseIdleConnections()
		if copyErr != nil {
			continue
		}
		resp = &classify.HTTPResponse{Status: httpResp.StatusCode, Size: n, BodyHash: hex.EncodeToString(h.Sum(nil))}
		break
	}
	if resp == nil {
		http.Error(w, "fetch failed", http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":    resp.Status,
		"size":      resp.Size,
		"body_hash": resp.BodyHash,
	})
}

// anySNIHandler prepares the second listener, which completes a TLS
// handshake for any SNI. With --tls-cert/--tls-key it loads that PEM pair;
// otherwise it generates an ephemeral self-signed certificate and prints its
// SHA-256 fingerprint to stderr. An empty --tls-addr disables the listener
// (nil listener, nil error). It never logs SNI or client addresses.
func anySNIHandler(cfg *Config) (net.Listener, error) {
	if cfg.TLSAddr == "" {
		return nil, nil
	}

	var cert tls.Certificate
	var fingerprint string
	switch {
	case cfg.TLSCert != "" && cfg.TLSKey != "":
		var err error
		cert, err = tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
		if err != nil {
			return nil, fmt.Errorf("load TLS key pair: %w", err)
		}
	case cfg.TLSCert == "" && cfg.TLSKey == "":
		var err error
		cert, fingerprint, err = newSelfSignedCert()
		if err != nil {
			return nil, fmt.Errorf("generate ephemeral cert: %w", err)
		}
	default:
		return nil, errors.New("--tls-cert and --tls-key must be given together")
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return &cert, nil
		},
	}

	ln, err := net.Listen("tcp", cfg.TLSAddr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", cfg.TLSAddr, err)
	}

	if fingerprint != "" {
		fmt.Fprintf(os.Stderr, "any-SNI TLS certificate sha256 fingerprint: %s\n", fingerprint)
	}
	return tls.NewListener(ln, tlsCfg), nil
}

// serveTLSListener accepts connections on the any-SNI listener and closes
// each one right after explicitly completing its lazy TLS handshake.
func serveTLSListener(ln net.Listener) {
	defer ln.Close()
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			if err := c.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
				return
			}
			if tlsConn, ok := c.(*tls.Conn); ok {
				_ = tlsConn.Handshake()
			}
		}(c)
	}
}

// main parses flags, starts the any-SNI TLS listener and the HTTP API.
func main() {
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	srv, err := newCtrlServer(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	if cfg.TLSAddr == "" {
		fmt.Fprintln(os.Stderr, "any-SNI TLS listener disabled (--tls-addr is empty)")
	} else {
		tlsLn, err := anySNIHandler(cfg)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		go serveTLSListener(tlsLn)
	}

	if err := srv.http.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
