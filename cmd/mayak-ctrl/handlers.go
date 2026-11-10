package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"github.com/polargoose18/mayak/internal/classify"
	"github.com/polargoose18/mayak/internal/probe"
)

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
	if s.targetsList == nil || !s.now().Before(s.targetsList.Expires) {
		return false
	}
	for _, item := range s.targetsList.Items {
		if strings.EqualFold(item.Host, host) {
			return true
		}
	}
	return false
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
