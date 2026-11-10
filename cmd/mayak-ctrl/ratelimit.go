package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"time"
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
