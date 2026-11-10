package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/polargoose18/mayak/internal/probe"
	"github.com/polargoose18/mayak/internal/targets"
)

func TestRejectMalformedQuery(t *testing.T) {
	for _, endpoint := range []string{"/v1/reach?host=example.org", "/v1/fetch?host=example.org&path=/"} {
		for _, suffix := range []string{"&ip=%ZZ", "&port=%ZZ", "&host=%ZZ", "&host=evil.invalid", "&path=/robots.txt"} {
			t.Run(endpoint+suffix, func(t *testing.T) {
				list := sampleTargets("example.org")
				srv := newCtrlServerWithTargets(&Config{}, &list)
				srv.lookupHost = func(context.Context, string) ([]netip.Addr, error) {
					t.Error("invalid query reached DNS lookup")
					return nil, fmt.Errorf("unexpected lookup")
				}
				reply := httptest.NewRecorder()
				srv.http.Handler.ServeHTTP(reply, httptest.NewRequest(http.MethodGet, endpoint+suffix, nil))
				if reply.Code != http.StatusBadRequest {
					t.Fatalf("status %d, want 400; body %q", reply.Code, reply.Body.String())
				}
			})
		}
	}
}

func TestRateLimitAtCapacity(t *testing.T) {
	srv := newCtrlServerWithTargets(&Config{}, nil)
	for i := 0; i < maxRateBuckets; i++ {
		addr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i)}), 1234)
		req := httptest.NewRequest(http.MethodGet, "/v1/ping", nil)
		req.RemoteAddr = addr.String()
		reply := httptest.NewRecorder()
		srv.http.Handler.ServeHTTP(reply, req)
		if reply.Code != http.StatusOK {
			t.Fatalf("filling bucket %d: status %d", i, reply.Code)
		}
	}
	for i := 0; i < 21; i++ {
		req := httptest.NewRequest(http.MethodGet, "/v1/ping", nil)
		req.RemoteAddr = "203.0.113.77:1234"
		reply := httptest.NewRecorder()
		srv.http.Handler.ServeHTTP(reply, req)
		if reply.Code != http.StatusTooManyRequests {
			t.Fatalf("fresh client request %d at full capacity: status %d, want 429", i+1, reply.Code)
		}
	}
	if len(srv.buckets) != maxRateBuckets {
		t.Fatalf("bucket count %d, want %d", len(srv.buckets), maxRateBuckets)
	}
	// Existing clients retain their remaining allowance at capacity.
	req := httptest.NewRequest(http.MethodGet, "/v1/ping", nil)
	req.RemoteAddr = "198.18.0.0:5678"
	reply := httptest.NewRecorder()
	srv.http.Handler.ServeHTTP(reply, req)
	if reply.Code != http.StatusOK {
		t.Fatalf("tracked client at capacity: status %d, want 200", reply.Code)
	}
}

func TestResolveBogonRefusal(t *testing.T) {
	for _, ips := range [][]string{{"127.0.0.1"}, {"10.0.0.1"}, {"::1"}, {"::ffff:192.168.1.1"}, {"1.1.1.1", "10.0.0.1"}} {
		for _, endpoint := range []string{"/v1/reach?host=example.org", "/v1/fetch?host=example.org&path=/"} {
			t.Run(fmt.Sprint(ips)+endpoint, func(t *testing.T) {
				list := sampleTargets("example.org")
				srv := newCtrlServerWithTargets(&Config{}, &list)
				srv.lookupHost = func(context.Context, string) ([]netip.Addr, error) {
					var addrs []netip.Addr
					for _, ip := range ips {
						addrs = append(addrs, netip.MustParseAddr(ip))
					}
					return addrs, nil
				}
				srv.dialContext = func(context.Context, string, string) (net.Conn, error) {
					t.Error("bogon DNS answer reached dial")
					return nil, fmt.Errorf("unexpected dial")
				}
				reply := httptest.NewRecorder()
				srv.http.Handler.ServeHTTP(reply, httptest.NewRequest(http.MethodGet, endpoint, nil))
				if reply.Code != http.StatusBadRequest {
					t.Fatalf("status %d, want 400", reply.Code)
				}
			})
		}
	}
}

func TestBogonDialGuard(t *testing.T) {
	for _, address := range []string{"127.0.0.1:443", "10.0.0.1:443", "[::1]:443", "[::ffff:192.168.1.1]:443"} {
		if err := refuseBogonDial("tcp", address, nil); err == nil {
			t.Errorf("dial guard accepted %s", address)
		}
	}
	if err := refuseBogonDial("tcp", "1.1.1.1:443", nil); err != nil {
		t.Fatalf("dial guard rejected public address: %v", err)
	}
}

func TestFetchOversizedBody(t *testing.T) {
	cert, err := newSelfSignedCertForNames([]string{"example.org"})
	if err != nil {
		t.Fatal(err)
	}
	// A distinct suffix proves the hash covers only the retained prefix.
	prefix := bytes.Repeat([]byte("x"), int(probe.MaxBody))
	body := append(append([]byte(nil), prefix...), []byte("excluded suffix")...)
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/robots.txt" || r.TLS.ServerName != "example.org" {
			t.Errorf("upstream request path %q, SNI %q", r.URL.Path, r.TLS.ServerName)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(body)
	}))
	upstream.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	upstream.StartTLS()
	defer upstream.Close()

	cts := startCtrlTestServer(t, []string{"example.org"})
	cts.server.rootCAs = x509.NewCertPool()
	cts.server.rootCAs.AddCert(cert.Leaf)
	cts.server.lookupHost = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
	}
	cts.server.dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "1.1.1.1:443" {
			t.Errorf("destination %q, want pinned public IP", address)
		}
		return (&net.Dialer{}).DialContext(ctx, network, upstream.Listener.Addr().String())
	}
	resp, err := http.Get(cts.url + "/v1/fetch?host=example.org&path=/robots.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, body %q", resp.StatusCode, data)
	}
	var reply map[string]any
	if err := json.Unmarshal(data, &reply); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(prefix)
	if len(reply) != 3 || reply["status"] != float64(http.StatusCreated) || reply["size"] != float64(probe.MaxBody) || reply["body_hash"] != hex.EncodeToString(hash[:]) {
		t.Fatalf("unexpected fetch reply: %s", data)
	}
}

func TestSignedTargetsFreshness(t *testing.T) {
	path := "../../targets/targets.signed.json"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	list, err := targets.Open(targets.PublicKeys(), data)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		now       time.Time
		wantError bool
	}{
		{"fresh", list.Expires.Add(-time.Hour), false},
		{"expired", list.Expires.Add(time.Second), true},
		{"future-invalid", list.Expires.Add(-365 * 24 * time.Hour), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadCtrlTargets(path, t.TempDir(), tc.now)
			if (err != nil) != tc.wantError {
				t.Fatalf("load error %v, wantError %v", err, tc.wantError)
			}
		})
	}
}
