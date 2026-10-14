package probe

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/polargoose18/mayak/internal/classify"
	"github.com/polargoose18/mayak/testbed/mockdpi"
)

func runHTTP(t *testing.T, timeout time.Duration, env *mockdpi.Env, req HTTPRequest) HTTPObservation {
	t.Helper()
	req.roots = env.CertPool
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	obs, err := HTTP(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	return obs
}

func httpReq(t *testing.T, target string) HTTPRequest {
	return HTTPRequest{Addr: addr(t, target), Host: dnsHost, Path: "/page"}
}

func TestHTTPEcho(t *testing.T) {
	env := mockdpi.Start(t, mockdpi.Config{Control: true, CertNames: []string{dnsHost}})
	obs := runHTTP(t, generous, env, httpReq(t, env.ControlTLS))
	if obs.Result != classify.HTTPResponded || obs.Response.Status != 200 {
		t.Fatalf("obs = %+v", obs)
	}
	// The echo describes the request, which shows that the connection went to
	// the given address with the right SNI, host and path.
	want := `{"method":"GET","path":"/page","host":"` + dnsHost + `","sni":"` + dnsHost + `"}` + "\n"
	sum := sha256.Sum256([]byte(want))
	if obs.Response.BodyHash != hex.EncodeToString(sum[:]) || obs.Response.Size != int64(len(want)) {
		t.Errorf("response = %+v, want size %d hash %x", obs.Response, len(want), sum)
	}
	if obs.MatchesKnownStub {
		t.Error("no stub hashes were given")
	}

	ref := obs.Response
	c := obs.ForClassifier(&ref)
	if c.Result != classify.HTTPResponded || c.Reference != &ref || c.Response != obs.Response {
		t.Errorf("ForClassifier = %+v", c)
	}
}

func TestHTTPDefaultPath(t *testing.T) {
	env := mockdpi.Start(t, mockdpi.Config{Control: true, CertNames: []string{dnsHost}})
	r := httpReq(t, env.ControlTLS)
	r.Path = ""
	obs := runHTTP(t, generous, env, r)
	want := `{"method":"GET","path":"/","host":"` + dnsHost + `","sni":"` + dnsHost + `"}` + "\n"
	if obs.Response.Size != int64(len(want)) {
		t.Errorf("response = %+v", obs.Response)
	}
}

func TestHTTPStubPage(t *testing.T) {
	env := mockdpi.Start(t, mockdpi.Config{StubPage: true, CertNames: []string{dnsHost}})
	body := "<html><body><h1>" + mockdpi.StubBody + "</h1></body></html>"
	sum := sha256.Sum256([]byte(body))
	stubHash := hex.EncodeToString(sum[:])

	r := httpReq(t, env.StubPageTLS)
	r.KnownStubHashes = []string{"00ff", strings.ToUpper(stubHash)} // case does not matter
	obs := runHTTP(t, generous, env, r)
	if obs.Response.BodyHash != stubHash || !obs.MatchesKnownStub {
		t.Errorf("obs = %+v, want stub %s", obs, stubHash)
	}

	r.KnownStubHashes = []string{"00ff"}
	if obs := runHTTP(t, generous, env, r); obs.MatchesKnownStub {
		t.Error("unknown hash must not match")
	}
}

func TestHTTPFailures(t *testing.T) {
	env := mockdpi.Start(t, mockdpi.Config{
		ResetAfterHello: &mockdpi.ResetAfterHelloConfig{BlockedSNI: []string{dnsHost}},
		Blackhole:       true,
		StubPage:        true,
		Control:         true,
		ClosedPort:      true,
		CertNames:       []string{dnsHost},
	})
	tests := []struct {
		name    string
		target  string
		host    string
		timeout time.Duration
		want    classify.HTTPResult
	}{
		{"reset after the hello", env.ResetAfterHello, dnsHost, generous, classify.HTTPReset},
		{"silent server", env.Blackhole, dnsHost, short, classify.HTTPTimeout},
		{"connection refused", env.ClosedPort, dnsHost, generous, classify.HTTPOther},
		{"plain HTTP on a TLS port", env.StubPage, dnsHost, generous, classify.HTTPOther},
		{"certificate not valid for the host", env.ControlTLS, "other.example", generous, classify.HTTPOther},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httpReq(t, tc.target)
			r.Host = tc.host
			obs := runHTTP(t, tc.timeout, env, r)
			if obs.Result != tc.want {
				t.Errorf("result = %q, want %q", obs.Result, tc.want)
			}
			if obs.Response != (classify.HTTPResponse{}) {
				t.Errorf("a failed request has a response: %+v", obs.Response)
			}
		})
	}
}

// tlsServer starts an HTTPS server with its own certificate (valid for
// example.com) and returns its address and a pool that trusts it.
func tlsServer(t *testing.T, h http.HandlerFunc) (netip.AddrPort, *x509.CertPool) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return srv.Listener.Addr().(*net.TCPAddr).AddrPort(), pool
}

func TestHTTPRedirectIsNotFollowedAndBodyIsCapped(t *testing.T) {
	a, pool := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, "https://elsewhere.invalid/", http.StatusFound)
		case "/big":
			_, _ = w.Write([]byte(strings.Repeat("x", 2*MaxBody)))
		case "/403":
			w.WriteHeader(http.StatusForbidden)
		}
	})
	do := func(path string) HTTPObservation {
		ctx, cancel := context.WithTimeout(context.Background(), generous)
		defer cancel()
		obs, err := HTTP(ctx, HTTPRequest{Addr: a, Host: "example.com", Path: path, roots: pool})
		if err != nil {
			t.Fatal(err)
		}
		return obs
	}
	if obs := do("/redirect"); obs.Response.Status != http.StatusFound {
		t.Errorf("redirect: status = %d, want 302 (not followed)", obs.Response.Status)
	}
	if obs := do("/big"); obs.Response.Size != MaxBody {
		t.Errorf("big: size = %d, want %d", obs.Response.Size, MaxBody)
	}
	if obs := do("/403"); obs.Response.Status != 403 || obs.Result != classify.HTTPResponded {
		t.Errorf("403: %+v", obs)
	}
}

func TestHTTPBodyReadFailure(t *testing.T) {
	// The server announces a body and then drops the connection.
	a, pool := tlsServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "1000")
		_, _ = w.Write([]byte("partial"))
		w.(http.Flusher).Flush() // headers are out, then the body is cut
		panic(http.ErrAbortHandler)
	})
	ctx, cancel := context.WithTimeout(context.Background(), generous)
	defer cancel()
	obs, err := HTTP(ctx, HTTPRequest{Addr: a, Host: "example.com", roots: pool})
	if err != nil {
		t.Fatal(err)
	}
	if obs.Result != classify.HTTPOther {
		t.Errorf("result = %q, want other", obs.Result)
	}
}

func TestHTTPPathThatCannotBeSent(t *testing.T) {
	env := mockdpi.Start(t, mockdpi.Config{Control: true, CertNames: []string{dnsHost}})
	r := httpReq(t, env.ControlTLS)
	r.Path = "/a\x7fb" // a control character is not allowed in a URL
	if obs := runHTTP(t, generous, env, r); obs.Result != classify.HTTPOther {
		t.Errorf("result = %q, want other", obs.Result)
	}
}

func TestHTTPFailureMapping(t *testing.T) {
	tests := []struct {
		err  error
		want classify.HTTPResult
	}{
		{context.DeadlineExceeded, classify.HTTPTimeout},
		{syscall.ECONNRESET, classify.HTTPReset},
		{syscall.EPIPE, classify.HTTPOther},
		{errors.New("boom"), classify.HTTPOther},
	}
	for _, tc := range tests {
		if got := httpFailure(tc.err); got != tc.want {
			t.Errorf("httpFailure(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}

func TestHTTPValidationAndCancel(t *testing.T) {
	good := HTTPRequest{Addr: netip.MustParseAddrPort("127.0.0.1:443"), Host: "example.com", Path: "/"}
	tests := map[string]func(r *HTTPRequest){
		"zero address":    func(r *HTTPRequest) { r.Addr = netip.AddrPort{} },
		"no port":         func(r *HTTPRequest) { r.Addr = netip.AddrPortFrom(r.Addr.Addr(), 0) },
		"empty host":      func(r *HTTPRequest) { r.Host = "" },
		"host with path":  func(r *HTTPRequest) { r.Host = "example.com/x" },
		"host with space": func(r *HTTPRequest) { r.Host = "exa mple.com" },
		"relative path":   func(r *HTTPRequest) { r.Path = "page" },
	}
	for name, edit := range tests {
		t.Run(name, func(t *testing.T) {
			r := good
			edit(&r)
			if _, err := HTTP(context.Background(), r); err == nil {
				t.Error("want error")
			}
		})
	}

	env := mockdpi.Start(t, mockdpi.Config{Control: true, CertNames: []string{dnsHost}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := httpReq(t, env.ControlTLS)
	r.roots = env.CertPool
	if _, err := HTTP(ctx, r); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}
