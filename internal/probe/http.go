package probe

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"

	"github.com/polargoose18/mayak/internal/classify"
)

// MaxBody is the number of body bytes read and hashed. The control node must
// apply the same cap when it makes the reference response.
const MaxBody = 1 << 20

// HTTPRequest describes one http test: a GET of a small path over HTTPS to
// the trusted IP of the target.
type HTTPRequest struct {
	Addr netip.AddrPort // trusted IP of the target (port TLSPort in production)
	Host string         // name for SNI, certificate check and the Host header
	Path string         // starts with "/"; empty means "/"

	// KnownStubHashes are hex SHA-256 hashes of block pages known to be
	// served by operators.
	KnownStubHashes []string

	roots *x509.CertPool // test override for the trusted CAs
}

// HTTPObservation is the result of the http test. It holds no body, only its
// size and hash.
type HTTPObservation struct {
	Result           classify.HTTPResult   `json:"result"`
	Response         classify.HTTPResponse `json:"response"`
	MatchesKnownStub bool                  `json:"matches_known_stub"`
	Ms               int64                 `json:"ms"`
}

// ForClassifier converts the observation to the classifier's input; ref is
// the control node's response for the same request, or nil.
func (o HTTPObservation) ForClassifier(ref *classify.HTTPResponse) classify.HTTP {
	return classify.HTTP{
		Result:           o.Result,
		Response:         o.Response,
		Reference:        ref,
		MatchesKnownStub: o.MatchesKnownStub,
	}
}

// HTTP fetches the path and reports status, body size and body hash. It does
// not follow redirects and does not use proxies from the environment. A
// failed request is a result; the error is for a bad request or a cancelled
// context.
func HTTP(ctx context.Context, req HTTPRequest) (HTTPObservation, error) {
	path, err := req.validate()
	if err != nil {
		return HTTPObservation{}, fmt.Errorf("http: %w", err)
	}
	runCtx, cancel := context.WithTimeout(ctx, testTimeout)
	defer cancel()

	elapsed := start()
	resp, err := fetch(runCtx, req.Addr, req.Host, path, req.roots)
	obs := HTTPObservation{Ms: elapsed()}
	if err != nil {
		obs.Result = httpFailure(err)
	} else {
		obs.Result = classify.HTTPResponded
		obs.Response = *resp
		obs.MatchesKnownStub = contains(req.KnownStubHashes, resp.BodyHash)
	}
	if err := cancelled("http", ctx); err != nil {
		return HTTPObservation{}, err
	}
	return obs, nil
}

func (r HTTPRequest) validate() (path string, err error) {
	switch {
	case !r.Addr.IsValid() || r.Addr.Port() == 0:
		return "", errors.New("invalid address")
	case r.Host == "" || strings.ContainsAny(r.Host, "/ \t\r\n"):
		return "", errors.New("invalid host")
	case r.Path != "" && !strings.HasPrefix(r.Path, "/"):
		return "", errors.New("path must start with /")
	}
	if r.Path == "" {
		return "/", nil
	}
	return r.Path, nil
}

// fetch does the GET. The connection goes to addr whatever the URL says, the
// way the user's browser would after a trusted lookup.
func fetch(ctx context.Context, addr netip.AddrPort, host, path string, roots *x509.CertPool) (*classify.HTTPResponse, error) {
	var d net.Dialer
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return d.DialContext(ctx, network, addr.String())
		},
		TLSClientConfig:   &tls.Config{ServerName: host, RootCAs: roots, MinVersion: tls.VersionTLS12},
		DisableKeepAlives: true,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Transport:     tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	u := url.URL{Scheme: "https", Host: host}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String()+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "mayak")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(resp.Body, MaxBody))
	if err != nil {
		return nil, err
	}
	return &classify.HTTPResponse{Status: resp.StatusCode, Size: n, BodyHash: hex.EncodeToString(h.Sum(nil))}, nil
}

// httpFailure maps a request error to a result by error type.
func httpFailure(err error) classify.HTTPResult {
	switch {
	case isTimeout(err):
		return classify.HTTPTimeout
	case errors.Is(err, syscall.ECONNRESET):
		return classify.HTTPReset
	}
	return classify.HTTPOther
}

func contains(list []string, hash string) bool {
	for _, h := range list {
		if strings.EqualFold(h, hash) {
			return true
		}
	}
	return false
}
