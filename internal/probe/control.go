package probe

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"

	"github.com/polargoose18/mayak/internal/classify"
)

// ControlClient talks to the control node (SPEC section 4). The protocol is
// a proposal for cmd/mayak-ctrl, which does not exist yet; all of it lives in
// this file so it can be changed in one place:
//
//	GET /v1/ping
//	    200 when the node is up.
//	GET /v1/reach?ip=<ip>&port=<port>
//	    200 {"reachable": bool}: the node tries a TCP connect to ip:port
//	    from outside the filtered zone.
//	GET /v1/fetch?host=<host>&ip=<ip>&port=<port>&path=<path>
//	    200 {"status": int, "size": int, "body_hash": "<hex sha-256>"}: the
//	    node makes the same request as the http test (HTTPS to ip:port with
//	    SNI host, no redirects, at most MaxBody bytes) and describes the
//	    response. Any other status means it could not.
//
// The node must serve /v1/reach and /v1/fetch only for targets from the
// signed list; otherwise it would be an open scanner. It receives no
// information about the user except what any connection carries.
type ControlClient struct {
	BaseURL string // e.g. https://ctrl.example:8443

	roots *x509.CertPool // test override for the trusted CAs
}

const maxControlReply = 64 << 10

// Ping reports nil if the node answers /v1/ping with 200.
func (c ControlClient) Ping(ctx context.Context) error {
	return c.get(ctx, "/v1/ping", nil, nil)
}

// Reach asks the node whether it can connect to addr from outside.
func (c ControlClient) Reach(ctx context.Context, addr netip.AddrPort) (classify.External, error) {
	var reply struct {
		Reachable *bool `json:"reachable"`
	}
	q := url.Values{"ip": {addr.Addr().String()}, "port": {strconv.Itoa(int(addr.Port()))}}
	if err := c.get(ctx, "/v1/reach", q, &reply); err != nil {
		return "", err
	}
	switch {
	case reply.Reachable == nil:
		return "", errors.New("control reach: reply has no reachable field")
	case *reply.Reachable:
		return classify.ExternalReachable, nil
	}
	return classify.ExternalUnreachable, nil
}

// Reference asks the node for its response to the http test's request.
func (c ControlClient) Reference(ctx context.Context, host, path string, addr netip.AddrPort) (*classify.HTTPResponse, error) {
	var reply struct {
		Status   int    `json:"status"`
		Size     int64  `json:"size"`
		BodyHash string `json:"body_hash"`
	}
	q := url.Values{
		"host": {host}, "path": {path},
		"ip": {addr.Addr().String()}, "port": {strconv.Itoa(int(addr.Port()))},
	}
	if err := c.get(ctx, "/v1/fetch", q, &reply); err != nil {
		return nil, err
	}
	if reply.Status == 0 || reply.BodyHash == "" {
		return nil, errors.New("control fetch: incomplete reply")
	}
	return &classify.HTTPResponse{Status: reply.Status, Size: reply.Size, BodyHash: reply.BodyHash}, nil
}

// get calls the node and decodes a JSON reply into out (if not nil). It does
// not follow redirects and does not use proxies from the environment.
func (c ControlClient) get(ctx context.Context, path string, query url.Values, out any) error {
	if c.BaseURL == "" {
		return errors.New("control: no base URL")
	}
	u := c.BaseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return fmt.Errorf("control %s: %w", path, err)
	}
	resp, err := newClient(c.roots).Do(req)
	if err != nil {
		return fmt.Errorf("control %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("control %s: status %d", path, resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxControlReply))
	if err != nil {
		return fmt.Errorf("control %s: %w", path, err)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("control %s: bad reply: %w", path, err)
	}
	return nil
}
