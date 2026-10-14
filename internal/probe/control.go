package probe

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/polargoose18/mayak/internal/classify"
)

// ControlClient talks to the control node (SPEC section 4). The protocol is
// a proposal for cmd/mayak-ctrl, which does not exist yet; all of it lives in
// this file so it can be changed in one place.
//
// The client names only the target's host. It never sends an IP address or a
// port: the node looks the name up itself and connects itself, so it cannot be
// used to scan an arbitrary address.
//
//	GET /v1/ping
//	    200 when the node is up.
//	GET /v1/reach?host=<host>
//	    200 {"reachable": bool}: the node tries a TCP connect to the host on
//	    port 443 from outside the filtered zone.
//	GET /v1/fetch?host=<host>&path=<path>
//	    path is ControlPathRoot or ControlPathRobots, nothing else.
//	    200 {"status": int, "size": int, "body_hash": "<hex sha-256>"}: the
//	    node makes the same request as the http test (HTTPS on port 443 with
//	    SNI host, no redirects, at most MaxBody bytes, the body decoded as
//	    the agent's HTTP client decodes it) and describes the response. Any
//	    other status means it could not.
//
// Requirements for mayak-ctrl (the client cannot enforce them):
//
//   - It serves a host only if the host is in its own copy of the signed
//     targets list (verified like the agent does). Any other host is refused.
//   - It connects only to port 443 and only to public addresses, that is, no
//     private, loopback, link-local, CGNAT or other bogon address, whatever
//     the name resolves to, and it re-checks the address it actually
//     connects to. It ignores and refuses requests that carry an ip or a
//     port parameter.
//   - It rate-limits requests and caps the size it fetches at MaxBody.
//   - It logs no client addresses.
//
// Consequences: the node's view of the target ("from outside") may come from
// another CDN node than the agent's. For /v1/fetch the path must be static,
// otherwise the body hashes differ; Reference enforces it with
// ErrBadControlPath, and the node should refuse any other path as well.
type ControlClient struct {
	BaseURL string // e.g. https://ctrl.example:8443

	roots *x509.CertPool // test override for the trusted CAs
}

// The only paths /v1/fetch is asked for: pages that are the same for every
// visitor, so the body hashes of the node and of the agent can agree.
const (
	ControlPathRoot   = "/"
	ControlPathRobots = "/robots.txt"
)

// ErrBadControlPath is returned by Reference for a path that is not one of
// ControlPathRoot and ControlPathRobots. Nothing is sent then.
var ErrBadControlPath = errors.New("control fetch: path must be / or /robots.txt")

const maxControlReply = 64 << 10

// Ping reports nil if the node answers /v1/ping with 200.
func (c ControlClient) Ping(ctx context.Context) error {
	return c.get(ctx, "/v1/ping", nil, nil)
}

// Reach asks the node whether it can connect to the target from outside.
func (c ControlClient) Reach(ctx context.Context, host string) (classify.External, error) {
	var reply struct {
		Reachable *bool `json:"reachable"`
	}
	if err := c.get(ctx, "/v1/reach", url.Values{"host": {host}}, &reply); err != nil {
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
func (c ControlClient) Reference(ctx context.Context, host, path string) (*classify.HTTPResponse, error) {
	if path != ControlPathRoot && path != ControlPathRobots {
		return nil, ErrBadControlPath // the value is not repeated: it may be anything
	}
	var reply struct {
		Status   int    `json:"status"`
		Size     int64  `json:"size"`
		BodyHash string `json:"body_hash"`
	}
	if err := c.get(ctx, "/v1/fetch", url.Values{"host": {host}, "path": {path}}, &reply); err != nil {
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
