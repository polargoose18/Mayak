package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/polargoose18/mayak/internal/classify"
)

// CtrlRequest describes one ctrl test.
type CtrlRequest struct {
	Control ControlClient

	// Anchors are URLs of sites that are always up. At least one is needed.
	Anchors []string
	// Allowlist are URLs of sites that stay reachable in allowlist mode.
	// They are only requested when neither the control node nor an anchor
	// answers.
	Allowlist []string

	// Host is the target's host name, for the control node's own check of it.
	// The node finds the addresses itself.
	Host string

	roots *x509.CertPool // test override for the trusted CAs
}

// CtrlObservation is the result of the ctrl test.
type CtrlObservation struct {
	ControlAlive   bool `json:"control_alive"`
	AnchorsAlive   bool `json:"anchors_alive"`
	AllowlistAlive bool `json:"allowlist_alive"`

	// TargetExternal is the control node's view of the target; empty if the
	// node could not be asked.
	TargetExternal classify.External `json:"target_external,omitempty"`

	Ms int64 `json:"ms"`
}

// ForClassifier returns the observation for the classifier.
func (o CtrlObservation) ForClassifier() classify.Ctrl {
	return classify.Ctrl{
		ControlAlive:   o.ControlAlive,
		AnchorsAlive:   o.AnchorsAlive,
		AllowlistAlive: o.AllowlistAlive,
		TargetExternal: o.TargetExternal,
	}
}

// Ctrl checks that the measurement itself can be trusted: the control node
// answers, at least one anchor site answers, and, when the node is up, what
// it sees of the target. The allowlist sites are only asked when both the
// node and every anchor are down. A site counts as alive if it answers an
// HTTP GET with a status below 500. Everything runs under one 8 second
// deadline, of which the node and the anchors may use the first half;
// failures are results, the error is for a bad request or a cancelled
// context.
func Ctrl(ctx context.Context, req CtrlRequest) (CtrlObservation, error) {
	switch {
	case req.Control.BaseURL == "":
		return CtrlObservation{}, errors.New("ctrl: no control node URL")
	case len(req.Anchors) == 0:
		return CtrlObservation{}, errors.New("ctrl: no anchor sites")
	case req.Host == "":
		return CtrlObservation{}, errors.New("ctrl: no target host")
	}
	runCtx, cancel := context.WithTimeout(ctx, testTimeout)
	defer cancel()

	// A silent control node would use up the whole deadline and leave nothing
	// for the second stage, so the first stage gets half of the time left.
	deadline, _ := runCtx.Deadline()
	firstCtx, cancelFirst := context.WithTimeout(runCtx, time.Until(deadline)/2)
	defer cancelFirst()

	elapsed := start()
	var obs CtrlObservation
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		obs.ControlAlive = req.Control.Ping(firstCtx) == nil
	}()
	go func() {
		defer wg.Done()
		obs.AnchorsAlive = anyAlive(firstCtx, req.Anchors, req.roots)
	}()
	wg.Wait()

	if obs.ControlAlive {
		if ext, err := req.Control.Reach(runCtx, req.Host); err == nil {
			obs.TargetExternal = ext
		}
	}
	if !obs.ControlAlive && !obs.AnchorsAlive {
		obs.AllowlistAlive = anyAlive(runCtx, req.Allowlist, req.roots)
	}
	obs.Ms = elapsed()

	if err := cancelled("ctrl", ctx); err != nil {
		return CtrlObservation{}, err
	}
	return obs, nil
}

// anyAlive requests all URLs concurrently and reports whether one is alive.
func anyAlive(ctx context.Context, urls []string, roots *x509.CertPool) bool {
	alive := make([]bool, len(urls))
	var wg sync.WaitGroup
	for i, u := range urls {
		wg.Add(1)
		go func() {
			defer wg.Done()
			alive[i] = siteAlive(ctx, u, roots)
		}()
	}
	wg.Wait()
	for _, a := range alive {
		if a {
			return true
		}
	}
	return false
}

func siteAlive(ctx context.Context, rawURL string, roots *x509.CertPool) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "mayak")
	resp, err := newClient(roots).Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode < 500
}

// newClient returns an HTTP client that does not follow redirects, does not
// use proxies from the environment and does not keep connections.
func newClient(roots *x509.CertPool) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}
