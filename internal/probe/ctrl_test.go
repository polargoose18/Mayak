package probe

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/polargoose18/mayak/internal/classify"
	"github.com/polargoose18/mayak/testbed/mockdpi"
)

// fakeControl is a control node that speaks the protocol in control.go and
// keeps its requirements: it serves only hosts from its list, and refuses any
// request that carries an ip or a port other than 443. It records the
// queries it gets.
type fakeControl struct {
	srv       *httptest.Server
	reachable bool
	hosts     []string // the hosts of its signed list

	reachQuery atomic.Value // url.Values of the last /v1/reach
	fetchQuery atomic.Value // url.Values of the last /v1/fetch
	pingStatus int
	rawReach   string // if set, sent as the /v1/reach body

	// fetchFrom, if valid, is the clean server /v1/fetch really fetches from:
	// the node sees the page from outside the filtered zone.
	fetchFrom netip.AddrPort
	roots     *x509.CertPool
}

func (f *fakeControl) client() ControlClient { return ControlClient{BaseURL: f.srv.URL} }

func newFakeControl(t *testing.T, reachable bool) *fakeControl {
	t.Helper()
	f := &fakeControl{
		reachable:  reachable,
		pingStatus: http.StatusOK,
		hosts:      []string{dnsHost, "example.org", "example.com", "intercepted.example"},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/ping", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(f.pingStatus) })
	mux.HandleFunc("/v1/reach", func(w http.ResponseWriter, r *http.Request) {
		f.reachQuery.Store(r.URL.Query())
		if !f.admit(w, r) {
			return
		}
		if f.rawReach != "" {
			_, _ = w.Write([]byte(f.rawReach))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]bool{"reachable": f.reachable})
	})
	mux.HandleFunc("/v1/fetch", func(w http.ResponseWriter, r *http.Request) {
		f.fetchQuery.Store(r.URL.Query())
		if !f.admit(w, r) {
			return
		}
		if !f.fetchFrom.IsValid() {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		q := r.URL.Query()
		resp, err := fetch(r.Context(), f.fetchFrom, q.Get("host"), q.Get("path"), f.roots)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": resp.Status, "size": resp.Size, "body_hash": resp.BodyHash})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// admit applies what the control node requires of a request: no ip, no port
// other than 443, and a host from its list.
func (f *fakeControl) admit(w http.ResponseWriter, r *http.Request) bool {
	q := r.URL.Query()
	switch {
	case q.Has("ip"):
		http.Error(w, "ip is not accepted", http.StatusBadRequest)
	case q.Has("port") && q.Get("port") != "443":
		http.Error(w, "only port 443", http.StatusBadRequest)
	case !slices.Contains(f.hosts, q.Get("host")):
		http.Error(w, "host is not in the list", http.StatusForbidden)
	default:
		return true
	}
	return false
}

func TestControlClient(t *testing.T) {
	f := newFakeControl(t, true)
	c := f.client()
	ctx := context.Background()

	if err := c.Ping(ctx); err != nil {
		t.Errorf("Ping: %v", err)
	}

	ext, err := c.Reach(ctx, "example.org")
	if err != nil || ext != classify.ExternalReachable {
		t.Errorf("Reach = %q, %v", ext, err)
	}
	// The client names the host and nothing else: no ip, no port.
	if q := f.reachQuery.Load().(url.Values); len(q) != 1 || q.Get("host") != "example.org" {
		t.Errorf("reach query = %v, want only host=example.org", q)
	}

	f.reachable = false
	if ext, err := c.Reach(ctx, "example.org"); err != nil || ext != classify.ExternalUnreachable {
		t.Errorf("Reach = %q, %v", ext, err)
	}

	// A host that is not in the node's list is refused.
	if ext, err := c.Reach(ctx, "not-in-the-list.example"); err == nil || ext != "" {
		t.Errorf("unknown host: Reach = %q, %v; want an error", ext, err)
	}
}

// The control node must not take an address from the client: this is the
// requirement that keeps it from being an open scanner. The fake enforces it
// the way mayak-ctrl must.
func TestControlNodeRefusesAddressesAndOtherPorts(t *testing.T) {
	f := newFakeControl(t, true)
	get := func(path string) int {
		resp, err := http.Get(f.srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	tests := []struct {
		query string
		want  int
	}{
		{"?host=example.org", http.StatusOK},
		{"?host=example.org&ip=169.254.169.254", http.StatusBadRequest},
		{"?host=example.org&ip=203.0.113.5&port=443", http.StatusBadRequest},
		{"?host=example.org&port=8080", http.StatusBadRequest},
		{"?host=example.org&port=22", http.StatusBadRequest},
		{"?host=example.org&port=443", http.StatusOK},
		{"?host=internal.example&ip=10.0.0.5", http.StatusBadRequest},
		{"?host=not-in-the-list.example", http.StatusForbidden},
		{"", http.StatusForbidden},
	}
	for _, tc := range tests {
		if got := get("/v1/reach" + tc.query); got != tc.want {
			t.Errorf("/v1/reach%s: status %d, want %d", tc.query, got, tc.want)
		}
	}
	if got := get("/v1/fetch?host=example.org&path=/&ip=10.0.0.5"); got != http.StatusBadRequest {
		t.Errorf("/v1/fetch with ip: status %d, want 400", got)
	}
	if got := get("/v1/fetch?host=not-in-the-list.example&path=/"); got != http.StatusForbidden {
		t.Errorf("/v1/fetch with an unknown host: status %d, want 403", got)
	}
}

func TestControlClientErrors(t *testing.T) {
	f := newFakeControl(t, true)
	c := f.client()
	ctx := context.Background()

	f.pingStatus = http.StatusServiceUnavailable
	if err := c.Ping(ctx); err == nil {
		t.Error("Ping on 503: want error")
	}

	for name, body := range map[string]string{"no field": `{}`, "bad json": `nope`, "wrong type": `{"reachable":"yes"}`} {
		f.rawReach = body
		if ext, err := c.Reach(ctx, "example.org"); err == nil || ext != "" {
			t.Errorf("%s: Reach = %q, %v; want error", name, ext, err)
		}
	}

	if err := (ControlClient{}).Ping(ctx); err == nil {
		t.Error("no base URL: want error")
	}
	if err := (ControlClient{BaseURL: "http://127.0.0.1:1"}).Ping(ctx); err == nil {
		t.Error("refused: want error")
	}
	if err := (ControlClient{BaseURL: "://bad"}).Ping(ctx); err == nil {
		t.Error("bad URL: want error")
	}
}

func TestControlClientTruncatedReply(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "100")
		_, _ = w.Write([]byte(`{"reach`))
		w.(http.Flusher).Flush()
		panic(http.ErrAbortHandler)
	}))
	defer srv.Close()
	_, err := ControlClient{BaseURL: srv.URL}.Reach(context.Background(), "example.org")
	if err == nil {
		t.Error("truncated reply: want error")
	}
}

func TestControlClientReference(t *testing.T) {
	var got atomic.Value
	reply := `{"status":200,"size":12,"body_hash":"abc"}`
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Store(r.URL.Query())
		w.WriteHeader(status)
		_, _ = w.Write([]byte(reply))
	}))
	defer srv.Close()
	c := ControlClient{BaseURL: srv.URL}

	ref, err := c.Reference(context.Background(), "example.org", "/p?x=1")
	if err != nil {
		t.Fatal(err)
	}
	if *ref != (classify.HTTPResponse{Status: 200, Size: 12, BodyHash: "abc"}) {
		t.Errorf("ref = %+v", ref)
	}
	// The client names the host and the path, no ip and no port.
	if q := got.Load().(url.Values); len(q) != 2 || q.Get("host") != "example.org" || q.Get("path") != "/p?x=1" {
		t.Errorf("query = %v, want only host and path", q)
	}

	reply = `{"status":0}`
	if _, err := c.Reference(context.Background(), "example.org", "/"); err == nil {
		t.Error("incomplete reply: want error")
	}
	status, reply = http.StatusBadGateway, `{}`
	if _, err := c.Reference(context.Background(), "example.org", "/"); err == nil {
		t.Error("502: want error")
	}
}

func anchorURL(env *mockdpi.Env) string { return "https://" + env.ControlTLS + "/" }

func runCtrl(t *testing.T, env *mockdpi.Env, req CtrlRequest, useShort bool) CtrlObservation {
	t.Helper()
	req.roots = env.CertPool
	req.Control.roots = env.CertPool
	timeout := generous
	if useShort {
		timeout = short
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	obs, err := Ctrl(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if obs.Ms < 0 {
		t.Errorf("ms = %d", obs.Ms)
	}
	return obs
}

func TestCtrlAllAlive(t *testing.T) {
	env := mockdpi.Start(t, mockdpi.Config{Control: true})
	for _, reachable := range []bool{true, false} {
		f := newFakeControl(t, reachable)
		var asked atomic.Int32
		allow := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { asked.Add(1) }))
		defer allow.Close()

		obs := runCtrl(t, env, CtrlRequest{
			Control:   f.client(),
			Anchors:   []string{anchorURL(env)},
			Allowlist: []string{allow.URL},
			Host:      dnsHost,
		}, false)

		want := classify.ExternalUnreachable
		if reachable {
			want = classify.ExternalReachable
		}
		if !obs.ControlAlive || !obs.AnchorsAlive || obs.TargetExternal != want {
			t.Errorf("reachable=%v: obs = %+v", reachable, obs)
		}
		if obs.AllowlistAlive || asked.Load() != 0 {
			t.Errorf("the allowlist must not be asked while the node and anchors answer: %+v, %d requests", obs, asked.Load())
		}
		if c := obs.ForClassifier(); !c.ControlAlive || !c.AnchorsAlive || c.TargetExternal != want {
			t.Errorf("ForClassifier = %+v", c)
		}
	}
}

func TestCtrlControlNodeDown(t *testing.T) {
	env := mockdpi.Start(t, mockdpi.Config{Control: true, Blackhole: true})

	t.Run("silent node", func(t *testing.T) {
		obs := runCtrl(t, env, CtrlRequest{
			Control: ControlClient{BaseURL: "http://" + env.Blackhole},
			Anchors: []string{anchorURL(env)},
			Host:    dnsHost,
		}, true)
		if obs.ControlAlive || !obs.AnchorsAlive || obs.TargetExternal != "" || obs.AllowlistAlive {
			t.Errorf("obs = %+v", obs)
		}
	})

	t.Run("node answers 500", func(t *testing.T) {
		f := newFakeControl(t, true)
		f.pingStatus = http.StatusInternalServerError
		obs := runCtrl(t, env, CtrlRequest{Control: f.client(), Anchors: []string{anchorURL(env)}, Host: dnsHost}, false)
		if obs.ControlAlive || obs.TargetExternal != "" {
			t.Errorf("obs = %+v", obs)
		}
	})

	t.Run("node alive but reach reply is broken", func(t *testing.T) {
		f := newFakeControl(t, true)
		f.rawReach = `nope`
		obs := runCtrl(t, env, CtrlRequest{Control: f.client(), Anchors: []string{anchorURL(env)}, Host: dnsHost}, false)
		if !obs.ControlAlive || obs.TargetExternal != "" {
			t.Errorf("obs = %+v", obs)
		}
	})
}

func TestCtrlAnchors(t *testing.T) {
	env := mockdpi.Start(t, mockdpi.Config{Control: true, Blackhole: true})
	f := newFakeControl(t, true)
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) }))
	defer down.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://elsewhere.invalid/", http.StatusFound)
	}))
	defer redirect.Close()

	tests := []struct {
		name    string
		anchors []string
		short   bool
		want    bool
	}{
		{"one alive among dead ones", []string{down.URL, "http://" + env.Blackhole, anchorURL(env)}, true, true},
		{"a redirect counts as alive", []string{redirect.URL}, false, true},
		{"5xx only", []string{down.URL}, false, false},
		{"silent only", []string{"http://" + env.Blackhole}, true, false},
		{"unparsable URL only", []string{"://bad"}, false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			obs := runCtrl(t, env, CtrlRequest{Control: f.client(), Anchors: tc.anchors, Host: dnsHost}, tc.short)
			if obs.AnchorsAlive != tc.want {
				t.Errorf("AnchorsAlive = %v, want %v", obs.AnchorsAlive, tc.want)
			}
		})
	}
}

func TestCtrlAllowlistMode(t *testing.T) {
	env := mockdpi.Start(t, mockdpi.Config{Control: true, Blackhole: true})
	silent := ControlClient{BaseURL: "http://" + env.Blackhole}
	silentSite := "http://" + env.Blackhole

	obs := runCtrl(t, env, CtrlRequest{
		Control: silent, Anchors: []string{silentSite}, Allowlist: []string{silentSite, anchorURL(env)},
		Host: dnsHost,
	}, true)
	if obs.ControlAlive || obs.AnchorsAlive || !obs.AllowlistAlive {
		t.Errorf("allowlist up: obs = %+v", obs)
	}
	if c := obs.ForClassifier(); classify.Classify(classify.Observation{Ctrl: c}) != "allowlist_mode" {
		t.Errorf("classifier does not see allowlist_mode for %+v", c)
	}

	obs = runCtrl(t, env, CtrlRequest{
		Control: silent, Anchors: []string{silentSite}, Allowlist: []string{silentSite},
		Host: dnsHost,
	}, true)
	if obs.AllowlistAlive {
		t.Errorf("allowlist down: obs = %+v", obs)
	}

	obs = runCtrl(t, env, CtrlRequest{Control: silent, Anchors: []string{silentSite}, Host: dnsHost}, true)
	if obs.AllowlistAlive {
		t.Errorf("no allowlist configured: obs = %+v", obs)
	}
}

func TestCtrlValidationAndCancel(t *testing.T) {
	env := mockdpi.Start(t, mockdpi.Config{Control: true})
	f := newFakeControl(t, true)
	good := CtrlRequest{Control: f.client(), Anchors: []string{anchorURL(env)}, Host: dnsHost, roots: env.CertPool}
	tests := map[string]func(r *CtrlRequest){
		"no control URL": func(r *CtrlRequest) { r.Control = ControlClient{} },
		"no anchors":     func(r *CtrlRequest) { r.Anchors = nil },
		"no target host": func(r *CtrlRequest) { r.Host = "" },
	}
	for name, edit := range tests {
		t.Run(name, func(t *testing.T) {
			r := good
			edit(&r)
			if _, err := Ctrl(context.Background(), r); err == nil {
				t.Error("want error")
			}
		})
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Ctrl(ctx, good); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

// A host that the control node does not serve leaves the external check
// unanswered; the node itself still counts as alive.
func TestCtrlHostNotServedByTheNode(t *testing.T) {
	env := mockdpi.Start(t, mockdpi.Config{Control: true})
	f := newFakeControl(t, true)
	obs := runCtrl(t, env, CtrlRequest{Control: f.client(), Anchors: []string{anchorURL(env)}, Host: "not-in-the-list.example"}, false)
	if !obs.ControlAlive || obs.TargetExternal != "" {
		t.Errorf("obs = %+v", obs)
	}
}
