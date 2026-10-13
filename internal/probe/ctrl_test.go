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
	"sync/atomic"
	"testing"

	"github.com/polargoose18/mayak/internal/classify"
	"github.com/polargoose18/mayak/testbed/mockdpi"
)

// fakeControl is a control node that speaks the protocol in control.go. It
// records the queries it gets.
type fakeControl struct {
	srv       *httptest.Server
	reachable bool

	reachQuery atomic.Value // url.Values of the last /v1/reach
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
	f := &fakeControl{reachable: reachable, pingStatus: http.StatusOK}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/ping", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(f.pingStatus) })
	mux.HandleFunc("/v1/reach", func(w http.ResponseWriter, r *http.Request) {
		f.reachQuery.Store(r.URL.Query())
		if f.rawReach != "" {
			_, _ = w.Write([]byte(f.rawReach))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]bool{"reachable": f.reachable})
	})
	mux.HandleFunc("/v1/fetch", func(w http.ResponseWriter, r *http.Request) {
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

func TestControlClient(t *testing.T) {
	f := newFakeControl(t, true)
	c := f.client()
	ctx := context.Background()
	target := netip.MustParseAddrPort("203.0.113.5:443")

	if err := c.Ping(ctx); err != nil {
		t.Errorf("Ping: %v", err)
	}

	ext, err := c.Reach(ctx, target)
	if err != nil || ext != classify.ExternalReachable {
		t.Errorf("Reach = %q, %v", ext, err)
	}
	q := f.reachQuery.Load().(url.Values)
	if q["ip"][0] != "203.0.113.5" || q["port"][0] != "443" {
		t.Errorf("reach query = %v", q)
	}

	f.reachable = false
	if ext, err := c.Reach(ctx, target); err != nil || ext != classify.ExternalUnreachable {
		t.Errorf("Reach = %q, %v", ext, err)
	}
}

func TestControlClientErrors(t *testing.T) {
	f := newFakeControl(t, true)
	c := f.client()
	ctx := context.Background()
	target := netip.MustParseAddrPort("203.0.113.5:443")

	f.pingStatus = http.StatusServiceUnavailable
	if err := c.Ping(ctx); err == nil {
		t.Error("Ping on 503: want error")
	}

	for name, body := range map[string]string{"no field": `{}`, "bad json": `nope`, "wrong type": `{"reachable":"yes"}`} {
		f.rawReach = body
		if ext, err := c.Reach(ctx, target); err == nil || ext != "" {
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
	_, err := ControlClient{BaseURL: srv.URL}.Reach(context.Background(), netip.MustParseAddrPort("203.0.113.5:443"))
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
	target := netip.MustParseAddrPort("203.0.113.5:443")

	ref, err := c.Reference(context.Background(), "example.org", "/p?x=1", target)
	if err != nil {
		t.Fatal(err)
	}
	if *ref != (classify.HTTPResponse{Status: 200, Size: 12, BodyHash: "abc"}) {
		t.Errorf("ref = %+v", ref)
	}
	q := got.Load().(url.Values)
	if q["host"][0] != "example.org" || q["path"][0] != "/p?x=1" || q["ip"][0] != "203.0.113.5" || q["port"][0] != "443" {
		t.Errorf("query = %v", q)
	}

	reply = `{"status":0}`
	if _, err := c.Reference(context.Background(), "example.org", "/", target); err == nil {
		t.Error("incomplete reply: want error")
	}
	status, reply = http.StatusBadGateway, `{}`
	if _, err := c.Reference(context.Background(), "example.org", "/", target); err == nil {
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
			Control:    f.client(),
			Anchors:    []string{anchorURL(env)},
			Allowlist:  []string{allow.URL},
			TargetAddr: addr(t, env.ControlTLS),
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
			Control:    ControlClient{BaseURL: "http://" + env.Blackhole},
			Anchors:    []string{anchorURL(env)},
			TargetAddr: addr(t, env.ControlTLS),
		}, true)
		if obs.ControlAlive || !obs.AnchorsAlive || obs.TargetExternal != "" || obs.AllowlistAlive {
			t.Errorf("obs = %+v", obs)
		}
	})

	t.Run("node answers 500", func(t *testing.T) {
		f := newFakeControl(t, true)
		f.pingStatus = http.StatusInternalServerError
		obs := runCtrl(t, env, CtrlRequest{Control: f.client(), Anchors: []string{anchorURL(env)}, TargetAddr: addr(t, env.ControlTLS)}, false)
		if obs.ControlAlive || obs.TargetExternal != "" {
			t.Errorf("obs = %+v", obs)
		}
	})

	t.Run("node alive but reach reply is broken", func(t *testing.T) {
		f := newFakeControl(t, true)
		f.rawReach = `nope`
		obs := runCtrl(t, env, CtrlRequest{Control: f.client(), Anchors: []string{anchorURL(env)}, TargetAddr: addr(t, env.ControlTLS)}, false)
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
			obs := runCtrl(t, env, CtrlRequest{Control: f.client(), Anchors: tc.anchors, TargetAddr: addr(t, env.ControlTLS)}, tc.short)
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
		TargetAddr: addr(t, env.ControlTLS),
	}, true)
	if obs.ControlAlive || obs.AnchorsAlive || !obs.AllowlistAlive {
		t.Errorf("allowlist up: obs = %+v", obs)
	}
	if c := obs.ForClassifier(); classify.Classify(classify.Observation{Ctrl: c}) != "allowlist_mode" {
		t.Errorf("classifier does not see allowlist_mode for %+v", c)
	}

	obs = runCtrl(t, env, CtrlRequest{
		Control: silent, Anchors: []string{silentSite}, Allowlist: []string{silentSite},
		TargetAddr: addr(t, env.ControlTLS),
	}, true)
	if obs.AllowlistAlive {
		t.Errorf("allowlist down: obs = %+v", obs)
	}

	obs = runCtrl(t, env, CtrlRequest{Control: silent, Anchors: []string{silentSite}, TargetAddr: addr(t, env.ControlTLS)}, true)
	if obs.AllowlistAlive {
		t.Errorf("no allowlist configured: obs = %+v", obs)
	}
}

func TestCtrlValidationAndCancel(t *testing.T) {
	env := mockdpi.Start(t, mockdpi.Config{Control: true})
	f := newFakeControl(t, true)
	good := CtrlRequest{Control: f.client(), Anchors: []string{anchorURL(env)}, TargetAddr: addr(t, env.ControlTLS), roots: env.CertPool}
	tests := map[string]func(r *CtrlRequest){
		"no control URL": func(r *CtrlRequest) { r.Control = ControlClient{} },
		"no anchors":     func(r *CtrlRequest) { r.Anchors = nil },
		"zero target":    func(r *CtrlRequest) { r.TargetAddr = netip.AddrPort{} },
		"target no port": func(r *CtrlRequest) { r.TargetAddr = netip.AddrPortFrom(r.TargetAddr.Addr(), 0) },
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
