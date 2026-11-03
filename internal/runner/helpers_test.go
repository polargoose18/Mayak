package runner

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/polargoose18/mayak/internal/targets"
)

// fakeClock is a Clock whose After fires at once and records what was asked,
// so that pauses can be checked without waiting for them.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	waited []time.Duration
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	c.waited = append(c.waited, d)
	c.now = c.now.Add(d)
	now := c.now
	c.mu.Unlock()
	ch := make(chan time.Time, 1)
	ch <- now
	return ch
}

func (c *fakeClock) pauses() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Duration(nil), c.waited...)
}

// testNow is the time of these tests.
var testNow = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// listOf builds a valid list of n targets.
func listOf(rev string, expires time.Time, n int) targets.Targets {
	l := targets.Targets{V: 1, Rev: rev, Expires: expires}
	for i := range n {
		l.Items = append(l.Items, targets.Target{
			ID:        fmt.Sprintf("t%02d", i),
			Host:      fmt.Sprintf("t%02d.example.org", i),
			Category:  targets.CategoryInfra,
			Rationale: "Fictional target for the runner tests.",
			Rev:       rev,
		})
	}
	return l
}

// signRaw signs the payload bytes as they are, without the signer's checks,
// so that tests can build lists the signer would refuse.
func signRaw(t *testing.T, priv ed25519.PrivateKey, payload []byte) []byte {
	t.Helper()
	out, err := json.Marshal(map[string]string{
		"payload": base64.StdEncoding.EncodeToString(payload),
		"sig":     base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// signedFile writes a signed list to a temporary file and returns its path.
func signedFile(t *testing.T, priv ed25519.PrivateKey, l targets.Targets) string {
	t.Helper()
	payload, err := json.Marshal(l)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "list.json")
	if err := os.WriteFile(path, signRaw(t, priv, payload), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
