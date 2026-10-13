package targets

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func sample() Targets {
	return Targets{
		Rev: "2026-10-13.1",
		Items: []Target{
			{ID: "a", Host: "example.org", Category: CategoryInfra, Rationale: "Fictional target number one.", Rev: "2026-10-13.1"},
			{ID: "b", Host: "example.net", Category: CategoryDev, Rationale: "Fictional target number two.", Rev: "2026-10-13.1"},
		},
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv := newKey(t)
	want := sample()
	data, err := Sign(priv, want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Verify(pub, data)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*got, want) {
		t.Errorf("got %+v, want %+v", *got, want)
	}
}

func TestCanonicalForm(t *testing.T) {
	tr := Targets{Rev: "r1", Items: []Target{
		{ID: "a", Host: "h<&>", Category: CategoryAI, Rationale: "Причина не короче двадцати.", Rev: "r1"},
	}}
	got, err := canonical(tr)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"rev":"r1","items":[{"id":"a","host":"h<&>","category":"ai","rationale":"Причина не короче двадцати.","rev":"r1"}]}`
	if string(got) != want {
		t.Errorf("canonical = %s\nwant       %s", got, want)
	}
}

// The file may be re-indented and its keys reordered without breaking the
// signature, because Verify re-serializes the parsed payload.
func TestVerifyIgnoresFormatting(t *testing.T) {
	pub, priv := newKey(t)
	data, err := Sign(priv, sample())
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Payload map[string]any `json:"payload"`
		Sig     string         `json:"sig"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	pretty, err := json.MarshalIndent(f, "", "    ") // map keys come out sorted
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(pretty, data) {
		t.Fatal("test bug: file was not reformatted")
	}
	if _, err := Verify(pub, pretty); err != nil {
		t.Errorf("reformatted file: %v", err)
	}
}

func TestVerifyBadSignature(t *testing.T) {
	pub, priv := newKey(t)
	otherPub, _ := newKey(t)
	data, err := Sign(priv, sample())
	if err != nil {
		t.Fatal(err)
	}
	flipped := func(s string) string {
		raw, _ := base64.StdEncoding.DecodeString(s)
		raw[0] ^= 1
		return base64.StdEncoding.EncodeToString(raw)
	}
	var f map[string]any
	_ = json.Unmarshal(data, &f)

	tests := []struct {
		name string
		pub  ed25519.PublicKey
		data []byte
	}{
		{"other key", otherPub, data},
		{"flipped sig bit", pub, rewrite(t, f, func(m map[string]any) { m["sig"] = flipped(m["sig"].(string)) })},
		{"short sig", pub, rewrite(t, f, func(m map[string]any) { m["sig"] = base64.StdEncoding.EncodeToString([]byte("short")) })},
		{"tampered host", pub, rewrite(t, f, func(m map[string]any) {
			m["payload"].(map[string]any)["items"].([]any)[0].(map[string]any)["host"] = "evil.example"
		})},
		{"tampered rev", pub, rewrite(t, f, func(m map[string]any) { m["payload"].(map[string]any)["rev"] = "2026-10-14.1" })},
		{"reordered items", pub, rewrite(t, f, func(m map[string]any) {
			items := m["payload"].(map[string]any)["items"].([]any)
			items[0], items[1] = items[1], items[0]
		})},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Verify(tc.pub, tc.data)
			if !errors.Is(err, ErrBadSignature) {
				t.Fatalf("err = %v, want ErrBadSignature", err)
			}
			if got != nil {
				t.Errorf("got %+v, want nil", got)
			}
		})
	}
}

// rewrite deep-copies f through JSON, applies edit and encodes the result.
func rewrite(t *testing.T, f map[string]any, edit func(m map[string]any)) []byte {
	t.Helper()
	b, _ := json.Marshal(f)
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	edit(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestVerifyMalformedFile(t *testing.T) {
	pub, priv := newKey(t)
	good, err := Sign(priv, sample())
	if err != nil {
		t.Fatal(err)
	}
	var f map[string]any
	_ = json.Unmarshal(good, &f)

	tests := []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"not json", []byte("nope")},
		{"trailing data", append(append([]byte{}, good...), []byte(` {}`)...)},
		{"missing payload", rewrite(t, f, func(m map[string]any) { delete(m, "payload") })},
		{"missing sig", rewrite(t, f, func(m map[string]any) { delete(m, "sig") })},
		{"sig not base64", rewrite(t, f, func(m map[string]any) { m["sig"] = "!!!" })},
		{"unknown file field", rewrite(t, f, func(m map[string]any) { m["extra"] = 1 })},
		{"unknown payload field", rewrite(t, f, func(m map[string]any) { m["payload"].(map[string]any)["extra"] = 1 })},
		{"payload wrong type", rewrite(t, f, func(m map[string]any) { m["payload"] = "x" })},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Verify(pub, tc.data); !errors.Is(err, ErrInvalid) {
				t.Fatalf("err = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestKeySizeChecks(t *testing.T) {
	pub, priv := newKey(t)
	if _, err := Sign(priv[:10], sample()); err == nil {
		t.Error("Sign with short key: want error")
	}
	data, _ := Sign(priv, sample())
	if _, err := Verify(pub[:10], data); err == nil {
		t.Error("Verify with short key: want error")
	}
}

func TestValidationRules(t *testing.T) {
	longEnough := "Twenty characters ok" // exactly 20
	tests := []struct {
		name string
		edit func(t *Targets)
		ok   bool
	}{
		{"valid", func(*Targets) {}, true},
		{"rationale exactly 20", func(t *Targets) { t.Items[0].Rationale = longEnough }, true},
		{"rationale 19", func(t *Targets) { t.Items[0].Rationale = longEnough[:19] }, false},
		{"rationale 20 cyrillic runes", func(t *Targets) { t.Items[0].Rationale = strings.Repeat("я", 20) }, true},
		{"rationale 19 cyrillic runes", func(t *Targets) { t.Items[0].Rationale = strings.Repeat("я", 19) }, false},
		{"rationale empty", func(t *Targets) { t.Items[0].Rationale = "" }, false},
		{"empty list", func(t *Targets) { t.Items = nil }, false},
		{"empty id", func(t *Targets) { t.Items[0].ID = "" }, false},
		{"duplicate id", func(t *Targets) { t.Items[1].ID = t.Items[0].ID }, false},
		{"empty host", func(t *Targets) { t.Items[0].Host = "" }, false},
		{"host with space", func(t *Targets) { t.Items[0].Host = "exa mple.org" }, false},
		{"host with tab", func(t *Targets) { t.Items[0].Host = "example.org\t" }, false},
		{"host with https scheme", func(t *Targets) { t.Items[0].Host = "https://example.org" }, false},
		{"host with other scheme", func(t *Targets) { t.Items[0].Host = "ftp://example.org" }, false},
		{"unknown category", func(t *Targets) { t.Items[0].Category = "porn" }, false},
		{"empty category", func(t *Targets) { t.Items[0].Category = "" }, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pub, priv := newKey(t)
			tr := sample()
			tc.edit(&tr)

			// Sign refuses invalid input.
			_, err := Sign(priv, tr)
			if tc.ok != (err == nil) || (!tc.ok && !errors.Is(err, ErrInvalid)) {
				t.Errorf("Sign err = %v, ok = %v", err, tc.ok)
			}

			// Verify refuses validly signed but invalid content.
			data, err := signUnchecked(priv, tr)
			if err != nil {
				t.Fatal(err)
			}
			_, err = Verify(pub, data)
			if tc.ok != (err == nil) || (!tc.ok && !errors.Is(err, ErrInvalid)) {
				t.Errorf("Verify err = %v, ok = %v", err, tc.ok)
			}
		})
	}
}

func TestAllCategoriesAccepted(t *testing.T) {
	pub, priv := newKey(t)
	for _, c := range Categories() {
		tr := sample()
		tr.Items[0].Category = c
		data, err := Sign(priv, tr)
		if err != nil {
			t.Fatalf("%s: %v", c, err)
		}
		if _, err := Verify(pub, data); err != nil {
			t.Errorf("%s: %v", c, err)
		}
	}
}

// The example file must stay a valid sample of the format. Its signature is
// a placeholder, so verification against any key must fail.
func TestExampleFile(t *testing.T) {
	data, err := os.ReadFile("../../targets/targets.example.json")
	if err != nil {
		t.Fatal(err)
	}
	tr, sig, err := decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Errorf("sig length = %d, want %d", len(sig), ed25519.SignatureSize)
	}
	if err := tr.validate(); err != nil {
		t.Errorf("example payload: %v", err)
	}
	if len(tr.Items) != 3 {
		t.Errorf("items = %d, want 3", len(tr.Items))
	}
	pub, _ := newKey(t)
	if _, err := Verify(pub, data); !errors.Is(err, ErrBadSignature) {
		t.Errorf("err = %v, want ErrBadSignature", err)
	}
}
