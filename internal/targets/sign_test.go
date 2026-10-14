package targets

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// testNow is the clock of these tests.
var testNow = time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)

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
		V:       1,
		Rev:     "2026-10-13.1",
		Expires: testNow.Add(14 * 24 * time.Hour),
		Items: []Target{
			{ID: "a", Host: "example.org", Category: CategoryInfra, Rationale: "Fictional target number one.", Rev: "2026-10-13.1"},
			{ID: "b", Host: "example.net", Category: CategoryDev, Rationale: "Fictional target number two.", Rev: "2026-10-13.1"},
		},
	}
}

func payloadOf(t *testing.T, tr Targets) []byte {
	t.Helper()
	b, err := json.Marshal(tr)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustSign(t *testing.T, priv ed25519.PrivateKey, tr Targets) []byte {
	t.Helper()
	data, err := Sign(priv, payloadOf(t, tr), testNow)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// envelope returns the decoded file for editing.
func envelope(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func encode(t *testing.T, m map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv := newKey(t)
	want := sample()
	got, err := Verify([]ed25519.PublicKey{pub}, mustSign(t, priv, want), testNow)
	if err != nil {
		t.Fatal(err)
	}
	if got.V != 1 || got.Rev != want.Rev || !got.Expires.Equal(want.Expires) || len(got.Items) != 2 || got.Items[0] != want.Items[0] {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

// The signature is over the exact payload bytes, so any field order and
// whitespace the signer chose verify, and one changed byte does not.
func TestSignatureIsOverExactBytes(t *testing.T) {
	pub, priv := newKey(t)
	pubs := []ed25519.PublicKey{pub}
	exp := sample().Expires.Format(time.RFC3339)
	item := `{"id":"a","host":"example.org","category":"infra","rationale":"Fictional target number one.","rev":"2026-10-13.1"}`

	payloads := map[string]string{
		"compact":        `{"v":1,"rev":"2026-10-13.1","expires":"` + exp + `","items":[` + item + `]}`,
		"reordered":      `{"items":[` + item + `],"expires":"` + exp + `","rev":"2026-10-13.1","v":1}`,
		"pretty printed": "{\n  \"v\": 1,\n  \"rev\": \"2026-10-13.1\",\n  \"expires\": \"" + exp + "\",\n  \"items\": [\n    " + item + "\n  ]\n}\n",
		"odd spacing":    ` { "v" : 1 , "rev":"2026-10-13.1" ,"expires":"` + exp + `","items":[ ` + item + ` ] } `,
	}
	for name, p := range payloads {
		t.Run(name, func(t *testing.T) {
			data, err := Sign(priv, []byte(p), testNow)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Verify(pubs, data, testNow); err != nil {
				t.Errorf("verify: %v", err)
			}

			// Change one byte of the payload, keep the signature.
			m := envelope(t, data)
			raw, _ := base64.StdEncoding.DecodeString(m["payload"].(string))
			raw[strings.Index(string(raw), "example.org")] ^= 0x20 // 'e' -> 'E'
			m["payload"] = b64(raw)
			if _, err := Verify(pubs, encode(t, m), testNow); !errors.Is(err, ErrBadSignature) {
				t.Errorf("changed byte: err = %v, want ErrBadSignature", err)
			}
		})
	}

	// Trailing whitespace is part of the bytes too.
	data, _ := Sign(priv, []byte(payloads["compact"]), testNow)
	m := envelope(t, data)
	raw, _ := base64.StdEncoding.DecodeString(m["payload"].(string))
	m["payload"] = b64(append(raw, ' '))
	if _, err := Verify(pubs, encode(t, m), testNow); !errors.Is(err, ErrBadSignature) {
		t.Errorf("appended byte: err = %v, want ErrBadSignature", err)
	}
}

// A field the agent does not know is signed with the rest and is ignored.
func TestUnknownFieldsInSignedPayloadAreIgnored(t *testing.T) {
	pub, priv := newKey(t)
	tr := sample()
	p := payloadOf(t, tr)
	p = []byte(strings.Replace(string(p), `"v":1,`, `"v":1,"future_field":{"x":[1,2]},`, 1))

	// The signer refuses it ...
	if _, err := Sign(priv, p, testNow); !errors.Is(err, ErrInvalid) {
		t.Errorf("Sign: err = %v, want ErrInvalid", err)
	}
	// ... but a newer signer's file is accepted by this agent.
	data, err := signBytes(priv, p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Verify([]ed25519.PublicKey{pub}, data, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if got.Rev != tr.Rev {
		t.Errorf("got %+v", got)
	}
}

func TestVersion(t *testing.T) {
	pub, priv := newKey(t)
	pubs := []ed25519.PublicKey{pub}

	tests := []struct {
		name string
		v    int
		want error
	}{
		{"v2 from the future", 2, ErrUnsupportedVersion},
		{"v100", 100, ErrUnsupportedVersion},
		{"v0", 0, ErrInvalid},
		{"negative", -1, ErrInvalid},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tr := sample()
			tr.V = tc.v
			data, err := signBytes(priv, payloadOf(t, tr))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Verify(pubs, data, testNow); !errors.Is(err, tc.want) {
				t.Errorf("Verify: err = %v, want %v", err, tc.want)
			}
		})
	}

	// The signer only signs the version it knows.
	tr := sample()
	tr.V = 2
	if _, err := Sign(priv, payloadOf(t, tr), testNow); !errors.Is(err, ErrUnsupportedVersion) {
		t.Errorf("Sign v2: err = %v, want ErrUnsupportedVersion", err)
	}

	// A payload without v is invalid.
	noV := `{"rev":"2026-10-13.1","expires":"` + sample().Expires.Format(time.RFC3339) + `","items":[{"id":"a","host":"example.org","category":"dev","rationale":"Fictional target number one.","rev":"2026-10-13.1"}]}`
	if _, err := Sign(priv, []byte(noV), testNow); !errors.Is(err, ErrInvalid) {
		t.Errorf("no v: err = %v, want ErrInvalid", err)
	}
}

func TestExpiry(t *testing.T) {
	pub, priv := newKey(t)
	pubs := []ed25519.PublicKey{pub}

	tests := []struct {
		name    string
		expires time.Time
		want    error // nil: accepted
	}{
		{"a day left", testNow.Add(24 * time.Hour), nil},
		{"a second left", testNow.Add(time.Second), nil},
		{"exactly 30 days", testNow.Add(MaxLifetime), nil},
		{"31 days", testNow.Add(MaxLifetime + time.Second), ErrInvalid},
		{"expires now", testNow, ErrExpired},
		{"expired a second ago", testNow.Add(-time.Second), ErrExpired},
		{"long expired", testNow.Add(-90 * 24 * time.Hour), ErrExpired},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tr := sample()
			tr.Expires = tc.expires
			p := payloadOf(t, tr)

			// Sign and Verify apply the same rule.
			_, signErr := Sign(priv, p, testNow)
			data, err := signBytes(priv, p)
			if err != nil {
				t.Fatal(err)
			}
			_, verifyErr := Verify(pubs, data, testNow)
			for name, got := range map[string]error{"Sign": signErr, "Verify": verifyErr} {
				if tc.want == nil && got != nil || tc.want != nil && !errors.Is(got, tc.want) {
					t.Errorf("%s: err = %v, want %v", name, got, tc.want)
				}
			}
		})
	}

	// The same signed list ages: valid today, expired later. Open ignores the clock.
	data := mustSign(t, priv, sample())
	later := testNow.Add(15 * 24 * time.Hour)
	if _, err := Verify(pubs, data, later); !errors.Is(err, ErrExpired) {
		t.Errorf("later: err = %v, want ErrExpired", err)
	}
	if _, err := Open(pubs, data); err != nil {
		t.Errorf("Open must not look at the clock: %v", err)
	}

	// A missing expires is not "never expires".
	noExp := `{"v":1,"rev":"2026-10-13.1","items":[{"id":"a","host":"example.org","category":"dev","rationale":"Fictional target number one.","rev":"2026-10-13.1"}]}`
	if _, err := Sign(priv, []byte(noExp), testNow); !errors.Is(err, ErrInvalid) {
		t.Errorf("no expires: err = %v, want ErrInvalid", err)
	}
}

func TestCheckRev(t *testing.T) {
	tests := []struct {
		stored, next string
		want         error // nil: accepted
	}{
		{"2026-10-13.1", "2026-10-13.2", nil},
		{"2026-10-13.9", "2026-10-13.10", nil}, // numbers compare as numbers
		{"2026-10-13.10", "2026-10-13.9", ErrRollback},
		{"2026-10-13.1", "2026-10-13.1", nil}, // the same list again
		{"2026-10-13.2", "2026-10-13.1", ErrRollback},
		{"2026-10-13.5", "2026-10-14.1", nil}, // a newer date wins whatever the number
		{"2026-10-14.1", "2026-10-13.99", ErrRollback},
		{"2026-09-30.1", "2026-10-01.1", nil},
		{"2025-12-31.1", "2026-01-01.1", nil},
		{"2026-01-01.1", "2025-12-31.1", ErrRollback},
		{"", "2026-10-13.1", nil}, // nothing stored
		{"", "junk", ErrInvalid},
		{"2026-10-13.1", "junk", ErrInvalid},
		{"junk", "2026-10-13.1", ErrInvalid},
		{"2026-10-13.1", "2026-13-01.1", ErrInvalid}, // no such month
		{"2026-10-13.1", "2026-10-13.", ErrInvalid},  // no number
		{"2026-10-13.1", "2026-10-13.12345", ErrInvalid},
		{"2026-10-13.1", "2026-10-13.a", ErrInvalid},
		{"2026-10-13.1", "2026-10-13", ErrInvalid},
		{"2026-10-13.1", "2026-10-13.1.2", ErrInvalid},
	}
	for _, tc := range tests {
		err := CheckRev(tc.stored, tc.next)
		if tc.want == nil && err != nil || tc.want != nil && !errors.Is(err, tc.want) {
			t.Errorf("CheckRev(%q, %q) = %v, want %v", tc.stored, tc.next, err, tc.want)
		}
	}

	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"2026-10-13.1", "2026-10-13.1", 0},
		{"2026-10-13.1", "2026-10-13.2", -1},
		{"2026-10-14.1", "2026-10-13.9", 1},
		{"2026-10-13.10", "2026-10-13.9", 1},
	} {
		if got, err := CompareRev(tc.a, tc.b); err != nil || got != tc.want {
			t.Errorf("CompareRev(%q, %q) = %d, %v; want %d", tc.a, tc.b, got, err, tc.want)
		}
	}
	if _, err := CompareRev("junk", "2026-10-13.1"); err == nil {
		t.Error("CompareRev with junk: want error")
	}
	if _, err := CompareRev("2026-10-13.1", "junk"); err == nil {
		t.Error("CompareRev with junk: want error")
	}
}

func TestStoredRev(t *testing.T) {
	_, priv := newKey(t)
	data := mustSign(t, priv, sample())
	if rev, err := StoredRev(data); err != nil || rev != "2026-10-13.1" {
		t.Errorf("StoredRev = %q, %v", rev, err)
	}
	// It does not need the signature to be good.
	m := envelope(t, data)
	m["sig"] = b64(make([]byte, 64))
	if rev, err := StoredRev(encode(t, m)); err != nil || rev != "2026-10-13.1" {
		t.Errorf("StoredRev with another signature = %q, %v", rev, err)
	}
	for name, in := range map[string]string{
		"not json":        "nope",
		"no payload":      `{"sig":"AAAA"}`,
		"payload junk":    `{"payload":"` + b64([]byte("nope")) + `","sig":"AAAA"}`,
		"no rev":          `{"payload":"` + b64([]byte(`{"v":1}`)) + `","sig":"AAAA"}`,
		"payload not b64": `{"payload":"!!!","sig":"AAAA"}`,
	} {
		if _, err := StoredRev([]byte(in)); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestVerifyBadSignature(t *testing.T) {
	pub, priv := newKey(t)
	otherPub, _ := newKey(t)
	data := mustSign(t, priv, sample())

	flipped := func() []byte {
		m := envelope(t, data)
		raw, _ := base64.StdEncoding.DecodeString(m["sig"].(string))
		raw[0] ^= 1
		m["sig"] = b64(raw)
		return encode(t, m)
	}
	withSig := func(sig []byte) []byte {
		m := envelope(t, data)
		m["sig"] = b64(sig)
		return encode(t, m)
	}

	tests := []struct {
		name string
		pubs []ed25519.PublicKey
		data []byte
	}{
		{"other key", []ed25519.PublicKey{otherPub}, data},
		{"flipped sig bit", []ed25519.PublicKey{pub}, flipped()},
		{"short sig", []ed25519.PublicKey{pub}, withSig([]byte("short"))},
		{"zero sig", []ed25519.PublicKey{pub}, withSig(make([]byte, 64))},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Verify(tc.pubs, tc.data, testNow)
			if !errors.Is(err, ErrBadSignature) || got != nil {
				t.Errorf("got %v, %v; want ErrBadSignature", got, err)
			}
		})
	}
}

func TestVerifyAnyOfSeveralKeys(t *testing.T) {
	pub1, priv1 := newKey(t)
	pub2, _ := newKey(t)
	data := mustSign(t, priv1, sample())
	for name, keys := range map[string][]ed25519.PublicKey{
		"first":  {pub1, pub2},
		"second": {pub2, pub1},
		"single": {pub1},
	} {
		if _, err := Verify(keys, data, testNow); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := Verify([]ed25519.PublicKey{pub2}, data, testNow); !errors.Is(err, ErrBadSignature) {
		t.Errorf("wrong key: err = %v, want ErrBadSignature", err)
	}
	if _, err := Verify(nil, data, testNow); err == nil {
		t.Error("no keys: want error")
	}
	if _, err := Verify([]ed25519.PublicKey{pub2, pub1[:10]}, data, testNow); err == nil {
		t.Error("short key: want error")
	}
}

func TestVerifyMalformedFile(t *testing.T) {
	pub, priv := newKey(t)
	pubs := []ed25519.PublicKey{pub}
	good := mustSign(t, priv, sample())

	// A payload that is validly signed but is not JSON.
	notJSON, _ := signBytes(priv, []byte("nope"))
	// A signed payload with an unknown extra top-level field next to payload/sig is fine.
	m := envelope(t, good)
	m["comment"] = "unsigned note"
	withComment := encode(t, m)

	tests := []struct {
		name string
		data []byte
		ok   bool
	}{
		{"empty", nil, false},
		{"not json", []byte("nope"), false},
		{"missing payload", encode(t, map[string]any{"sig": envelope(t, good)["sig"]}), false},
		{"missing sig", encode(t, map[string]any{"payload": envelope(t, good)["payload"]}), false},
		{"payload not base64", encode(t, map[string]any{"payload": "!!!", "sig": envelope(t, good)["sig"]}), false},
		{"sig not base64", encode(t, map[string]any{"payload": envelope(t, good)["payload"], "sig": "!!!"}), false},
		{"payload is an object (v1 format)", encode(t, map[string]any{"payload": map[string]any{"v": 1}, "sig": "AAAA"}), false},
		{"signed payload is not json", notJSON, false},
		{"unsigned field next to payload is ignored", withComment, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Verify(pubs, tc.data, testNow)
			if tc.ok && err != nil {
				t.Fatal(err)
			}
			if !tc.ok && !errors.Is(err, ErrInvalid) {
				t.Errorf("err = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestSignKeySize(t *testing.T) {
	_, priv := newKey(t)
	if _, err := Sign(priv[:10], payloadOf(t, sample()), testNow); err == nil {
		t.Error("Sign with a short key: want error")
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
		{"host with https scheme", func(t *Targets) { t.Items[0].Host = "https://example.org" }, false},
		{"unknown category", func(t *Targets) { t.Items[0].Category = "porn" }, false},
		{"empty category", func(t *Targets) { t.Items[0].Category = "" }, false},
		{"bad rev", func(t *Targets) { t.Rev = "r1" }, false},
		{"empty rev", func(t *Targets) { t.Rev = "" }, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pub, priv := newKey(t)
			tr := sample()
			tc.edit(&tr)
			p := payloadOf(t, tr)

			// Sign refuses invalid input.
			_, err := Sign(priv, p, testNow)
			if tc.ok != (err == nil) || (!tc.ok && !errors.Is(err, ErrInvalid)) {
				t.Errorf("Sign err = %v, ok = %v", err, tc.ok)
			}

			// Verify refuses validly signed but invalid content.
			data, err := signBytes(priv, p)
			if err != nil {
				t.Fatal(err)
			}
			_, err = Verify([]ed25519.PublicKey{pub}, data, testNow)
			if tc.ok != (err == nil) || (!tc.ok && !errors.Is(err, ErrInvalid)) {
				t.Errorf("Verify err = %v, ok = %v", err, tc.ok)
			}
		})
	}
}

func TestParseUnsigned(t *testing.T) {
	good := string(payloadOf(t, sample()))
	if tr, err := ParseUnsigned([]byte(good)); err != nil || len(tr.Items) != 2 {
		t.Fatalf("good: %v, %v", tr, err)
	}
	for name, in := range map[string]string{
		"junk":          "nope",
		"unknown field": strings.Replace(good, `"v":1,`, `"v":1,"extra":1,`, 1),
		"empty list":    `{"v":1,"rev":"2026-10-13.1","expires":"2026-10-20T00:00:00Z","items":[]}`,
		"trailing":      good + ` {}`,
		"short reason":  strings.Replace(good, "Fictional target number one.", "short", 1),
		"no expires":    strings.Replace(good, `"expires"`, `"expired"`, 1),
	} {
		if _, err := ParseUnsigned([]byte(in)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
}

func TestAllCategoriesAccepted(t *testing.T) {
	pub, priv := newKey(t)
	for _, c := range Categories() {
		tr := sample()
		tr.Items[0].Category = c
		if _, err := Verify([]ed25519.PublicKey{pub}, mustSign(t, priv, tr), testNow); err != nil {
			t.Errorf("%s: %v", c, err)
		}
	}
}

// The example file must stay a valid sample of the format. Its signature is
// a placeholder, so verification against any key must fail, and its payload
// must be the one shown next to it for reading.
func TestExampleFile(t *testing.T) {
	data, err := os.ReadFile("../../targets/targets.example.json")
	if err != nil {
		t.Fatal(err)
	}
	payload, sig, err := decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Errorf("sig length = %d, want %d", len(sig), ed25519.SignatureSize)
	}
	readable, err := os.ReadFile("../../targets/targets.example.payload.json")
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != string(readable) {
		t.Error("the payload in targets.example.json differs from targets.example.payload.json")
	}
	tr, err := ParseUnsigned(payload)
	if err != nil {
		t.Fatalf("example payload: %v", err)
	}
	if len(tr.Items) != 3 || tr.V != CurrentVersion {
		t.Errorf("example: v = %d, items = %d", tr.V, len(tr.Items))
	}
	pub, _ := newKey(t)
	if _, err := Open([]ed25519.PublicKey{pub}, data); !errors.Is(err, ErrBadSignature) {
		t.Errorf("err = %v, want ErrBadSignature", err)
	}
}
