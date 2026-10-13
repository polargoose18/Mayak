package targets

import (
	"crypto/ed25519"
	"errors"
	"os"
	"testing"
)

func TestPublicKeys(t *testing.T) {
	keys := PublicKeys()
	if len(keys) == 0 {
		t.Fatal("PublicKeys() is empty")
	}
	seen := map[string]bool{}
	for i, k := range keys {
		if len(k) != ed25519.PublicKeySize {
			t.Errorf("key %d: size %d", i, len(k))
		}
		if seen[string(k)] {
			t.Errorf("key %d is a duplicate", i)
		}
		seen[string(k)] = true
	}
}

// If targets/targets.signed.json exists, it must be signed by one of the
// built-in keys. Run by `make sign-check`.
func TestSignedTargetsFile(t *testing.T) {
	data, err := os.ReadFile("../../targets/targets.signed.json")
	if errors.Is(err, os.ErrNotExist) {
		t.Skip("targets/targets.signed.json does not exist")
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAny(PublicKeys(), data); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyAny(t *testing.T) {
	pub1, priv1 := newKey(t)
	pub2, _ := newKey(t)
	data, err := Sign(priv1, sample())
	if err != nil {
		t.Fatal(err)
	}

	for name, keys := range map[string][]ed25519.PublicKey{
		"first":  {pub1, pub2},
		"second": {pub2, pub1},
		"single": {pub1},
	} {
		if _, err := VerifyAny(keys, data); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := VerifyAny([]ed25519.PublicKey{pub2}, data); !errors.Is(err, ErrBadSignature) {
		t.Errorf("wrong key: err = %v, want ErrBadSignature", err)
	}
	if _, err := VerifyAny(nil, data); err == nil {
		t.Error("no keys: want error")
	}
	if _, err := VerifyAny([]ed25519.PublicKey{pub2, pub1}, []byte("junk")); !errors.Is(err, ErrInvalid) {
		t.Errorf("junk: err = %v, want ErrInvalid", err)
	}
}

func TestParseUnsigned(t *testing.T) {
	good := `{"rev":"r1","items":[{"id":"a","host":"example.org","category":"dev","rationale":"Fictional target number one.","rev":"r1"}]}`
	if tr, err := ParseUnsigned([]byte(good)); err != nil || len(tr.Items) != 1 {
		t.Fatalf("good: %v, %v", tr, err)
	}
	for name, in := range map[string]string{
		"junk":          "nope",
		"unknown field": `{"rev":"r1","items":[],"extra":1}`,
		"empty list":    `{"rev":"r1","items":[]}`,
		"trailing":      good + ` {}`,
		"short reason":  `{"rev":"r1","items":[{"id":"a","host":"example.org","category":"dev","rationale":"short","rev":"r1"}]}`,
	} {
		if _, err := ParseUnsigned([]byte(in)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
}
