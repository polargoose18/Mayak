package targets

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// ErrBadSignature is returned when the signature does not match the payload.
var ErrBadSignature = errors.New("bad signature")

// file is the on-disk format: {"payload": <Targets>, "sig": "<base64>"}.
type file struct {
	Payload json.RawMessage `json:"payload"`
	Sig     string          `json:"sig"`
}

// canonical returns the bytes that are signed.
//
// Canonical form: the Targets value is serialized by encoding/json from the
// Go structs, not taken from the file as is. That fixes the three things that
// otherwise make JSON ambiguous: field order is the struct declaration order
// (rev, items; id, host, category, rationale, rev), there is no whitespace,
// and strings use Go's escaping with HTML escaping turned off. The order of
// items is part of the signed data. Verify re-serializes the parsed payload
// the same way, so indentation or key order in the file do not matter, and
// what is verified is exactly what was parsed. Another implementation must
// reproduce this byte for byte (compact JSON, that field order).
func canonical(t Targets) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(t); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// Sign validates t and returns the signed targets file.
func Sign(priv ed25519.PrivateKey, t Targets) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("sign targets: invalid private key size")
	}
	if err := t.validate(); err != nil {
		return nil, fmt.Errorf("sign targets: %w", err)
	}
	return signUnchecked(priv, t)
}

func signUnchecked(priv ed25519.PrivateKey, t Targets) ([]byte, error) {
	payload, err := canonical(t)
	if err != nil {
		return nil, fmt.Errorf("canonicalize targets: %w", err)
	}
	sig := ed25519.Sign(priv, payload)
	out, err := json.Marshal(file{
		Payload: payload,
		Sig:     base64.StdEncoding.EncodeToString(sig),
	})
	if err != nil {
		return nil, fmt.Errorf("encode targets file: %w", err)
	}
	return out, nil
}

// decode parses the file format strictly and returns the payload and the
// raw signature. It does not check the signature.
func decode(data []byte) (*Targets, []byte, error) {
	var f file
	if err := strictUnmarshal(data, &f); err != nil {
		return nil, nil, invalid("file: %v", err)
	}
	if len(f.Payload) == 0 {
		return nil, nil, invalid("missing payload")
	}
	if f.Sig == "" {
		return nil, nil, invalid("missing sig")
	}
	sig, err := base64.StdEncoding.DecodeString(f.Sig)
	if err != nil {
		return nil, nil, invalid("sig is not base64")
	}
	var t Targets
	if err := strictUnmarshal(f.Payload, &t); err != nil {
		return nil, nil, invalid("payload: %v", err)
	}
	return &t, sig, nil
}

// strictUnmarshal rejects unknown fields and trailing data. Unknown fields in
// the payload are rejected because the signature would not cover them.
func strictUnmarshal(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}

// Verify checks the signature of a targets file and the format rules, and
// returns the list. The signature is checked first, so nothing from an
// unsigned file is interpreted beyond parsing.
func Verify(pub ed25519.PublicKey, data []byte) (*Targets, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("verify targets: invalid public key size")
	}
	t, sig, err := decode(data)
	if err != nil {
		return nil, fmt.Errorf("verify targets: %w", err)
	}
	payload, err := canonical(*t)
	if err != nil {
		return nil, fmt.Errorf("canonicalize targets: %w", err)
	}
	if !ed25519.Verify(pub, payload, sig) {
		return nil, fmt.Errorf("verify targets: %w", ErrBadSignature)
	}
	if err := t.validate(); err != nil {
		return nil, fmt.Errorf("verify targets: %w", err)
	}
	return t, nil
}
