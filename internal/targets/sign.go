package targets

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// ErrBadSignature is returned when no key matches the signature.
var ErrBadSignature = errors.New("bad signature")

// File format (v2):
//
//	{"payload": "<base64 of the exact JSON bytes>", "sig": "<base64 ed25519>"}
//
// The signature is over the payload bytes exactly as they are. Nothing is
// parsed before the signature is checked and nothing is serialized again
// afterwards, so there is no canonical form to agree on: the signer may use
// any field order and whitespace, and a verifier sees the bytes the signer
// signed. Because the signature covers every byte, fields that an older agent
// does not know are ignored by it (they are signed, not injected); an
// incompatible change is announced by raising v.
type file struct {
	Payload string `json:"payload"`
	Sig     string `json:"sig"`
}

// Sign validates the payload (a JSON Targets document) and returns the signed
// file. The payload bytes are signed as they are. Unknown fields in the
// payload are refused here, because a typo would otherwise be signed; now is
// the signing time, against which expires is checked.
func Sign(priv ed25519.PrivateKey, payload []byte, now time.Time) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("sign targets: invalid private key size")
	}
	t, err := ParseUnsigned(payload)
	if err != nil {
		return nil, fmt.Errorf("sign targets: %w", err)
	}
	if t.V != CurrentVersion {
		return nil, fmt.Errorf("sign targets: %w: v is %d, this tool signs v%d", ErrUnsupportedVersion, t.V, CurrentVersion)
	}
	if err := t.checkClock(now); err != nil {
		return nil, fmt.Errorf("sign targets: %w", err)
	}
	return signBytes(priv, payload)
}

// signBytes signs the bytes without looking at them.
func signBytes(priv ed25519.PrivateKey, payload []byte) ([]byte, error) {
	out, err := json.Marshal(file{
		Payload: base64.StdEncoding.EncodeToString(payload),
		Sig:     base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload)),
	})
	if err != nil {
		return nil, fmt.Errorf("encode targets file: %w", err)
	}
	return out, nil
}

// ParseUnsigned reads a list without a signature (the bare Targets JSON) and
// checks its content against the format rules. Unknown fields are refused.
// It does not look at the clock.
func ParseUnsigned(data []byte) (*Targets, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var t Targets
	if err := dec.Decode(&t); err != nil {
		return nil, invalid("targets: %v", err)
	}
	if dec.More() {
		return nil, invalid("targets: trailing data")
	}
	if err := t.validate(); err != nil {
		return nil, err
	}
	return &t, nil
}

// Verify checks that the file is signed by one of the keys, reads the list
// and checks it: the format version, the content rules and the clock (not
// expired, and expiring at most MaxLifetime from now). Any of the keys may
// have signed it, which is what makes key rotation possible (docs/KEYS.md).
func Verify(pubs []ed25519.PublicKey, data []byte, now time.Time) (*Targets, error) {
	t, err := Open(pubs, data)
	if err != nil {
		return nil, err
	}
	if err := t.checkClock(now); err != nil {
		return nil, fmt.Errorf("verify targets: %w", err)
	}
	return t, nil
}

// Open is Verify without the clock check: the signature, the format version
// and the content rules.
func Open(pubs []ed25519.PublicKey, data []byte) (*Targets, error) {
	for _, pub := range pubs {
		if len(pub) != ed25519.PublicKeySize {
			return nil, errors.New("verify targets: invalid public key size")
		}
	}
	if len(pubs) == 0 {
		return nil, errors.New("verify targets: no public keys")
	}
	payload, sig, err := decode(data)
	if err != nil {
		return nil, fmt.Errorf("verify targets: %w", err)
	}

	// The signature first: nothing of an unsigned payload is interpreted.
	if !verifiedByAny(pubs, payload, sig) {
		return nil, fmt.Errorf("verify targets: %w", ErrBadSignature)
	}

	var t Targets // unknown fields are ignored: they are signed
	if err := json.Unmarshal(payload, &t); err != nil {
		return nil, fmt.Errorf("verify targets: %w", invalid("payload: %v", err))
	}
	if t.V > CurrentVersion {
		return nil, fmt.Errorf("verify targets: %w: v is %d, this agent knows up to %d", ErrUnsupportedVersion, t.V, CurrentVersion)
	}
	if err := t.validate(); err != nil {
		return nil, fmt.Errorf("verify targets: %w", err)
	}
	return &t, nil
}

// StoredRev returns the rev of a signed file without checking the signature.
// It is for the owner's own file, to keep revs growing when signing; an agent
// must use Open or Verify.
func StoredRev(data []byte) (string, error) {
	payload, _, err := decode(data)
	if err != nil {
		return "", err
	}
	var t struct {
		Rev string `json:"rev"`
	}
	if err := json.Unmarshal(payload, &t); err != nil {
		return "", invalid("payload: %v", err)
	}
	if _, err := parseRev(t.Rev); err != nil {
		return "", err
	}
	return t.Rev, nil
}

// decode splits the file into the payload bytes and the signature. Unknown
// fields next to payload and sig are ignored: they are not signed, so they
// carry no meaning.
func decode(data []byte) (payload, sig []byte, err error) {
	var f file
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, nil, invalid("file: %v", err)
	}
	if f.Payload == "" {
		return nil, nil, invalid("missing payload")
	}
	if f.Sig == "" {
		return nil, nil, invalid("missing sig")
	}
	if payload, err = base64.StdEncoding.DecodeString(f.Payload); err != nil {
		return nil, nil, invalid("payload is not base64")
	}
	if sig, err = base64.StdEncoding.DecodeString(f.Sig); err != nil {
		return nil, nil, invalid("sig is not base64")
	}
	return payload, sig, nil
}

func verifiedByAny(pubs []ed25519.PublicKey, payload, sig []byte) bool {
	if len(sig) != ed25519.SignatureSize {
		return false
	}
	for _, pub := range pubs {
		if ed25519.Verify(pub, payload, sig) {
			return true
		}
	}
	return false
}
