package targets

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
)

// PublicKeys returns the ed25519 public keys the agent trusts for the
// targets list. A list signed by any of them is accepted (see Verify), which
// is what makes key rotation possible: see docs/KEYS.md.
func PublicKeys() []ed25519.PublicKey {
	// ЗАМЕНИТЬ реальным перед релизом. Это тестовый ключ, его приватная часть
	// не сохранена, поэтому подписать список им нельзя. Метка TESTKEY ниже
	// нужна цели `make release-check`: пока она есть в файле, релиз невозможен.
	encoded := []string{
		"n8O6Ai33OUIh9meb91UtYW5YBmQQuUZA3FQkwBzvMvQ=", 
	}

	keys := make([]ed25519.PublicKey, 0, len(encoded))
	for _, s := range encoded {
		raw, err := base64.StdEncoding.DecodeString(s)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			// The strings above are constants; a bad one is a programming error.
			panic(fmt.Sprintf("targets: invalid built-in public key %q", s))
		}
		keys = append(keys, ed25519.PublicKey(raw))
	}
	return keys
}
