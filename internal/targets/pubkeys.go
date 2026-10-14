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
	// Правило для `make release-check` (его же CI запускает на тегах v*):
	// пока в этом файле есть строка ключа с меткой TESTKEY в конце, релиз
	// невозможен. Метка ставится только на тестовый ключ. Реальный ключ
	// добавляют строкой без метки, а тестовый удаляют вместе с его строкой.
	// Этот комментарий под проверку не попадает: она ищет метку сразу после
	// кавычки и запятой, как в строке с ключом.
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
