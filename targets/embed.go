// Package targets holds the signed targets list built into mayak
// (ADR-006, Q7). The list format and its checks live in internal/targets.
package targets

import _ "embed"

// signed is a string so that the built-in copy cannot be changed at run time.
//
//go:embed targets.signed.json
var signed string

// Signed returns the signed targets list built into the binary.
func Signed() []byte { return []byte(signed) }
