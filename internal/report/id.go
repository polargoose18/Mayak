package report

import (
	"crypto/rand"
	"encoding/hex"
)

// reportIDBytes is the number of random bytes behind a 10-char report ID.
const reportIDBytes = 5

// NewReportID returns a random report ID: 10 lowercase hex characters.
func NewReportID() string {
	var b [reportIDBytes]byte
	// Since Go 1.24 rand.Read never returns an error (it aborts the program).
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
