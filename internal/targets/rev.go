package targets

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// parseRev splits "YYYY-MM-DD.N" (N has 1-4 digits) into its date and number.
func parseRev(rev string) (revKey, error) {
	date, n, ok := strings.Cut(rev, ".")
	if !ok || len(n) < 1 || len(n) > 4 || !allDigits(n) || len(date) != 10 {
		return revKey{}, invalid("rev must look like 2026-10-13.1")
	}
	d, err := time.Parse("2006-01-02", date)
	if err != nil {
		return revKey{}, invalid("rev must look like 2026-10-13.1")
	}
	num, _ := strconv.Atoi(n) // 1-4 digits, checked above
	return revKey{date: d, n: num}, nil
}

// revKey orders revisions: by date, then by the number as a number, so that
// "2026-10-13.10" is newer than "2026-10-13.9".
type revKey struct {
	date time.Time
	n    int
}

// CompareRev returns -1, 0 or 1 as a is older than, equal to or newer than b.
func CompareRev(a, b string) (int, error) {
	ka, err := parseRev(a)
	if err != nil {
		return 0, err
	}
	kb, err := parseRev(b)
	if err != nil {
		return 0, err
	}
	if c := ka.date.Compare(kb.date); c != 0 {
		return c, nil
	}
	switch {
	case ka.n < kb.n:
		return -1, nil
	case ka.n > kb.n:
		return 1, nil
	}
	return 0, nil
}

// CheckRev rejects a list that is older than the one already stored, so that
// an old signed list cannot be put in place of a newer one. The same rev is
// fine (it is the same list). An empty stored rev means nothing is stored.
func CheckRev(stored, next string) error {
	if stored == "" {
		_, err := parseRev(next)
		return err
	}
	c, err := CompareRev(next, stored)
	if err != nil {
		return err
	}
	if c < 0 {
		return fmt.Errorf("%w: have %s, got %s", ErrRollback, stored, next)
	}
	return nil
}
