// Package targets defines the signed list of measurement targets.
//
// The agent probes only targets from this list (SPEC section 5); the list is
// signed with ed25519 so that it cannot be swapped on the way (section 12).
package targets

import (
	"errors"
	"fmt"
	"slices"
	"time"
	"unicode/utf8"
)

// MinRationaleLen is the minimum length of Target.Rationale, in characters.
const MinRationaleLen = 20

// Category is a target category.
type Category string

// Categories.
const (
	CategoryAI        Category = "ai"
	CategoryVideo     Category = "video"
	CategoryMessenger Category = "messenger"
	CategoryDev       Category = "dev"
	CategorySocial    Category = "social"
	CategoryInfra     Category = "infra"
)

// Categories returns all known categories.
func Categories() []Category {
	return []Category{
		CategoryAI, CategoryVideo, CategoryMessenger,
		CategoryDev, CategorySocial, CategoryInfra,
	}
}

// Format limits.
const (
	// CurrentVersion is the newest list format this code understands.
	CurrentVersion = 1

	// MaxLifetime is how far ahead of the signing time a list may expire.
	MaxLifetime = 30 * 24 * time.Hour
)

var (
	// ErrInvalid is returned for a list that breaks the format rules.
	ErrInvalid = errors.New("invalid targets")
	// ErrExpired is returned for a list whose expires is in the past.
	ErrExpired = errors.New("targets list expired")
	// ErrUnsupportedVersion is returned for a list with a newer format version.
	ErrUnsupportedVersion = errors.New("unsupported targets format version")
	// ErrRollback is returned when a list is older than the one already held.
	ErrRollback = errors.New("targets list is older than the stored one")
)

// Target is one service the agent may probe.
type Target struct {
	ID        string   `json:"id"`
	Host      string   `json:"host"`
	Category  Category `json:"category"`
	Rationale string   `json:"rationale"`
	Rev       string   `json:"rev"`
}

// Targets is a versioned list of targets.
//
// V is the format version. Rev is the revision, "YYYY-MM-DD.N" (e.g.
// "2026-10-13.1"), which only grows: see CheckRev. Expires is when the list
// stops being valid, at most MaxLifetime after it was signed, so that an old
// signed list cannot be replayed for ever.
type Targets struct {
	V       int       `json:"v"`
	Rev     string    `json:"rev"`
	Expires time.Time `json:"expires"`
	Items   []Target  `json:"items"`
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// validate checks the content of the list against the format rules. It does
// not look at the clock.
func (t Targets) validate() error {
	if t.V < 1 {
		return invalid("v is missing")
	}
	if _, err := parseRev(t.Rev); err != nil {
		return err
	}
	if t.Expires.IsZero() {
		return invalid("expires is missing")
	}
	if len(t.Items) == 0 {
		return invalid("list is empty")
	}
	seenID := make(map[string]bool, len(t.Items))
	seenHost := make(map[string]bool, len(t.Items))
	for i, it := range t.Items {
		if it.ID == "" {
			return invalid("items[%d]: empty id", i)
		}
		if seenID[it.ID] {
			return invalid("items[%d]: duplicate id %s", i, show(it.ID))
		}
		seenID[it.ID] = true

		if problem := hostProblem(it.Host); problem != "" {
			return invalid("items[%d]: %s", i, problem)
		}
		if seenHost[it.Host] {
			return invalid("items[%d]: duplicate host %s", i, show(it.Host))
		}
		seenHost[it.Host] = true

		if !slices.Contains(Categories(), it.Category) {
			return invalid("items[%d]: unknown category %s", i, show(string(it.Category)))
		}
		if utf8.RuneCountInString(it.Rationale) < MinRationaleLen {
			return invalid("items[%d]: rationale shorter than %d chars", i, MinRationaleLen)
		}
	}
	return nil
}

// checkClock checks expires against now: it must be in the future and not
// further than MaxLifetime ahead.
func (t Targets) checkClock(now time.Time) error {
	switch {
	case !now.Before(t.Expires):
		return ErrExpired
	case t.Expires.After(now.Add(MaxLifetime)):
		return invalid("expires is more than %d days ahead", int(MaxLifetime/(24*time.Hour)))
	}
	return nil
}
