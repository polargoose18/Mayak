// Package targets defines the signed list of measurement targets.
//
// The agent probes only targets from this list (SPEC section 5); the list is
// signed with ed25519 so that it cannot be swapped on the way (section 12).
package targets

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"
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

// ErrInvalid is returned for a list that breaks the format rules.
var ErrInvalid = errors.New("invalid targets")

// Target is one service the agent may probe.
//
// The field order is part of the canonical form (see canonical in sign.go);
// do not reorder fields.
type Target struct {
	ID        string   `json:"id"`
	Host      string   `json:"host"`
	Category  Category `json:"category"`
	Rationale string   `json:"rationale"`
	Rev       string   `json:"rev"`
}

// Targets is a versioned list of targets, e.g. Rev "2026-10-13.1".
type Targets struct {
	Rev   string   `json:"rev"`
	Items []Target `json:"items"`
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// validate checks the list against the format rules.
func (t Targets) validate() error {
	if len(t.Items) == 0 {
		return invalid("list is empty")
	}
	seen := make(map[string]bool, len(t.Items))
	for i, it := range t.Items {
		if it.ID == "" {
			return invalid("items[%d]: empty id", i)
		}
		if seen[it.ID] {
			return invalid("items[%d]: duplicate id %q", i, it.ID)
		}
		seen[it.ID] = true

		if it.Host == "" {
			return invalid("items[%d]: empty host", i)
		}
		if strings.IndexFunc(it.Host, unicode.IsSpace) >= 0 {
			return invalid("items[%d]: host contains whitespace", i)
		}
		if strings.Contains(it.Host, "://") {
			return invalid("items[%d]: host contains a scheme", i)
		}
		if !slices.Contains(Categories(), it.Category) {
			return invalid("items[%d]: unknown category %q", i, it.Category)
		}
		if utf8.RuneCountInString(it.Rationale) < MinRationaleLen {
			return invalid("items[%d]: rationale shorter than %d chars", i, MinRationaleLen)
		}
	}
	return nil
}
