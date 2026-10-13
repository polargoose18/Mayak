package report

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"
	"unicode/utf8"
)

// Limits from SPEC section 7.
const (
	MaxReportSize     = 64 * 1024
	MaxEvidenceString = 200
	MaxEvidenceDepth  = 2
	reportIDLen       = 10
	tsGranularity     = 5 * time.Minute
)

var (
	// ErrTooLarge is returned for reports over MaxReportSize bytes.
	ErrTooLarge = errors.New("report too large")
	// ErrInvalid is returned for reports that do not match the schema.
	ErrInvalid = errors.New("invalid report")
)

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// Validate parses and checks a mayak.report/1 document. Unknown fields are
// dropped, ts is rounded down to 5 minutes (UTC). Error messages never
// contain values from the input.
func Validate(data []byte) (*Report, error) {
	if len(data) > MaxReportSize {
		return nil, ErrTooLarge
	}

	var r Report
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, invalid("decode: %v", err)
	}
	if err := checkRequired(data); err != nil {
		return nil, err
	}

	if r.Schema != SchemaID {
		return nil, invalid("schema must be %q", SchemaID)
	}
	if !isReportID(r.ReportID) {
		return nil, invalid("report_id must be %d lowercase hex chars", reportIDLen)
	}
	if r.Agent.Source != SourceCLI && r.Agent.Source != SourceWeb {
		return nil, invalid("agent.source must be %q or %q", SourceCLI, SourceWeb)
	}
	if !isCountry(r.Net.Country) {
		return nil, invalid("net.country must be two uppercase letters or empty")
	}
	for i, res := range r.Results {
		if !slices.Contains(Tests(), res.Test) {
			return nil, invalid("results[%d].test is unknown", i)
		}
		if !slices.Contains(Verdicts(), res.Verdict) {
			return nil, invalid("results[%d].verdict is unknown", i)
		}
		if err := checkEvidence(res.Evidence, 1); err != nil {
			return nil, invalid("results[%d].evidence: %v", i, err)
		}
	}

	r.TS = r.TS.UTC().Truncate(tsGranularity)
	return &r, nil
}

// checkRequired verifies the presence of required keys, which the typed
// decode alone cannot tell apart from zero values.
func checkRequired(data []byte) error {
	// Validate has already decoded data into Report, so the shape is known
	// to be right and the Unmarshal errors below cannot happen.
	var top map[string]json.RawMessage
	_ = json.Unmarshal(data, &top)
	if err := need(top, "report", "schema", "report_id", "ts", "agent", "net", "targets_rev", "results"); err != nil {
		return err
	}
	for _, sub := range []struct {
		key  string
		need []string
	}{
		{"agent", []string{"ver", "os", "source"}},
		{"net", []string{"ip_ver", "resolver", "country"}},
	} {
		var m map[string]json.RawMessage
		_ = json.Unmarshal(top[sub.key], &m)
		if err := need(m, sub.key, sub.need...); err != nil {
			return err
		}
	}
	var results []map[string]json.RawMessage
	_ = json.Unmarshal(top["results"], &results)
	if results == nil {
		return invalid("results must be an array")
	}
	for i, m := range results {
		if err := need(m, fmt.Sprintf("results[%d]", i), "target", "test", "verdict"); err != nil {
			return err
		}
	}
	return nil
}

func need(m map[string]json.RawMessage, where string, keys ...string) error {
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			return invalid("%s: missing %q", where, k)
		}
	}
	return nil
}

func isReportID(s string) bool {
	if len(s) != reportIDLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func isCountry(s string) bool {
	if s == "" {
		return true
	}
	return len(s) == 2 && s[0] >= 'A' && s[0] <= 'Z' && s[1] >= 'A' && s[1] <= 'Z'
}

// checkEvidence enforces the evidence limits. The evidence object itself is
// level 1; objects and arrays inside it are level 2 and may only hold scalars.
func checkEvidence(v any, depth int) error {
	switch x := v.(type) {
	case map[string]any:
		if depth > MaxEvidenceDepth {
			return fmt.Errorf("nesting deeper than %d levels", MaxEvidenceDepth)
		}
		for _, child := range x {
			if err := checkEvidence(child, depth+1); err != nil {
				return err
			}
		}
	case []any:
		if depth > MaxEvidenceDepth {
			return fmt.Errorf("nesting deeper than %d levels", MaxEvidenceDepth)
		}
		for _, child := range x {
			if err := checkEvidence(child, depth+1); err != nil {
				return err
			}
		}
	case string:
		if utf8.RuneCountInString(x) > MaxEvidenceString {
			return fmt.Errorf("string longer than %d chars", MaxEvidenceString)
		}
	}
	return nil
}
