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
	MaxResults        = 200
	reportIDLen       = 10
	tsGranularity     = 5 * time.Minute

	// ValidateAt accepts timestamps from MaxTSAge in the past to MaxTSAhead
	// in the future.
	MaxTSAge   = 24 * time.Hour
	MaxTSAhead = 5 * time.Minute
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
// contain values from the input. It does not look at the clock; use
// ValidateAt for reports that arrive from outside.
func Validate(data []byte) (*Report, error) {
	r, err := parse(data)
	if err != nil {
		return nil, err
	}
	r.TS = r.TS.UTC().Truncate(tsGranularity)
	return r, nil
}

// ValidateAt is Validate plus a check that ts is not older than MaxTSAge and
// not further ahead than MaxTSAhead of now.
func ValidateAt(data []byte, now time.Time) (*Report, error) {
	r, err := parse(data)
	if err != nil {
		return nil, err
	}
	if r.TS.Before(now.Add(-MaxTSAge)) || r.TS.After(now.Add(MaxTSAhead)) {
		return nil, invalid("ts is outside the accepted window")
	}
	r.TS = r.TS.UTC().Truncate(tsGranularity)
	return r, nil
}

// parse does all checks except the clock ones and leaves ts as sent.
func parse(data []byte) (*Report, error) {
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
	if !isTargetsRev(r.TargetsRev) {
		return nil, invalid("targets_rev must look like 2026-10-13.1")
	}
	if !isAgentVersion(r.Agent.Ver) {
		return nil, invalid("agent.ver must be major.minor or dev")
	}
	if !slices.Contains(OSes(), r.Agent.OS) {
		return nil, invalid("agent.os is unknown")
	}
	if r.Agent.Source != SourceCLI && r.Agent.Source != SourceWeb {
		return nil, invalid("agent.source must be %q or %q", SourceCLI, SourceWeb)
	}
	if r.Net.IPVer != 4 && r.Net.IPVer != 6 {
		return nil, invalid("net.ip_ver must be 4 or 6")
	}
	if !slices.Contains(Resolvers(), r.Net.Resolver) {
		return nil, invalid("net.resolver is unknown")
	}
	if !isCountry(r.Net.Country) {
		return nil, invalid("net.country must be two uppercase letters or empty")
	}
	if r.Net.Region != nil && !isRegion(*r.Net.Region) {
		return nil, invalid("net.region must look like RU-MOW or be null")
	}
	if n := len(r.Results); n < 1 || n > MaxResults {
		return nil, invalid("results must hold 1 to %d items", MaxResults)
	}
	for i, res := range r.Results {
		if !isTargetID(res.Target) {
			return nil, invalid("results[%d].target must be 1-64 chars of a-z, 0-9, -", i)
		}
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

func isReportID(s string) bool { return allOf(s, reportIDLen, reportIDLen, isHexLow) }

func isCountry(s string) bool { return s == "" || allOf(s, 2, 2, isUpper) }

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
