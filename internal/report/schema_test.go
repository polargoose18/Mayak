package report

import (
	"encoding/json"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// TestSchemaMatchesConstants keeps schema/report.schema.json in sync with
// the Go constants, since Validate does not read the schema file.
func TestSchemaMatchesConstants(t *testing.T) {
	b, err := os.ReadFile("../../schema/report.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var s struct {
		Properties struct {
			Results struct {
				Items struct {
					Properties struct {
						Test    struct{ Enum []string } `json:"test"`
						Verdict struct{ Enum []string } `json:"verdict"`
					} `json:"properties"`
				} `json:"items"`
			} `json:"results"`
			Schema struct{ Const string } `json:"schema"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	var verdicts, tests []string
	for _, v := range Verdicts() {
		verdicts = append(verdicts, string(v))
	}
	for _, v := range Tests() {
		tests = append(tests, string(v))
	}
	props := s.Properties.Results.Items.Properties
	if !slices.Equal(props.Verdict.Enum, verdicts) {
		t.Errorf("schema verdicts = %v, want %v", props.Verdict.Enum, verdicts)
	}
	if !slices.Equal(props.Test.Enum, tests) {
		t.Errorf("schema tests = %v, want %v", props.Test.Enum, tests)
	}
	if s.Properties.Schema.Const != SchemaID {
		t.Errorf("schema const = %q, want %q", s.Properties.Schema.Const, SchemaID)
	}
}

// The hand-written matchers and the schema patterns must accept the same
// strings, and the schema enums must hold the same values as the constants.
func TestSchemaFieldsMatchValidator(t *testing.T) {
	b, err := os.ReadFile("../../schema/report.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var s struct {
		Properties struct {
			TargetsRev struct{ Pattern string } `json:"targets_rev"`
			Agent      struct {
				Properties struct {
					Ver struct{ Pattern string }
					OS  struct{ Enum []string } `json:"os"`
				}
			}
			Net struct {
				Properties struct {
					IPVer    struct{ Enum []int }    `json:"ip_ver"`
					Resolver struct{ Enum []string } `json:"resolver"`
					Region   struct{ Pattern string }
				}
			}
			Results struct {
				MinItems, MaxItems int
				Items              struct {
					Properties struct {
						Target struct{ Pattern string }
					}
				}
			}
		}
	}
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	p := s.Properties
	if !slices.Equal(p.Agent.Properties.OS.Enum, OSes()) {
		t.Errorf("schema os = %v, want %v", p.Agent.Properties.OS.Enum, OSes())
	}
	if !slices.Equal(p.Net.Properties.Resolver.Enum, Resolvers()) {
		t.Errorf("schema resolver = %v, want %v", p.Net.Properties.Resolver.Enum, Resolvers())
	}
	if !slices.Equal(p.Net.Properties.IPVer.Enum, []int{4, 6}) {
		t.Errorf("schema ip_ver = %v", p.Net.Properties.IPVer.Enum)
	}
	if p.Results.MinItems != 1 || p.Results.MaxItems != MaxResults {
		t.Errorf("schema results items = %d..%d", p.Results.MinItems, p.Results.MaxItems)
	}

	corpus := []string{
		"", "0.3", "10.20", "123.456", "1234.1", "0.", ".3", "0.3.1", "dev", "Dev", "v0.3", "a.b", "1.2 ", " 1.2",
		"RU-MOW", "RU-S01", "RU-MOSC", "ru-mow", "RUMOW", "RU-", "-MOW", "RU-MO-W", "R-MOW", "RUS-MOW", "203.0.113.7",
		"2026-10-13.1", "2026-10-13.1234", "2026-10-13.12345", "2026-10-13", "2026-1-13.1", "26-10-13.1", "2026-10-13.", "2026-10-13.1.2", "x2026-10-13.1",
		"a", "a-1", "A", "a.b", "a_b", "-", strings.Repeat("a", 64), strings.Repeat("a", 65), "пример",
	}
	checks := []struct {
		name    string
		pattern string
		match   func(string) bool
	}{
		{"agent.ver", p.Agent.Properties.Ver.Pattern, isAgentVersion},
		{"net.region", p.Net.Properties.Region.Pattern, isRegion},
		{"targets_rev", p.TargetsRev.Pattern, isTargetsRev},
		{"target", p.Results.Items.Properties.Target.Pattern, isTargetID},
	}
	for _, c := range checks {
		re, err := regexp.Compile(c.pattern)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		for _, v := range corpus {
			if re.MatchString(v) != c.match(v) {
				t.Errorf("%s: schema pattern says %v for %q, validator says %v", c.name, re.MatchString(v), v, c.match(v))
			}
		}
	}
}
