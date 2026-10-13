package report

import (
	"encoding/json"
	"os"
	"slices"
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
