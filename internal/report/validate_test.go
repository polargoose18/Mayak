package report

import (
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite golden files")

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestValidateGolden(t *testing.T) {
	tests := []struct {
		file    string
		wantErr error
	}{
		{file: "valid"},
		{file: "extra_fields"},
		{file: "odd_ts"},
		{file: "too_large", wantErr: ErrTooLarge},
		{file: "unknown_verdict", wantErr: ErrInvalid},
		{file: "bad_os_login", wantErr: ErrInvalid},
		{file: "bad_region_address", wantErr: ErrInvalid},
		{file: "bad_ver_ip", wantErr: ErrInvalid},
		{file: "empty_results", wantErr: ErrInvalid},
		{file: "too_many_results", wantErr: ErrInvalid},
	}
	for _, tc := range tests {
		t.Run(tc.file, func(t *testing.T) {
			got, err := Validate(readTestdata(t, tc.file+".json"))
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				if got != nil {
					t.Errorf("report = %+v, want nil on error", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			out, err := json.MarshalIndent(got, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, '\n')
			golden := filepath.Join("testdata", tc.file+".golden.json")
			if *update {
				if err := os.WriteFile(golden, out, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatal(err)
			}
			if string(out) != string(want) {
				t.Errorf("output mismatch\ngot:\n%s\nwant:\n%s", out, want)
			}
		})
	}
}

// mutate returns valid.json with the given top-level edit applied.
func mutate(t *testing.T, edit func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(readTestdata(t, "valid.json"), &m); err != nil {
		t.Fatal(err)
	}
	edit(m)
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func firstResult(m map[string]any) map[string]any {
	return m["results"].([]any)[0].(map[string]any)
}

func TestValidateRejects(t *testing.T) {
	longStr := strings.Repeat("x", MaxEvidenceString+1)
	tests := []struct {
		name string
		edit func(m map[string]any)
	}{
		{"wrong schema", func(m map[string]any) { m["schema"] = "mayak.report/2" }},
		{"report_id too short", func(m map[string]any) { m["report_id"] = "b7c1e0a4f" }},
		{"report_id too long", func(m map[string]any) { m["report_id"] = "b7c1e0a4f2a" }},
		{"report_id uppercase hex", func(m map[string]any) { m["report_id"] = "B7C1E0A4F2" }},
		{"report_id non-hex", func(m map[string]any) { m["report_id"] = "b7c1e0a4fg" }},
		{"report_id below 0", func(m map[string]any) { m["report_id"] = "b7c1e0a4f/" }},
		{"source unknown", func(m map[string]any) { m["agent"].(map[string]any)["source"] = "app" }},
		{"country lowercase", func(m map[string]any) { m["net"].(map[string]any)["country"] = "ru" }},
		{"country one letter", func(m map[string]any) { m["net"].(map[string]any)["country"] = "R" }},
		{"country three letters", func(m map[string]any) { m["net"].(map[string]any)["country"] = "RUS" }},
		{"country second not letter", func(m map[string]any) { m["net"].(map[string]any)["country"] = "R1" }},
		{"ip_ver 5", func(m map[string]any) { m["net"].(map[string]any)["ip_ver"] = 5 }},
		{"ip_ver 0", func(m map[string]any) { m["net"].(map[string]any)["ip_ver"] = 0 }},
		{"ip_ver 44", func(m map[string]any) { m["net"].(map[string]any)["ip_ver"] = 44 }},
		{"os with arch", func(m map[string]any) { m["agent"].(map[string]any)["os"] = "linux/arm64" }},
		{"os uppercase", func(m map[string]any) { m["agent"].(map[string]any)["os"] = "Linux" }},
		{"os empty", func(m map[string]any) { m["agent"].(map[string]any)["os"] = "" }},
		{"ver three parts", func(m map[string]any) { m["agent"].(map[string]any)["ver"] = "0.3.1" }},
		{"ver one part", func(m map[string]any) { m["agent"].(map[string]any)["ver"] = "3" }},
		{"ver four digits", func(m map[string]any) { m["agent"].(map[string]any)["ver"] = "1000.1" }},
		{"ver with v", func(m map[string]any) { m["agent"].(map[string]any)["ver"] = "v0.3" }},
		{"ver trailing dot", func(m map[string]any) { m["agent"].(map[string]any)["ver"] = "0." }},
		{"ver Dev", func(m map[string]any) { m["agent"].(map[string]any)["ver"] = "Dev" }},
		{"resolver unknown value", func(m map[string]any) { m["net"].(map[string]any)["resolver"] = "8.8.8.8" }},
		{"resolver empty", func(m map[string]any) { m["net"].(map[string]any)["resolver"] = "" }},
		{"region city", func(m map[string]any) { m["net"].(map[string]any)["region"] = "Moscow" }},
		{"region lowercase", func(m map[string]any) { m["net"].(map[string]any)["region"] = "ru-mow" }},
		{"region no dash", func(m map[string]any) { m["net"].(map[string]any)["region"] = "RUMOW" }},
		{"region too long", func(m map[string]any) { m["net"].(map[string]any)["region"] = "RU-MOSC" }},
		{"region empty", func(m map[string]any) { m["net"].(map[string]any)["region"] = "" }},
		{"region two dashes", func(m map[string]any) { m["net"].(map[string]any)["region"] = "RU-MO-W" }},
		{"targets_rev free text", func(m map[string]any) { m["targets_rev"] = "alice" }},
		{"targets_rev no number", func(m map[string]any) { m["targets_rev"] = "2026-10-13" }},
		{"targets_rev short date", func(m map[string]any) { m["targets_rev"] = "2026-1-13.1" }},
		{"targets_rev long number", func(m map[string]any) { m["targets_rev"] = "2026-10-13.12345" }},
		{"targets_rev two dots", func(m map[string]any) { m["targets_rev"] = "2026-10-13.1.2" }},
		{"target with uppercase", func(m map[string]any) { firstResult(m)["target"] = "Example" }},
		{"target with dot", func(m map[string]any) { firstResult(m)["target"] = "example.org" }},
		{"target empty", func(m map[string]any) { firstResult(m)["target"] = "" }},
		{"target 65 chars", func(m map[string]any) { firstResult(m)["target"] = strings.Repeat("a", 65) }},
		{"no results", func(m map[string]any) { m["results"] = []any{} }},
		{"201 results", func(m map[string]any) {
			r := make([]any, MaxResults+1)
			for i := range r {
				r[i] = map[string]any{"target": "a", "test": "dns", "verdict": "ok"}
			}
			m["results"] = r
		}},
		{"unknown test", func(m map[string]any) { firstResult(m)["test"] = "ping" }},
		{"unknown verdict", func(m map[string]any) { firstResult(m)["verdict"] = "blocked" }},
		{"evidence string too long", func(m map[string]any) { firstResult(m)["evidence"] = map[string]any{"e": longStr} }},
		{"evidence nested string too long", func(m map[string]any) {
			firstResult(m)["evidence"] = map[string]any{"e": map[string]any{"k": longStr}}
		}},
		{"evidence too deep object", func(m map[string]any) {
			firstResult(m)["evidence"] = map[string]any{"a": map[string]any{"b": map[string]any{"c": 1}}}
		}},
		{"evidence too deep array", func(m map[string]any) {
			firstResult(m)["evidence"] = map[string]any{"a": []any{[]any{1}}}
		}},
		{"evidence array in object too deep", func(m map[string]any) {
			firstResult(m)["evidence"] = map[string]any{"a": map[string]any{"b": []any{1}}}
		}},
		{"missing top-level key", func(m map[string]any) { delete(m, "targets_rev") }},
		{"missing ts", func(m map[string]any) { delete(m, "ts") }},
		{"missing agent key", func(m map[string]any) { delete(m["agent"].(map[string]any), "os") }},
		{"missing net key", func(m map[string]any) { delete(m["net"].(map[string]any), "ip_ver") }},
		{"missing result key", func(m map[string]any) { delete(firstResult(m), "target") }},
		{"agent null", func(m map[string]any) { m["agent"] = nil }},
		{"agent not object", func(m map[string]any) { m["agent"] = "cli" }},
		{"results null", func(m map[string]any) { m["results"] = nil }},
		{"results not array", func(m map[string]any) { m["results"] = "x" }},
		{"result not object", func(m map[string]any) { m["results"] = []any{1} }},
		{"ts not a time", func(m map[string]any) { m["ts"] = "yesterday" }},
		{"ip_ver wrong type", func(m map[string]any) { m["net"].(map[string]any)["ip_ver"] = "4" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Validate(mutate(t, tc.edit))
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("err = %v, want ErrInvalid", err)
			}
			if got != nil {
				t.Errorf("report = %+v, want nil on error", got)
			}
		})
	}
}

func TestValidateMalformedJSON(t *testing.T) {
	for _, in := range []string{"", "not json", "{", "[]", `{"schema":"mayak.report/1"} trailing`} {
		if _, err := Validate([]byte(in)); !errors.Is(err, ErrInvalid) {
			t.Errorf("Validate(%q) err = %v, want ErrInvalid", in, err)
		}
	}
}

func TestValidateAcceptsEdgeCases(t *testing.T) {
	tests := []struct {
		name string
		edit func(m map[string]any)
	}{
		{"empty country", func(m map[string]any) { m["net"].(map[string]any)["country"] = "" }},
		{"source web", func(m map[string]any) { m["agent"].(map[string]any)["source"] = "web" }},
		{"region set", func(m map[string]any) { m["net"].(map[string]any)["region"] = "RU-MOW" }},
		{"region with digits", func(m map[string]any) { m["net"].(map[string]any)["region"] = "RU-S01" }},
		{"region null", func(m map[string]any) { m["net"].(map[string]any)["region"] = nil }},
		{"ver dev", func(m map[string]any) { m["agent"].(map[string]any)["ver"] = "dev" }},
		{"ver three digits", func(m map[string]any) { m["agent"].(map[string]any)["ver"] = "123.456" }},
		{"ip_ver 6", func(m map[string]any) { m["net"].(map[string]any)["ip_ver"] = 6 }},
		{"target 64 chars with dash and digits", func(m map[string]any) { firstResult(m)["target"] = "a-1" + strings.Repeat("b", 61) }},
		{"200 results", func(m map[string]any) {
			r := make([]any, MaxResults)
			for i := range r {
				r[i] = map[string]any{"target": "a", "test": "dns", "verdict": "ok"}
			}
			m["results"] = r
		}},
		{"targets_rev with long number", func(m map[string]any) { m["targets_rev"] = "2026-10-13.1234" }},
		{"region absent", func(m map[string]any) { delete(m["net"].(map[string]any), "region") }},
		{"no evidence", func(m map[string]any) { delete(firstResult(m), "evidence") }},
		{"evidence string at limit", func(m map[string]any) {
			firstResult(m)["evidence"] = map[string]any{"e": strings.Repeat("я", MaxEvidenceString)}
		}},
		{"evidence at depth limit", func(m map[string]any) {
			firstResult(m)["evidence"] = map[string]any{"a": map[string]any{"b": 1}, "c": []any{1, "x"}}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Validate(mutate(t, tc.edit)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestValidateAllKnownValues(t *testing.T) {
	for _, v := range Verdicts() {
		for _, tst := range Tests() {
			b := mutate(t, func(m map[string]any) {
				firstResult(m)["verdict"] = string(v)
				firstResult(m)["test"] = string(tst)
			})
			if _, err := Validate(b); err != nil {
				t.Errorf("verdict %q test %q: %v", v, tst, err)
			}
		}
	}
}

func TestValidateAllOSesAndResolvers(t *testing.T) {
	for _, os := range OSes() {
		for _, res := range Resolvers() {
			b := mutate(t, func(m map[string]any) {
				m["agent"].(map[string]any)["os"] = os
				m["net"].(map[string]any)["resolver"] = res
			})
			if _, err := Validate(b); err != nil {
				t.Errorf("os %q resolver %q: %v", os, res, err)
			}
		}
	}
}

func TestValidateAt(t *testing.T) {
	now := time.Date(2026, 10, 13, 12, 40, 0, 0, time.UTC)
	tests := []struct {
		ts string
		ok bool
	}{
		{"2026-10-13T12:30:00Z", true},
		{"2026-10-13T12:44:59Z", true},       // within 5 minutes ahead
		{"2026-10-13T12:45:00Z", true},       // exactly 5 minutes ahead
		{"2026-10-13T12:45:01Z", false},      // just over
		{"2026-10-12T12:40:00Z", true},       // exactly 24 hours old
		{"2026-10-12T12:39:59Z", false},      // just over
		{"2026-10-12T15:40:00+03:00", true},  // offsets are honoured: 12:40Z
		{"2026-10-12T14:00:00+03:00", false}, // 11:00Z is too old
		{"2099-01-01T00:00:00Z", false},      // far future
		{"2020-01-01T00:00:00Z", false},      // far past
	}
	for _, tc := range tests {
		t.Run(tc.ts, func(t *testing.T) {
			r, err := ValidateAt(mutate(t, func(m map[string]any) { m["ts"] = tc.ts }), now)
			if tc.ok {
				if err != nil {
					t.Fatal(err)
				}
				if r.TS.Minute()%5 != 0 || r.TS.Second() != 0 {
					t.Errorf("ts %v is not rounded", r.TS)
				}
				return
			}
			if !errors.Is(err, ErrInvalid) || r != nil {
				t.Errorf("r = %v, err = %v; want ErrInvalid", r, err)
			}
		})
	}

	// The checks of Validate still apply.
	if _, err := ValidateAt(readTestdata(t, "bad_os_login.json"), now); !errors.Is(err, ErrInvalid) {
		t.Errorf("bad os: err = %v", err)
	}
	if _, err := ValidateAt(make([]byte, MaxReportSize+1), now); !errors.Is(err, ErrTooLarge) {
		t.Errorf("too large: err = %v", err)
	}
	// Validate itself does not look at the clock.
	if _, err := Validate(readTestdata(t, "ts_2099.json")); err != nil {
		t.Errorf("Validate must accept any ts: %v", err)
	}
	if _, err := ValidateAt(readTestdata(t, "ts_2099.json"), now); !errors.Is(err, ErrInvalid) {
		t.Errorf("ts 2099: err = %v", err)
	}
}

func TestValidateSizeLimit(t *testing.T) {
	base := readTestdata(t, "valid.json")
	// Pad with an unknown field to reach exactly n bytes.
	pad := func(n int) []byte {
		head := strings.TrimRight(string(base), " \n")
		head = head[:len(head)-1] + `,"pad":"`
		fill := n - len(head) - len(`"}`)
		return []byte(head + strings.Repeat("a", fill) + `"}`)
	}
	if b := pad(MaxReportSize); len(b) != MaxReportSize {
		t.Fatalf("pad produced %d bytes", len(b))
	} else if _, err := Validate(b); err != nil {
		t.Errorf("exactly %d bytes: %v", MaxReportSize, err)
	}
	if _, err := Validate(pad(MaxReportSize + 1)); !errors.Is(err, ErrTooLarge) {
		t.Errorf("%d bytes: err = %v, want ErrTooLarge", MaxReportSize+1, err)
	}
}

func TestValidateRoundsTS(t *testing.T) {
	tests := []struct{ in, want string }{
		{"2026-10-13T12:30:00Z", "2026-10-13T12:30:00Z"},
		{"2026-10-13T12:34:59Z", "2026-10-13T12:30:00Z"},
		{"2026-10-13T12:35:00Z", "2026-10-13T12:35:00Z"},
		{"2026-10-13T12:59:59.999Z", "2026-10-13T12:55:00Z"},
		{"2026-10-13T15:37:42+03:00", "2026-10-13T12:35:00Z"},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			r, err := Validate(mutate(t, func(m map[string]any) { m["ts"] = tc.in }))
			if err != nil {
				t.Fatal(err)
			}
			want, _ := time.Parse(time.RFC3339, tc.want)
			if !r.TS.Equal(want) || r.TS.Location() != time.UTC {
				t.Errorf("ts = %v, want %v UTC", r.TS, want)
			}
		})
	}
}

func TestValidateDropsUnknownFields(t *testing.T) {
	r, err := Validate(readTestdata(t, "extra_fields.json"))
	if err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(r)
	for _, leak := range []string{"client_ip", "203.0.113.7", "extra"} {
		if strings.Contains(string(out), leak) {
			t.Errorf("output still contains %q: %s", leak, out)
		}
	}
}

func TestErrorsDoNotEchoInput(t *testing.T) {
	const secret = "alice@203.0.113.7"
	edits := map[string]func(m map[string]any){
		"report_id":   func(m map[string]any) { m["report_id"] = secret },
		"os":          func(m map[string]any) { m["agent"].(map[string]any)["os"] = secret },
		"ver":         func(m map[string]any) { m["agent"].(map[string]any)["ver"] = secret },
		"source":      func(m map[string]any) { m["agent"].(map[string]any)["source"] = secret },
		"resolver":    func(m map[string]any) { m["net"].(map[string]any)["resolver"] = secret },
		"region":      func(m map[string]any) { m["net"].(map[string]any)["region"] = secret },
		"country":     func(m map[string]any) { m["net"].(map[string]any)["country"] = secret },
		"targets_rev": func(m map[string]any) { m["targets_rev"] = secret },
		"target":      func(m map[string]any) { firstResult(m)["target"] = secret },
		"test":        func(m map[string]any) { firstResult(m)["test"] = secret },
		"verdict":     func(m map[string]any) { firstResult(m)["verdict"] = secret },
		"evidence":    func(m map[string]any) { firstResult(m)["evidence"] = map[string]any{"e": strings.Repeat(secret, 20)} },
	}
	for name, edit := range edits {
		_, err := Validate(mutate(t, edit))
		if err == nil || strings.Contains(err.Error(), "203.0.113.7") || strings.Contains(err.Error(), "alice") {
			t.Errorf("%s: err = %v, must fail without echoing the input", name, err)
		}
	}
}
