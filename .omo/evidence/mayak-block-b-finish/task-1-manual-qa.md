# manualQa matrix — task 1: Map one run to a mayak.report/1 document

Goal: `internal/runner/report.go` implementing `BuildReport`, `OSName`, `IPVersion` against the contract in `internal/runner/report_test.go`.

## surfaceEvidence

| scenario | criterion | surface | invocation | verdict | artifactRefs |
|---|---|---|---|---|---|
| build-report-all-verdicts | verdict→test table exact (14 verdicts) | CLI/data (go test) | `go test ./internal/runner -run 'TestBuildReport\|TestOSName\|TestIPVersion' -count=1 -v` | PASS | qa-targeted |
| omit-zero-evidence | evidence omits zero keys; nil when all zero | CLI/data | same, subtest `TestBuildReportOmitsZeroEvidence` | PASS | qa-targeted |
| too-large-report | >64KiB → error wrapping report.ErrInvalid | CLI/data | same, subtest `TestBuildReportTooLarge` | PASS | qa-targeted |
| unknown-verdict | error wraps report.ErrInvalid | CLI/data | same, subtest `TestBuildReportUnknownVerdict` | PASS | qa-targeted |
| full-suite | no regressions | go test | `go test ./... -count=1` | PASS (exit 0) | qa-full |
| make-check | fmt+vet+test green | make | `make check` | PASS (exit 0) | qa-check |
| emitted-document | real JSON + `report.Validate` PASS | CLI/data | `go test ./internal/runner -run TestQADump -v` (temporary QA dump test, removed after) | PASS | qa-dump |

## adversarialCases

| scenario | criterion | class | expected behavior | verdict | artifactRefs |
|---|---|---|---|---|---|
| unknown-verdict | table total + ErrInvalid wrap | invalid input | error wrapping `report.ErrInvalid`, not a panic | PASS | qa-targeted |
| too-large-report | 64KiB ceiling | resource limit | error wrapping `report.ErrInvalid` (validator's ErrTooLarge rewrapped) | PASS | qa-targeted |
| omit-zero-evidence | privacy: empty run yields no evidence keys | privacy / data minimization | `evidence: nil` when nothing observed | PASS | qa-targeted |
| n/a cases | — | — | no network/HTTP surfaces triggered by this change; no browser or GUI surface exists in repo | not_applicable: change is a pure in-process data mapping, no external surface | — |

## artifactRefs

| id | kind | description | path |
|---|---|---|---|
| qa-targeted | test-run output | targeted go test -v output | .omo/evidence/mayak-block-b-finish/task-1-report-mapping.log §1 |
| qa-full | test-run output | `go test ./... -count=1` | same, §2 |
| qa-check | build output | `make check` exit 0 | same, §3 |
| qa-dump | JSON document + validator PASS | full emitted mayak.report/1 doc (sni_block scenario) + `report.Validate: PASS` line | same, §4 |

Code under test: `internal/runner/report.go` (tests pre-existing: `internal/runner/report_test.go`).
