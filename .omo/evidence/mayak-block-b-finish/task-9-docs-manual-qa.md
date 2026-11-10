# manualQa

Worktree: `/home/goose/Documents/Mayak-wt/block-b-wave1`.
Goal: `task-9-docs`. Caller evidence directory used; no JS eval tool or ULW attempt directory is available in this executor.

Only README product documentation was edited. Existing changes in README and other files belong to the shared worktree and were preserved. All artifact contents cited below were independently read after execution. Historical entries before `=== Task 9 correction: baseline ===` are retained but are not evidence for these verdicts.

## surfaceEvidence

| scenario id | criterion reference | surface | exact invocation | verdict | artifactRefs |
| --- | --- | --- | --- | --- | --- |
| DOC-9-TEXT | Remove stale version-only description; include control and runner paths | README via CLI | `grep -n "пока только version\|cmd/mayak-ctrl\|internal/runner" README.md` | PASS: no stale phrase; both structure entries and corresponding status entries present | A1, A2 |
| DOC-9-DIFF | README-only correction, Russian descriptions and explicit pending deployment | Git diff via CLI | `git diff -- README.md` | PASS: structure describes version and local check, control API/TLS and runner; control status explicitly says deployment remains pending | A1, A2 |
| DOC-9-PATHS | Every newly claimed path exists | Filesystem via CLI | `ls -ld cmd/mayak cmd/mayak/check.go cmd/mayak-ctrl/ cmd/mayak-ctrl/main.go cmd/mayak-sign internal/runner/ internal/runner/runner.go internal/report schema/report.schema.json internal/probe internal/classify internal/targets testbed/mockdpi .github/workflows/ci.yml` | PASS: every path exists, exit 0 | A1 |
| DOC-9-WHITESPACE | Clean README diff | Git via CLI | `git diff --check -- README.md` | PASS: exit 0 | A1 |
| DOC-9-CHECK | Repository required checks | Repository CLI | `make check` | PASS: go vet and all 10 package test results pass, make_check_exit_code=0 | A1 |

All eight implemented-status bullets were cross-checked against the current files. The appended source-claim section in A1 records filenames, line numbers, regex patterns, and matching source for report/schema/validation, probe implementations and mock integration, signed file v2/ed25519/expiry/rollback, signing commands, check output, runner constants, control API/TLS, and Windows CI configuration. Signed envelope v2 is distinct from payload CurrentVersion=1. Windows CI configuration was verified locally; this task does not claim a new remote Windows run. Runtime control HTTP/TLS scenarios are outside this README correction.

## adversarialCases

| scenario id | criterion reference | adversarial class | expected behavior | verdict | artifactRefs |
| --- | --- | --- | --- | --- | --- |
| DOC-9-STALE | Eliminate contradictory structure statement | Stale duplicate description | No version-only statement survives in README | PASS: pre-edit assertions detected all three requested defects, post-edit assertions passed; grep and full diff confirm correction | A1, A2 |
| DOC-9-OVERCLAIM | Keep plan-approved scope and deployment pending | Documentation scope inflation | No claim of deployed control node, outgoing reports, server or advanced probes | PASS: explicit deployment-pending note, existing future-scope bullets and local/no-send statements retained in inspected diff | A1, A2 |
| DOC-9-INPUT | README-only correction | Malformed runtime input | Not triggered by static documentation text | not_applicable: the change adds no runtime parser, input boundary, or behavior | A2 |
| DOC-9-CONCURRENCY | README-only correction | Concurrency or cancellation | Not triggered by static documentation text | not_applicable: the change adds no concurrent or asynchronous product behavior | A2 |

## artifactRefs

| id | kind | description | path |
| --- | --- | --- | --- |
| A1 | command transcript | Append-only baseline, full requested grep/diff/ls output, assertions, make check output and source claim references; current evidence begins at correction baseline marker | `.omo/evidence/mayak-block-b-finish/task-9-docs.log` |
| A2 | documentation | Corrected README inspected through full git diff | `README.md` |

Diagnostics: requested Markdown LSP diagnostics, but no `.md` language server is configured. README textual assertions and git whitespace checks passed. No commits, network services, or temporary files were created. No edits were made to SPEC or ADR-006.
