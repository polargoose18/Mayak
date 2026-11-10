# Manual QA matrix: task 2 — `mayak check` command

Worktree: `/home/goose/Documents/Mayak-wt/block-b-wave1`
Date: 2026-11-09. Binary under test: `go build -o /tmp/mayak-qa ./cmd/mayak`.

## surfaceEvidence

| scenario id | criterion | surface | exact invocation | verdict | artifactRefs |
|---|---|---|---|---|---|
| S1 | guard path: no control node -> exact sentence on stderr, exit 2, no network | CLI (real binary) | `/tmp/mayak-qa check` (fresh `~/.config/mayak`) | PASS | A1, A2 |
| S2 | guard path via flag surface (`--targets core --limit 5`) | CLI (real binary) | `/tmp/mayak-qa check --targets core --limit 5` | PASS | A1 |
| S3 | guard path with isolated fresh agent state | CLI (real binary, `XDG_CONFIG_HOME=/tmp/mayak-qa-config`) | `XDG_CONFIG_HOME=/tmp/mayak-qa-config /tmp/mayak-qa check` | PASS | A1 |
| S4 | flags: `--limit 4` rejected, exit 1 | CLI (real binary) | `/tmp/mayak-qa check --limit 4` | PASS | A1 |
| S5 | flags: `--targets cat` rejected, exit 1 | CLI (real binary) | `/tmp/mayak-qa check --targets cat` | PASS | A1 |
| S6 | `version` unchanged | CLI (real binary) | `/tmp/mayak-qa version` -> `dev`, exit 0 | PASS | A1 |
| S7 | full run with control+anchors up: exit 0, one line per target, summary, `Nothing was sent.` | in-process CLI (`go test`, mockdpi control node + signed list) | `go test ./cmd/mayak -run TestCheckRunOK -count=1 -v` | PASS | A1, A3 |
| S8 | `--json` output is one `[]report.Report` document that passes `report.Validate`; rev/ver/source correct | in-process CLI | `go test ./cmd/mayak -run TestCheckJSON -count=1 -v` | PASS | A1, A3 |
| S9 | expired signed list -> exit 1, plain-English message | in-process CLI | `go test ./cmd/mayak -run TestCheckExpiredList -count=1 -v` | PASS | A1, A3 |
| S10 | guard before network: zero requests reach the control node | in-process CLI (request counter) | `go test ./cmd/mayak -run TestCheckNoControlGuard -count=1 -v` (asserts `node.requests == 0` via `testControl.requests`) | PASS | A3 |

## adversarialCases

| scenario id | criterion | adversarial class | expected behavior | verdict | artifactRefs |
|---|---|---|---|---|---|
| AD1 | guard path | misconfigured deployment (empty `defaultControlURL`) | guard sentence to stderr, exit 2, no probe, no DNS, no fetch (counter at 0) | PASS | A1, A3 |
| AD2 | flag validation | out-of-range input (`--limit 4`, `--limit 21`) | exit 1, message names the accepted range, no run | PASS | A1, A3 |
| AD3 | flag validation | invalid enum (`--targets cat`) | exit 1, message names `--targets`, no run | PASS | A1, A3 |
| AD4 | targets acceptance | expired signed list | exit 1, plain-English expiry message, stdout empty, nothing sent | PASS | A3 |
| AD5 | exit-code plumbing | SIGINT during a run | context cancel propagates through `runner.Run`; exit code 130 | not_applicable: interrupt mapping is a shell/OS-signal interaction wired through `signal.NotifyContext`; the unit spec wires the plumbing (cancel -> 130 path implemented in check.go/main.go) and assigns behavioral interrupt testing to todo 3 ("todo 3 will refine"); triggering a mid-run SIGINT against this binary is out of this unit's harness |
| AD6 | privacy | probe requests | control client sends only `host` (no `ip`/`port` params); `testControl.admit` rejects any request carrying `ip` or a non-443 `port`, and the full run passes against it | PASS | A3 |

## artifactRefs

| id | kind | description | path |
|---|---|---|---|
| A1 | terminal log | real-binary runs: guard path (3 fresh-state variants, exit 2 + exact sentence), bad flags (exit 1), `version`, plus the full in-process test transcript | `.omo/evidence/mayak-block-b-finish/task-2-check-command.log` |
| A2 | code (read) | guard constant and its single use before any network call: `cmd/mayak/check.go` (`guardNoControl`, checked after `src.Load`/`src.Pick`, before `runner.Run`) | `cmd/mayak/check.go` |
| A3 | test transcript | `go test ./cmd/mayak -count=1 -v` (7/7 PASS), incl. JSON-validation, counter-based no-network guard, expiry, limit/enum bounds | same log, section "IN-PROCESS END-TO-END RUNS" |

## Verification commands (real output)

```
go test ./cmd/mayak -count=1      -> ok  github.com/polargoose18/mayak/cmd/mayak  0.501s
go test ./internal/runner -count=1 -> ok  github.com/polargoose18/mayak/internal/runner 2.369s
go vet ./cmd/mayak ./internal/runner -> (no output, exit 0)
go build ./cmd/mayak              -> (no output, exit 0)
```
