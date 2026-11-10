# Code review: task 2 "Add the mayak check command"

Reviewer: independent verifier (omo-native-code-reviewer), worktree `/home/goose/Documents/Mayak-wt/block-b-wave1`.
Scope reviewed: `./cmd/mayak` and `./internal/runner` only (`cmd/mayak-ctrl` is owned by another unit and does not compile; ignored per instruction).

## Skill-perspective check

The `remove-ai-slops` and `programming` skill files are not available in this session (only `gpt-image-gen` and `bun` are installed), so the documented criteria from the task instructions were applied manually. Result: **no slop violations found.** No deletion-only or tautological tests; tests assert observable behavior (exit codes, exact guard sentence, stdout shape, request counters on a real httptest control node), not implementation constants. No needless parsing/normalization in production code; the flag validation and verdict-sentence table are required by the plan.

## Verification performed (all evidence from this session)

- Read the full diff of `cmd/mayak/main.go` and full `check.go`, `env.go`, `check_test.go`, `testcontrol_test.go`, `internal/runner/report.go`, `source.go`, `pool.go`, `targets/revstore.go` (`Accept`).
- `go vet ./cmd/mayak ./internal/runner`: clean. `gofmt -l cmd/mayak internal/runner`: empty. `go build ./cmd/mayak`: OK.
- `go test ./cmd/mayak -count=1 -v`: 7/7 PASS (TestCheckRunOK, TestCheckNoControlGuard, TestCheckJSON, TestCheckLimitBounds, TestCheckBadTargetsKind, TestCheckExpiredList, TestVersionCommand). `-count=2`: PASS. `go test ./internal/runner -count=1`: PASS.
- Real-surface QA of the built binary (`/tmp/verify-mayak`, no control URL compiled in):
  - Fresh `XDG_CONFIG_HOME`: `mayak check` -> exit 2, stdout 0 bytes, stderr exactly the guard sentence. State dir created with `targets.rev` + `rotation`, mode 0600, dir 0700.
  - `mayak check --json` (same state): exit 2, stdout 0 bytes, stderr guard sentence.
  - Pre-existing real config dir with newer rev: built-in older list correctly refused, exit 1, plain-English rollback message.
- Adversarial probes:
  - `--limit 0` -> exit 1, `--limit must be between 5 and 20, got 0`. `--limit abc` -> exit 1, cobra parse error (plain, no panic). `--targets corex` -> exit 1. `--bogus` -> exit 1. `--limit 100` -> exit 1. No panics anywhere.
  - JSON validation: captured a real `--json` doc from an in-process mock run (1009 bytes, 2 results); standalone program calling `report.Validate` on each element: VALID, `schema=mayak.report/1`, `ts=2026-11-09T12:00:00Z` (the injected test clock, not wall time), `targets_rev=2026-11-09.1` (the accepted list's rev). `BuildReport` rejects a bogus verdict and a bad rev. TS-from-`env.Clock.Now()` and rev-from-accepted-list confirmed.
  - Interrupt wiring (code inspection; unexercised, plan todo 3): `signal.NotifyContext(ctx, os.Interrupt)`; on `runner.Run` error with `ctx.Err()==context.Canceled` the run prints results and exits 130. `targets.rev`/`rotation` are written by `Source.Load`/`Source.Pick` before any probe, so they survive an interrupt. Wiring looks correct; deferred to todo 3 for its tests.
  - Prompt injection: not applicable, no external text is processed.
- dirty_worktree: expected cross-todo modifications (Makefile, ci.yml, docs, classify, embed_test) plus untracked `.omo/` and `cmd/mayak-ctrl/` (other unit). No stray leftovers in `cmd/mayak` or `internal/runner`.

## Contract compliance (plan todo 2)

- Flags `--limit` (default `runner.DefaultLimit`, bounds 5..20), `--targets` (only "core"/empty), `--targets-file`, `--json`: present, validated before any IO. ✔
- Flow: `Source{File,Dir}.Load` -> `Pick(limit)` -> control guard before any network. ✔ (Guard test asserts the fake control server receives requests only in the OK run; in the guard run the code returns before `runner.Run`.)
- Guard: exact sentence, stderr, exit 2, no network. ✔ (verified on the real binary)
- Text output: ASCII/English, one line per target, summary with per-verdict counts, control-unreachable note, trailing `Nothing was sent.` ✔
- All 14 verdict constants (`internal/report/report.go:14-27`) have a sentence in `verdictSentence` (`cmd/mayak/check.go:20-36`); none missing. ✔
- `--json`: single-element array of `mayak.report/1`, elements pass `report.Validate`, nothing else on stdout. ✔

## Findings

### HIGH
1. **Exit code 2 is never produced for an all-inconclusive run** — `cmd/mayak/check.go:64-137` (`runCheck`/`printText`). The plan (todo 2: "2 exactly when NOT ONE result has a verdict other than inconclusive"), ADR-006 Q5, and success criterion IS-1 all require it; only the no-control guard reaches exit 2. Reproduced in an in-process probe with a dead control node (`/v1/ping` = 500): run completes, every verdict is `inconclusive`, text correctly says "The control node was unreachable, so nothing could be measured.", but the process exits **0**. No test covers this case. Scripts cannot distinguish "measured, blocked" from "could not measure".

### MEDIUM
2. **Interrupt path prints unmeasured targets with a misleading sentence** — `cmd/mayak/check.go:126-133` (`printText`): unstarted targets get `Result{Err: ctx.Err()}` with an empty verdict, printed as `<id>    The result could not be interpreted.` and counted in `Summary`. Plan todo 3 requires `not measured` and exclusion from the per-verdict summary. Correct handling is explicitly todo 3's scope, so this is a deferred note, not a blocker for todo 2 — but the current fallback sentence is actively wrong for this state.

### LOW
3. `runCheck` wraps every error path in `&exitError{Code: 1}` including `userDir()`/`MkdirAll` failures — fine, but `Pick` also re-validates the limit (dead duplicate of the flag check at `check.go:73`). Harmless duplication, no action needed for this goal.

## Verdict

Status: **BLOCK** — finding 1 is a HIGH contract violation that is cheap to fix (count non-inconclusive verdicts in `printText`/`runCheck` and return exit 2) and needs a test.
Recommendation: **REQUEST_CHANGES**.
