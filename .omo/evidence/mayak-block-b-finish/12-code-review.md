# Task 12 independent code review

Task: prove a real OS interrupt during `mayak check`, between completed t1 and unstarted t2. Reviewed worktree: `/home/goose/Documents/Mayak-wt/block-b-wave1`. Review date: November 9, 2026.

Verdict: **confirmed**. `codeQualityStatus`: **WATCH**. `recommendation`: **APPROVE**. `blockers`: **[]**. No CRITICAL or HIGH finding. The medium maintainability finding below does not invalidate the signal proof.

## Findings by severity

- **CRITICAL:** none.
- **HIGH:** none.
- **MEDIUM — oversized test module:** `cmd/mayak/check_interrupt_test.go:1-394` contains 351 nonblank, noncomment lines, exceeding the 250 pure LOC ceiling in both requested skills. There is no SIZE_OK explanation. Move the coherent OS subprocess test and its clock into a separate test file when addressing this maintainability finding; no production redesign is required. This is a skill-perspective violation, not a demonstrated behavior failure or a blocker for the requested proof.
- **LOW — completion synchronization depends on clock call count:** `cmd/mayak/check_interrupt_test.go:35-38,281-297` uses the inherited third `Now()` call as its completion witness. Inspection of `internal/runner/pool.go` and source loading confirms the count is correct today. A harmless extra clock read could make this test time out or signal at the wrong point, although the exact JSON result assertion prevents a false success if t1 is lost. This coupling predates the signal helper and is documented in the test.

## Independently executed checks

All three requested commands ran against the specified worktree and exited 0:

1. `go test ./cmd/mayak -run TestCheckInterruptSignal -count=1 -v`: PASS, package duration 0.028 seconds. Fresh child executable `/tmp/go-build2672417427/b001/mayak.test`, PID **456018**. Fresh marker `/tmp/TestCheckInterruptSignal2880148851/001/signal-ready`. Output records the readiness marker, actual `cmd.Process.Signal(os.Interrupt)`, child test process exit **0**, command result **130**, valid report JSON containing only t1, unchanged state bytes, and empty command stderr.
2. `go test ./cmd/mayak -count=2`: PASS, package duration 7.164 seconds. This also exercises the real-signal test twice in fresh subprocesses.
3. `go vet ./cmd/mayak`: exit 0, no output.

These are fresh reviewer executions, not copies of the executor's success claims. Their terminal outputs were inspected directly. This report is the durable artifact of those executions; no additional log files were written under the read-only review authorization. Repository-wide checks, a race run, and Windows execution were not requested and were not run.

## Signal and output proof

`cmd/mayak/check_interrupt_test.go:330-343` obtains the current test executable and starts a real child with the anchored `TestCheckInterruptSignal` selector. It does not replace the interrupt with context cancellation. The helper calls `newRootCmd(env).Execute()` without an injected canceled context at lines 304-310. Production `cmd/mayak/check.go:83-86` installs `signal.NotifyContext(ctx, os.Interrupt)` before loading or running targets.

The helper's notifier waits for both `clock.parked` and `clock.paused` before writing the readiness marker (lines 287-299). `signalGateClock.After` returns a nil channel, so the production pool cannot advance to t2 through the pause. The third `Now()` is evaluated after `runner.Check` returns for t1, in `runOne`'s duration assignment. The pool joins the worker before returning results. Thus signaling immediately after the marker cannot discard t1 merely because the worker has not assigned its result slot yet.

The parent observes the marker and then calls `cmd.Process.Signal(os.Interrupt)` at lines 356-372. The child asserts the actual command error maps to code 130 before printing its success marker (lines 310-314). **The child test process exits 0, not 130**: 130 is the Cobra command result carried by `*exitError`, which is the intended scope of this harness. This verifies the production command's signal path but does not independently execute `main`'s final `os.Exit` mapping.

The `SIGNAL_CHILD_EXIT=130` string is not accepted alone. The child parses the captured command stdout and invokes `report.Validate` on its raw report; the parent repeats that validation on the transported JSON and demands exactly one report with exactly one result for t1 (lines 241-260,314,384-391). A malformed report, unfinished t1, extra t2 result, wrong command code, or failing helper fails the parent. There are no production changes in task 12 and no new production parsing or normalization.

Both `targets.rev` and `rotation` are explicitly seeded in the child's fresh config directory and read after the interrupted command (lines 269-279,315-323). `bytes.Equal` compares the complete bytes, including trailing newlines. Fresh output confirmed `targets.rev="2026-11-08.1\n"` and `rotation="2\n"` unchanged.

## Adversarial and lifecycle review

- **stale_state:** the parent allocates a fresh `t.TempDir()` before constructing its marker path. The child `setup` allocates another fresh config directory, writes a freshly signed two-target list, and explicitly writes both state fixtures. TMPDIR/TMP/TEMP nest child temp directories within the fresh parent directory. The independently observed marker path and PID differ from the executor evidence, so this result cannot be a stale replay.
- **misleading_success_output:** inspected both real `report.Validate` calls and the exit-code assertion. Parent checks `cmd.Wait()` before accepting markers. A printed success string cannot mask child test failure.
- **repeated interruptions:** not required. The requested scenario is one interrupt during one paused run; repeated signals have different process termination semantics. The twice-run package check checks repeated independent runs, not multiple signals to one command.
- **cleanup/reaping:** after successful start, deferred cleanup kills and waits if normal `Wait` has not run (lines 346-353). A 30-second command context bounds marker waiting and child execution. Normal success calls `Wait` and sets `waited=true`. Helper notifier has a done channel and is joined on return; signal pause creates no extra timer goroutine. Independent post-run `/proc/456018` existence check returned false; `/tmp/TestCheckInterruptSignal2880148851/001` was also absent. The process listing contained no surviving mayak test binary; the only textual selector match was the audit shell's own command line.
- **platform skips:** no Linux skip occurred. The only skip is Windows after a real signal attempt returns an error whose text contains `not supported` or `not implemented` (lines 372-375). Other signal failures fail the test. Windows behavior remains unexecuted. The predicate does not silently skip all non-Linux platforms.

## Scope and evidence integrity

Read and checked `.omo/evidence/mayak-block-b-finish/task-12-sigint.log` and `task-12-manual-qa.md`. Their executor run records child PID 451467, a distinct fresh marker, valid t1 JSON, command code 130, test process exit 0, and unchanged states; those claims agree with the source and independent execution. The manual QA's package invocation is `-count=1`; the reviewer independently supplied the requested stronger `-count=2` run.

`check_interrupt_test.go` is untracked, so ordinary `git diff -- <file>` is empty. The complete file was read and `git diff --no-index --stat /dev/null ...` confirms a 394-line addition relative to HEAD. There is no trusted task-12 pre-edit snapshot proving historical attribution of every line; existing context-cancellation tests were assessed as surrounding coverage, and the OS proof is the coherent addition at lines 227-394.

The worktree already contains parallel changes: tracked `.github/workflows/ci.yml`, `Makefile`, `README.md`, `cmd/mayak/main.go`, `cmd/mayak/main_test.go`, `docs/KEYS.md`, `docs/SPEC.md`, `docs/adr/ADR-006-agent-check.md`, `internal/classify/classify.go`, `internal/classify/classify_test.go`, and `targets/embed_test.go`; untracked `.omo/`, `cmd/mayak-ctrl/`, `cmd/mayak/check.go`, `check_interrupt_test.go`, `check_test.go`, `env.go`, `smoke_test.go`, `testcontrol_test.go`, `internal/runner/report.go`, `report_test.go`, and `targets/freshness.go`. These are not attributed to task 12. No source files were edited by this review. Its sole write is this report.

## Requested skill perspectives

Both `remove-ai-slops` and `programming` were available and loaded, including the Go reference, test authoring gate, and junk-class table. The review applied both perspectives to the test and inspected the production signal owner and pool for relevance. The size finding violates both perspectives; the clock-call coupling is a lesser brittleness concern. No deletion-only test, requested-removal certificate, tautology, copied implementation-constant assertion, prompt test, untyped escape hatch, speculative production extraction, or unnecessary production parsing was found in the task-12 addition.

Retention ledger: `TestCheckInterruptSignal` is **R**, guarding a real OS/platform signal boundary that context cancellation tests cannot cover. Removing production signal registration would leave it waiting until timeout or terminate the child instead of returning validated interrupted results. Existing `TestCheckInterruptMidRun`, `TestCheckInterruptText`, and `TestCheckInterruptBeforeStart` are **R** for measured output/state, text output, and before-start cancellation respectively; they do not substitute for signal delivery. No mutation was performed because this verifier is expressly read-only outside its report.

JS eval/toolkit status is unavailable in the exposed tools. The explicit report destination requested by the caller was used instead of inventing a toolkit attempt directory.
