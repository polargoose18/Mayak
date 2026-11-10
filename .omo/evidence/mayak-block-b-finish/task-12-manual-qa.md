# Task 12 manualQa

Scope: `cmd/mayak/check_interrupt_test.go`, `TestCheckInterruptSignal`. Execution platform: Linux. Criterion references: task 12 requested behavior; ADR-006 Q4 (JSON), Q5 (interrupt exit and state), Q8 (test-only injection).

The caller's evidence directory is used because JS eval and the toolkit status tool are unavailable in this session. No repository-wide tests were run. All PASS entries below refer to non-empty artifacts containing real execution output.

## surfaceEvidence

| scenario id | criterion reference | surface | exact invocation | verdict | artifactRefs |
| --- | --- | --- | --- | --- | --- |
| sigint-os | Task 12; ADR-006 Q5/Q8 | Linux OS subprocess of the Go test binary, running Cobra with the production signal.NotifyContext path | `go test ./cmd/mayak -run TestCheckInterruptSignal -count=1 -v`; parent invokes `os.Executable()` with `-test.run=^TestCheckInterruptSignal$ -test.v`, helper marker env, and temporary config; after the readiness file, `cmd.Process.Signal(os.Interrupt)` | PASS: actual signal call logged for PID 451467, child test exit 0, command marker SIGNAL_CHILD_EXIT=130 | signal-log |
| sigint-json | Task 12; ADR-006 Q4/Q5 | Captured stdout from the child Cobra command | Child runs `newRootCmd(env)` with `check --targets-file <signed two-target list> --json`; child and parent parse captured JSON, invoke report.Validate, and require exactly one result for t1 | PASS: full SIGNAL_CHILD_JSON captured, valid mayak.report/1 containing only t1, stderr empty | signal-log |
| sigint-state | Task 12; ADR-006 Q5 | Actual state files in temporary agent config | Child seeds targets.rev=`2026-11-08.1\n`, rotation=`2\n`; after SIGINT reads both and compares using bytes.Equal | PASS: before/after bytes logged and unchanged | signal-log |
| package-regression | Task 12 verification | Go CLI test suite for cmd/mayak | `go test ./cmd/mayak -count=1` | PASS: package success, exit 0 | package-log |
| vet | Task 12 verification | Go static analysis | `go vet ./cmd/mayak` | PASS: exit 0 | vet-log |
| format | Task 12 verification | Go formatting | `gofmt -l cmd/mayak/check_interrupt_test.go` | PASS: no listed files, exit 0 | format-log |
| cleanup | Task 12 cleanup | OS process table and filesystem following focused test completion | Evidence audit uses `os.kill(451467, 0)` and `Path('/tmp/TestCheckInterruptSignal1274915996/001').exists()` | PASS: ProcessLookupError for child; parent temp directory absent. Child temp directories are nested under the parent via TMPDIR/TMP/TEMP. | signal-log |

## adversarialCases

| scenario id | criterion reference | adversarial class | expected behavior | verdict | artifactRefs |
| --- | --- | --- | --- | --- | --- |
| interrupt-between-targets | Task 12; ADR-006 Q5 | Asynchronous cancellation during a pool pause | Readiness requires first target completion and pool pause; real SIGINT cancels command, yields code 130, and excludes t2 | PASS | signal-log |
| truncated-output | Task 12; ADR-006 Q4/Q5 | Output interrupted before all planned targets run | Emit a complete valid JSON array containing exactly the completed target | PASS: parent and child validation succeeded | signal-log |
| interrupted-state-write | Task 12; ADR-006 Q5 | Cancellation while accepted revision and rotation updates are staged | Original state bytes survive cancellation unchanged | PASS | signal-log |
| resource-leak | Task 12 cleanup | Subprocess and temporary-file lifetime | Reap child and remove parent and nested child temporary files; gate clock starts no timer goroutines, notifier is joined on helper exit | PASS: executed process/filesystem cleanup checks; helper passed | signal-log |
| windows-signal | Task 12 platform allowance | Unsupported Windows Process.Signal(os.Interrupt) | Windows skip only after actual unsupported-signal error | not_applicable: execution platform is Linux; the Windows-specific branch was not exercised. | signal-log |
| external-input-security | Task 12 scope | Untrusted product input or network-facing API changes | No changed production input boundary | not_applicable: this change only adds a test and its explicitly marked subprocess helper. | signal-log |

## artifactRefs

| id | kind | description | path |
| --- | --- | --- | --- |
| signal-log | terminal transcript | Focused real SIGINT run, exact subprocess invocation and readiness marker, Process.Signal call, command code marker, captured JSON, state-file byte comparisons, child exit status, artifact audit and cleanup results | `.omo/evidence/mayak-block-b-finish/task-12-sigint.log` |
| package-log | terminal transcript | Requested cmd/mayak regression suite, exit status | `.omo/evidence/mayak-block-b-finish/task-12-package.log` |
| vet-log | terminal transcript | Requested cmd/mayak vet check, exit status | `.omo/evidence/mayak-block-b-finish/task-12-vet.log` |
| format-log | terminal transcript | Requested assigned-file formatting check, no output files and exit status | `.omo/evidence/mayak-block-b-finish/task-12-format.log` |

Limitations: gopls is not installed, so language-server diagnostics could not run; compilation through both test invocations and go vet succeeded. Windows was not run. The assigned test file already existed as an untracked file; its earlier tests were preserved. No production files, other packages, or commits were changed.
