# Independent review: tasks 2, 3, and 7

Reviewed actual files in `/home/goose/Documents/Mayak-wt/block-b-wave1` on November 9, 2026. No production or test files were edited. The requested report path was used directly; a JS eval / agentToolkit status tool was not available in this child session.

- codeQualityStatus: WATCH
- recommendation: APPROVE
- blockers: none for the bounded tasks 2, 3, and 7.
- verdict: confirmed, with the external-signal and mixed-verdict coverage limits below.

## Findings by severity

### CRITICAL

None found.

### HIGH

None found. The previously reported all-inconclusive exit-code bug is fixed: `cmd/mayak/check.go:161-185` tests actual verdicts, returns 2 when all are inconclusive in both output modes, and allows any other verdict, including allowlist_mode, to finish normally.

### MEDIUM

1. **Damaged-state recovery names a deleted staging file.** `cmd/mayak/check.go:119-122` passes the staging directory to Source.Load, and `internal/runner/source.go:85-89` embeds that path in its user-facing recovery instructions. A real binary run with `targets.rev` containing `broken\n` exits 1 and tells the user to delete `.../mayak/.check-2724700178/targets.rev`. The deferred cleanup has already deleted that directory by process exit; the actual damaged file remains `.../mayak/targets.rev`. State is correctly preserved, but the recovery instruction cannot repair it. Reference evidence: `/tmp/mayak-237-review/state.json`. This does not invalidate the requested normal, inconclusive, or interrupt results.

2. **Interrupt synchronization depends on private clock call order and has no bounded failure.** `cmd/mayak/check_interrupt_test.go:31-35` treats the third Now call as target completion; `:54-60` waits unconditionally for that event. A harmless added clock read can change where cancellation occurs, and a missing completion can hang the suite instead of failing clearly. This is an implementation-mirroring test synchronization seam. Use an explicit observable completion event and a bounded wait when maintaining this test. The existing tests did pass all three executions requested in this review.

3. **Test infrastructure and size violate the loaded skill perspectives.** `cmd/mayak/check_test.go:145-160` reimplements errors.As even though errors is already imported. `cmd/mayak/check_interrupt_test.go:193-228` reimplements string splitting and substring search. `cmd/mayak/check_test.go` measures 330 nonblank, non-comment lines, beyond the skills' 250-line ceiling. These are maintainability findings, not demonstrated behavior failures. No fixes or mutation experiments were performed because this is a read-only verification task.

### LOW

1. `cmd/mayak/check_interrupt_test.go:97-111` validates the report and first result's target but does not assert exactly one result. Its name and comment promise measured results only. The text test rejects t2, and captured JSON really contains only t1, so current behavior is correct; the JSON assertion could be stronger.

2. The guard creates an empty configuration directory before refusing measurement (`cmd/mayak/check.go:92-105`). Real QA left `.config/mayak` but no state files. Therefore the comment saying “nothing was touched” is broader than observed behavior. No network activity is indicated by the inspected prior strace.

## Independent checks and real surface

All four required commands completed successfully against the reviewed worktree:

| Command | Result | Captured evidence |
| --- | --- | --- |
| `go vet ./cmd/mayak` | exit 0 | `/tmp/mayak-237-review/vet.log` |
| `go test ./cmd/mayak -count=1 -v` | exit 0, all tests pass, 3.822 s | `/tmp/mayak-237-review/test-v.log` |
| `go test ./cmd/mayak -count=2` | exit 0, both executions pass, 7.437 s | `/tmp/mayak-237-review/test-repeat.log` |
| `go build -o /tmp/verifier-mayak ./cmd/mayak` | exit 0 | `/tmp/mayak-237-review/build.log` |

The verbose log independently shows text and JSON all-inconclusive runs returning 2; two allowlist_mode results returning 0; successful JSON passing the actual report.Validate call in TestCheckJSON; interrupted JSON passing report.Validate; context cancellation returning 130; and before/after revision and rotation bytes equal. The validator is actually invoked in `internal/runner/report.go:98` before the report is returned, so success is not merely a test log statement.

Real `/tmp/verifier-mayak` invocations used a separate temporary HOME and XDG_CONFIG_HOME for every case. Complete stdout, stderr, exit codes, and resulting file lists are captured in `/tmp/mayak-237-review/cli.json`:

| Arguments | Exit | stdout | stderr |
| --- | --- | --- | --- |
| `version` | 0 | `dev\n` | empty |
| `check --limit 3` | 1 | empty | `error: --limit must be between 5 and 20, got 3\n` |
| `check` | 2 | empty | `mayak check: no control node is configured in this build, so nothing can be measured. Nothing was sent.\n` |
| `check --json` | 2 | empty | same no-control guard |

Additional adversarial binary cases: nonnumeric limit, negative limit, zero, 21, integer overflow, arbitrary --host, positional target, unsupported --targets, and malformed --json all returned 1 with empty stdout and no configuration files. Limits 5 and 20, and --targets core, passed flag validation and reached the no-control guard with exit 2.

Real stale/damaged-state QA in `/tmp/mayak-237-review/state.json` confirmed rollback refusal with stored revision `9999-12-31.1`, damaged revision refusal, empty JSON stdout, and unchanged original file bytes. Two additional fixtures using stored revision `2026-11-08.1` also correctly refused the older embedded `2026-10-14.1` list; because rollback happens first, those cases do not independently verify damaged-rotation handling.

## Inspected executor evidence

Read all three required logs in `.omo/evidence/mayak-block-b-finish/`:

- `task-2-check-command.log`: binary version / no-control / limit / JSON refusal, plus in-process dead-control and allowlist cases. Inspected its referenced `no-control-network.strace`: only process exit records, no network syscalls.
- `task-3-interrupt.log`: explicitly in-process cancellation; exit 130, measured-only output, unchanged seeded state, and no leftover state before start. It contains no external SIGINT delivery.
- `task-7-smoke.log`: real built binaries exercised version, trusted-but-expired list, foreign-key list, malformed limit, and configuration isolation. Independent package tests reproduced these passes.

`cmd/mayak/smoke_test.go:31-65` builds inside t.TempDir. Ed25519 fixtures are real GenerateKey results (`:129-135`), not undersized hand-built private keys. The expired-list smoke uses a temporary Go overlay to trust only that fixture key in that smoke build, allowing expiry rejection to be exercised instead of stopping at a bad signature. The normal production binary retains its normal key set. The foreign-key smoke exercises genuine signature rejection.

## Coverage limits and trust boundaries

- External OS SIGINT and repeated SIGINT delivery were **not exercised**. The supplied tests cancel a parent context. `signal.NotifyContext(ctx, os.Interrupt)` is present at `cmd/mayak/check.go:78`, and main maps exitError.Code to os.Exit, but that wiring is inspected rather than verified with a signal sent to a running measurement binary. The normal binary has an empty control URL and immediately refuses measurement, so the requested unmodified binary surface cannot provide a mid-run signal scenario. Do not describe the evidence as an external SIGINT smoke pass.
- There is no distinct mixed inconclusive/non-inconclusive regression test. The branch at `check.go:161-167` handles mixed results correctly by checking for any non-inconclusive verdict; all-ok, all-inconclusive, and all-allowlist cases passed. Mixed behavior is supported by code inspection, not an executed mixed fixture.
- JSON metadata comes directly from the accepted list's Rev and env.Clock.Now at `check.go:264-271`; it does not read stale persisted metadata. Successful JSON asserts targets_rev and uses a fixed clock in test fixtures. There is no explicit TS equality assertion. Invalid lists never emit report JSON in the exercised binary cases.
- Cancellation before start and after one completed target was tested; cancellation during an active probe and cancellation during list loading/state commit were not separately exercised.
- No new full-repository gate is claimed. `cmd/mayak-ctrl/main.go` and `main_test.go` are currently untracked, unverified changes, so `go test ./...` and make check were intentionally not run under the task's restriction. Unrelated packages can still prevent the wider gate from passing.

## Scope and skill-perspective audit

Loaded remove-ai-slops/SKILL.md, programming/SKILL.md, programming/references/go/README.md, testing/README.md, and testing/junk-classes.md before judging tests and maintainability. Applied both perspectives to production code and all cmd/mayak test files. The violations are the MEDIUM infrastructure/size findings and the LOW weak cardinality assertion above. No deletion-only tests, prose pins, source-grep tests, or tautological tests were found. Tests protect public CLI behavior, signed-list acceptance, storage preservation, output schema, and binary execution. The wire-level control fake actually fetches reference content; it does not simply return a mocked final verdict. Report serialization and report.Validate are required by the schema boundary, not unnecessary parsing introduced for this task. No production prompt tests or untyped domain escape hatches were found in the reviewed command changes; map[string]any in JSON overlay construction is test serialization, not a domain API.

Dirty paths outside cmd/mayak were identified, not reviewed as part of this approval: `.github/workflows/ci.yml`, Makefile, README.md, docs/KEYS.md, docs/SPEC.md, docs/adr/ADR-006-agent-check.md, internal/classify/classify.go and classify_test.go, targets/embed_test.go, untracked cmd/mayak-ctrl/, internal/runner/report.go and report_test.go, targets/freshness.go, and .omo/. The report builder and source/pool code were read where necessary to trace CLI behavior; this is not approval of those whole packages.

The scoped claims are confirmed. Approval does not certify an external SIGINT run, Windows execution, or the full block-B repository gate.
