# F4. Ideal-state fidelity (refreshed after task 15)

recommendation: GAPS
verdict: GAPS
task: F4. Ideal-state fidelity
reviewDate: 2026-11-10
reviewedTree: /home/goose/Documents/Mayak-wt/block-b-wave1
reviewedCommit: 21337d823ba80787be95835dde4ac231021e7199
confidence: 0.98

## Original intent

Finish Block B so `mayak check` offers truthful local diagnostics and reports, and `mayak-ctrl` serves the guarded SPEC §21.1 API plus the any-SNI TLS handshake needed by the agent. The repo should accurately describe supported behavior and verification. Delivery is direct/local: no push, PR, remote CI trigger, or product edits during this review.

## Desired outcome

A user can run the local diagnostic with truthful results and interruption behavior; the owner can safely operate the control node with signed-target trust, expiry enforcement, privacy-preserving diagnostics, and working TLS/SNI integration. Contributors can trust the documented support and gates, while still seeing the tasks and external prerequisites that remain open.

## User outcome review

Task 15 is now included in the requested integration checkout at `21337d823ba80787be95835dde4ac231021e7199` (`fix(mayak-ctrl): enforce target lifecycle and privacy invariants`). Its ten control-node paths are committed. This refresh supersedes the old F4 report's claim that task 15 was unlanded: task 15's IS-5 contribution is delivered and its task-specific tests are evidenced. Persistent accepted-revision state rejects rollback after restart; authorization stops at expiry while ping remains available; the privacy regression searches captured logger/output/state sinks for a distinctive client address; and the real `probe.TLSSNI` integration reaches `TargetSNIViaControl` successfully.

IS-5 as a whole is still incomplete because task 16 is explicitly `[~]`: the selected 120 requests/minute per-prefix budget, 60-request supported-run test, and 121st-request rejection test were not implemented. `cmd/mayak-ctrl/ratelimit.go` remains at 20 requests per minute. The requested 20-target run can require 60 control requests, so the current cap can throttle a supported run.

The final full `make check` and `make sign-check` outputs are available and exit 0. The embedded signed targets payload expires at `2026-11-11T00:00:00Z`, which is still in the future on this report's date, November 10, 2026; owner re-signing remains necessary for post-expiry use. The Windows CI job is configured, but there is no native Windows execution receipt. The requested direct/no-push constraint rules out triggering that remote job here.

## IS row assessment

| IS | Result | Evidence and fidelity assessment |
| --- | --- | --- |
| IS-1 | PASS, with disclosed deployment limitation | Task-13 committed CLI wiring supplies the required resolver configuration, fails closed before network activity when production control settings are incomplete, propagates writer errors, and preserves interrupt output/state contracts. README and ADR describe the empty-control build as not measurable. Evidence: `cmd/mayak/env.go`, `cmd/mayak/check.go`, task-13 QA/review, `final-gates.log`. |
| IS-2 | PASS | The report output is validated at the report boundary, and task 14 preserves the classifier's deciding stage. Evidence: `internal/runner/report.go`, `internal/classify/classify.go`, task-14 QA/review, task-2 QA. |
| IS-3 | PASS | OS-level interrupt test evidence verifies exit 130, partial measured output, and byte-identical `targets.rev`/`rotation`. Evidence: `task-12-sigint.log`, `cmd/mayak/check_interrupt_test.go`. |
| IS-4 | PASS as of 2026-11-10; near expiry | The signed payload's expiry is `2026-11-11T00:00:00Z`; `make check` and `make sign-check` pass. These checks do not renew the list. Owner re-signing is needed before or after expiry for continued fresh-checkout use. Evidence: `targets/targets.signed.json`, `task-11-expiry-skip.log`, `final-gates.log`. |
| IS-5 | TASK 15 PASS; ROW REMAINS GAP on task 16 | Task 15 hardening is present in commit `21337d8`; restart rollback, corrupt state, runtime expiry, privacy sinks, real `probe.TLSSNI`, and retained API/security tests are in the package test run. Task 16 is not implemented: the cap remains 20/minute rather than the owner-selected 120/minute, and the 60-request/121st-request acceptance tests are absent. Thus the IS-5 end-to-end row and its full proving scenario do not pass yet. Evidence: `cmd/mayak-ctrl/config.go`, `handlers.go`, `ratelimit.go`, `hardening_test.go`; `task-15-integration.log`; `task-16-rate-budget.log`; plan todo 16 and IS-5 row. |
| IS-6 | GAP: native Windows run missing | README, SPEC, ADR, and `.github/workflows/ci.yml` describe/configure Linux and Windows; the workflow has a `windows-2025` build-and-test job. No native Windows run output or run URL exists in checked evidence. The configuration is not execution evidence, and direct/no-push delivery precludes triggering it here. Evidence: `.github/workflows/ci.yml`, `task-10-windows-ci.log`, plan IS-6 / todo 10 QA. |
| IS-7 | PASS | ADR-006 records the owner decision to defer `tcp_freeze`/`throughput` and associated verdicts to block F; no such probes or classifier rules are claimed as shipped. Evidence: `docs/adr/ADR-006-agent-check.md`, `internal/classify/classify.go`, task-8 evidence. |

## Blockers

Each blocker is tied to a named plan success criterion; no task-15 gap is carried forward after the delivered commit.

- violatedCriterion: `IS-5 / todo 16 acceptance: 120 requests/minute budget admits the 60 requests for a 20-target run and rejects request 121; privacy-prefix key has no address leakage.`
  evidencePointer: `/home/goose/Documents/Mayak-wt/block-b-wave1/cmd/mayak-ctrl/ratelimit.go` (`rateLimitBucketSize = 20`, `rateLimitWindow = 1 * time.Minute`); `/home/goose/Documents/Mayak/.omo/evidence/mayak-block-b-finish/task-16-rate-budget.log` (explicitly no implementation or acceptance run).
- violatedCriterion: `IS-6 / todo 10 QA: confirm a green native Windows job and record its run URL.`
  evidencePointer: `/home/goose/Documents/Mayak-wt/block-b-wave1/.github/workflows/ci.yml` (configured `windows-2025` job); `/home/goose/Documents/Mayak/.omo/evidence/mayak-block-b-finish/task-10-windows-ci.log` (no native run receipt or URL).
- violatedCriterion: `IS-4 / embedded targets list remains usable for fresh checkouts; owner re-sign is required after the embedded expiry.`
  evidencePointer: `/home/goose/Documents/Mayak-wt/block-b-wave1/targets/targets.signed.json` (signed payload `expires: 2026-11-11T00:00:00Z`); `/home/goose/Documents/Mayak/.omo/evidence/mayak-block-b-finish/final-gates.log` (`make sign-check` verifies the current signature but does not renew expiry).

## Task 15 direct review and overfit/slop pass

I inspected the exact task-15 commit diff and the current source rather than relying only on prior review prose. The diff adds the persistent state directory and `targets.Accept`/`FileRevStore` loading, runtime expiry check before target DNS/dial, suppressed `net/http` diagnostic logging, and responsibility-specific source files. It removes the former status-only `TestNoClientAddressInLogs` and adds a real listener test that injects `203.0.113.219`, exercises success and rejection paths, and searches HTTP logger, standard logger, stdout/stderr, and retained state. It also adds restart/rollback and runtime-expiry tests and a real `probe.TLSSNI` call against the any-SNI listener with trusted test roots.

The task-15 integration log records `go build ./cmd/mayak-ctrl`, `go vet ./cmd/mayak-ctrl`, `go test ./cmd/mayak-ctrl -count=2`, `make check`, and `make sign-check`, all exit 0. The initial gofmt wrapper invocation failed because its glob was expanded outside the checkout; the corrected in-checkout gofmt command exited 0 with no filenames. The integration QA matrix maps those scenarios to the task's acceptance criteria. I did not rerun tests, as requested.

I loaded the available `remove-ai-slops` and `programming` skills and reviewed the task-15 diff/tests against their criteria. The added tests assert behavioral contracts at HTTP, persistence/restart, expiry, and TLS-probe boundaries. I found no deletion-only, removal-certificate, source-grep, tautological, or implementation-mirroring-only tests, and no unnecessary production parsing/normalization or extraction beyond the requested source split. `TestTargetsRuntimeExpiry` and `TestControlHTTPWireSurface` cover overlapping expiry paths at handler and real HTTP wire surfaces; the latter is a distinct external-surface check, not a requested-removal test. No slop finding establishes failure of a named success criterion.

The task-15 code review report explicitly records both the `remove-ai-slops` and `programming` perspectives and separately evaluates overfit/junk-test criteria, including failure-sensitive behavior, deletion-only tests, implementation mirroring, and production extraction/parsing. I independently checked these perspectives against the diff and tests; report coverage is not being substituted for that inspection.

## Remaining gaps and exact evidence gaps

1. **IS-5 / task 16 / 120 requests-per-minute budget:** `cmd/mayak-ctrl/ratelimit.go` still defines `rateLimitBucketSize = 20` and `rateLimitWindow = 1 * time.Minute`. The plan requires a 120/minute prefix budget, admission of the maximum 60 API requests for a 20-target run, and rejection of request 121. `task-16-rate-budget.log` explicitly records no implementation and no QA run.
2. **IS-6 / native Windows execution:** `.github/workflows/ci.yml` configures the Windows job, but no Windows runner output/run URL is in the checked QA evidence. A local Linux run or workflow definition cannot establish that the native job is green. No remote CI was triggered because the delivery constraint is direct/no-push.
3. **IS-4 / signed-target-list renewal:** `targets/targets.signed.json` expires at `2026-11-11T00:00:00Z`. It is valid as of November 10, 2026 and passes sign-check, but continued post-expiry operation requires the owner's re-signing action. No signing was done.
4. **Not rerun for this refresh:** requested source-of-truth task-15 scoped and full gate outputs were taken from the committed task-15 integration log, as directed. No new tests were run during this review.

## Checked artifact paths

- `/home/goose/Documents/Mayak-wt/block-b-wave1` (branch `block-b-wave1`, HEAD `21337d823ba80787be95835dde4ac231021e7199`)
- `/home/goose/Documents/Mayak-wt/block-b-wave1/cmd/mayak-ctrl/config.go`
- `/home/goose/Documents/Mayak-wt/block-b-wave1/cmd/mayak-ctrl/dial.go`
- `/home/goose/Documents/Mayak-wt/block-b-wave1/cmd/mayak-ctrl/handlers.go`
- `/home/goose/Documents/Mayak-wt/block-b-wave1/cmd/mayak-ctrl/main.go`
- `/home/goose/Documents/Mayak-wt/block-b-wave1/cmd/mayak-ctrl/ratelimit.go`
- `/home/goose/Documents/Mayak-wt/block-b-wave1/cmd/mayak-ctrl/server.go`
- `/home/goose/Documents/Mayak-wt/block-b-wave1/cmd/mayak-ctrl/tls.go`
- `/home/goose/Documents/Mayak-wt/block-b-wave1/cmd/mayak-ctrl/hardening_test.go`
- `/home/goose/Documents/Mayak-wt/block-b-wave1/cmd/mayak-ctrl/main_test.go`
- `/home/goose/Documents/Mayak-wt/block-b-wave1/cmd/mayak-ctrl/security_test.go`
- `/home/goose/Documents/Mayak-wt/block-b-wave1/targets/targets.signed.json`
- `/home/goose/Documents/Mayak-wt/block-b-wave1/.github/workflows/ci.yml`
- `/home/goose/Documents/Mayak-wt/block-b-wave1/README.md`
- `/home/goose/Documents/Mayak-wt/block-b-wave1/docs/SPEC.md`
- `/home/goose/Documents/Mayak-wt/block-b-wave1/docs/adr/ADR-006-agent-check.md`
- `/home/goose/Documents/Mayak/.omo/plans/mayak-block-b-finish.md`
- `/home/goose/Documents/Mayak/.omo/ulw-execute/ledger.jsonl`
- `/home/goose/Documents/Mayak/.omo/evidence/mayak-block-b-finish/task-15-integration.log`
- `/home/goose/Documents/Mayak/.omo/evidence/mayak-block-b-finish/task-15-integration-manual-qa.md`
- `/home/goose/Documents/Mayak/.omo/evidence/mayak-block-b-finish/15-code-review.md`
- `/home/goose/Documents/Mayak/.omo/evidence/mayak-block-b-finish/task-16-rate-budget.log`
- `/home/goose/Documents/Mayak/.omo/evidence/mayak-block-b-finish/task-10-windows-ci.log`
- `/home/goose/Documents/Mayak/.omo/evidence/mayak-block-b-finish/task-11-expiry-skip.log`
- `/home/goose/Documents/Mayak/.omo/evidence/mayak-block-b-finish/final-gates.log`
- `/home/goose/Documents/Mayak/.omo/evidence/mayak-block-b-finish/F1-final.md`
- `/home/goose/Documents/Mayak/.omo/evidence/mayak-block-b-finish/F2-final.md`
- `/home/goose/Documents/Mayak/.omo/evidence/mayak-block-b-finish/F3-qa-matrix.md`
- `/home/goose/.omo/binary-runtime/5.1.65/plugin/skills/remove-ai-slops/SKILL.md`
- `/home/goose/.omo/binary-runtime/5.1.65/plugin/skills/programming/SKILL.md`

No product files, CI state, Git history, or signing data were changed. This artifact is the only write made for this gate review.
