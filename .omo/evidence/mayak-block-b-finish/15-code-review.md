# Task 15 Independent Code Review

## Decision

- **Task:** 15. Harden control-node trust and integration tests
- **codeQualityStatus:** CLEAR
- **recommendation:** APPROVE
- **verdict:** confirmed
- **failure_class:** none
- **blockers:** none
- **confidence:** 0.97

The current source, rather than the interrupted executor's claim, was reviewed. The requested hardening is present and the required build, vet, formatting, repeated-test, integration, and privacy behaviors reproduce cleanly.

## Findings by severity

### CRITICAL

None.

### HIGH

None.

### MEDIUM

None.

### LOW

None affecting task-15 correctness or approval.

Operational caveat: the worktree is dirty and the task-15 production split files are currently untracked (`config.go`, `dial.go`, `handlers.go`, `ratelimit.go`, `server.go`, `tls.go`, and `hardening_test.go`), alongside unrelated task changes. This is a delivery-state risk, not a defect in the reviewed current source. A later integration/commit step must include the intended files without sweeping in unrelated changes.

## Scope and source inspection

Inspected all requested files:

- `cmd/mayak-ctrl/config.go`
- `cmd/mayak-ctrl/dial.go`
- `cmd/mayak-ctrl/handlers.go`
- `cmd/mayak-ctrl/main.go`
- `cmd/mayak-ctrl/ratelimit.go`
- `cmd/mayak-ctrl/server.go`
- `cmd/mayak-ctrl/tls.go`
- `cmd/mayak-ctrl/hardening_test.go`
- `cmd/mayak-ctrl/main_test.go`
- `cmd/mayak-ctrl/security_test.go`
- `.omo/evidence/mayak-block-b-finish/task-15-control-hardening.log`

Also inspected the directly relied-on implementations in `internal/targets/revstore.go` and `internal/probe/tls.go` rather than accepting the integration tests at face value.

The refactor is scope-controlled: the previous monolithic control-node implementation was split by concern without changing the rate-limit constants. New task behavior is limited to persistent revision state, runtime target expiry, HTTP diagnostic-log suppression, injected clock/root pool support, and focused integration tests.

## Success-criteria verification

### Persistent revision store and restart rollback rejection

Confirmed in source:

- `cmd/mayak-ctrl/config.go:13-20` adds the dedicated `StateDir` configuration field.
- `cmd/mayak-ctrl/config.go:23-28` defaults it below the user's config directory as `mayak-ctrl`.
- `cmd/mayak-ctrl/config.go:45-46` parses `--state-dir`.
- `cmd/mayak-ctrl/config.go:78-92` creates the state directory and calls `targets.Accept` with `targets.FileRevStore(<state-dir>/targets.rev)`.
- `internal/targets/revstore.go:31-51` verifies, rejects rollback, and persists only accepted newer revisions.
- `cmd/mayak-ctrl/hardening_test.go:24-96` runs a child test process against the same state directory, proves rollback rejection after restart, proves the stored newer revision is unchanged, and proves a damaged revision file fails closed.

The reproduced test output showed the restarted process rejecting repository revision `2026-10-14.1` after durable revision `2099-01-01.1` was seeded.

### Runtime expiry with injected clock

Confirmed in source:

- `cmd/mayak-ctrl/server.go:17-19` stores an injected `now` function.
- `cmd/mayak-ctrl/server.go:41-44` initializes it to `time.Now` in production.
- `cmd/mayak-ctrl/handlers.go:45-47` refuses authorization when `now >= Expires` before resolver or dial work.
- `cmd/mayak-ctrl/hardening_test.go:113-150` tests the exact expiry boundary and one second after it, with resolver and dial functions that fail the test if called.

Reproduced behavior for both test repetitions:

- `/v1/reach` -> HTTP 400, DNS calls 0, dial calls 0.
- `/v1/fetch` -> HTTP 400, DNS calls 0, dial calls 0.
- `/v1/ping` -> HTTP 200, DNS calls 0, dial calls 0.

### Client-address privacy across sinks

Confirmed in source:

- `cmd/mayak-ctrl/server.go:68-77` installs an `http.Server` diagnostic logger writing to `io.Discard`.
- `cmd/mayak-ctrl/ratelimit.go:36-49` uses `RemoteAddr` only to derive a SHA-256 key; the literal address is not retained in the bucket map.
- Production response and error paths do not interpolate `RemoteAddr`, `X-Forwarded-For`, or request parameter values into responses or logs.
- `cmd/mayak-ctrl/hardening_test.go:161-272` injects distinctive client address `203.0.113.219`, exercises success and rejection responses through a real HTTP listener and `curl`, and searches the HTTP logger, standard logger, stdout/stderr, and retained application state.

Both reproduced repetitions reported the distinctive literal absent from all four sinks, while exercising ping success, reach success, unauthorized-host rejection, and forbidden-parameter rejection.

### Real TLS/SNI probe integration

Confirmed in source:

- `cmd/mayak-ctrl/hardening_test.go:274-317` starts the real any-SNI TLS listener with a generated certificate covering target and neutral names.
- The test builds a trusted `x509.CertPool` from that certificate.
- It calls the production `probe.TLSSNI`, not a local imitation.
- `internal/probe/tls.go:107-115` assigns the third real handshake to the control address with target SNI.
- The test asserts `TargetSNI`, `NeutralSNI`, and `TargetSNIViaControl` all produce `TLSOutcomeOK`.

Both required repetitions and the 20-run stress pass produced successful trusted observations.

### Production file size

All production files are below 250 lines even when counting blank and comment lines, which is stronger than the requested nonblank/noncomment threshold:

- `config.go`: 95 total lines
- `dial.go`: 54 total lines
- `handlers.go`: 181 total lines
- `main.go`: 54 total lines
- `ratelimit.go`: 85 total lines
- `server.go`: 80 total lines
- `tls.go`: 116 total lines

### Rate cap unchanged

The baseline at `HEAD` contains:

- `rateLimitBucketSize = 20`
- `rateLimitWindow = 1 * time.Minute`
- `maxRateBuckets = 10000`

The current `cmd/mayak-ctrl/ratelimit.go:11-23` retains those exact numeric values. Task 15 did not implement task-16 rate-cap changes.

## Reproduction evidence

Run against `/home/goose/Documents/Mayak-wt/block-b-final` on 2026-11-10:

1. `gofmt -l /home/goose/Documents/Mayak-wt/block-b-final/cmd/mayak-ctrl/*.go`
   - Exit 0; no output.
2. `go -C /home/goose/Documents/Mayak-wt/block-b-final build ./cmd/mayak-ctrl`
   - Exit 0; no output.
3. `go -C /home/goose/Documents/Mayak-wt/block-b-final vet ./cmd/mayak-ctrl`
   - Exit 0; no output.
4. `go -C /home/goose/Documents/Mayak-wt/block-b-final test ./cmd/mayak-ctrl -count=2 -v`
   - Exit 0; package PASS; all requested restart, expiry, privacy, TLS, malformed-input, bogon, size-limit, and freshness tests passed twice.
5. `go -C /home/goose/Documents/Mayak-wt/block-b-final test ./cmd/mayak-ctrl -run 'TestTargetsRollbackAfterRestart|TestTargetsRuntimeExpiry|TestNoClientAddressInLogs|TestProbeTLSSNIAnySNIListener' -count=20`
   - Exit 0; package PASS.
6. `go -C /home/goose/Documents/Mayak-wt/block-b-final test -race ./cmd/mayak-ctrl`
   - Exit 0; package PASS with no race report.
7. `git -C /home/goose/Documents/Mayak-wt/block-b-final diff --check`
   - Exit 0; no whitespace errors.

The pre-existing executor evidence at `.omo/evidence/mayak-block-b-finish/task-15-control-hardening.log` is consistent with this independent reproduction. It was not used as proof without rerunning the commands.

## Adversarial class probe

- **malformed_input:** Relevant and passed. `TestRejectMalformedQuery` rejects malformed encodings, repeated allowed keys, unknown `ip`/`port`, and disallowed path keys before DNS. Existing bad path and bogon tests also pass.
- **stale_state:** Relevant and passed. Restart rollback rejection, unchanged newer revision, damaged-store fail-closed behavior, signature rejection, initial freshness checks, and runtime expiry are covered and reproduced.
- **cancel_resume:** Not directly relevant to the task-15 control-node acceptance criteria because the control service has no resumable operation or persisted in-flight workflow. Request cancellation/timeout behavior remains exercised by `TestFetchTimeout`; no task-15 regression appeared.
- **dirty_worktree:** Relevant and observed. The worktree contains task-15 untracked files and unrelated modified files. Review conclusions apply to the exact current filesystem. This is recorded as an operational caveat, not a product failure.
- **misleading_success_output:** Probed and not found. The prior log names concrete commands and surfaces, and its claims matched independently inspected source and rerun output. The required artifact path exists.
- **flaky_tests:** Relevant and passed. Required suite passed with `-count=2`; the four core hardening tests passed 20 repetitions; the complete package also passed under `-race`.
- **repeated_interruptions:** No product-level class applies. The executor interruption could have left partial files, so all source and evidence were inspected and commands rerun. The current task-15 implementation is complete-looking and behaviorally complete despite the dirty/uncommitted state.

## Skill-perspective review

The requested `remove-ai-slops` and `programming` skill files were not available in this session's advertised skill set, and no general skill-loading tool exposed them. I therefore applied the criteria explicitly supplied in the task instructions.

- **remove-ai-slops perspective:** Passed. The new tests are behavioral and failure-sensitive; none merely assert that code was deleted, mirror constants as their sole purpose, or add unnecessary production parsing/data extraction. The production split reduces a 500+ line file into cohesive files and does not introduce speculative layers.
- **programming perspective:** Passed. No brittle prompt/prose tests, untyped escape hatches, implementation-mirroring-only tests, or unnecessary boundary parsing were introduced. Query parsing remains necessary at the untrusted HTTP boundary. Clock, resolver, dialer, root pool, and target-list injection are narrow test seams around real behavior rather than abstractions for their own sake.

Language-server diagnostics were unavailable because `gopls` is not installed. This did not block verification: `go vet`, build, repeated tests, and race tests all passed.

## Final recommendation

Approve task 15 as implemented in the current worktree. Before integration, ensure the untracked task-15 files are deliberately included and unrelated dirty-worktree changes remain separated according to their own tasks.
