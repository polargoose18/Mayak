# F4. Ideal-state fidelity

recommendation: REJECT
verdict: GAPS
task: F4. Ideal-state fidelity
reviewDate: 2026-11-09
reviewedTree: /home/goose/Documents/Mayak-wt/block-b-final
reviewedCommit: ae0e5db (ci: build and test on Windows)
artifact: /home/goose/Documents/Mayak/.omo/evidence/mayak-block-b-finish/F4-ideal-state.md

This is an independent review of the committed final tree. No implementation, test, documentation, signing data, or git history was changed. The report is the sole persistent audit artifact written by this reviewer. The exposed tools do not include JS eval or agentToolkit status, so currentAttemptDir could not be queried; the caller's explicit report destination is used.

## Original intent and desired outcome

originalIntent: Finish block B: a local diagnostic command, valid machine-readable reports, honest exit codes, interrupt safety, a deployable control node, and accurate documentation and CI. The owner explicitly deferred freeze/throughput probes and control-node deployment, and retained signing as an owner responsibility.

desiredOutcome: A contributor can build and test the implementation, a script can trust the output/exit contract, an interrupted run preserves state, and the owner can see exactly what remains before an operational release. Successful tests against injected environments must not be mistaken for a usable stock binary or a native Windows run.

userOutcomeReview: The implementation demonstrates local measurement and reporting against real local fixtures. The stock binary deliberately refuses measurement with exit 2 because its control URL is empty; this is authorized by the approved plan and ADR, rather than an unannounced product regression. However, productionEnv also omits the resolver configuration explicitly required by task 2, so supplying the two documented control addresses alone will not produce a working measurement environment. Required privacy regression coverage and native Windows execution evidence are also missing. The embedded list is still valid on November 9, 2026, but expires November 11, 2026 at 00:00:00 UTC; owner re-signing has not landed in this tree.

## Blockers

1. violatedCriterion: IS-1 / task 2 productionEnv contract.
   Observation: productionEnv never sets ControlResolver or PublicResolvers. The plan explicitly requires a control DNS resolver and two public DoT resolvers. DNSRequest.validate rejects the zero control resolver with "invalid resolver address", before making DNS requests. A reachable deployed control node does not repair this omission. The test environment supplies a resolver, so its successful run does not exercise production wiring.
   evidencePointer: /home/goose/Documents/Mayak-wt/block-b-final/cmd/mayak/env.go:27-63; internal/runner/target.go:54-64; internal/probe/dns.go:119-131; cmd/mayak/check_test.go:166-181; /home/goose/Documents/Mayak/.omo/plans/mayak-block-b-finish.md, task 2 "productionEnv() fills".
   Consequence: after the documented URL/address configuration, a healthy control/anchor path reaches DNS and returns per-target errors instead of measured verdicts. Run returns these results without an aggregate error (internal/runner/pool.go:95-102), while runCheck treats the empty verdict as non-inconclusive (check.go:159-166). Text can therefore print an uninterpretable result and return 0; JSON rejects the unknown verdict. This is a direct code-path finding, not a claim that deployment or a live-network reproduction was performed.
   Required closure: provide the specified production resolver wiring and verify the production environment contract, keeping the authorized empty-control guard.

2. violatedCriterion: IS-1 / ADR-006 Q5 exit 1 for IO failure.
   Observation: printText discards every writer error and returns no error; runCheck returns nil after invoking it on a trusted run. An output writer returning an IO error cannot affect the exit status. JSON checks its encoder error, but text does not.
   evidencePointer: /home/goose/Documents/Mayak-wt/block-b-final/cmd/mayak/check.go:177-180,226-249; docs/adr/ADR-006-agent-check.md, Q5.
   Required closure: propagate text-output IO failure to command code 1 and cover the failing-writer boundary. This is proven by the unchecked error flow; a failing-writer execution was not added or run under this report-only authorization.

3. violatedCriterion: IS-5 / plan privacy gate / task 4 acceptance requirement for a captured log buffer containing no client address.
   Observation: TestNoClientAddressInLogs sends a ping and checks only HTTP 200. It captures no logs and searches no output or stored state. No other final control-node test supplies the required privacy assertion. The separate manual server transcripts contain only the fingerprint, which is useful observation of those runs but does not satisfy the required regression test.
   evidencePointer: /home/goose/Documents/Mayak-wt/block-b-final/cmd/mayak-ctrl/main_test.go:239-253; security_test.go:1-196; /home/goose/Documents/Mayak/.omo/plans/mayak-block-b-finish.md, Verification strategy "Privacy gate" and task 4 acceptance criteria; /home/goose/Documents/Mayak-wt/block-b-wave1/.omo/evidence/mayak-block-b-finish/4-5-code-review.md, finding 4.
   Required closure: exercise the listener with a known client address, capture the actual logging surface, and assert that address is absent. The current misnamed test would stay green if ping started logging the client address. No actual client-address leak was demonstrated by this audit.

4. violatedCriterion: IS-6 / task 10 happy QA requirement to confirm a green Windows job and record its run URL.
   Observation: the workflow configures a Windows job, but the supplied evidence contains Linux executions and a GOOS=windows compile-error probe only. There is no native Windows CI run URL or Windows runner output for the final tree. Configuration is not evidence that the shipped tests ran on Windows.
   evidencePointer: /home/goose/Documents/Mayak-wt/block-b-final/.github/workflows/ci.yml:28-36; /home/goose/Documents/Mayak-wt/block-b-wave1/.omo/evidence/mayak-block-b-finish/task-10-windows-ci.log, sections 3 and 5; /home/goose/Documents/Mayak/.omo/plans/mayak-block-b-finish.md, task 10 QA scenarios.
   Required closure: supply the final revision's native Windows job result and run URL. No remote CI was launched by this report-only reviewer.

## IS rows

| Row | Verdict | Concrete evidence and limits |
| --- | --- | --- |
| IS-1 | FAIL | Fresh focused CLI tests show t1/t2 result lines, summary, "Nothing was sent.", successful/all-allowlist code 0, and all-inconclusive code 2. A newly built binary gives version code 0, invalid --limit code 1, and empty-control guard code 2 with no network syscalls. Nevertheless, production DNS wiring is missing and text writer errors cannot reach code 1; see blockers 1 and 2. |
| IS-2 | PASS | Fresh TestCheckJSON output is a one-element JSON array with schema mayak.report/1 and two target results. The test calls report.Validate, and production BuildReport marshals and validates before returning (internal/runner/report.go:75-104). Interrupted OS-signal output is also validated, including raw JSON validation in the signal test. Empty-control --json intentionally produces no stdout and code 2, rather than a fabricated report. |
| IS-3 | PASS | Fresh TestCheckInterruptSignal starts an actual child test process, waits for t1 completion and the pause before t2, and sends Process.Signal(os.Interrupt). Fresh child PID 596197; command result 130; JSON has exactly t1; targets.rev remains "2026-11-08.1\\n" and rotation remains "2\\n" byte-for-byte. Source cmd/mayak/check_interrupt_test.go:240-394 and task-12-sigint.log agree. The child test process exits 0 because it asserts the command's typed result; this does NOT prove a built production process exited 130 through main. The requested command-code signal criterion is satisfied. |
| IS-4 | PASS | make check and make sign-check reproduced successfully. make targets-expiry reproduced expected make exit 2 / Go test failure, naming 2026-11-11T00:00:00Z and the signing command. Decoded signed payload remains rev 2026-10-14.1, expires 2026-11-11T00:00:00Z. Guard is intentionally opt-in and CI warning-only; docs/KEYS.md records rev bump, approximately +28 days, owner signing, and sign-check. Owner OD-3 action has not landed and remains a release prerequisite. This PASS covers the requested guard/prerequisite behavior as of November 9, not release readiness or a successful post-signing check. |
| IS-5 | FAIL | Control API, malformed/duplicate query refusal, allowlisted hosts, private/mixed DNS rejection, dial recheck, bounded limiter, capped body hash, freshness loader, and arbitrary/absent SNI handshake tests passed in fresh make check. Final main.go SHA-256 508d9eeceed995a8eb9ae2273f40a621d59829dd13467392f5fbfac3a81bad54 matches the post-fix evidence. Raw server output has fingerprint only. Mandatory privacy regression test is still absent; see blocker 3. Additional protocol/coverage limitations are recorded below without claiming an observed leak. |
| IS-6 | FAIL | README lists check, runner and control node as implemented and deployment as pending. SPEC M1 says Linux and Windows with macOS deferred; workflow pins windows-2025 with go build/go test. ADR accurately leaves B9 open and explicitly disclaims Windows execution. Native Windows execution evidence required by task 10 is absent; see blocker 4. |
| IS-7 | PASS | ADR-006 Q2 explicitly records owner decision dated 2026-11-09 moving tcp_freeze/throughput and freeze_after_n/throttled to block F; workload and Consequences also defer related traffic accounting. No freeze/throughput probe or new classifier rule is shipped. classify.go:62 still states those rules do not exist; report mapping includes their schema enum cases, as explicitly required, without implementing probes. The plan's additional requested source-comment pointer to the gate change was not added; the caller's stated ADR-and-no-probes outcome is met, and this small documentation omission is noted. |

## Independently executed evidence

Executed in /home/goose/Documents/Mayak-wt/block-b-final:

- git status --short: empty. HEAD ae0e5db. git diff 86e7a33..HEAD --stat: 23 files, 3290 insertions, 38 deletions. Final status remained empty.
- make check: exit 0; gofmt produced no filenames, go vet succeeded, all 10 package test results were ok, including cmd/mayak and cmd/mayak-ctrl.
- make sign-check: exit 0, TestSignedTargetsFile PASS.
- make targets-expiry: expected exit 2 from make, underlying freshness test fails with the exact expiry and re-sign command. This is expected behavior, not a green freshness/release gate.
- go test ./cmd/mayak -run 'TestCheckRunOK|TestCheckJSON|TestCheckDeadControlAnchorsDown|TestCheckAllowlistModeExitZero|TestCheckInterruptSignal' -count=1 -v: exit 0. Observed outputs and actual signal execution are described in the row table. The focused run exposed signal and rendered-output details not visible in make check's package summary.
- go build -o <temporary-directory>/mayak ./cmd/mayak: exit 0. Each invocation used temporary XDG_CONFIG_HOME and strace -f -e trace=network. version: code 0/stdout dev; check and check --json: code 2/empty stdout/exact no-control sentence on stderr; check --limit 3: code 1/range explanation. Check traces contain process exit records only, no network syscalls. Temporary build/config/trace files were automatically removed.
- Decoded the signed payload and hashed final control source in a read-only Python check. Values are given above.

No new source mutation, regression test, full release, external deployment, native Windows run, or remote CI write was performed. No language-server claim is made. The stock binary has no measuring environment reachable through user flags, so successful production-path measurement cannot be reproduced without supplying deployment configuration at build time.

## Deployment, documentation and exact evidence gaps

The inability of the stock build to measure is explicitly accepted by the plan's decisions and ADR Q1/address section: deployment is outside block B, defaults are empty, and the command must exit 2 without network activity. It is a release/usability limitation, not an independent blocker. There is no artifact proving local installation into a user's PATH; this review built a temporary binary and does not claim an installation. An end-user announcement promising immediate useful measurements would conflict with the delivered defaults, but no such release artifact was supplied.

Missing URL and TLS address are documented. Missing ControlResolver and PublicResolvers are a separate implementation omission, not just owner deployment values; env.go:17-18 says filling the two constants suffices, which the DNS contract contradicts. Allowlist URLs are also absent, but ADR explicitly records allowlist_mode as unavailable until provided; that omission is authorized.

README's Windows statement is supported as workflow configuration only, not as a passed Windows test claim. README's no-report-submission wording is consistent with this local slice; measurement requests themselves necessarily contact a configured control node. The older SPEC §21 introduction still says the node does not exist and §21.2 says CLI state wiring is not connected. docs/KEYS.md "Что пока не сделано" similarly retains old CLI-state wording. These stale historical descriptions are documentation notes: task 9 explicitly limited SPEC edits to the M1 wording, and this audit does not invent authority to rewrite other sections. ADR B9 being unchecked is an honest outstanding final-gate statement, not completion proof.

Control-node list loading uses Verify with time checks but no retained revision store (main.go:245-254). SPEC §21.1 says the node verifies like the agent and §21.2 describes rollback protection; the supplied QA explicitly excludes persistent list rollback. The approved task-4 recipe originally requested Open and supplied no state path/persistence contract for the node. This scope conflict needs resolution before claiming complete agent-equivalent list acceptance; this report does not assert that rollback was exercised or silently invent a persistence requirement as an additional blocker.

IsBogon intentionally admits documentation networks (internal/classify/classify.go:214-226). Therefore the security tests prove the listed private/loopback/mapped/mixed classes, not every possible non-public/reserved range. No separate actual-address DNS rebinding run was supplied; the real Dialer.Control hookup and literal guard tests were inspected. No successful compressed-body comparison to probe.HTTP, redirect integration test, or probe.TLSSNI-to-new-listener integration test was found in final control tests, although default decompression, redirect refusal and the any-SNI listener are implemented. These are explicitly unproven portions of broader task QA, not invented observed protocol failures.

## Direct remove-ai-slops and programming review

Loaded both available skill files from /home/goose/.omo/binary-runtime/5.1.65/plugin/skills/, plus programming's Go reference, testing authoring gate and junk-class table. Applied their criteria directly to the final production code and tests, rather than accepting reviewer approval counts.

- Required boundary tests are retained: signed-list rejection/freshness, CLI schema and exit behavior, state preservation, real signal delivery, malformed queries, bogon rejection, capped hash/size, limiter saturation and real TLS handshake/EOF. Their owners are production boundaries, not documentation wording.
- TestNoClientAddressInLogs is F: its name promises privacy while its assertions only duplicate ping status. This creates false confidence and is the mandatory-regression blocker above. TestRateLimit is also F as an exact rate-boundary claim: it accepts any nonzero count of 429 and skips transport errors. Saturation has stronger, separate assertions and does not prove the ordinary 20/21 boundary. The fingerprint test asserts length only, not correspondence to the returned certificate.
- Report mapping's per-verdict expected test tags are a public schema/mapping contract explicitly requested by task 1, not a deletion-only inventory test. The totality check against report.Verdicts is also explicitly required. Repeating common metadata/evidence assertions for every verdict adds test maintenance but does not prove a failed user criterion.
- Signal synchronization uses the third Now call as a completion witness; this mirrors private implementation timing and can break on harmless clock reads. The actual OS signal test nevertheless validates exactly one completed result, and fresh execution confirmed it. No fabricated success marker substitutes for the checked command error.
- No deletion-only tests, requested-removal certificates, prose pins, source-grep repository tests, or self-comparison tautologies were found in the inspected change. No production extraction or normalization was added to test a removal. Report re-marshalling/validation is explicitly required by the report boundary. State staging implements the interruption preservation contract, rather than speculative fallback behavior.
- Maintenance notes: hand-written string splitting/substring helpers in check_interrupt_test.go duplicate strings; asExitError duplicates errors.As; the control CLI hand-parses flags instead of using the requested standard flag package; freshEnough is production-package code called only from tests. These are scope/style/maintenance notes, not extra approval blockers.
- Several new files exceed the skills' 250 pure-LOC threshold, notably control main.go and CLI/test modules. Existing scoped reviews already identify size and clock coupling. No refactor was performed under review-only authorization, and size alone is not treated as a failed IS behavior.

The inspected code-review reports explicitly include both requested skill perspectives and overfit/slop coverage: 2-3-7-code-review.md, 12-code-review.md, 4-5-code-review.md, 6-code-review.md, 8-code-review.md, 9-code-review-round2.md and 10-code-review.md. Some initial reviews could not locate the skill files and applied prompt criteria manually. The direct pass here used the actual available skill files. The control review's original rate-capacity, malformed-query and freshness product findings are repaired in the final source and backed by security_test.go plus matching post-fix evidence. Its privacy-test finding remains unresolved. A final consolidated F2 report was not present when this audit inspected the evidence; scoped reports are not presented as that artifact.

## Checked artifact paths

Primary inputs:

- /home/goose/Documents/Mayak/.omo/plans/mayak-block-b-finish.md (IS table, acceptance criteria, owner prerequisites, final gate).
- /home/goose/Documents/Mayak/.omo/drafts/mayak-block-b-finish.md (original intent, OD-1 through OD-4, approval).
- /home/goose/Documents/Mayak/.omo/evidence/mayak-block-b-finish/task-11-expiry-skip.log; corresponding plan/draft/evidence copies in /home/goose/.omo/wt/t12835c396d/m/.omo were located and distinguished from final-tree artifacts.
- Final README.md, docs/SPEC.md §15/§21, docs/KEYS.md, docs/adr/ADR-006-agent-check.md, .github/workflows/ci.yml, Makefile, cmd/mayak/*.go, cmd/mayak-ctrl/*.go, internal/runner/report.go and report_test.go, runner pool/target code, probe DNS contract, classifier code, targets freshness/embed tests and signed payload.

Executor/reviewer evidence is under /home/goose/Documents/Mayak-wt/block-b-wave1/.omo/evidence/mayak-block-b-finish/; it is not a hidden directory in the clean final worktree. Inspected the evidence inventory and review/failure/coverage entries across this directory, then directly read the decisive artifacts:

- task-2-check-command-manual-qa.md, task-2-check-command.log, no-control-network.strace, 2-3-7-code-review.md.
- task-12-sigint.log, 12-code-review.md; signal test source and fresh signal output independently establish the claim.
- task-4-5-manual-qa.md (including post-fix cases and coverageLimits), 4-5-code-review.md, task-4-5-independent-checks.log, control-evidence-review.log, task-5-any-sni.log, control security tests. The large task-4 HTTP/saturation transcript was indexed through evidence search and corroborated by its parsed post-fix review, source hash and fresh tests; its hundreds of thousands of repeated response lines were not individually treated as approval evidence.
- task-10-windows-ci.log and Windows/code-review coverage entries; no native run URL was found.
- 6-code-review.md, and the documentation review/QA coverage entries for tasks 8 and 9, which distinguish configured CI from executed Windows tests.

Evidence counts were never used as approval. Fresh executed checks substantiate the supported rows; exact missing or contradicted contracts are listed as blockers above. Owner signing and deployment remain visible release prerequisites rather than being silently counted as completed work.
