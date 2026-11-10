# F1. Plan compliance audit

Date: 2026-11-09. Branch: block-b-final-verification. Reviewed HEAD: ae0e5db437c375872f2972d6e91943278c666004. Base: 86e7a33.

recommendation: REJECT
verdict: CHANGES_REQUESTED
confidence: 0.98

originalIntent: Finish block B as a usable local diagnostic command, validated JSON reports, clean interruption, a bounded control-node API and any-SNI listener, truthful documentation, and Windows CI, within the owner's direct local delivery scope.

desiredOutcome: All twelve implementation rows have current implementation and substantive evidence satisfying their actual criteria; final reviewers can assess the result without mistaking historical passes, incomplete tests, or pending external prerequisites for completed acceptance.

userOutcomeReview: The branch contains the intended major components and nine local commits, and its plan structure is correct. The checked implementation rows overstate compliance in several specific places. Production resolver configuration is missing, required CLI scenario coverage is absent, the named privacy test does not inspect logs, the required agent-to-new-listener integration test is absent, and interrupted text deliberately omits the required unmeasured rows. These are concrete plan failures, not objections to architecture or alternative designs. No tests were run by this audit; F3 owns execution and QA. Prior test output is reported as inspected evidence, never as independently reproduced runtime behavior.

## Blockers

Each entry identifies its violatedCriterion and evidencePointer.

1. **F1-T2-ENV**
   - violatedCriterion: Todo 2, What to do: productionEnv must populate ControlResolver and two public DoT resolvers, in addition to the deployment URL/TLS address.
   - observation: The entire productionEnv function sets neither resolver field. Both remain zero even after the owner fills the two documented control constants. The existing DNS probe rejects the zero control resolver before making DNS requests. The fixture-based command tests populate these fields themselves, masking the missing production wiring.
   - evidencePointer: `/home/goose/Documents/Mayak-wt/block-b-final/cmd/mayak/env.go:27-63`; `/home/goose/Documents/Mayak-wt/block-b-final/internal/runner/target.go:53-63`; `/home/goose/Documents/Mayak-wt/block-b-final/internal/probe/dns.go:117-128`; plan `/home/goose/Documents/Mayak/.omo/plans/mayak-block-b-finish.md:132`.
   - requiredResolution: Supply the resolver configuration required by the approved production environment and add coverage that exercises the actual production wiring contract. Do not count fixture-only Env construction as proof of it.

2. **F1-T2-SCENARIOS**
   - violatedCriterion: Todo 2 Acceptance criteria: a case per mockdpi scenario, explicitly ok, sni_block, dns_tamper, http_stub, ip_block, and inconclusive, driven through newRootCmd(env).
   - observation: The complete current command tests cover ok, dead control/inconclusive, allowlist mode, flags, JSON, expiry, and cancellation. They contain no CLI-driven sni_block, dns_tamper, http_stub, or ip_block cases. Lower-layer classifier/probe tests and a report table with fabricated verdict inputs do not exercise command wiring for those cases.
   - evidencePointer: `/home/goose/Documents/Mayak-wt/block-b-final/cmd/mayak/check_test.go:1-385`; `/home/goose/Documents/Mayak-wt/block-b-final/cmd/mayak/check_interrupt_test.go:1-394`; `/home/goose/Documents/Mayak-wt/block-b-final/cmd/mayak/smoke_test.go:1-223`; evidence `/home/goose/Documents/Mayak-wt/block-b-wave1/.omo/evidence/mayak-block-b-finish/task-2-check-command.log`; plan acceptance at line 138.
   - requiredResolution: Implement the four missing scenario cases through the command boundary and record their actual results. Existing seven-case success prose does not satisfy the named scenario matrix.

3. **F1-T4-PRIVACY-TEST**
   - violatedCriterion: Verification strategy privacy gate and todo 4 Acceptance criteria require a captured log buffer searched for the test client's address; listener changes must add or extend that regression test.
   - observation: TestNoClientAddressInLogs sends ping and asserts HTTP 200. It neither captures stdout/stderr/server ErrorLog nor searches any logs or retained state. No other current control-node test supplies that check. The final independent checks log passing this test is therefore not privacy regression evidence. Separate manual server-output scans exist, but they do not satisfy the explicitly required executable regression test.
   - evidencePointer: `/home/goose/Documents/Mayak-wt/block-b-final/cmd/mayak-ctrl/main_test.go:239-253`; complete `/home/goose/Documents/Mayak-wt/block-b-final/cmd/mayak-ctrl/security_test.go`; `/home/goose/Documents/Mayak-wt/block-b-wave1/.omo/evidence/mayak-block-b-finish/4-5-code-review.md`, finding 4; `/home/goose/Documents/Mayak-wt/block-b-wave1/.omo/evidence/mayak-block-b-finish/task-4-5-independent-checks.log:17-18`.
   - requiredResolution: Replace or extend the status-only test with a real captured-log privacy assertion against a known client address. Preserve manual scan evidence as complementary evidence.

4. **F1-T5-AGENT-INTEGRATION**
   - violatedCriterion: Todo 5 Acceptance criteria explicitly require a separate probe.TLSSNI test using the new listener and asserting TargetSNIViaControl is ok.
   - observation: TestAnySNIHandshake drives crypto/tls directly and checks handshake/EOF. No test in either control-node test file invokes probe.TLSSNI. Existing command fixtures use mockdpi's ControlTLS listener instead of the new mayak-ctrl listener. The required integration between the agent probe and this delivered listener has no current test or corresponding output artifact.
   - evidencePointer: `/home/goose/Documents/Mayak-wt/block-b-final/cmd/mayak-ctrl/main_test.go:277-301`; `/home/goose/Documents/Mayak-wt/block-b-final/cmd/mayak-ctrl/security_test.go:1-196`; `/home/goose/Documents/Mayak-wt/block-b-final/cmd/mayak/check_test.go:171-187`; plan `/home/goose/Documents/Mayak/.omo/plans/mayak-block-b-finish.md:171`; evidence `/home/goose/Documents/Mayak-wt/block-b-wave1/.omo/evidence/mayak-block-b-finish/task-5-any-sni.log`.
   - requiredResolution: Exercise probe.TLSSNI against the delivered listener and capture the requested observation assertion. An openssl handshake proves a different boundary.

5. **F1-T3-UNMEASURED-TEXT**
   - violatedCriterion: Todo 3 What to do: results whose Err is set must print as `not measured` and must not count in the per-verdict summary.
   - observation: interruptedOutput filters all Err-bearing results away before both output modes. Filtering is required for JSON, but text also loses all unmeasured rows. The current text test explicitly demands no t2 line, and the captured transcript contains only t1. That assertion encodes behavior contrary to the requested text contract.
   - evidencePointer: `/home/goose/Documents/Mayak-wt/block-b-final/cmd/mayak/check.go:188-203`; `/home/goose/Documents/Mayak-wt/block-b-final/cmd/mayak/check_interrupt_test.go:133-150`; `/home/goose/Documents/Mayak-wt/block-b-wave1/.omo/evidence/mayak-block-b-finish/task-3-interrupt.log:8-11`; plan `/home/goose/Documents/Mayak/.omo/plans/mayak-block-b-finish.md:143`.
   - requiredResolution: Render unmeasured target rows in interrupted text while keeping them out of verdict counts and JSON. Correct the contradictory text assertion.

## Read-only checks performed

Executed in `/home/goose/Documents/Mayak-wt/block-b-final`:

- `GIT_MASTER=1 git status --short`: exit 0, empty output. No product changes or untracked leftovers were present in this worktree at inspection time. Uncommitted orchestration state in the other worktrees is expected.
- `git log --oneline 86e7a33..HEAD`: exit 0, nine commits:
  - ae0e5db ci: build and test on Windows
  - 3ee8b8d docs: bring SPEC and README in line with the code
  - 2e66c19 docs(adr): record block B decisions and block F gate
  - d802ef2 test(mayak): smoke-test the built binary
  - 7c08895 build(targets): guard embedded list expiry
  - b60a0a5 feat(mayak-ctrl): serve and validate the control-node API
  - 25096ba feat(mayak): stop cleanly on interrupt with exit code 130
  - 0130f28 feat(mayak): add the check command with text and JSON output
  - 3fbdfc3 feat(runner): map one run to a mayak.report/1 document
- `git diff --stat 86e7a33..HEAD`, remaining scoped diff, branch name, and HEAD identity inspected. There are 23 changed product files, 3290 insertions, 38 deletions. Every changed path is within a named implementation unit or the directly necessary tests/callers of its changed signature/export. No go.mod/go.sum, report schema, signed target payload, probe implementation, backend, deployment, or deferred-probe changes appear in this diff.
- Python structural inspection: exactly one each of `## Todos`, `## Final verification wave`, `## Commit strategy`, `## Success criteria`, and `## Review record`. Exactly twelve column-zero implementation rows numbered 1 through 12, all `[x]`; all twelve have an executor category. Exactly F1-F4 once each, all unchecked. No `[~]` row exists. Four unchecked rows total in this plan.
- Evidence inventory snapshot before writing this report: wave1 evidence directory has 42 regular files, all nonempty. Main evidence directory had two regular files, both nonempty (task-11-expiry-skip.log and concurrently written F3-real-manual-qa.log). F3's in-progress artifact is not used to certify QA.
- Ledger parsed as JSONL: 59 events at inspection, including current final-wave dispatches. No malformed JSON entry found.

No build, tests, race checks, test mutations, push, PR, merge, or product edits were performed. This report is this audit's only write. A JS eval/agentToolkit status tool is not exposed; the explicitly requested non-ULW artifact path is used. No notepad path was supplied.

## Implementation-to-artifact matrix

Paths in the Current files column are relative to the final worktree. `W/` means `/home/goose/Documents/Mayak-wt/block-b-wave1/.omo/evidence/mayak-block-b-finish/`; `M/` means `/home/goose/Documents/Mayak/.omo/evidence/mayak-block-b-finish/`. Artifact byte counts were measured directly. A nonempty artifact establishes existence, not satisfaction.

| Todo | Acceptance mapping to current files | Inspected nonempty evidence | Assessment |
| --- | --- | --- | --- |
| 1 | internal/runner/report.go and report_test.go: verdict mapping, metadata, invalid verdict/size errors, OS/IP helper coverage, total table | W/task-1-report-mapping.log (4440 bytes), W/task-1-manual-qa.md | Implemented; historical targeted/full gate output exists. Report.Validate is called in production. This audit does not rerun it. |
| 2 | cmd/mayak/check.go, env.go, main.go, check_test.go, testcontrol_test.go: flags, source/runner flow, guard, output, exit codes | W/task-2-check-command.log (3581), W/2-3-7-code-review.md | Incomplete: F1-T2-ENV and F1-T2-SCENARIOS. Real no-control strace proof is separate W/no-control-network.strace. |
| 3 | cmd/mayak/check.go and check_interrupt_test.go: signal registration, measured JSON, state staging/preservation, exitError 130 | W/task-3-interrupt.log (2451), W/2-3-7-code-review.md | JSON/state evidence exists; text violates F1-T3-UNMEASURED-TEXT. Actual OS signal evidence is supplied by todo 12. |
| 4 | cmd/mayak-ctrl/main.go, main_test.go, security_test.go; internal/classify/classify.go and classify_test.go: endpoint/query/host/dial guards, limiter, body cap, exported predicate | W/task-4-control-api.log (735284), W/task-4-5-independent-checks.log, W/4-5-code-review.md | Substantive HTTP/adversarial artifacts exist. F1-T4-PRIVACY-TEST remains unresolved despite the final ledger confirmation. |
| 5 | cmd/mayak-ctrl/main.go anySNIHandler/serveTLSListener; main_test.go TestAnySNIHandshake/Disabled | W/task-5-any-sni.log (16949), W/task-4-5-manual-qa.md | Actual TLS transcript and cleanup exist; F1-T5-AGENT-INTEGRATION absent. |
| 6 | targets/embed_test.go, targets/freshness.go, Makefile, docs/KEYS.md, .github/workflows/ci.yml: explicit expiry warning and nonblocking CI | W/task-6-expiry-guard.log (4189), W/6-code-review.md | Expected near-expiry failure and deterministic freshEnough cases exist. Initial full-gate failure is historical concurrent work, not current proof. Owner re-sign is explicitly external. |
| 7 | cmd/mayak/smoke_test.go: binary version, trusted expired fixture via temporary build overlay, foreign signature, limit refusal | W/task-7-smoke.log (1792), W/2-3-7-code-review.md | Four requested refusal/version cases have actual binary output. Overlay is restricted to temporary smoke build; no production override flag/key added. Builds occur more than once rather than once; maintenance note only. |
| 8 | docs/adr/ADR-006-agent-check.md: block-F move, interrupt 130, deployment constants, allowlist limitation, B action statuses | W/task-8-adr.log (50435), W/task-8-manual-qa.md, W/8-code-review.md | Latest correction evidence is distinguishable from superseded completion prose. No checked entry claims deferred traffic work or remote Windows success. Missing new commit references and pending B9 are discussed below. |
| 9 | README.md and docs/SPEC.md: present CLI/control/runner paths, pending deployment, Linux/Windows M1 wording | W/task-9-docs.log (23678), W/task-9-docs-manual-qa.md, W/9-code-review-round2.md | Current documented paths exist. SPEC diff changes only the M1 row. Windows bullet is configuration, not a verified Windows run. |
| 10 | .github/workflows/ci.yml: check/windows/release-check jobs; pinned image/actions; Windows build/test, no race/make | W/task-10-windows-ci.log (3914), W/10-code-review.md | Local workflow/commands and negative Windows cross-build evidence exist. No native Windows/remote run receipt exists. Direct/no-push instruction is honored. |
| 11 | targets/embed_test.go env gate; Makefile targets-expiry exports it; TestFreshEnough remains unconditional | M/task-11-expiry-skip.log (409), W/6-code-review.md | Source matches required skip/explicit guard behavior. Primary log contains only formatting/Makefile output; skip/fail/pass command outcomes are described in the independent review, not full raw output in this log. |
| 12 | cmd/mayak/check_interrupt_test.go TestCheckInterruptSignal: real child signal, readiness marker, valid t1 JSON, state equality, unsupported-Windows-only skip | W/task-12-sigint.log (2355), W/task-12-manual-qa.md, W/12-code-review.md | Actual OS signal command path is evidenced. Child test process exits 0 while command error maps to 130, accurately disclosed. Main's process exit mapping is inspected, not exercised by this helper. Missing negative signal-handler mutation receipt is an evidence limit. |

## ADR action items against committed code

Inspected the complete current action list, production defaults, and current commit log.

- B1 checked: existing source/rotation implementation, historically cited 79f7c07. No relevant source changes in this branch.
- B3 checked: runner/target.go exists; cmd/mayak/env.go separately parses defaultControlAddr into ControlTLS. Documentation does not falsely derive TLS address from API URL.
- B4 checked: report builder is in 3fbdfc3; command JSON path in 0130f28.
- B5 checked: command interruption/state tests are in 25096ba. Text has the concrete deviation identified above; broad completion should not hide it.
- B8 checked: API/any-SNI code is committed in b60a0a5. It is local implementation, not a deployment claim.
- B10 checked with limited wording: SPEC correction in 3ee8b8d; Windows job in ae0e5db. ADR explicitly says execution of Windows CI is not confirmed.
- B9 unchecked at ADR line 138: specifically final acceptance is pending, while smoke subset is acknowledged. This is honest during F1-F4 and reflects the later task-8 correction instructions documented in task-8-manual-qa.md and 8-code-review.md. Do not mechanically mark final acceptance complete just because smoke tests are committed. This ADR checkbox is outside the twelve implementation rows in the plan.
- B6/B7 and traffic accounting explicitly deferred to F; no false checked action claims that code landed.

Documentation compliance notes: the task-8 plan originally asks for implementing commit references for B4/B5/B8/B9/B10; the final ADR uses test names and does not add those new hashes. The later correction changed B9's treatment, but the master plan has not reconciled that wording. The original task-8 phrase 'no Action Item for a landed step remains unchecked' is satisfied for the listed implementation portions; B9 is now expressly a final acceptance action. Record this distinction when updating the plan, rather than attributing unlanded work to a checked row.

## Ledger audit

The following line references are to `/home/goose/Documents/Mayak/.omo/ulw-execute/ledger.jsonl` at its 59-event inspection snapshot. Subsequent parallel final-wave appends are outside this snapshot.

| Todos | Executor and verification receipt | Adversarial/command/artifact/cleanup coverage |
| --- | --- | --- |
| 1 | completed line 13: st_01a1bfff / st_01a1c002 | commands, artifact, stale/misleading/dirty/flaky classes present; prompt injection marked n/a. No dedicated cleanup field; temporary TestQADump is absent from committed changed files. |
| 2,3,7 | completed lines 41-42: st_01a1c0c8 / st_01a1c0ce | command list on line 41, shared review artifact, flags/stale/JSON/cancel classes. OS SIGINT gap carried to todo 12. Cleanup documented in manual artifacts rather than completion record. |
| 4,5 | completed line 48: st_01a1c0c7 / fix verifier st_01a1c0cf / independent st_01a1c0dc | commands and four artifact pointers; malformed/bogon/rate/body/privacy/timeout/stale classes. Cleanup inside adversarial_classes records reaped server/closed ports/binary removal. Privacy claim overstates actual test coverage as F1-T4-PRIVACY-TEST shows. |
| 6 | executor report line 12, combined verifier dispatch line 16, completion line 18 lists st_01a1c000 + st_01a1c004 and verifier st_01a1c005 | commands, guard/embedded/dirty classes, artifact. Line 18 still says pending verifier although W/6-code-review.md confirms; combined todo 11 line 26 has confirmed verifier. Final task-6 state should be reconciled in ledger. |
| 8 | final completed line 46: st_01a1c0cc / st_01a1c0d0; commands in line 40 | actual diff/assertions/stale/dirty classes, review artifact. Docs-only cleanup stated in task-8 log; no services started. Superseded self-verification is not the final receipt. |
| 9 | completed line 47: st_01a1c0cd / st_01a1c0d4 | diff/stale/path classes and round-2 artifact; actual commands and docs-only n/a/cleanup in QA matrix, not every field repeated in completion record. |
| 10 | completed line 8: st_01a1bff2 / st_01a1bff3 | commands, artifact, explicit n/a classes for parsing/external/resumable/hung/flaky/repeated-interrupt domains, probe cleanup present. Native Windows execution is not among commands. |
| 11 | completed line 26: st_01a1c004 / st_01a1c005 | skip/fail commands, artifact, embedded/stale/dirty/flaky classes. No explicit cleanup field; source changes are within assigned targets/Makefile/workflow/docs paths. |
| 12 | completed line 52: st_01a1c0df / st_01a1c0e2 | commands, review/manual artifacts, stale/misleading/cancel/dirty classes; repeated interrupts explicitly outside single-interrupt scope. Child reaping/temp cleanup recorded. |

Every task has an identifiable executor and verifier, either its own or an explicitly combined unit. There is no need to invent a nonapplicable verifier for these rows. The ledger is heterogeneous: command, artifact and cleanup details sometimes reside in linked reviews/matrices, and obsolete needs-fix/pending events remain append-only history. This is a traceability note, except where the current artifact directly fails a criterion identified in Blockers.

Direct delivery matches the plan: nine local typed commits, integration verification branch, no PR or push receipt and no such operation performed here. A local log cannot prove the universal absence of an earlier external push; this audit verifies the configured delivery mode and inspected receipts, without claiming an external audit trail it does not have.

## Direct remove-ai-slops and programming review

Loaded both skill files from `/home/goose/.omo/binary-runtime/5.1.65/plugin/skills/`, plus programming references/go/README.md, references/testing/README.md and references/testing/junk-classes.md. Applied their criteria directly to the current scoped production changes and tests. The task forbids fixes and tests; cleanup instructions in those skills were used as review criteria only. No mutation proof, deletion proof, or dynamic test execution is claimed.

- Tests generally guard public CLI output/exit contracts, schema serialization, signing/list acceptance, storage preservation, control protocol/security, and actual TLS/OS signal boundaries. The report's total verdict table is expressly required by the plan, so it is not dismissed as a copied inventory.
- No deletion-only/removal-certificate, source-grep, documentation/prose-pin, or self-comparison test was found in the inspected changed tests. Disposal of historical wording is checked in manual evidence, not permanently added as prose-pinning tests.
- **False-confidence test:** TestNoClientAddressInLogs is F (fix): it guards no privacy observable. This directly violates a named plan requirement and is blocker F1-T4-PRIVACY-TEST, not just a style preference.
- **Contradictory contract test:** TestCheckInterruptText rejects an unmeasured row the plan asks to show. This needs correction together with its production owner, not deletion to obtain a green gate.
- **Implementation mirroring:** gateClock completion synchronizes on the third Now call. A harmless added clock read can move that witness. The signal test has exact result validation and a bounded subprocess timeout; the older context-cancel helper waits without an equivalent bound. Maintenance note; no unrelated test rewrite is demanded by F1.
- **Weak tests:** TestRateLimit tolerates transport errors and only needs at least one 429; it could pass an always-reject implementation. TestAnySNIHanderCert checks fingerprint length rather than hash correspondence. Keep the security/platform contracts, strengthen their assertions when addressing F2; neither creates a new F1 blocker beyond the named privacy failure.
- **Unnecessary production extraction:** targets/freshness.go contains freshEnough solely for the test/Makefile guard. It has no production caller. This could live beside its test caller without changing behavior. This is a maintenance note, not a failed user outcome.
- **Unnecessary parsing/helpers:** check_test.go hand-rolls errors.As; check_interrupt_test.go hand-rolls strings splitting/substring checks; loadConfig manually parses arguments despite the task specifying standard flag. These increase maintenance burden. Boundary URL parsing, target signature/freshness checks, public-address checks, response cap/hash, report marshaling and validation are required contracts, not slop to remove.
- Measured new oversized files: cmd/mayak-ctrl/main.go 474 pure LOC; main_test.go 284; cmd/mayak/check_test.go 330; check_interrupt_test.go 351; internal/runner/report_test.go 331. No SIZE_OK marker is present. Existing classify_test.go is 381 and only the required predicate rename changed. Record new-module size findings for F2; this audit does not turn architecture taste into a plan blocker or change product files.
- No dependency additions, speculative server/backend features, schema expansion, deferred-probe implementation, or production env override hook is in the scoped diff.

Confirmed that W/2-3-7-code-review.md, W/4-5-code-review.md, W/6-code-review.md, W/8-code-review.md, W/9-code-review-round2.md, W/10-code-review.md and W/12-code-review.md explicitly discuss both skill perspectives and deletion-only/tautological/mirroring or corresponding overfit coverage. The early task-1 standalone code-review artifact is not present; task-1 ledger verifier receipt and manual evidence exist. Existing review coverage does not replace this direct pass. The 4-5 report remains REQUEST_CHANGES despite later fix receipts: source inspection confirms malformed query handling, capacity admission, freshness, bogon and body cap regressions landed, while privacy testing and size findings were not fixed. A blanket ledger 'confirmed' must not be read as closing every original finding.

## Exact evidence gaps and external prerequisites

- Required missing acceptance evidence is enumerated in F1-T2-SCENARIOS, F1-T4-PRIVACY-TEST and F1-T5-AGENT-INTEGRATION. These are not inferred from artifact counts.
- No final native Windows test run or remote CI URL appears in task-10 evidence. Local Linux dry runs and a negative GOOS=windows compile probe are present. The later direct/no-push scope supersedes the earlier request to push for QA; do not push merely to manufacture a receipt. The plan's IS-6 'Windows job green' success row remains unproved unless native Windows evidence or an explicit revised success gate is supplied.
- Owner re-sign is explicitly external under draft OD-3 and Commit strategy. Decoded actual committed signed payload expires 2026-11-11T00:00:00Z, revision 2026-10-14.1, still unexpired on 2026-11-09 but within seven days. No after-owner-re-sign expiry/sign-check pass is in task-6 evidence. IS-4's release-readiness proof remains pending; this does not authorize the agent to sign or make that external prerequisite a product edit.
- M/task-11-expiry-skip.log is nonempty but only contains gofmt status and the Makefile block. The required raw skip/pass/fail transcript is absent there. W/6-code-review.md supplies independently claimed outcomes and the ledger has commands, making traceability possible but weaker than the plan's exact-command/full-output requirement.
- Task-12's negative no-signal-handler mutation output is absent. Its actual child test exits 0, and command return code 130 is asserted inside it. Do not present this as a production main process independently exiting 130 under signal. The source's main mapping is present and separately inspected.
- Historical package passes are against earlier uncommitted snapshots, not cryptographically bound to final HEAD. F3's current gate run owns final execution. This audit neither waits on nor approves pending F2/F3/F4 output.
- No notepad was supplied; no currentAttemptDir JS API was exposed. The explicit artifact path supplied by the caller is the only report artifact written.

## Checked artifact paths

Plan/draft/ledger:
- /home/goose/Documents/Mayak/.omo/plans/mayak-block-b-finish.md
- /home/goose/Documents/Mayak/.omo/drafts/mayak-block-b-finish.md
- /home/goose/Documents/Mayak/.omo/ulw-execute/ledger.jsonl

Current final files directly read: cmd/mayak/{check.go,check_test.go,check_interrupt_test.go,smoke_test.go,testcontrol_test.go,env.go}, cmd/mayak-ctrl/{main.go,main_test.go,security_test.go}, internal/runner/{report.go,report_test.go,runner.go,target.go}, internal/probe/dns.go, targets/{embed_test.go,freshness.go,targets.signed.json}, docs/adr/ADR-006-agent-check.md, README.md, .github/workflows/ci.yml. The actual base-to-HEAD diffs of Makefile, docs/KEYS.md, docs/SPEC.md, cmd/mayak/{main.go,main_test.go}, internal/classify/{classify.go,classify_test.go} were read as well.

Evidence: every task primary artifact and independent report named in the matrix above; additionally W/task-4-5-independent-checks.log, W/task-4-5-manual-qa.md, W/task-8-manual-qa.md and W/task-9-docs-manual-qa.md. Large task-4, task-5, task-8 and task-9 logs were inspected at the relevant current transcript/correction sections, not every historical byte. The 1 MiB control-saturation.curl request inventory was counted as an artifact but not fully read or executed. No approval is inferred from unread bytes.
