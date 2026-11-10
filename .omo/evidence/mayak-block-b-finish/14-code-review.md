Independent review of task 14: Preserve classifier decision provenance in reports

codeQualityStatus: WATCH
recommendation: APPROVE
blockers: []
verdict: confirmed
failure_class: none

CRITICAL: None.
HIGH: None.
MEDIUM: internal/runner/target_test.go:128 adds provenance assertions to an existing oversized test module. The file now has 299 nonblank, noncomment lines, above the 250-line ceiling in both requested skills. internal/runner/report_test.go remains oversized at 310 such lines, although this change reduces that file. This is a maintainability deviation from the skill perspective, without a demonstrated correctness or regression failure for task 14. A later test-file organization change can move the Check verdict scenarios and their fixtures into a cohesive file. It does not block this scoped functional approval.
LOW: None.

Scope and review basis

Reviewed the working-tree diff against HEAD ae0e5db in /home/goose/Documents/Mayak-wt/block-b-final for internal/classify/classify.go, internal/runner/runner.go, internal/runner/target.go, internal/runner/report.go, internal/runner/report_test.go, and internal/runner/target_test.go, plus the new untracked internal/runner/provenance_test.go. Read the implementations, the existing classifier behavior table, the relevant runner fixtures, report.Validate, the pool result transport, the CLI BuildReport caller, and SPEC sections 5, 7, and the current report schema table. No product or test files were edited by this reviewer.

The scoped dirty files at review time were the six tracked paths above and the untracked provenance_test.go. The shared worktree also contained changes under cmd/mayak and cmd/mayak-ctrl, untracked control-node files, and .omo evidence. Those concurrent units were not reviewed or reverted. This report is the reviewer's only write. Review tools do not expose a JS eval cell or agentToolkit status, so currentAttemptDir could not be queried; the explicit report path supplied by the task is used.

Correctness findings

internal/classify/classify.go:79 returns the deciding test alongside the verdict at the decision itself. The original Classify API delegates to that same implementation at line 72. Diff inspection confirms no rule predicates, branch order, or verdict values changed: control first; decisive DNS outcomes; TCP/TLS transport; HTTP; QUIC; deferred system DNS failure; success. The legacy classifier table and combination tests passed unchanged.

The three timeout_unknown sources retain distinct provenance: deferred system DNS failure returns dns at classify.go:104-105; an unexplained target TLS timeout is attributed to tls_sni by the transport decision at lines 257-261; HTTP timeout returns http through the HTTP decision at lines 96-97. Vendor-down decisions retain tcp, tls_sni, or http according to the stage. Inconclusive results retain ctrl, dns, tcp, tls_sni, or http according to the first deciding rule. QUIC remains after HTTP and before the deferred DNS timeout. Success remains ok/http.

internal/runner/runner.go:108 carries the report.Test value with the verdict. Every normal classified return in Check assigns both from the current r.Observation: target.go:49, 87, 103, 124, and 162. Error returns retain their previous error contract and do not fabricate a decision. The pool transfers the complete Result by value and only adds target/timing metadata.

internal/runner/report.go:64 rejects empty provenance. Lines 68-72 copy the supplied deciding stage directly; no verdict-to-stage lookup remains. Lines 80-83 still invoke the real report.Validate on serialized output. Unknown test values and unknown verdicts are rejected by the actual validator enum checks in internal/report/validate.go. The missing/invalid-test regression uses otherwise valid report metadata and a valid target, so an unrelated invalid field does not explain its success.

Adversarial checks

- stale_state: inspected the production data flow. ClassifyWithTest has no persisted decision state or cache; it computes the pair from its observation argument. Check constructs a fresh Result and assigns the pair together at all five normal exits. BuildReport serializes the pair from that Result without re-deriving provenance from the verdict. This conclusion is code inspection, supported by independently constructed table scenarios; no additional state-mutation test was added or claimed.
- misleading_success_output: inspected report.Validate and both actual call sites in BuildReport and TestReportProvenance. The current test run executes real validation; the evidence script alone would only prove captured JSON parsing and therefore was not treated as proof of Go validation. All cited artifacts exist.
- malformed/inconsistent observations: the new TCP contradiction scenario leaves successful TLS after TCP failure and expects inconclusive/tcp. Missing TCP and TLS observations expect their respective stages. The unchanged classifier suite also covers unknown TCP, TLS, HTTP, and DNS address-check values. All passed in the scoped run.
- precedence: new scenarios cover DNS tamper over TCP failure, HTTP stub over geoblock, and deferred DNS failure yielding to TLS or QUIC. Existing precedence and contradiction tests also passed.
- flaky_tests: both requested packages passed with -count=2. This is evidence for two executions, not a claim that all timing risks have been eliminated. The existing real-network blackhole scenario uses a 700 ms deadline; this review did not change it.
- dirty_worktree: reviewed the explicit scoped dirty paths listed above and avoided broad repository tests while concurrent units were changing.

Skill-perspective check

Loaded remove-ai-slops/SKILL.md and programming/SKILL.md before judging test relevance or maintainability. Also loaded programming/references/go/README.md, references/testing/README.md, and references/testing/junk-classes.md. Applied the removal/overfit pass to production code and changed tests. The size deviation is recorded as MEDIUM above; no other new slop or programming-perspective violation was found in this scope.

Test relevance ledger: retain TestReportProvenance because it guards the public classification-to-report serialization contract using independent expected verdict/stage pairs, including identical verdicts with different stages. Retain the new TestCheckVerdicts assertions because they guard Check's real network/probe wiring rather than merely re-running the pure classifier. Retain TestBuildReportMissingOrInvalidTest as an invalid serialization-input boundary contract. Retain the existing report/evidence assertions because they cover report fields and privacy-relevant technical evidence, distinct from stage attribution. The Classify wrapper assertion checks API compatibility; its expectation is also anchored by the independent expected verdict earlier in each row.

No deletion-only test, prose/source pin, mock echo, test-only production seam, implementation-constant inventory, untyped escape hatch newly introduced by this diff, or unnecessary production extraction/parsing/normalization was found. Removed verdict-map table cases and TestVerdictTableTotal asserted the old derivation mechanism; they are replaced by actual observation-to-validated-report scenarios. The new production API is used by Check, so it is not a seam introduced only for tests. Boundary report validation is pre-existing and required by BuildReport's contract. No mutation proof was run because this reviewer was instructed not to edit source files.

Independent command evidence

Executed in /home/goose/Documents/Mayak-wt/block-b-final:

$ go test ./internal/classify ./internal/runner -count=2
ok github.com/polargoose18/mayak/internal/classify 0.149s
ok github.com/polargoose18/mayak/internal/runner 4.715s
TEST_EXIT=0

$ go vet ./internal/classify ./internal/runner
VET_EXIT=0

$ gofmt -l internal/classify internal/runner
[no file paths printed]
GOFMT_EXIT=0

These are direct tool results from this review, recorded here rather than inferred from the executor's log. No go test ./... or make check was run by this reviewer, as requested for the shared worktree. The executor log records an earlier make check failure at formatting of out-of-scope cmd/mayak-ctrl/hardening_test.go; this review neither reproduces nor asserts that the unrelated blocker is still current. No language-server diagnostics were run; scoped compilation/tests and vet provide the available diagnostics evidence.

Inspected evidence artifacts

- .omo/evidence/mayak-block-b-finish/task-14-report-provenance.log: inspected the initial compile-red transcript, subsequent scoped tests/vet, verbose Go validator outputs, all 25 provenance cases, invalid-test cases, six loopback Check scenarios, and the documented broad-check formatting failure. A compile-red transcript establishes API absence before implementation, not a behavioral mutation proof.
- .omo/evidence/mayak-block-b-finish/task-14-manual-qa.md: parsed the full JSON matrix; it contains 31 surface scenarios, the adversarial entries, and existing artifact paths. Its Go/test surfaces are accurately identified; it is an automated QA matrix rather than evidence of browser or desktop interaction.
- .omo/evidence/mayak-block-b-finish/task-14-smoke-reports.json: parsed all 25 reports and independently compared the entire saved documents with JSON captured in the supplied log. All matched, including report IDs and evidence. No mismatch or missing scenario was found.
- .omo/evidence/mayak-block-b-finish/task-14-smoke-validate.py: read the verifier. It parses the log and generates both JSON and the QA matrix, so those three artifacts are related evidence rather than independent executions. Did not execute it because it writes artifacts and this review permits only the review report write.

Reproduction: cd /home/goose/Documents/Mayak-wt/block-b-final && go test ./internal/classify ./internal/runner -count=2 && go vet ./internal/classify ./internal/runner && gofmt -l internal/classify internal/runner

Task 14's requested provenance behavior is confirmed. The approval is scoped to task 14, with the nonblocking maintainability issue and repository-wide verification limit explicitly recorded.
