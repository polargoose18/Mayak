# Task 9 independent code review, round 2

Reviewed on November 9, 2026 in `/home/goose/Documents/Mayak-wt/block-b-wave1`, against the current working tree. Scope: README.md and docs/SPEC.md, with supporting implementation and tests inspected to verify the documentation. No production files were edited.

Result: **confirmed**. codeQualityStatus: **CLEAR**. recommendation: **APPROVE**. Blockers: none.

## Findings by severity

- CRITICAL: none.
- HIGH: none.
- MEDIUM: none within this documentation change.
- LOW: none.

The earlier README.md:94 finding is obsolete. The current structure block says `cmd/mayak/ агент (CLI): version и локальный check` and includes both `cmd/mayak-ctrl/` and `internal/runner/` accurately. The complete current README was read with the read tool, including the status, pending work, structure, and license sections.

## Diff scope

Ran `git diff -- README.md docs/SPEC.md > /tmp/mayak-9-round2.diff`: exit 0. Read the complete captured diff with the read tool. Diff summary: README.md has 21 changed lines (13 additions, 8 deletions); docs/SPEC.md has one replacement (1 addition, 1 deletion).

README changes only update the implemented status, remaining work, operational limitation, and repository structure. They add the local check command, runner, control-node implementation, and Windows CI; distinguish the control implementation from its pending deployment; and remove the obsolete version-only structure description. No unrelated README sections changed.

SPEC has exactly one hunk at docs/SPEC.md:277, changing the M1 OS criterion from `бинарники под 3 ОС` to `бинарники под Linux и Windows; macOS отложен`. No other SPEC text changed.

## Cross-check of implemented claims

- Report schema and validator: `schema/report.schema.json`, `internal/report/validate.go`, and report test files exist. The report package tests passed.
- DNS, TCP, TLS/SNI, HTTP, control probes, classifier, and mock censor: corresponding files exist under `internal/probe`, `internal/classify`, and `testbed/mockdpi`; the probe and classifier suites passed, including their integration tests.
- Signed targets v2, Ed25519, expiry, rollback: `internal/targets/sign.go` explicitly documents the v2 signed envelope and implements Ed25519 verification and clock checks. Revision storage and rollback tests exist in `internal/targets`; that package's tests passed.
- Owner signing tool: inspected `cmd/mayak-sign/main.go:1-85`, including command registration for keygen, pubkey, sign, and verify and standard-library Ed25519 key generation. This tool is an existing claim; its package tests were not separately run in this review.
- Local `mayak check` and JSON: `cmd/mayak/main.go` registers version and check; `cmd/mayak/check.go` registers `--json`, runs the runner, emits text or JSON, and contains no report-submission step. `TestCheckRunOK` and `TestCheckJSON` in `cmd/mayak/check_test.go` exercise the command against local mock/control fixtures; JSON is unmarshaled and passed through the actual report validator. The entire CLI package passed. **JSON is implemented and tested, not pending.**
- Load limits: `internal/runner/runner.go:26-34` defines 5..20 requested targets, concurrency 4, pause 200..800 ms, and timeout 8 seconds. `internal/runner/pool.go` applies and rejects looser scheduling options; `pool_test.go` includes concurrency, pauses, timeout, and cancellation coverage. The runner suite passed. Target count is the configured request limit; a shorter signed list can yield fewer actual targets, as the CLI fixtures demonstrate. This is consistent with the existing command limit model.
- Control node: inspected the complete `cmd/mayak-ctrl/main.go`. It registers GET `/v1/ping`, `/v1/reach`, and `/v1/fetch`; `anySNIHandler` supplies a certificate independent of SNI, and `serveTLSListener` completes handshakes. The package includes endpoint, privacy, security, and arbitrary-SNI handshake tests and passed.
- Windows CI: read the complete `.github/workflows/ci.yml`. The `windows` job runs on `windows-2025`, sets up Go from go.mod, and executes `go build ./...` and `go test ./...`. This verifies that build and test jobs are configured. No remote CI run or native Windows execution was available or claimed in this review.

## Pending work and operational qualification

README's `Ещё нет` section remains consistent with the tree: there is no mayakd command, consent/report command, web probe, public page, bot, QUIC/freeze/throughput probe implementation, or Privacy Pass implementation in the inspected command/internal inventory. Signed release publication is not established by this local tree and is not claimed as complete.

Control deployment is explicitly pending in both the implemented control-node bullet and the `Ещё нет` section (`развёрнутого контрольного узла`). `cmd/mayak/env.go:20-23` still has empty production control URL/address constants. Consequently the stock build's measurement and JSON result output remain gated on deploying/configuring a control node, despite those code paths being implemented and tested with fixtures. README explicitly states the exit-2/no-network limitation. `cmd/mayak/check.go` checks the empty URL before runner/network execution; source loading can still reject invalid or expired local inputs earlier, so the exit-2 description applies to otherwise valid invocation/input.

## Commands and observed evidence

Executed in the reviewed working tree:

```text
$ git diff --check -- README.md docs/SPEC.md
(no output)
exit: 0

$ grep -n 'пока только version' README.md
(no output)
exit: 1 (expected: no match)

$ go test ./cmd/mayak ./cmd/mayak-ctrl ./internal/runner ./internal/probe ./internal/classify ./internal/report ./internal/targets
ok github.com/polargoose18/mayak/cmd/mayak 3.480s
ok github.com/polargoose18/mayak/cmd/mayak-ctrl 0.086s
ok github.com/polargoose18/mayak/internal/runner (cached)
ok github.com/polargoose18/mayak/internal/probe (cached)
ok github.com/polargoose18/mayak/internal/classify (cached)
ok github.com/polargoose18/mayak/internal/report (cached)
ok github.com/polargoose18/mayak/internal/targets (cached)
exit: 0
```

Test output was captured in `/tmp/mayak-9-round2-tests.log` and read using the read tool; the complete output is reproduced above for durable evidence. The initial combined inventory/skill-discovery shell command ended with status 1 because its final find included an unavailable root; the individual diff, diff-check, and grep statuses were explicitly printed and are recorded above. This did not prevent reading either skill from its discovered real path.

This is a documentation review, not a full gate review of the other simultaneous branch changes. `make check`, race tests, release/sign checks, and Windows runtime checks were not run here. No claim is made that those gates passed.

## Skill-perspective and scope-control review

Explicitly loaded both `/home/goose/.omo/binary-runtime/5.1.65/plugin/skills/remove-ai-slops/SKILL.md` and `/home/goose/.omo/binary-runtime/5.1.65/plugin/skills/programming/SKILL.md` before judging test relevance or maintainability.

Applied their requested review perspectives to this diff: there are no added, removed, or reshaped tests and no production code changes in the two-file task-9 diff. Therefore there are no deletion-only tests, removal certificates, tautological tests, implementation-constant mirrors, brittle prose/prompt tests, untyped escape hatches, needless abstractions, or unnecessary production extraction/parsing/normalization introduced by this change. No violation of either skill perspective was found. Existing behavioral CLI tests used as evidence exercise observable results and the real report validator rather than pinning documentation wording. No prose-pinning test was added for this editorial correction.

The requested explicit report location was used. A JS eval/status tool was not available in this reviewer session; no SDK-derived attempt directory was fabricated. No notepad or executor evidence was supplied as a trusted basis; review used current files, the current diff, and independently executed tests.
