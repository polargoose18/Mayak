# Independent review: task 8, ADR-006 correction pass

codeQualityStatus: CLEAR
recommendation: APPROVE
verdict: confirmed
failure_class: none
blockers: []

Scope: verify the ADR correction against the actual worktree, production deployment defaults, owner decisions, and the supplied evidence. This approves task 8 only, not final block-B acceptance. No product files were edited by this reviewer.

## Findings by severity

- CRITICAL: none.
- HIGH: none.
- MEDIUM: none within this correction pass.
- LOW: none requiring a change within this correction pass.

## Independently checked results

1. `docs/adr/ADR-006-agent-check.md:23` retains the dated owner decision moving B6/B7 to block F. Traffic accounting is explicitly deferred in the workload section at line 88 and Consequences at line 128. No checked B7 item or promise to finish traffic accounting in block B remains.
2. `docs/adr/ADR-006-agent-check.md:84,133` correctly identifies `defaultControlAddr` as the independent source of `ControlTLS`. Actual source `cmd/mayak/env.go:35-44` initializes `Control.BaseURL` from `defaultControlURL`, parses `defaultControlAddr` with `netip.ParseAddrPort`, and assigns the result to `env.ControlTLS`. There is no URL-derived TLS address in that path.
3. The empty deployment constants at `cmd/mayak/env.go:20-21` are distinguished from the populated anchors and neutral SNI at lines 46-47. The two anchor URLs and `example.net` in ADR line 84 exactly match that source. The wording does not claim those defaults are empty.
4. ADR line 138 leaves B9 unchecked, explicitly disclaims completion, and distinguishes passing smoke tests from final acceptance. The task-8 manual QA matrix also explicitly leaves Windows CI and complete final acceptance unexecuted. A successful current repository check therefore does not silently close B9.
5. B1 and B3 remain checked at ADR lines 132-133. `git log -1 --oneline 79f7c07` resolves to `79f7c07 Add the targets source and rotation for mayak check`. `git diff --exit-code -- internal/runner/source.go internal/runner/target.go internal/probe` exits 0: those implementation paths were not changed by the pending correction. The B3 description has the intended factual correction to its address source.
6. Q5 retains exit code 130 and the measured-results/state-file contract at ADR line 47. Q2 matches owner decision OD-2 in the supplied draft, including the deterministic-verification rationale. The plan dependency matrix identifies task 8 as a documentation amendment; the review follows the newer explicit correction requirements concerning B9 rather than mechanically marking it complete.

## Commands and evidence inspected

Worktree: `/home/goose/Documents/Mayak-wt/block-b-wave1`.

- Read the complete current ADR and its actual `git diff -- docs/adr/ADR-006-agent-check.md`.
- Read actual `cmd/mayak/env.go`, not merely its quoted log copy.
- Ran whole-worktree `git diff --check`: exit 0, no whitespace errors.
- Ran independent Python assertions over the current files for traffic deferral in both sections, the separate TLS parser, populated anchors/neutral SNI, unchecked B9, retained Q2/Q5, retained B1/B3 completion, current ADR/log consistency, and unchanged B1/B3 implementation paths: all eight checks passed.
- Ran `make check`: exit 0. It ran `go vet ./...` and `go test ./...`; all ten reported packages passed using cached test results. This is independently observed gate output, not a fresh uncached or race-test run.
- Inspected `.omo/evidence/mayak-block-b-finish/task-8-adr.log`, including the historical invalid completion claims and the appended correction evidence. The appended section contains package-test exit 0, diff-check exit 0, make-check exit 0, the corrected ADR diff, and criterion results.
- Inspected `.omo/evidence/mayak-block-b-finish/task-8-manual-qa.md`: the matrix labels the historical failure/invalid verdict as superseded and references concrete artifacts. It does not claim final block-B acceptance.
- Consulted `/home/goose/.omo/wt/t1d1bc67edd/m/.omo/plans/mayak-block-b-finish.md` and `/home/goose/.omo/wt/t1d1bc67edd/m/.omo/drafts/mayak-block-b-finish.md` for the dependency matrix and owner decision OD-2.

Reproduction: in the worktree, run `git diff --check`, `git diff -- docs/adr/ADR-006-agent-check.md`, `git diff --exit-code -- internal/runner/source.go internal/runner/target.go internal/probe`, and `make check`; compare ADR lines 23, 47, 84, 88, 128, and 132-138 to `cmd/mayak/env.go:19-47` and draft OD-2.

## Skill-perspective check

Explicitly loaded `remove-ai-slops/SKILL.md`, `programming/SKILL.md`, the Go reference index, and the testing authoring gate and junk-class table from `/home/goose/.omo/binary-runtime/5.1.65/plugin/skills/`. Applied both perspectives to this bounded documentation correction and the production defaults it describes.

The correction introduces no production parsing, extraction, normalization, abstractions, untyped escapes, or repository tests. The independent prose/source assertions are disposable review checks, not permanent tests pinning ADR wording. No deletion-only, removal-certificate, tautological, implementation-mirroring, or brittle prompt test is introduced by task 8. The independent TLS address parser predates this documentation correction and is required by its compile-time deployment boundary. Neither skill perspective identifies a violation in this correction. Other pending implementation tasks in the worktree were not subjected to a full branch-wide quality review here.

## Limits

The report path was supplied explicitly by the caller and the plan identifies this as a non-ULW-loop run. No JS eval or agentToolkit status tool is exposed to this reviewer, so currentAttemptDir could not be queried; the requested artifact path is used. Windows CI, deployment, a fresh uncached full suite, and final block-B acceptance were not run by this reviewer. No such completion is implied by this approval.
