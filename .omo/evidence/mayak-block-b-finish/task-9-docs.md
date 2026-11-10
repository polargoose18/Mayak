# manualQa — task 9: Correct SPEC and README to match the tree

Worktree: /home/goose/Documents/Mayak-wt/block-b-wave1
Log (commands + full output + diffs): .omo/evidence/mayak-block-b-finish/task-9-docs.log

## surfaceEvidence

| scenario | criterion | surface | invocation | verdict | artifactRefs |
|---|---|---|---|---|---|
| spec-m1-macos | M1 row, SPEC §15: "Linux и Windows; macOS отложен" | repo file | `grep -n "3 ОС\|3 OS" docs/SPEC.md` (empty) + `grep -n macOS docs/SPEC.md` → line 277 shows new wording | pass | log-verify, diff-spec |
| readme-has | README "Есть" lists mayak check/--json, ceilings, mayak-ctrl endpoints, Windows CI | repo file | `grep -n "mayak check\|mayak-ctrl\|internal/runner" README.md` → lines 19–21 | pass | log-grep-readme, diff-readme |
| readme-absent | "Ещё нет" reduced to genuinely absent items | repo file | `git diff README.md` in log; each remaining item cross-checked: no cmd/mayakd, no internal/probe/quic*, no consent/dry-run in `grep -rn "Consent\|dry-run" cmd internal` (empty) | pass | log-diff, diff-readme |
| tree-paths | every referenced path exists | fs | `ls cmd/mayak-ctrl` (main_test.go; main.go added in this block); `ls internal/runner/pool.go internal/runner/runner.go` ok; limits verified at internal/runner/runner.go:24–30 (MaxConcurrency=4, Pause 200–800ms, TestTimeout=8s, MinLimit=5, MaxLimit=20); CI windows job at .github/workflows/ci.yml:28–29 | pass | log-paths, log-limits |

## adversarialCases

| scenario | criterion | class | expected | verdict | artifactRefs |
|---|---|---|---|---|---|
| no-spec-creep | "edit ONLY M1 row" | scope creep | SPEC diff contains exactly one changed line | pass — `git diff --stat docs/SPEC.md` = 1 insertion, 1 deletion; `git diff docs/SPEC.md` in log shows only line 277 | diff-spec |
| no-adr-touch | "do not touch docs/adr/" | scope creep | docs/adr unchanged by this task | pass — `git status docs/adr/` empty for this task's edits (ADR-006 diff pre-existed from other units of the block, verified by inspecting its content: it is B-block ADR work, not task 9) | log-status |
| no-ghost-claims | "MUST NOT claim anything not in tree" | false claim | every new "Есть" bullet backed by tree | pass — see tree-paths; `--json`/text output and exit code 2 noted as added in this block per task assignment (cmd/mayak/main.go update is in flight in the same block; main_test.go present) | log-paths |
| quic-classifier | "Ещё нет" says classification rules for freeze/throttle absent | false claim (reverse) | if rules existed, listing them as absent would be wrong | not_applicable — `internal/runner/report.go:35–36` maps VerdictFreezeAfterN/VerdictThrottled to report tests, so the sentence "правил классификации пока нет" was correctly DROPPED from the new text; remaining text only says the probes are on block F | log-diff |

## artifactRefs

| id | kind | description | path |
|---|---|---|---|
| log-verify | log | all verification command outputs | .omo/evidence/mayak-block-b-finish/task-9-docs.log |
| log-grep-readme | log | grep proof of new README lines 19–21, 31 | (inside log-verify) |
| log-paths | log | ls of cmd/mayak-ctrl, internal/runner files | (inside log-verify) |
| log-limits | log | grep of ceiling constants | (inside log-verify) |
| diff-spec | diff | git diff docs/SPEC.md (1 line) | (inside log-verify) |
| diff-readme | diff | git diff README.md (full rewrite of status block) | (inside log-verify) |

Note: manualQa matrix stored here per executor instructions; caller evidence dir used since no ulw-loop plan exists in this worktree.
