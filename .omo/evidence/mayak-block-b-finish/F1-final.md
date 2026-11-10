# F1. Final plan-compliance review

Date: 2026-11-10  
Reviewed integration branch: `/home/goose/Documents/Mayak-wt/block-b-wave1`  
Expected and verified HEAD: `21337d823ba80787be95835dde4ac231021e7199`  
Recommendation: **GAPS**  
Confidence: 0.97

## Original intent

`originalIntent`: Deliver block B as a locally usable diagnostic command with validated machine-readable reports, honest exit codes and interruption safety; provide a constrained control-node API and any-SNI TLS listener; and align documentation and CI with the shipped behavior, while honoring direct local delivery without pushing.

`desiredOutcome`: The integration branch and its evidence show which planned behaviors are delivered, which acceptance criteria remain incomplete, and which operational prerequisites need owner or native-platform evidence.

`userOutcomeReview`: The requested integration commit is present at the exact expected HEAD. It contains the ten control-node task-15 files, including persistent revision rollback protection, runtime expiry checks, a real client-IP privacy regression, and an integration test calling `probe.TLSSNI` against the delivered listener. The task-15 integration log records `make check` and `make sign-check` passing against the same source content before those exact files were committed. The remaining task-16 120-requests/minute budget and acceptance tests are absent; the committed limiter remains at 20 requests/minute. No native Windows run is evidenced under the direct/no-push constraint. The embedded signed targets list has expiry `2026-11-11T00:00:00Z`, so the near-term owner re-sign/release prerequisite remains unresolved by the inspected artifacts.

## Blockers

1. **IS-5 / todo 16 acceptance criteria — request budget**  
   `violatedCriterion`: Plan success row IS-5 and todo 16 require a 120/minute per-prefix budget that admits the supported run's 60 requests and rejects request 121, with tests.  
   Observation: Todo 16 remains `[~]`. Its evidence explicitly says no 60-request run or 121st-request rejection was tested, and the task-15 review confirms the 20/minute constants remain.  
   `evidencePointer`: `/home/goose/Documents/Mayak/.omo/plans/mayak-block-b-finish.md` todo 16 and IS-5; `/home/goose/Documents/Mayak/.omo/evidence/mayak-block-b-finish/task-16-rate-budget.log`; `/home/goose/Documents/Mayak/.omo/evidence/mayak-block-b-finish/15-code-review.md`, “Rate cap unchanged”; integration source `/home/goose/Documents/Mayak-wt/block-b-wave1/cmd/mayak-ctrl/ratelimit.go`.

2. **IS-6 / todo 10 Windows execution evidence**  
   `violatedCriterion`: Todo 10's happy QA scenario requires a green native Windows job and its run URL; IS-6 identifies Windows CI as a target platform.  
   Observation: The workflow is configured for `windows-2025`, but no native Windows runner output or run URL appears in the checked evidence. Linux checks and Windows cross-build probes do not prove the Windows job ran. The no-push delivery constraint is respected; this review did not trigger CI or push.  
   `evidencePointer`: `/home/goose/Documents/Mayak/.omo/plans/mayak-block-b-finish.md` todo 10 QA scenario and IS-6; `/home/goose/Documents/Mayak/.omo/evidence/mayak-block-b-finish/task-10-windows-ci.log`; `/home/goose/Documents/Mayak-wt/block-b-wave1/.github/workflows/ci.yml`.

3. **IS-4 / todo 6 owner re-sign acceptance**  
   `violatedCriterion`: Todo 6 acceptance requires the expiry check and `make sign-check` to pass after owner re-signing; IS-4 requires the embedded list to remain unexpired for a fresh checkout.  
   Observation: The inspected signed payload is set to expire at `2026-11-11T00:00:00Z`. The evidence records the expected near-expiry guard failure, but contains no owner re-sign and no post-re-sign expiry/sign-check receipt. The owner-only signing prerequisite is therefore still open; this review did not sign or change targets.  
   `evidencePointer`: `/home/goose/Documents/Mayak/.omo/plans/mayak-block-b-finish.md` todo 6, IS-4, and Commit strategy; `/home/goose/Documents/Mayak/.omo/evidence/mayak-block-b-finish/task-11-expiry-skip.log`; `/home/goose/Documents/Mayak-wt/block-b-wave1/targets/targets.signed.json`.

## Plan, ledger, and integration commit

The current plan marks todos 1–15 `[x]`, todo 16 `[~]`, F2 `[x]`, F3 `[x]`, and F1/F4 `[~]`. Task 15 is no longer a missing integration: `GIT_MASTER=1 git show --stat 21337d823ba80787be95835dde4ac231021e7199` confirms ten changed files under `cmd/mayak-ctrl`, and `GIT_MASTER=1 git rev-parse HEAD` in the requested worktree returned the expected hash. The commit is `fix(mayak-ctrl): enforce target lifecycle and privacy invariants`.

The task-15 integration log records the requested formatting correction and successful control-node build, vet, repeated package tests, `make check`, and `make sign-check`. Its capture predates the commit and prints the earlier worktree state; it also records that no task-15 source was changed after copying. The user specifically confirms that the committed files are exactly the checked source content. Per instruction, I did not rerun tests. The earlier F1 report's task-15 integration absence and associated privacy/TLS findings are superseded by this commit and its evidence.

The ledger records task 15's former unmet checkpoint followed by task 16 blocked on task 15; those entries describe earlier state. Current plan and commit supersede task 15's unlanded status. Task 16 remains unmet, with the selected 120/minute choice recorded but unimplemented. F3's prior gate report covers an older HEAD, so it is historical context; the task-15 integration log supplies the current-source `make check` and `make sign-check` receipt as described above.

## Task and skill-perspective check

Loaded `remove-ai-slops/SKILL.md` and `programming/SKILL.md`. Directly reviewed the task-15 diff summary, changed production/tests as represented by the committed file set, task-15 review and integration log, and the task-16 absence evidence. From the user's perspective, the privacy and probe-integration tests added by task 15 test real observable contracts: a distinctive address is searched across output/log/state sinks, and the actual probe reports target-SNI-via-control success. The rollback and expiry tests likewise exercise restart and authorization boundaries. I found no deletion-only tests, tests solely certifying a requested removal, tautological tests, or tests that only mirror implementation constants in task 15. The new file split follows task 15's explicit plan criterion. There is no task-16 production code or test to overfit-review because the task is explicitly unimplemented.

The task-15 independent review at `/home/goose/Documents/Mayak/.omo/evidence/mayak-block-b-finish/15-code-review.md` explicitly records both skill perspectives and checks for deletion-only, tautological, implementation-mirroring, unnecessary parsing, and unnecessary production extraction. That review covered the task-15 worktree and is corroborated by the integration commit and integration log. It does not satisfy task 16 or provide Windows execution evidence.

## Exact evidence gaps

- No implementation or test demonstrates the chosen 120/minute budget, admits all 60 requests of the supported check run, or rejects request 121.
- No native Windows job receipt or run URL exists in the checked evidence.
- No owner re-sign or post-re-sign expiry plus `make sign-check` receipt exists for the payload expiring `2026-11-11T00:00:00Z`.
- This review performed no tests, build, CI trigger, push, signing operation, or product edit, as requested. Task-15 check results are taken from its inspected pre-commit log and the user's statement that the committed files match that tested content.

## Checked artifact paths

- `/home/goose/Documents/Mayak/.omo/plans/mayak-block-b-finish.md`
- `/home/goose/Documents/Mayak/.omo/ulw-execute/ledger.jsonl`
- `/home/goose/Documents/Mayak/.omo/evidence/mayak-block-b-finish/F1-plan-compliance.md` (prior review; task-15 section superseded)
- `/home/goose/Documents/Mayak/.omo/evidence/mayak-block-b-finish/F1-final.md` (previous final review; replaced by this review)
- `/home/goose/Documents/Mayak/.omo/evidence/mayak-block-b-finish/F2-code-quality.md`
- `/home/goose/Documents/Mayak/.omo/evidence/mayak-block-b-finish/F3-qa-matrix.md`
- `/home/goose/Documents/Mayak/.omo/evidence/mayak-block-b-finish/F4-ideal-state.md`
- `/home/goose/Documents/Mayak/.omo/evidence/mayak-block-b-finish/task-15-control-hardening.log`
- `/home/goose/Documents/Mayak/.omo/evidence/mayak-block-b-finish/task-15-integration-manual-qa.md`
- `/home/goose/Documents/Mayak/.omo/evidence/mayak-block-b-finish/15-code-review.md`
- `/home/goose/Documents/Mayak/.omo/evidence/mayak-block-b-finish/task-16-rate-budget.log`
- `/home/goose/Documents/Mayak/.omo/evidence/mayak-block-b-finish/task-10-windows-ci.log`
- `/home/goose/Documents/Mayak-wt/block-b-wave1/` at commit `21337d823ba80787be95835dde4ac231021e7199`
- `/home/goose/.omo/binary-runtime/5.1.65/plugin/skills/remove-ai-slops/SKILL.md`
- `/home/goose/.omo/agent/desktop-launch-profiles/c3709b5f58c47da72d77a180475dd20472b09fcb5d99ef7219b0990065215d13/skills/programming/SKILL.md`

{"task":"F1. Plan compliance audit","verdict":"GAPS","blockers":[{"violatedCriterion":"IS-5 / todo 16 acceptance criteria","observation":"The 120/minute per-prefix budget and 60/121 request tests are not implemented; committed rate limit remains 20/minute.","evidencePointer":"/home/goose/Documents/Mayak/.omo/evidence/mayak-block-b-finish/task-16-rate-budget.log; /home/goose/Documents/Mayak-wt/block-b-wave1/cmd/mayak-ctrl/ratelimit.go"},{"violatedCriterion":"IS-6 / todo 10 Windows execution evidence","observation":"No native Windows run output or CI URL is present.","evidencePointer":"/home/goose/Documents/Mayak/.omo/evidence/mayak-block-b-finish/task-10-windows-ci.log"},{"violatedCriterion":"IS-4 / todo 6 owner re-sign acceptance","observation":"The signed targets payload expires 2026-11-11T00:00:00Z; no owner re-sign or post-re-sign expiry/sign-check receipt is evidenced.","evidencePointer":"/home/goose/Documents/Mayak-wt/block-b-wave1/targets/targets.signed.json; /home/goose/Documents/Mayak/.omo/evidence/mayak-block-b-finish/task-11-expiry-skip.log"}],"evidence":["Expected integration HEAD verified: 21337d823ba80787be95835dde4ac231021e7199.","Commit contains all ten task-15 control-node files.","Task-15 integration log records make check and make sign-check passing before commit on unchanged source content; tests were not repeated per instruction.","Task 15 rollback protection, runtime expiry, privacy regression, and probe.TLSSNI integration are present and backed by task-15 evidence.","remove-ai-slops and programming skill criteria were loaded and directly applied to task 15."],"confidence":0.97}
