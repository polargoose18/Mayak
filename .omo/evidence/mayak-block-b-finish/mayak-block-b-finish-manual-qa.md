# Manual QA: final repository gates

| Scenario | Criterion reference | Surface | Exact invocation | Verdict | Artifact refs |
|---|---|---|---|---|---|
| GATE-1 | Task: required gate 1 (`make check`) | Repository Make target on `/home/goose/Documents/Mayak-wt/block-b-wave1`, branch `block-b-wave1`, HEAD `5078a1d856e21799a8a66b2271299ef023cf0dd8` | `cd /home/goose/Documents/Mayak-wt/block-b-wave1 && make check` | PASS, exit code 0 | `gate-log` |
| GATE-2 | Task: required gate 2 (`make sign-check`) | Same checkout and HEAD; run sequentially after GATE-1 | `cd /home/goose/Documents/Mayak-wt/block-b-wave1 && make sign-check` | PASS, exit code 0 | `gate-log` |
| BRANCH-1 | Task: use integration branch; exclude task-15 unlanded edits | Git refs and tracked tree | `GIT_MASTER=1 git status --short --branch`; `GIT_MASTER=1 git branch --show-current`; `GIT_MASTER=1 git rev-parse HEAD`; `GIT_MASTER=1 git diff --name-status block-b-wave1..block-b-final-verification`; `GIT_MASTER=1 git ls-tree -r --name-only <ref> | grep -Ei 'control|task.?15'` for both refs | PASS. Correct branch/HEAD confirmed. Only pre-existing untracked `.omo/` shown before and after. The integration branch has none of the task-15-only modified/deleted paths from the comparison branch; tracked paths matching control terms are identical on both refs (`cmd/mayak/testcontrol_test.go`, `internal/probe/control.go`). | `gate-log` |

## Adversarial cases

| Scenario | Criterion reference | Adversarial class | Expected behavior | Verdict | Artifact refs |
|---|---|---|---|---|---|
| ADV-1 | Task: do not run the separate `block-b-final-verification` checkout | Wrong-branch contamination | Gate commands execute in the specified `block-b-wave1` repository on the integration branch, never the task-15 verification branch. | PASS. Captured branch and HEAD identify the requested checkout; branch comparison records the separate task-15 changes. | `gate-log` |
| ADV-2 | Task: no network or remote CI writes | External side effects | Local Make targets and read-only Git inspection must not issue remote writes. | NOT_APPLICABLE — the requested gates and branch inspections are local commands and this run made no network or remote CI calls. | `gate-log` |

## Artifacts

| ID | Kind | Description | Path |
|---|---|---|---|
| `gate-log` | command transcript | Full combined stdout/stderr and exit codes for both gates, plus branch/status, task-15 branch comparison, and tracked control-path inspection. | `/home/goose/Documents/Mayak/.omo/evidence/mayak-block-b-finish/final-gates.log` |

Both required gates passed. Initial and final `git status --short --branch` were `## block-b-wave1` and `?? .omo/`; no tracked or other worktree changes appeared during this gate run. No code changes were made. Residual limitation: the substring-based tracked-path inspection identifies control-related filenames, while the branch comparison establishes the exact path differences; it does not assert semantic identity of modified contents.