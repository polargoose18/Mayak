# Code review — task 6+11: Embedded targets list expiry guard

Worktree: /home/goose/Documents/Mayak-wt/block-b-wave1
Reviewed by: independent verifier (omo-native-code-reviewer), 2026-11-09.

## Scope of change (verified from git status + diff)

- `targets/freshness.go` (new): `freshEnough(expires, now, warn)` — fails when
  `!now.Add(warn).Before(expires)` (conservative: exactly-at-7-days fails) and
  on zero expiry; error message embeds re-sign instructions.
- `targets/embed_test.go`: `TestFreshEnough` (unconditional, table-driven) and
  `TestEmbeddedListFreshness` (gated on `MAYAK_TARGETS_EXPIRY_GUARD=1`, reads
  the EMBEDDED list via `list.Open(list.PublicKeys(), Signed())`, warn = 7*24h).
- `Makefile`: `targets-expiry` target exports the env var; deliberately not a
  dep of `check` (`check: fmt vet test` confirmed).
- `.github/workflows/ci.yml`: `check` job runs `make targets-expiry` with
  `continue-on-error: true` (verified with a real YAML parser).
- `docs/KEYS.md`: "Перед релизом" section with re-sign commands (lines 70–80).

## Reproduced commands (all in the worktree)

| Command | Result | Expected | OK |
|---|---|---|---|
| `go test ./targets -count=1` | ok (0.002s) | pass, guard skips | yes |
| `go test ./targets -run '^TestEmbeddedListFreshness$' -count=1 -v` | `--- SKIP: TestEmbeddedListFreshness` + skip line | skip shown | yes |
| `MAYAK_TARGETS_EXPIRY_GUARD=1 go test -run '^TestEmbeddedListFreshness$' ./targets -count=1` | FAIL: `targets list expires 2026-11-11T00:00:00Z, which is within 168h0m0s` | fail, 2026-11-11 | yes |
| `make targets-expiry` | exit 2 (make Error 1) | non-zero | yes |
| `go test ./targets -run TestFreshEnough -v -count=1` | PASS (all subtests) | pass without env | yes |
| `go vet ./targets` | rc=0 | clean | yes |
| `gofmt -l targets` | empty | empty | yes |
| `go test ./targets -count=1` twice | both ok | no flake | yes |

## Adversarial checks

- (a) Misleading success: the skip is a genuine skip (visible `--- SKIP` line),
  and the same test FAILS with the env var set — the guard is inert by default
  by design, not silently passing.
- (b) Stale state: test opens `Signed()` (embedded bytes), not the disk file;
  correct target. `TestSignedIsTheCommittedFile` separately pins embedded ==
  committed file.
- (c) Dirty worktree: modified files include unrelated concurrent-unit changes
  (classify.go, ADR-006, SPEC.md, README, runner reports, cmd/mayak-ctrl);
  leftovers attributable to 6+11: `targets/freshness.go`, `targets/embed_test.go`,
  Makefile `targets-expiry` target, ci.yml expiry step, KEYS.md section. No
  debris (temp files, stray logs) from these units.
- (d) Flakiness: two consecutive `go test ./targets` runs both ok.

## Skill-perspective check

The `remove-ai-slops` and `programming` skill files were not loadable as files
in this environment (no skill loader); criteria applied from the review prompt:

- No deletion-only, tautological, or removal-mirroring tests. `TestFreshEnough`
  tests real behavior (conservative boundary, zero expiry); the table case
  "exactly 7 days left" pins a stated requirement, not an implementation
  accident (conservative is the documented intent).
- `TestEmbeddedListFreshness` reads domain data through the real
  open-with-built-in-keys path — not an implementation mirror.
- No untyped escape hatches; no needless production complexity: the env-var
  gate lives in the test, not production code; `freshEnough` is a small pure
  function with constant error strings.

Verdict: does not violate either skill perspective.

## Findings by severity

- CRITICAL: none.
- HIGH: none.
- MEDIUM: none.
- LOW: `Makefile` recipe uses `$$` escaping for `^...$` — correct but subtle;
  verified working (make passes the regex intact to go test). No action needed.
- LOW (observation, out of scope): concurrent sibling units leave the full
  `go test ./...` in an unknown state in this shared worktree; scoped checks
  (`./targets`, vet, gofmt) are all green.

## Verdict

All claims under test reproduce exactly. codeQualityStatus: CLEAR,
recommendation: APPROVE, blockers: none.
