# Code Review: Task 10 — Add Windows CI job

**Reviewer:** omo-native-code-reviewer (independent verifier)  
**Date:** 2026-11-09  
**Goal:** Add a Windows CI job to `.github/workflows/ci.yml` matching the spec.  
**Changed file:** `.github/workflows/ci.yml`

---

## Verification Results

All executor claims were independently verified.

### 1. Diff Inspection

```
$ git diff .github/workflows/ci.yml
```
- Exactly 10 lines added (the `windows` job block).
- No deletions or modifications to existing jobs.
- The `release-check` job is untouched (starts at the same line offset, same content).

### 2. Ubuntu Job Unchanged

Compared `git show HEAD:.github/workflows/ci.yml` against the working tree:

| Job | Status |
|-----|--------|
| `check` | **Byte-identical** — same `runs-on: ubuntu-24.04`, same 6 steps, same pinned SHAs |
| `release-check` | **Byte-identical** — same `if: startsWith(github.ref, 'refs/tags/v')`, same `runs-on: ubuntu-24.04`, same 2 steps |

### 3. YAML Parsing

Parsed with `python3 -c "import yaml; ..."`:

```
Job: check
  runs-on: ubuntu-24.04
  steps:
    uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
    uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e
    run: make check
    run: make sign-check
    run: go test -race ./...
    run: go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...

Job: windows
  runs-on: windows-2025
  steps:
    uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
    uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e
    run: go build ./...
    run: go test ./...

Job: release-check
  runs-on: ubuntu-24.04
  if: startsWith(github.ref, 'refs/tags/v')
  steps:
    uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
    run: make release-check
```

### 4. Pinned SHAs

| Action | `check` job | `windows` job | Match? |
|--------|-------------|---------------|--------|
| `actions/checkout` | `3d3c42e5aac5ba805825da76410c181273ba90b1` | `3d3c42e5aac5ba805825da76410c181273ba90b1` | ✅ |
| `actions/setup-go` | `b7ad1dad31e06c5925ef5d2fc7ad053ef454303e` | `b7ad1dad31e06c5925ef5d2fc7ad053ef454303e` | ✅ |

### 5. Build & Test Reproduction

```
$ go build ./...
(no output — success)

$ go test ./... -count=1
ok  	github.com/polargoose18/mayak/cmd/mayak	0.007s
ok  	github.com/polargoose18/mayak/cmd/mayak-sign	0.046s
ok  	github.com/polargoose18/mayak/internal/classify	0.157s
ok  	github.com/polargoose18/mayak/internal/probe	3.500s
ok  	github.com/polargoose18/mayak/internal/report	0.032s
ok  	github.com/polargoose18/mayak/internal/runner	2.461s
ok  	github.com/polargoose18/mayak/internal/targets	0.028s
ok  	github.com/polargoose18/mayak/targets	0.003s
ok  	github.com/polargoose18/mayak/testbed/mockdpi	0.541s

$ make check
go vet ./...
go test ./...
ok  	github.com/polargoose18/mayak/cmd/mayak	(cached)
...
```

All green.

### 6. Executor QA Log Inspection

Opened `.omo/evidence/mayak-block-b-finish/task-10-windows-ci.log`:
- Contains real `python3` parser output (not prose).
- Contains verbatim `git diff`.
- Contains actual `go build` / `go test` / `make check` command output.
- Contains an adversarial `GOOS=windows go build ./...` probe with a deliberate compile error, then cleanup.
- No unsupported claims.

### 7. Adversarial Checks

| Check | Result |
|-------|--------|
| **(a) Misleading YAML** | The `windows` job is a real, top-level job map key. No aliases, no indentation tricks. It is a sibling of `check`, not nested under it. |
| **(b) Stale state** | The `windows` job has no `if:` condition, so it triggers on every `push` and `pull_request`. Reachable. |
| **(c) Dirty worktree** | `git status --porcelain` shows only ` M .github/workflows/ci.yml` and `?? .omo/`. The `.omo/` directory is the evidence artifact store (untracked, expected). No stray probe files. |

---

## Findings

**No findings.**

| Severity | Count | Details |
|----------|-------|---------|
| CRITICAL | 0 | — |
| HIGH | 0 | — |
| MEDIUM | 0 | — |
| LOW | 0 | — |

---

## Skill-Perspective Check

- **`remove-ai-slops` skill**: Applied. No deletion-only tests, no tautological tests, no implementation-mirroring tests, no unnecessary data extraction. N/A for a CI-only change.
- **`programming` skill**: Applied. No brittle prompt tests, no untyped escape hatches, no needless abstraction. The change is a minimal, declarative YAML addition.

---

## Verdict

| Field | Value |
|-------|-------|
| `codeQualityStatus` | CLEAR |
| `recommendation` | APPROVE |
| `blockers` | none |

All executor claims confirmed by independent verification.
