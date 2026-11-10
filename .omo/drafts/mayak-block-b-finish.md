---
slug: mayak-block-b-finish
status: plan-written
intent: clear
review_required: true
plan_path: .omo/plans/mayak-block-b-finish.md
plan_sha256: 316d73f1a110c437426f88c3f58983739ac28db031bbc4a0413dea636be5bc94
review_round_id: round-1
review_round_limit: 5
pending-action: write and review .omo/plans/mayak-block-b-finish.md
review:
  plan_reviewer:
    status: unavailable
    workspace_root: /home/goose/Documents/Mayak
    runtime_home: null
    target: .omo/plans/mayak-block-b-finish.md
    round_id: round-1
    plan_sha256: 316d73f1a110c437426f88c3f58983739ac28db031bbc4a0413dea636be5bc94
    launch_id: null # spawn failed: no usable model for plan-reviewer
    session: null
    result: substituted by in-session self-review, round 1 (see plan Review record)
approach: Finish block B of `mayak check` (steps B4, B5, B8, B9, B10 and the CI/doc corrections), because ADR-006 records B1-B3 as done and the command itself does not exist yet; slow probes B6/B7 and the control-node deployment stay behind an explicit owner decision.
---

# Draft: mayak-block-b-finish

## Affected user and ideal state

**Affected users.**
1. A person running `mayak check` on their own machine (Linux; Windows planned). Today they get `mayak version` and nothing else. After: they type one command and learn, per popular service, whether the problem is theirs or their operator's, and why.
2. A tool author or script consuming `mayak check --json`. Today: no such output. After: a stable array of `mayak.report/1` documents that passes the project's own validator.
3. The project owner operating the control node. Today: `mayak-ctrl` is a written protocol with no binary, so every real run ends `inconclusive` (ADR-006 Q1/Consequences). After: one deployable binary with the SPEC 21.1 guardrails and the any-SNI TLS listener the agent's third handshake needs.
4. Whoever reads the repo next (a contributor, an agent, or the owner after a break). Today: README, SPEC and ADR-006 contradict the tree. After: docs and CI describe what actually ships.

| Row | Statement | Reason |
| --- | --- | --- |
| IS-1 | `mayak check` runs on Linux, prints one line per target plus a summary and a plain "nothing was sent", and exits 0 for any verdicts, 1 for a run/IO failure, 2 when ctrl failed on every target (ADR-006 Q5). | This is the whole point of block B: a usable local diagnostic, and a script needs a stable exit contract. |
| IS-2 | `mayak check --json` writes only a JSON array of `mayak.report/1` documents to stdout, and each document passes `report.Validate`. | The report format is the project's public interface (SPEC 7); anything else breaks downstream tools. |
| IS-3 | Ctrl-C during a run prints what was measured so far, leaves `targets.rev` and `rotation` intact, and exits with a documented code. | Users interrupt long runs; a truncated or corrupt state file would silently break rollback protection or rotation. |
| IS-4 | The targets list built into the binary is unexpired, so a fresh checkout can actually run `mayak check`; `make check` and `make sign-check` stay green. | The embedded list expires 2026-11-11; an expired list is refused by design (SPEC 21.2), which would make the finished command unusable on day one. |
| IS-5 | `cmd/mayak-ctrl` serves `/v1/ping`, `/v1/reach`, `/v1/fetch` exactly as SPEC 21.1 states (static paths, host allowlist from its own signed list, public addresses only, no ip/port parameters, rate limit, no client-address logs) and a TLS listener on 443 that accepts any SNI. | Without the any-SNI listener the agent's third handshake always fails and `sni_block` via the control node is unreachable (ADR-006, open gap 1). |
| IS-6 | The repo tells the truth: SPEC says Linux and Windows with macOS deferred, CI builds and tests on both, ADR-006 action items reflect the real state, README no longer claims the orchestrator is missing. | A contributor or agent reading stale docs will re-do finished work or contradict a decision. |
| IS-7 | `freeze_after_n` and `throttled` are explicitly out of block B: ADR-006 records the move to block F, and `internal/classify/classify.go:62` keeps saying the rules do not exist yet, now with a pointer to the gate change. | SPEC 21.3 lists the verdicts while ADR-006 Q2 first put them in block B; the owner has now decided they cannot be proven in this slice, so the decision must be written down instead of silently skipped. |

| Row | Difference from today | Why it matters | Closed by |
| --- | --- | --- | --- |
| GAP-1 | `cmd/mayak/main.go:20` registers only `version`; no `check` subcommand, no flags, no output, no exit codes. | There is no product yet. | 1, 2, 3 |
| GAP-2 | No production code builds `report.Report` from `runner.Result`; `report.NewReportID` is called only from its own test (`internal/report/id_test.go`). | `--json` cannot exist, and the report format stays unused. | 2 |
| GAP-3 | `runner.Run` returns `ctx.Err()` on cancel (internal/runner/pool.go:98) and marks unstarted targets, but nothing in `cmd/mayak` handles signals or chooses an exit code. | Ctrl-C behaviour is explicitly left to B5 (ADR-006 Q5). | 3 |
| GAP-4 | `targets/targets.signed.json` payload has `expires: 2026-11-11T00:00:00Z`, `rev 2026-10-14.1`; today is 2026-11-09. | In two days every fresh binary refuses its own built-in list. | 0 (owner action) + 6 |
| GAP-5 | No `cmd/mayak-ctrl` directory; `internal/probe/control.go:16-18` says the protocol "is a proposal for cmd/mayak-ctrl, which does not exist yet". | Without it every real run is `inconclusive` (exit 2). | 4 |
| GAP-6 | `.github/workflows/ci.yml` has one job on `ubuntu-24.04`; no Windows build or test. ADR-006 Q10 requires both OSes in CI. | A Windows-only regression would ship unnoticed, and the ADR promise stays unverifiable. | 5 |
| GAP-7 | `internal/classify/classify.go:62` states `freeze_after_n` and `throttled` have no rules; no `tcp_freeze` or `throughput` probe exists; `testbed/mockdpi` has no throttling scenario. | Two verdicts listed in SPEC 21.3 are unreachable, and B6/B7 are unplanned. | 8 (ADR-006 gate edit; probes deferred to block F by owner decision OD-2) |
| GAP-8 | `README.md` "Ещё нет" lists the orchestrator with load ceilings as missing, though `internal/runner/pool.go` implements them; ADR-006 Action Items still show B1 unchecked although commit 79f7c07 landed it. | Readers and agents act on wrong state. | 6 |
| GAP-9 | SPEC 15 (M1 row) still says "бинарники под 3 ОС"; ADR-006 Q10 decided Linux+Windows with macOS deferred and assigned the correction to B10. | Conflicting sources of truth; AGENTS.md says SPEC wins, so the wrong text wins. | 6 |

## Components (topology ledger)

| id | outcome | status | evidence path |
| --- | --- | --- | --- |
| C1 CLI | `mayak check` exists with flags, English/ASCII text output, `--json`, exit codes, Ctrl-C | active | cmd/mayak/main.go:1-41 |
| C2 report | one run's results become valid `mayak.report/1` documents | active | internal/report/report.go:101-134, internal/report/validate.go:44-71 |
| C3 control node | `cmd/mayak-ctrl` serves SPEC 21.1 and an any-SNI TLS listener | active | docs/SPEC.md:21.1, internal/probe/control.go:16-52 |
| C4 targets freshness | built-in signed list valid; re-sign documented as an owner step | active (owner action) | targets/targets.signed.json, docs/KEYS.md |
| C5 slow probes | `tcp_freeze`, `throughput`, and the two missing classifier rules | deferred to block F by owner decision OD-2 (recorded in ADR-006 by todo 8) | internal/classify/classify.go:62, docs/SPEC.md:19 |
| C6 docs & CI | SPEC/README/ADR/CI match the tree; Windows job exists | active | .github/workflows/ci.yml:1-33, README.md:16-31 |

## Open assumptions (announced defaults)

| assumption | adopted default | rationale | reversible? |
| --- | --- | --- | --- |
| One report per target vs one report per run | Decide in the plan, but default to **one report per run**: a single document whose `results` holds every measured test outcome of that run. | The schema allows 1..200 results; one document per run keeps `ts` and `targets_rev` single-valued and avoids N report IDs for one act of measurement. | Yes, mapping lives in one function. |
| `report_id` randomness | `report.NewReportID()` per document (5 random bytes, 10 hex). | Already implemented and tested; SPEC 7 requires unlinkable IDs. | No (format). |
| `agent.ver` | reuse the existing `version` const (`dev`) — the validator accepts `dev` (internal/report/fields.go:181-189). | No release pipeline exists yet; ADR-006 Q4 forbids inventing versioning here. | Yes. |
| `net.country`, `net.region` | empty string and `null`: the server determines country from the IP (SPEC 21.3), region only if the user set it. | SPEC 21.3 says the agent does not send country; a local diagnostic run has no region input. | Yes (flag later). |
| `net.ip_ver` | the address family the run actually used for the trusted target address, `4` or `6`. | The validator requires 4 or 6 and the field must mean something. | Yes. |
| `net.resolver` | `unknown` in this slice. | Nothing in the code classifies the resolver today; guessing `isp` would be a false claim. A later step can detect DoH/DoT. | Yes. |
| Ctrl-C exit code | 130. | Shell convention (128+SIGINT); ADR-006 Q5 leaves the value to B5 and the code must be documented and tested. | Yes. |
| Windows CI | Add a `windows-latest`-pinned job running `go build ./...` and `go test ./...`; keep `-race` on Linux only. | ADR-006 Q10 states exactly this, and CI currently has only Ubuntu. | Yes. |
| Ordering | B4 (report mapping) → B5 (command) → B8 (control node) → B10/CI docs → review; slow probes last if approved. | The command needs the mapping; the control node is independent of the command and can be done by a second worker; docs last because they describe the result. | Yes. |

## Findings (cited - path:lines)

- The working directory `/home/goose/Documents/git/Mayak` is empty and not a git repository. The real repository is `/home/goose/Documents/Mayak` (module `github.com/polargoose18/mayak`, branch `main` at 86e7a33, worktree clean). All plan paths are relative to `/home/goose/Documents/Mayak`.
- `make check` and `make sign-check` are green today (go test ./... all packages ok; `TestSignedTargetsFile` PASS), Go 1.27.1 on this machine while go.mod pins 1.26.10.
- `cmd/mayak/main.go:13-41`: only `newRootCmd` + `version`; `main` exits 1 on any error.
- `internal/runner/runner.go:21-30`: `MinLimit=5`, `MaxLimit=20`, `DefaultLimit=10`, `MaxConcurrency=4`, `PauseMin=200ms`, `PauseMax=800ms`, `TestTimeout=8s`.
- `internal/runner/pool.go:61-102`: `Run` keeps the ceilings, returns results in list order, returns `ctx.Err()` on cancel.
- `internal/runner/target.go:26-164`: `Check` runs ctrl → dns (+addr check) → tcp → tls_sni → http with control reference; stops early.
- `internal/runner/source.go:46-76,119-146`: `Source.Load` (embedded or `--targets-file`, `targets.Accept` + `FileRevStore`) and `Source.Pick` (rotation) are done; `runner.RevFile`/`RotationFile` names defined.
- `targets/embed.go:7-13`: `go:embed targets.signed.json` → `Signed()`.
- `targets/targets.signed.json`: payload `rev 2026-10-14.1`, `expires 2026-11-11T00:00:00Z`, 24 items; `targets/targets.json` matches.
- `internal/report/report.go:101-134`: `Report`, `Agent`, `Net`, `Result` structs with JSON tags; `internal/report/id.go:11-17`: `NewReportID`; `internal/report/validate.go:44-71`: `Validate`/`ValidateAt`, 5-minute truncation.
- `internal/report/validate.go:13-39`: `MaxReportSize` 64 KiB, `MaxEvidenceString` 200, `MaxEvidenceDepth` 2, `MaxResults` 200, `TS` window 24h/5min.
- `internal/report/validate.go:120-190`: required keys enforced; `evidence` may only hold scalars at depth 2.
- `internal/classify/classify.go:62`: "freeze_after_n and throttled have no rules yet."; `:338`: `quicBlocked` exists but no QUIC probe.
- `internal/probe/control.go:16-52`: the control-node protocol and its requirements are documented as a proposal for a binary that does not exist; `:53-59` `ControlClient{BaseURL, RootCAs}`.
- `testbed/mockdpi/mockdpi.go:24-90`: scenarios reset_after_hello, dns_spoof, blackhole, stub_page, control, closed_port; no throttling/freeze scenario, and SYN drops cannot be emulated without a firewall.
- `.github/workflows/ci.yml:6-33`: one Ubuntu job (`make check`, `make sign-check`, `go test -race`, `govulncheck`) plus a tag-only `release-check`.
- `docs/adr/ADR-006-agent-check.md:126-132`: Action Items — B1 unchecked (landed in 79f7c07), B3 checked, B5/B7/B8/B10 open; Q2 (ADR-006:23) puts B6/B7 in block B but allows moving them to block F only by owner decision; Q10 (:79) requires Linux+Windows CI.
- `README.md:16-31`: "Ещё нет" still lists the orchestrator with load ceilings and `mayak check`.
- `docs/SPEC.md:15` (M1 row): "бинарники под 3 ОС" — contradicts ADR-006 Q10.
- `docs/KEYS.md`: re-signing is an owner procedure with the private key outside the repo; `make sign-check` does not check expiry.
- `AGENTS.md:9-13`: source-of-truth order is SPEC (higher section number wins) → ADRs → AGENTS.md; `AGENTS.md:79-84` requires `make check` green before claiming done, and forbids new dependencies without justification.

## Decisions (with rationale)

- D1. The plan covers **block B's remainder plus its documentation/CI debt**, because ADR-006 is the accepted decision record for `mayak check` and B1-B3 are already in `main`; starting block C or M2 instead would leave a half-built command.
- D2. `--json` reuses `internal/report` for construction and `report.Validate` as the acceptance gate, so the command cannot emit a document the server would reject.
- D3. The report mapping lives in a new `internal/runner` (or `internal/report`) pure function taking `[]runner.Result` + run metadata, so it is unit-testable without network (AGENTS.md's "vertical slice" rule and ADR-006 Q8's in-process testing).
- D4. `cmd/mayak-ctrl` reuses `internal/targets` for its own signed-list acceptance and `internal/classify`/`internal/probe` address rules for the public-address check, rather than re-implementing them; the any-SNI listener is a separate `tls.Config{GetCertificate}` server on 443.
- D5. Docs are updated in the same block (B10) because AGENTS.md makes SPEC the top source of truth; a stale SPEC actively misleads the next worker.
- D6. The embedded-list expiry is an **owner action with the private key** (OD-3), not a code task; the plan records it as a release prerequisite and documents it in the rollout section.
- D7. `tcp_freeze`/`throughput` are removed from this plan by OD-2 and ADR-006 is amended to say so, because a verdict neither the mock censor nor CI can reach is unverifiable work (AGENTS.md forbids shipping half-features).
- D8. Windows CI is added in this plan (OD-4) rather than deferred, so the ADR-006 Q10 promise is testable before any release.

## Scope IN

- B4: pure mapping from one run's results to `mayak.report/1` document(s), including id, 5-minute `ts`, `agent`, `net`, `targets_rev`, per-result `evidence`.
- B5: `mayak check` command: `--limit`, `--targets core`, `--targets-file`, `--json`, English/ASCII text output, exit codes 0/1/2, Ctrl-C (exit code + partial output + intact state files).
- B8: `cmd/mayak-ctrl` with `/v1/ping`, `/v1/reach`, `/v1/fetch` per SPEC 21.1, signed-list host allowlist, public-address-only dialing, refusal of ip/port parameters, rate limiting, body cap, no client-address logging, plus the any-SNI TLS listener on 443.
- B10: SPEC 15 OS wording; README status; ADR-006 action items **and the B6/B7 gate move to block F**; Windows CI job.
- B9 (inferred): the smoke tests ADR-006 Q8 requires for the built binary (`version`, expired list refusal, bad signature refusal) and `make check` integration.
- Owner prerequisite OD-3: re-signed embedded list (not an implementation todo).

## Scope OUT (Must NOT have)

- No `mayakd` server, ingest API, Postgres, aggregator, public page, Telegram bot (that is M2/M3).
- No `mayak run` daemon, `mayak report --dry-run`, `mayak consent *`, `mayak selfupdate` (later stages).
- No network download of the targets list (block C).
- No OHTTP, Privacy Pass, anonymous credentials, Rust binaries (M4.5/M7).
- No `tcp_freeze` probe, no `throughput` probe, and no classifier rules for `freeze_after_n`/`throttled` — explicitly moved to block F (OD-2).
- No `quic` probe and no `rst_ttl` (M5).
- No new third-party dependencies; standard library plus the already-approved `cobra`, `miekg/dns` (AGENTS.md).
- No change to the report schema, verdict list, or `internal/targets` format.
- No test hooks, env-var overrides, or test keys in production binaries (ADR-006 Q8).
- No macOS support.

## Decisions taken by the owner (2026-11-09, this session)

- OD-1 **Scope**: block B only. M2 (`mayakd`, ingest) is a separate plan.
- OD-2 **B6/B7 moved to block F**: `tcp_freeze` and `throughput` are NOT built in this plan; ADR-006 must record the gate change. Reason quoted: no deterministic way to prove the verdicts in CI (no throttling scenario in `testbed/mockdpi`, SYN drops need a firewall), and `freeze_after_n`/`throttled` are already unreachable (`internal/classify/classify.go:62`). The plan must add an ADR-006 edit that moves Q2's B6/B7 from block B to block F with the gate updated.
- OD-3 **Embedded targets list**: the owner re-signs `targets/targets.json` + `targets/targets.signed.json` himself (private key is his, `docs/KEYS.md`) with `rev 2026-11-09.1` and `expires ≈ +28 days`. The plan records it as an owner prerequisite before the first `mayak check` release, not as an implementation todo; a TODO-style row may only document and verify it.
- OD-4 **Windows CI**: add a `windows-latest`-pinned job running `go build ./...` and `go test ./...`; `-race` stays Linux-only (ADR-006 Q10).

## Open questions

None blocking. Residual (resolved by default, recorded in Open assumptions): report-per-run mapping, Ctrl-C exit code 130, `net.resolver = unknown` for this slice.

## Approval gate

status: approved (2026-11-09, user answered "Одобряю")

Approach: finish block B of `mayak check` — B4 report mapping, B5 command/output/exit codes/Ctrl-C, B8 control node with the any-SNI listener, B9 smoke tests, B10 docs + Windows CI — with `tcp_freeze`/`throughput` explicitly moved to block F by owner decision OD-2 and the embedded-list re-sign recorded as owner prerequisite OD-3.

Next: on approval, write `.omo/plans/mayak-block-b-finish.md`, run the structural self-check, then the plan-reviewer high-accuracy review.
