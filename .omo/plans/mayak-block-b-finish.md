# mayak-block-b-finish - Work Plan

## TL;DR (For humans)
<!-- Fill this LAST, after the detailed plan below is written, so it summarizes the REAL plan. -->
<!-- Plain English for a non-engineer: NO file paths, NO todo numbers, NO wave/agent/tool names. -->

**Who this is for and what changes for them:** a person who wants to know whether a service is broken for them or for their operator. Today the program can only print its version; after this work one command measures a handful of popular services and says, in plain English, what is blocking each one.

**What you'll get:** a working local check command with a machine-readable mode, an honest exit code for scripts, safe behaviour when interrupted, a separate small server that lets the check tell a real block from a site being down, and documentation and Windows testing that finally match the code.

**Why this approach:** the check command is assembled from parts that already exist and are tested (targets list, load ceilings, per-target measurement pass); the only new pieces are the report serialisation, the command shell, and the control server. Building the command first without its control server would ship something that can never say anything but "cannot tell", which is why both land together.

**What it will NOT do:** nothing is sent anywhere; no blocking is bypassed; the slow "connection freeze" and "speed throttling" checks are deliberately left for a later stage, and no server, bot, or public page is built.

**Effort:** Medium
**Risk:** Medium - the control server is new surface, and on a real network a run still cannot conclude anything until that server is actually deployed.

**Decisions to sanity-check:** one report per run; interrupt exit code 130; the control-node address is a compile-time value that is empty until you deploy the node (every real run then honestly exits 2 with "nothing was measured"); the shipped targets list must be re-signed by you before release.

Your next move: read the plan; the high-accuracy review could not be run (no usable model for `plan-reviewer` on this machine), so the plan was self-reviewed against the same checklist and its findings are listed at the end of this file. Full execution detail follows below.

---

> TL;DR (machine): Medium/Medium. Finish block B of `mayak check`: B4 report mapping, B5 command + exit codes + Ctrl-C, B8 control node with any-SNI listener, B9 binary smoke tests, B10 docs + Windows CI; B6/B7 moved to block F by owner decision.

## Scope

### Affected user and ideal state

**Affected users.**

1. A person running `mayak check` on their own machine (Linux; Windows planned). Today they get `mayak version` and nothing else (`cmd/mayak/main.go:20`). After: one command tells them, per popular service, whether the problem is theirs or their operator's, and why.
2. A tool author or script consuming `mayak check --json`. Today: no such output. After: a stable array of `mayak.report/1` documents that passes the project's own validator.
3. The project owner operating the control node. Today: `mayak-ctrl` is a written protocol with no binary (`internal/probe/control.go:16-18`), so every real run ends `inconclusive` (ADR-006 Consequences). After: one deployable binary with the SPEC 21.1 guardrails and the any-SNI TLS listener the agent's third handshake needs.
4. Whoever reads the repo next (a contributor, an agent, or the owner after a break). Today: README, SPEC and ADR-006 contradict the tree. After: docs and CI describe what actually ships.

| Row | Statement | Reason |
| --- | --- | --- |
| IS-1 | `mayak check` runs on Linux, prints one line per target plus a summary and a plain "nothing was sent", and exits 0 for any verdicts, 1 for a run/IO failure, 2 when ctrl failed on every target (ADR-006 Q5). | This is the whole point of block B: a usable local diagnostic, and a script needs a stable exit contract. |
| IS-2 | `mayak check --json` writes only a JSON array of `mayak.report/1` documents to stdout, and each document passes `report.Validate`. | The report format is the project's public interface (SPEC 7); anything else breaks downstream tools. |
| IS-3 | Ctrl-C during a run prints what was measured so far, leaves `targets.rev` and `rotation` intact, and exits 130. | Users interrupt long runs; a truncated or corrupt state file would silently break rollback protection or rotation. |
| IS-4 | The targets list built into the binary is unexpired, so a fresh checkout can actually run `mayak check`; `make check` and `make sign-check` stay green. | The embedded list expires 2026-11-11; an expired list is refused by design (SPEC 21.2), which would make the finished command unusable on day one. |
| IS-5 | `cmd/mayak-ctrl` serves `/v1/ping`, `/v1/reach`, `/v1/fetch` exactly as SPEC 21.1 states (static paths, host allowlist from its own signed list, public addresses only, no ip/port parameters, rate limit, no client-address logs) and a TLS listener on 443 that accepts any SNI. | Without the any-SNI listener the agent's third handshake always fails and `sni_block` via the control node is unreachable (ADR-006, open gap 1). |
| IS-6 | The repo tells the truth: SPEC says Linux and Windows with macOS deferred, CI builds and tests on both, ADR-006 action items reflect the real state, README no longer claims the orchestrator is missing. | A contributor or agent reading stale docs will re-do finished work or contradict a decision. |
| IS-7 | `freeze_after_n` and `throttled` are explicitly out of block B: ADR-006 records the move to block F, and `internal/classify/classify.go:62` keeps saying the rules do not exist yet, now with a pointer to the gate change. | SPEC 21.3 lists the verdicts while ADR-006 Q2 first put them in block B; the owner decided on 2026-11-09 that they cannot be proven in this slice, so the decision must be written down instead of silently skipped. |

| Row | Difference from today | Why it matters | Closed by |
| --- | --- | --- | --- |
| GAP-1 | `cmd/mayak/main.go:20` registers only `version`; no `check` subcommand, no flags, no output, no exit codes. | There is no product yet. | 2, 3 |
| GAP-2 | No production code builds `report.Report` from `runner.Result`; `report.NewReportID` is called only from its own test (`internal/report/id_test.go`). | `--json` cannot exist, and the report format stays unused. | 1, 2 |
| GAP-3 | `runner.Run` returns `ctx.Err()` on cancel (`internal/runner/pool.go:98`) and marks unstarted targets, but nothing in `cmd/mayak` handles signals or chooses an exit code. | Ctrl-C behaviour is explicitly left to B5 (ADR-006 Q5). | 3 |
| GAP-4 | `targets/targets.signed.json` payload has `expires: 2026-11-11T00:00:00Z`, `rev 2026-10-14.1`; today is 2026-11-09. | In two days every fresh binary refuses its own built-in list. | 6 (owner re-sign is the input) |
| GAP-5 | No `cmd/mayak-ctrl` directory; `internal/probe/control.go:16-18` says the protocol "is a proposal for cmd/mayak-ctrl, which does not exist yet". | Without it every real run is `inconclusive` (exit 2). | 4, 5 |
| GAP-6 | `.github/workflows/ci.yml` has one job on `ubuntu-24.04`; no Windows build or test. ADR-006 Q10 requires both OSes in CI. | A Windows-only regression would ship unnoticed, and the ADR promise stays unverifiable. | 10 |
| GAP-7 | `internal/classify/classify.go:62` states `freeze_after_n` and `throttled` have no rules; no `tcp_freeze` or `throughput` probe exists; `testbed/mockdpi` has no throttling scenario. | Two verdicts listed in SPEC 21.3 are unreachable, and B6/B7 are unplanned. | 8 (ADR-006 gate edit; probes deferred to block F by owner decision) |
| GAP-8 | `README.md:16-31` lists the orchestrator with load ceilings as missing, though `internal/runner/pool.go` implements them; ADR-006 Action Items still show B1 unchecked although commit 79f7c07 landed it. | Readers and agents act on wrong state. | 8, 9 |
| GAP-9 | SPEC 15 (M1 row) still says "бинарники под 3 ОС"; ADR-006 Q10 decided Linux+Windows with macOS deferred and assigned the correction to B10. | Conflicting sources of truth; AGENTS.md says SPEC wins, so the wrong text wins. | 9 |

### Must have

- A `mayak check` subcommand built on the existing `internal/runner` pipeline (`Source.Load` → `Source.Pick` → `runner.Run` → `runner.Check`), never bypassing the signed-list or load-ceiling rules.
- A pure, unit-tested mapping from run results to one `mayak.report/1` document, accepted by `report.Validate`.
- Text output in English/ASCII, one line per target, a summary, and an explicit statement that nothing was sent (ADR-006 Q4).
- Exit codes 0/1/2 exactly as ADR-006 Q5 states, plus 130 on interrupt.
- `cmd/mayak-ctrl` as its own binary, standard library only (ADR-006 Q1), implementing SPEC 21.1 plus the any-SNI TLS listener.
- Binary-level smoke tests for `version`, an expired list, and a badly signed list (ADR-006 Q8).
- An ADR-006 amendment recording the B6/B7 move to block F and the interrupt exit code.
- SPEC/README corrections and a Windows CI job.

### Must NOT have (guardrails, anti-slop, scope boundaries)

- No `mayakd` server, ingest API, Postgres, aggregator, public page, Telegram bot (M2/M3).
- No `mayak run` daemon, `mayak report --dry-run`, `mayak consent *`, `mayak selfupdate`.
- No network download of the targets list (block C), no `/v1/control` fetch; the agent knows exactly one control node from a compile-time constant (ADR-006 Q1).
- No `tcp_freeze` probe, no `throughput` probe, and no classifier rules for `freeze_after_n`/`throttled` — moved to block F by owner decision.
- No `quic` probe, no `rst_ttl` (M5).
- No new third-party dependencies: standard library plus the already-approved `spf13/cobra`, `miekg/dns` (AGENTS.md).
- No change to the report schema, verdict list, targets format, or `internal/probe` semantics.
- No test hooks, env-var overrides, or test keys in production binaries (ADR-006 Q8).
- No macOS support; no deployment of the control node to a VPS (ADR-006 Q1).
- No `--host` flag, no "check all targets" mode, no `--targets` value other than `core` (ADR-006 Q3).

## Verification strategy
> Zero human intervention - all verification is agent-executed.

- Test decision: **TDD** (AGENTS.md: "Сначала тест, потом код"). Table-driven tests with `testing`; golden files in `testdata/`; `testbed/mockdpi` for network scenarios; in-process command tests through `newRootCmd()` with an injected `runner.Env` (ADR-006 Q8).
- Global gate for every todo: `make check` (gofmt list empty + `go vet ./...` + `go test ./...`) and, where the targets list is touched, `make sign-check`.
- Evidence dir: `.omo/evidence/mayak-block-b-finish/` (this run is not an ulw-loop run). Each todo appends `task-<N>-<name>.log` with the exact command and its full output.
- No real-network test may be required for a todo to pass: every network path is exercised against `testbed/mockdpi`, and the one real-network behaviour (missing control node) is simulated by the empty compile-time constant.
- Privacy gate: any todo touching a listener adds/extends a test that greps captured logs for the test client's address and fails if it appears (AGENTS.md "IP не оседает").

## Execution strategy
### Parallel execution waves

- **Wave 1 (independent)**: todo 1 (report mapping, `internal/runner`), todo 4 (control-node API, `cmd/mayak-ctrl`), todo 10 (Windows CI).
- **Wave 2**: todo 2 (the `check` command, needs 1), todo 5 (any-SNI listener, needs 4), todo 8 (ADR-006 amendment), todo 9 (SPEC/README corrections).
- **Wave 3**: todo 3 (Ctrl-C, needs 2), todo 7 (binary smoke tests, needs 2), todo 6 (expiry guard + release checklist).
- **Final wave**: F1-F4 in parallel after every todo is green.

If the executing harness cannot spawn a recommended category (no usable model for it on that machine), run the todo in the executing session itself with the same intent and the same acceptance criteria; record that substitution in the evidence log. Never weaken a criterion because a subagent was unavailable.

### Dependency matrix

| Todo | Depends on | Blocks | Can parallelize with |
| --- | --- | --- | --- |
| 1. Report mapping | - | 2, 7 | 4, 10 |
| 2. `mayak check` command | 1 | 3, 7 | 5, 8, 9 |
| 3. Ctrl-C and exit 130 | 2 | F3 | 7, 6 |
| 4. Control-node HTTP API | - | 5 | 1, 10 |
| 5. Any-SNI TLS listener | 4 | F3 | 2, 8 |
| 6. Embedded-list expiry guard | - | - | 3, 7 |
| 7. Binary smoke tests | 2 | F3 | 3, 6 |
| 8. ADR-006 amendment | - | - | 2, 5, 9 |
| 9. SPEC and README corrections | - | - | 2, 5, 8 |
| 10. Windows CI job | - | - | 1, 4 |

## Todos
> Implementation + Test = ONE todo. Never separate.

- [x] 1. Map one run to a mayak.report/1 document
  What to do: add `internal/runner/report.go` with `type ReportMeta struct { Ver, OS, Rev string; Now time.Time; IPVer int; Resolver string }` and `func BuildReport(meta ReportMeta, results []Result) (report.Report, error)`. It builds `report.Report{Schema: report.SchemaID, ReportID: report.NewReportID(), TS: meta.Now, Agent: report.Agent{Ver: meta.Ver, OS: meta.OS, Source: report.SourceCLI}, Net: report.Net{IPVer: meta.IPVer, Resolver: meta.Resolver, Country: "", Region: nil}, TargetsRev: meta.Rev}` and one `report.Result` per element of `results`. Test selection per target is a fixed table keyed on the target's verdict: `ok` → `report.TestHTTP`; `dns_tamper` and `timeout_unknown` → `report.TestDNS`; `ip_block` and `vendor_down` → `report.TestTCP`; `sni_block` and `tls_intercept` → `report.TestTLSSNI`; `http_stub` and `vendor_geoblock` → `report.TestHTTP`; `quic_block` → `report.TestQUIC`; `inconclusive` and `allowlist_mode` → `report.TestCtrl`; `freeze_after_n` and `throttled` → `report.TestTCPFreeze` and `report.TestThroughput` respectively. Provide `func OSName(goos string) string` mapping `runtime.GOOS` values to `report.OS*` constants (`linux`, `windows`, `darwin`, `android`, `ios`; anything else → `report.OSOther`). Provide `func IPVersion(results []Result) int` returning 4 or 6 from the first trusted address found by the existing `trustedAddr` helper (`internal/runner/target.go:180-189`) over the results; 4 when none is found. Evidence: `map[string]any` per target built only from scalars, at most depth 2, no strings longer than 200 runes: keys `ctrl_alive`, `anchors_alive`, `allowlist_alive` (bools), `external` (string), `dns_system`, `dns_control` (strings of the `classify.DNSStatus`), `tcp` (string), `tls_target_sni`, `tls_neutral_sni`, `tls_via_control` (strings of `classify.Handshake`), `http_result`, `http_status`, `http_size`, `http_hash` (string/int64), `ms` (int64) from `Result.Duration.Milliseconds()`. Omit a key whose value is the zero value of its type instead of inventing data. Return an error wrapping `report.ErrInvalid` if the produced document fails `report.Validate` on its re-marshalled JSON, so a mapping bug can never reach stdout.
  Must NOT do: do not add fields to `report.Report`, `report.Result`, the schema, or `internal/probe` observation types; do not import `internal/runner` from `internal/report`; do not put anything in evidence that is not a scalar; do not emit bodies, certificates, addresses, or host names. The `quic_block`, `freeze_after_n` and `throttled` branches are unreachable until M5/block F: keep them in the table (so the mapping is total over `report.Verdicts()`) and add a unit test that asserts the table has an entry for every verdict returned by `report.Verdicts()`, which is what keeps the mapping total as verdicts are added.
  Recommended task executor category: unspecified-high
  Closes: GAP-2
  Parallelization: Wave 1 | Blocked by: none | Blocks: 2, 7
  References: `internal/report/report.go:101-134` (structs and JSON tags), `internal/report/id.go:11-17` (`NewReportID`), `internal/report/validate.go:13-39,44-71,120-190` (limits, `Validate`, required keys, evidence depth), `internal/classify/classify.go:63-98` (verdict order), `internal/classify/observation.go:5-167` (observation types), `internal/runner/runner.go:104-128` (`Result`), `internal/runner/target.go:180-189` (`trustedAddr`), `docs/SPEC.md` §7 and §21.3, ADR-006 Q4.
  Acceptance criteria: `go test ./internal/runner -run 'TestBuildReport|TestOSName|TestIPVersion' -count=1` passes; a table case per verdict produces a document where `report.Validate(marshalled)` returns no error; a case with an unknown verdict string returns an error; `make check` green.
  QA scenarios: happy - build a report from a mockdpi `ok` run and a `sni_block` run, marshal it, run `report.Validate`, assert nil error and that `results[0].test` is `http` and `tls_sni` respectively. failure - feed a `Result` whose verdict is `report.Verdict("bogus")` and assert an error wrapping `report.ErrInvalid`, plus a marshalled document longer than `report.MaxReportSize` (200 fake results) is rejected. Evidence `.omo/evidence/mayak-block-b-finish/task-1-report-mapping.log`
  Commit: Y | `feat(runner): map one run to a mayak.report/1 document`

- [x] 2. Add the mayak check command
  What to do: add `cmd/mayak/check.go` and register it in `newRootCmd()` (`cmd/mayak/main.go:13-22`), switching `newRootCmd` to take a `runner.Env` argument (`newRootCmd(env runner.Env)`) exactly as `cmd/mayak-sign/main.go:26-43` injects its clock, so tests pass a mockdpi-backed `runner.Env` and production passes `productionEnv()` from `cmd/mayak/env.go`. Flags: `--limit` int (default `runner.DefaultLimit`, validated into `runner.MinLimit..runner.MaxLimit`), `--targets` string (only `core` accepted; empty means `core`), `--targets-file` string, `--json` bool. Flow: `dir := filepath.Join(os.UserConfigDir(), "mayak")`, `os.MkdirAll(dir, 0o700)`, `src := runner.Source{File: targetsFile, Dir: dir}`, `list, err := src.Load(env)`, `picked, err := src.Pick(list, limit)`, then the control-node guard, then build options explicitly: `opts := runner.DefaultOptions(); opts.Limit = limit`, and `results, runErr := runner.Run(ctx, env, opts, picked, func(ctx context.Context, t targets.Target) runner.Result { return runner.Check(ctx, env, t) })`. `productionEnv()` fills `runner.Env` with `SystemResolver: nil`, `ControlResolver: probe.DNSServer{Addr: defaultControlDNS, Transport: probe.DNSTransportUDP}`, `PublicResolvers` from two hardcoded public DoT resolvers, `Control: probe.ControlClient{BaseURL: defaultControlURL}`, `ControlTLS: defaultControlTLS`, `Anchors: []string{"https://example.com/", "https://www.iana.org/"}`, `Allowlist: nil`, `NeutralSNI: "example.net"`, `Clock: runner.SystemClock{}`, `Rand: rand.New(rand.NewPCG(seed1, seed2))` seeded from `crypto/rand` at startup, all defined as package-level constants/vars in `cmd/mayak/env.go` with a comment "compile-time deployment values; see ADR-006". `defaultControlURL` and `defaultControlTLS` are EMPTY until the owner deploys the node. When `env.Control.BaseURL` is empty the command must not touch the network: it prints `mayak check: no control node is configured in this build, so nothing can be measured. Nothing was sent.` to stderr and returns exit 2. Text output: for each result one ASCII line `<target id>  <verdict>  <one sentence meaning>`; a verdict→sentence table must cover all 14 verdicts and say plainly what to do next (nothing to do for `ok`); then a summary line with counts per verdict and `Nothing was sent.`; when ctrl failed everywhere, state that the control node was unreachable instead of only printing `inconclusive`. `--json`: marshal the array from `runner.BuildReport` (todo 1), print it to stdout with `json.Marshal` (compact) plus a trailing newline, print nothing else to stdout; errors go to stderr. Implement exit codes through a typed error (for example `type exitError struct{ code int; err error }`) handled in `main` (`cmd/mayak/main.go:36-41`): 0 when the run finished, whatever the verdicts; 1 for a flag, IO, or targets-list failure; 2 exactly when NOT ONE result has a verdict other than `inconclusive` (that is, `ctrl` failed on every target), per ADR-006 Q5, so a single `allowlist_mode` or any measured verdict keeps the code at 0.
  Must NOT do: no `--host`, no all-targets mode, no `--targets` values besides `core`, no network list download, no test key or address override reachable from the production binary (ADR-006 Q8), no localized output, do not print raw Go errors to the user (wrap them in plain-English sentences as `internal/runner/source.go:81-117` does).
  Recommended task executor category: unspecified-high
  Closes: GAP-1, GAP-2
  Parallelization: Wave 2 | Blocked by: 1 | Blocks: 3, 7
  References: `cmd/mayak/main.go:13-41`, `cmd/mayak-sign/main.go:26-43` (env injection pattern), `internal/runner/source.go:14-18,32-76,119-146`, `internal/runner/pool.go:26-36,52-102`, `internal/runner/target.go:14-26`, `internal/runner/runner.go:21-79`, `internal/probe/ctrl.go:13-70`, `internal/probe/dns.go:33-53`, `internal/probe/control.go:53-59`, `internal/probe/ctrl_test.go:22-120` (control-server test double to copy), `testbed/mockdpi/mockdpi.go:24-140`, `docs/SPEC.md` §5 and §21.1, ADR-006 Q3-Q5, Q7, Q8.
  Acceptance criteria: `go test ./cmd/mayak -run 'TestCheck' -count=1` passes, including a case per mockdpi scenario (`ok`, `sni_block`, `dns_tamper`, `http_stub`, `ip_block`, `inconclusive`) driven through `newRootCmd(env)` with the mock certificate pool and test keys. **The control-node JSON API is not part of `testbed/mockdpi`** (it supplies `ControlTLS`/`ControlHTTP`/`ControlDNS`/`ControlDoT`, not `/v1/ping|reach|fetch`), and `internal/probe`'s `fakeControl` is test-only and cannot be imported, so add `cmd/mayak/testcontrol_test.go` with an `httptest.Server` implementing the three endpoints, modeled on `internal/probe/ctrl_test.go:22-120`; every scenario test wires `env.Control.BaseURL` to it. Also cover: a case with no control URL prints the guard message, exits 2, and proves with a counter that no probe ran; `--json` output of a mock run unmarshals as `[]report.Report` and each element passes `report.Validate`; `--limit 4` and `--limit 21` exit 1; `--targets cat` exits 1; a bad/expired signed list exits 1 with a plain-English sentence; `make check` green.
  QA scenarios: happy - run the built binary with a `--targets-file` pointing at a test-signed list against mockdpi and assert the text output lines and exit code 0. failure - run with a tampered `targets.signed.json` and assert exit 1 plus a sentence naming the signature, and run with no control node configured and assert exit 2 plus the exact guard sentence and zero network calls. Evidence `.omo/evidence/mayak-block-b-finish/task-2-check-command.log`
  Commit: Y | `feat(mayak): add the check command with text and JSON output`

- [x] 3. Handle Ctrl-C during a run
  What to do: in `cmd/mayak/check.go` build the run context with `signal.NotifyContext(context.Background(), os.Interrupt)` and `defer stop()`. When `runner.Run` returns a non-nil error that is `context.Canceled`, print the results that reached a verdict (the same text renderer as todo 2), print `Interrupted. Results above were measured before you stopped. Nothing was sent.`, and exit 130. Results whose `Err` is set must be printed as `not measured` and must not be counted in the per-verdict summary. The state files are written by `Source.Load` and `Source.Pick` before any probe runs, so nothing is written on cancel; add a test asserting the `targets.rev` and `rotation` file contents are byte-identical before and after an interrupted run. `--json` on interrupt prints the array of the measured results only, with the same exit code, and nothing to stdout when no result was measured.
  Must NOT do: do not ignore the signal and let the run finish; do not delete or rewrite state files on cancel; do not print a partial JSON document (invalid JSON) under any interruption timing.
  Recommended task executor category: unspecified-high
  Closes: GAP-3
  Parallelization: Wave 3 | Blocked by: 2 | Blocks: F3
  References: `internal/runner/pool.go:52-102` (cancel semantics, unstarted results), `internal/runner/source.go:43-76,119-146` (state written before probes), ADR-006 Q5 (interrupt code assigned to B5), `cmd/mayak/main.go:36-41`.
  Acceptance criteria: `go test ./cmd/mayak -run 'TestCheckInterrupt' -count=1` passes: a run against a mockdpi scenario that never answers is cancelled after the first result via a controllable `runner.Clock`, output contains the measured line and the interrupt sentence, the returned exit code is 130, and the rev/rotation files are unchanged; `make check` green.
  QA scenarios: happy - start the built binary against a slow mock server, send `os.Interrupt` after the first target, assert exit 130 and that stdout is either valid JSON or the partial text report. failure - interrupt before any target starts, assert exit 130 and `Nothing was sent.` with no result lines. Evidence `.omo/evidence/mayak-block-b-finish/task-3-interrupt.log`
  Commit: Y | `feat(mayak): stop cleanly on interrupt with exit code 130`

- [x] 4. Implement the control-node HTTP API
  What to do: add `cmd/mayak-ctrl/main.go` (standard library only, `flag` for flags, no cobra) serving `GET /v1/ping` → 200, `GET /v1/reach?host=<host>` → `{"reachable": bool}` by a TCP connect to the host on port 443 from the node, and `GET /v1/fetch?host=<host>&path=<path>` → `{"status":int,"size":int,"body_hash":"<hex sha-256>"}` by making the same request the http probe makes (HTTPS, SNI = host, no redirects, body read up to `probe.MaxBody`, decompressed as the Go client decodes it). Requirements: the served host must be in the node's own copy of the signed list, loaded with `--targets <file>` through `targets.Open(targets.PublicKeys(), data)`, compared case-insensitively against `items[].host`; `path` must be `probe.ControlPathRoot` or `probe.ControlPathRobots`; any other query key than `host`/`path` (notably `ip`, `port`) is refused with 400 and the response must not echo the value; every dial resolves the name and refuses if any candidate address is not public, re-checking the address actually dialed by using a `net.Dialer.Control` hook; per-remote-address token bucket in memory (default 20 requests/minute) with a bounded map that is never logged; response bodies capped at `probe.MaxBody`; `ReadHeaderTimeout`, `ReadTimeout`, `WriteTimeout` set; no client address in any log line or error text; `--addr` flag for the listen address (default `:8443`). Export the address predicate: rename `classify.isBogon` (`internal/classify/classify.go:214-226`) to the exported `IsBogon` with a doc comment and update its callers, so the node and the classifier cannot drift.
  Must NOT do: do not add `/v1/targets`, `/v1/control`, or any endpoint beyond the three SPEC 21.1 lists; no third-party router; no client address in logs, metrics, or error strings; do not fetch arbitrary paths; do not follow redirects; do not accept `ip`/`port`; do not serve hosts outside the signed list.
  Recommended task executor category: unspecified-high
  Closes: GAP-5
  Parallelization: Wave 1 | Blocked by: none | Blocks: 5
  References: `internal/probe/control.go:16-113` (the client contract and node requirements), `internal/probe/http.go:24,66-141` (request shape, `MaxBody`, body hash), `internal/targets/targets.go:60-100,138-146`, `internal/targets/revstore.go:31-57` (`Accept`), `internal/targets/revstore.go:59-105` (`FileRevStore`), `internal/classify/classify.go:190-226` (`isBogon`), `docs/SPEC.md` §21.1 and §12, AGENTS.md privacy rules.
  Acceptance criteria: `go test ./cmd/mayak-ctrl -count=1` passes with httptest cases for: ping 200; reach on a mockdpi listener returns `reachable: true`; reach on a closed port returns `false` with 200 (the node's answer, not an error); fetch returns a hash equal to the one `probe.HTTP` computes for the same mockdpi server; a host absent from the target list gives 400; `?ip=10.0.0.1` gives 400; `path=/etc/passwd` gives 400; a host whose resolver answer is `10.0.0.1` is refused; 21 rapid requests give at least one 429; a captured log buffer contains no occurrence of the test client address. `make check` green.
  QA scenarios: happy - start the binary against a local test server, `curl` all three endpoints, and compare the fetch hash with `sha256sum` of the fetched body. failure - `curl 'http://host/v1/fetch?host=example.com&port=22'` returns 400 and the log file contains neither the client address nor the rejected value. Evidence `.omo/evidence/mayak-block-b-finish/task-4-control-api.log`
  Commit: Y | `feat(mayak-ctrl): serve ping, reach and fetch per SPEC 21.1`

- [x] 5. Add the any-SNI TLS listener to the control node
  What to do: in `cmd/mayak-ctrl/main.go` start a second listener on `--tls-addr` (default `:443`) whose `tls.Config` completes a TLS 1.2/1.3 handshake with ANY client-supplied SNI, using `GetCertificate` that returns the configured certificate for every `ClientHelloInfo`. Flags `--tls-cert` and `--tls-key` load a PEM pair; when both are absent the node generates an ephemeral self-signed certificate at startup (stdlib `crypto/ecdsa` + `crypto/x509`) and writes only its SHA-256 fingerprint to stderr. After the handshake the connection is closed immediately; no HTTP is served on this port. Document in the file header that the agent's third `tls_sni` handshake only needs the handshake to complete and treats `cert_invalid` as completed (ADR-006 B3).
  Must NOT do: do not terminate HTTP on the any-SNI port; do not log SNI values or client addresses; do not depend on a certificate that is valid for any particular name; do not add a second port when `--tls-addr` is empty (then the listener is disabled and the node logs one line saying so).
  Recommended task executor category: unspecified-high
  Closes: GAP-5, IS-5
  Parallelization: Wave 2 | Blocked by: 4 | Blocks: F3
  References: `internal/probe/tls.go:43-70,97-137,155-207` (three handshakes, `ControlAddr`, cert handling), `docs/SPEC.md` §4 and §21.1, `docs/adr/ADR-006-agent-check.md:104-108` (open gap 1 and 2), `testbed/mockdpi/mockdpi.go:79` (`ControlTLS` accepts any SNI).
  Acceptance criteria: `go test ./cmd/mayak-ctrl -run 'TestAnySNI' -count=1` passes: a client dialing the listener with `ServerName: "target.example"` and `InsecureSkipVerify: true` completes the handshake; the same listener with a generated certificate works with no flags; `--tls-addr ""` disables it; the log buffer contains no SNI and no client address. A separate test proves the agent's `probe.TLSSNI` against this listener yields `TargetSNIViaControl: ok`; build the `TLSSNIRequest` against mockdpi's `env.ControlTLS` replaced by this listener's address and mockdpi's `CertPool` as `RootCAs` (see `testbed/mockdpi/mockdpi_test.go:480-500` for the handshake-with-any-SNI pattern).
  QA scenarios: happy - start the node, run `openssl s_client -connect 127.0.0.1:443 -servername target.example` and assert a completed handshake. failure - connect with a plain HTTP request to the same port and assert the connection is closed without an HTTP response and no address is logged. Evidence `.omo/evidence/mayak-block-b-finish/task-5-any-sni.log`
  Commit: Y | `feat(mayak-ctrl): accept TLS with any SNI for the agent's third handshake`

- [x] 6. Guard the embedded targets list expiry
  What to do: add a `make targets-expiry` target that fails when the embedded list in `targets/targets.signed.json` expires within 7 days or is already expired, implemented as a Go test `TestEmbeddedListFreshness` in `targets/embed_test.go` (skip-able with `-short`? no: never skip) called from the Makefile with `go test -count=1 -run '^TestEmbeddedListFreshness$' ./targets`. Add the target to the release checklist section of `docs/KEYS.md` and to `.github/workflows/ci.yml` as a separate non-blocking `continue-on-error: true` step so a near-expiry warning never blocks an unrelated PR. Record the owner procedure in `docs/KEYS.md`: bump `targets/targets.json` `rev` to `<today>.<N>` and `expires` to about +28 days, then `go run ./cmd/mayak-sign sign --key <key> --in targets/targets.json --out targets/targets.signed.json`, then `make sign-check`.
  Must NOT do: do not sign anything yourself; do not commit a private key; do not make `make check` fail on expiry (it would block every unrelated change); do not change the 30-day format rule.
  Recommended task executor category: unspecified-low
  Closes: GAP-4
  Parallelization: Wave 3 | Blocked by: none | Blocks: none
  References: `targets/embed.go:7-13`, `targets/targets.signed.json` (payload `rev 2026-10-14.1`, `expires 2026-11-11T00:00:00Z`), `internal/targets/revstore.go:31-57`, `docs/KEYS.md` (signing procedure, `make sign-check` does not check expiry), `Makefile:1-27`, `.github/workflows/ci.yml:6-33`, ADR-006 Q7.
  Acceptance criteria: `make targets-expiry` fails today (the list expires in 2 days) with a message naming the date and the re-sign command; after the owner re-signs, the same target passes and `make sign-check` passes; `make check` stays green before and after. The CI step is present and marked `continue-on-error: true`.
  QA scenarios: happy - run `go test ./targets -run TestEmbeddedListFreshness -count=1` against a copy of the repo where `expires` is +28 days and assert PASS. failure - run it against the current list and assert FAIL with the expiry date in the output. Evidence `.omo/evidence/mayak-block-b-finish/task-6-expiry-guard.log`
  Commit: Y | `build(targets): fail when the embedded list is about to expire`

- [x] 7. Add binary smoke tests
  What to do: add `cmd/mayak/smoke_test.go` that builds the real binary once into `t.TempDir()` with `exec.Command("go", "build", "-o", filepath.Join(dir, "mayak"), "./cmd/mayak")` and then: `mayak version` prints `dev` and exits 0; `mayak check --targets-file <expired signed list>` exits 1 and stderr names expiry and gives a next step; `mayak check --targets-file <list signed by another key>` exits 1 and stderr says the list is not signed by a trusted key; `mayak check --limit 3` exits 1. Build the three lists in the test with `internal/targets` signing helpers — read `cmd/mayak-sign/main_test.go:1-200` for how a test key pair and a signed payload are produced, and reuse `internal/targets/sign.go` (`Sign`/`Verify`/`Open`) rather than shelling out to `mayak-sign`. Skip the whole file when `exec.LookPath("go")` fails.
  Must NOT do: do not ship a test key or a testing flag in the production binary; do not require network or root; do not assert on localized text; do not build into the repository tree.
  Recommended task executor category: unspecified-low
  Closes: GAP-1, GAP-3
  Parallelization: Wave 3 | Blocked by: 2 | Blocks: F3
  References: ADR-006 Q8 ("Собранный бинарник проверяется только дымовым тестом: `version`, отказ на истёкшем и на неверно подписанном списке"), `cmd/mayak-sign/main_test.go:180-215` (signing helper pattern), `internal/targets/sign.go:1-60`, `cmd/mayak/main.go:36-41`.
  Acceptance criteria: `go test ./cmd/mayak -run 'TestSmoke' -count=1` passes and each of the four sub-cases asserts both the exit code and one plain-English phrase; `make check` green; the test leaves no files outside `t.TempDir()`.
  QA scenarios: happy - all four sub-cases pass on a clean checkout. failure - temporarily rename the embedded list expectation so `version` prints something else and assert the test fails with a clear message (run manually once, do not commit the mutation). Evidence `.omo/evidence/mayak-block-b-finish/task-7-smoke.log`
  Commit: Y | `test(mayak): smoke-test the built binary`

- [x] 8. Amend ADR-006 to match the decisions
  What to do: edit `docs/adr/ADR-006-agent-check.md`: mark Action Items B1 done (commit 79f7c07), B3 done, add B4/B5/B8/B9/B10 as done with the commit that implements each; change Q2 and the "Обновлённый план" notes so `tcp_freeze`/`throughput` live in **block F**, with a dated line "решение владельца 2026-11-09: перенесено в блок F, причина — вердикты `freeze_after_n`/`throttled` нечем проверить детерминированно (в `testbed/mockdpi` нет сценария троттлинга, дроп SYN без firewall не эмулируется)"; record the interrupt exit code 130 in Q5; record that the control node address and the any-SNI listener address are compile-time values in `cmd/mayak/env.go`, empty until deployment, and that an empty value makes `mayak check` exit 2 without touching the network; record that the allowlist URLs are not configured in block B, so `allowlist_mode` is unreachable until the owner supplies them; update the Consequences section so it no longer says only B1-B10 exist.
  Must NOT do: do not change Q1-Q10 decisions themselves beyond the B6/B7 gate move and the recorded values; do not rewrite the ADR in English; do not touch SPEC section numbering.
  Recommended task executor category: unspecified-low
  Closes: GAP-7, GAP-8
  Parallelization: Wave 2 | Blocked by: none | Blocks: none
  References: `docs/adr/ADR-006-agent-check.md:1-135` (especially :17-23 Q1/Q2, :37-48 Q4/Q5, :79 Q10, :104-135 open gaps and Action Items), owner decisions recorded in `.omo/drafts/mayak-block-b-finish.md`.
  Acceptance criteria: `grep -c 'TCPFreeze\|tcp_freeze' docs/adr/ADR-006-agent-check.md` shows the block-F line, `grep '130' docs/adr/ADR-006-agent-check.md` shows the interrupt code, no Action Item for a landed step remains unchecked, and `make check` is unaffected (docs only).
  QA scenarios: happy - read the amended ADR and check every rendered item against `git log --oneline` for the implementing commit. failure - an unchecked item whose commit exists is a failure of this todo. Evidence `.omo/evidence/mayak-block-b-finish/task-8-adr.log`
  Commit: Y | `docs(adr): record block B's remaining steps and the block F gate move`

- [x] 9. Correct SPEC and README to match the tree
  What to do: in `docs/SPEC.md` change the M1 row of §15 so the readiness criterion reads "Linux и Windows; macOS отложен" instead of "бинарники под 3 ОС"; do not renumber sections or add a new section. In `README.md` move the implemented pieces from "Ещё нет" to "Есть" (`mayak check` with output and `--json`, the load ceilings in `internal/runner`, the control node `cmd/mayak-ctrl`, Windows CI) and rewrite the remaining "Ещё нет" items to what is actually absent (`mayakd`, the web probe, consent, `quic`/`tcp_freeze`/`throughput`, signed releases, a deployed control node, Privacy Pass). Add one sentence to "Чего проект не делает" or the status block: `mayak check` never sends anything and needs a configured control node to give a confident verdict.
  Must NOT do: do not claim any feature that does not exist; do not translate the README into English; do not touch `docs/adr/` from this todo; do not edit `docs/SPEC.md` sections other than the M1 row wording.
  Recommended task executor category: unspecified-low
  Closes: GAP-8, GAP-9
  Parallelization: Wave 2 | Blocked by: none | Blocks: none
  References: `docs/SPEC.md` §15 M1 row, `README.md:1-40` (status block), `docs/adr/ADR-006-agent-check.md:79` (Q10 wording decision), `AGENTS.md:9-13` (source-of-truth order).
  Acceptance criteria: `grep -n '3 ОС\|3 OS' docs/SPEC.md` returns nothing; `grep -n 'mayak check' README.md` lists it under "Есть"; every claim added is backed by a file that exists (`cmd/mayak-ctrl`, `internal/runner/pool.go`); `make check` unaffected.
  QA scenarios: happy - walk each README bullet and run `ls`/`grep` on the cited path; every bullet resolves. failure - a bullet naming a missing path fails this todo. Evidence `.omo/evidence/mayak-block-b-finish/task-9-docs.log`
  Commit: Y | `docs: bring SPEC and README in line with the code`

- [x] 10. Add the Windows CI job
  What to do: add a second job `windows` to `.github/workflows/ci.yml` with `runs-on: windows-2025`, steps: pinned `actions/checkout` (same SHA as the existing job), pinned `actions/setup-go` with `go-version-file: go.mod`, `go build ./...`, `go test ./...`; no `-race` (ADR-006 Q10), no `make` (not guaranteed on the runner image unless proven). Keep the existing Ubuntu job unchanged, including `make check`, `make sign-check`, `-race` and `govulncheck`. Do not use `windows-latest`: as of 2026 it is migrating labels, so pin `windows-2025` like the existing Ubuntu job pins `ubuntu-24.04`.
  Must NOT do: do not remove or reorder the Ubuntu checks; do not add `-race` on Windows; do not add new action versions beyond the already pinned SHAs; do not gate `make check` on the Windows job.
  Recommended task executor category: unspecified-low
  Closes: GAP-6
  Parallelization: Wave 1 | Blocked by: none | Blocks: none
  References: `.github/workflows/ci.yml:1-33`, `docs/adr/ADR-006-agent-check.md:79` (Q10), `go.mod` (Go 1.26.10).
  Acceptance criteria: the workflow parses (`python3 -c "import yaml,sys;yaml.safe_load(open('.github/workflows/ci.yml'))"` or `bun -e` with a YAML parse), the job names are `check`, `windows`, `release-check`, and a local dry run of the same commands succeeds on Linux (`go build ./... && go test ./...`).
  QA scenarios: happy - push to a branch and confirm the `windows` job runs green (the executor records the run URL in evidence); failure - a deliberately broken build on Windows-only code (`//go:build windows` file with a syntax error) turns the job red. Evidence `.omo/evidence/mayak-block-b-finish/task-10-windows-ci.log`
  Commit: Y | `ci: build and test on Windows`

- [x] 11. Keep the expiry guard out of the default test run
  What to do: the freshness test added by todo 6 makes `go test ./...` fail whenever the embedded list is within 7 days of expiry, which breaks `make check` (the project's gate) for every unrelated change. Change `TestEmbeddedListFreshness` in `targets/embed_test.go` so it calls `t.Skip` unless the environment variable `MAYAK_TARGETS_EXPIRY_GUARD` is `1`, and make the `targets-expiry` Makefile target export that variable (e.g. `MAYAK_TARGETS_EXPIRY_GUARD=1 go test -count=1 -run '^TestEmbeddedListFreshness$' ./targets`). Keep `freshEnough` and its table cases (`TestFreshEnough`) running unconditionally — they are fast and deterministic. The CI step keeps `continue-on-error: true`.
  Must NOT do: do not weaken the 7-day threshold; do not add the target to `check`; do not delete `TestFreshEnough`.
  Recommended task executor category: unspecified-low
  Closes: GAP-4 (gate integrity)
  Parallelization: Wave 3 | Blocked by: 6 | Blocks: none
  References: `targets/embed_test.go` (the test added by todo 6), `Makefile` `targets-expiry` target, `.github/workflows/ci.yml` (check job), `Makefile:1-27` (`check: fmt vet test`).
  Acceptance criteria: `go test ./... -count=1` is green today even though the embedded list expires in 2 days; `MAYAK_TARGETS_EXPIRY_GUARD=1 go test -run '^TestEmbeddedListFreshness$' ./targets` fails today with the expiry date; `make targets-expiry` fails today; `make check` is green.
  QA scenarios: happy - `go test ./...` green and `make targets-expiry` red today, both proven by pasted output. failure - unset the variable and confirm the freshness test reports SKIP, not PASS. Evidence `.omo/evidence/mayak-block-b-finish/task-11-expiry-skip.log`
  Commit: Y | `test(targets): run the expiry guard only on demand`

- [x] 12. Prove Ctrl-C through an OS-level signal
  What to do: add a subprocess integration test in `cmd/mayak/check_interrupt_test.go` (Linux/macOS only; skip on Windows if `os.Interrupt` is unsupported) that starts the test binary as a child in helper mode, constructs a mockdpi-backed `runner.Env`, begins `newRootCmd(env).Execute()`, waits until the first target is measured and the second target is blocked in the runner pause, then the parent sends `child.Process.Signal(os.Interrupt)`. Assert the child exits with code 130, stdout is either valid partial JSON or text with the measured line plus the interrupt sentence, and `targets.rev`/`rotation` bytes are unchanged. Keep the existing deterministic context-cancel test; this todo specifically closes the missing real-signal QA artifact.
  Must NOT do: no production hooks or env-based address overrides; the helper mode is only in the `_test.go` binary and is guarded by an explicit test-only environment variable. Do not make the test flaky; coordinate through a pipe/file marker, not a sleep.
  Recommended task executor category: unspecified-high
  Closes: IS-3 / GAP-3 evidence gap
  Parallelization: Wave 3 | Blocked by: 3 | Blocks: F3
  References: `cmd/mayak/check.go` signal.NotifyContext path, `cmd/mayak/check_interrupt_test.go` existing cancellation test, `internal/runner/pool.go:52-102`, ADR-006 Q5.
  Acceptance criteria: `go test ./cmd/mayak -run TestCheckInterruptSignal -count=1 -v` passes on Linux; test fails if the signal handler is removed or the exit code is not 130; state files are unchanged; Windows runs still pass all `cmd/mayak` tests (the signal-specific case skips only if the OS reports unsupported).
  QA scenarios: happy - run the signal test and capture child stdout/stderr/exit code 130. failure - temporarily run the child without installing signal.NotifyContext and prove the parent observes termination by interrupt rather than a misleading exit 0; restore the test fixture. Evidence `.omo/evidence/mayak-block-b-finish/task-12-sigint.log`
  Commit: Y | `test(mayak): prove Ctrl-C via process signal`

- [x] 13. Complete CLI production wiring and safe state publication
  What to do: address the independent F1/F2 findings in `cmd/mayak`: populate `PublicResolvers` with two DoT endpoints (Cloudflare `1.1.1.1:853` / `cloudflare-dns.com` and Google `8.8.8.8:853` / `dns.google`); add the compile-time `defaultControlDNS` for the separate DNS resolver selected by the owner; and before any request, require the control URL, control TLS address, control resolver and both public resolvers to be valid, otherwise print the existing no-control/not-measurable message and exit 2 without network. Propagate stdout write errors from text/JSON renderers as exit 1. On Ctrl-C, print one `not measured` line for each Result with `Err != nil`, exclude those rows from verdict counts, and retain measured rows. Isolate every in-process/subprocess test's config directory on Windows by setting `APPDATA` as well as `XDG_CONFIG_HOME` to a unique `t.TempDir()`. Expand the command-level mockdpi table to cover `sni_block`, `dns_tamper`, `http_stub` and `ip_block`, each with its own valid fake control API. Prevent concurrent `mayak check` invocations from overwriting staged `targets.rev`/`rotation`: acquire an exclusive lock in the mayak config directory before loading/picking/staging state; if a lock already exists, fail closed with exit 1 and an actionable message; release it on all normal returns and interrupts. A stale lock after a process crash may be removed manually only when no `mayak check` is running; document the lock file and recovery sentence in ADR-006 Q6.
  Must NOT do: no new dependency, no change to report schema, no new production test hooks or address override flags, no silent reset of rev/rotation, and never include raw error/host/IP data in reports or logs.
  Recommended task executor category: unspecified-high
  Closes: F1-T2-ENV, F1-T2-SCENARIOS, F1-T3-UNMEASURED-TEXT, F2-01, F2-03, F2-06
  Parallelization: Wave 4 | Blocked by: 2, 3 | Blocks: F1, F3, F4
  References: `cmd/mayak/env.go:19-63`, `cmd/mayak/check.go:64-249`, `cmd/mayak/check_test.go`, `cmd/mayak/check_interrupt_test.go`, `internal/probe/dns.go:83-131`, `internal/runner/source.go`, `internal/targets/revstore.go:31-57,101-111`, ADR-006 Q5-Q8.
  Acceptance criteria: command tests cover the four omitted mockdpi verdict scenarios; text/JSON writer failures exit 1; interrupted text prints measured and `not measured` rows; Windows tests use `APPDATA`/XDG temp dirs and leave them clean; a deterministic two-process regression shows an overlapping second command exits 1 without changing the first command's accepted rev/rotation; missing control DNS config exits 2 before any network; `go test ./cmd/mayak -count=2`, `go vet ./cmd/mayak`, `make check` pass.
  QA scenarios: happy - exercise all four CLI mockdpi scenarios and a full-state command with the selected resolver values; failure - force a writer error, run with an incomplete resolver config, interrupt before target 2, and race two commands on the same state dir. Evidence `.omo/evidence/mayak-block-b-finish/task-13-cli-hardening.log`
  Commit: Y | `fix(mayak): complete production resolver and state safety contracts`

- [x] 14. Preserve the classifier stage in report results
  What to do: fix F2-07 in `internal/classify` and `internal/runner/report.go`. Verdict alone does not uniquely identify the test: `timeout_unknown` can come from DNS, TLS or HTTP; `vendor_down` and `inconclusive` can also be decided at multiple stages. Add a pure `classify.ClassifyWithTest(Observation) (report.Verdict, report.Test)` that follows the existing Classify rule order and returns the actual deciding stage. Keep `classify.Classify` as a compatibility wrapper returning only the verdict. Have `runner.Check` store the returned test in `Result` and have `BuildReport` use that field; remove the verdict-only test mapping except as a rejecting check when the deciding stage is empty.
  Must NOT do: no JSON schema/report field changes, no changes to classifier verdict precedence, no duplicated second classifier, and no tests that mirror the mapping table without constructing realistic observations.
  Recommended task executor category: deep-low
  Closes: F2-07
  Parallelization: Wave 4 | Blocked by: 1 | Blocks: F2, F4
  References: `internal/classify/classify.go:72-98,228-304`, `internal/classify/observation.go`, `internal/runner/runner.go:104-128`, `internal/runner/target.go:33-164`, `internal/runner/report.go`, SPEC §7 and §21.3.
  Acceptance criteria: table-driven tests build realistic observations for DNS-system failure, TLS timeout, HTTP timeout, transport `vendor_down`, and ctrl/DNS inconclusive; each emitted report `test` identifies the layer that actually decided that verdict, and `report.Validate` accepts the document; `go test ./internal/classify ./internal/runner -count=2`, `go vet ./internal/classify ./internal/runner`, `make check` pass.
  QA scenarios: happy - successful DNS/TCP/TLS followed by HTTP timeout returns `timeout_unknown` with `test=http`; failure - the same verdict produced by a target-SNI timeout reports `test=tls_sni`, not DNS. Evidence `.omo/evidence/mayak-block-b-finish/task-14-report-provenance.log`
  Commit: Y | `fix(report): preserve the classifier's deciding test`

- [x] 15. Harden control-node trust and integration tests
  What to do: address F1-T4/F1-T5 and F2-04/F2-05/F2-08 in `cmd/mayak-ctrl`. Load the signed targets list with `targets.Accept` and a persistent `FileRevStore` under a dedicated `--state-dir` (default `os.UserConfigDir()/mayak-ctrl`) so restarts reject rollback. Check expiry at request authorization time using an injected clock, so a node that passes `Expires` stops authorizing target hosts while `/v1/ping` remains available. Replace the status-only privacy test with a real test that sends a distinctive client IP, captures every logger sink, searches logs/errors/state for that literal, and fails if found. Add a `probe.TLSSNI` integration test against the delivered any-SNI listener with a trusted test certificate pool, proving `TargetSNIViaControl` completes for target SNI. Split `main.go` into responsibility-named files within package `main` (configuration/list loading, handlers/dialing/rate limit, TLS listener/startup) without changing the API or introducing a dependency; keep each production file below 250 nonblank, non-comment lines.
  Must NOT do: no new API endpoint, no client IP persistence/logging, no new dependency, no rollback acceptance after a newer rev was recorded, no authorization after expiry, and no changes to the HTTP JSON shapes.
  Recommended task executor category: deep-low
  Closes: F1-T4-PRIVACY-TEST, F1-T5-AGENT-INTEGRATION, F2-04, F2-05, F2-08
  Parallelization: Wave 4 | Blocked by: 4, 5 | Blocks: F1, F2, F3, F4
  References: `cmd/mayak-ctrl/main.go`, `cmd/mayak-ctrl/main_test.go`, `cmd/mayak-ctrl/security_test.go`, `internal/probe/control.go`, `internal/probe/tls.go:43-70,97-137,155-207`, `internal/targets/revstore.go:31-57,101-111`, SPEC §21.1-21.2, ADR-006 Q1.
  Acceptance criteria: tests prove rollback refusal after restart, runtime expiry refusal, privacy logs contain no test client IP, and `probe.TLSSNI` against the live listener completes the target-SNI-via-control handshake; all API/rate/bogon/body-cap tests still pass; each `cmd/mayak-ctrl/*.go` production file meets the 250-line limit; `go test ./cmd/mayak-ctrl -count=2`, `go vet ./cmd/mayak-ctrl`, `make check` pass.
  QA scenarios: happy - restart node with lower rev and observe refusal, advance fake clock past expiry and observe no dial, run the agent's TLS probe, and grep captured logs for the client address. failure - prove the test suite fails if the privacy logger is deliberately made to include that address (run only in a disposable copy). Evidence `.omo/evidence/mayak-block-b-finish/task-15-control-hardening.log`
  Commit: Y | `fix(mayak-ctrl): enforce target lifecycle and privacy invariants`

- [~] 16. Set the control-node request budget
  Gap: the owner-directed best-judgment choice of 120 req/min is recorded, but this commit request did not add the rate-limit change or its acceptance tests. The committed control node remains at 20 requests/minute, below the supported 20-target run's maximum 60 control calls.
  What to do: the owner directed us to continue using best judgment after the decision question timed out, so apply the plan's recommended 120 requests/minute per-prefix budget with a bounded burst. The current 20 requests/minute cap is too low: the supported 20-target run can use up to 60 API requests (ping/reach/fetch per target) inside one minute. Test that all 60 requests from one supported run pass and the 121st is rejected. Keep buckets keyed by the privacy-preserving client prefix (/24 IPv4, /56 IPv6), not the full address, and never log the key. Record that 120/minute was selected under the owner's best-judgment direction in ADR-006 Q1/Q2 or Consequences.
  Must NOT do: do not lower supported target count; do not key on or log full client IP; do not add a third-party rate-limit dependency.
  Recommended task executor category: unspecified-low
  Closes: F2-02
  Parallelization: Wave 4 | Blocked by: none (not implemented in the commit-all follow-up) | Blocks: F1, F2, F3
  References: `cmd/mayak-ctrl/main.go` limiter, `internal/probe/ctrl.go:91-109`, `internal/runner/runner.go:21-30` (20 targets and pacing), final review artifact `.omo/evidence/mayak-block-b-finish/F2-final.md`.
  Acceptance criteria: the 120/minute budget admits the maximum 60 control API requests for a 20-target run and rejects the 121st request; test bucket key is the /24 or /56 prefix and no address appears in logs.
  QA scenarios: happy - run a maximum-demand synthetic check and show all control API requests admitted. failure - one request over the selected budget receives 429; malformed/unknown hosts remain rejected before the limiter creates unbounded state. Evidence `.omo/evidence/mayak-block-b-finish/task-16-rate-budget.log`
  Commit: Y | `fix(mayak-ctrl): size rate limit for a supported check run`

## Final verification wave
> Runs in parallel after ALL todos. ALL must APPROVE. Surface results and wait for the user's explicit okay before declaring complete.

- [~] F1. Plan compliance audit
  Gap: task 16's 120/minute budget and acceptance tests are absent; there is no native Windows run receipt under direct/no-push delivery; the signed targets payload expires 2026-11-11T00:00:00Z pending owner re-sign and post-sign check.
- [x] F2. Code quality review
- [x] F3. Real manual QA
- [~] F4. Ideal-state fidelity
  Gap: the committed integration branch lacks task 16's supported-run rate budget; the Windows job is configured but no native run exists under direct/no-push delivery, and the signed target list expires 2026-11-11T00:00:00Z pending owner re-signing.

## Commit strategy

Delivery mode is direct: create local typed commits on `block-b-wave1`, do not open a PR or push. The verified units are grouped only where their edits share files or one executor implemented them as a single coherent unit:

1. `feat(runner): map one run to a mayak.report/1 document` — todo 1.
2. `feat(mayak): add the check command with text and JSON output` — todo 2.
3. `feat(mayak): stop cleanly on interrupt with exit code 130` — todos 3 and 12 (same test file and signal path).
4. `feat(mayak-ctrl): serve and validate the control-node API` — todos 4 and 5 (same binary and TLS listener).
5. `build(targets): guard embedded list expiry` — todos 6 and 11 (same freshness test/Makefile target).
6. `test(mayak): smoke-test the built binary` — todo 7.
7. `docs(adr): record block B decisions and block F gate` — todo 8.
8. `docs: bring SPEC and README in line with the code` — todo 9.
9. `ci: build and test on Windows` — todo 10 (including the expiry warning step in the same workflow file).
10. `fix(mayak): complete production resolver and state safety contracts` — todo 13.
11. `fix(report): preserve the classifier's deciding test` — todo 14.
12. `fix(mayak-ctrl): enforce target lifecycle and privacy invariants` — todo 15, commit `21337d8`.
13. `chore: commit Mayak block B execution evidence` — task-owned `.omo/` plan, ledger, Boulder state, and evidence, separately from product code. This grouping follows the owner's later “commit all changes” instruction; exclude the unrelated prior `block-b-1-code-review.md`.

Stage only the listed product files for each product commit. Stage reviewed task-owned `.omo/` files in their separate evidence commit, preserving unrelated local state outside the commit. Do not include the owner's targets re-signing: it is an external prerequisite and the private key remains outside the repository.

## Success criteria
> One row per IS row. The plan is complete only when every IS row has a delivering todo and a proving QA scenario; F4 checks the delivered behavior against these rows 1:1, and a shortfall becomes new `- [ ] N.` rows, never a note.

| IS | Delivering todo(s) | Proving QA scenario | Evidence |
| --- | --- | --- | --- |
| IS-1 | 2, 13 | text-output run against mockdpi with exit 0, 1 and 2 cases; production guard refuses incomplete resolvers before networking | `.omo/evidence/mayak-block-b-finish/task-2-check-command.log`, `task-13-cli-hardening.log` |
| IS-2 | 1, 2 | `--json` output validated by `report.Validate` | `.omo/evidence/mayak-block-b-finish/task-2-check-command.log` |
| IS-3 | 3 | interrupted run keeps state files and exits 130 | `.omo/evidence/mayak-block-b-finish/task-3-interrupt.log` |
| IS-4 | 6 | `make targets-expiry` and `make sign-check` after the owner re-sign | `.omo/evidence/mayak-block-b-finish/task-6-expiry-guard.log` |
| IS-5 | 4, 5, 15, 16 | `curl` of the three endpoints plus any-SNI probe, rollback/expiry/privacy checks, and the 20-target request budget | `.omo/evidence/mayak-block-b-finish/task-4-control-api.log`, `task-5-any-sni.log`, `task-15-control-hardening.log`, `task-16-rate-budget.log` |
| IS-6 | 8, 9, 10 | docs walkthrough against real paths, Windows job green | `task-8-adr.log`, `task-9-docs.log`, `task-10-windows-ci.log` |
| IS-7 | 8 | amended ADR shows the block F gate move and the unchanged classify comment | `.omo/evidence/mayak-block-b-finish/task-8-adr.log` |

## Review record

- Round 1, 2026-11-09: `plan-reviewer` and `omo-native-gate-reviewer` could not be spawned — no usable model for either on this machine (only the `custom-routerai` provider is connected, and every builtin category chain excludes it). The plan was therefore self-reviewed against the same checklist, and the findings were fixed in the same round:
  1. **BLOCKER (fixed)** — todo 2's acceptance criterion assumed `testbed/mockdpi` serves the control-node JSON API. It does not: it provides `ControlTLS`/`ControlHTTP`/`ControlDNS`/`ControlDoT` only, and `internal/probe`'s `fakeControl` is unexported test code. The plan now requires a `cmd/mayak/testcontrol_test.go` double modeled on `internal/probe/ctrl_test.go:22-120`.
  2. **BLOCKER (fixed)** — the exit-code sentence for 2 was self-contradictory (`every result is inconclusive or allowlist_mode never fired`). Replaced with the single testable rule: code 2 exactly when no result has a verdict other than `inconclusive`.
  3. **NOTE (fixed)** — todo 2's `runner.Run` call was described in prose (`with Limit set`); replaced with the explicit `opts := runner.DefaultOptions(); opts.Limit = limit` sequence.
  4. **NOTE (fixed)** — the verdict→test table was total but untested for totality; todo 1 now requires a test asserting an entry for every `report.Verdicts()` value, which keeps the M5/block-F verdicts (`quic_block`, `freeze_after_n`, `throttled`) mapped without making them reachable.
  5. **NOTE (fixed)** — `windows-latest` migrates labels in 2026; the plan pins `windows-2025`, matching the repo's existing pinning of `ubuntu-24.04`.
  6. **NOTE (fixed)** — the TL;DR told the reader to "approve and run the review result" when no review result can exist on this machine; it now states the situation.
- Residual risk accepted: the plan has no independent reviewer receipt. Re-running `ulw-plan`'s review after connecting a provider is the way to close that.
