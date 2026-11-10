# F2. Independent code quality and security review

Verdict: CHANGES_REQUESTED. codeQualityStatus: BLOCK. recommendation: REQUEST_CHANGES.

Reviewed `/home/goose/Documents/Mayak-wt/block-b-final` at HEAD `ae0e5db437c375872f2972d6e91943278c666004`, including the working tree, against base `86e7a33`. The working tree was clean when inventoried. The complete change set contains 23 files, 3,290 added lines and 38 removed lines. Product files were not edited. Manual QA was not run; that belongs to F3.

## Findings

### HIGH F2-01: Windows tests use the real configuration directory and fail to isolate state

Locations: `cmd/mayak/check_test.go:189`, `cmd/mayak/check_test.go:307`, `cmd/mayak/check_interrupt_test.go:70`, `cmd/mayak/check_interrupt_test.go:182`, `cmd/mayak/check_interrupt_test.go:339`, `cmd/mayak/smoke_test.go:77`.

`setup` isolates only `XDG_CONFIG_HOME`. `userDir` correctly calls `os.UserConfigDir`, which uses `AppData` on Windows, not XDG_CONFIG_HOME or HOME. The signal child and binary smoke helpers make the same assumption. Consequently the new Windows CI job runs command tests against one shared `%AppData%/mayak` directory. More seriously, `TestCheckInterruptMidRun` unconditionally writes fixture contents to `targets.rev` and `rotation` in that directory, overwriting a developer's real state on Windows.

Exact reproduction: on Windows, run `go test ./cmd/mayak -count=1 -run '^TestCheckInterrupt(MidRun|BeforeStart)$'` with the usual AppData environment. MidRun leaves its deliberately preserved fixture state in `%AppData%/mayak`; BeforeStart then observes the same files and fails its assertions that neither file exists and the directory is empty. Setting a new XDG_CONFIG_HOME for each test does not change this directory. A developer with existing state can have that state overwritten by the first test.

Evidence: source inspection corroborated against the installed Go source `/usr/lib/go/src/os/file.go:552-564`, where the Windows branch reads `Getenv("AppData")`. Windows cross compilation passed, but Windows runtime tests were not available on this Linux workstation. This is a source-proven platform failure, not a claim that Windows tests were executed.

Required correction: isolate the configuration variable used by the active OS in all in-process and subprocess helpers. Verify the sequence on Windows and preserve any pre-existing user configuration.

### HIGH F2-02: The control node rate limit rejects a normal supported agent run

Locations: `cmd/mayak-ctrl/main.go:53`, `cmd/mayak-ctrl/main.go:305-347`. Relevant consumers: `internal/probe/ctrl.go:91-109`, `internal/runner/target.go:144-162`.

The node permits 20 total API requests per client IP per minute, including ping. A healthy target uses three requests: `/v1/ping`, `/v1/reach`, and `/v1/fetch`. The default ten-target run needs 30 requests, and the supported twenty-target run needs 60. These runs can finish well inside a minute under the prescribed 200-800 ms pauses. The node therefore throttles its own normal client. Later pings fail and targets become `inconclusive`; earlier reference fetches can also fail, losing evidence needed to distinguish a geoblock. Multiple users behind one NAT share the same budget.

Exact reproduction: use the production ctrlServer handler and send ten repetitions of `GET /v1/ping`, `GET /v1/reach?host=<an allowed healthy host>`, and `GET /v1/fetch?host=<the same host>&path=/`, from one RemoteAddr in less than 60 seconds. Requests 1-20 are admitted by the limiter; request 21 and all remaining requests receive 429. The agent's normal healthy path produces this request sequence. `TestRateLimit` already verifies that 25 requests from one IP reach 429, while the CLI tests use `testControl`, which omits this production limiter and cannot expose the integration failure.

Evidence: relevant package tests passed, including the limiter's existing tests. Request demand and budget were independently traced through the real consumers; this review did not run a manual node or external network scenario.

Required correction: choose and test a bounded rate budget that supports a full allowed run, or reduce repeated control requests while retaining the specified load and security limits. Add a test exercising the real limiter with the agent's request demand.

### HIGH F2-03: Staged state commits can roll back an already accepted revision

Locations: `cmd/mayak/check.go:109-119`, `cmd/mayak/check.go:150-154`.

A command snapshots live state into a staging directory, validates the list against that snapshot, measures the network, then replaces the live revision with an unconditional `os.Rename`. The final write bypasses `targets.FileRevStore.Save`, including its comparison with the current stored revision. A second command can accept and commit a newer revision while the first command is still measuring. When the older command finishes, it overwrites that newer revision and defeats rollback protection. Rotation updates can be lost for the same reason.

Exact reproduction: start with live revision `2026-11-08.1`. Start command A with a still-valid signed `2026-11-09.1` list and hold its checks in progress after staging. Start command B against the same configuration directory with a valid signed `2026-11-09.2` list and let B complete. Then release A. A's line 151 renames its `2026-11-09.1` file over B's live `2026-11-09.2`. A later invocation now accepts `2026-11-09.1`, although a newer revision had already been accepted. No invalid signature or writable-state attacker is needed; two normal invocations suffice.

Evidence: source trace, including the existing monotonic comparison in `internal/targets/revstore.go:101-111`, which the new final commit does not call. The existing interrupt tests cover a single invocation and passed; they do not cover concurrent commands. The concurrent reproduction was not executed because this reviewer is limited to the report artifact and does not add a product/test harness.

Required correction: coordinate acceptance and state publication across invocations so a completed run cannot replace a newer accepted revision or lose a rotation update. Preserve the promised cancellation behavior.

### HIGH F2-04: Control-node list trust omits rollback protection and never expires after startup

Locations: `cmd/mayak-ctrl/main.go:232-255`, `cmd/mayak-ctrl/main.go:291-302`.

`loadCtrlTargets` calls `targets.Verify`, not `targets.Accept`, and the node has no persistent accepted-revision state. Thus restarting with an older but still-valid signed list succeeds. In addition, expiry is checked only at startup: `authorizeHost` subsequently checks only membership. A long-running node continues serving targets from an expired list indefinitely. SPEC section 21.1 requires the node's list to be checked like the agent's, while section 21.2 defines expiry and rollback refusal.

Exact rollback reproduction: sign two currently valid lists with a trusted key, revision `2026-11-09.1` containing host A and revision `2026-11-09.2` removing host A. Run the node with .2, stop it, and restart it with .1. The older list is accepted and A is authorized again because no accepted revision is recorded or compared.

Exact expiry reproduction: start the node just before a valid list's Expires timestamp. After that timestamp, request `/v1/reach?host=<a member of the list>`. `authorizeHost` still returns true and DNS/dial work proceeds. It never reads Expires. An equivalent package test can construct a node with a list, advance a supplied clock past expiry, and assert no DNS/dial occurs.

Evidence: `TestSignedTargetsFreshness` passed but calls `loadCtrlTargets` separately at different times; it proves startup validation only. No runtime expiry or rollback test is present in the changed node tests. These runtime/restart sequences are source-derived reproductions and were not performed as manual QA.

Required correction: retain a monotonic accepted revision for the node and stop authorizing expired lists. Tests must cover restart rollback and an already-running node crossing expiry.

### MEDIUM F2-05: The required privacy regression test never examines logs or stored addresses

Location: `cmd/mayak-ctrl/main_test.go:239-253`.

`TestNoClientAddressInLogs` sends a ping and checks only HTTP 200. It does not supply a distinctive client IP, capture stdout/stderr or the HTTP server ErrorLog, inspect retained state, or search any sink. Adding logging of `r.RemoteAddr` to the production middleware would leave this test green. This fails the explicit AGENTS.md and SPEC section 21.1 requirement for the control node's "IP does not settle" test and gives a misleading name to unrelated ping coverage.

Exact reproduction of the coverage hole: in a disposable copy, add `fmt.Fprintln(os.Stderr, r.RemoteAddr)` in `rateLimitMiddleware`, then run `go test ./cmd/mayak-ctrl -run '^TestNoClientAddressInLogs$' -count=1`. Its only assertion remains status 200, so the privacy leak is not detected. No such mutation was made in this review. The source itself exposes the missing assertion.

Evidence: independently inspected the entire test body and ran the package successfully. This finding does not allege that the current normal ping path logs addresses; it identifies the absent required regression protection. It is an F (fix weak assertion) under the loaded skills, not a recommendation to delete a security test.

Required correction: exercise the actual node with a known client address, capture every configured logging sink, inspect retained state applicable to this node, and fail on the literal address. Cover error/rejection paths as well as ping.

### MEDIUM F2-06: The production environment cannot perform DNS once the documented deployment constants are filled

Locations: `cmd/mayak/env.go:27-47`; contract: `internal/probe/dns.go:118-130`.

`productionEnv` never sets ControlResolver or PublicResolvers. DNSRequest.validate always validates the Control resolver and rejects its zero address. Filling `defaultControlURL` and `defaultControlAddr`, which the new comments present as the remaining deployment setup, therefore leaves every otherwise healthy check failing with `dns: invalid resolver address` before measuring DNS. The CLI test environment supplies a valid mock ControlResolver and masks the omission. The current empty-control guard intentionally prevents this path in the shipped configuration, so this is latent rather than a claim that the existing guarded binary contacts the network.

Exact reproduction: build the documented deployed configuration by setting the two control constants to a reachable node. Use a fresh valid signed list and reachable anchors, then run `mayak check --json`. After successful ctrl, Check constructs DNSRequest from the zero ControlResolver; validate returns the error above. Results have no verdict, and BuildReport rejects them. Text output instead prints an empty verdict with the fallback sentence because Run does not aggregate Result.Err.

Evidence: direct trace of productionEnv, Check, DNSRequest.validate, and the output code. No deployed-node run was made. The relevant packages passed using their supplied mock resolver.

Required correction: define the production trusted resolver configuration and test the assembled production environment's required inputs. Do not require undocumented additional code changes after filling the endpoint constants.

### MEDIUM F2-07: Verdict-only mapping assigns the wrong originating test to reports

Locations: `internal/runner/report.go:22-37`, especially line 25; `internal/runner/report_test.go:22`.

`timeout_unknown` is always reported as test `dns`, but the classifier also returns it for an unexplained target TLS timeout and an HTTP timeout after successful DNS/TCP/TLS. Likewise `vendor_down` and `inconclusive` can arise at different stages. A verdict does not uniquely identify its producing test. The new table and its mirrored unit case enforce a false provenance for these real results, undermining the report's diagnostic purpose even though schema validation passes.

Exact reproduction: form a valid Result whose observations have ControlAlive/AnchorsAlive true, consistent successful DNS, TCPOK, target HandshakeOK, and HTTPTimeout with the outside target reachable. Classify returns `timeout_unknown` (`internal/classify/classify.go:293-304`). Pass it to BuildReport. `results[0].test` is `dns` despite successful DNS and the deciding failure being HTTP. The corresponding unexplained TLS timeout is at classify.go:275-276.

Evidence: classifier branches and report mapping inspected. Existing BuildReport tests passed; their timeout case supplies successful HTTP observations and a manually assigned timeout verdict, so it does not validate causal consistency. This is the implementation-mirroring aspect of the test review; public schema/mapping tests otherwise remain legitimate protocol coverage.

Required correction: preserve the deciding stage in the runner result or derive it from the observations using the classifier's actual decision, then cover realistic DNS, TLS, and HTTP timeout cases.

### MEDIUM F2-08: The new control-node module bundles distinct security responsibilities in 474 pure lines

Location: `cmd/mayak-ctrl/main.go:1-591`.

The file owns configuration parsing, certificate generation, target loading, rate-limit storage, host authorization, DNS/address restrictions, API fetch/reach behavior, the any-SNI accept loop, and process startup. It contains 474 nonblank, non-//-comment lines, exceeding both loaded skills' 250 pure-line ceiling. The mixed ownership also separates important related checks: startup list verification is far from runtime authorization, and the request budget is far from the client integration. No SIZE_OK exception or indivisible-state-machine rationale is present.

Exact reproduction: `awk '!/^[[:space:]]*$/ && !/^[[:space:]]*(#|\/\/)/' cmd/mayak-ctrl/main.go | wc -l` returns `474`. The separate responsibilities are visible in `loadConfig`, `newSelfSignedCert`, `loadCtrlTargets`, `allow`, `resolvePublic`, `reach`, `fetch`, `serveTLSListener`, and `main`.

Evidence: measured and inspected the entire module. Changed test files also exceed this ceiling: main_test.go 284, check_test.go 330, check_interrupt_test.go 351, and runner/report_test.go 331 pure lines. Those test measurements are supporting maintenance evidence rather than separate findings.

Required correction: split by owned concepts within the existing package, preserving behavior and avoiding new dependencies or generic helper layers. This review does not request a repository-wide refactor.

## Severity inventory and blockers

CRITICAL: none found.

HIGH: F2-01, F2-02, F2-03, F2-04. These must be resolved before approval: safe Windows test isolation; a control budget compatible with supported runs; monotonic state publication across invocations; control-node rollback and expiry enforcement.

MEDIUM: F2-05, F2-06, F2-07, F2-08. The privacy assertion, missing production resolver, report provenance, and oversized control-node module remain requested changes.

LOW: none separately raised. The interrupt tests' hand-written substring/splitting and error-unwrapping helpers duplicate strings.Contains/strings.Split/errors.As; they are minor maintenance observations, not additional blockers.

## Independent checks and evidence

The following command ran once and exited 0:

```text
cd /home/goose/Documents/Mayak-wt/block-b-final
go test -race -count=1 ./cmd/mayak ./cmd/mayak-ctrl ./internal/runner ./internal/classify ./targets && go vet ./cmd/mayak ./cmd/mayak-ctrl ./internal/runner ./internal/classify ./targets

ok github.com/polargoose18/mayak/cmd/mayak       10.007s
ok github.com/polargoose18/mayak/cmd/mayak-ctrl   2.893s
ok github.com/polargoose18/mayak/internal/runner 4.674s
ok github.com/polargoose18/mayak/internal/classify 2.821s
ok github.com/polargoose18/mayak/targets          1.060s
```

Vet emitted no diagnostics and the combined command exited 0. `GOOS=windows GOARCH=amd64 go build ./...` also exited 0 without output. `git diff --check 86e7a33` exited 0. `git diff --name-only 86e7a33 -- go.mod go.sum` emitted nothing: no new module dependencies were introduced. These are direct tool observations, recorded here as the review artifact; they are not executor/verifier claims.

All changed production files, tests, CI/Makefile changes, and documentation changes were inspected. The underlying runner/pool, source acceptance, target traversal, probe TLS/DNS/HTTP/control, target revision stores, report types, SPEC sections 19-21, and ADR-006 were consulted to check integration contracts. AGENTS.md was read first. No prior success report was used as proof. No manual QA was performed, and no claim is made that the new Windows CI job passed. A full `make check`, release-check, vulnerability scan, and Windows runtime suite were not run by F2; the scoped race tests and relevant vet are the independent checks for this review.

The requested explicit artifact path was used. A JS eval tool to query agentToolkit.currentAttemptDir is not exposed to this child, so that optional discovery step could not run; it does not replace the user's explicit artifact destination.

## Security and behavior assessment beyond findings

The node rejects unknown, duplicate, and malformed query keys; fetch paths are restricted to `/` and `/robots.txt`; host membership is checked before resolution. Reach/fetch pin the resolved destination and port 443, and the production Dialer.Control checks the actual dial address with the shared bogon predicate. Redirects are disabled and response hashing is bounded to MaxBody. Existing tests exercise malformed query rejection, mixed bogon answers, mapped IPv4 addresses, destination pinning, timeout handling, and bounded hashing. The bogon predicate retains its documented test-oriented treatment of documentation ranges; this review does not certify it as a complete IANA special-purpose-address registry.

The any-SNI listener explicitly handshakes under an eight-second deadline and closes the connection. The arbitrary/empty-SNI handshake test passed. The agent deliberately treats a control listener's invalid-for-target certificate as a completed handshake; the self-signed any-SNI certificate therefore does not by itself break that classifier semantics. No claim is made that it authenticates the arbitrary SNI name.

Evidence construction selects scalar status/hash/duration fields rather than serializing raw observations, DNS addresses, errors, host names, or bodies. No direct client-address logging was found in the new application code. The missing privacy regression identified above prevents treating this as a fully tested guarantee. Report validation enforces the existing schema and size contract; the provenance error is semantic rather than a schema violation.

The existing pool tests and inspected code support a four-target concurrency ceiling, 200-800 ms pauses, and bounded contexts. The command stages state and the executed single-invocation interrupt tests preserve state and emit measured-only JSON/text. The concurrent-state finding remains despite those passing tests. Deferral of deployment, macOS, freeze/throughput probes, and traffic accounting is stated in the changed ADR/README; it was not mistaken for completed functionality.

## Skill perspective check

Both requested skills were available and explicitly loaded before judging test relevance or maintainability:

- `/home/goose/.omo/binary-runtime/5.1.65/plugin/skills/remove-ai-slops/SKILL.md`.
- `/home/goose/.omo/binary-runtime/5.1.65/plugin/skills/programming/SKILL.md`, plus its Go README, testing README, and junk-classes table.

The overfit/slop pass covered the changed production and test code. It found no deletion-only tests, tests merely asserting a requested removal, prose/source-grep tests, or tautological self-comparisons. The freshness tests exercise an operational check consumed by Makefile/CI, so the date arithmetic is required behavior, not gratuitous extraction. The existing evidence map follows the schema's representation; its use of map[string]any is not an added domain escape hatch.

The diff violates the perspectives in F2-05 (misnamed privacy coverage with no privacy assertion), F2-07 (a literal verdict mapping tested without causal observations), and F2-08 (oversized mixed-responsibility modules). The fixture clock that signals on its third Now call is also coupled to implementation order, although the separate actual-signal subprocess test provides useful lifecycle coverage; it is a fragility observation, not an independently reproduced blocker. No tests were deleted, weakened, or mutated and no production normalization/parsing was added by the reviewer. Suggested consolidation/deletion is not claimed as mutation-proven: security/protocol tests should be retained and strengthened.

Confidence: 0.94 for the overall changes-requested verdict. The exact Windows runtime failure, concurrent command interleaving, and runtime expiry/restart reproductions are source-derived and explicitly remain unexecuted by F2; Linux race tests, vet, whitespace checking, and Windows compilation are directly corroborated.
