# Independent review: tasks 4 and 5

codeQualityStatus: BLOCK
recommendation: REQUEST_CHANGES
verdict: needs-fix
failure_class: product

Scope: `/home/goose/Documents/Mayak-wt/block-b-wave1/cmd/mayak-ctrl/main.go` and `main_test.go`, both untracked new files relative to HEAD `86e7a33`. Inspected both complete files and their complete new-file diffs. Other worktree changes were outside this review. No implementation or test source was edited. The requested `go build` refreshed the existing local executable.

## Findings

### CRITICAL

None.

### HIGH

1. **Rate limiting disappears for new clients when the map is full.** `cmd/mayak-ctrl/main.go:324-327` returns true without creating or charging a bucket when 10,000 live buckets already exist. Every subsequent request from an untracked client is admitted until space becomes available. This violates the claimed bounded 20/min limiter and removes the load protection exactly when the node is busy.

   Independently reproduced against the built binary using HTTP connections bound to distinct loopback source addresses. An initial client's first 20 requests returned 200 and requests 21-25 returned 429. Added 9,999 other distinct clients in 6.05 seconds, then sent 25 requests from a fresh client: all 25 returned 200. This requires no spoofed forwarding header. Fix the admission policy at capacity so an untracked client cannot obtain unlimited requests; cover saturation through the request boundary.

2. **Control-node list loading skips freshness validation required by SPEC 21.1/21.2.** `cmd/mayak-ctrl/main.go:245` calls `targets.Open`, whose contract at `internal/targets/sign.go:100-103` explicitly excludes clock checks. Thus an expired but validly signed list remains authorized on startup. SPEC 21.1 requires verification like the agent; SPEC 21.2 rejects expired and excessively future-dated lists. `targets.Verify` performs the existing clock check. This is a direct static finding: no simulated-clock binary reproduction was performed. Current checked-in signed data expires November 11, 2026; its current successful startup on November 9 does not exercise expiry rejection. Use the required freshness validation and add expired/future-list rejection coverage. Rollback persistence policy should also be reconciled explicitly with the same-agent-verification requirement rather than assumed satisfied by signature verification alone.

### MEDIUM

3. **Malformed query parsing bypasses explicit forbidden-parameter rejection.** `cmd/mayak-ctrl/main.go:377-378` and `421-422` use `r.URL.Query()`, discarding parsing errors before `validateQuery` sees the parameters. Against the real binary and the actual signed allowlist:

   ```text
   /v1/reach?host=www.youtube.com&ip=%ZZ       -> 200 {"reachable":true}
   /v1/reach?host=www.youtube.com&port=%ZZ     -> 200 {"reachable":true}
   /v1/reach?host=www.youtube.com&host=evil.invalid -> 200 {"reachable":true}
   /v1/reach?host=www.youtube.com&junk=1       -> 400
   /v1/reach?host=www.youtube.com&ip=127.0.0.1 -> 400
   ```

   Invalid escaping drops the offending pair, so requests containing `ip` or `port` are accepted despite SPEC 21.1. Duplicate host values also contradict the strict validation claim, although the first allowlisted value remains the actual destination: no arbitrary-destination SSRF was demonstrated. Parse the raw query with error checking and define/reject duplicate singleton fields. Apply the same checked parsing to both endpoints.

4. **The privacy test does not test privacy; important adversarial contracts remain uncovered.** `cmd/mayak-ctrl/main_test.go:235-250` (`TestNoClientAddressInLogs`) only checks ping's HTTP status. It captures no output and searches neither logs nor retained state, and is effectively a second ping status test. It would still pass if request handling started logging the client IP. This is an F (fix) under both requested skill perspectives, not evidence of the required "IP does not settle" regression check. No deletion or mutation was performed, as this is a read-only review. `TestRateLimit` at lines 205-232 asserts only at least one 429 out of 25 requests, silently ignores transport errors, and would pass if every request were rejected. Assert the exact boundary and treat request failures as failures. The missing saturation case allowed finding 1 through.

   No existing test exercises private/mixed/bogon DNS answers, the real dial guard, oversized bodies or decompressed hashes, redirect refusal, successful fetch JSON/hash correctness, invalid signed-file rejection, or signed-list freshness. The existing fetch timeout test exercises a stalled TLS handshake, not a slow response body or DNS timeout. Manual success fetches cover ordinary responses only; their sizes (874,751 and 792 bytes) are below 1 MiB. These gaps are material to the claimed security and body-cap verification, even though the corresponding guards are present in source.

5. **Both new modules exceed the skill size ceiling.** `cmd/mayak-ctrl/main.go:1-570` contains 455 nonblank, non-comment lines and mixes CLI parsing, list loading, rate limiting, HTTP API/client work, certificate generation, and TLS accept handling. `main_test.go:1-319` contains 284 such lines. Neither has a SIZE_OK exception. Both requested skills classify this as a maintainability defect. Split by responsibility within the package. Boundary validation and the actual-address bogon recheck are necessary security checks, not redundant validation to remove.

### LOW

6. **Unused certificate test fixture adds noise.** `cmd/mayak-ctrl/main_test.go:64-96` defines `newSelfSignedCertForNames` but no test calls it. The associated certificate-generation code is not evidence of successful HTTPS fetch verification. Remove it or use it in the missing wire-level fetch contract coverage. Production `rootCAs` currently has no nonnil assignment in these tests either.

## Independent checks and observed results

All five requested commands ran against the reviewed worktree in one shell, in the following order; the shell exited 0:

```text
go build ./cmd/mayak-ctrl                  PASS, no output
go vet ./cmd/mayak-ctrl                    PASS, no output
go test ./cmd/mayak-ctrl -count=1          ok .../cmd/mayak-ctrl 0.047s
go test ./cmd/mayak-ctrl -count=2          ok .../cmd/mayak-ctrl 0.088s
gofmt -l cmd/mayak-ctrl                   PASS, empty output
```

Independent real-binary TLS exercise: `arbitrary-review.invalid` SNI and absent SNI both negotiated TLS 1.3; reading immediately after the handshake returned an empty byte string (EOF). The binary's captured stdout/stderr contained only the ephemeral certificate fingerprint and no client loopback IP or custom SNI. Both listener ports refused connections with `connect_ex == 111` after process termination; process exit was -15 (SIGTERM). This verifies immediate post-handshake closure and process/port teardown, not graceful draining of stalled handshakes.

The saturation reproduction used a second independently started binary. Its process was terminated and its API port also refused connections afterward. No listener or child process was intentionally left running.

`lsp_diagnostics` was attempted and could not run because `gopls` is not installed. No dependency was installed. Compiler and vet results above are the available static checks. `make check`, race detection, full-repository tests, supplied certificate files, and privileged default-port binding were not run as part of this scoped review.

## Evidence inspected, rather than assumed

- `.omo/evidence/mayak-block-b-finish/task-4-control-api.log`: ordinary unknown-host/ip/port/path rejection; later real signed host `www.youtube.com` reaches successfully and fetches both paths with the documented response keys. Earlier example.org/youtube.com requests are 400 authorization cases, not success evidence.
- `.omo/evidence/mayak-block-b-finish/task-5-any-sni.log`: target.example TLS 1.3 handshake, self-signed certificate, server closure, actual server output, and teardown. Independent binary checks above extend this to absent/custom SNI.
- `.omo/evidence/mayak-block-b-finish/control-checks.log`: prior scoped green commands; independently rerun rather than accepted as proof.
- `.omo/evidence/mayak-block-b-finish/task-4-5-manual-qa.md`: parsed the scenarios and artifact references; its coverageLimits correctly admit no separate bogon or oversize-body exercise.
- `.omo/evidence/mayak-block-b-finish/control-evidence-review.log`: inspected response-shape/privacy/port assertions and source hash records. Those records are prior-run claims; the source and executable checks above are the review's independent evidence.
- `docs/SPEC.md:443-481`, `internal/targets/sign.go:90-145`, `internal/targets/revstore.go:26-56`, and `internal/classify/classify.go:214-226`: inspected the relevant contracts and callees. The control implementation reuses a classifier bogon predicate that intentionally admits documentation ranges; complete non-public-address coverage was not demonstrated.

## Skill-perspective pass

Loaded `remove-ai-slops/SKILL.md`, `programming/SKILL.md`, `programming/references/go/README.md`, `programming/references/testing/README.md`, and `programming/references/testing/junk-classes.md` before judging tests and maintainability. Both perspectives ran by source review. Findings 4-6 violate those perspectives. No brittle prompt tests, prose pins, deletion-only tests, removal certificates, implementation-constant mirrors, or unnecessary production parsing/normalization were found. Runtime input validation is required here; the malformed-query problem is missing boundary error handling, not a reason to remove validation. Response `map[string]any` encoders are less precise than typed protocol structs but are localized serialization, not domain-level untyped escape hatches.

Test ledger: R = reach true/false, unknown-host rejection, forbidden-IP rejection, bad-path rejection, TLS disabled, real arbitrary/absent SNI handshake and EOF, stalled-handshake timeout. F = ping (does not assert empty body), rate boundary, privacy test, certificate fingerprint test (only checks string length, not correspondence to returned certificate). No tests were deleted or changed, and no mutation proof is claimed.

The available tool set has no JS eval or agentToolkit status tool, so `currentAttemptDir` could not be queried with the requested snippet. The task's explicit report location is used. No todo or monitor tool was available; bounded verification commands completed synchronously.

## Approval blockers

- Preserve rate enforcement when the client map reaches capacity and add a regression that exercises saturation.
- Enforce signed-list freshness at the control-node boundary and cover rejection.
- Reject malformed query encoding, including malformed forbidden parameters; specify singleton parameter handling.
- Replace the privacy status-only test with captured-output/state assertions and cover the untested security/body-cap contracts before claiming them verified.
- Resolve the new files' module-size violations and remove or put the unused certificate fixture to meaningful use.

The green requested commands establish buildability and the behavior currently asserted by the suite. They do not override the reproduced rate-limit and query-validation failures or the direct freshness-validation defect.
