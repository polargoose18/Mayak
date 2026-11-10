Task 13 manual QA, executed on Linux on November 9, 2026.

The matrix below records actual executions against the command tree, local mockdpi listeners, fake control HTTP server, OS subprocesses, and the compiled binary. The verbose transcript records the generated signed-list paths, complete output, exit codes, signal delivery, control request counts, and state snapshots. No browser or HTTP endpoint is the changed user surface; HTTP requests in these scenarios are made by the CLI probes themselves.

The additional incomplete-resolver regression failed before the guard fix (nine failing subcases), then passed in both full verification iterations. Other assigned fixes were already present when the first targeted baseline executed; their passing baseline is not represented as a failing TDD run.

```json
{
  "manualQa": {
    "surfaceEvidence": [
      {
        "scenarioId": "production-resolvers",
        "criterionReference": "R1",
        "surface": "productionEnv configuration inspected by TestProductionResolvers",
        "exactInvocation": "go test ./cmd/mayak -count=2 -v",
        "verdict": "PASS",
        "artifactRefs": ["cli-transcript"]
      },
      {
        "scenarioId": "production-binary-refusal",
        "criterionReference": "R1",
        "surface": "compiled binary with temporary HOME, XDG_CONFIG_HOME, and APPDATA; MANUAL COMPILED GUARD transcript",
        "exactInvocation": "cmd/mayak/mayak check --json",
        "verdict": "PASS",
        "artifactRefs": ["cli-transcript"]
      },
      {
        "scenarioId": "sni-block-json",
        "criterionReference": "R4",
        "surface": "TestCheckMockDPIJSON/sni_block; Cobra CLI with mockdpi reset_after_hello and fake control HTTP server; t1=sni_block/tls_sni, exit 0, schema-valid JSON",
        "exactInvocation": "go test ./cmd/mayak -count=2 -v",
        "verdict": "PASS",
        "artifactRefs": ["cli-transcript"]
      },
      {
        "scenarioId": "dns-tamper-json",
        "criterionReference": "R4",
        "surface": "TestCheckMockDPIJSON/dns_tamper; Cobra CLI with mockdpi dns_spoof and fake control HTTP server; t1=dns_tamper/dns, exit 0, schema-valid JSON",
        "exactInvocation": "go test ./cmd/mayak -count=2 -v",
        "verdict": "PASS",
        "artifactRefs": ["cli-transcript"]
      },
      {
        "scenarioId": "http-stub-json",
        "criterionReference": "R4",
        "surface": "TestCheckMockDPIJSON/http_stub; Cobra CLI with mockdpi TLS block page and fake control HTTP server; t1=http_stub/http, exit 0, schema-valid JSON",
        "exactInvocation": "go test ./cmd/mayak -count=2 -v",
        "verdict": "PASS",
        "artifactRefs": ["cli-transcript"]
      },
      {
        "scenarioId": "ip-block-json",
        "criterionReference": "R4",
        "surface": "TestCheckMockDPIJSON/ip_block; Cobra CLI with mockdpi closed port and fake control HTTP server; t1=ip_block/tcp, exit 0, schema-valid JSON",
        "exactInvocation": "go test ./cmd/mayak -count=2 -v",
        "verdict": "PASS",
        "artifactRefs": ["cli-transcript"]
      },
      {
        "scenarioId": "mockdpi-text",
        "criterionReference": "R4",
        "surface": "TestCheckMockDPIVerdicts subcases; all four command scenarios print the expected verdict sentence, measured count, and sending notice with exit 0",
        "exactInvocation": "go test ./cmd/mayak -count=2 -v",
        "verdict": "PASS",
        "artifactRefs": ["cli-transcript"]
      },
      {
        "scenarioId": "isolated-command-config",
        "criterionReference": "R3",
        "surface": "command and subprocess tests use isolated XDG_CONFIG_HOME and APPDATA; subprocess lock transcript records distinct temporary directories; smoke refusal leaves no state",
        "exactInvocation": "go test ./cmd/mayak -count=2 -v",
        "verdict": "PASS",
        "artifactRefs": ["cli-transcript", "regression-source"]
      }
    ],
    "adversarialCases": [
      {
        "scenarioId": "missing-config",
        "criterionReference": "R1",
        "adversarialClass": "incomplete configuration",
        "expectedBehavior": "TestCheckIncompleteEnvGuard and TestCheckIncompleteResolverFields refuse missing URL/TLS/DNS/public resolvers, either empty public address, port zero, missing transport, and missing DoT server name with exit 2, empty stdout, no control requests, and no persisted state",
        "verdict": "PASS",
        "artifactRefs": ["cli-transcript"]
      },
      {
        "scenarioId": "failed-output",
        "criterionReference": "R2",
        "adversarialClass": "output I/O failure",
        "expectedBehavior": "TestCheckTextWriteError and TestCheckJSONWriteError return exit 1 with stdout closed for normal, all-inconclusive, and interrupted runs",
        "verdict": "PASS",
        "artifactRefs": ["cli-transcript"]
      },
      {
        "scenarioId": "interrupt-output-and-state",
        "criterionReference": "R2; preserved ADR-006 Q5",
        "adversarialClass": "cancellation before and during measurement",
        "expectedBehavior": "TestCheckInterruptText prints explicit unmeasured rows and counts only measured rows; TestCheckInterruptMidRun produces valid measured-only JSON; TestCheckInterruptBeforeStart leaves empty JSON stdout; exit remains 130 and state remains unchanged",
        "verdict": "PASS",
        "artifactRefs": ["cli-transcript"]
      },
      {
        "scenarioId": "real-sigint",
        "criterionReference": "preserved ADR-006 Q5",
        "adversarialClass": "OS interrupt signal",
        "expectedBehavior": "TestCheckInterruptSignal sends os.Interrupt to an OS subprocess, validates the complete measured-only JSON report, observes command exit 130, and verifies byte-identical rev and rotation",
        "verdict": "PASS",
        "artifactRefs": ["cli-transcript"]
      },
      {
        "scenarioId": "all-inconclusive",
        "criterionReference": "preserved exit 2 semantics",
        "adversarialClass": "unavailable control and anchors",
        "expectedBehavior": "TestCheckDeadControlAnchorsDown preserves exit 2 in text and JSON; TestCheckAllowlistModeExitZero preserves exit 0 for measured allowlist mode",
        "verdict": "PASS",
        "artifactRefs": ["cli-transcript"]
      },
      {
        "scenarioId": "cross-process-lock",
        "criterionReference": "R5",
        "adversarialClass": "concurrent processes sharing configuration",
        "expectedBehavior": "TestCheckConcurrentProcesses parks the holder after its first measurement, runs a competing OS process, verifies exit 1 before network or publication, releases the holder through stdin, and verifies accepted rev 2026-11-09.2, rotation 1, and removal of check.lock",
        "verdict": "PASS",
        "artifactRefs": ["cli-transcript", "regression-source"]
      },
      {
        "scenarioId": "rollback-after-contention",
        "criterionReference": "R5; signed targets constraints",
        "adversarialClass": "older revision competing with newer accepted state",
        "expectedBehavior": "TestCheckConcurrentPublication rejects a live competitor and subsequently rejects its older signed list, preserving the newer accepted revision and rotation",
        "verdict": "PASS",
        "artifactRefs": ["cli-transcript"]
      },
      {
        "scenarioId": "crash-lock-recovery",
        "criterionReference": "R5",
        "adversarialClass": "stale crash lock",
        "expectedBehavior": "TestCheckCrashLockRecovery refuses even a year-old lock immediately without modifying it or using the network; after explicit removal of the fixture known to have no live owner, a new run succeeds and releases its lock",
        "verdict": "PASS",
        "artifactRefs": ["cli-transcript"]
      },
      {
        "scenarioId": "untrusted-and-expired-targets",
        "criterionReference": "preserved signed targets constraints",
        "adversarialClass": "expired or foreign-key signed list",
        "expectedBehavior": "TestSmokeExpiredList and TestSmokeForeignKeyList exercise compiled binaries and preserve actionable refusal with exit 1",
        "verdict": "PASS",
        "artifactRefs": ["cli-transcript"]
      }
    ],
    "artifactRefs": [
      {
        "id": "cli-transcript",
        "kind": "CLI execution transcript",
        "description": "Non-empty log containing the failing additional TDD regression, successful vet/build, both complete final CLI test iterations, exact generated invocations, stdout/stderr, exits, subprocess lock transcripts, state snapshots, and compiled production guard scenario",
        "path": "/home/goose/Documents/Mayak/.omo/evidence/mayak-block-b-finish/task-13-cli-hardening.log"
      },
      {
        "id": "regression-source",
        "kind": "test source",
        "description": "Resolver field, output failure, JSON mockdpi, crash recovery, and deterministic OS subprocess concurrency scenarios",
        "path": "/home/goose/Documents/Mayak-wt/block-b-final/cmd/mayak/hardening_test.go"
      }
    ]
  }
}
```

Verification: gofmt completed successfully; go vet ./cmd/mayak exited 0; go test ./cmd/mayak -count=2 -v exited 0 (29.663 seconds); go build -o cmd/mayak/mayak ./cmd/mayak exited 0. The explicit output path keeps the generated binary inside the assigned command directory. The temporary binary was removed after its manual scenario.

Crash recovery is bounded by immediate refusal: there is no waiting loop and no automatic age/PID-based lock deletion. On abnormal process termination, an operator must first verify that no mayak check process is running, then explicitly remove the indicated check.lock. This avoids removing a lock owned by a slow or paused live process.

Limitations: gopls is unavailable, so language-server diagnostics could not run; go vet, compiler, and actual tests supplied diagnostics. Native Windows execution was not available in this Linux workstation; APPDATA isolation is implemented and passed through subprocess environments, but native Windows runtime success is not claimed. The repository-wide suite and make check were intentionally not run because task 14 owns concurrent classifier/runner work. No commit was created.
