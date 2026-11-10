# manualQa

Executor: omo-native-qa-executor, task st_01a1c0c8. Workspace: /home/goose/Documents/Mayak-wt/block-b-wave1. Date: 2026-11-09.

The toolkit status returned no currentAttemptDir, so artifacts use the caller's evidence directory. The executor ran the scenarios, then read the saved logs and network trace before assigning these verdicts. All paths below are relative to this workspace. All scenarios ran on Linux.

The real binary smoke tests execute compiled subprocesses. The expired-list smoke binary uses a temporary Go build overlay replacing only its trusted public key with the generated fixture public key. Its fixture private key comes from ed25519.GenerateKey and has the required 64-byte size. The normal binary retains the repository trust roots. Interrupt scenarios execute the command in process against real local mock servers and cancel its context after the first measurement completes; they do not send an external operating-system SIGINT. Their PASS verdicts cover that stated surface only.

```json
{
  "manualQa": {
    "surfaceEvidence": [
      {
        "scenarioId": "CLI-01",
        "criterionReference": "Task 7; ADR-006 Q8: version exits 0",
        "surface": "Real compiled CLI subprocess with temporary HOME and XDG directories",
        "exactInvocation": "/tmp/mayak version",
        "verdict": "PASS",
        "artifactRefs": ["command-log"]
      },
      {
        "scenarioId": "CLI-02",
        "criterionReference": "Task 2; ADR-006 control-node guard: exit 2 without network use",
        "surface": "Real compiled CLI subprocess with system-call tracing",
        "exactInvocation": "strace -f -e trace=network -o /home/goose/Documents/Mayak-wt/block-b-wave1/.omo/evidence/mayak-block-b-finish/no-control-network.strace /tmp/mayak check",
        "verdict": "PASS",
        "artifactRefs": ["command-log", "network-trace"]
      },
      {
        "scenarioId": "CLI-03",
        "criterionReference": "Task 7; ADR-006 Q3/Q5: --limit 3 exits 1",
        "surface": "Real compiled CLI subprocess",
        "exactInvocation": "/tmp/mayak check --limit 3",
        "verdict": "PASS",
        "artifactRefs": ["command-log"]
      },
      {
        "scenarioId": "CLI-04",
        "criterionReference": "Task 2; ADR-006 Q4/Q5: JSON no-control guard leaves stdout empty and exits 2",
        "surface": "Real compiled CLI subprocess with separate stdout and stderr capture",
        "exactInvocation": "/tmp/mayak check --json",
        "verdict": "PASS",
        "artifactRefs": ["command-log"]
      },
      {
        "scenarioId": "CTRL-01",
        "criterionReference": "Task 2; ADR-006 Q5: every result inconclusive exits 2",
        "surface": "In-process CLI against local control HTTP server returning 503 for /v1/ping and anchors; text and JSON modes",
        "exactInvocation": "go test ./cmd/mayak -count=1 -v; scenarios TestCheckDeadControlAnchorsDown/json=false and TestCheckDeadControlAnchorsDown/json=true",
        "verdict": "PASS",
        "artifactRefs": ["command-log", "package-tests"]
      },
      {
        "scenarioId": "CTRL-02",
        "criterionReference": "Task 2; ADR-006 Q5: allowlist_mode is a measurement and exits 0",
        "surface": "In-process CLI against local HTTP fixtures with dead control/anchors and a reachable allowlist endpoint",
        "exactInvocation": "go test ./cmd/mayak -count=1 -v; scenario TestCheckAllowlistModeExitZero",
        "verdict": "PASS",
        "artifactRefs": ["command-log", "package-tests"]
      },
      {
        "scenarioId": "INT-01",
        "criterionReference": "Task 3; ADR-006 Q5: cancellation returns 130, prints measured results as complete JSON, and preserves state",
        "surface": "In-process CLI with cancellation after the first real local measurement",
        "exactInvocation": "go test ./cmd/mayak -count=1 -v; scenario TestCheckInterruptMidRun",
        "verdict": "PASS",
        "artifactRefs": ["interrupt-log"]
      },
      {
        "scenarioId": "INT-02",
        "criterionReference": "Task 3; ADR-006 Q5: interrupted text output includes only completed measurements",
        "surface": "In-process CLI with context cancellation after the first measurement",
        "exactInvocation": "go test ./cmd/mayak -count=1 -v; scenario TestCheckInterruptText",
        "verdict": "PASS",
        "artifactRefs": ["interrupt-log"]
      },
      {
        "scenarioId": "INT-03",
        "criterionReference": "Task 3; ADR-006 Q4/Q5: cancellation before start exits 130, leaves JSON stdout empty, and creates no state files",
        "surface": "In-process CLI with a context cancelled before execution",
        "exactInvocation": "go test ./cmd/mayak -count=1 -v; scenario TestCheckInterruptBeforeStart",
        "verdict": "PASS",
        "artifactRefs": ["interrupt-log"]
      },
      {
        "scenarioId": "SMOKE-01",
        "criterionReference": "Task 7; ADR-006 Q7/Q8: expired list exits 1 with expiry guidance",
        "surface": "Real compiled subprocess using a generated trusted fixture key through a temporary build overlay",
        "exactInvocation": "/tmp/TestSmokeExpiredList2855493667/001/mayak check --targets-file /tmp/TestSmokeExpiredList2855493667/002/targets.signed.json; executed by go test ./cmd/mayak -count=1 -v",
        "verdict": "PASS",
        "artifactRefs": ["smoke-log"]
      },
      {
        "scenarioId": "SMOKE-02",
        "criterionReference": "Task 7; ADR-006 Q7/Q8: foreign-signature list exits 1 with signature guidance",
        "surface": "Real compiled subprocess with repository trust roots",
        "exactInvocation": "/tmp/TestSmokeForeignKeyList4111443586/001/mayak check --targets-file /tmp/TestSmokeForeignKeyList4111443586/002/targets.signed.json; executed by go test ./cmd/mayak -count=1 -v",
        "verdict": "PASS",
        "artifactRefs": ["smoke-log"]
      }
    ],
    "adversarialCases": [
      {
        "scenarioId": "ADV-01",
        "criterionReference": "CLI-03; ADR-006 Q3/Q5",
        "adversarialClass": "Out-of-range user input",
        "expectedBehavior": "--limit 3 is rejected with exit 1 and a range message before creating state",
        "verdict": "PASS",
        "artifactRefs": ["command-log", "smoke-log"]
      },
      {
        "scenarioId": "ADV-02",
        "criterionReference": "SMOKE-01; ADR-006 Q7",
        "adversarialClass": "Expired authenticated input",
        "expectedBehavior": "Reject the expired signed list with exit 1, an expiry explanation, and --targets-file guidance",
        "verdict": "PASS",
        "artifactRefs": ["smoke-log"]
      },
      {
        "scenarioId": "ADV-03",
        "criterionReference": "SMOKE-02; ADR-006 Q7",
        "adversarialClass": "Untrusted signature",
        "expectedBehavior": "Reject a structurally valid foreign-key list with exit 1 and trusted-signature guidance",
        "verdict": "PASS",
        "artifactRefs": ["smoke-log"]
      },
      {
        "scenarioId": "ADV-04",
        "criterionReference": "CLI-02/CLI-04; ADR-006 control-node guard",
        "adversarialClass": "Missing deployment configuration",
        "expectedBehavior": "Exit 2, keep JSON stdout empty, and make no network calls",
        "verdict": "PASS",
        "artifactRefs": ["command-log", "network-trace"]
      },
      {
        "scenarioId": "ADV-05",
        "criterionReference": "CTRL-01/CTRL-02; ADR-006 Q5",
        "adversarialClass": "Unavailable measurement infrastructure",
        "expectedBehavior": "Dead ping plus failed anchors yields all inconclusive and exit 2 in both output modes; reachable allowlist changes the verdict to allowlist_mode and exit 0",
        "verdict": "PASS",
        "artifactRefs": ["command-log"]
      },
      {
        "scenarioId": "ADV-06",
        "criterionReference": "INT-01/INT-02/INT-03; ADR-006 Q5",
        "adversarialClass": "Cancellation during and before measurement",
        "expectedBehavior": "The context cancellation path exits 130, emits only completed measurements, preserves pre-existing rev and rotation bytes, and leaves no new state when cancelled before start",
        "verdict": "PASS",
        "artifactRefs": ["interrupt-log"]
      },
      {
        "scenarioId": "ADV-07",
        "criterionReference": "Assigned scope: cmd/mayak CLI only",
        "adversarialClass": "Browser or desktop layout and focus",
        "expectedBehavior": "Not applicable because this change exposes no browser or desktop GUI",
        "verdict": "not_applicable",
        "artifactRefs": []
      }
    ],
    "artifactRefs": [
      {"id": "command-log", "kind": "CLI transcript", "description": "Exact binary invocations, stdout, stderr, exit status, XDG cleanup, and control-failure scenario output", "path": ".omo/evidence/mayak-block-b-finish/task-2-check-command.log"},
      {"id": "network-trace", "kind": "strace network syscall trace", "description": "All traced threads exit 2 without network syscalls", "path": ".omo/evidence/mayak-block-b-finish/no-control-network.strace"},
      {"id": "interrupt-log", "kind": "In-process CLI test transcript", "description": "Actual command output, complete JSON, exit 130, unchanged state bytes, and pre-start state cleanup", "path": ".omo/evidence/mayak-block-b-finish/task-3-interrupt.log"},
      {"id": "smoke-log", "kind": "Binary smoke test transcript", "description": "Compiled binary version, expired list, foreign signature, limit rejection, and isolated-state tests", "path": ".omo/evidence/mayak-block-b-finish/task-7-smoke.log"},
      {"id": "package-tests", "kind": "Verbose Go test output", "description": "Complete passing package test run", "path": ".omo/evidence/mayak-block-b-finish/package-tests.log"},
      {"id": "checks", "kind": "Verification transcript", "description": "Package vet, count=2 test run, and /tmp/mayak build", "path": ".omo/evidence/mayak-block-b-finish/checks.log"}
    ]
  }
}
```

Requested checks passed: `gofmt -w cmd/mayak/*.go`, `go vet ./cmd/mayak`, `go test ./cmd/mayak -count=1 -v`, `go test ./cmd/mayak -count=2`, and `go build -o /tmp/mayak ./cmd/mayak`. No repository-wide test run or commit was made. Language-server diagnostics could not run because gopls is not installed. Temporary test files and the manual QA XDG directory were removed; /tmp/mayak is retained as the requested build artifact.
