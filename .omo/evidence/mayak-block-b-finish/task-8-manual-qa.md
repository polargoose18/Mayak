# task-8 manualQa

The caller's evidence directory is used. No JS eval or agentToolkit status tool is exposed to this executor. All paths below are relative to `/home/goose/Documents/Mayak-wt/block-b-wave1`.

The earlier section of task-8-adr.log is retained as historical evidence, including its failed make check and invalid completion verdict. Current evidence begins at `=== task-8 reviewer correction: current verification ===` and supersedes that earlier verdict. The repository check in this correction exited 0; the ADR still leaves final block-B acceptance (B9) unchecked.

```yaml
manualQa:
  surfaceEvidence:
    - scenarioId: QA-doc
      criterionReference: reviewer corrections 1-4
      surface: Markdown document and repository CLI
      exactInvocation: "git diff --check -- docs/adr/ADR-006-agent-check.md; grep -nE 'B7|трафик|ControlTLS|defaultControlAddr|NeutralSNI|Итоговый прогон|make check' docs/adr/ADR-006-agent-check.md; git diff -- docs/adr/ADR-006-agent-check.md"
      verdict: PASS
      artifactRefs: [current-log, corrected-adr]
    - scenarioId: QA-defaults
      criterionReference: reviewer corrections 2-3
      surface: source and document data
      exactInvocation: "nl -ba cmd/mayak/env.go; python3 - <<'PY' # ADR reviewer-criterion assertions (full assertions and results in current-log)"
      verdict: PASS
      artifactRefs: [current-log, deployment-source]
    - scenarioId: QA-implementation
      criterionReference: reviewer correction 4, B4/B5/B8 and B9 smoke subset
      surface: Go package tests with in-process CLI, real TLS connections, and built-binary smoke invocations
      exactInvocation: "go test -count=1 -v ./cmd/mayak ./cmd/mayak-ctrl ./internal/runner"
      verdict: PASS
      artifactRefs: [current-log]
    - scenarioId: QA-spec-wording
      criterionReference: reviewer correction 4, B10 documentation item
      surface: SPEC document data
      exactInvocation: "grep -nE 'Linux|Windows|macOS' docs/SPEC.md"
      verdict: PASS
      artifactRefs: [current-log]
    - scenarioId: QA-repository
      criterionReference: repository required check, not final B9 acceptance
      surface: repository CLI
      exactInvocation: "make check"
      verdict: PASS
      artifactRefs: [current-log]
  adversarialCases:
    - scenarioId: QA-stale-B7-completion
      criterionReference: reviewer correction 1
      adversarialClass: contradictory deferred-work completion
      expectedBehavior: No checked B7 action; workload prose and consequences move traffic accounting to F.
      exactInvocation: "python3 - <<'PY' # ADR reviewer-criterion assertions (C1 in current-log)"
      verdict: PASS
      artifactRefs: [current-log, corrected-adr]
    - scenarioId: QA-deployment-conflation
      criterionReference: reviewer corrections 2-3
      adversarialClass: conflating URL derivation with independent TLS address and populated defaults
      expectedBehavior: Documentation distinguishes empty control constants from populated anchors and neutral SNI, and names the independent TLS address parser.
      exactInvocation: "python3 - <<'PY' # ADR reviewer-criterion assertions (C2/C3 in current-log)"
      verdict: PASS
      artifactRefs: [current-log, deployment-source]
    - scenarioId: QA-premature-final-acceptance
      criterionReference: reviewer correction 4
      adversarialClass: partial verification presented as final acceptance
      expectedBehavior: B9 remains unchecked; historical check failure is disclosed; checked implementation entries name current passing tests; B10 does not claim a Windows CI execution.
      exactInvocation: "python3 - <<'PY' # ADR reviewer-criterion assertions (C4 in current-log); go test -count=1 -v ./cmd/mayak ./cmd/mayak-ctrl ./internal/runner"
      verdict: PASS
      artifactRefs: [current-log, corrected-adr]
    - scenarioId: QA-runtime-input-attacks
      criterionReference: scope of documentation correction
      adversarialClass: new HTTP input validation or GUI interactions
      expectedBehavior: not_applicable because this change edits only ADR prose and introduces no runtime input or UI surface.
      verdict: not_applicable
      artifactRefs: [corrected-adr]
  artifactRefs:
    - id: current-log
      kind: command-output-and-diff
      description: Preserved historical log followed by fresh full package output, exact required grep and whitespace check, numbered env.go, SPEC wording, full ADR diff, make check exit 0, and consistency assertion results.
      path: .omo/evidence/mayak-block-b-finish/task-8-adr.log
    - id: corrected-adr
      kind: document
      description: Russian ADR with the four reviewer corrections and B9 left unchecked.
      path: docs/adr/ADR-006-agent-check.md
    - id: deployment-source
      kind: source
      description: Independently inspected production defaults and separate ControlTLS parser; unchanged by this executor.
      path: cmd/mayak/env.go
```

No application server or persistent background process was started. Package tests use their own temporary resources. No commits were created. Markdown language-server diagnostics are unavailable because this environment has no server configured for `.md`; the edited prose was read directly and whitespace and executable consistency checks passed. Windows CI and the complete block-B final acceptance were not executed or claimed by this documentation correction.
