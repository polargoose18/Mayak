# Task 14 manual QA

Executed in `/home/goose/Documents/Mayak-wt/block-b-final`. The requested implementation and tests appeared in the shared worktree during initial inspection; existing edits were preserved. This executor inspected the actual code and tests, formatted the scoped directories, and independently executed the requested checks. No previous executor's result was used as test evidence.

All scenarios below ran as part of `go test ./internal/classify ./internal/runner -count=2`. The inspected scenario tests contain no skip branches. The evidence contains package-level passing output, rather than verbose per-subtest transcripts. Observation scenarios exercise the real classifier, BuildReport, JSON serialization, and report.Validate. Network scenarios use actual local DNS/TCP/TLS mock servers through runner.Check. They do not claim external-network or CLI UI coverage.

```json
{
  "manualQa": {
    "surfaceEvidence": [
      {"scenarioId":"S01","criterionReference":"F2-07 DNS system failure","surface":"Go observation-to-validated-report API; TestReportProvenance/system_DNS_failure_otherwise_green","exactInvocation":"cd /home/goose/Documents/Mayak-wt/block-b-final && go test ./internal/classify ./internal/runner -count=2","verdict":"PASS","artifactRefs":["A1","A2"]},
      {"scenarioId":"S02","criterionReference":"F2-07 HTTP timeout after successful DNS/TCP/TLS","surface":"Go observation-to-validated-report API; TestReportProvenance/HTTP_timeout_after_good_TLS","exactInvocation":"cd /home/goose/Documents/Mayak-wt/block-b-final && go test ./internal/classify ./internal/runner -count=2","verdict":"PASS","artifactRefs":["A1","A2"]},
      {"scenarioId":"S03","criterionReference":"F2-07 target-SNI timeout with successful control handshake","surface":"Go observation-to-validated-report API; TestReportProvenance/unexplained_target_SNI_timeout","exactInvocation":"cd /home/goose/Documents/Mayak-wt/block-b-final && go test ./internal/classify ./internal/runner -count=2","verdict":"PASS","artifactRefs":["A1","A2"]},
      {"scenarioId":"S04","criterionReference":"F2-07 vendor_down/tcp","surface":"Go observation-to-validated-report API; TestReportProvenance/TCP_failure_external_down","exactInvocation":"cd /home/goose/Documents/Mayak-wt/block-b-final && go test ./internal/classify ./internal/runner -count=2","verdict":"PASS","artifactRefs":["A1","A2"]},
      {"scenarioId":"S05","criterionReference":"F2-07 vendor_down/tls_sni","surface":"Go observation-to-validated-report API; TestReportProvenance/TLS_failure_external_down","exactInvocation":"cd /home/goose/Documents/Mayak-wt/block-b-final && go test ./internal/classify ./internal/runner -count=2","verdict":"PASS","artifactRefs":["A1","A2"]},
      {"scenarioId":"S06","criterionReference":"F2-07 inconclusive/ctrl","surface":"Go observation-to-validated-report API; TestReportProvenance/control_failure","exactInvocation":"cd /home/goose/Documents/Mayak-wt/block-b-final && go test ./internal/classify ./internal/runner -count=2","verdict":"PASS","artifactRefs":["A1","A2"]},
      {"scenarioId":"S07","criterionReference":"F2-07 ok/http","surface":"Go observation-to-validated-report API and local network runner.Check; TestReportProvenance/all_clear and TestCheckVerdicts/clean_target_is_ok","exactInvocation":"cd /home/goose/Documents/Mayak-wt/block-b-final && go test ./internal/classify ./internal/runner -count=2","verdict":"PASS","artifactRefs":["A1","A2","A3"]},
      {"scenarioId":"S08","criterionReference":"F2-07 runner.Check retains deciding stage","surface":"Local mock DNS/TCP/TLS network; TestCheckVerdicts reset-after-hello, DNS spoof, stub page, closed port, and blackhole scenarios","exactInvocation":"cd /home/goose/Documents/Mayak-wt/block-b-final && go test ./internal/classify ./internal/runner -count=2","verdict":"PASS","artifactRefs":["A1","A3"]}
    ],
    "adversarialCases": [
      {"scenarioId":"A01","criterionReference":"F2-07 reject missing deciding Test","adversarialClass":"Missing or unknown provenance","expectedBehavior":"BuildReport rejects empty and unknown Test with errors.Is(err, report.ErrInvalid).","verdict":"PASS","artifactRefs":["A1","A4"]},
      {"scenarioId":"A02","criterionReference":"F2-07 first deciding stage","adversarialClass":"Contradictory observations","expectedBehavior":"TCP timeout with completed TLS produces inconclusive/tcp, never a verdict-derived ctrl stage.","verdict":"PASS","artifactRefs":["A1","A2"]},
      {"scenarioId":"A03","criterionReference":"F2-07 preserve Classify order","adversarialClass":"Multiple failures compete","expectedBehavior":"DNS tamper precedes TCP failure; deferred system DNS failure yields to deciding TLS or QUIC rules.","verdict":"PASS","artifactRefs":["A1","A2"]},
      {"scenarioId":"A04","criterionReference":"F2-07 actual vendor_down stage","adversarialClass":"Same verdict from distinct origins","expectedBehavior":"TCP, TLS and HTTP external-unreachable failures retain tcp, tls_sni and http respectively through report.Validate.","verdict":"PASS","artifactRefs":["A1","A2"]},
      {"scenarioId":"A05","criterionReference":"F2-07 compatibility wrapper","adversarialClass":"Existing caller compatibility","expectedBehavior":"Classify equals ClassifyWithTest's verdict for every observation scenario; existing classifier tests pass.","verdict":"PASS","artifactRefs":["A1","A2"]},
      {"scenarioId":"A06","criterionReference":"F2-07 scope","adversarialClass":"Browser and desktop presentation","expectedBehavior":"Not applicable: the change is classifier and report data provenance, with no browser or desktop surface.","verdict":"not_applicable","artifactRefs":[]}
    ],
    "artifactRefs": [
      {"id":"A1","kind":"execution_log","description":"Independently inspected non-empty log: gofmt exit 0; both requested packages pass with count=2; go vet exit 0.","path":"/home/goose/Documents/Mayak/.omo/evidence/mayak-block-b-finish/task-14-report-provenance.log"},
      {"id":"A2","kind":"test_source","description":"Inspected actual observation scenarios, compatibility assertions, BuildReport serialization and report.Validate checks.","path":"/home/goose/Documents/Mayak-wt/block-b-final/internal/runner/provenance_test.go"},
      {"id":"A3","kind":"test_source","description":"Inspected real local mock network tests asserting runner.Check deciding stages.","path":"/home/goose/Documents/Mayak-wt/block-b-final/internal/runner/target_test.go"},
      {"id":"A4","kind":"test_source","description":"Inspected explicit ErrInvalid rejection tests for missing and unknown deciding Test.","path":"/home/goose/Documents/Mayak-wt/block-b-final/internal/runner/report_test.go"}
    ]
  }
}
```

Diagnostics: gopls is unavailable; the language-server diagnostic call could not run. The requested go vet check passed. Repository-wide tests were not run, as explicitly instructed. No commit was created.
