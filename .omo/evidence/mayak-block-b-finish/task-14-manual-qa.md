```json
{
  "manualQa": {
    "surfaceEvidence": [
      {
        "scenarioId": "F2-07-01",
        "criterionRef": "F2-07 deciding stage and classifier precedence",
        "surface": "Go classification -> BuildReport -> JSON -> report.Validate: TestReportProvenance/all_clear",
        "exactInvocation": "go test ./internal/runner -run \"TestReportProvenance|TestBuildReportMissingOrInvalidTest|TestCheckVerdicts\" -count=1 -v",
        "verdict": "PASS",
        "observed": "ok/http",
        "artifactRefs": [
          "run-log",
          "smoke-json"
        ]
      },
      {
        "scenarioId": "F2-07-02",
        "criterionRef": "F2-07 deciding stage and classifier precedence",
        "surface": "Go classification -> BuildReport -> JSON -> report.Validate: TestReportProvenance/system_DNS_failure_otherwise_green",
        "exactInvocation": "go test ./internal/runner -run \"TestReportProvenance|TestBuildReportMissingOrInvalidTest|TestCheckVerdicts\" -count=1 -v",
        "verdict": "PASS",
        "observed": "timeout_unknown/dns",
        "artifactRefs": [
          "run-log",
          "smoke-json"
        ]
      },
      {
        "scenarioId": "F2-07-03",
        "criterionRef": "F2-07 deciding stage and classifier precedence",
        "surface": "Go classification -> BuildReport -> JSON -> report.Validate: TestReportProvenance/unexplained_target_SNI_timeout",
        "exactInvocation": "go test ./internal/runner -run \"TestReportProvenance|TestBuildReportMissingOrInvalidTest|TestCheckVerdicts\" -count=1 -v",
        "verdict": "PASS",
        "observed": "timeout_unknown/tls_sni",
        "artifactRefs": [
          "run-log",
          "smoke-json"
        ]
      },
      {
        "scenarioId": "F2-07-04",
        "criterionRef": "F2-07 deciding stage and classifier precedence",
        "surface": "Go classification -> BuildReport -> JSON -> report.Validate: TestReportProvenance/HTTP_timeout_after_good_TLS",
        "exactInvocation": "go test ./internal/runner -run \"TestReportProvenance|TestBuildReportMissingOrInvalidTest|TestCheckVerdicts\" -count=1 -v",
        "verdict": "PASS",
        "observed": "timeout_unknown/http",
        "artifactRefs": [
          "run-log",
          "smoke-json"
        ]
      },
      {
        "scenarioId": "F2-07-05",
        "criterionRef": "F2-07 deciding stage and classifier precedence",
        "surface": "Go classification -> BuildReport -> JSON -> report.Validate: TestReportProvenance/TCP_failure_external_down",
        "exactInvocation": "go test ./internal/runner -run \"TestReportProvenance|TestBuildReportMissingOrInvalidTest|TestCheckVerdicts\" -count=1 -v",
        "verdict": "PASS",
        "observed": "vendor_down/tcp",
        "artifactRefs": [
          "run-log",
          "smoke-json"
        ]
      },
      {
        "scenarioId": "F2-07-06",
        "criterionRef": "F2-07 deciding stage and classifier precedence",
        "surface": "Go classification -> BuildReport -> JSON -> report.Validate: TestReportProvenance/TLS_failure_external_down",
        "exactInvocation": "go test ./internal/runner -run \"TestReportProvenance|TestBuildReportMissingOrInvalidTest|TestCheckVerdicts\" -count=1 -v",
        "verdict": "PASS",
        "observed": "vendor_down/tls_sni",
        "artifactRefs": [
          "run-log",
          "smoke-json"
        ]
      },
      {
        "scenarioId": "F2-07-07",
        "criterionRef": "F2-07 deciding stage and classifier precedence",
        "surface": "Go classification -> BuildReport -> JSON -> report.Validate: TestReportProvenance/HTTP_failure_external_down",
        "exactInvocation": "go test ./internal/runner -run \"TestReportProvenance|TestBuildReportMissingOrInvalidTest|TestCheckVerdicts\" -count=1 -v",
        "verdict": "PASS",
        "observed": "vendor_down/http",
        "artifactRefs": [
          "run-log",
          "smoke-json"
        ]
      },
      {
        "scenarioId": "F2-07-08",
        "criterionRef": "F2-07 deciding stage and classifier precedence",
        "surface": "Go classification -> BuildReport -> JSON -> report.Validate: TestReportProvenance/control_failure",
        "exactInvocation": "go test ./internal/runner -run \"TestReportProvenance|TestBuildReportMissingOrInvalidTest|TestCheckVerdicts\" -count=1 -v",
        "verdict": "PASS",
        "observed": "inconclusive/ctrl",
        "artifactRefs": [
          "run-log",
          "smoke-json"
        ]
      },
      {
        "scenarioId": "F2-07-09",
        "criterionRef": "F2-07 deciding stage and classifier precedence",
        "surface": "Go classification -> BuildReport -> JSON -> report.Validate: TestReportProvenance/allowlist_mode",
        "exactInvocation": "go test ./internal/runner -run \"TestReportProvenance|TestBuildReportMissingOrInvalidTest|TestCheckVerdicts\" -count=1 -v",
        "verdict": "PASS",
        "observed": "allowlist_mode/ctrl",
        "artifactRefs": [
          "run-log",
          "smoke-json"
        ]
      },
      {
        "scenarioId": "F2-07-10",
        "criterionRef": "F2-07 deciding stage and classifier precedence",
        "surface": "Go classification -> BuildReport -> JSON -> report.Validate: TestReportProvenance/DNS_tamper_precedes_TCP_failure",
        "exactInvocation": "go test ./internal/runner -run \"TestReportProvenance|TestBuildReportMissingOrInvalidTest|TestCheckVerdicts\" -count=1 -v",
        "verdict": "PASS",
        "observed": "dns_tamper/dns",
        "artifactRefs": [
          "run-log",
          "smoke-json"
        ]
      },
      {
        "scenarioId": "F2-07-11",
        "criterionRef": "F2-07 deciding stage and classifier precedence",
        "surface": "Go classification -> BuildReport -> JSON -> report.Validate: TestReportProvenance/no_trusted_DNS_answer",
        "exactInvocation": "go test ./internal/runner -run \"TestReportProvenance|TestBuildReportMissingOrInvalidTest|TestCheckVerdicts\" -count=1 -v",
        "verdict": "PASS",
        "observed": "inconclusive/dns",
        "artifactRefs": [
          "run-log",
          "smoke-json"
        ]
      },
      {
        "scenarioId": "F2-07-12",
        "criterionRef": "F2-07 deciding stage and classifier precedence",
        "surface": "Go classification -> BuildReport -> JSON -> report.Validate: TestReportProvenance/unverified_DNS_answer",
        "exactInvocation": "go test ./internal/runner -run \"TestReportProvenance|TestBuildReportMissingOrInvalidTest|TestCheckVerdicts\" -count=1 -v",
        "verdict": "PASS",
        "observed": "inconclusive/dns",
        "artifactRefs": [
          "run-log",
          "smoke-json"
        ]
      },
      {
        "scenarioId": "F2-07-13",
        "criterionRef": "F2-07 deciding stage and classifier precedence",
        "surface": "Go classification -> BuildReport -> JSON -> report.Validate: TestReportProvenance/TCP_block",
        "exactInvocation": "go test ./internal/runner -run \"TestReportProvenance|TestBuildReportMissingOrInvalidTest|TestCheckVerdicts\" -count=1 -v",
        "verdict": "PASS",
        "observed": "ip_block/tcp",
        "artifactRefs": [
          "run-log",
          "smoke-json"
        ]
      },
      {
        "scenarioId": "F2-07-14",
        "criterionRef": "F2-07 deciding stage and classifier precedence",
        "surface": "Go classification -> BuildReport -> JSON -> report.Validate: TestReportProvenance/TCP_contradiction",
        "exactInvocation": "go test ./internal/runner -run \"TestReportProvenance|TestBuildReportMissingOrInvalidTest|TestCheckVerdicts\" -count=1 -v",
        "verdict": "PASS",
        "observed": "inconclusive/tcp",
        "artifactRefs": [
          "run-log",
          "smoke-json"
        ]
      },
      {
        "scenarioId": "F2-07-15",
        "criterionRef": "F2-07 deciding stage and classifier precedence",
        "surface": "Go classification -> BuildReport -> JSON -> report.Validate: TestReportProvenance/TCP_not_run",
        "exactInvocation": "go test ./internal/runner -run \"TestReportProvenance|TestBuildReportMissingOrInvalidTest|TestCheckVerdicts\" -count=1 -v",
        "verdict": "PASS",
        "observed": "inconclusive/tcp",
        "artifactRefs": [
          "run-log",
          "smoke-json"
        ]
      },
      {
        "scenarioId": "F2-07-16",
        "criterionRef": "F2-07 deciding stage and classifier precedence",
        "surface": "Go classification -> BuildReport -> JSON -> report.Validate: TestReportProvenance/SNI_block",
        "exactInvocation": "go test ./internal/runner -run \"TestReportProvenance|TestBuildReportMissingOrInvalidTest|TestCheckVerdicts\" -count=1 -v",
        "verdict": "PASS",
        "observed": "sni_block/tls_sni",
        "artifactRefs": [
          "run-log",
          "smoke-json"
        ]
      },
      {
        "scenarioId": "F2-07-17",
        "criterionRef": "F2-07 deciding stage and classifier precedence",
        "surface": "Go classification -> BuildReport -> JSON -> report.Validate: TestReportProvenance/invalid_target_certificate",
        "exactInvocation": "go test ./internal/runner -run \"TestReportProvenance|TestBuildReportMissingOrInvalidTest|TestCheckVerdicts\" -count=1 -v",
        "verdict": "PASS",
        "observed": "tls_intercept/tls_sni",
        "artifactRefs": [
          "run-log",
          "smoke-json"
        ]
      },
      {
        "scenarioId": "F2-07-18",
        "criterionRef": "F2-07 deciding stage and classifier precedence",
        "surface": "Go classification -> BuildReport -> JSON -> report.Validate: TestReportProvenance/TLS_unexplained_reset",
        "exactInvocation": "go test ./internal/runner -run \"TestReportProvenance|TestBuildReportMissingOrInvalidTest|TestCheckVerdicts\" -count=1 -v",
        "verdict": "PASS",
        "observed": "inconclusive/tls_sni",
        "artifactRefs": [
          "run-log",
          "smoke-json"
        ]
      },
      {
        "scenarioId": "F2-07-19",
        "criterionRef": "F2-07 deciding stage and classifier precedence",
        "surface": "Go classification -> BuildReport -> JSON -> report.Validate: TestReportProvenance/TLS_not_run",
        "exactInvocation": "go test ./internal/runner -run \"TestReportProvenance|TestBuildReportMissingOrInvalidTest|TestCheckVerdicts\" -count=1 -v",
        "verdict": "PASS",
        "observed": "inconclusive/tls_sni",
        "artifactRefs": [
          "run-log",
          "smoke-json"
        ]
      },
      {
        "scenarioId": "F2-07-20",
        "criterionRef": "F2-07 deciding stage and classifier precedence",
        "surface": "Go classification -> BuildReport -> JSON -> report.Validate: TestReportProvenance/HTTP_stub_before_geoblock",
        "exactInvocation": "go test ./internal/runner -run \"TestReportProvenance|TestBuildReportMissingOrInvalidTest|TestCheckVerdicts\" -count=1 -v",
        "verdict": "PASS",
        "observed": "http_stub/http",
        "artifactRefs": [
          "run-log",
          "smoke-json"
        ]
      },
      {
        "scenarioId": "F2-07-21",
        "criterionRef": "F2-07 deciding stage and classifier precedence",
        "surface": "Go classification -> BuildReport -> JSON -> report.Validate: TestReportProvenance/HTTP_geoblock",
        "exactInvocation": "go test ./internal/runner -run \"TestReportProvenance|TestBuildReportMissingOrInvalidTest|TestCheckVerdicts\" -count=1 -v",
        "verdict": "PASS",
        "observed": "vendor_geoblock/http",
        "artifactRefs": [
          "run-log",
          "smoke-json"
        ]
      },
      {
        "scenarioId": "F2-07-22",
        "criterionRef": "F2-07 deciding stage and classifier precedence",
        "surface": "Go classification -> BuildReport -> JSON -> report.Validate: TestReportProvenance/HTTP_unexplained_reset",
        "exactInvocation": "go test ./internal/runner -run \"TestReportProvenance|TestBuildReportMissingOrInvalidTest|TestCheckVerdicts\" -count=1 -v",
        "verdict": "PASS",
        "observed": "inconclusive/http",
        "artifactRefs": [
          "run-log",
          "smoke-json"
        ]
      },
      {
        "scenarioId": "F2-07-23",
        "criterionRef": "F2-07 deciding stage and classifier precedence",
        "surface": "Go classification -> BuildReport -> JSON -> report.Validate: TestReportProvenance/QUIC_block",
        "exactInvocation": "go test ./internal/runner -run \"TestReportProvenance|TestBuildReportMissingOrInvalidTest|TestCheckVerdicts\" -count=1 -v",
        "verdict": "PASS",
        "observed": "quic_block/quic",
        "artifactRefs": [
          "run-log",
          "smoke-json"
        ]
      },
      {
        "scenarioId": "F2-07-24",
        "criterionRef": "F2-07 deciding stage and classifier precedence",
        "surface": "Go classification -> BuildReport -> JSON -> report.Validate: TestReportProvenance/DNS_system_failure_defers_to_TLS",
        "exactInvocation": "go test ./internal/runner -run \"TestReportProvenance|TestBuildReportMissingOrInvalidTest|TestCheckVerdicts\" -count=1 -v",
        "verdict": "PASS",
        "observed": "timeout_unknown/tls_sni",
        "artifactRefs": [
          "run-log",
          "smoke-json"
        ]
      },
      {
        "scenarioId": "F2-07-25",
        "criterionRef": "F2-07 deciding stage and classifier precedence",
        "surface": "Go classification -> BuildReport -> JSON -> report.Validate: TestReportProvenance/DNS_system_failure_defers_to_QUIC",
        "exactInvocation": "go test ./internal/runner -run \"TestReportProvenance|TestBuildReportMissingOrInvalidTest|TestCheckVerdicts\" -count=1 -v",
        "verdict": "PASS",
        "observed": "quic_block/quic",
        "artifactRefs": [
          "run-log",
          "smoke-json"
        ]
      },
      {
        "scenarioId": "CHECK-clean_target_is_ok",
        "criterionRef": "F2-07 runner.Check captures actual deciding test",
        "surface": "Go runner.Check with real loopback mock DNS/TCP/TLS/HTTP services: clean_target_is_ok",
        "exactInvocation": "go test ./internal/runner -run \"TestReportProvenance|TestBuildReportMissingOrInvalidTest|TestCheckVerdicts\" -count=1 -v",
        "verdict": "PASS",
        "artifactRefs": [
          "run-log"
        ]
      },
      {
        "scenarioId": "CHECK-reset_after_hello_is_sni_block",
        "criterionRef": "F2-07 runner.Check captures actual deciding test",
        "surface": "Go runner.Check with real loopback mock DNS/TCP/TLS/HTTP services: reset_after_hello_is_sni_block",
        "exactInvocation": "go test ./internal/runner -run \"TestReportProvenance|TestBuildReportMissingOrInvalidTest|TestCheckVerdicts\" -count=1 -v",
        "verdict": "PASS",
        "artifactRefs": [
          "run-log"
        ]
      },
      {
        "scenarioId": "CHECK-dns_spoof_is_dns_tamper",
        "criterionRef": "F2-07 runner.Check captures actual deciding test",
        "surface": "Go runner.Check with real loopback mock DNS/TCP/TLS/HTTP services: dns_spoof_is_dns_tamper",
        "exactInvocation": "go test ./internal/runner -run \"TestReportProvenance|TestBuildReportMissingOrInvalidTest|TestCheckVerdicts\" -count=1 -v",
        "verdict": "PASS",
        "artifactRefs": [
          "run-log"
        ]
      },
      {
        "scenarioId": "CHECK-stub_page_is_http_stub",
        "criterionRef": "F2-07 runner.Check captures actual deciding test",
        "surface": "Go runner.Check with real loopback mock DNS/TCP/TLS/HTTP services: stub_page_is_http_stub",
        "exactInvocation": "go test ./internal/runner -run \"TestReportProvenance|TestBuildReportMissingOrInvalidTest|TestCheckVerdicts\" -count=1 -v",
        "verdict": "PASS",
        "artifactRefs": [
          "run-log"
        ]
      },
      {
        "scenarioId": "CHECK-closed_port_is_ip_block",
        "criterionRef": "F2-07 runner.Check captures actual deciding test",
        "surface": "Go runner.Check with real loopback mock DNS/TCP/TLS/HTTP services: closed_port_is_ip_block",
        "exactInvocation": "go test ./internal/runner -run \"TestReportProvenance|TestBuildReportMissingOrInvalidTest|TestCheckVerdicts\" -count=1 -v",
        "verdict": "PASS",
        "artifactRefs": [
          "run-log"
        ]
      },
      {
        "scenarioId": "CHECK-blackhole_is_timeout_unknown",
        "criterionRef": "F2-07 runner.Check captures actual deciding test",
        "surface": "Go runner.Check with real loopback mock DNS/TCP/TLS/HTTP services: blackhole_is_timeout_unknown",
        "exactInvocation": "go test ./internal/runner -run \"TestReportProvenance|TestBuildReportMissingOrInvalidTest|TestCheckVerdicts\" -count=1 -v",
        "verdict": "PASS",
        "artifactRefs": [
          "run-log"
        ]
      }
    ],
    "adversarialCases": [
      {
        "scenarioId": "ADV-TCP_contradiction",
        "criterionRef": "F2-07 preserve first deciding rule",
        "adversarialClass": "contradictory observations",
        "expectedBehavior": "inconclusive/tcp",
        "verdict": "PASS",
        "artifactRefs": [
          "run-log",
          "smoke-json"
        ]
      },
      {
        "scenarioId": "ADV-DNS_tamper_precedes_TCP_failure",
        "criterionRef": "F2-07 preserve first deciding rule",
        "adversarialClass": "simultaneous layer failures",
        "expectedBehavior": "dns_tamper/dns",
        "verdict": "PASS",
        "artifactRefs": [
          "run-log",
          "smoke-json"
        ]
      },
      {
        "scenarioId": "ADV-HTTP_stub_before_geoblock",
        "criterionRef": "F2-07 preserve first deciding rule",
        "adversarialClass": "overlapping HTTP rules",
        "expectedBehavior": "http_stub/http",
        "verdict": "PASS",
        "artifactRefs": [
          "run-log",
          "smoke-json"
        ]
      },
      {
        "scenarioId": "ADV-DNS_system_failure_defers_to_TLS",
        "criterionRef": "F2-07 preserve first deciding rule",
        "adversarialClass": "deferred DNS failure",
        "expectedBehavior": "timeout_unknown/tls_sni",
        "verdict": "PASS",
        "artifactRefs": [
          "run-log",
          "smoke-json"
        ]
      },
      {
        "scenarioId": "ADV-DNS_system_failure_defers_to_QUIC",
        "criterionRef": "F2-07 preserve first deciding rule",
        "adversarialClass": "deferred DNS failure",
        "expectedBehavior": "quic_block/quic",
        "verdict": "PASS",
        "artifactRefs": [
          "run-log",
          "smoke-json"
        ]
      },
      {
        "scenarioId": "ADV-no_trusted_DNS_answer",
        "criterionRef": "F2-07 preserve first deciding rule",
        "adversarialClass": "missing trusted data",
        "expectedBehavior": "inconclusive/dns",
        "verdict": "PASS",
        "artifactRefs": [
          "run-log",
          "smoke-json"
        ]
      },
      {
        "scenarioId": "ADV-unverified_DNS_answer",
        "criterionRef": "F2-07 preserve first deciding rule",
        "adversarialClass": "unverified data",
        "expectedBehavior": "inconclusive/dns",
        "verdict": "PASS",
        "artifactRefs": [
          "run-log",
          "smoke-json"
        ]
      },
      {
        "scenarioId": "ADV-TCP_not_run",
        "criterionRef": "F2-07 preserve first deciding rule",
        "adversarialClass": "missing observations",
        "expectedBehavior": "inconclusive/tcp",
        "verdict": "PASS",
        "artifactRefs": [
          "run-log",
          "smoke-json"
        ]
      },
      {
        "scenarioId": "ADV-TLS_not_run",
        "criterionRef": "F2-07 preserve first deciding rule",
        "adversarialClass": "missing observations",
        "expectedBehavior": "inconclusive/tls_sni",
        "verdict": "PASS",
        "artifactRefs": [
          "run-log",
          "smoke-json"
        ]
      },
      {
        "scenarioId": "ADV-test-#00",
        "criterionRef": "F2-07 refuse missing provenance",
        "adversarialClass": "empty deciding test",
        "expectedBehavior": "BuildReport error wraps report.ErrInvalid",
        "verdict": "PASS",
        "artifactRefs": [
          "run-log"
        ]
      },
      {
        "scenarioId": "ADV-test-unknown_test",
        "criterionRef": "F2-07 refuse missing provenance",
        "adversarialClass": "invalid deciding test",
        "expectedBehavior": "BuildReport error wraps report.ErrInvalid",
        "verdict": "PASS",
        "artifactRefs": [
          "run-log"
        ]
      },
      {
        "scenarioId": "NA-browser-responsive-layout",
        "criterionRef": "F2-07",
        "adversarialClass": "browser responsive layout",
        "expectedBehavior": "Change has no browser surface.",
        "verdict": "not_applicable",
        "artifactRefs": []
      },
      {
        "scenarioId": "NA-desktop-input-automation",
        "criterionRef": "F2-07",
        "adversarialClass": "desktop input automation",
        "expectedBehavior": "Change has no desktop GUI surface.",
        "verdict": "not_applicable",
        "artifactRefs": []
      },
      {
        "scenarioId": "NA-authentication-and-authorization",
        "criterionRef": "F2-07",
        "adversarialClass": "authentication and authorization",
        "expectedBehavior": "Change has no authentication or authorization boundary.",
        "verdict": "not_applicable",
        "artifactRefs": []
      }
    ],
    "artifactRefs": [
      {
        "id": "run-log",
        "kind": "command-transcript",
        "description": "Red regression, gofmt, repeated package tests, vet, verbose JSON smoke and real loopback probe scenarios, make check blocker",
        "path": "/home/goose/Documents/Mayak-wt/block-b-final/.omo/evidence/mayak-block-b-finish/task-14-report-provenance.log"
      },
      {
        "id": "smoke-json",
        "kind": "json",
        "description": "25 emitted reports independently parsed and matched against expected deciding stages",
        "path": "/home/goose/Documents/Mayak-wt/block-b-final/.omo/evidence/mayak-block-b-finish/task-14-smoke-reports.json"
      },
      {
        "id": "smoke-script",
        "kind": "source",
        "description": "Independent captured JSON verifier and QA matrix producer",
        "path": "/home/goose/Documents/Mayak-wt/block-b-final/.omo/evidence/mayak-block-b-finish/task-14-smoke-validate.py"
      }
    ]
  },
  "blockers": [
    "Repository-wide make check exit 2: formatting of out-of-scope cmd/mayak-ctrl/hardening_test.go. Full repository vet/tests not reached.",
    "LSP diagnostics unavailable: gopls is not installed. Scoped go test and go vet passed."
  ],
  "executionDirectory": "/home/goose/Documents/Mayak-wt/block-b-final",
  "attemptDirectoryResolution": "Toolkit status returned ULW_LOOP_PLAN_MISSING; caller evidence directory used."
}
```
