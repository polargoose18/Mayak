import json
from pathlib import Path

base = Path(__file__).resolve().parent
log = (base / "task-14-report-provenance.log").read_text()
expected = {
    "all_clear": ("ok", "http"),
    "system_DNS_failure_otherwise_green": ("timeout_unknown", "dns"),
    "unexplained_target_SNI_timeout": ("timeout_unknown", "tls_sni"),
    "HTTP_timeout_after_good_TLS": ("timeout_unknown", "http"),
    "TCP_failure_external_down": ("vendor_down", "tcp"),
    "TLS_failure_external_down": ("vendor_down", "tls_sni"),
    "HTTP_failure_external_down": ("vendor_down", "http"),
    "control_failure": ("inconclusive", "ctrl"),
    "allowlist_mode": ("allowlist_mode", "ctrl"),
    "DNS_tamper_precedes_TCP_failure": ("dns_tamper", "dns"),
    "no_trusted_DNS_answer": ("inconclusive", "dns"),
    "unverified_DNS_answer": ("inconclusive", "dns"),
    "TCP_block": ("ip_block", "tcp"),
    "TCP_contradiction": ("inconclusive", "tcp"),
    "TCP_not_run": ("inconclusive", "tcp"),
    "SNI_block": ("sni_block", "tls_sni"),
    "invalid_target_certificate": ("tls_intercept", "tls_sni"),
    "TLS_unexplained_reset": ("inconclusive", "tls_sni"),
    "TLS_not_run": ("inconclusive", "tls_sni"),
    "HTTP_stub_before_geoblock": ("http_stub", "http"),
    "HTTP_geoblock": ("vendor_geoblock", "http"),
    "HTTP_unexplained_reset": ("inconclusive", "http"),
    "QUIC_block": ("quic_block", "quic"),
    "DNS_system_failure_defers_to_TLS": ("timeout_unknown", "tls_sni"),
    "DNS_system_failure_defers_to_QUIC": ("quic_block", "quic"),
}
seen = {}
scenario = None
for line in log.splitlines():
    if line.startswith("=== RUN   TestReportProvenance/"):
        scenario = line.split("TestReportProvenance/", 1)[1]
    if "validated JSON: " in line:
        assert scenario in expected, scenario
        data = json.loads(line.split("validated JSON: ", 1)[1])
        result = data["results"][0]
        assert (result["verdict"], result["test"]) == expected[scenario], scenario
        assert data["schema"] == "mayak.report/1"
        assert f"--- PASS: TestReportProvenance/{scenario} " in log
        assert scenario not in seen
        seen[scenario] = data
        print(f"PASS {scenario}: {result['verdict']}/{result['test']}; Go report.Validate passed before emission; independent JSON parse passed")
assert seen.keys() == expected.keys()
(base / "task-14-smoke-reports.json").write_text(json.dumps(seen, indent=2) + "\n")

invocation = 'go test ./internal/runner -run "TestReportProvenance|TestBuildReportMissingOrInvalidTest|TestCheckVerdicts" -count=1 -v'
refs = [
    {"id": "run-log", "kind": "command-transcript", "description": "Red regression, gofmt, repeated package tests, vet, verbose JSON smoke and real loopback probe scenarios, make check blocker", "path": str(base / "task-14-report-provenance.log")},
    {"id": "smoke-json", "kind": "json", "description": "25 emitted reports independently parsed and matched against expected deciding stages", "path": str(base / "task-14-smoke-reports.json")},
    {"id": "smoke-script", "kind": "source", "description": "Independent captured JSON verifier and QA matrix producer", "path": str(Path(__file__).resolve())},
]
surface = []
for i, (name, (verdict, test)) in enumerate(expected.items(), 1):
    surface.append({"scenarioId": f"F2-07-{i:02}", "criterionRef": "F2-07 deciding stage and classifier precedence", "surface": f"Go classification -> BuildReport -> JSON -> report.Validate: TestReportProvenance/{name}", "exactInvocation": invocation, "verdict": "PASS", "observed": f"{verdict}/{test}", "artifactRefs": ["run-log", "smoke-json"]})
for name in ["clean_target_is_ok", "reset_after_hello_is_sni_block", "dns_spoof_is_dns_tamper", "stub_page_is_http_stub", "closed_port_is_ip_block", "blackhole_is_timeout_unknown"]:
    assert f"--- PASS: TestCheckVerdicts/{name} " in log
    surface.append({"scenarioId": "CHECK-" + name, "criterionRef": "F2-07 runner.Check captures actual deciding test", "surface": "Go runner.Check with real loopback mock DNS/TCP/TLS/HTTP services: " + name, "exactInvocation": invocation, "verdict": "PASS", "artifactRefs": ["run-log"]})
adversarial = []
for name, cls in [("TCP_contradiction", "contradictory observations"), ("DNS_tamper_precedes_TCP_failure", "simultaneous layer failures"), ("HTTP_stub_before_geoblock", "overlapping HTTP rules"), ("DNS_system_failure_defers_to_TLS", "deferred DNS failure"), ("DNS_system_failure_defers_to_QUIC", "deferred DNS failure"), ("no_trusted_DNS_answer", "missing trusted data"), ("unverified_DNS_answer", "unverified data"), ("TCP_not_run", "missing observations"), ("TLS_not_run", "missing observations")]:
    v, test = expected[name]
    adversarial.append({"scenarioId": "ADV-" + name, "criterionRef": "F2-07 preserve first deciding rule", "adversarialClass": cls, "expectedBehavior": f"{v}/{test}", "verdict": "PASS", "artifactRefs": ["run-log", "smoke-json"]})
for name in ["#00", "unknown_test"]:
    assert f"--- PASS: TestBuildReportMissingOrInvalidTest/{name} " in log
    adversarial.append({"scenarioId": "ADV-test-" + name, "criterionRef": "F2-07 refuse missing provenance", "adversarialClass": "empty deciding test" if name == "#00" else "invalid deciding test", "expectedBehavior": "BuildReport error wraps report.ErrInvalid", "verdict": "PASS", "artifactRefs": ["run-log"]})
for cls, reason in [("browser responsive layout", "Change has no browser surface."), ("desktop input automation", "Change has no desktop GUI surface."), ("authentication and authorization", "Change has no authentication or authorization boundary.")]:
    adversarial.append({"scenarioId": "NA-" + cls.replace(" ", "-"), "criterionRef": "F2-07", "adversarialClass": cls, "expectedBehavior": reason, "verdict": "not_applicable", "artifactRefs": []})
matrix = {"manualQa": {"surfaceEvidence": surface, "adversarialCases": adversarial, "artifactRefs": refs}, "blockers": ["Repository-wide make check exit 2: formatting of out-of-scope cmd/mayak-ctrl/hardening_test.go. Full repository vet/tests not reached.", "LSP diagnostics unavailable: gopls is not installed. Scoped go test and go vet passed."], "executionDirectory": "/home/goose/Documents/Mayak-wt/block-b-final", "attemptDirectoryResolution": "Toolkit status returned ULW_LOOP_PLAN_MISSING; caller evidence directory used."}
(base / "task-14-manual-qa.md").write_text("```json\n" + json.dumps(matrix, indent=2) + "\n```\n")
print(f"PASS independently inspected {len(seen)} reports; QA matrix includes {len(surface)} surface scenarios.")
