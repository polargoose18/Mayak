package runner

import (
	"encoding/json"
	"fmt"

	"github.com/polargoose18/mayak/internal/report"
	"time"
)

// ReportMeta is the context one run is reported with.
type ReportMeta struct {
	Ver      string
	OS       string
	Rev      string
	Now      time.Time
	IPVer    int
	Resolver string
}

// verdictTest maps a classifier verdict to the report test that produced it.
var verdictTest = map[report.Verdict]report.Test{
	report.VerdictOK:             report.TestHTTP,
	report.VerdictDNSTamper:      report.TestDNS,
	report.VerdictTimeoutUnknown: report.TestDNS,
	report.VerdictIPBlock:        report.TestTCP,
	report.VerdictVendorDown:     report.TestTCP,
	report.VerdictSNIBlock:       report.TestTLSSNI,
	report.VerdictTLSIntercept:   report.TestTLSSNI,
	report.VerdictHTTPStub:       report.TestHTTP,
	report.VerdictVendorGeoblock: report.TestHTTP,
	report.VerdictQUICBlock:      report.TestQUIC,
	report.VerdictInconclusive:   report.TestCtrl,
	report.VerdictAllowlistMode:  report.TestCtrl,
	report.VerdictFreezeAfterN:   report.TestTCPFreeze,
	report.VerdictThrottled:      report.TestThroughput,
}

// OSName converts a Go runtime GOOS to the report's agent.os family.
func OSName(goos string) string {
	switch goos {
	case "linux":
		return report.OSLinux
	case "windows":
		return report.OSWindows
	case "darwin":
		return report.OSDarwin
	case "android":
		return report.OSAndroid
	case "ios":
		return report.OSIOS
	}
	return report.OSOther
}

// IPVersion returns the IP version of the first trusted address seen in the
// run, or 4 when there is none.
func IPVersion(results []Result) int {
	for _, r := range results {
		if addr, ok := trustedAddr(r.Observation.DNS); ok {
			if addr.Is6() {
				return 6
			}
			return 4
		}
	}
	return 4
}

// BuildReport turns one run's results into a mayak.report/1 document. The
// document is checked with report.Validate before it is returned, so a
// caller can never hold an invalid report.
func BuildReport(meta ReportMeta, results []Result) (report.Report, error) {
	out := report.Report{
		Schema:     report.SchemaID,
		ReportID:   report.NewReportID(),
		TS:         meta.Now,
		Agent:      report.Agent{Ver: meta.Ver, OS: meta.OS, Source: report.SourceCLI},
		Net:        report.Net{IPVer: meta.IPVer, Resolver: meta.Resolver},
		TargetsRev: meta.Rev,
	}
	for _, r := range results {
		test, ok := verdictTest[r.Verdict]
		if !ok {
			return report.Report{}, fmt.Errorf("build report: %w: unknown verdict", report.ErrInvalid)
		}
		out.Results = append(out.Results, report.Result{
			Target:   r.Target.ID,
			Test:     test,
			Verdict:  r.Verdict,
			Evidence: evidence(r),
		})
	}
	data, err := json.Marshal(out)
	if err != nil {
		return report.Report{}, fmt.Errorf("build report: encode: %w", err)
	}
	if _, err := report.Validate(data); err != nil {
		// Preserve the specific cause but always expose ErrInvalid, the
		// caller's contract is "invalid or too large reports cannot be built".
		return report.Report{}, fmt.Errorf("build report: %w: %w", report.ErrInvalid, err)
	}
	return out, nil
}

// evidence collects the scalar observations of one result. Only non-zero
// values are kept, so an untouched probe contributes no key; no host names,
// addresses or bodies ever reach the report.
func evidence(r Result) map[string]any {
	ev := map[string]any{}
	setStr := func(k, v string) {
		if v != "" {
			ev[k] = v
		}
	}
	setInt := func(k string, v int64) {
		if v != 0 {
			ev[k] = v
		}
	}
	if r.Ctrl.ControlAlive {
		ev["ctrl_alive"] = true
	}
	if r.Ctrl.AnchorsAlive {
		ev["anchors_alive"] = true
	}
	if r.Ctrl.AllowlistAlive {
		ev["allowlist_alive"] = true
	}
	setStr("external", string(r.Ctrl.TargetExternal))
	setStr("dns_system", string(r.DNS.System.Status))
	setStr("dns_control", string(r.DNS.Control.Status))
	setStr("tcp", string(r.TCP.Result))
	setStr("tls_target_sni", string(r.Observation.TLS.TargetSNI))
	setStr("tls_neutral_sni", string(r.Observation.TLS.NeutralSNI))
	setStr("tls_via_control", string(r.Observation.TLS.TargetSNIViaControl))
	// The classifier's view and the probe's own result carry the same HTTP
	// facts; either may be set depending on how the check stopped, so take
	// the first non-zero of each.
	h := r.Observation.HTTP
	if h.Result == "" {
		h.Result = r.HTTP.Result
	}
	if h.Response.Status == 0 && h.Response.Size == 0 && h.Response.BodyHash == "" {
		h.Response = r.HTTP.Response
	}
	setStr("http_result", string(h.Result))
	if h.Response.Status != 0 {
		ev["http_status"] = h.Response.Status
	}
	setInt("http_size", h.Response.Size)
	setStr("http_hash", h.Response.BodyHash)
	setInt("ms", r.Duration.Milliseconds())
	if len(ev) == 0 {
		return nil
	}
	return ev
}
