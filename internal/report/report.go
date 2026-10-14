// Package report defines the mayak.report/1 format and its validator.
package report

import "time"

// SchemaID is the only schema identifier accepted by Validate.
const SchemaID = "mayak.report/1"

// Verdict is the outcome of a single test (SPEC sections 5 and 19).
type Verdict string

// Verdicts.
const (
	VerdictOK             Verdict = "ok"
	VerdictDNSTamper      Verdict = "dns_tamper"
	VerdictIPBlock        Verdict = "ip_block"
	VerdictSNIBlock       Verdict = "sni_block"
	VerdictTLSIntercept   Verdict = "tls_intercept"
	VerdictHTTPStub       Verdict = "http_stub"
	VerdictQUICBlock      Verdict = "quic_block"
	VerdictVendorGeoblock Verdict = "vendor_geoblock"
	VerdictTimeoutUnknown Verdict = "timeout_unknown"
	VerdictInconclusive   Verdict = "inconclusive"
	VerdictVendorDown     Verdict = "vendor_down"
	VerdictAllowlistMode  Verdict = "allowlist_mode"
	VerdictFreezeAfterN   Verdict = "freeze_after_n"
	VerdictThrottled      Verdict = "throttled"
)

// Test is the identifier of a measurement test.
type Test string

// Tests.
const (
	TestDNS        Test = "dns"
	TestTCP        Test = "tcp"
	TestTLSSNI     Test = "tls_sni"
	TestHTTP       Test = "http"
	TestQUIC       Test = "quic"
	TestTCPFreeze  Test = "tcp_freeze"
	TestThroughput Test = "throughput"
	TestCtrl       Test = "ctrl"
)

// Agent sources.
const (
	SourceCLI = "cli"
	SourceWeb = "web"
)

// Agent operating systems. Only the family is reported, never the version or
// the architecture, so that the value does not fingerprint a machine.
const (
	OSLinux   = "linux"
	OSWindows = "windows"
	OSDarwin  = "darwin"
	OSAndroid = "android"
	OSIOS     = "ios"
	OSOpenWrt = "openwrt"
	OSOther   = "other"
)

// DNS resolver kinds (net.resolver).
const (
	ResolverISP       = "isp"
	ResolverPublic    = "public"
	ResolverEncrypted = "encrypted"
	ResolverVPN       = "vpn"
	ResolverUnknown   = "unknown"
)

// OSes returns all accepted values of agent.os.
func OSes() []string {
	return []string{OSLinux, OSWindows, OSDarwin, OSAndroid, OSIOS, OSOpenWrt, OSOther}
}

// Resolvers returns all accepted values of net.resolver.
func Resolvers() []string {
	return []string{ResolverISP, ResolverPublic, ResolverEncrypted, ResolverVPN, ResolverUnknown}
}

// Verdicts returns all known verdicts.
func Verdicts() []Verdict {
	return []Verdict{
		VerdictOK, VerdictDNSTamper, VerdictIPBlock, VerdictSNIBlock,
		VerdictTLSIntercept, VerdictHTTPStub, VerdictQUICBlock,
		VerdictVendorGeoblock, VerdictTimeoutUnknown, VerdictInconclusive,
		VerdictVendorDown, VerdictAllowlistMode, VerdictFreezeAfterN,
		VerdictThrottled,
	}
}

// Tests returns all known test identifiers.
func Tests() []Test {
	return []Test{
		TestDNS, TestTCP, TestTLSSNI, TestHTTP, TestQUIC,
		TestTCPFreeze, TestThroughput, TestCtrl,
	}
}

// Report is a mayak.report/1 document.
type Report struct {
	Schema     string    `json:"schema"`
	ReportID   string    `json:"report_id"`
	TS         time.Time `json:"ts"`
	Agent      Agent     `json:"agent"`
	Net        Net       `json:"net"`
	TargetsRev string    `json:"targets_rev"`
	Results    []Result  `json:"results"`
}

// Agent describes the reporting agent.
type Agent struct {
	Ver    string `json:"ver"`
	OS     string `json:"os"`
	Source string `json:"source"`
}

// Net describes the network context. Region is set only when the user
// provided it explicitly.
type Net struct {
	IPVer    int     `json:"ip_ver"`
	Resolver string  `json:"resolver"`
	Country  string  `json:"country"`
	Region   *string `json:"region"`
}

// Result is the outcome of one test against one target.
type Result struct {
	Target   string         `json:"target"`
	Test     Test           `json:"test"`
	Verdict  Verdict        `json:"verdict"`
	Evidence map[string]any `json:"evidence,omitempty"`
}
