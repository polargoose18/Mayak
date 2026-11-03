package probe

import (
	"context"
	"testing"

	"github.com/polargoose18/mayak/internal/classify"
	"github.com/polargoose18/mayak/testbed/mockdpi"
)

// The RootCAs field of the exported requests is what the runner uses to trust
// the mock certificate (ADR-006, B3 and Q8). These tests make sure the
// exported functions read it and do not fall back to the system roots.

func TestExportedTLSSNIHonoursRootCAs(t *testing.T) {
	env := mockdpi.Start(t, mockdpi.Config{Control: true})
	ctx, cancel := context.WithTimeout(context.Background(), generous)
	defer cancel()

	obs, err := TLSSNI(ctx, TLSSNIRequest{
		TargetAddr:  addr(t, env.ControlTLS),
		ControlAddr: addr(t, env.ControlTLS),
		Host:        targetHost,
		NeutralSNI:  neutralSNI,
		RootCAs:     env.CertPool,
	})
	if err != nil {
		t.Fatal(err)
	}
	if obs.TargetSNI.Outcome != TLSOutcomeOK {
		t.Errorf("target SNI outcome = %q, want ok (RootCAs must be used)", obs.TargetSNI.Outcome)
	}
}

func TestExportedHTTPHonoursRootCAs(t *testing.T) {
	env := mockdpi.Start(t, mockdpi.Config{Control: true, CertNames: []string{dnsHost}})
	ctx, cancel := context.WithTimeout(context.Background(), generous)
	defer cancel()

	obs, err := HTTP(ctx, HTTPRequest{
		Addr:    addr(t, env.ControlTLS),
		Host:    dnsHost,
		Path:    ControlPathRoot,
		RootCAs: env.CertPool,
	})
	if err != nil {
		t.Fatal(err)
	}
	if obs.Result != classify.HTTPResponded {
		t.Errorf("result = %q, want responded (RootCAs must be used)", obs.Result)
	}
}

func TestExportedDNSHonoursRootCAsOverDoT(t *testing.T) {
	env := mockdpi.Start(t, mockdpi.Config{Control: true, CertNames: []string{dnsHost}})
	res, err := DNSAddrCheckRoots(context.Background(), addr(t, env.ControlTLS), dnsHost, env.CertPool)
	if err != nil {
		t.Fatal(err)
	}
	if res != classify.AddrCheckValidCert {
		t.Errorf("addr check = %q, want valid_cert (RootCAs must be used)", res)
	}
}

func TestExportedControlClientHonoursRootCAs(t *testing.T) {
	env := mockdpi.Start(t, mockdpi.Config{Control: true})
	c := ControlClient{BaseURL: "https://" + env.ControlTLS, RootCAs: env.CertPool}
	if err := c.Ping(context.Background()); err != nil {
		t.Errorf("Ping = %v, want nil (RootCAs must be used)", err)
	}
}
