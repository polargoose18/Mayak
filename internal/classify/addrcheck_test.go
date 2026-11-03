package classify

import "testing"

// NeedsAddrCheck tells the caller when rule 2 will read
// DNS.SystemAddrCheck. The runner makes the TLS check of a system address
// exactly then (ADR-006, B3).
func TestNeedsAddrCheck(t *testing.T) {
	tests := []struct {
		name string
		dns  DNS
		want bool
	}{
		{
			"system answer overlaps the trusted set",
			DNS{System: answer("203.0.113.10"), Control: answer("203.0.113.10")},
			false,
		},
		{
			"system answer shares no address",
			DNS{System: answer("203.0.113.99"), Control: answer("203.0.113.10")},
			true,
		},
		{
			"no trusted answer at all",
			DNS{System: answer("203.0.113.99"), Control: DNSAnswer{Status: DNSFailure}},
			false,
		},
		{
			"system answer empty",
			DNS{System: DNSAnswer{Status: DNSOK}, Control: answer("203.0.113.10")},
			false,
		},
		{
			"system answer is a failure",
			DNS{System: DNSAnswer{Status: DNSFailure}, Control: answer("203.0.113.10")},
			false,
		},
		{
			"system answer is a bogon",
			DNS{System: answer("10.0.0.99"), Control: answer("203.0.113.10")},
			false,
		},
		{
			"system answer has one bogon and one clean address",
			DNS{System: answer("203.0.113.99", "10.0.0.1"), Control: answer("203.0.113.10")},
			false,
		},
		{
			"trusted set only from the public resolvers",
			DNS{System: answer("203.0.113.99"), Public: []DNSAnswer{answer("203.0.113.10")}},
			true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := NeedsAddrCheck(tc.dns); got != tc.want {
				t.Errorf("NeedsAddrCheck = %v, want %v", got, tc.want)
			}
		})
	}
}
