package targets

import (
	"net/netip"
	"strings"
)

// maxEchoLen is the longest input value that an error message repeats.
const maxEchoLen = 100

// show quotes a value for an error message, cutting it if it is long, so that
// a pull request with a huge field cannot flood a log.
func show(s string) string {
	if len(s) > maxEchoLen {
		return `"` + s[:maxEchoLen] + `..."`
	}
	return `"` + s + `"`
}

// internalZones are names that never belong to a public service.
func internalZones() []string {
	return []string{"localhost", "local", "internal", "lan", "home.arpa", "test", "invalid"}
}

// hostProblem returns why h is not an acceptable target host, or "" if it is.
//
// Only a DNS name is accepted: ASCII, lower case, labels of 1-63 characters
// from [a-z0-9-] that do not start or end with a hyphen, at most 253
// characters, at least two labels. Non-ASCII names must be written in
// punycode (xn--). Addresses, ports, paths, wildcards, user info, schemes, a
// trailing dot and internal zones are refused: the agent connects to what the
// list says, so the list must not point it at the user's own network.
func hostProblem(h string) string {
	switch {
	case h == "":
		return "host is empty"
	case len(h) > 253:
		return "host is longer than 253 characters"
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return "host is an IP address"
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		switch {
		case c >= 0x80:
			return "host is not ASCII (write it in punycode)"
		case c >= 'A' && c <= 'Z':
			return "host has upper-case letters"
		case !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.'):
			return "host has a character that is not allowed (only a-z, 0-9, - and .)"
		}
	}
	for _, zone := range internalZones() {
		if h == zone || strings.HasSuffix(h, "."+zone) {
			return "host is in an internal zone"
		}
	}

	labels := strings.Split(h, ".")
	for _, l := range labels {
		switch {
		case l == "":
			return "host has an empty label (leading, trailing or double dot)"
		case len(l) > 63:
			return "host has a label longer than 63 characters"
		case l[0] == '-' || l[len(l)-1] == '-':
			return "host has a label that starts or ends with a hyphen"
		}
	}
	if len(labels) < 2 {
		return "host needs at least two labels"
	}
	if allDigits(labels[len(labels)-1]) {
		return "host ends in a number, so it is an address, not a name"
	}
	return ""
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}
