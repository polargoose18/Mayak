package targets

import (
	"errors"
	"strings"
	"testing"
)

func TestHostProblem(t *testing.T) {
	label63 := strings.Repeat("a", 63)
	name253 := strings.Join([]string{label63, label63, label63, strings.Repeat("a", 61)}, ".") // 63*3+61+3 = 253

	accepted := []string{
		"example.org",
		"sub.example.org",
		"a-b.example.com",
		"1a.example.org",
		"example.co.uk",
		"xn--e1afmkfd.xn--p1ai", // пример.рф in punycode
		"a.bc",
		label63 + ".org",
		name253,
		"x.internal-tools.example.org", // "internal" only matters as the last label
		"testing.example.org",          // not the .test zone
	}
	for _, h := range accepted {
		if got := hostProblem(h); got != "" {
			t.Errorf("hostProblem(%.40q) = %q, want accepted", h, got)
		}
	}

	rejected := []struct {
		host string
		why  string // part of the expected reason
	}{
		{"", "empty"},
		{"example", "two labels"},
		{"Example.com", "upper-case"},
		{"пример.рф", "ASCII"},
		{"exämple.com", "ASCII"},
		{"1.2.3.4", "IP address"},
		{"169.254.169.254", "IP address"},
		{"127.0.0.1", "IP address"},
		{"::1", "IP address"},
		{"2001:db8::1", "IP address"},
		{"[::1]", "not allowed"},
		{"127.1", "number"},
		{"example.123", "number"},
		{"10.0.0.5:8080", "not allowed"},
		{"example.com:443", "not allowed"},
		{"example.com/path?x=1", "not allowed"},
		{"example.com/", "not allowed"},
		{"example.com?x", "not allowed"},
		{"example.com#frag", "not allowed"},
		{"*.example.com", "not allowed"},
		{"user@example.com", "not allowed"},
		{"https://example.com", "not allowed"},
		{"ftp://example.com", "not allowed"},
		{" example.com", "not allowed"},
		{"example.com ", "not allowed"},
		{"exa mple.com", "not allowed"},
		{"example.com\t", "not allowed"},
		{"example_name.com", "not allowed"},
		{"example.com.", "empty label"},
		{".example.com", "empty label"},
		{"a..example.com", "empty label"},
		{"-a.example.com", "hyphen"},
		{"a-.example.com", "hyphen"},
		{"a.-example.com", "hyphen"},
		{strings.Repeat("a", 64) + ".org", "63"},
		{name253 + "a", "253"},
		{"localhost", "internal"},
		{"foo.localhost", "internal"},
		{"printer.local", "internal"},
		{"x.internal", "internal"},
		{"router.lan", "internal"},
		{"x.home.arpa", "internal"},
		{"home.arpa", "internal"},
		{"x.test", "internal"},
		{"x.invalid", "internal"},
	}
	for _, tc := range rejected {
		got := hostProblem(tc.host)
		if got == "" {
			t.Errorf("hostProblem(%.40q) accepted, want a problem with %q", tc.host, tc.why)
			continue
		}
		if !strings.Contains(got, tc.why) {
			t.Errorf("hostProblem(%.40q) = %q, want it to mention %q", tc.host, got, tc.why)
		}
	}
}

func TestValidateRejectsBadHostsAndDuplicates(t *testing.T) {
	for _, host := range []string{"localhost", "169.254.169.254", "10.0.0.5:8080", "example.com/path?x=1", "*.example.com", "user@example.com", "Example.com", "пример.рф"} {
		tr := sample()
		tr.Items[0].Host = host
		if err := tr.validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("host %q: err = %v, want ErrInvalid", host, err)
		}
	}

	tr := sample()
	tr.Items[1].Host = tr.Items[0].Host // two ids, one host
	err := tr.validate()
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "duplicate host") {
		t.Errorf("duplicate host: err = %v", err)
	}
}

func TestErrorsDoNotEchoLongValues(t *testing.T) {
	long := strings.Repeat("x", 300)
	tests := map[string]func(tr *Targets){
		"host": func(tr *Targets) { tr.Items[0].Host = long + ".org" },

		"category":  func(tr *Targets) { tr.Items[0].Category = Category(long) },
		"dup id":    func(tr *Targets) { tr.Items[0].ID, tr.Items[1].ID = long, long },
		"dup host":  func(tr *Targets) { tr.Items[0].Host, tr.Items[1].Host = long, long },
		"punycode":  func(tr *Targets) { tr.Items[0].Host = strings.Repeat("я", 300) },
		"zone name": func(tr *Targets) { tr.Items[0].Host = long + ".local" },
	}
	for name, edit := range tests {
		tr := sample()
		edit(&tr)
		err := tr.validate()
		if err == nil {
			t.Errorf("%s: want an error", name)
			continue
		}
		if len(err.Error()) > 250 {
			t.Errorf("%s: error is %d bytes long, it echoes the input", name, len(err.Error()))
		}
	}

	// A short value is repeated whole.
	if got := show("abc"); got != `"abc"` {
		t.Errorf("show = %s", got)
	}
}
