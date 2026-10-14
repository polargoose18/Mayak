package report

// Matchers for the free-form text fields. They are written by hand rather
// than with regular expressions; the same patterns are in
// schema/report.schema.json, and a test checks that the two agree.

func isDigit(c byte) bool  { return c >= '0' && c <= '9' }
func isUpper(c byte) bool  { return c >= 'A' && c <= 'Z' }
func isLower(c byte) bool  { return c >= 'a' && c <= 'z' }
func isHexLow(c byte) bool { return isDigit(c) || (c >= 'a' && c <= 'f') }

// allOf reports whether s has min..max bytes, all satisfying ok.
func allOf(s string, min, max int, ok func(byte) bool) bool {
	if len(s) < min || len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !ok(s[i]) {
			return false
		}
	}
	return true
}

// isTargetID matches ^[a-z0-9-]{1,64}$.
func isTargetID(s string) bool {
	return allOf(s, 1, 64, func(c byte) bool { return isLower(c) || isDigit(c) || c == '-' })
}

// isAgentVersion matches ^([0-9]{1,3}\.[0-9]{1,3}|dev)$.
func isAgentVersion(s string) bool {
	if s == "dev" {
		return true
	}
	return splitTwo(s, '.', func(a, b string) bool {
		return allOf(a, 1, 3, isDigit) && allOf(b, 1, 3, isDigit)
	})
}

// isRegion matches ^[A-Z]{2}-[A-Z0-9]{1,3}$.
func isRegion(s string) bool {
	return splitTwo(s, '-', func(a, b string) bool {
		return allOf(a, 2, 2, isUpper) && allOf(b, 1, 3, func(c byte) bool { return isUpper(c) || isDigit(c) })
	})
}

// isTargetsRev matches ^[0-9]{4}-[0-9]{2}-[0-9]{2}\.[0-9]{1,4}$.
func isTargetsRev(s string) bool {
	return splitTwo(s, '.', func(date, n string) bool {
		return allOf(n, 1, 4, isDigit) && len(date) == 10 &&
			allOf(date[0:4], 4, 4, isDigit) && date[4] == '-' &&
			allOf(date[5:7], 2, 2, isDigit) && date[7] == '-' &&
			allOf(date[8:10], 2, 2, isDigit)
	})
}

// splitTwo splits s at the only occurrence of sep and applies f to the parts.
func splitTwo(s string, sep byte, f func(a, b string) bool) bool {
	at := -1
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			if at >= 0 {
				return false
			}
			at = i
		}
	}
	return at >= 0 && f(s[:at], s[at+1:])
}
