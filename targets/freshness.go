package targets

import (
	"fmt"
	"time"
)

// freshEnough reports whether a targets list that expires at expires stays
// usable for at least warn from now. It is the freshness guard behind
// TestEmbeddedListFreshness (make targets-expiry): it fails before the
// built-in list expires so the owner re-signs it in time.
func freshEnough(expires, now time.Time, warn time.Duration) error {
	if expires.IsZero() {
		return fmt.Errorf("targets list has no expiry date")
	}
	if !now.Add(warn).Before(expires) {
		return fmt.Errorf(
			"targets list expires %s, which is within %s of now (%s); re-sign it:\n"+
				"  go run ./cmd/mayak-sign sign --key <key> --in targets/targets.json --out targets/targets.signed.json\n"+
				"  make sign-check",
			expires.Format(time.RFC3339), warn, now.Format(time.RFC3339))
	}
	return nil
}
