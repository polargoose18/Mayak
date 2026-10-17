package runner

import (
	"math/rand/v2"
	"testing"
	"time"
)

// The standard generator is enough for a run, as the Rand comment says.
var _ Rand = (*rand.Rand)(nil)

// The ceilings of SPEC section 5. Other code relies on these values; a change
// here must be a change of the SPEC first.
func TestLimitsMatchSpec(t *testing.T) {
	tests := []struct {
		name      string
		got, want any
	}{
		{"MinLimit", MinLimit, 5},
		{"MaxLimit", MaxLimit, 20},
		{"DefaultLimit", DefaultLimit, 10},
		{"MaxConcurrency", MaxConcurrency, 4},
		{"PauseMin", PauseMin, 200 * time.Millisecond},
		{"PauseMax", PauseMax, 800 * time.Millisecond},
		{"TestTimeout", TestTimeout, 8 * time.Second},
	}
	for _, tc := range tests {
		if tc.got != tc.want {
			t.Errorf("%s = %v, want %v", tc.name, tc.got, tc.want)
		}
	}
	if !(MinLimit <= DefaultLimit && DefaultLimit <= MaxLimit) {
		t.Errorf("DefaultLimit %d is outside %d..%d", DefaultLimit, MinLimit, MaxLimit)
	}
}
