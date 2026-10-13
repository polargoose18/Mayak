package report

import "testing"

func TestNewReportID(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := NewReportID()
		if !isReportID(id) {
			t.Fatalf("NewReportID() = %q, not 10 lowercase hex chars", id)
		}
		seen[id] = true
	}
	if len(seen) < 99 {
		t.Errorf("only %d distinct IDs in 100 calls", len(seen))
	}
}
