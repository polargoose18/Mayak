package targets

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// items returns n targets with ids t00, t01, ...
func items(n int) []Target {
	out := make([]Target, n)
	for i := range out {
		out[i] = Target{ID: fmt.Sprintf("t%02d", i), Host: fmt.Sprintf("t%02d.example.org", i)}
	}
	return out
}

func ids(ts []Target) []string {
	out := make([]string, len(ts))
	for i, t := range ts {
		out[i] = t.ID
	}
	return out
}

// memRotation is a rotation store in memory.
type memRotation struct{ n uint64 }

func (m *memRotation) Load() (uint64, error) { return m.n, nil }
func (m *memRotation) Save(n uint64) error   { m.n = n; return nil }

// 24 targets with limit 10: three runs cover all 24, and over any 24
// consecutive picks each target appears exactly once.
func TestPickGoesRoundTheList(t *testing.T) {
	list := items(24)
	s := FileRotationStore(filepath.Join(t.TempDir(), "rotation"))

	var picked []string
	seen := map[string]int{}
	for run := 0; run < 3; run++ {
		got, err := Pick(list, 10, s)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 10 {
			t.Fatalf("run %d picked %d targets", run, len(got))
		}
		inRun := map[string]bool{}
		for _, id := range ids(got) {
			if inRun[id] {
				t.Errorf("run %d picked %s twice", run, id)
			}
			inRun[id] = true
			seen[id]++
		}
		picked = append(picked, ids(got)...)
	}
	if len(seen) != 24 {
		t.Errorf("three runs covered %d of 24 targets", len(seen))
	}
	// Any window of 24 consecutive picks is one full round.
	for start := 0; start+24 <= len(picked); start++ {
		round := map[string]bool{}
		for _, id := range picked[start : start+24] {
			if round[id] {
				t.Fatalf("round starting at pick %d has %s twice", start, id)
			}
			round[id] = true
		}
	}
	// The first round is exactly the list order.
	want := ids(list)
	if strings.Join(picked[:24], ",") != strings.Join(want, ",") {
		t.Errorf("first round = %v, want the list order", picked[:24])
	}
}

func TestPickIsDeterministicForAFixedCounter(t *testing.T) {
	list := items(24)
	tests := []struct {
		counter uint64
		limit   int
		want    string
		next    uint64
	}{
		{0, 5, "t00,t01,t02,t03,t04", 5},
		{20, 6, "t20,t21,t22,t23,t00,t01", 2},
		{23, 2, "t23,t00", 1},
		{48 + 3, 2, "t03,t04", 5},                // a counter beyond the list wraps
		{0, 30, strings.Join(ids(list), ","), 0}, // limit above the list size picks the whole list once
	}
	for _, tc := range tests {
		m := &memRotation{n: tc.counter}
		got, err := Pick(list, tc.limit, m)
		if err != nil {
			t.Fatal(err)
		}
		if g := strings.Join(ids(got), ","); g != tc.want {
			t.Errorf("counter %d limit %d: got %s, want %s", tc.counter, tc.limit, g, tc.want)
		}
		if m.n != tc.next {
			t.Errorf("counter %d limit %d: next counter %d, want %d", tc.counter, tc.limit, m.n, tc.next)
		}
	}
}

func TestPickRefusesBadInput(t *testing.T) {
	m := &memRotation{}
	if _, err := Pick(nil, 5, m); err == nil {
		t.Error("an empty list: want error")
	}
	for _, limit := range []int{0, -1} {
		if _, err := Pick(items(3), limit, m); err == nil {
			t.Errorf("limit %d: want error", limit)
		}
	}
}

type failingRotation struct{ loadErr, saveErr error }

func (f failingRotation) Load() (uint64, error) { return 0, f.loadErr }
func (f failingRotation) Save(uint64) error     { return f.saveErr }

func TestPickStoreErrors(t *testing.T) {
	boom := errors.New("disk on fire")
	if got, err := Pick(items(5), 2, failingRotation{loadErr: boom}); !errors.Is(err, boom) || got != nil {
		t.Errorf("Load error: %v, %v", got, err)
	}
	// If the counter cannot be moved on, the same targets would come back
	// next time; say so instead of hiding it.
	if got, err := Pick(items(5), 2, failingRotation{saveErr: boom}); !errors.Is(err, boom) || got != nil {
		t.Errorf("Save error: %v, %v", got, err)
	}
}

func TestFileRotationStore(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "mayak", "rotation")
	s := FileRotationStore(path)

	if n, err := s.Load(); err != nil || n != 0 {
		t.Fatalf("Load without a file = %d, %v; want 0 and no error", n, err)
	}
	if err := s.Save(17); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != "17\n" {
		t.Errorf("file = %q", b)
	}
	if n, err := s.Load(); err != nil || n != 17 {
		t.Errorf("Load = %d, %v", n, err)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Errorf("directory holds %v, want only rotation (atomic write leaves nothing else)", entries)
	}

	if runtime.GOOS != "windows" {
		if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
			t.Errorf("file mode %v, want 0600", info.Mode().Perm())
		}
		if info, _ := os.Stat(filepath.Dir(path)); info.Mode().Perm() != 0o700 {
			t.Errorf("dir mode %v, want 0700", info.Mode().Perm())
		}
	}
}

func TestFileRotationStoreDamagedIsAnErrorNotAReset(t *testing.T) {
	for name, content := range map[string]string{
		"garbage":        "SECRET-CONTENT\n",
		"empty":          "",
		"no newline":     "17",
		"negative":       "-1\n",
		"two numbers":    "1 2\n",
		"extra line":     "1\n2\n",
		"leading zero":   "07\n",
		"too big":        "99999999999999999999999\n",
		"windows ending": "17\r\n",
		"plus sign":      "+3\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "rotation")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := FileRotationStore(path).Load()
			if !errors.Is(err, ErrRotationDamaged) {
				t.Fatalf("err = %v, want ErrRotationDamaged", err)
			}
			if !strings.Contains(err.Error(), path) || strings.Contains(err.Error(), "SECRET") {
				t.Errorf("the error should name the file and not repeat it: %v", err)
			}
			// Pick does not reset it either.
			if _, err := Pick(items(5), 2, FileRotationStore(path)); !errors.Is(err, ErrRotationDamaged) {
				t.Errorf("Pick: err = %v", err)
			}
			if b, _ := os.ReadFile(path); string(b) != content {
				t.Errorf("the damaged file was changed to %q", b)
			}
		})
	}
}

func TestFileRotationStoreUnreadable(t *testing.T) {
	dir := t.TempDir() // a directory where a file is expected
	if _, err := FileRotationStore(dir).Load(); err == nil || errors.Is(err, ErrRotationDamaged) {
		t.Errorf("err = %v, want a read error", err)
	}
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := FileRotationStore(filepath.Join(blocker, "sub", "rotation")).Save(1); err == nil {
		t.Error("an unusable directory: want error")
	}
}
