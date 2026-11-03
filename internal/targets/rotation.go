package targets

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"
)

// ErrRotationDamaged is returned when the stored rotation counter cannot be
// read as a number. Like a damaged rev file, it is an error, not a reset.
var ErrRotationDamaged = errors.New("stored rotation counter is damaged")

// RotationStore keeps where the next run starts in the list (ADR-006, Q3).
type RotationStore interface {
	// Load returns the stored counter, or 0 if nothing is stored yet.
	Load() (uint64, error)
	// Save stores a counter.
	Save(n uint64) error
}

// Pick returns limit targets, going round the list: each run starts where
// the previous one stopped, so every target is checked once per round. If
// limit is larger than the list, the whole list is picked once. The counter
// is moved on before Pick returns; if that fails, Pick fails too, rather than
// pick the same targets again next time without saying so.
func Pick(items []Target, limit int, s RotationStore) ([]Target, error) {
	if len(items) == 0 {
		return nil, errors.New("pick targets: the list is empty")
	}
	if limit < 1 {
		return nil, fmt.Errorf("pick targets: limit %d is below 1", limit)
	}
	counter, err := s.Load()
	if err != nil {
		return nil, fmt.Errorf("pick targets: %w", err)
	}
	n := len(items)
	limit = min(limit, n)
	start := int(counter % uint64(n))

	picked := make([]Target, 0, limit)
	for i := range limit {
		picked = append(picked, items[(start+i)%n])
	}
	if err := s.Save(uint64((start + limit) % n)); err != nil {
		return nil, fmt.Errorf("pick targets: %w", err)
	}
	return picked, nil
}

// FileRotationStore stores the counter in a file: one line, a decimal number.
// The file has mode 0600 and is written atomically; the directory is created
// with mode 0700. The caller chooses the path.
func FileRotationStore(path string) RotationStore { return fileRotationStore{path: path} }

type fileRotationStore struct{ path string }

func (f fileRotationStore) Load() (uint64, error) {
	b, err := os.ReadFile(f.path)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read rotation file %s: %w", f.path, err)
	}
	text, ok := strings.CutSuffix(string(b), "\n")
	if !ok {
		return 0, f.damaged()
	}
	n, err := strconv.ParseUint(text, 10, 64)
	// Only the form Save writes: no sign, no leading zeros, nothing else.
	if err != nil || strconv.FormatUint(n, 10) != text {
		return 0, f.damaged()
	}
	return n, nil
}

// damaged builds the error without any of the file's content.
func (f fileRotationStore) damaged() error {
	return fmt.Errorf("%w: %s does not hold a counter; it is not reset on its own", ErrRotationDamaged, f.path)
}

func (f fileRotationStore) Save(n uint64) error {
	if err := writeFileAtomic(f.path, strconv.FormatUint(n, 10)+"\n"); err != nil {
		return fmt.Errorf("write rotation file: %w", err)
	}
	return nil
}
