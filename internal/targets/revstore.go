package targets

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"
)

// ErrRevStoreDamaged is returned when the stored rev cannot be read as a rev.
// It is an error, not a reset: wiping the stored rev would also wipe the
// protection against rollbacks.
var ErrRevStoreDamaged = errors.New("stored rev is damaged")

// RevStore keeps the newest rev the agent has accepted.
type RevStore interface {
	// Load returns the stored rev, or "" if nothing is stored yet.
	Load() (string, error)
	// Save stores a rev.
	Save(rev string) error
}

// Accept is what the agent calls for a list it was given: Verify, then the
// check against the stored rev (a rollback is refused), then the recording of
// the new rev if it grew. A list that fails any step leaves the store as it
// was. If the new rev cannot be recorded the list is refused too: accepting
// it would leave the rollback protection one step behind.
func Accept(pubs []ed25519.PublicKey, data []byte, now time.Time, s RevStore) (*Targets, error) {
	if s == nil {
		return nil, errors.New("accept targets: no rev store")
	}
	t, err := Verify(pubs, data, now)
	if err != nil {
		return nil, err
	}
	stored, err := s.Load()
	if err != nil {
		return nil, fmt.Errorf("accept targets: %w", err)
	}
	if err := CheckRev(stored, t.Rev); err != nil {
		return nil, fmt.Errorf("accept targets: %w", err)
	}
	if stored == "" || t.Rev != stored {
		// CheckRev has passed, so a different rev is a newer one.
		if err := s.Save(t.Rev); err != nil {
			return nil, fmt.Errorf("accept targets: %w", err)
		}
	}
	return t, nil
}

// FileRevStore stores the rev in a file: one line, the rev. The file has mode
// 0600 and is written atomically (a temporary file in the same directory,
// then a rename); the directory is created with mode 0700. The caller chooses
// the path. Save never moves the stored rev back.
func FileRevStore(path string) RevStore { return fileRevStore{path: path} }

type fileRevStore struct{ path string }

func (f fileRevStore) Load() (string, error) {
	b, err := os.ReadFile(f.path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read rev file %s: %w", f.path, err)
	}
	rev, ok := strings.CutSuffix(string(b), "\n")
	if !ok {
		return "", f.damaged()
	}
	if _, err := parseRev(rev); err != nil {
		return "", f.damaged()
	}
	return rev, nil
}

// damaged builds the error without any of the file's content.
func (f fileRevStore) damaged() error {
	return fmt.Errorf("%w: %s does not hold a rev like 2026-10-13.1; it is not reset on its own, "+
		"delete the file only if you trust the list you are about to accept", ErrRevStoreDamaged, f.path)
}

func (f fileRevStore) Save(rev string) error {
	if _, err := parseRev(rev); err != nil {
		return err
	}
	stored, err := f.Load()
	if err != nil {
		return err
	}
	if stored != "" {
		if c, _ := CompareRev(rev, stored); c < 0 {
			return fmt.Errorf("%w: have %s, got %s", ErrRollback, stored, rev)
		}
	}

	if err := writeFileAtomic(f.path, rev+"\n"); err != nil {
		return fmt.Errorf("write rev file: %w", err)
	}
	return nil
}
