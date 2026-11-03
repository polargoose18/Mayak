package runner

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/polargoose18/mayak/internal/targets"
	builtin "github.com/polargoose18/mayak/targets"
)

// Files the agent keeps in its directory, os.UserConfigDir()/mayak (ADR-006).
const (
	RevFile      = "targets.rev" // newest accepted rev, the rollback protection
	RotationFile = "rotation"    // where the next run starts in the list
)

// SourceError is a failure to get the targets for a run, explained for the
// user: Error returns only the message, in plain English, with what to do.
// The cause stays reachable through errors.Is and errors.As.
type SourceError struct {
	Msg string
	Err error
}

func (e *SourceError) Error() string { return e.Msg }

func (e *SourceError) Unwrap() error { return e.Err }

// Source is where the targets list comes from and where the agent keeps its
// state about it.
type Source struct {
	// File is a signed list given with --targets-file; "" means the copy
	// built into the binary.
	File string
	// Dir holds RevFile and RotationFile; the command passes
	// os.UserConfigDir()/mayak.
	Dir string
}

// Load reads the list and accepts it with targets.Accept against the rev
// stored in Dir, with the keys of env (the built-in keys if env has none) and
// the time of env.Clock. Failures are *SourceError.
func (s Source) Load(env Env) (*targets.Targets, error) {
	if s.Dir == "" {
		return nil, errors.New("load targets: no directory for the agent's files")
	}
	if env.Clock == nil {
		return nil, errors.New("load targets: no clock")
	}
	data, name := builtin.Signed(), "built into mayak"
	if s.File != "" {
		b, err := os.ReadFile(s.File)
		if err != nil {
			return nil, &SourceError{
				Msg: fmt.Sprintf("mayak cannot read the targets list %s. Check the path given with --targets-file.", s.File),
				Err: err,
			}
		}
		data, name = b, s.File
	}
	keys := env.PublicKeys
	if keys == nil {
		keys = targets.PublicKeys()
	}
	revPath := filepath.Join(s.Dir, RevFile)
	store := targets.FileRevStore(revPath)

	l, err := targets.Accept(keys, data, env.Clock.Now(), store)
	if err != nil {
		return nil, &SourceError{Msg: explainAccept(err, keys, data, name, revPath, store), Err: err}
	}
	return l, nil
}

// explainAccept turns an error of targets.Accept into a message for the user.
// The damaged rev file comes before ErrInvalid: it is about the agent's own
// file, not the list.
func explainAccept(err error, keys []ed25519.PublicKey, data []byte, name, revPath string, store targets.RevStore) string {
	switch {
	case errors.Is(err, targets.ErrRevStoreDamaged):
		return fmt.Sprintf("The file %s, where mayak records the newest targets list it has accepted, is damaged. "+
			"mayak does not reset it on its own, because that would also remove the protection against old lists. "+
			"Delete it only if you trust the targets list you are about to use.", revPath)
	case errors.Is(err, targets.ErrExpired):
		when := "its expiry date"
		if l, oerr := targets.Open(keys, data); oerr == nil {
			when = l.Expires.UTC().Format("2006-01-02")
		}
		return fmt.Sprintf("The targets list (%s) expired on %s. Old lists are refused. "+
			"Check that your clock is right, then update mayak or pass a newer signed list with --targets-file.", name, when)
	case errors.Is(err, targets.ErrRollback):
		next, stored := "this list", "the one recorded"
		if l, oerr := targets.Open(keys, data); oerr == nil {
			next = l.Rev
		}
		if r, lerr := store.Load(); lerr == nil && r != "" {
			stored = r
		}
		return fmt.Sprintf("The targets list (%s) has version %s, which is older than version %s that mayak has already accepted. "+
			"An older list is refused. Update mayak or pass the newer signed list with --targets-file.", name, next, stored)
	case errors.Is(err, targets.ErrBadSignature):
		return fmt.Sprintf("The targets list (%s) is not signed by a key this mayak trusts. "+
			"Use the list built into mayak or a list from the project.", name)
	case errors.Is(err, targets.ErrUnsupportedVersion):
		return fmt.Sprintf("The targets list (%s) has a format this mayak does not know. "+
			"It needs a newer version of mayak: update it.", name)
	case errors.Is(err, targets.ErrInvalid):
		return fmt.Sprintf("The targets list (%s) is not a valid targets list, or its dates do not fit the time on this computer. "+
			"Check that your clock is right and that the file is a signed list from the project.", name)
	default:
		return fmt.Sprintf("mayak cannot record the targets list version in %s. "+
			"Check that the directory %s can be written.", revPath, filepath.Dir(revPath))
	}
}

// Pick chooses limit targets of the list, going round it with the counter in
// Dir (targets.Pick). limit must be within MinLimit..MaxLimit. Failures to
// read or write the counter are *SourceError.
func (s Source) Pick(list *targets.Targets, limit int) ([]targets.Target, error) {
	if s.Dir == "" {
		return nil, errors.New("pick targets: no directory for the agent's files")
	}
	if limit < MinLimit || limit > MaxLimit {
		return nil, fmt.Errorf("pick targets: limit %d is outside %d..%d", limit, MinLimit, MaxLimit)
	}
	path := filepath.Join(s.Dir, RotationFile)
	picked, err := targets.Pick(list.Items, limit, targets.FileRotationStore(path))
	switch {
	case errors.Is(err, targets.ErrRotationDamaged):
		return nil, &SourceError{
			Msg: fmt.Sprintf("The file %s, where mayak records which targets to check next, is damaged. "+
				"mayak does not reset it on its own. Delete it and mayak starts again from the top of the list.", path),
			Err: err,
		}
	case err != nil:
		return nil, &SourceError{
			Msg: fmt.Sprintf("mayak cannot record which targets to check next in %s. "+
				"Check that the directory %s can be written.", path, s.Dir),
			Err: err,
		}
	}
	return picked, nil
}
