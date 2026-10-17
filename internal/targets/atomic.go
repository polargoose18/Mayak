package targets

import (
	"fmt"
	"os"
	"path/filepath"
)

// writeFileAtomic replaces the file at path with text. The file gets mode
// 0600 and its directory, if it has to be created, mode 0700. The text goes
// to a temporary file in the same directory first and is renamed into place,
// so a reader sees either the old file or the whole new one.
func writeFileAtomic(path, text string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // a no-op after the rename
	if err := fillAndClose(tmp, text); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// fillAndClose writes the text to the new file, makes it 0600, flushes it to
// disk and closes it, so that the rename that follows publishes a whole file.
func fillAndClose(f *os.File, text string) (err error) {
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		return err
	}
	if _, err := f.WriteString(text); err != nil {
		return err
	}
	return f.Sync()
}
