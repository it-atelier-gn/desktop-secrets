package utils

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/gofrs/flock"
)

var (
	appLock  *flock.Flock
	lockFile string
)

func EnsureSingleInstance(filename string) error {
	dir, err := GetRuntimeDirectory()
	if err != nil {
		return fmt.Errorf("locate runtime directory: %w", err)
	}
	lockFile = filepath.Join(dir, filename)
	appLock = flock.New(lockFile)

	locked, err := appLock.TryLock()
	if err != nil {
		return err
	}
	if !locked {
		return fmt.Errorf("could not acquire lock (%s)", lockFile)
	}
	return nil
}

func ReleaseSingleInstance() {
	if appLock != nil {
		_ = appLock.Unlock()
	}
	if lockFile != "" {
		_ = os.Remove(lockFile) // optional
	}
}
