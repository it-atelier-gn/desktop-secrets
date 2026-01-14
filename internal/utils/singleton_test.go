package utils

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gofrs/flock"
)

// withIsolatedTempDir ensures os.TempDir() resolves into a per-test directory.
// It sets TMPDIR/TEMP/TMP to t.TempDir() and returns that path.
func withIsolatedTempDir(t *testing.T) string {
	t.Helper()
	td := t.TempDir()

	// On Unix, TMPDIR is respected; on Windows, TEMP/TMP are respected.
	// We set all three to be safe across platforms.
	t.Setenv("TMPDIR", td)
	t.Setenv("TEMP", td)
	t.Setenv("TMP", td)

	return td
}

// cleanShm resets globals and removes any lock file if present.
// This keeps test cases isolated even if a previous assertion fails.
func cleanSingleton(t *testing.T) {
	t.Helper()
	if appLock != nil {
		_ = appLock.Unlock()
	}
	if lockFile != "" {
		_ = os.Remove(lockFile)
	}
	appLock = nil
	lockFile = ""
}

func TestEnsureSingleInstance_AllowsFirstLock(t *testing.T) {
	cleanSingleton(t)
	td := withIsolatedTempDir(t)

	if err := EnsureSingleInstance("tplenv.lock"); err != nil {
		t.Fatalf("EnsureSingleInstance() first acquire: unexpected error: %v", err)
	}
	t.Cleanup(func() {
		ReleaseSingleInstance()
		cleanSingleton(t)
	})

	// The lock file path should be in our isolated temp dir.
	if lockFile == "" {
		t.Fatalf("lockFile not set")
	}
	if filepath.Dir(lockFile) != td {
		t.Fatalf("lockFile not in isolated temp dir; got %q want dir %q", lockFile, td)
	}

	// The lock file should exist (the flock implementation creates a file).
	if _, err := os.Stat(lockFile); err != nil {
		t.Fatalf("lock file should exist after successful lock, stat error: %v", err)
	}
}

func TestEnsureSingleInstance_BlocksSecondInstance(t *testing.T) {
	cleanSingleton(t)
	_ = withIsolatedTempDir(t)

	// First instance acquires the lock.
	if err := EnsureSingleInstance("tplenv.lock"); err != nil {
		t.Fatalf("first EnsureSingleInstance() failed: %v", err)
	}
	t.Cleanup(func() {
		ReleaseSingleInstance()
		cleanSingleton(t)
	})

	// Simulate a second instance by creating a new flock on the same file.
	if lockFile == "" {
		t.Fatalf("lockFile not set by EnsureSingleInstance")
	}
	second := flock.New(lockFile)

	locked, err := second.TryLock()
	if err != nil {
		// Some platforms may return an error; it's still acceptable as "cannot acquire".
		t.Logf("second TryLock returned error (acceptable as contention): %v", err)
		locked = false
	}
	if locked {
		t.Fatalf("second instance unexpectedly acquired the lock on %q", lockFile)
	}
}

func TestReleaseSingleInstance_UnlocksAndAllowsRelock(t *testing.T) {
	cleanSingleton(t)
	_ = withIsolatedTempDir(t)

	// Acquire via EnsureSingleInstance.
	if err := EnsureSingleInstance("tplenv.lock"); err != nil {
		t.Fatalf("EnsureSingleInstance() failed: %v", err)
	}

	// Release and remove the file (ReleaseSingleInstance does both).
	ReleaseSingleInstance()
	// Do not call cleanShm() here to keep lockFile path for the next check.

	// Try to acquire using a fresh flock (simulating a new process).
	if lockFile == "" {
		t.Fatalf("lockFile not set by EnsureSingleInstance")
	}
	f := flock.New(lockFile)
	locked, err := f.TryLock()
	if err != nil {
		t.Fatalf("unexpected error acquiring lock after release: %v", err)
	}
	if !locked {
		t.Fatalf("expected to acquire lock after release, but locked=false")
	}
	// Cleanup: unlock and remove file to keep temp dir tidy.
	_ = f.Unlock()
	_ = os.Remove(lockFile)

	cleanSingleton(t)
}
