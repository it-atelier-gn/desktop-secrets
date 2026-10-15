package server

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenDaemonLogAppends(t *testing.T) {
	dir := t.TempDir()
	for _, line := range []string{"a\n", "b\n"} {
		f, err := openDaemonLog(dir)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString(line); err != nil {
			t.Fatal(err)
		}
		f.Close()
	}
	got, err := os.ReadFile(filepath.Join(dir, daemonLogName))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "a\nb\n" {
		t.Fatalf("log content = %q, want %q", got, "a\nb\n")
	}
}

func TestOpenDaemonLogRotatesOversizedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, daemonLogName)
	if err := os.WriteFile(path, make([]byte, daemonLogMaxSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := openDaemonLog(dir)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if info, err := os.Stat(path); err != nil || info.Size() != 0 {
		t.Fatalf("expected fresh empty log, got %v, %v", info, err)
	}
	if info, err := os.Stat(path + ".1"); err != nil || info.Size() != daemonLogMaxSize+1 {
		t.Fatalf("expected rotated log, got %v, %v", info, err)
	}
}
