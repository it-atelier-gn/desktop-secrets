package approval

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeExe(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatalf("write exe: %v", err)
	}
	return path
}

func TestStoreExecutableGrant(t *testing.T) {
	s := NewStore()
	exe := writeExe(t, "a.bin", "binary-a")
	if s.Check(exe, "k") {
		t.Fatal("empty store reported grant")
	}
	s.GrantExecutable(exe, "k", time.Minute)
	if !s.Check(exe, "k") {
		t.Fatal("expected live grant")
	}
	other := writeExe(t, "b.bin", "binary-b")
	if s.Check(other, "k") {
		t.Fatal("grant must be exe-scoped")
	}
}

func TestStoreExecutableGrantHashPin(t *testing.T) {
	s := NewStore()
	exe := writeExe(t, "pin.bin", "original")
	s.GrantExecutable(exe, "k", time.Minute)
	if !s.Check(exe, "k") {
		t.Fatal("grant should match original binary")
	}
	if err := os.WriteFile(exe, []byte("tampered"), 0o755); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if s.Check(exe, "k") {
		t.Fatal("grant must NOT match after binary replacement")
	}
}

func TestStoreUntilRestart(t *testing.T) {
	s := NewStore()
	exe := writeExe(t, "ur.bin", "ur")
	s.GrantExecutable(exe, "k", DurationUntilRestart)
	if !s.Check(exe, "k") {
		t.Fatal("until-restart grant should be live")
	}
}

func TestStoreExpiry(t *testing.T) {
	s := NewStore()
	exe := writeExe(t, "exp.bin", "exp")
	s.GrantExecutable(exe, "k", time.Millisecond)
	time.Sleep(5 * time.Millisecond)
	if s.Check(exe, "k") {
		t.Fatal("expired grant should not be live")
	}
}

func TestStoreForget(t *testing.T) {
	s := NewStore()
	exeA := writeExe(t, "a.bin", "a")
	exeB := writeExe(t, "b.bin", "b")
	s.GrantExecutable(exeA, "k", time.Minute)
	s.GrantExecutable(exeB, "other", time.Minute)

	s.Forget("k")
	if s.Check(exeA, "k") {
		t.Fatal("k should be cleared")
	}
	if !s.Check(exeB, "other") {
		t.Fatal("unrelated key should remain")
	}
}

func TestStoreHasAny(t *testing.T) {
	s := NewStore()
	if s.HasAny("k") {
		t.Fatal("empty has any")
	}
	exe := writeExe(t, "ha.bin", "ha")
	s.GrantExecutable(exe, "k", time.Millisecond)
	if !s.HasAny("k") {
		t.Fatal("expected has any")
	}
	time.Sleep(5 * time.Millisecond)
	if s.HasAny("k") {
		t.Fatal("expired grants should not count")
	}
}

func TestStoreRevokeAll(t *testing.T) {
	s := NewStore()
	exeA := writeExe(t, "a.bin", "a")
	exeB := writeExe(t, "b.bin", "b")
	s.GrantExecutable(exeA, "a", time.Minute)
	s.GrantExecutable(exeB, "b", time.Minute)
	s.RevokeAll()
	if s.Check(exeA, "a") || s.Check(exeB, "b") {
		t.Fatal("revoke all should clear store")
	}
}

func TestStoreEmptyExePath(t *testing.T) {
	s := NewStore()
	s.GrantExecutable("", "k", time.Minute)
	if s.Check("", "k") {
		t.Fatal("empty exe path must not yield a grant")
	}
}
