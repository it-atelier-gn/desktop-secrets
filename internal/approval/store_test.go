package approval

import (
	"testing"
	"time"
)

func TestStoreProcessGrant(t *testing.T) {
	s := NewStore()
	if s.Check(42, 100, "", "k") {
		t.Fatal("empty store reported grant")
	}
	s.GrantProcess(42, 100, "k", time.Minute)
	if !s.Check(42, 100, "", "k") {
		t.Fatal("expected live grant")
	}
	if s.Check(43, 100, "", "k") {
		t.Fatal("grant must be PID-scoped")
	}
}

func TestStoreProcessGrantStartTimeBound(t *testing.T) {
	// A grant for (pid=42, startTime=100) must not be honored after a PID
	// reuse, where startTime would differ.
	s := NewStore()
	s.GrantProcess(42, 100, "k", time.Minute)
	if s.Check(42, 200, "", "k") {
		t.Fatal("grant must NOT match a different start time on the same PID")
	}
	if !s.Check(42, 100, "", "k") {
		t.Fatal("grant should still match the original (pid, startTime)")
	}
}

func TestStoreExecutableGrant(t *testing.T) {
	s := NewStore()
	s.GrantExecutable("/usr/bin/getsec", "k", time.Minute)
	if !s.Check(123, 0, "/usr/bin/getsec", "k") {
		t.Fatal("exe match should grant access regardless of PID")
	}
	if !s.Check(456, 0, "/usr/bin/getsec", "k") {
		t.Fatal("exe-scoped grant should apply to other PIDs of same exe")
	}
	if s.Check(123, 0, "/other/bin", "k") {
		t.Fatal("exe-scoped grant must not match different exe")
	}
}

func TestStoreUntilRestart(t *testing.T) {
	s := NewStore()
	s.GrantProcess(7, 1, "k", DurationUntilRestart)
	if !s.Check(7, 1, "", "k") {
		t.Fatal("until-restart grant should be live")
	}
	s.GrantExecutable("/x", "k2", DurationUntilRestart)
	if !s.Check(0, 0, "/x", "k2") {
		t.Fatal("exe until-restart grant should be live")
	}
}

func TestStoreExpiry(t *testing.T) {
	s := NewStore()
	s.GrantProcess(1, 1, "k", time.Millisecond)
	s.GrantExecutable("/x", "k", time.Millisecond)
	time.Sleep(5 * time.Millisecond)
	if s.Check(1, 1, "/x", "k") {
		t.Fatal("expired grants should not be live")
	}
}

func TestStoreForget(t *testing.T) {
	s := NewStore()
	s.GrantProcess(1, 1, "k", time.Minute)
	s.GrantExecutable("/x", "k", DurationUntilRestart)
	s.GrantProcess(3, 1, "other", time.Minute)

	s.Forget("k")
	if s.Check(1, 1, "/x", "k") {
		t.Fatal("k should be cleared (both scopes)")
	}
	if !s.Check(3, 1, "", "other") {
		t.Fatal("unrelated key should remain")
	}
}

func TestStoreHasAny(t *testing.T) {
	s := NewStore()
	if s.HasAny("k") {
		t.Fatal("empty has any")
	}
	s.GrantProcess(1, 1, "k", time.Millisecond)
	if !s.HasAny("k") {
		t.Fatal("expected has any (process)")
	}
	time.Sleep(5 * time.Millisecond)
	if s.HasAny("k") {
		t.Fatal("expired grants should not count")
	}

	s.GrantExecutable("/x", "k2", time.Minute)
	if !s.HasAny("k2") {
		t.Fatal("expected has any (executable)")
	}
}

func TestStoreRevokeAll(t *testing.T) {
	s := NewStore()
	s.GrantProcess(1, 1, "a", time.Minute)
	s.GrantExecutable("/x", "b", time.Minute)
	s.RevokeAll()
	if s.Check(1, 1, "/x", "a") || s.Check(1, 1, "/x", "b") {
		t.Fatal("revoke all should clear store")
	}
}
