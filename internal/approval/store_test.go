package approval

import (
	"testing"
	"time"
)

func TestStoreProcessGrant(t *testing.T) {
	s := NewStore()
	if s.Check(42, 100, "k") {
		t.Fatal("empty store reported grant")
	}
	s.GrantProcess(42, 100, "k", time.Minute)
	if !s.Check(42, 100, "k") {
		t.Fatal("expected live grant")
	}
	if s.Check(43, 100, "k") {
		t.Fatal("grant must be PID-scoped")
	}
}

func TestStoreProcessGrantStartTimeBound(t *testing.T) {
	s := NewStore()
	s.GrantProcess(42, 100, "k", time.Minute)
	if s.Check(42, 200, "k") {
		t.Fatal("grant must NOT match a different start time on the same PID")
	}
	if !s.Check(42, 100, "k") {
		t.Fatal("grant should still match the original (pid, startTime)")
	}
}

func TestStoreUntilRestart(t *testing.T) {
	s := NewStore()
	s.GrantProcess(7, 1, "k", DurationUntilRestart)
	if !s.Check(7, 1, "k") {
		t.Fatal("until-restart grant should be live")
	}
}

func TestStoreExpiry(t *testing.T) {
	s := NewStore()
	s.GrantProcess(1, 1, "k", time.Millisecond)
	time.Sleep(5 * time.Millisecond)
	if s.Check(1, 1, "k") {
		t.Fatal("expired grant should not be live")
	}
}

func TestStoreForget(t *testing.T) {
	s := NewStore()
	s.GrantProcess(1, 1, "k", time.Minute)
	s.GrantProcess(3, 1, "other", time.Minute)

	s.Forget("k")
	if s.Check(1, 1, "k") {
		t.Fatal("k should be cleared")
	}
	if !s.Check(3, 1, "other") {
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
		t.Fatal("expected has any")
	}
	time.Sleep(5 * time.Millisecond)
	if s.HasAny("k") {
		t.Fatal("expired grants should not count")
	}
}

func TestStoreRevokeAll(t *testing.T) {
	s := NewStore()
	s.GrantProcess(1, 1, "a", time.Minute)
	s.GrantProcess(2, 1, "b", time.Minute)
	s.RevokeAll()
	if s.Check(1, 1, "a") || s.Check(2, 1, "b") {
		t.Fatal("revoke all should clear store")
	}
}
