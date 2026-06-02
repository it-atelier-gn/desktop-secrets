package user

import (
	"testing"
	"time"

	"github.com/it-atelier-gn/desktop-secrets/internal/memprotect"
)

func cacheEntry(t *testing.T, m *UserManager, title string, exp time.Time) {
	t.Helper()
	s, err := memprotect.SealString("pw-" + title)
	if err != nil {
		t.Fatal(err)
	}
	m.password[title] = &passwordEntry{expires: exp, sealed: s}
}

func TestUserCachedKeysAndEvictAll(t *testing.T) {
	m := NewUserManager()
	cacheEntry(t, m, "b", time.Now().Add(time.Hour))
	cacheEntry(t, m, "a", time.Now().Add(time.Hour))

	keys := m.CachedKeys()
	if len(keys) != 2 {
		t.Fatalf("got %d keys, want 2", len(keys))
	}
	if keys[0].Key != "a" || keys[1].Key != "b" {
		t.Errorf("keys not sorted: %v", keys)
	}

	m.EvictAll()
	if len(m.password) != 0 {
		t.Error("password map not cleared")
	}
	if got := m.CachedKeys(); len(got) != 0 {
		t.Errorf("CachedKeys not empty after EvictAll: %d", len(got))
	}
}

func TestUserCachedKeysExcludesExpired(t *testing.T) {
	m := NewUserManager()
	cacheEntry(t, m, "x", time.Now().Add(-time.Minute))
	if got := m.CachedKeys(); len(got) != 0 {
		t.Fatalf("expected expired excluded, got %d", len(got))
	}
}
