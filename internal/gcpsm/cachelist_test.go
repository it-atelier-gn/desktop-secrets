package gcpsm

import (
	"testing"
	"time"
)

func TestCachedKeysAndEvictAll(t *testing.T) {
	m := NewManager(time.Hour)
	m.storeCache("projects/p/secrets/b/versions/latest", "v1")
	m.storeCache("projects/p/secrets/a/versions/latest", "v2")

	keys := m.CachedKeys()
	if len(keys) != 2 {
		t.Fatalf("got %d keys, want 2", len(keys))
	}
	if keys[0].Key >= keys[1].Key {
		t.Errorf("keys not sorted: %v", keys)
	}

	m.EvictAll()
	if got := m.CachedKeys(); len(got) != 0 {
		t.Errorf("CachedKeys not empty after EvictAll: %d", len(got))
	}
	if len(m.cache) != 0 {
		t.Error("cache map not cleared")
	}
}

func TestCachedKeysExcludesExpired(t *testing.T) {
	m := NewManager(time.Hour)
	m.storeCache("projects/p/secrets/x/versions/latest", "v")
	for k, e := range m.cache {
		e.expires = time.Now().Add(-time.Minute)
		m.cache[k] = e
	}
	if got := m.CachedKeys(); len(got) != 0 {
		t.Fatalf("expected expired excluded, got %d", len(got))
	}
}
