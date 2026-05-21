package approval

import (
	"sync"
	"time"
)

const DurationUntilRestart time.Duration = -1

type grant struct {
	expires time.Time
	exeHash string
}

type keyGrants struct {
	exes map[string]grant
}

func newKeyGrants() *keyGrants {
	return &keyGrants{exes: make(map[string]grant)}
}

func (k *keyGrants) empty() bool {
	return len(k.exes) == 0
}

type Store struct {
	mu    sync.Mutex
	byKey map[string]*keyGrants
}

func NewStore() *Store {
	return &Store{byKey: make(map[string]*keyGrants)}
}

func (s *Store) Check(exePath, key string) bool {
	if exePath == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	kg, ok := s.byKey[key]
	if !ok {
		return false
	}
	now := time.Now()
	if g, ok := kg.exes[exePath]; ok {
		if alive(g, now) && exeHashMatches(exePath, g.exeHash) {
			return true
		}
		delete(kg.exes, exePath)
	}
	if kg.empty() {
		delete(s.byKey, key)
	}
	return false
}

func alive(g grant, now time.Time) bool {
	return g.expires.IsZero() || now.Before(g.expires)
}

func (s *Store) GrantExecutable(exePath, key string, d time.Duration) {
	if exePath == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	kg, ok := s.byKey[key]
	if !ok {
		kg = newKeyGrants()
		s.byKey[key] = kg
	}
	g := makeGrant(d)
	g.exeHash, _ = computeExeHash(exePath)
	kg.exes[exePath] = g
}

func makeGrant(d time.Duration) grant {
	if d == DurationUntilRestart {
		return grant{}
	}
	return grant{expires: time.Now().Add(d)}
}

func (s *Store) Forget(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byKey, key)
}

func (s *Store) HasAny(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	kg, ok := s.byKey[key]
	if !ok {
		return false
	}
	now := time.Now()
	for path, g := range kg.exes {
		if alive(g, now) && exeHashMatches(path, g.exeHash) {
			return true
		}
		delete(kg.exes, path)
	}
	if kg.empty() {
		delete(s.byKey, key)
	}
	return false
}

func (s *Store) RevokeAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byKey = make(map[string]*keyGrants)
}
