package approval

import (
	"sync"
	"time"
)

const DurationUntilRestart time.Duration = -1

type grant struct {
	expires time.Time
}

type pidKey struct {
	pid       int
	startTime uint64
}

type keyGrants struct {
	pids map[pidKey]grant
}

func newKeyGrants() *keyGrants {
	return &keyGrants{pids: make(map[pidKey]grant)}
}

func (k *keyGrants) empty() bool {
	return len(k.pids) == 0
}

type Store struct {
	mu    sync.Mutex
	byKey map[string]*keyGrants
}

func NewStore() *Store {
	return &Store{byKey: make(map[string]*keyGrants)}
}

func (s *Store) Check(pid int, startTime uint64, key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	kg, ok := s.byKey[key]
	if !ok {
		return false
	}
	now := time.Now()
	pk := pidKey{pid: pid, startTime: startTime}
	if g, ok := kg.pids[pk]; ok {
		if alive(g, now) {
			return true
		}
		delete(kg.pids, pk)
	}
	if kg.empty() {
		delete(s.byKey, key)
	}
	return false
}

func alive(g grant, now time.Time) bool {
	return g.expires.IsZero() || now.Before(g.expires)
}

func (s *Store) GrantProcess(pid int, startTime uint64, key string, d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	kg, ok := s.byKey[key]
	if !ok {
		kg = newKeyGrants()
		s.byKey[key] = kg
	}
	kg.pids[pidKey{pid: pid, startTime: startTime}] = makeGrant(d)
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
	for k, g := range kg.pids {
		if alive(g, now) {
			return true
		}
		delete(kg.pids, k)
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
