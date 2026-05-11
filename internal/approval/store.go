// Package approval implements per-process and per-executable consent
// for secret resolution.
//
// A grant is keyed by providerKey + scope. Scope is either:
//   - ScopeProcess: a single PID
//   - ScopeExecutable: an absolute exe path (any future PID matching
//     this path inherits the grant)
//
// Provider keys are canonical strings built by the resolver (e.g.
// "keepass:vault.kdbx|entry"). When a secret is resolved the gate
// consults the store; if no live grant exists the user is prompted via
// the approval dialog.
package approval

import (
	"sync"
	"time"
)

// Scope describes the breadth of an approval grant.
type Scope int

const (
	ScopeProcess Scope = iota
	ScopeExecutable
)

// DurationUntilRestart is the sentinel for grants that last the entire
// daemon lifetime. Stored verbatim as the per-grant duration.
const DurationUntilRestart time.Duration = -1

type grant struct {
	expires time.Time // zero value means "until restart"
}

// pidKey is the composite identity for PID-scoped grants. Including the
// process start time defeats PID reuse: a recycled PID has a different
// start time, so Check() falls through. startTime == 0 means the platform
// could not report one (e.g. macOS without cgo) — grants stored with 0 only
// match lookups with 0.
type pidKey struct {
	pid       int
	startTime uint64
}

type keyGrants struct {
	pids map[pidKey]grant
	exes map[string]grant
}

func newKeyGrants() *keyGrants {
	return &keyGrants{
		pids: make(map[pidKey]grant),
		exes: make(map[string]grant),
	}
}

func (k *keyGrants) empty() bool {
	return len(k.pids) == 0 && len(k.exes) == 0
}

// Store holds active retrieval-approval grants. Safe for concurrent use.
type Store struct {
	mu    sync.Mutex
	byKey map[string]*keyGrants
}

func NewStore() *Store {
	return &Store{byKey: make(map[string]*keyGrants)}
}

// Check returns true when (pid, startTime, exePath, key) has a live grant.
// Executable scope is tried first (broader), then process scope. PID-scoped
// matches require both pid AND startTime to equal the grant-time values.
func (s *Store) Check(pid int, startTime uint64, exePath, key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	kg, ok := s.byKey[key]
	if !ok {
		return false
	}
	now := time.Now()

	if exePath != "" {
		if g, ok := kg.exes[exePath]; ok {
			if alive(g, now) {
				return true
			}
			delete(kg.exes, exePath)
		}
	}
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

// GrantProcess records a PID-scoped approval. d == DurationUntilRestart
// means no expiry. startTime comes from clientinfo.Info; 0 = unknown.
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

// GrantExecutable records an exe-path-scoped approval. Any future
// process running the same path inherits this grant. d ==
// DurationUntilRestart means no expiry.
func (s *Store) GrantExecutable(exePath, key string, d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	kg, ok := s.byKey[key]
	if !ok {
		kg = newKeyGrants()
		s.byKey[key] = kg
	}
	kg.exes[exePath] = makeGrant(d)
}

func makeGrant(d time.Duration) grant {
	if d == DurationUntilRestart {
		return grant{}
	}
	return grant{expires: time.Now().Add(d)}
}

// Forget removes all grants for a key (both scopes).
func (s *Store) Forget(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byKey, key)
}

// HasAny reports whether any (live) grant exists for the key, in
// either scope. Used by the dialog to enable/disable Forget.
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
	for k, g := range kg.exes {
		if alive(g, now) {
			return true
		}
		delete(kg.exes, k)
	}
	if kg.empty() {
		delete(s.byKey, key)
	}
	return false
}

// RevokeAll empties the store.
func (s *Store) RevokeAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byKey = make(map[string]*keyGrants)
}
