package approval

import (
	"sync"
	"time"

	"github.com/it-atelier-gn/desktop-secrets/internal/clientinfo"
	"github.com/it-atelier-gn/desktop-secrets/internal/prompt"
	"github.com/it-atelier-gn/desktop-secrets/internal/static"
)

// PromptFunc is the function used to prompt the user when no live
// grant exists. Defaults to prompt.PromptApproval; tests substitute.
type PromptFunc func(req prompt.ApprovalRequest) (prompt.ApprovalDecision, error)

// Evictor removes a cached secret from a provider when the user picks
// Forget. Each provider that holds a cache implements this; nil is
// allowed and means "no cache to evict".
type Evictor func(providerKey string)

// Gate serialises approval prompts per provider key (so concurrent
// renders asking for the same secret only prompt once) and hides the
// store + clientinfo plumbing from callers.
type Gate struct {
	store    *Store
	prompter PromptFunc
	keyMu    sync.Mutex
	keyLocks map[string]*sync.Mutex
}

func NewGate(store *Store, prompter PromptFunc) *Gate {
	if prompter == nil {
		prompter = prompt.PromptApproval
	}
	return &Gate{
		store:    store,
		prompter: prompter,
		keyLocks: make(map[string]*sync.Mutex),
	}
}

func (g *Gate) lockFor(key string) *sync.Mutex {
	g.keyMu.Lock()
	defer g.keyMu.Unlock()
	mu, ok := g.keyLocks[key]
	if !ok {
		mu = &sync.Mutex{}
		g.keyLocks[key] = mu
	}
	return mu
}

// Check enforces approval for (pid, providerKey). When a live grant
// exists Check returns immediately. Otherwise it prompts the user
// (serialised per key) and updates the store.
//
// Returns nil on Allow, ErrDenied on Deny, or ErrForgotten on Forget.
func (g *Gate) Check(pid int, providerKey, providerRef string, evictor Evictor) error {
	info := clientinfo.Lookup(pid)
	exePath := info.ExePath
	startTime := info.StartTime

	if g.store.Check(pid, startTime, exePath, providerKey) {
		return nil
	}

	mu := g.lockFor(providerKey)
	mu.Lock()
	defer mu.Unlock()

	// Re-check after acquiring the lock — another goroutine may have
	// just been granted approval for the same key.
	if g.store.Check(pid, startTime, exePath, providerKey) {
		return nil
	}

	req := prompt.ApprovalRequest{
		ProviderRef:      providerRef,
		ClientDisplay:    info.Display(),
		ExePath:          exePath,
		HasExistingGrant: g.store.HasAny(providerKey),
	}
	decision, err := g.prompter(req)
	if err != nil {
		return err
	}
	if decision.Forget {
		g.store.Forget(providerKey)
		if evictor != nil {
			evictor(providerKey)
		}
		return ErrForgotten
	}
	if !decision.Allow {
		return ErrDenied
	}

	d := durationFromMinutes(decision.DurationMinutes)
	if decision.Scope == prompt.ApprovalScopeExecutable && exePath != "" {
		g.store.GrantExecutable(exePath, providerKey, d)
	} else {
		g.store.GrantProcess(pid, startTime, providerKey, d)
	}
	return nil
}

// Store exposes the underlying store for tray-side controls (e.g.
// "Forget all approvals").
func (g *Gate) Store() *Store {
	return g.store
}

// IsApproved reports whether a live grant exists for (pid, providerKey).
// Resolves clientinfo internally so callers don't need to.
func (g *Gate) IsApproved(pid int, providerKey string) bool {
	info := clientinfo.Lookup(pid)
	return g.store.Check(pid, info.StartTime, info.ExePath, providerKey)
}

// GrantImplicit records a process-scoped grant without prompting the
// user. Intended for the "auto-approve after first unlock" path: when
// the provider is about to show a password/master-password dialog, we
// treat a successful unlock as approval evidence and skip the separate
// retrieval-approval prompt. The grant uses the daemon-restart sentinel
// (no time-based expiry) so subsequent calls fall through quickly until
// the user explicitly forgets.
func (g *Gate) GrantImplicit(pid int, providerKey string) {
	info := clientinfo.Lookup(pid)
	g.store.GrantProcess(pid, info.StartTime, providerKey, DurationUntilRestart)
}

func durationFromMinutes(m int) time.Duration {
	if m == static.ApprovalDurationUntilRestart {
		return DurationUntilRestart
	}
	return time.Duration(m) * time.Minute
}

// ErrDenied is returned by Gate.Check when the user denies approval.
var ErrDenied = denyErr{}

// ErrForgotten is returned by Gate.Check when the user picks Forget.
var ErrForgotten = forgetErr{}

type denyErr struct{}

func (denyErr) Error() string { return "secret retrieval denied by user" }

type forgetErr struct{}

func (forgetErr) Error() string { return "secret retrieval forgotten by user" }
