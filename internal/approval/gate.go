package approval

import (
	"sync"
	"time"

	"github.com/it-atelier-gn/desktop-secrets/internal/clientinfo"
	"github.com/it-atelier-gn/desktop-secrets/internal/osauth"
	"github.com/it-atelier-gn/desktop-secrets/internal/prompt"
	"github.com/it-atelier-gn/desktop-secrets/internal/static"
)

// PromptFunc is the function used to prompt the user when no live
// grant exists. Defaults to prompt.PromptApproval; tests substitute.
type PromptFunc func(req prompt.ApprovalRequest) (prompt.ApprovalDecision, error)

// VerifierFunc runs an OS-rendered authentication step after the user
// clicks Allow on the approval dialog. Returning a non-nil error
// causes the gate to treat the click as Deny and surface
// ErrOSAuthFailed to the caller (which logs `os_auth_failed`).
// osauth.ErrUnsupported is treated as "factor not available" and
// downgraded to a click-only grant — this keeps the click default
// safe to run on platforms without the factor wired up.
type VerifierFunc func(reason string) (osauth.Factor, error)

// FactorRequiredFunc returns the live `approval_factor_required`
// setting. Read fresh on every Check so a settings change takes
// effect without restarting the daemon.
type FactorRequiredFunc func() string

// Evictor removes a cached secret from a provider when the user picks
// Forget. Each provider that holds a cache implements this; nil is
// allowed and means "no cache to evict".
type Evictor func(providerKey string)

// Gate serialises approval prompts per provider key (so concurrent
// renders asking for the same secret only prompt once) and hides the
// store + clientinfo plumbing from callers.
//
// verifier + factorRequired are optional: when factorRequired returns
// `os_local` the gate runs verifier after the user clicks Allow. When
// either hook is nil the gate behaves as in click-only mode — same as
// the pre-osauth implementation.
type Gate struct {
	store          *Store
	prompter       PromptFunc
	verifier       VerifierFunc
	factorRequired FactorRequiredFunc
	keyMu          sync.Mutex
	keyLocks       map[string]*sync.Mutex
}

func NewGate(store *Store, prompter PromptFunc) *Gate {
	return NewGateWithVerifier(store, prompter, nil, nil)
}

// NewGateWithVerifier wires the optional OS-factor verifier. Pass nil
// for verifier or factorRequired to retain click-only behaviour.
func NewGateWithVerifier(store *Store, prompter PromptFunc, verifier VerifierFunc, factorRequired FactorRequiredFunc) *Gate {
	if prompter == nil {
		prompter = prompt.PromptApproval
	}
	return &Gate{
		store:          store,
		prompter:       prompter,
		verifier:       verifier,
		factorRequired: factorRequired,
		keyLocks:       make(map[string]*sync.Mutex),
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
// Returns ("", nil) on Allow with no OS factor wired (legacy
// behaviour), (factor, nil) when an OS factor verified the grant,
// ErrDenied on Deny, ErrForgotten on Forget, or ErrOSAuthFailed when
// the user clicked Allow but the OS prompt did not verify.
func (g *Gate) Check(pid int, providerKey, providerRef string, evictor Evictor) (string, error) {
	info := clientinfo.Lookup(pid)
	exePath := info.ExePath
	startTime := info.StartTime

	if g.store.Check(pid, startTime, exePath, providerKey) {
		return "", nil
	}

	mu := g.lockFor(providerKey)
	mu.Lock()
	defer mu.Unlock()

	// Re-check after acquiring the lock — another goroutine may have
	// just been granted approval for the same key.
	if g.store.Check(pid, startTime, exePath, providerKey) {
		return "", nil
	}

	req := prompt.ApprovalRequest{
		ProviderRef:      providerRef,
		ClientDisplay:    info.Short(),
		ClientDetails:    info.Tooltip(),
		ExePath:          exePath,
		HasExistingGrant: g.store.HasAny(providerKey),
	}
	decision, err := g.prompter(req)
	if err != nil {
		return "", err
	}
	if decision.Forget {
		g.store.Forget(providerKey)
		if evictor != nil {
			evictor(providerKey)
		}
		return "", ErrForgotten
	}
	if !decision.Allow {
		return "", ErrDenied
	}

	// Optional second factor: an OS-rendered prompt that user-space
	// input can't reach (Windows Hello). Only invoked when the user
	// has opted in via the `approval_factor_required` setting.
	factor := string(osauth.FactorClick)
	if g.factorRequired != nil && g.verifier != nil {
		switch g.factorRequired() {
		case static.ApprovalFactorOSLocal:
			f, vErr := g.verifier("Allow " + providerRef)
			if vErr != nil {
				if vErr == osauth.ErrUnsupported {
					// Platform doesn't have a factor wired up yet —
					// fall through to a click-only grant. We don't
					// want to break Linux/macOS users while the
					// other factors are in flight.
					break
				}
				return "", ErrOSAuthFailed
			}
			factor = string(f)
		}
	}

	d := durationFromMinutes(decision.DurationMinutes)
	if decision.Scope == prompt.ApprovalScopeExecutable && exePath != "" {
		g.store.GrantExecutable(exePath, providerKey, d)
	} else {
		g.store.GrantProcess(pid, startTime, providerKey, d)
	}
	return factor, nil
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

// ErrOSAuthFailed is returned when the user clicked Allow but the
// OS-level second factor (Windows Hello / etc.) did not verify. The
// click is discarded — no grant is recorded — and the caller should
// log `os_auth_failed` in the audit record.
var ErrOSAuthFailed = osAuthErr{}

type denyErr struct{}

func (denyErr) Error() string { return "secret retrieval denied by user" }

type forgetErr struct{}

func (forgetErr) Error() string { return "secret retrieval forgotten by user" }

type osAuthErr struct{}

func (osAuthErr) Error() string { return "OS-level authentication did not verify" }
