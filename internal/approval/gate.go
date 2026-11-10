package approval

import (
	"fmt"
	"sync"
	"time"

	"github.com/it-atelier-gn/desktop-secrets/internal/clientinfo"
	"github.com/it-atelier-gn/desktop-secrets/internal/osauth"
	"github.com/it-atelier-gn/desktop-secrets/internal/prompt"
	"github.com/it-atelier-gn/desktop-secrets/internal/static"
)

type PromptFunc func(req prompt.ApprovalRequest) (prompt.ApprovalDecision, error)

type VerifierFunc func(reason string) (osauth.Factor, error)

type FactorRequiredFunc func() string

type Evictor func(providerKey string)

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

func (g *Gate) Check(pid int, providerKey, providerRef string, evictor Evictor) (string, error) {
	info := clientinfo.Lookup(pid)
	grantExe := effectiveGrantExe(info)

	if g.store.Check(grantExe, providerKey) {
		return "", nil
	}

	mu := g.lockFor(providerKey)
	mu.Lock()
	defer mu.Unlock()

	if g.store.Check(grantExe, providerKey) {
		return "", nil
	}

	req := prompt.ApprovalRequest{
		ProviderRef:      providerRef,
		ProcessDisplay:   info.EffectiveDisplay(),
		ProcessDetails:   info.EffectiveTooltip(),
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

	factor, err := g.verifyFactor("Allow " + providerRef)
	if err != nil {
		return "", err
	}
	if decision.DurationMinutes != static.ApprovalDurationOnce {
		g.store.GrantExecutable(grantExe, providerKey, durationFromMinutes(decision.DurationMinutes))
	}
	return factor, nil
}

type BatchItem struct {
	Key string
	Ref string
}

func (g *Gate) CheckBatch(pid int, items []BatchItem) (string, error) {
	if len(items) == 0 {
		return "", nil
	}
	info := clientinfo.Lookup(pid)
	grantExe := effectiveGrantExe(info)

	refs := make([]string, len(items))
	for i, it := range items {
		refs[i] = it.Ref
	}
	decision, err := g.prompter(prompt.ApprovalRequest{
		ProviderRef:    refs[0],
		ProviderRefs:   refs,
		ProcessDisplay: info.EffectiveDisplay(),
		ProcessDetails: info.EffectiveTooltip(),
	})
	if err != nil {
		return "", err
	}
	if !decision.Allow {
		return "", ErrDenied
	}

	factor, err := g.verifyFactor(fmt.Sprintf("Allow %d secrets", len(items)))
	if err != nil {
		return "", err
	}
	if decision.DurationMinutes != static.ApprovalDurationOnce {
		d := durationFromMinutes(decision.DurationMinutes)
		for _, it := range items {
			g.store.GrantExecutable(grantExe, it.Key, d)
		}
	}
	return factor, nil
}

func (g *Gate) verifyFactor(reason string) (string, error) {
	factor := string(osauth.FactorClick)
	if g.factorRequired == nil || g.verifier == nil {
		return factor, nil
	}
	if g.factorRequired() != static.ApprovalFactorOSLocal {
		return factor, nil
	}
	f, err := g.verifier(reason)
	if err == osauth.ErrUnsupported {
		return factor, nil
	}
	if err != nil {
		return "", ErrOSAuthFailed
	}
	return string(f), nil
}

func effectiveGrantExe(info clientinfo.Info) string {
	if info.IsTplenvRun() {
		return ""
	}
	if info.IsDesktopSecretsCLI() && info.ParentPID != 0 {
		parent := clientinfo.Lookup(info.ParentPID)
		if parent.ExePath != "" {
			return parent.ExePath
		}
	}
	return info.ExePath
}

func (g *Gate) Store() *Store {
	return g.store
}

func (g *Gate) IsApproved(pid int, providerKey string) bool {
	info := clientinfo.Lookup(pid)
	return g.store.Check(effectiveGrantExe(info), providerKey)
}

func durationFromMinutes(m int) time.Duration {
	if m == static.ApprovalDurationUntilRestart {
		return DurationUntilRestart
	}
	return time.Duration(m) * time.Minute
}

var ErrDenied = denyErr{}

var ErrForgotten = forgetErr{}

var ErrOSAuthFailed = osAuthErr{}

type denyErr struct{}

func (denyErr) Error() string { return "secret retrieval denied by user" }

type forgetErr struct{}

func (forgetErr) Error() string { return "secret retrieval forgotten by user" }

type osAuthErr struct{}

func (osAuthErr) Error() string { return "OS-level authentication did not verify" }
