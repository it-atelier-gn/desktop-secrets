//go:build hardened && windows

package approval

import (
	"errors"
	"testing"

	"github.com/it-atelier-gn/desktop-secrets/internal/osauth"
	"github.com/it-atelier-gn/desktop-secrets/internal/policy"
	"github.com/it-atelier-gn/desktop-secrets/internal/prompt"
	"github.com/it-atelier-gn/desktop-secrets/internal/static"
)

func newHardenedTestGate(t *testing.T, verifier VerifierFunc) *Gate {
	t.Helper()
	t.Setenv("APPDATA", t.TempDir())
	if err := policy.DeleteMarker(); err != nil {
		t.Fatalf("marker pre-clean: %v", err)
	}
	store := NewStore()
	allowProcess := func(req prompt.ApprovalRequest) (prompt.ApprovalDecision, error) {
		return prompt.ApprovalDecision{
			Allow:           true,
			DurationMinutes: 5,
		}, nil
	}
	return NewGateWithVerifier(store, allowProcess, verifier, func() string {
		return static.ApprovalFactorOSLocal
	})
}

func TestHardenedGate_WritesMarkerOnSuccessfulVerify(t *testing.T) {
	calls := 0
	verifier := func(reason string) (osauth.Factor, error) {
		calls++
		return osauth.FactorOSLocal, nil
	}
	g := newHardenedTestGate(t, verifier)

	factor, err := g.Check(1234, "kp:vault.kdbx", "kp ref", nil)
	if err != nil {
		t.Fatalf("Check returned error: %v", err)
	}
	if factor != string(osauth.FactorOSLocal) {
		t.Fatalf("expected factor=%q, got %q", osauth.FactorOSLocal, factor)
	}
	if calls != 1 {
		t.Fatalf("expected verifier to be called once, was called %d", calls)
	}
	exists, err := policy.MarkerExists()
	if err != nil {
		t.Fatalf("MarkerExists: %v", err)
	}
	if !exists {
		t.Fatalf("expected hardened marker to be written after successful os_local verify")
	}
}

func TestHardenedGate_NoMarkerOnCanceledVerify(t *testing.T) {
	verifier := func(reason string) (osauth.Factor, error) {
		return osauth.FactorClick, osauth.ErrCanceled
	}
	g := newHardenedTestGate(t, verifier)

	_, err := g.Check(2345, "kp:vault.kdbx", "kp ref", nil)
	if !errors.Is(err, ErrOSAuthFailed) {
		t.Fatalf("expected ErrOSAuthFailed on canceled verifier, got %v", err)
	}
	exists, err := policy.MarkerExists()
	if err != nil {
		t.Fatalf("MarkerExists: %v", err)
	}
	if exists {
		t.Fatalf("marker must NOT exist when verifier was canceled")
	}
}

func TestHardenedGate_NoMarkerWhenVerifierUnsupported(t *testing.T) {
	verifier := func(reason string) (osauth.Factor, error) {
		return osauth.FactorClick, osauth.ErrUnsupported
	}
	g := newHardenedTestGate(t, verifier)

	factor, err := g.Check(3456, "kp:vault.kdbx", "kp ref", nil)
	if err != nil {
		t.Fatalf("Check returned error: %v", err)
	}
	if factor != string(osauth.FactorClick) {
		t.Fatalf("expected click fallback when factor unsupported, got %q", factor)
	}
	exists, err := policy.MarkerExists()
	if err != nil {
		t.Fatalf("MarkerExists: %v", err)
	}
	if exists {
		t.Fatalf("marker must NOT be written on click fallback")
	}
}
