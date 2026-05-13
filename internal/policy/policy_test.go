package policy

import (
	"errors"
	"testing"

	"github.com/spf13/viper"

	"github.com/it-atelier-gn/desktop-secrets/internal/osauth"
	"github.com/it-atelier-gn/desktop-secrets/internal/static"
)

func TestCompareEqual(t *testing.T) {
	p := Defaults()
	if got := Compare(p, p); got != RelEqual {
		t.Fatalf("identical policies should be RelEqual, got %v", got)
	}
}

func TestCompareStricterRetrieval(t *testing.T) {
	base := Defaults()
	base.RetrievalApproval = false
	c := base
	c.RetrievalApproval = true
	if got := Compare(c, base); got != RelStricter {
		t.Fatalf("enabling retrieval_approval should be stricter, got %v", got)
	}
}

func TestCompareWeakerAutoApprove(t *testing.T) {
	base := Defaults()
	base.AutoApproveOnUnlock = false
	c := base
	c.AutoApproveOnUnlock = true
	if got := Compare(c, base); got != RelWeaker {
		t.Fatalf("enabling auto_approve_on_unlock should be weaker, got %v", got)
	}
}

func TestCompareFactorOrdering(t *testing.T) {
	base := Defaults()
	base.ApprovalFactorRequired = static.ApprovalFactorOSLocal
	c := base
	c.ApprovalFactorRequired = static.ApprovalFactorClick
	if got := Compare(c, base); got != RelWeaker {
		t.Fatalf("click after os_local should be weaker, got %v", got)
	}
	c.ApprovalFactorRequired = "hardware"
	if got := Compare(c, base); got != RelStricter {
		t.Fatalf("hardware after os_local should be stricter, got %v", got)
	}
}

func TestCompareMixed(t *testing.T) {
	base := Defaults()
	base.RetrievalApproval = true
	base.ApprovalFactorRequired = static.ApprovalFactorOSLocal
	c := base
	c.RetrievalApproval = false               // weaker
	c.ApprovalFactorRequired = "hardware"     // stricter
	if got := Compare(c, base); got != RelMixed {
		t.Fatalf("mixed change should be RelMixed, got %v", got)
	}
}

// memStore is an in-memory Store for testing Reconcile without
// touching DPAPI / the filesystem.
type memStore struct {
	data    *Policy
	saveErr error
	loadErr error
}

func (m *memStore) Load() (*Policy, error) {
	if m.loadErr != nil {
		return nil, m.loadErr
	}
	if m.data == nil {
		return nil, nil
	}
	p := *m.data
	return &p, nil
}

func (m *memStore) Save(p Policy) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	cp := p
	m.data = &cp
	return nil
}

func setViperPolicy(p Policy) {
	viper.Reset()
	viper.Set("retrieval_approval", p.RetrievalApproval)
	viper.Set("auto_approve_on_unlock", p.AutoApproveOnUnlock)
	viper.Set("approval_factor_required", p.ApprovalFactorRequired)
}

func TestReconcileFirstRun(t *testing.T) {
	disk := Defaults()
	setViperPolicy(disk)
	store := &memStore{}
	outcome, applied, err := Reconcile(store, nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if outcome != OutcomeFirstRun {
		t.Fatalf("want OutcomeFirstRun, got %v", outcome)
	}
	if store.data == nil || *store.data != applied {
		t.Fatalf("keystore not populated on first run")
	}
}

func TestReconcileEqual(t *testing.T) {
	disk := Defaults()
	setViperPolicy(disk)
	store := &memStore{data: &disk}
	outcome, _, err := Reconcile(store, nil)
	if err != nil || outcome != OutcomeEqual {
		t.Fatalf("want OutcomeEqual nil err, got %v / %v", outcome, err)
	}
}

func TestReconcileAdoptStricter(t *testing.T) {
	base := Defaults()
	base.ApprovalFactorRequired = static.ApprovalFactorClick
	stricter := base
	stricter.ApprovalFactorRequired = static.ApprovalFactorOSLocal
	setViperPolicy(stricter)
	store := &memStore{data: &base}
	outcome, applied, err := Reconcile(store, nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if outcome != OutcomeAdoptStricter {
		t.Fatalf("want AdoptStricter, got %v", outcome)
	}
	if applied.ApprovalFactorRequired != static.ApprovalFactorOSLocal {
		t.Fatalf("expected adopted factor os_local, got %s", applied.ApprovalFactorRequired)
	}
}

func TestReconcileRejectDowngradeNoVerifier(t *testing.T) {
	base := Defaults()
	base.ApprovalFactorRequired = static.ApprovalFactorOSLocal
	weaker := base
	weaker.ApprovalFactorRequired = static.ApprovalFactorClick
	setViperPolicy(weaker)
	store := &memStore{data: &base}
	outcome, applied, err := Reconcile(store, nil)
	if !errors.Is(err, ErrDowngradeRejected) {
		t.Fatalf("want ErrDowngradeRejected, got %v", err)
	}
	if outcome != OutcomeRejectedDowngrade {
		t.Fatalf("want RejectedDowngrade outcome, got %v", outcome)
	}
	if applied.ApprovalFactorRequired != static.ApprovalFactorOSLocal {
		t.Fatalf("policy should remain os_local, got %s", applied.ApprovalFactorRequired)
	}
	// Viper should have been reverted to the keystore copy.
	if viper.GetString("approval_factor_required") != static.ApprovalFactorOSLocal {
		t.Fatalf("viper not reverted: %s", viper.GetString("approval_factor_required"))
	}
}

func TestReconcileAcceptDowngradeVerified(t *testing.T) {
	base := Defaults()
	base.ApprovalFactorRequired = static.ApprovalFactorOSLocal
	weaker := base
	weaker.ApprovalFactorRequired = static.ApprovalFactorClick
	setViperPolicy(weaker)
	store := &memStore{data: &base}
	called := false
	ok := func(reason string) (osauth.Factor, error) {
		called = true
		return osauth.FactorOSLocal, nil
	}
	outcome, applied, err := Reconcile(store, ok)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !called {
		t.Fatalf("verifier should have been called for downgrade")
	}
	if outcome != OutcomeAdoptWeakerVerified {
		t.Fatalf("want AdoptWeakerVerified, got %v", outcome)
	}
	if applied.ApprovalFactorRequired != static.ApprovalFactorClick {
		t.Fatalf("expected adopted factor click, got %s", applied.ApprovalFactorRequired)
	}
}
