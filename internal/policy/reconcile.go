package policy

import (
	"errors"
	"log"

	"github.com/spf13/viper"

	"github.com/it-atelier-gn/desktop-secrets/internal/osauth"
)

// FromViper snapshots the current policy keys from viper. Called both
// to read the on-disk policy (immediately after viper.ReadInConfig)
// and to assemble what we'd write back if a downgrade is rejected.
func FromViper() Policy {
	p := Defaults()
	if viper.IsSet("retrieval_approval") {
		p.RetrievalApproval = viper.GetBool("retrieval_approval")
	}
	if viper.IsSet("auto_approve_on_unlock") {
		p.AutoApproveOnUnlock = viper.GetBool("auto_approve_on_unlock")
	}
	if v := viper.GetString("approval_factor_required"); v != "" {
		p.ApprovalFactorRequired = v
	}
	return p
}

// ApplyToViper writes p into viper. Use after a Reconcile reverts an
// on-disk downgrade — the in-memory configuration must match the
// keystore copy, not the (rejected) yaml.
func ApplyToViper(p Policy) {
	viper.Set("retrieval_approval", p.RetrievalApproval)
	viper.Set("auto_approve_on_unlock", p.AutoApproveOnUnlock)
	viper.Set("approval_factor_required", p.ApprovalFactorRequired)
}

// ReconcileOutcome describes which branch Reconcile took. Used for
// audit-log and user-visible messaging.
type ReconcileOutcome int

const (
	OutcomeFirstRun ReconcileOutcome = iota
	OutcomeEqual
	OutcomeAdoptStricter
	OutcomeAdoptWeakerVerified
	OutcomeRejectedDowngrade
)

// ErrDowngradeRejected is returned when the on-disk policy is weaker
// than the keystore copy and the user could not (or would not) pass
// the OS factor required to confirm the downgrade. The caller is
// expected to have already reverted viper to the keystore copy and
// rewritten config.yaml.
var ErrDowngradeRejected = errors.New("policy downgrade rejected")

// Reconcile compares the on-disk policy (snapshot from viper) against
// the keystore policy and applies the rules from TODO.md.
//
//   - No keystore copy → first run: adopt disk, persist to keystore.
//   - Equal → no-op.
//   - Disk stricter → adopt disk, refresh keystore.
//   - Disk weaker / mixed → run the OS factor. On success: adopt and
//     refresh. On failure: revert viper to the keystore copy and
//     rewrite config.yaml so the on-disk change is undone too.
//
// The verifier is invoked with the *current* (keystore) policy as
// context — the user is consenting to a downgrade from that state.
// When verifier is nil or returns ErrUnsupported the downgrade is
// rejected outright (no factor wired up means no way to authorise
// a weaker policy).
//
// Reconcile never returns errors for the happy paths — only
// ErrDowngradeRejected when a downgrade was actively reverted, or
// I/O errors from the keystore / config file.
func Reconcile(store Store, verifier func(reason string) (osauth.Factor, error)) (ReconcileOutcome, Policy, error) {
	disk := FromViper()

	stored, err := store.Load()
	if err != nil {
		return OutcomeFirstRun, disk, err
	}
	if stored == nil {
		// First run (or keystore wiped). Adopt whatever is on disk —
		// the user hasn't established a baseline yet.
		if err := store.Save(disk); err != nil {
			return OutcomeFirstRun, disk, err
		}
		return OutcomeFirstRun, disk, nil
	}

	rel := Compare(disk, *stored)
	switch rel {
	case RelEqual:
		return OutcomeEqual, *stored, nil
	case RelStricter:
		if err := store.Save(disk); err != nil {
			return OutcomeAdoptStricter, *stored, err
		}
		return OutcomeAdoptStricter, disk, nil
	case RelWeaker, RelMixed:
		// Anything weakening requires the OS factor.
		reason := "Confirm policy downgrade for desktop-secrets"
		if verifier == nil {
			return revertDowngrade(*stored)
		}
		_, vErr := verifier(reason)
		if vErr != nil {
			return revertDowngrade(*stored)
		}
		if err := store.Save(disk); err != nil {
			return OutcomeAdoptWeakerVerified, *stored, err
		}
		return OutcomeAdoptWeakerVerified, disk, nil
	}
	return OutcomeEqual, *stored, nil
}

// revertDowngrade puts the keystore policy back into viper and
// rewrites the on-disk config so subsequent reads see the reverted
// values. Best-effort on the rewrite — if the yaml is unwritable, the
// in-memory revert still protects the running daemon for this
// session.
func revertDowngrade(stored Policy) (ReconcileOutcome, Policy, error) {
	ApplyToViper(stored)
	if err := viper.WriteConfig(); err != nil {
		log.Printf("policy: keystore reverted in memory but failed to rewrite config.yaml: %v", err)
	}
	return OutcomeRejectedDowngrade, stored, ErrDowngradeRejected
}
