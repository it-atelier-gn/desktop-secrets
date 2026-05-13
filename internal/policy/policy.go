// Package policy defines the security-policy subset of the daemon's
// settings — the keys whose values, if silently weakened, would
// degrade the security posture. Policy is mirrored into an
// OS-protected store on every confirmed change, and reconciled at
// startup against the on-disk settings file so a process running as
// the user cannot quietly edit config.yaml to disable the approval
// dialog or downgrade the required authentication factor.
//
// "Stricter" / "weaker" relations are defined per field. A downgrade
// requires a re-authentication using the *current* factor before it
// is allowed to take effect — without it, the on-disk value is
// reverted to the keystore copy and the attempt is logged loudly.
package policy

import (
	"encoding/json"

	"github.com/it-atelier-gn/desktop-secrets/internal/static"
)

// SchemaVersion is bumped whenever the Policy struct gains a field
// whose default cannot be inferred from older blobs. Older blobs are
// upgraded by re-saving with the current defaults filled in.
const SchemaVersion = 1

// Policy captures every setting whose silent downgrade we want to
// detect. Keep in sync with the viper keys used elsewhere.
type Policy struct {
	Version                int    `json:"version"`
	RetrievalApproval      bool   `json:"retrieval_approval"`
	AutoApproveOnUnlock    bool   `json:"auto_approve_on_unlock"`
	ApprovalFactorRequired string `json:"approval_factor_required"`
}

// Defaults returns a Policy populated with the same defaults
// InitConfig applies. Used when the keystore is empty (first run) or
// when an older blob is missing fields.
func Defaults() Policy {
	return Policy{
		Version:                SchemaVersion,
		RetrievalApproval:      static.DefaultRetrievalApproval,
		AutoApproveOnUnlock:    static.DefaultAutoApproveOnUnlock,
		ApprovalFactorRequired: static.DefaultApprovalFactor,
	}
}

// Marshal returns a stable JSON representation suitable for the
// keystore blob.
func (p Policy) Marshal() ([]byte, error) {
	if p.Version == 0 {
		p.Version = SchemaVersion
	}
	return json.Marshal(p)
}

// Unmarshal parses a keystore blob, filling missing fields with
// Defaults values so callers don't have to special-case older blobs.
func Unmarshal(b []byte) (Policy, error) {
	out := Defaults()
	if err := json.Unmarshal(b, &out); err != nil {
		return Policy{}, err
	}
	return out, nil
}

// factorRank orders the ApprovalFactorRequired values from weakest
// (click) to strongest (hardware). Unknown values are treated as
// click-equivalent so a typo cannot accidentally count as stronger.
func factorRank(s string) int {
	switch s {
	case "hardware":
		return 3
	case "os_remote_passkey":
		return 2
	case static.ApprovalFactorOSLocal:
		return 1
	default:
		return 0
	}
}

// Compare classifies the relationship between candidate (typically
// the on-disk policy) and baseline (typically the keystore policy).
//
//   - RelEqual: nothing changed.
//   - RelStricter: candidate is at least as strict on every field and
//     strictly stronger on at least one. Adopting it is always safe.
//   - RelWeaker: at least one field would be weakened. Adopting it
//     requires re-authentication.
//   - RelMixed: some fields stricter, others weaker. Treated as
//     RelWeaker for the purposes of authorisation — any weakening
//     needs consent.
type Relation int

const (
	RelEqual Relation = iota
	RelStricter
	RelWeaker
	RelMixed
)

func compareBoolStricterTrue(c, b bool) int {
	// For RetrievalApproval, `true` is stricter than `false`.
	switch {
	case c == b:
		return 0
	case c && !b:
		return 1 // stricter
	default:
		return -1 // weaker
	}
}

func compareBoolStricterFalse(c, b bool) int {
	// For AutoApproveOnUnlock, `false` is stricter than `true`.
	switch {
	case c == b:
		return 0
	case !c && b:
		return 1
	default:
		return -1
	}
}

// Compare returns the relation candidate has to baseline.
func Compare(candidate, baseline Policy) Relation {
	scores := []int{
		compareBoolStricterTrue(candidate.RetrievalApproval, baseline.RetrievalApproval),
		compareBoolStricterFalse(candidate.AutoApproveOnUnlock, baseline.AutoApproveOnUnlock),
	}
	// Approval factor: higher rank == stricter.
	cr := factorRank(candidate.ApprovalFactorRequired)
	br := factorRank(baseline.ApprovalFactorRequired)
	switch {
	case cr > br:
		scores = append(scores, 1)
	case cr < br:
		scores = append(scores, -1)
	default:
		scores = append(scores, 0)
	}

	hasStricter, hasWeaker := false, false
	for _, s := range scores {
		switch {
		case s > 0:
			hasStricter = true
		case s < 0:
			hasWeaker = true
		}
	}
	switch {
	case !hasStricter && !hasWeaker:
		return RelEqual
	case hasStricter && !hasWeaker:
		return RelStricter
	case !hasStricter && hasWeaker:
		return RelWeaker
	default:
		return RelMixed
	}
}
