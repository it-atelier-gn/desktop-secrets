package policy

import (
	"encoding/json"

	"github.com/it-atelier-gn/desktop-secrets/internal/static"
)

const SchemaVersion = 1

type Policy struct {
	Version                int    `json:"version"`
	RetrievalApproval      bool   `json:"retrieval_approval"`
	ApprovalFactorRequired string `json:"approval_factor_required"`
}

func Defaults() Policy {
	return Policy{
		Version:                SchemaVersion,
		RetrievalApproval:      static.DefaultRetrievalApproval,
		ApprovalFactorRequired: static.DefaultApprovalFactor,
	}
}

func (p Policy) Marshal() ([]byte, error) {
	if p.Version == 0 {
		p.Version = SchemaVersion
	}
	return json.Marshal(p)
}

func Unmarshal(b []byte) (Policy, error) {
	out := Defaults()
	if err := json.Unmarshal(b, &out); err != nil {
		return Policy{}, err
	}
	return out, nil
}

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

type Relation int

const (
	RelEqual Relation = iota
	RelStricter
	RelWeaker
	RelMixed
)

func compareBoolStricterTrue(c, b bool) int {
	switch {
	case c == b:
		return 0
	case c && !b:
		return 1
	default:
		return -1
	}
}

func Compare(candidate, baseline Policy) Relation {
	scores := []int{
		compareBoolStricterTrue(candidate.RetrievalApproval, baseline.RetrievalApproval),
	}
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
