package policy

import (
	"fmt"
	"strconv"

	"github.com/it-atelier-gn/desktop-secrets/internal/static"
)

const SetFlag = "--set-machine-policy"

type Floor struct {
	RetrievalApproval bool
	MinApprovalFactor string
	MaxUnlockTTL      int
}

func (f Floor) factorEnforced() bool {
	return FactorEnforced && f.MinApprovalFactor == static.ApprovalFactorOSLocal
}

func (f Floor) IgnoredFactor() bool {
	return !FactorEnforced && f.MinApprovalFactor == static.ApprovalFactorOSLocal
}

func (f Floor) EffectiveApproval(user bool) bool {
	return user || f.RetrievalApproval || f.factorEnforced()
}

func (f Floor) EffectiveFactor(user string) string {
	if f.factorEnforced() {
		return static.ApprovalFactorOSLocal
	}
	return user
}

func (f Floor) EffectiveTTL(user int) int {
	if f.MaxUnlockTTL > 0 && user > f.MaxUnlockTTL {
		return f.MaxUnlockTTL
	}
	return user
}

func (f Floor) MinMode() static.ApprovalMode {
	return static.DeriveApprovalMode(f.EffectiveApproval(false), f.EffectiveFactor(static.ApprovalFactorClick))
}

func (f Floor) AllowsMode(m static.ApprovalMode) bool {
	return modeRank(m) >= modeRank(f.MinMode())
}

func (f Floor) AllowsTTL(minutes int) bool {
	return f.EffectiveTTL(minutes) == minutes
}

func modeRank(m static.ApprovalMode) int {
	switch m {
	case static.ApprovalModeAdvanced:
		return 2
	case static.ApprovalModeStandard:
		return 1
	default:
		return 0
	}
}

func normalizeFactor(s string) string {
	if s == static.ApprovalFactorOSLocal {
		return s
	}
	return ""
}

func (f Floor) Args() []string {
	return []string{strconv.FormatBool(f.RetrievalApproval), normalizeFactor(f.MinApprovalFactor), strconv.Itoa(f.MaxUnlockTTL)}
}

func ParseArgs(args []string) (Floor, error) {
	if len(args) != 3 {
		return Floor{}, fmt.Errorf("expected 3 values (retrieval approval, minimum factor, maximum unlock TTL), got %d", len(args))
	}
	approval, err := strconv.ParseBool(args[0])
	if err != nil {
		return Floor{}, fmt.Errorf("retrieval approval: %w", err)
	}
	if args[1] != "" && args[1] != static.ApprovalFactorClick && args[1] != static.ApprovalFactorOSLocal {
		return Floor{}, fmt.Errorf("unknown approval factor %q", args[1])
	}
	ttl, err := strconv.Atoi(args[2])
	if err != nil || ttl < 0 {
		return Floor{}, fmt.Errorf("maximum unlock TTL: %q is not a number of minutes", args[2])
	}
	return Floor{RetrievalApproval: approval, MinApprovalFactor: normalizeFactor(args[1]), MaxUnlockTTL: ttl}, nil
}
