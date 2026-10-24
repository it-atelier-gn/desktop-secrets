package policy

import (
	"testing"

	"github.com/it-atelier-gn/desktop-secrets/internal/static"
)

func TestEmptyFloorKeepsUserChoice(t *testing.T) {
	var f Floor
	if f.EffectiveApproval(false) {
		t.Fatal("empty floor turned approval on")
	}
	if got := f.EffectiveFactor(static.ApprovalFactorClick); got != static.ApprovalFactorClick {
		t.Fatalf("factor = %q", got)
	}
	if got := f.EffectiveTTL(240); got != 240 {
		t.Fatalf("ttl = %d", got)
	}
	for _, m := range []static.ApprovalMode{static.ApprovalModeOff, static.ApprovalModeStandard, static.ApprovalModeAdvanced} {
		if !f.AllowsMode(m) {
			t.Fatalf("empty floor rejects %v", m)
		}
	}
}

func TestFloorRaisesApproval(t *testing.T) {
	f := Floor{RetrievalApproval: true}
	if !f.EffectiveApproval(false) {
		t.Fatal("approval not raised")
	}
	if f.AllowsMode(static.ApprovalModeOff) {
		t.Fatal("off allowed below the floor")
	}
	if !f.AllowsMode(static.ApprovalModeStandard) || !f.AllowsMode(static.ApprovalModeAdvanced) {
		t.Fatal("stricter modes must stay selectable")
	}
}

func TestFloorFactor(t *testing.T) {
	f := Floor{MinApprovalFactor: static.ApprovalFactorOSLocal}
	got := f.EffectiveFactor(static.ApprovalFactorClick)
	if FactorEnforced {
		if got != static.ApprovalFactorOSLocal || !f.EffectiveApproval(false) {
			t.Fatalf("os_local floor not applied: factor=%q", got)
		}
		if f.AllowsMode(static.ApprovalModeStandard) || !f.AllowsMode(static.ApprovalModeAdvanced) {
			t.Fatal("standard must be blocked, advanced allowed")
		}
		if f.IgnoredFactor() {
			t.Fatal("enforced factor reported as ignored")
		}
		return
	}
	if got != static.ApprovalFactorClick || f.EffectiveApproval(false) {
		t.Fatalf("factor floor must be ignored on this platform: factor=%q", got)
	}
	if !f.IgnoredFactor() {
		t.Fatal("ignored factor not reported")
	}
}

func TestFloorCapsTTL(t *testing.T) {
	f := Floor{MaxUnlockTTL: 60}
	if got := f.EffectiveTTL(240); got != 60 {
		t.Fatalf("ttl = %d, want 60", got)
	}
	if got := f.EffectiveTTL(15); got != 15 {
		t.Fatalf("shorter ttl changed to %d", got)
	}
	if f.AllowsTTL(120) || !f.AllowsTTL(60) {
		t.Fatal("AllowsTTL disagrees with the cap")
	}
}

func TestArgsRoundTrip(t *testing.T) {
	for _, f := range []Floor{
		{},
		{RetrievalApproval: true, MinApprovalFactor: static.ApprovalFactorOSLocal, MaxUnlockTTL: 60},
	} {
		got, err := ParseArgs(f.Args())
		if err != nil || got != f {
			t.Fatalf("round trip %+v -> %+v (%v)", f, got, err)
		}
	}
}

func TestParseArgsRejectsInvalid(t *testing.T) {
	for _, args := range [][]string{
		{"true", ""},
		{"maybe", "", "0"},
		{"true", "fingerprint", "0"},
		{"true", "", "-5"},
		{"true", "", "soon"},
	} {
		if _, err := ParseArgs(args); err == nil {
			t.Fatalf("ParseArgs(%q) accepted", args)
		}
	}
}

func TestParseArgsClickMeansNoMinimum(t *testing.T) {
	f, err := ParseArgs([]string{"false", static.ApprovalFactorClick, "0"})
	if err != nil || f.MinApprovalFactor != "" {
		t.Fatalf("got %+v, %v", f, err)
	}
}
