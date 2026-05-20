package static

import "testing"

func TestDeriveApprovalMode(t *testing.T) {
	cases := []struct {
		name     string
		approval bool
		factor   string
		want     ApprovalMode
	}{
		{"off when approval disabled", false, ApprovalFactorClick, ApprovalModeOff},
		{"off ignores factor when approval disabled", false, ApprovalFactorOSLocal, ApprovalModeOff},
		{"standard when approval enabled with click", true, ApprovalFactorClick, ApprovalModeStandard},
		{"advanced when approval enabled with os_local", true, ApprovalFactorOSLocal, ApprovalModeAdvanced},
		{"unknown factor falls back to standard", true, "future-factor", ApprovalModeStandard},
		{"empty factor falls back to standard", true, "", ApprovalModeStandard},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DeriveApprovalMode(tc.approval, tc.factor); got != tc.want {
				t.Fatalf("DeriveApprovalMode(%v,%q) = %v, want %v", tc.approval, tc.factor, got, tc.want)
			}
		})
	}
}

func TestApplyApprovalMode(t *testing.T) {
	cases := []struct {
		mode         ApprovalMode
		wantApproval bool
		wantFactor   string
	}{
		{ApprovalModeOff, false, ApprovalFactorClick},
		{ApprovalModeStandard, true, ApprovalFactorClick},
		{ApprovalModeAdvanced, true, ApprovalFactorOSLocal},
		{ApprovalMode("garbage"), true, ApprovalFactorClick},
	}
	for _, tc := range cases {
		t.Run(string(tc.mode), func(t *testing.T) {
			gotApproval, gotFactor := ApplyApprovalMode(tc.mode)
			if gotApproval != tc.wantApproval || gotFactor != tc.wantFactor {
				t.Fatalf("ApplyApprovalMode(%q) = (%v,%q), want (%v,%q)",
					tc.mode, gotApproval, gotFactor, tc.wantApproval, tc.wantFactor)
			}
		})
	}
}

func TestApprovalModeRoundTrip(t *testing.T) {
	for _, m := range []ApprovalMode{ApprovalModeOff, ApprovalModeStandard, ApprovalModeAdvanced} {
		approval, factor := ApplyApprovalMode(m)
		if got := DeriveApprovalMode(approval, factor); got != m {
			t.Fatalf("round trip lost %v -> (%v,%q) -> %v", m, approval, factor, got)
		}
	}
}
