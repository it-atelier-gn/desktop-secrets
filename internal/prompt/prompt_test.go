package prompt

import (
	"fmt"
	"testing"

	"github.com/it-atelier-gn/desktop-secrets/internal/static"

	"fyne.io/fyne/v2/test"
)

func TestTTLLabelForMatchingValue(t *testing.T) {
	if got := ttlLabelFor(static.TTLOptions, 240); got != "4 hours" {
		t.Fatalf("ttlLabelFor(240) = %q, want %q", got, "4 hours")
	}
}

func TestTTLLabelForUnknownValueFallsBackToDefault(t *testing.T) {
	want := ""
	for _, opt := range static.TTLOptions {
		if opt.IsDefault {
			want = opt.Label
		}
	}
	for _, current := range []int{0, 7, 999} {
		if got := ttlLabelFor(static.TTLOptions, current); got != want {
			t.Fatalf("ttlLabelFor(%d) = %q, want default %q", current, got, want)
		}
	}
}

func TestTTLOptionsRespectMaximum(t *testing.T) {
	cases := []struct {
		max  int
		want []int
	}{
		{0, []int{5, 15, 60, 120, 240}},
		{60, []int{5, 15, 60}},
		{30, []int{5, 15, 30}},
		{2, []int{2}},
		{1000, []int{5, 15, 60, 120, 240, 1000}},
	}
	for _, tc := range cases {
		var got []int
		for _, o := range ttlOptions(tc.max) {
			got = append(got, o.Minutes)
		}
		if fmt.Sprint(got) != fmt.Sprint(tc.want) {
			t.Errorf("ttlOptions(%d) = %v, want %v", tc.max, got, tc.want)
		}
	}
}

func TestBuildTTLSelectStaysWithinMaximum(t *testing.T) {
	test.NewTempApp(t)
	prev := MaxUnlockTTLProvider
	t.Cleanup(func() { MaxUnlockTTLProvider = prev })
	for _, max := range []int{2, 30, 60} {
		MaxUnlockTTLProvider = func() int { return max }
		for _, current := range []int{0, 2, 15, 30, 240} {
			sel, m := buildTTLSelect(current)
			for label, minutes := range m {
				if minutes > max {
					t.Errorf("max %d: option %q offers %d minutes", max, label, minutes)
				}
			}
			if got := m[sel.Selected]; got <= 0 || got > max {
				t.Errorf("max %d, current %d: selected %q with %d minutes", max, current, sel.Selected, got)
			}
		}
	}
}

func TestBuildTTLSelectNeverYieldsZeroTTL(t *testing.T) {
	test.NewTempApp(t)
	for _, current := range []int{0, 7, 15, 240, 999} {
		sel, m := buildTTLSelect(current)
		if m[sel.Selected] <= 0 {
			t.Fatalf("buildTTLSelect(%d) selected %q with %d minutes", current, sel.Selected, m[sel.Selected])
		}
	}
}
