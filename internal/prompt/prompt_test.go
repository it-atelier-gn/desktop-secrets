package prompt

import (
	"testing"

	"github.com/it-atelier-gn/desktop-secrets/internal/static"

	"fyne.io/fyne/v2/test"
)

func TestTTLLabelForMatchingValue(t *testing.T) {
	if got := ttlLabelFor(240); got != "4 hours" {
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
		if got := ttlLabelFor(current); got != want {
			t.Fatalf("ttlLabelFor(%d) = %q, want default %q", current, got, want)
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
