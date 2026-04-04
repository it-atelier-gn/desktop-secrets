package keepass

import (
	"testing"
)

func TestSplitAttribute(t *testing.T) {
	cases := []struct {
		in          string
		defaultAttr string
		wantEntry   string
		wantAttr    string
	}{
		{"/AWS/Prod/key", "Password", "/AWS/Prod/key", "Password"},
		{"/AWS/Prod/key|UserName", "Password", "/AWS/Prod/key", "UserName"},
		{"/AWS/Prod/key|Notes", "Password", "/AWS/Prod/key", "Notes"},
		{"/AWS/Prod/key|", "Password", "/AWS/Prod/key", "Password"}, // empty attr falls back to default
		{"entry|custom", "Password", "entry", "custom"},
	}

	for _, tc := range cases {
		entry, attr := splitAttribute(tc.in, tc.defaultAttr)
		if entry != tc.wantEntry || attr != tc.wantAttr {
			t.Errorf("splitAttribute(%q, %q) = (%q, %q), want (%q, %q)",
				tc.in, tc.defaultAttr, entry, attr, tc.wantEntry, tc.wantAttr)
		}
	}
}

func TestSplitPattern(t *testing.T) {
	cases := []struct {
		in      string
		want    []string
		wantErr bool
	}{
		{"/AWS/Prod/api-key", []string{"AWS", "Prod", "api-key"}, false},
		{"/AWS/*/api-key", []string{"AWS", "*", "api-key"}, false},
		{"/AWS/**/api-key", []string{"AWS", "**", "api-key"}, false},
		{"bare", []string{"bare"}, false},
		{"/AWS/My\\/Key", []string{"AWS", "My/Key"}, false}, // escaped slash
		{"/AWS/trailing\\", nil, true},                       // dangling escape
		{"/", []string{}, false}, // root-only: no segments
	}

	for _, tc := range cases {
		got, err := splitPattern(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("splitPattern(%q) error=%v, wantErr=%v", tc.in, err, tc.wantErr)
			continue
		}
		if err != nil {
			continue
		}
		if len(got) != len(tc.want) {
			t.Errorf("splitPattern(%q) = %v, want %v", tc.in, got, tc.want)
			continue
		}
		for i := range tc.want {
			if got[i] != tc.want[i] {
				t.Errorf("splitPattern(%q)[%d] = %q, want %q", tc.in, i, got[i], tc.want[i])
			}
		}
	}
}

func TestMatchSegments(t *testing.T) {
	cases := []struct {
		pattern []string
		path    []string
		want    bool
	}{
		// exact match
		{[]string{"AWS", "Prod", "key"}, []string{"AWS", "Prod", "key"}, true},
		// too short
		{[]string{"AWS", "Prod", "key"}, []string{"AWS", "Prod"}, false},
		// too long
		{[]string{"AWS", "Prod"}, []string{"AWS", "Prod", "key"}, false},
		// single wildcard
		{[]string{"AWS", "*", "key"}, []string{"AWS", "Prod", "key"}, true},
		{[]string{"AWS", "*", "key"}, []string{"AWS", "Dev", "key"}, true},
		{[]string{"AWS", "*", "key"}, []string{"AWS", "Prod", "other"}, false},
		// ** matches zero segments
		{[]string{"**", "key"}, []string{"key"}, true},
		// ** matches one segment
		{[]string{"**", "key"}, []string{"Prod", "key"}, true},
		// ** matches multiple segments
		{[]string{"AWS", "**", "key"}, []string{"AWS", "a", "b", "key"}, true},
		{[]string{"AWS", "**", "key"}, []string{"AWS", "key"}, true},
		// ** at end matches anything remaining
		{[]string{"AWS", "**"}, []string{"AWS", "Prod", "key"}, true},
		{[]string{"AWS", "**"}, []string{"AWS"}, true},
		// no match
		{[]string{"AWS"}, []string{"GCP"}, false},
	}

	for _, tc := range cases {
		got := matchSegments(tc.pattern, tc.path)
		if got != tc.want {
			t.Errorf("matchSegments(%v, %v) = %v, want %v", tc.pattern, tc.path, got, tc.want)
		}
	}
}
