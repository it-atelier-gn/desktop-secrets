package prompt

import "testing"

func TestSanitizeForDisplay(t *testing.T) {
	cases := []struct {
		in     string
		maxLen int
		want   string
	}{
		{"plain", 0, "plain"},
		{"line1\nline2", 0, "line1 line2"},
		{"a\tb\rc\x00d", 0, "a b c d"},
		{"abcdef", 4, "abcd..."},
		{"abc", 4, "abc"},
		{"", 0, ""},
	}
	for _, c := range cases {
		if got := sanitizeForDisplay(c.in, c.maxLen); got != c.want {
			t.Errorf("sanitizeForDisplay(%q, %d) = %q, want %q", c.in, c.maxLen, got, c.want)
		}
	}
}
