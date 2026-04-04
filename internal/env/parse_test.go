package env

import (
	"testing"
)

func TestParseEnvBytes(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  map[string]string
	}{
		{
			name:  "basic key=value",
			input: "A=1\nB=2\n",
			want:  map[string]string{"A": "1", "B": "2"},
		},
		{
			name:  "comments and blank lines skipped",
			input: "# comment\n\nA=1\n# another\nB=2\n",
			want:  map[string]string{"A": "1", "B": "2"},
		},
		{
			name:  "equals sign in value preserved",
			input: "TOKEN=abc=def==\n",
			want:  map[string]string{"TOKEN": "abc=def=="},
		},
		{
			name:  "whitespace trimmed from key",
			input: "  KEY  =value\n",
			want:  map[string]string{"KEY": "value"},
		},
		{
			name:  "leading whitespace in value preserved, trailing stripped",
			input: "A= hello world \n",
			want:  map[string]string{"A": " hello world"},
		},
		{
			name:  "line without equals skipped",
			input: "NOEQUALSSIGN\nA=1\n",
			want:  map[string]string{"A": "1"},
		},
		{
			name:  "empty input",
			input: "",
			want:  map[string]string{},
		},
		{
			name:  "empty value allowed",
			input: "A=\n",
			want:  map[string]string{"A": ""},
		},
		{
			name:  "windows line endings",
			input: "A=1\r\nB=2\r\n",
			want:  map[string]string{"A": "1", "B": "2"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseEnvBytes([]byte(tc.input))
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for k, wv := range tc.want {
				if got[k] != wv {
					t.Errorf("key %q: got %q, want %q", k, got[k], wv)
				}
			}
		})
	}
}
