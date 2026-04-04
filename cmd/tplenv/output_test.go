package main

import (
	"strings"
	"testing"
)

func TestOneLinerForShell(t *testing.T) {
	cases := []struct {
		shell   string
		exeName string
		want    string
	}{
		{"sh", "tplenv", `eval "$(tplenv --shell=sh env)"`},
		{"pwsh", "tplenv", `tplenv --shell=pwsh env | Invoke-Expression`},
		{"cmd", "tplenv", `for /f "delims=" %L in ('tplenv --shell=cmd env') do @%L`},
		// default: contains all three suggestions
		{"auto", "tplenv", "# POSIX:"},
		{"auto", "tplenv", "# PowerShell:"},
		{"auto", "tplenv", "# cmd:"},
	}

	seen := map[string]string{}
	for _, tc := range cases {
		got, ok := seen[tc.shell]
		if !ok {
			got = oneLinerForShell(tc.shell, tc.exeName)
			seen[tc.shell] = got
		}
		if !strings.Contains(got, tc.want) {
			t.Errorf("oneLinerForShell(%q, %q): got %q, want it to contain %q", tc.shell, tc.exeName, got, tc.want)
		}
	}
}

func TestOneLinerForShell_CmdNoGoFormatVerbs(t *testing.T) {
	got := oneLinerForShell("cmd", "tplenv")
	if strings.Contains(got, "%!") {
		t.Errorf("cmd one-liner contains malformed Go format output: %q", got)
	}
	if !strings.Contains(got, "%L") {
		t.Errorf("cmd one-liner missing %%L loop variable: %q", got)
	}
}

func TestQuoteForSh(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", "''"},
		{"simple", "simple"},
		{"hello world", "'hello world'"},
		{"it's", `'it'\''s'`},
		{"$VAR", "'$VAR'"},
		{"`cmd`", "'`cmd`'"},
	}
	for _, tc := range cases {
		if got := quoteForSh(tc.in); got != tc.want {
			t.Errorf("quoteForSh(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestQuoteForPowerShell(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", "''"},
		{"simple", "'simple'"},
		{"it's here", "'it''s here'"},
		{"no'quote", "'no''quote'"},
	}
	for _, tc := range cases {
		if got := quoteForPowerShell(tc.in); got != tc.want {
			t.Errorf("quoteForPowerShell(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestQuoteForCmd(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", `""`},
		{"simple", "simple"},
		{"hello world", `"hello world"`},
		{`say "hi"`, `"say ""hi"""`},
	}
	for _, tc := range cases {
		if got := quoteForCmd(tc.in); got != tc.want {
			t.Errorf("quoteForCmd(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestFilterEnv(t *testing.T) {
	m := map[string]string{"A": "1", "B": "2", "C": "3"}

	// no filters: pass everything
	got := filterEnv(m, nil, nil)
	if len(got) != 3 {
		t.Errorf("no filter: expected 3 keys, got %d", len(got))
	}

	// only list
	got = filterEnv(m, []string{"A", "C"}, nil)
	if len(got) != 2 || got["A"] != "1" || got["C"] != "3" {
		t.Errorf("only filter: got %v", got)
	}

	// exclude list
	got = filterEnv(m, nil, []string{"B"})
	if len(got) != 2 || got["B"] != "" {
		t.Errorf("exclude filter: got %v", got)
	}

	// both: only A,B then exclude B → just A
	got = filterEnv(m, []string{"A", "B"}, []string{"B"})
	if len(got) != 1 || got["A"] != "1" {
		t.Errorf("only+exclude filter: got %v", got)
	}

	// whitespace trimmed in list entries
	got = filterEnv(m, []string{" A "}, nil)
	if len(got) != 1 || got["A"] != "1" {
		t.Errorf("whitespace trim: got %v", got)
	}
}
