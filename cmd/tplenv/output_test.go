package main

import (
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestOneLinerForShell(t *testing.T) {
	cases := []struct {
		shell string
		want  string
	}{
		{"sh", `eval "$(tplenv --shell=sh env)"`},
		{"pwsh", `tplenv --shell=pwsh env | Invoke-Expression`},
		{"cmd", `for /f "delims=" %L in ('tplenv --shell=cmd env') do @%L`},
		{"auto", `# POSIX: eval "$(tplenv env)"`},
		{"auto", "# PowerShell: tplenv env | Invoke-Expression"},
		{"auto", `# cmd: for /f "delims=" %L in ('tplenv env') do @%L`},
	}

	seen := map[string]string{}
	for _, tc := range cases {
		got, ok := seen[tc.shell]
		if !ok {
			got = oneLinerForShell(tc.shell)
			seen[tc.shell] = got
		}
		if !strings.Contains(got, tc.want) {
			t.Errorf("oneLinerForShell(%q): got %q, want it to contain %q", tc.shell, got, tc.want)
		}
	}
}

func TestOneLinerForShell_CmdNoGoFormatVerbs(t *testing.T) {
	got := oneLinerForShell("cmd")
	if strings.Contains(got, "%!") {
		t.Errorf("cmd one-liner contains malformed Go format output: %q", got)
	}
	if !strings.Contains(got, "%L") {
		t.Errorf("cmd one-liner missing %%L loop variable: %q", got)
	}
}

func TestOneLinerForShell_NoArtifactName(t *testing.T) {
	for _, shell := range []string{"sh", "pwsh", "cmd", "auto"} {
		got := oneLinerForShell(shell)
		for _, bad := range []string{".exe", "windows-amd64", "linux-amd64", "hardened"} {
			if strings.Contains(got, bad) {
				t.Errorf("oneLinerForShell(%q) = %q, must not contain %q", shell, got, bad)
			}
		}
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
		{"https://host:8080/a-b_c.d?x=1", "'https://host:8080/a-b_c.d?x=1'"},
		{"user@host.example", "user@host.example"},
		{"a;rm -rf ~", "'a;rm -rf ~'"},
		{"a&b|c", "'a&b|c'"},
		{"a>b<c", "'a>b<c'"},
		{"(x)", "'(x)'"},
		{"*", "'*'"},
		{"#x", "'#x'"},
		{"a\nb", "'a\nb'"},
	}
	for _, tc := range cases {
		if got := quoteForSh(tc.in); got != tc.want {
			t.Errorf("quoteForSh(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

var hostileValues = []string{
	"simple",
	"a;echo INJECTED",
	"a&echo INJECTED",
	"a|echo INJECTED",
	"$(echo INJECTED)",
	"`echo INJECTED`",
	"it's \"quoted\"",
	"a\nb\nc",
	"pa$word %PATH% ^!",
	"*",
}

func TestQuoteForShRoundTrip(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not available")
	}
	for _, v := range hostileValues {
		out, err := exec.Command(sh, "-c", "export K="+quoteForSh(v)+"; printf %s \"$K\"").Output()
		if err != nil {
			t.Fatalf("sh failed for %q: %v", v, err)
		}
		if string(out) != v {
			t.Errorf("sh round trip of %q gave %q", v, out)
		}
	}
}

func TestQuoteForPowerShell(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", "''"},
		{"simple", "'simple'"},
		{"it's here", "'it''s here'"},
		{"no'quote", "'no''quote'"},
		{"a\nb", "([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('YQpi')))"},
	}
	for _, tc := range cases {
		if got := quoteForPowerShell(tc.in); got != tc.want {
			t.Errorf("quoteForPowerShell(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestQuoteForPowerShellRoundTrip(t *testing.T) {
	ps, err := exec.LookPath("powershell")
	if err != nil {
		if ps, err = exec.LookPath("pwsh"); err != nil {
			t.Skip("PowerShell not available")
		}
	}
	for _, v := range hostileValues {
		script := "$Env:K = " + quoteForPowerShell(v) + "; [Console]::Out.Write([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Env:K)))"
		cmd := exec.Command(ps, "-NoProfile", "-NonInteractive", "-Command", script)
		got, err := cmd.Output()
		if err != nil {
			t.Fatalf("PowerShell failed for %q: %v", v, err)
		}
		dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(got)))
		if err != nil {
			t.Fatalf("decode %q: %v", got, err)
		}
		if string(dec) != v {
			t.Errorf("PowerShell round trip of %q gave %q", v, dec)
		}
	}
}

func TestCmdSetLine(t *testing.T) {
	cases := []struct {
		k, v, want string
		ok         bool
	}{
		{"K", "", `set "K="`, true},
		{"K", "simple", `set "K=simple"`, true},
		{"K", "hello world", `set "K=hello world"`, true},
		{"K", `say "hi"`, `set "K=say "hi""`, true},
		{"K", "a&b|c>d", `set "K=a&b|c>d"`, true},
		{"K", "a\nb", "", false},
	}
	for _, tc := range cases {
		got, ok := cmdSetLine(tc.k, tc.v)
		if got != tc.want || ok != tc.ok {
			t.Errorf("cmdSetLine(%q, %q) = %q, %v, want %q, %v", tc.k, tc.v, got, ok, tc.want, tc.ok)
		}
	}
}

func TestCmdSetLineRoundTrip(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("cmd.exe only on Windows")
	}
	for _, v := range hostileValues {
		line, ok := cmdSetLine("K", v)
		if !ok {
			continue
		}
		dir := t.TempDir()
		lines := filepath.Join(dir, "lines.txt")
		if err := os.WriteFile(lines, []byte(line+"\r\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		f := filepath.Join(dir, "t.cmd")
		script := "@echo off\r\nfor /f \"usebackq delims=\" %%L in (\"" + lines + "\") do @%%L\r\nset K>\"" + f + ".out\"\r\n"
		if err := os.WriteFile(f, []byte(script), 0o600); err != nil {
			t.Fatal(err)
		}
		c := exec.Command("cmd.exe", "/d", "/c", f)
		c.Env = []string{"SystemRoot=" + os.Getenv("SystemRoot")}
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("cmd failed for %q: %v: %s", v, err, out)
		}
		got, err := os.ReadFile(f + ".out")
		if err != nil {
			t.Fatal(err)
		}
		if want := "K=" + v + "\r\n"; string(got) != want {
			t.Errorf("cmd round trip of %q gave %q", v, got)
		}
	}
}

func TestFilterEnv(t *testing.T) {
	m := map[string]string{"A": "1", "B": "2", "C": "3"}

	got := filterEnv(m, nil, nil)
	if len(got) != 3 {
		t.Errorf("no filter: expected 3 keys, got %d", len(got))
	}

	got = filterEnv(m, []string{"A", "C"}, nil)
	if len(got) != 2 || got["A"] != "1" || got["C"] != "3" {
		t.Errorf("only filter: got %v", got)
	}

	got = filterEnv(m, nil, []string{"B"})
	if len(got) != 2 || got["B"] != "" {
		t.Errorf("exclude filter: got %v", got)
	}

	got = filterEnv(m, []string{"A", "B"}, []string{"B"})
	if len(got) != 1 || got["A"] != "1" {
		t.Errorf("only+exclude filter: got %v", got)
	}

	got = filterEnv(m, []string{" A "}, nil)
	if len(got) != 1 || got["A"] != "1" {
		t.Errorf("whitespace trim: got %v", got)
	}
}
