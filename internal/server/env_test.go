package server

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

// --- Fake resolvers used by tests ---

type fakeUserResolver struct {
	calls []string
	// map title -> password
	creds map[string]string
	err   error
}

func (f *fakeUserResolver) ResolvePassword(ctx context.Context, title string, ttl time.Duration) (string, error) {
	f.calls = append(f.calls, title)
	if f.err != nil {
		return "", f.err
	}
	if p, ok := f.creds[title]; ok {
		return p, nil
	}
	return "", errors.New("user not found")
}

type fakeKPResolver struct {
	// record calls as "vault|title|nested"
	calls []string
	// map key "vault|title|nested" -> password
	creds map[string]string
	err   error
}

func (f *fakeKPResolver) ResolvePassword(ctx context.Context, vault, title, nested string, ttl time.Duration) (string, error) {
	f.calls = append(f.calls, vault+"|"+title+"|"+nested)
	if f.err != nil {
		return "", f.err
	}
	k := vault + "|" + title + "|" + nested
	if p, ok := f.creds[k]; ok {
		return p, nil
	}
	return "", errors.New("keepass entry not found")
}

func (f *fakeKPResolver) LoadAliases() error {
	return nil
}

// --- Unit tests ---

func TestParseParenContent(t *testing.T) {
	tests := []struct {
		in       string
		wantBody string
		wantRem  string
		wantErr  bool
	}{
		{"(abc)rest", "abc", "rest", false},
		{"(a(b)c)X", "a(b)c", "X", false},
		{"()", "", "", false},
		{"(unclosed", "", "", true},
		{"noopen)", "", "", true},
	}

	for _, tc := range tests {
		body, rem, err := parseParenContent(tc.in)
		if (err != nil) != tc.wantErr {
			t.Fatalf("parseParenContent(%q) unexpected error state: %v", tc.in, err)
		}
		if err == nil {
			if body != tc.wantBody || rem != tc.wantRem {
				t.Fatalf("parseParenContent(%q) = (%q,%q), want (%q,%q)", tc.in, body, rem, tc.wantBody, tc.wantRem)
			}
		}
	}
}

func TestIndexTopLevelPipe(t *testing.T) {
	tests := []struct {
		in   string
		want int
	}{
		{"vault|title", 5},
		{"va(l|u)lt|title", 9},              // pipe inside parens ignored
		{"vault[keepass(x|y)|z]|title", 21}, // top-level pipe after bracket
		{"nope", -1},
	}

	for _, tc := range tests {
		got := indexTopLevelPipe(tc.in)
		if got != tc.want {
			t.Fatalf("indexTopLevelPipe(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestSplitVaultAndSingleNested(t *testing.T) {
	tests := []struct {
		in        string
		wantBase  string
		wantInner string
		wantErr   bool
	}{
		{"c:\\a\\b.kdbx", "c:\\a\\b.kdbx", "", false},
		{"c:\\a\\b.kdbx[keepass(creds.kdbx|t1)]", "c:\\a\\b.kdbx", "keepass(creds.kdbx|t1)", false},
		{"vault[ user(x) ]", "vault", "user(x)", false},
		{"vault[one,two]", "", "", true},
		{"vault[unclosed", "", "", true},
	}

	for _, tc := range tests {
		base, inner, err := splitVaultAndSingleNested(tc.in)
		if (err != nil) != tc.wantErr {
			t.Fatalf("splitVaultAndSingleNested(%q) unexpected error state: %v", tc.in, err)
		}
		if err == nil {
			if base != tc.wantBase || inner != tc.wantInner {
				t.Fatalf("splitVaultAndSingleNested(%q) = (%q,%q), want (%q,%q)", tc.in, base, inner, tc.wantBase, tc.wantInner)
			}
		}
	}
}

func TestParseAndResolve_UserAndKeepass_NoNested(t *testing.T) {
	ctx := context.Background()
	user := &fakeUserResolver{creds: map[string]string{"alice": "alice-pass"}}
	kp := &fakeKPResolver{creds: map[string]string{"/path.kdbx|entry|": "entry-pass"}}

	// user(...)
	got, err := parseAndResolve(ctx, kp, user, 0, "user(alice)")
	if err != nil {
		t.Fatalf("user parseAndResolve error: %v", err)
	}
	if got != "alice-pass" {
		t.Fatalf("user parseAndResolve = %q, want %q", got, "alice-pass")
	}

	// keepass(vault|entry) without nested
	got, err = parseAndResolve(ctx, kp, user, 0, "keepass(/path.kdbx|entry)")
	if err != nil {
		t.Fatalf("keepass parseAndResolve error: %v", err)
	}
	if got != "entry-pass" {
		t.Fatalf("keepass parseAndResolve = %q, want %q", got, "entry-pass")
	}
}

func TestParseAndResolve_Keepass_WithNestedUser(t *testing.T) {
	ctx := context.Background()
	// nested user resolves to "inner-pass" which should be passed as nested arg
	user := &fakeUserResolver{creds: map[string]string{"creds": "inner-pass"}}
	kp := &fakeKPResolver{
		creds: map[string]string{
			`outer.kdbx|title|inner-pass`: "outer-entry-pass",
		},
	}

	expr := `keepass(outer.kdbx[user(creds)]|title)`
	got, err := parseAndResolve(ctx, kp, user, 0, expr)
	if err != nil {
		t.Fatalf("nested parseAndResolve error: %v", err)
	}
	if got != "outer-entry-pass" {
		t.Fatalf("nested parseAndResolve = %q, want %q", got, "outer-entry-pass")
	}

	// verify calls recorded
	if !reflect.DeepEqual(user.calls, []string{"creds"}) {
		t.Fatalf("user resolver calls = %v, want %v", user.calls, []string{"creds"})
	}
	if !reflect.DeepEqual(kp.calls, []string{"outer.kdbx|title|inner-pass"}) {
		t.Fatalf("kp resolver calls = %v, want %v", kp.calls, []string{"outer.kdbx|title|inner-pass"})
	}
}

func TestResolveEnvLines_Integration(t *testing.T) {
	ctx := context.Background()
	user := &fakeUserResolver{creds: map[string]string{"u1": "u1pass"}}
	kp := &fakeKPResolver{
		creds: map[string]string{
			`creds.kdbx|test 1|`:                              "inner-pass", // used when no nested token
			`c:\Users\PC\Desktop\second.kdbx|blah|inner-pass`: "final-pass",
		},
	}

	app := &AppState{
		KP:   kp,
		USER: user,
	}

	lines := []string{
		"# comment stays",
		"",
		"A=keepass(c:\\Users\\PC\\Desktop\\second.kdbx[keepass(creds.kdbx|test 1)]|blah)",
		"B=user(u1)",
		"C=plainvalue",
		"D=notamatch(whatever)",
	}

	out, errs := ResolveEnvLines(ctx, app, lines)
	if len(errs) != 0 {
		t.Fatalf("ResolveEnvLines returned errors: %v", errs)
	}

	// Expect A replaced with final-pass, B replaced with u1pass, others preserved
	wantA := "A=final-pass"
	wantB := "B=u1pass"
	if !contains(out, wantA) || !contains(out, wantB) {
		t.Fatalf("ResolveEnvLines output missing expected replacements: got=%v", out)
	}
}

func TestParseAndResolve_Malformed(t *testing.T) {
	ctx := context.Background()
	kp := &fakeKPResolver{}
	user := &fakeUserResolver{}

	cases := []string{
		"keepass(no-pipe)",             // missing '|'
		"keepass(vault|)",              // empty title
		"user()",                       // empty user title
		"keepass(vault[unclosed|t]|x)", // unclosed bracket inside
		"keepass(vault|title)extra",    // trailing garbage
	}

	for _, c := range cases {
		if _, err := parseAndResolve(ctx, kp, user, 0, c); err == nil {
			t.Fatalf("expected error for %q, got nil", c)
		}
	}
}

func TestParseAndResolve_DoubleNestedRejected(t *testing.T) {
	ctx := context.Background()
	user := &fakeUserResolver{}
	kp := &fakeKPResolver{}

	expr := "keepass(outer.kdbx[keepass(inner.kdbx[keepass(deeper.kdbx|t)]|x)]|title)"
	if _, err := parseAndResolve(ctx, kp, user, 0, expr); err == nil {
		t.Fatalf("expected error for double-nested expression, got nil")
	}
}

func TestNestedSecretPassedToKP(t *testing.T) {
	ctx := context.Background()
	user := &fakeUserResolver{creds: map[string]string{"creds": "inner-pass"}}
	kp := &fakeKPResolver{creds: map[string]string{"outer.kdbx|title|inner-pass": "ok"}}

	got, err := parseAndResolve(ctx, kp, user, 0, "keepass(outer.kdbx[user(creds)]|title)")
	if err != nil || got != "ok" {
		t.Fatalf("unexpected result: %v %v", got, err)
	}
	if len(kp.calls) != 1 || kp.calls[0] != "outer.kdbx|title|inner-pass" {
		t.Fatalf("kp did not receive nested arg; calls=%v", kp.calls)
	}
}

// --- small helpers used by tests ---

// contains checks if slice contains exact string
func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
