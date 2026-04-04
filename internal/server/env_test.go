package server

import (
	"context"
	"errors"
	"github.com/it-atelier-gn/desktop-secrets/internal/utils"
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

func (f *fakeUserResolver) SetUnlockTTL(unlockTTL *utils.AtomicDuration) {
}

type fakeKPResolver struct {
	// record calls as "vault|title|nested"
	calls []string
	// map key "vault|title|nested" -> password
	creds map[string]string
	err   error
}

func (f *fakeKPResolver) ResolvePassword(ctx context.Context, vault, title, nested string, ttl time.Duration, resolve func(expr string) (string, error)) (string, error) {
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

func (f *fakeKPResolver) LoadKeyfiles() error {
	return nil
}

func (f *fakeKPResolver) SetUnlockTTL(unlockTTL *utils.AtomicDuration) {
}

type fakeAWSResolver struct {
	secrets    map[string]string // "sm:id|field" -> value
	parameters map[string]string // "ps:name|field" -> value
	err        error
}

func (f *fakeAWSResolver) ResolveSecret(_ context.Context, secretID, field string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	k := "sm:" + secretID + "|" + field
	if v, ok := f.secrets[k]; ok {
		return v, nil
	}
	return "", errors.New("secret not found")
}

func (f *fakeAWSResolver) ResolveParameter(_ context.Context, name, field string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	k := "ps:" + name + "|" + field
	if v, ok := f.parameters[k]; ok {
		return v, nil
	}
	return "", errors.New("parameter not found")
}

type fakeWincredResolver struct {
	// map "target|field" -> value
	creds map[string]string
	err   error
}

func (f *fakeWincredResolver) Resolve(_ context.Context, target, field string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	k := target + "|" + field
	if v, ok := f.creds[k]; ok {
		return v, nil
	}
	return "", errors.New("wincred entry not found")
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
	got, err := parseAndResolve(ctx, kp, user, &fakeWincredResolver{}, &fakeAWSResolver{}, 0, "user(alice)")
	if err != nil {
		t.Fatalf("user parseAndResolve error: %v", err)
	}
	if got != "alice-pass" {
		t.Fatalf("user parseAndResolve = %q, want %q", got, "alice-pass")
	}

	// keepass(vault|entry) without nested
	got, err = parseAndResolve(ctx, kp, user, &fakeWincredResolver{}, &fakeAWSResolver{}, 0, "keepass(/path.kdbx|entry)")
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
	got, err := parseAndResolve(ctx, kp, user, &fakeWincredResolver{}, &fakeAWSResolver{}, 0, expr)
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
		KP:      kp,
		USER:    user,
		WINCRED: &fakeWincredResolver{},
		AWS:     &fakeAWSResolver{},
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
		if _, err := parseAndResolve(ctx, kp, user, &fakeWincredResolver{}, &fakeAWSResolver{}, 0, c); err == nil {
			t.Fatalf("expected error for %q, got nil", c)
		}
	}
}

func TestParseAndResolve_DoubleNestedRejected(t *testing.T) {
	ctx := context.Background()
	user := &fakeUserResolver{}
	kp := &fakeKPResolver{}

	expr := "keepass(outer.kdbx[keepass(inner.kdbx[keepass(deeper.kdbx|t)]|x)]|title)"
	if _, err := parseAndResolve(ctx, kp, user, &fakeWincredResolver{}, &fakeAWSResolver{}, 0, expr); err == nil {
		t.Fatalf("expected error for double-nested expression, got nil")
	}
}

func TestNestedSecretPassedToKP(t *testing.T) {
	ctx := context.Background()
	user := &fakeUserResolver{creds: map[string]string{"creds": "inner-pass"}}
	kp := &fakeKPResolver{creds: map[string]string{"outer.kdbx|title|inner-pass": "ok"}}

	got, err := parseAndResolve(ctx, kp, user, &fakeWincredResolver{}, &fakeAWSResolver{}, 0, "keepass(outer.kdbx[user(creds)]|title)")
	if err != nil || got != "ok" {
		t.Fatalf("unexpected result: %v %v", got, err)
	}
	if len(kp.calls) != 1 || kp.calls[0] != "outer.kdbx|title|inner-pass" {
		t.Fatalf("kp did not receive nested arg; calls=%v", kp.calls)
	}
}

func TestParseAndResolve_Wincred(t *testing.T) {
	ctx := context.Background()
	kp := &fakeKPResolver{}
	user := &fakeUserResolver{}
	wc := &fakeWincredResolver{creds: map[string]string{
		"MyApp/DBPassword|":         "dbpass",
		"MyApp/DBPassword|password": "dbpass",
		"MyApp/DBPassword|username": "dbuser",
	}}

	// default field (password)
	got, err := parseAndResolve(ctx, kp, user, wc, &fakeAWSResolver{}, 0, "wincred(MyApp/DBPassword)")
	if err != nil || got != "dbpass" {
		t.Fatalf("wincred default: got %q, err %v", got, err)
	}

	// explicit password field
	got, err = parseAndResolve(ctx, kp, user, wc, &fakeAWSResolver{}, 0, "wincred(MyApp/DBPassword|password)")
	if err != nil || got != "dbpass" {
		t.Fatalf("wincred password: got %q, err %v", got, err)
	}

	// username field
	got, err = parseAndResolve(ctx, kp, user, wc, &fakeAWSResolver{}, 0, "wincred(MyApp/DBPassword|username)")
	if err != nil || got != "dbuser" {
		t.Fatalf("wincred username: got %q, err %v", got, err)
	}

	// empty target
	if _, err := parseAndResolve(ctx, kp, user, wc, &fakeAWSResolver{}, 0, "wincred()"); err == nil {
		t.Fatal("expected error for empty wincred target")
	}
}

func TestParseAndResolve_AWS(t *testing.T) {
	ctx := context.Background()
	kp := &fakeKPResolver{}
	user := &fakeUserResolver{}
	wc := &fakeWincredResolver{}
	awsr := &fakeAWSResolver{
		secrets: map[string]string{
			"sm:MyApp/DB|":         `{"username":"dbuser","password":"dbpass"}`,
			"sm:MyApp/Token|":      "rawtoken",
			"sm:MyApp/DB|username": "dbuser",
			"sm:MyApp/DB|password": "dbpass",
		},
		parameters: map[string]string{
			"ps:/myapp/prod/api-key|": "apikey123",
			"ps:/myapp/prod/db|host":  "db.prod.internal",
		},
	}

	// awssm — raw string secret
	got, err := parseAndResolve(ctx, kp, user, wc, awsr, 0, "awssm(MyApp/Token)")
	if err != nil || got != "rawtoken" {
		t.Fatalf("awssm raw: got %q, err %v", got, err)
	}

	// awssm — JSON field extraction
	got, err = parseAndResolve(ctx, kp, user, wc, awsr, 0, "awssm(MyApp/DB|username)")
	if err != nil || got != "dbuser" {
		t.Fatalf("awssm json username: got %q, err %v", got, err)
	}

	got, err = parseAndResolve(ctx, kp, user, wc, awsr, 0, "awssm(MyApp/DB|password)")
	if err != nil || got != "dbpass" {
		t.Fatalf("awssm json password: got %q, err %v", got, err)
	}

	// awsps — parameter value
	got, err = parseAndResolve(ctx, kp, user, wc, awsr, 0, "awsps(/myapp/prod/api-key)")
	if err != nil || got != "apikey123" {
		t.Fatalf("awsps raw: got %q, err %v", got, err)
	}

	// awsps — JSON field extraction
	got, err = parseAndResolve(ctx, kp, user, wc, awsr, 0, "awsps(/myapp/prod/db|host)")
	if err != nil || got != "db.prod.internal" {
		t.Fatalf("awsps json host: got %q, err %v", got, err)
	}

	// empty secret id
	if _, err := parseAndResolve(ctx, kp, user, wc, awsr, 0, "awssm()"); err == nil {
		t.Fatal("expected error for empty awssm secret id")
	}

	// empty parameter name
	if _, err := parseAndResolve(ctx, kp, user, wc, awsr, 0, "awsps()"); err == nil {
		t.Fatal("expected error for empty awsps parameter name")
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
