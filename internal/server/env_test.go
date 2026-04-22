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

type fakeAzureResolver struct {
	secrets map[string]string // "ref|field" -> value
	err     error
}

func (f *fakeAzureResolver) ResolveSecret(_ context.Context, ref, field string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	if v, ok := f.secrets[ref+"|"+field]; ok {
		return v, nil
	}
	return "", errors.New("azkv secret not found")
}

type fakeGCPResolver struct {
	secrets map[string]string // "ref|field" -> value
	err     error
}

func (f *fakeGCPResolver) ResolveSecret(_ context.Context, ref, field string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	if v, ok := f.secrets[ref+"|"+field]; ok {
		return v, nil
	}
	return "", errors.New("gcpsm secret not found")
}

type fakeKeychainResolver struct {
	creds map[string]string // "service|account" -> value
	err   error
}

func (f *fakeKeychainResolver) Resolve(_ context.Context, service, account string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	if v, ok := f.creds[service+"|"+account]; ok {
		return v, nil
	}
	return "", errors.New("keychain entry not found")
}

type fakeVaultResolver struct {
	secrets map[string]string // "path|field" -> value
	err     error
}

func (f *fakeVaultResolver) ResolveSecret(_ context.Context, path, field string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	if v, ok := f.secrets[path+"|"+field]; ok {
		return v, nil
	}
	return "", errors.New("vault secret not found")
}

type fakeOnePasswordResolver struct {
	secrets map[string]string // "ref|field" -> value
	err     error
}

func (f *fakeOnePasswordResolver) ResolveSecret(_ context.Context, ref, field string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	if v, ok := f.secrets[ref+"|"+field]; ok {
		return v, nil
	}
	return "", errors.New("op secret not found")
}

// newTestApp wires fakes into an AppState. Pass nil for any resolver to use the default empty fake.
func newTestApp(kp KPResolver, usr UserResolver, wc WincredResolver, awsr AWSResolver, az AzureResolver, gcp GCPResolver, kc KeychainResolver) *AppState {
	return newTestAppFull(kp, usr, wc, awsr, az, gcp, kc, nil, nil)
}

func newTestAppFull(kp KPResolver, usr UserResolver, wc WincredResolver, awsr AWSResolver, az AzureResolver, gcp GCPResolver, kc KeychainResolver, vlt VaultResolver, op OnePasswordResolver) *AppState {
	if kp == nil {
		kp = &fakeKPResolver{}
	}
	if usr == nil {
		usr = &fakeUserResolver{}
	}
	if wc == nil {
		wc = &fakeWincredResolver{}
	}
	if awsr == nil {
		awsr = &fakeAWSResolver{}
	}
	if az == nil {
		az = &fakeAzureResolver{}
	}
	if gcp == nil {
		gcp = &fakeGCPResolver{}
	}
	if kc == nil {
		kc = &fakeKeychainResolver{}
	}
	if vlt == nil {
		vlt = &fakeVaultResolver{}
	}
	if op == nil {
		op = &fakeOnePasswordResolver{}
	}
	return &AppState{KP: kp, USER: usr, WINCRED: wc, AWS: awsr, AZKV: az, GCPSM: gcp, KEYCHAIN: kc, VAULT: vlt, ONEPASSWORD: op}
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
	app := newTestApp(kp, user, nil, nil, nil, nil, nil)

	// user(...)
	got, err := parseAndResolve(ctx, app, 0, "user(alice)")
	if err != nil {
		t.Fatalf("user parseAndResolve error: %v", err)
	}
	if got != "alice-pass" {
		t.Fatalf("user parseAndResolve = %q, want %q", got, "alice-pass")
	}

	// keepass(vault|entry) without nested
	got, err = parseAndResolve(ctx, app, 0, "keepass(/path.kdbx|entry)")
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
	app := newTestApp(kp, user, nil, nil, nil, nil, nil)
	got, err := parseAndResolve(ctx, app, 0, expr)
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

	app := newTestApp(kp, user, nil, nil, nil, nil, nil)

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

	app := newTestApp(kp, user, nil, nil, nil, nil, nil)
	for _, c := range cases {
		if _, err := parseAndResolve(ctx, app, 0, c); err == nil {
			t.Fatalf("expected error for %q, got nil", c)
		}
	}
}

func TestParseAndResolve_DoubleNestedRejected(t *testing.T) {
	ctx := context.Background()
	app := newTestApp(nil, nil, nil, nil, nil, nil, nil)

	expr := "keepass(outer.kdbx[keepass(inner.kdbx[keepass(deeper.kdbx|t)]|x)]|title)"
	if _, err := parseAndResolve(ctx, app, 0, expr); err == nil {
		t.Fatalf("expected error for double-nested expression, got nil")
	}
}

func TestNestedSecretPassedToKP(t *testing.T) {
	ctx := context.Background()
	user := &fakeUserResolver{creds: map[string]string{"creds": "inner-pass"}}
	kp := &fakeKPResolver{creds: map[string]string{"outer.kdbx|title|inner-pass": "ok"}}
	app := newTestApp(kp, user, nil, nil, nil, nil, nil)

	got, err := parseAndResolve(ctx, app, 0, "keepass(outer.kdbx[user(creds)]|title)")
	if err != nil || got != "ok" {
		t.Fatalf("unexpected result: %v %v", got, err)
	}
	if len(kp.calls) != 1 || kp.calls[0] != "outer.kdbx|title|inner-pass" {
		t.Fatalf("kp did not receive nested arg; calls=%v", kp.calls)
	}
}

func TestParseAndResolve_Wincred(t *testing.T) {
	ctx := context.Background()
	wc := &fakeWincredResolver{creds: map[string]string{
		"MyApp/DBPassword|":         "dbpass",
		"MyApp/DBPassword|password": "dbpass",
		"MyApp/DBPassword|username": "dbuser",
	}}
	app := newTestApp(nil, nil, wc, nil, nil, nil, nil)

	// default field (password)
	got, err := parseAndResolve(ctx, app, 0, "wincred(MyApp/DBPassword)")
	if err != nil || got != "dbpass" {
		t.Fatalf("wincred default: got %q, err %v", got, err)
	}

	// explicit password field
	got, err = parseAndResolve(ctx, app, 0, "wincred(MyApp/DBPassword|password)")
	if err != nil || got != "dbpass" {
		t.Fatalf("wincred password: got %q, err %v", got, err)
	}

	// username field
	got, err = parseAndResolve(ctx, app, 0, "wincred(MyApp/DBPassword|username)")
	if err != nil || got != "dbuser" {
		t.Fatalf("wincred username: got %q, err %v", got, err)
	}

	// empty target
	if _, err := parseAndResolve(ctx, app, 0, "wincred()"); err == nil {
		t.Fatal("expected error for empty wincred target")
	}
}

func TestParseAndResolve_AWS(t *testing.T) {
	ctx := context.Background()
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
	app := newTestApp(nil, nil, nil, awsr, nil, nil, nil)

	// awssm — raw string secret
	got, err := parseAndResolve(ctx, app, 0, "awssm(MyApp/Token)")
	if err != nil || got != "rawtoken" {
		t.Fatalf("awssm raw: got %q, err %v", got, err)
	}

	// awssm — JSON field extraction
	got, err = parseAndResolve(ctx, app, 0, "awssm(MyApp/DB|username)")
	if err != nil || got != "dbuser" {
		t.Fatalf("awssm json username: got %q, err %v", got, err)
	}

	got, err = parseAndResolve(ctx, app, 0, "awssm(MyApp/DB|password)")
	if err != nil || got != "dbpass" {
		t.Fatalf("awssm json password: got %q, err %v", got, err)
	}

	// awsps — parameter value
	got, err = parseAndResolve(ctx, app, 0, "awsps(/myapp/prod/api-key)")
	if err != nil || got != "apikey123" {
		t.Fatalf("awsps raw: got %q, err %v", got, err)
	}

	// awsps — JSON field extraction
	got, err = parseAndResolve(ctx, app, 0, "awsps(/myapp/prod/db|host)")
	if err != nil || got != "db.prod.internal" {
		t.Fatalf("awsps json host: got %q, err %v", got, err)
	}

	// empty secret id
	if _, err := parseAndResolve(ctx, app, 0, "awssm()"); err == nil {
		t.Fatal("expected error for empty awssm secret id")
	}

	// empty parameter name
	if _, err := parseAndResolve(ctx, app, 0, "awsps()"); err == nil {
		t.Fatal("expected error for empty awsps parameter name")
	}
}

func TestParseAndResolve_Azure(t *testing.T) {
	ctx := context.Background()
	az := &fakeAzureResolver{secrets: map[string]string{
		"mykv/dbpass|":         "rawpass",
		"mykv/dbjson|username": "dbuser",
	}}
	app := newTestApp(nil, nil, nil, nil, az, nil, nil)

	got, err := parseAndResolve(ctx, app, 0, "azkv(mykv/dbpass)")
	if err != nil || got != "rawpass" {
		t.Fatalf("azkv raw: got %q, err %v", got, err)
	}
	got, err = parseAndResolve(ctx, app, 0, "azkv(mykv/dbjson|username)")
	if err != nil || got != "dbuser" {
		t.Fatalf("azkv field: got %q, err %v", got, err)
	}
	if _, err := parseAndResolve(ctx, app, 0, "azkv()"); err == nil {
		t.Fatal("expected error for empty azkv reference")
	}
}

func TestParseAndResolve_GCP(t *testing.T) {
	ctx := context.Background()
	gcp := &fakeGCPResolver{secrets: map[string]string{
		"my-proj/token|":      "gcptok",
		"my-proj/db|password": "gcp-db-pass",
	}}
	app := newTestApp(nil, nil, nil, nil, nil, gcp, nil)

	got, err := parseAndResolve(ctx, app, 0, "gcpsm(my-proj/token)")
	if err != nil || got != "gcptok" {
		t.Fatalf("gcpsm raw: got %q, err %v", got, err)
	}
	got, err = parseAndResolve(ctx, app, 0, "gcpsm(my-proj/db|password)")
	if err != nil || got != "gcp-db-pass" {
		t.Fatalf("gcpsm field: got %q, err %v", got, err)
	}
	if _, err := parseAndResolve(ctx, app, 0, "gcpsm()"); err == nil {
		t.Fatal("expected error for empty gcpsm reference")
	}
}

func TestParseAndResolve_Keychain(t *testing.T) {
	ctx := context.Background()
	kc := &fakeKeychainResolver{creds: map[string]string{
		"git.example.com|":        "tokA",
		"git.example.com|alice":   "alice-token",
		"github.com|":             "gh-default",
	}}
	app := newTestApp(nil, nil, nil, nil, nil, nil, kc)

	got, err := parseAndResolve(ctx, app, 0, "keychain(git.example.com)")
	if err != nil || got != "tokA" {
		t.Fatalf("keychain default: got %q, err %v", got, err)
	}
	got, err = parseAndResolve(ctx, app, 0, "keychain(git.example.com|alice)")
	if err != nil || got != "alice-token" {
		t.Fatalf("keychain account: got %q, err %v", got, err)
	}
	if _, err := parseAndResolve(ctx, app, 0, "keychain()"); err == nil {
		t.Fatal("expected error for empty keychain service")
	}
}

func TestParseAndResolve_Vault(t *testing.T) {
	ctx := context.Background()
	vlt := &fakeVaultResolver{secrets: map[string]string{
		"secret/data/myapp|":         "raw",
		"secret/data/myapp|password": "vpass",
	}}
	app := newTestAppFull(nil, nil, nil, nil, nil, nil, nil, vlt, nil)

	got, err := parseAndResolve(ctx, app, 0, "vault(secret/data/myapp)")
	if err != nil || got != "raw" {
		t.Fatalf("vault raw: got %q, err %v", got, err)
	}
	got, err = parseAndResolve(ctx, app, 0, "vault(secret/data/myapp|password)")
	if err != nil || got != "vpass" {
		t.Fatalf("vault field: got %q, err %v", got, err)
	}
	if _, err := parseAndResolve(ctx, app, 0, "vault()"); err == nil {
		t.Fatal("expected error for empty vault path")
	}
}

func TestParseAndResolve_OnePassword(t *testing.T) {
	ctx := context.Background()
	op := &fakeOnePasswordResolver{secrets: map[string]string{
		"Personal/GitHub|":           "gh-default",
		"Personal/AWS|access_key":    "AKIA123",
	}}
	app := newTestAppFull(nil, nil, nil, nil, nil, nil, nil, nil, op)

	got, err := parseAndResolve(ctx, app, 0, "op(Personal/GitHub)")
	if err != nil || got != "gh-default" {
		t.Fatalf("op default: got %q, err %v", got, err)
	}
	got, err = parseAndResolve(ctx, app, 0, "op(Personal/AWS|access_key)")
	if err != nil || got != "AKIA123" {
		t.Fatalf("op field: got %q, err %v", got, err)
	}
	if _, err := parseAndResolve(ctx, app, 0, "op()"); err == nil {
		t.Fatal("expected error for empty op reference")
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
