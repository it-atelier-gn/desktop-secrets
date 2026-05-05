package keepass

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/it-atelier-gn/desktop-secrets/internal/utils"

	"github.com/tobischo/gokeepasslib/v3"
	w "github.com/tobischo/gokeepasslib/v3/wrappers"
)

// writeKDBX builds an in-memory KeePass database and writes it to dir/file.kdbx.
// Returns the file path, master password, and the entries that were written
// (path → password) so tests can assert on lookups.
func writeKDBX(t *testing.T, dir string) (path, master string, want map[string]string) {
	t.Helper()
	master = "supersecret-master"

	mkPlain := func(k, v string) gokeepasslib.ValueData {
		return gokeepasslib.ValueData{Key: k, Value: gokeepasslib.V{Content: v}}
	}
	mkProtected := func(k, v string) gokeepasslib.ValueData {
		return gokeepasslib.ValueData{Key: k, Value: gokeepasslib.V{Content: v, Protected: w.NewBoolWrapper(true)}}
	}

	root := gokeepasslib.NewGroup()
	root.Name = "AWS"

	e1 := gokeepasslib.NewEntry()
	e1.Values = []gokeepasslib.ValueData{
		mkPlain("Title", "Prod"),
		mkPlain("UserName", "alice"),
		mkProtected("Password", "prod-secret-1"),
	}
	root.Entries = append(root.Entries, e1)

	sub := gokeepasslib.NewGroup()
	sub.Name = "Sub"
	e2 := gokeepasslib.NewEntry()
	e2.Values = []gokeepasslib.ValueData{
		mkPlain("Title", "Dev"),
		mkProtected("Password", "dev-secret-2"),
	}
	sub.Entries = append(sub.Entries, e2)
	root.Groups = append(root.Groups, sub)

	db := &gokeepasslib.Database{
		Header:      gokeepasslib.NewHeader(),
		Credentials: gokeepasslib.NewPasswordCredentials(master),
		Content: &gokeepasslib.DBContent{
			Meta: gokeepasslib.NewMetaData(),
			Root: &gokeepasslib.RootData{Groups: []gokeepasslib.Group{root}},
		},
	}
	db.LockProtectedEntries()

	var buf bytes.Buffer
	if err := gokeepasslib.NewEncoder(&buf).Encode(db); err != nil {
		t.Fatalf("encode kdbx: %v", err)
	}

	path = filepath.Join(dir, "test.kdbx")
	if err := os.WriteFile(path, buf.Bytes(), 0600); err != nil {
		t.Fatalf("write kdbx: %v", err)
	}

	want = map[string]string{
		"AWS/Prod":     "prod-secret-1",
		"AWS/Sub/Dev":  "dev-secret-2",
	}
	return path, master, want
}

func newManagerForTest(t *testing.T) *KPManager {
	t.Helper()
	m := NewKPManager()
	ttl := utils.AtomicDuration{}
	ttl.Store(time.Hour)
	m.SetUnlockTTL(&ttl)
	return m
}

func TestOpenVaultSealsProtectedEntries(t *testing.T) {
	dir := t.TempDir()
	path, master, _ := writeKDBX(t, dir)
	m := newManagerForTest(t)

	vlt, err := m.openVaultWithMaster(path, master, time.Hour)
	if err != nil {
		t.Fatalf("openVaultWithMaster: %v", err)
	}

	// Every protected attribute should now have its plaintext stripped from
	// the live database struct and stored only as a Sealed entry.
	var protectedFound int
	for _, g := range vlt.db.Content.Root.Groups {
		walkGroups(g, func(e *gokeepasslib.Entry) {
			for _, v := range e.Values {
				if v.Value.Protected.Bool {
					protectedFound++
					if v.Value.Content != "" {
						t.Errorf("protected entry %q still has plaintext content %q", v.Key, v.Value.Content)
					}
				}
			}
		})
	}
	if protectedFound == 0 {
		t.Fatal("no protected entries found in test fixture")
	}
	if len(vlt.sealedAttrs) == 0 {
		t.Fatal("sealedAttrs is empty")
	}
}

func walkGroups(g gokeepasslib.Group, fn func(*gokeepasslib.Entry)) {
	for i := range g.Entries {
		fn(&g.Entries[i])
	}
	for _, sub := range g.Groups {
		walkGroups(sub, fn)
	}
}

func TestResolvePasswordRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path, master, want := writeKDBX(t, dir)
	m := newManagerForTest(t)

	for entry, expected := range want {
		got, err := m.ResolvePassword(context.Background(), path, "/"+entry, master, time.Hour, nil)
		if err != nil {
			t.Fatalf("ResolvePassword(%q): %v", entry, err)
		}
		if got != expected {
			t.Fatalf("ResolvePassword(%q) = %q, want %q", entry, got, expected)
		}
	}
}

func TestResolvePasswordWildcard(t *testing.T) {
	dir := t.TempDir()
	path, master, _ := writeKDBX(t, dir)
	m := newManagerForTest(t)

	got, err := m.ResolvePassword(context.Background(), path, "Prod", master, time.Hour, nil)
	if err != nil {
		t.Fatalf("ResolvePassword: %v", err)
	}
	if got != "prod-secret-1" {
		t.Fatalf("got %q, want %q", got, "prod-secret-1")
	}
}

func TestResolveNonProtectedAttribute(t *testing.T) {
	dir := t.TempDir()
	path, master, _ := writeKDBX(t, dir)
	m := newManagerForTest(t)

	got, err := m.ResolvePassword(context.Background(), path, "/AWS/Prod|UserName", master, time.Hour, nil)
	if err != nil {
		t.Fatalf("ResolvePassword: %v", err)
	}
	if got != "alice" {
		t.Fatalf("got %q, want %q", got, "alice")
	}
}

func TestVaultDestroyWipesSealedEntries(t *testing.T) {
	dir := t.TempDir()
	path, master, _ := writeKDBX(t, dir)
	m := newManagerForTest(t)

	vlt, err := m.openVaultWithMaster(path, master, time.Hour)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if len(vlt.sealedAttrs) == 0 {
		t.Fatal("expected sealed entries before destroy")
	}

	vlt.destroy()

	if vlt.db != nil {
		t.Error("db not nil after destroy")
	}
	if vlt.sealedAttrs != nil {
		t.Error("sealedAttrs not nil after destroy")
	}
	// Double destroy must not panic.
	vlt.destroy()
}

func TestEntryNotFound(t *testing.T) {
	dir := t.TempDir()
	path, master, _ := writeKDBX(t, dir)
	m := newManagerForTest(t)

	if _, err := m.ResolvePassword(context.Background(), path, "/nonexistent", master, time.Hour, nil); err == nil {
		t.Fatal("expected error for missing entry")
	}
}
