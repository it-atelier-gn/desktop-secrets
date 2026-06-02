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
		"AWS/Prod":    "prod-secret-1",
		"AWS/Sub/Dev": "dev-secret-2",
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

	vlt, err := m.openVaultWithMaster(filepath.Base(path), path, master, time.Hour)
	if err != nil {
		t.Fatalf("openVaultWithMaster: %v", err)
	}

	if len(vlt.entries) == 0 {
		t.Fatal("no entries captured")
	}
	var sealedCount int
	for _, e := range vlt.entries {
		sealedCount += len(e.sealed)
	}
	if sealedCount == 0 {
		t.Fatal("no sealed attributes captured")
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

	vlt, err := m.openVaultWithMaster(filepath.Base(path), path, master, time.Hour)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if len(vlt.entries) == 0 {
		t.Fatal("expected sealed entries before destroy")
	}

	vlt.destroy()

	if vlt.entries != nil {
		t.Error("entries not nil after destroy")
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

func TestCachedVaultsListsUnlocked(t *testing.T) {
	dir := t.TempDir()
	path, master, _ := writeKDBX(t, dir)
	m := newManagerForTest(t)

	if got := m.CachedVaults(); len(got) != 0 {
		t.Fatalf("expected no cached vaults, got %d", len(got))
	}

	key := filepath.Base(path)
	vlt, err := m.openVaultWithMaster(key, path, master, time.Hour)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	m.vaults[key] = vlt

	got := m.CachedVaults()
	if len(got) != 1 {
		t.Fatalf("expected 1 cached vault, got %d", len(got))
	}
	if got[0].Key != key {
		t.Errorf("key = %q, want %q", got[0].Key, key)
	}
	if got[0].Filename != path {
		t.Errorf("filename = %q, want %q", got[0].Filename, path)
	}
	if got[0].Expires.IsZero() {
		t.Error("expires is zero")
	}
}

func TestCachedVaultsExcludesExpired(t *testing.T) {
	dir := t.TempDir()
	path, master, _ := writeKDBX(t, dir)
	m := newManagerForTest(t)

	key := filepath.Base(path)
	vlt, err := m.openVaultWithMaster(key, path, master, time.Hour)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	vlt.expires = time.Now().Add(-time.Minute)
	m.vaults[key] = vlt

	if got := m.CachedVaults(); len(got) != 0 {
		t.Fatalf("expected expired vault excluded, got %d", len(got))
	}
}

func TestEvictAllDestroysVaults(t *testing.T) {
	dir := t.TempDir()
	path, master, _ := writeKDBX(t, dir)
	m := newManagerForTest(t)

	key := filepath.Base(path)
	vlt, err := m.openVaultWithMaster(key, path, master, time.Hour)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	m.vaults[key] = vlt

	m.EvictAll()

	if len(m.vaults) != 0 {
		t.Errorf("vaults not cleared, got %d", len(m.vaults))
	}
	if vlt.entries != nil {
		t.Error("evicted vault not destroyed")
	}
	m.EvictAll()
}
