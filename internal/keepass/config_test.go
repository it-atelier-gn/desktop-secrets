package keepass

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSetAndGetAliases(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DESKTOP_SECRETS_ALIASES_FILE", filepath.Join(dir, "aliases.yaml"))

	m := newManagerForTest(t)
	in := []AliasInfo{
		{Name: "personal", File: `C:\Vaults\personal.kdbx`},
		{Name: "cloud", File: "$HOME/cloud.kdbx", Master: "keepass(&personal|Cloud Master)"},
	}
	if err := m.SetAliases(in); err != nil {
		t.Fatalf("SetAliases: %v", err)
	}

	got := m.Aliases()
	if len(got) != 2 {
		t.Fatalf("got %d aliases, want 2", len(got))
	}
	if got[0].Name != "cloud" || got[1].Name != "personal" {
		t.Errorf("aliases not sorted: %v", got)
	}
	if got[0].File != "$HOME/cloud.kdbx" {
		t.Errorf("env var not preserved raw: %q", got[0].File)
	}
	if got[0].Master != "keepass(&personal|Cloud Master)" {
		t.Errorf("master not preserved: %q", got[0].Master)
	}

	m2 := newManagerForTest(t)
	if err := m2.LoadAliases(); err != nil {
		t.Fatalf("LoadAliases: %v", err)
	}
	reloaded := m2.Aliases()
	if len(reloaded) != 2 || reloaded[0].File != "$HOME/cloud.kdbx" {
		t.Errorf("round-trip mismatch: %v", reloaded)
	}
}

func TestSetAliasesValidation(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DESKTOP_SECRETS_ALIASES_FILE", filepath.Join(dir, "aliases.yaml"))
	m := newManagerForTest(t)

	if err := m.SetAliases([]AliasInfo{{Name: "", File: "x.kdbx"}}); err == nil {
		t.Error("expected error for empty name")
	}
	if err := m.SetAliases([]AliasInfo{{Name: "a", File: ""}}); err == nil {
		t.Error("expected error for empty file")
	}
	if err := m.SetAliases([]AliasInfo{
		{Name: "dup", File: "a.kdbx"},
		{Name: "dup", File: "b.kdbx"},
	}); err == nil {
		t.Error("expected error for duplicate alias")
	}
}

func TestAliasEnvVarExpandedAtResolve(t *testing.T) {
	dir := t.TempDir()
	path, master, want := writeKDBX(t, dir)

	t.Setenv("DESKTOP_SECRETS_TEST_VAULTDIR", filepath.Dir(path))
	t.Setenv("DESKTOP_SECRETS_ALIASES_FILE", filepath.Join(dir, "aliases.yaml"))

	m := newManagerForTest(t)
	if err := m.SetAliases([]AliasInfo{
		{Name: "v", File: "$DESKTOP_SECRETS_TEST_VAULTDIR/" + filepath.Base(path)},
	}); err != nil {
		t.Fatalf("SetAliases: %v", err)
	}

	got, err := m.ResolvePassword(context.Background(), "&v", "AWS/Prod", master, time.Hour, nil)
	if err != nil {
		t.Fatalf("ResolvePassword: %v", err)
	}
	if got != want["AWS/Prod"] {
		t.Errorf("got %q, want %q", got, want["AWS/Prod"])
	}
}

func TestSetAndGetKeyfiles(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DESKTOP_SECRETS_KEYFILES_FILE", filepath.Join(dir, "keyfiles.yaml"))

	m := newManagerForTest(t)
	in := []KeyfileInfo{
		{Vault: `C:\Vaults\b.kdbx`, Keyfile: `C:\keys\b.key`},
		{Vault: `C:\Vaults\a.kdbx`, Keyfile: `C:\keys\a.key`},
	}
	if err := m.SetKeyfiles(in); err != nil {
		t.Fatalf("SetKeyfiles: %v", err)
	}

	got := m.Keyfiles()
	if len(got) != 2 {
		t.Fatalf("got %d keyfiles, want 2", len(got))
	}
	if got[0].Vault != `C:\Vaults\a.kdbx` || got[1].Vault != `C:\Vaults\b.kdbx` {
		t.Errorf("keyfiles not sorted: %v", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "keyfiles.yaml")); err != nil {
		t.Errorf("keyfiles.yaml not written: %v", err)
	}

	m2 := newManagerForTest(t)
	if err := m2.LoadKeyfiles(); err != nil {
		t.Fatalf("LoadKeyfiles: %v", err)
	}
	if len(m2.Keyfiles()) != 2 {
		t.Errorf("round-trip mismatch: %v", m2.Keyfiles())
	}
}

func TestSetKeyfilesValidation(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DESKTOP_SECRETS_KEYFILES_FILE", filepath.Join(dir, "keyfiles.yaml"))
	m := newManagerForTest(t)

	if err := m.SetKeyfiles([]KeyfileInfo{{Vault: "", Keyfile: "k"}}); err == nil {
		t.Error("expected error for empty vault")
	}
	if err := m.SetKeyfiles([]KeyfileInfo{{Vault: "v", Keyfile: ""}}); err == nil {
		t.Error("expected error for empty keyfile")
	}
}
