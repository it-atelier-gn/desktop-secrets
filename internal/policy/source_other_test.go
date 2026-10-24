//go:build !windows

package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileSourceRoundTrip(t *testing.T) {
	old := Location
	Location = filepath.Join(t.TempDir(), "etc", "policy.yaml")
	t.Cleanup(func() { Location = old })

	if f, err := Load(); err != nil || f != (Floor{}) {
		t.Fatalf("missing file: %+v, %v", f, err)
	}
	want := Floor{RetrievalApproval: true, MinApprovalFactor: "os_local", MaxUnlockTTL: 30}
	if err := Save(want); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(Location)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o644 {
		t.Fatalf("mode = %v, want 0644", st.Mode().Perm())
	}
	got, err := Load()
	if err != nil || got != want {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestFileSourceRejectsMalformed(t *testing.T) {
	old := Location
	Location = filepath.Join(t.TempDir(), "policy.yaml")
	t.Cleanup(func() { Location = old })
	if err := os.WriteFile(Location, []byte("retrieval_approval: [\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(); err == nil {
		t.Fatal("malformed file accepted")
	}
}
