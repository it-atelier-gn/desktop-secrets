//go:build windows

package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMarkerRoundTrip(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("APPDATA", tmp)
	t.Setenv("DESKTOP_SECRETS_CONFIG_FILE", filepath.Join(tmp, "desktop-secrets", "config.yaml"))

	exists, err := MarkerExists()
	if err != nil {
		t.Fatalf("MarkerExists initial: %v", err)
	}
	if exists {
		t.Fatalf("expected no marker initially")
	}

	if err := WriteMarker(); err != nil {
		t.Fatalf("WriteMarker: %v", err)
	}

	exists, err = MarkerExists()
	if err != nil {
		t.Fatalf("MarkerExists after write: %v", err)
	}
	if !exists {
		t.Fatalf("expected marker after write")
	}

	if err := WriteMarker(); err != nil {
		t.Fatalf("WriteMarker idempotent: %v", err)
	}

	if err := DeleteMarker(); err != nil {
		t.Fatalf("DeleteMarker: %v", err)
	}

	exists, err = MarkerExists()
	if err != nil {
		t.Fatalf("MarkerExists after delete: %v", err)
	}
	if exists {
		t.Fatalf("expected no marker after delete")
	}

	if err := DeleteMarker(); err != nil {
		t.Fatalf("DeleteMarker on missing: %v", err)
	}
}

func TestMarkerCorruptedBlobIsNonExistent(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("APPDATA", tmp)

	p, err := markerPath()
	if err != nil {
		t.Fatalf("markerPath: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(p, []byte("garbage"), 0o600); err != nil {
		t.Fatalf("write garbage: %v", err)
	}

	exists, err := MarkerExists()
	if err != nil {
		t.Fatalf("MarkerExists: %v", err)
	}
	if exists {
		t.Fatalf("expected corrupted blob to count as no marker")
	}
}
