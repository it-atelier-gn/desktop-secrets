//go:build integration && windows

package main_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/it-atelier-gn/desktop-secrets/internal/policy"
)

func buildLiteBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "getsec.exe")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = ""
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}
	return bin
}

func writeMarkerInto(t *testing.T, appdata string) {
	t.Helper()
	t.Setenv("APPDATA", appdata)
	if err := policy.WriteMarker(); err != nil {
		t.Fatalf("WriteMarker: %v", err)
	}
}

func TestIntegration_LiteRefusesWhenMarkerPresent(t *testing.T) {
	bin := buildLiteBinary(t)
	appdata := t.TempDir()
	writeMarkerInto(t, appdata)

	cmd := exec.Command(bin, "--daemon")
	cmd.Env = append(os.Environ(), "APPDATA="+appdata)

	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatalf("expected non-zero exit when marker is present, got success")
		}
	case <-time.After(8 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("daemon did not exit within timeout when marker should have refused it")
	}
}

func TestIntegration_AllowDowngradeRemovesMarker(t *testing.T) {
	bin := buildLiteBinary(t)
	appdata := t.TempDir()
	writeMarkerInto(t, appdata)

	exists, err := policy.MarkerExists()
	if err != nil || !exists {
		t.Fatalf("precondition: marker should exist, got exists=%v err=%v", exists, err)
	}

	cmd := exec.Command(bin, "--allow-downgrade")
	cmd.Env = append(os.Environ(), "APPDATA="+appdata)
	cmd.Stdin = strings.NewReader("yes\n")

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("--allow-downgrade exited non-zero: %v\nstdout:\n%s", err, out)
	}
	if !strings.Contains(string(out), "Hardened marker removed") {
		t.Fatalf("expected confirmation message in output, got:\n%s", out)
	}

	exists, err = policy.MarkerExists()
	if err != nil {
		t.Fatalf("post: MarkerExists err: %v", err)
	}
	if exists {
		t.Fatalf("marker should have been removed by --allow-downgrade")
	}
}

func TestIntegration_AllowDowngradeAbortsOnNo(t *testing.T) {
	bin := buildLiteBinary(t)
	appdata := t.TempDir()
	writeMarkerInto(t, appdata)

	cmd := exec.Command(bin, "--allow-downgrade")
	cmd.Env = append(os.Environ(), "APPDATA="+appdata)
	cmd.Stdin = strings.NewReader("no\n")

	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected non-zero exit when user declines, got success.\noutput:\n%s", out)
	}
	if !strings.Contains(string(out), "Aborted") {
		t.Fatalf("expected 'Aborted' message, got:\n%s", out)
	}
	exists, err := policy.MarkerExists()
	if err != nil {
		t.Fatalf("MarkerExists: %v", err)
	}
	if !exists {
		t.Fatalf("marker should still be present after declined downgrade")
	}
}
