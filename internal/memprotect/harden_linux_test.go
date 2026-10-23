//go:build linux

package memprotect

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	helperEnv    = "DESKTOP_SECRETS_MEMPROTECT_HELPER"
	helperDirEnv = "DESKTOP_SECRETS_MEMPROTECT_DIR"
)

func TestMemprotectHelper(t *testing.T) {
	role := os.Getenv(helperEnv)
	if role == "" {
		t.Skip("helper process")
	}
	if role == "hardened" {
		if err := HardenProcess(); err != nil {
			t.Fatal(err)
		}
	}
	if err := Init(); err != nil {
		t.Fatal(err)
	}
	data := fmt.Sprintf("%d\n", os.Getpid())
	if err := os.WriteFile(filepath.Join(os.Getenv(helperDirEnv), "pid"), []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Second)
}

func startHelper(t *testing.T, role string) int {
	t.Helper()
	dir := t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestMemprotectHelper$")
	cmd.Env = append(os.Environ(), helperEnv+"="+role, helperDirEnv+"="+dir)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	deadline := time.Now().Add(15 * time.Second)
	for {
		data, _ := os.ReadFile(filepath.Join(dir, "pid"))
		if line, _, ok := strings.Cut(string(data), "\n"); ok {
			pid, err := strconv.Atoi(line)
			if err != nil {
				t.Fatal(err)
			}
			return pid
		}
		if time.Now().After(deadline) {
			t.Fatal("helper did not report its pid")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func openMem(pid int) error {
	f, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err == nil {
		f.Close()
	}
	return err
}

func TestHardenedProcessRejectsMemoryAccess(t *testing.T) {
	if os.Getenv(helperEnv) != "" {
		t.Skip("helper process")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses the dumpable check")
	}
	if err := openMem(startHelper(t, "plain")); err != nil {
		t.Skipf("memory of an unhardened child is not readable here either: %v", err)
	}

	err := openMem(startHelper(t, "hardened"))
	if err == nil {
		t.Fatal("/proc/<pid>/mem of the hardened process is readable by the same user")
	}
	if !errors.Is(err, syscall.EACCES) && !errors.Is(err, syscall.EPERM) {
		t.Fatalf("unexpected error: %v", err)
	}
}
