//go:build windows

package memprotect

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

const (
	helperEnv     = "DESKTOP_SECRETS_MEMPROTECT_HELPER"
	helperDirEnv  = "DESKTOP_SECRETS_MEMPROTECT_DIR"
	miniDumpFull  = 0x2
	helperTimeout = 15 * time.Second
)

var procMiniDumpWriteDump = windows.NewLazySystemDLL("dbghelp.dll").NewProc("MiniDumpWriteDump")

func TestMemprotectHelper(t *testing.T) {
	role := os.Getenv(helperEnv)
	if role == "" {
		t.Skip("helper process")
	}
	dir := os.Getenv(helperDirEnv)
	if role == "hardened" {
		if err := HardenProcess(); err != nil {
			t.Fatal(err)
		}
	}
	secret, err := os.ReadFile(filepath.Join(dir, "secret"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := Seal(secret)
	Wipe(secret)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := s.Open()
	if err != nil {
		t.Fatal(err)
	}
	ok := len(pt) == 32
	Wipe(pt)
	if !ok {
		t.Fatal("round trip failed")
	}
	state := fmt.Sprintf("%d\n%s\n", os.Getpid(), hex.EncodeToString(s.ct))
	if err := os.WriteFile(filepath.Join(dir, "state"), []byte(state), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Second)
}

func startHelper(t *testing.T, role string) (pid int, ct []byte, secret []byte) {
	t.Helper()
	dir := t.TempDir()
	secret = make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "secret"), secret, 0o600); err != nil {
		t.Fatal(err)
	}
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

	deadline := time.Now().Add(helperTimeout)
	for {
		data, _ := os.ReadFile(filepath.Join(dir, "state"))
		if lines := strings.Split(string(data), "\n"); len(lines) == 3 {
			pid, _ = strconv.Atoi(lines[0])
			ct, _ = hex.DecodeString(lines[1])
			return pid, ct, secret
		}
		if time.Now().After(deadline) {
			t.Fatal("helper did not report its state")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func fullDump(t *testing.T, pid int) []byte {
	t.Helper()
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, uint32(pid))
	if err != nil {
		t.Fatalf("OpenProcess: %v", err)
	}
	defer windows.CloseHandle(h)
	path := filepath.Join(t.TempDir(), "helper.dmp")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	r, _, callErr := procMiniDumpWriteDump.Call(uintptr(h), uintptr(pid), f.Fd(), miniDumpFull, 0, 0, 0)
	f.Close()
	if r == 0 {
		t.Fatalf("MiniDumpWriteDump: %v", callErr)
	}
	dump, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return dump
}

func TestDumpOfProcessDoesNotRevealSecret(t *testing.T) {
	if os.Getenv(helperEnv) != "" {
		t.Skip("helper process")
	}
	pid, ct, secret := startHelper(t, "plain")
	dump := fullDump(t, pid)

	if !bytes.Contains(dump, ct) {
		t.Fatal("dump does not contain the sealed value; the test does not look at the right memory")
	}
	if bytes.Contains(dump, secret) {
		t.Fatal("dump contains the plaintext secret")
	}
	foreign := bytes.Clone(ct)
	if err := cryptMemory(procCryptUnprotectMemory, foreign); err == nil && bytes.Contains(foreign, secret) {
		t.Fatal("ciphertext from the dump decrypts in another process")
	}
}

func TestHardenedProcessRejectsMemoryAccess(t *testing.T) {
	if os.Getenv(helperEnv) != "" {
		t.Skip("helper process")
	}
	pid, _, _ := startHelper(t, "hardened")

	for name, access := range map[string]uint32{
		"PROCESS_VM_READ":       windows.PROCESS_VM_READ,
		"PROCESS_VM_WRITE":      windows.PROCESS_VM_WRITE | windows.PROCESS_VM_OPERATION,
		"PROCESS_CREATE_THREAD": windows.PROCESS_CREATE_THREAD,
		"PROCESS_DUP_HANDLE":    windows.PROCESS_DUP_HANDLE,
		"WRITE_DAC":             windows.WRITE_DAC,
		"WRITE_OWNER":           windows.WRITE_OWNER,
	} {
		h, err := windows.OpenProcess(access, false, uint32(pid))
		if err == nil {
			windows.CloseHandle(h)
			t.Errorf("%s granted to the same user", name)
		} else if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			t.Errorf("%s: unexpected error %v", name, err)
		}
	}

	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		t.Fatalf("query must stay available: %v", err)
	}
	windows.CloseHandle(h)

	h, err = windows.OpenProcess(windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_INFORMATION|windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		t.Fatalf("terminate as requested by taskkill and Task Manager must stay available: %v", err)
	}
	defer windows.CloseHandle(h)
	if err := windows.TerminateProcess(h, 0); err != nil {
		t.Fatalf("terminate: %v", err)
	}
	if ev, _ := windows.WaitForSingleObject(h, 5000); ev != windows.WAIT_OBJECT_0 {
		t.Fatal("hardened process did not end after TerminateProcess")
	}
}
