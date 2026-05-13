//go:build windows

package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/it-atelier-gn/desktop-secrets/internal/utils"
)

// DPAPI is what protects this blob. It's the same primitive Windows
// uses for the saved credentials in Credential Manager: encryption
// keys derive from the user's logon credentials, so another user on
// the same machine can't decrypt the blob, and a non-logged-in
// attacker who copies the file off the disk can't either.
//
// Failure modes worth knowing:
//   - The blob is *user-scope* (CRYPTPROTECT_LOCAL_MACHINE is NOT
//     passed). A password change keeps it readable; a domain
//     password reset by an admin invalidates it. On reset we treat a
//     decrypt failure as "no keystore yet" and rebuild from disk.
//   - On Windows running under a roaming profile, the blob will roam
//     with the user. That's fine — it's bound to the user, not the
//     machine.

var (
	modCrypt32             = windows.NewLazySystemDLL("crypt32.dll")
	procCryptProtectData   = modCrypt32.NewProc("CryptProtectData")
	procCryptUnprotectData = modCrypt32.NewProc("CryptUnprotectData")
)

type dataBlob struct {
	cbData uint32
	pbData *byte
}

func newBlob(b []byte) *dataBlob {
	if len(b) == 0 {
		return &dataBlob{}
	}
	return &dataBlob{
		cbData: uint32(len(b)),
		pbData: &b[0],
	}
}

func (b *dataBlob) toBytes() []byte {
	if b.cbData == 0 || b.pbData == nil {
		return nil
	}
	out := make([]byte, b.cbData)
	src := unsafe.Slice(b.pbData, int(b.cbData))
	copy(out, src)
	return out
}

func dpapiProtect(plain []byte) ([]byte, error) {
	in := newBlob(plain)
	out := dataBlob{}
	ret, _, err := procCryptProtectData.Call(
		uintptr(unsafe.Pointer(in)),
		0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&out)),
	)
	if ret == 0 {
		return nil, fmt.Errorf("CryptProtectData failed: %w", err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.pbData)))
	return out.toBytes(), nil
}

func dpapiUnprotect(cipher []byte) ([]byte, error) {
	in := newBlob(cipher)
	out := dataBlob{}
	ret, _, err := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(in)),
		0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&out)),
	)
	if ret == 0 {
		return nil, fmt.Errorf("CryptUnprotectData failed: %w", err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.pbData)))
	return out.toBytes(), nil
}

type winStore struct {
	path string
}

// DefaultStore returns the production keystore at
// <settings>/policy.dpapi. The directory is created lazily on first
// Save — Load handles the missing-file case as "first run".
func DefaultStore() (Store, error) {
	dir, err := utils.GetSettingsDirectory()
	if err != nil {
		return nil, err
	}
	return &winStore{path: filepath.Join(dir, "policy.dpapi")}, nil
}

func (s *winStore) Load() (*Policy, error) {
	b, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	plain, err := dpapiUnprotect(b)
	if err != nil {
		// A failed decrypt means somebody tampered with the blob, the
		// user's DPAPI key was reset, or we're running as a different
		// user than the one who wrote the blob. Return nil so the
		// caller treats this as "no keystore yet" — Reconcile will
		// re-prompt for any weakening relative to first-run defaults.
		return nil, nil
	}
	p, err := Unmarshal(plain)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (s *winStore) Save(p Policy) error {
	plain, err := p.Marshal()
	if err != nil {
		return err
	}
	cipher, err := dpapiProtect(plain)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	// Use a tmp + rename so a crash mid-write doesn't leave the
	// keystore truncated. Forced unused-import guard for syscall.
	_ = syscall.O_WRONLY
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, cipher, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
