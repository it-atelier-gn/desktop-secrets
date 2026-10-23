//go:build windows

package memprotect

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	cryptProtectBlockSize   = 16
	cryptProtectSameProcess = 0
)

var (
	crypt32                  = windows.NewLazySystemDLL("crypt32.dll")
	procCryptProtectMemory   = crypt32.NewProc("CryptProtectMemory")
	procCryptUnprotectMemory = crypt32.NewProc("CryptUnprotectMemory")
)

func Init() error {
	probe := make([]byte, cryptProtectBlockSize)
	if err := cryptMemory(procCryptProtectMemory, probe); err != nil {
		return err
	}
	return cryptMemory(procCryptUnprotectMemory, probe)
}

func seal(plaintext []byte) (*Sealed, error) {
	buf := make([]byte, (len(plaintext)/cryptProtectBlockSize+1)*cryptProtectBlockSize)
	copy(buf, plaintext)
	if err := cryptMemory(procCryptProtectMemory, buf); err != nil {
		Wipe(buf)
		return nil, err
	}
	return &Sealed{ct: buf, n: len(plaintext)}, nil
}

func open(s *Sealed) ([]byte, error) {
	buf := make([]byte, len(s.ct))
	copy(buf, s.ct)
	if err := cryptMemory(procCryptUnprotectMemory, buf); err != nil {
		Wipe(buf)
		return nil, err
	}
	Wipe(buf[s.n:])
	return buf[:s.n:s.n], nil
}

func cryptMemory(proc *windows.LazyProc, buf []byte) error {
	r, _, err := proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), cryptProtectSameProcess)
	if r == 0 {
		return fmt.Errorf("memprotect: %s: %w", proc.Name, err)
	}
	return nil
}
