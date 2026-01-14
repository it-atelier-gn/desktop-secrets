//go:build windows

package shm

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	shmNameWin = "Local\\DesktopSecretsState"
	shmSize    = 4096
)

// daemon handle + view kept open for lifetime, so the mapping exists.
type winShm struct {
	handle windows.Handle
	view   uintptr
}

var shmGlobal *winShm

// shmDaemonPublish creates/initializes a named page-file mapping and writes data.
// Keeps the mapping open until cleanup is called.
func ShmDaemonPublish(b []byte) (func(), error) {
	if len(b) > shmSize {
		return nil, fmt.Errorf("state too large (%d > %d)", len(b), shmSize)
	}
	name16, err := windows.UTF16PtrFromString(shmNameWin)
	if err != nil {
		return nil, err
	}

	// Create (or open) RW mapping in Local namespace.
	h, err := windows.CreateFileMapping(windows.InvalidHandle, nil, windows.PAGE_READWRITE, 0, uint32(shmSize), name16)
	if err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return nil, err
	}

	// Map RW view.
	addr, err := windows.MapViewOfFile(h, windows.FILE_MAP_WRITE, 0, 0, uintptr(shmSize))
	if err != nil {
		windows.CloseHandle(h)
		return nil, err
	}

	// Write content + zero remainder.
	buf := unsafe.Slice((*byte)(unsafe.Pointer(addr)), shmSize)
	copy(buf, b)
	if len(b) < len(buf) {
		for i := len(b); i < len(buf); i++ {
			buf[i] = 0
		}
	}

	shmGlobal = &winShm{handle: h, view: addr}

	cleanup := func() {
		if shmGlobal != nil {
			_ = windows.UnmapViewOfFile(shmGlobal.view)
			_ = windows.CloseHandle(shmGlobal.handle)
			shmGlobal = nil
		}
	}
	return cleanup, nil
}

// Call OpenFileMappingW directly (not present in x/sys/windows).
var (
	modKernel32          = windows.NewLazySystemDLL("kernel32.dll")
	procOpenFileMappingW = modKernel32.NewProc("OpenFileMappingW")
)

func openFileMapping(desiredAccess uint32, inherit bool, name *uint16) (windows.Handle, error) {
	inher := uintptr(0)
	if inherit {
		inher = 1
	}
	r0, _, e1 := procOpenFileMappingW.Call(uintptr(desiredAccess), inher, uintptr(unsafe.Pointer(name)))
	if r0 == 0 {
		if e1 != nil {
			return 0, e1
		}
		return 0, windows.ERROR_INVALID_HANDLE
	}
	return windows.Handle(r0), nil
}

// ShmClientRead opens the mapping RO and returns the non-zero prefix.
func ShmClientRead() ([]byte, error) {
	name16, err := windows.UTF16PtrFromString(shmNameWin)
	if err != nil {
		return nil, err
	}
	h, err := openFileMapping(windows.FILE_MAP_READ, false, name16)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(h)

	addr, err := windows.MapViewOfFile(h, windows.FILE_MAP_READ, 0, 0, uintptr(shmSize))
	if err != nil {
		return nil, err
	}
	defer windows.UnmapViewOfFile(addr)

	buf := unsafe.Slice((*byte)(unsafe.Pointer(addr)), shmSize)
	n := len(buf)
	for n > 0 && buf[n-1] == 0 {
		n--
	}
	out := make([]byte, n)
	copy(out, buf[:n])
	return out, nil
}

func shmRemove() {}
