//go:build windows

package ipc

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type rawConner interface {
	SyscallConn() (syscall.RawConn, error)
}

// fdGetter is implemented by go-winio's pipe connection, which does not
// expose SyscallConn. We use this as a fallback so the pipe handle can
// be passed directly to GetNamedPipeClientProcessId.
type fdGetter interface {
	Fd() uintptr
}

func peerPID(c net.Conn) (int, error) {
	var pid uint32

	if rc, ok := c.(rawConner); ok {
		raw, err := rc.SyscallConn()
		if err == nil {
			var callErr error
			ctlErr := raw.Control(func(fd uintptr) {
				callErr = getNamedPipeClientProcessId(windows.Handle(fd), &pid)
			})
			if ctlErr == nil && callErr == nil {
				return int(pid), nil
			}
		}
	}

	if fg, ok := c.(fdGetter); ok {
		if err := getNamedPipeClientProcessId(windows.Handle(fg.Fd()), &pid); err == nil {
			return int(pid), nil
		} else {
			return 0, err
		}
	}

	return 0, fmt.Errorf("connection exposes neither SyscallConn nor Fd (type %T)", c)
}

var (
	modKernel32                    = windows.NewLazySystemDLL("kernel32.dll")
	procGetNamedPipeClientProcessId = modKernel32.NewProc("GetNamedPipeClientProcessId")
)

func getNamedPipeClientProcessId(h windows.Handle, pid *uint32) error {
	r1, _, e1 := procGetNamedPipeClientProcessId.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(pid)),
	)
	if r1 == 0 {
		if e1 != nil {
			return e1
		}
		return windows.ERROR_INVALID_HANDLE
	}
	return nil
}
