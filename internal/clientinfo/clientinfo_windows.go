//go:build windows

package clientinfo

import (
	"path/filepath"
	"unsafe"

	ps "github.com/mitchellh/go-ps"
	"golang.org/x/sys/windows"
)

func Lookup(pid int) Info {
	info := Info{PID: pid}
	if pid <= 0 {
		return info
	}
	if p, err := ps.FindProcess(pid); err == nil && p != nil {
		info.Name = p.Executable()
	}
	if path, err := queryFullImageName(uint32(pid)); err == nil {
		info.ExePath = path
		if info.Name == "" {
			info.Name = filepath.Base(path)
		}
	}
	if st, err := processStartTime(uint32(pid)); err == nil {
		info.StartTime = st
	}
	fillFromGopsutil(&info)
	return info
}

func processStartTime(pid uint32) (uint64, error) {
	const PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
	h, err := windows.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(h)
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &creation, &exit, &kernel, &user); err != nil {
		return 0, err
	}
	return uint64(creation.HighDateTime)<<32 | uint64(creation.LowDateTime), nil
}

func queryFullImageName(pid uint32) (string, error) {
	const PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
	h, err := windows.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)

	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf))
	if err := queryFullProcessImageNameW(h, 0, &buf[0], &size); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf[:size]), nil
}

var (
	modKernel32                  = windows.NewLazySystemDLL("kernel32.dll")
	procQueryFullProcessImageNameW = modKernel32.NewProc("QueryFullProcessImageNameW")
)

func queryFullProcessImageNameW(h windows.Handle, flags uint32, buf *uint16, size *uint32) error {
	r1, _, e1 := procQueryFullProcessImageNameW.Call(
		uintptr(h),
		uintptr(flags),
		uintptr(unsafe.Pointer(buf)),
		uintptr(unsafe.Pointer(size)),
	)
	if r1 == 0 {
		if e1 != nil {
			return e1
		}
		return windows.ERROR_INVALID_HANDLE
	}
	return nil
}
