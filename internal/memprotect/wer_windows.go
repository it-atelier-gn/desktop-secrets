//go:build windows

package memprotect

import (
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	werDLL                        = syscall.NewLazyDLL("wer.dll")
	procWerAddExcludedApplication = werDLL.NewProc("WerAddExcludedApplication")
)

func DisableErrorReporting() {
	const (
		semFailCriticalErrors = 0x0001
		semNoGPFaultErrorBox  = 0x0002
		semNoOpenFileErrorBox = 0x8000
	)
	windows.SetErrorMode(semFailCriticalErrors | semNoGPFaultErrorBox | semNoOpenFileErrorBox)

	if exe, err := os.Executable(); err == nil {
		name := filepath.Base(exe)
		if p, err := syscall.UTF16PtrFromString(name); err == nil {
			_, _, _ = procWerAddExcludedApplication.Call(
				uintptr(unsafe.Pointer(p)),
				0,
			)
		}
	}
}
