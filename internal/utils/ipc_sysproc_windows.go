//go:build windows

package utils

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type sysProcAttr = syscall.SysProcAttr

const (
	detachedFlags = windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP
	breakawayFlag = windows.CREATE_BREAKAWAY_FROM_JOB
)

var procIsProcessInJob = windows.NewLazySystemDLL("kernel32.dll").NewProc("IsProcessInJob")

func DaemonSysProcAttrs() []*sysProcAttr {
	return []*sysProcAttr{
		{CreationFlags: detachedFlags | breakawayFlag, HideWindow: true},
		{CreationFlags: detachedFlags, HideWindow: true},
	}
}

func JobStatus() string {
	var inJob int32
	r, _, err := procIsProcessInJob.Call(uintptr(windows.CurrentProcess()), 0, uintptr(unsafe.Pointer(&inJob)))
	if r == 0 {
		return fmt.Sprintf("job: status unknown: %v", err)
	}
	if inJob == 0 {
		return "job: not inside a job object"
	}
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	err = windows.QueryInformationJobObject(0, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), nil)
	if err != nil {
		return fmt.Sprintf("job: inside a job object, limits unknown: %v", err)
	}
	flags := info.BasicLimitInformation.LimitFlags
	return fmt.Sprintf("job: inside a job object (kill-on-close=%v, breakaway-ok=%v)",
		flags&windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE != 0,
		flags&windows.JOB_OBJECT_LIMIT_BREAKAWAY_OK != 0)
}
