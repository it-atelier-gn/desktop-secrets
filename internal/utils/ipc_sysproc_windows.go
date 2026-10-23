//go:build windows

package utils

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	detachedFlags = windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP
	breakawayFlag = windows.CREATE_BREAKAWAY_FROM_JOB
)

var procIsProcessInJob = windows.NewLazySystemDLL("kernel32.dll").NewProc("IsProcessInJob")

func DaemonLaunchers() []DaemonLauncher {
	return []DaemonLauncher{
		{Name: "breakaway from job", Start: spawnWith(&syscall.SysProcAttr{CreationFlags: detachedFlags | breakawayFlag, HideWindow: true})},
		{Name: "task scheduler", Start: startScheduledDaemon},
		{Name: "detached inside job", Start: spawnWith(&syscall.SysProcAttr{CreationFlags: detachedFlags, HideWindow: true}), Degraded: true},
	}
}

type jobInfo struct {
	inJob bool
	flags uint32
}

func currentJob() (jobInfo, error) {
	var inJob int32
	r, _, err := procIsProcessInJob.Call(uintptr(windows.CurrentProcess()), 0, uintptr(unsafe.Pointer(&inJob)))
	if r == 0 {
		return jobInfo{}, fmt.Errorf("status unknown: %v", err)
	}
	if inJob == 0 {
		return jobInfo{}, nil
	}
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	err = windows.QueryInformationJobObject(0, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), nil)
	if err != nil {
		return jobInfo{inJob: true}, fmt.Errorf("inside a job object, limits unknown: %v", err)
	}
	return jobInfo{inJob: true, flags: info.BasicLimitInformation.LimitFlags}, nil
}

func JobStatus() string {
	j, err := currentJob()
	if err != nil {
		return "job: " + err.Error()
	}
	if !j.inJob {
		return "job: not inside a job object"
	}
	return fmt.Sprintf("job: inside a job object (kill-on-close=%v, breakaway-ok=%v)",
		j.flags&windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE != 0,
		j.flags&windows.JOB_OBJECT_LIMIT_BREAKAWAY_OK != 0)
}

func JobKillsOnClose() bool {
	j, err := currentJob()
	return err == nil && j.flags&windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE != 0
}
