//go:build windows

package utils

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	detachedFlags = windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP
	breakawayFlag = windows.CREATE_BREAKAWAY_FROM_JOB
)

var (
	procIsProcessInJob = windows.NewLazySystemDLL("kernel32.dll").NewProc("IsProcessInJob")
	errStillInJob      = errors.New("the process is still inside an outer job object")
)

func DaemonLaunchers() []DaemonLauncher {
	breakaway := &syscall.SysProcAttr{CreationFlags: detachedFlags | breakawayFlag, HideWindow: true}
	return []DaemonLauncher{
		{Name: "breakaway from job", Start: spawnOutsideJob(breakaway)},
		{Name: "task scheduler", Start: startScheduledDaemon},
		{Name: "breakaway from inner job", Start: spawnWith(breakaway), Degraded: true},
		{Name: "detached inside job", Start: spawnWith(&syscall.SysProcAttr{CreationFlags: detachedFlags, HideWindow: true}), Degraded: true},
	}
}

func spawnOutsideJob(attr *syscall.SysProcAttr) func(string, []string, []string) error {
	return func(exe string, args, env []string) error {
		suspended := *attr
		suspended.CreationFlags |= windows.CREATE_SUSPENDED
		cmd := exec.Command(exe, args...)
		cmd.Env = append(os.Environ(), env...)
		cmd.SysProcAttr = &suspended
		if err := cmd.Start(); err != nil {
			return err
		}
		if err := releaseOutsideJob(uint32(cmd.Process.Pid)); err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Process.Release()
			return err
		}
		return cmd.Process.Release()
	}
}

func releaseOutsideJob(pid uint32) error {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return fmt.Errorf("open started process: %w", err)
	}
	defer windows.CloseHandle(h)
	inJob, err := processInJob(h)
	if err != nil {
		return err
	}
	if inJob {
		return errStillInJob
	}
	return resumeProcess(pid)
}

func processInJob(h windows.Handle) (bool, error) {
	var inJob int32
	r, _, err := procIsProcessInJob.Call(uintptr(h), 0, uintptr(unsafe.Pointer(&inJob)))
	if r == 0 {
		return false, fmt.Errorf("status unknown: %v", err)
	}
	return inJob != 0, nil
}

func resumeProcess(pid uint32) error {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return fmt.Errorf("resume started process: %w", err)
	}
	defer windows.CloseHandle(snap)
	te := windows.ThreadEntry32{Size: uint32(unsafe.Sizeof(windows.ThreadEntry32{}))}
	resumed := 0
	for err = windows.Thread32First(snap, &te); err == nil; err = windows.Thread32Next(snap, &te) {
		if te.OwnerProcessID != pid {
			continue
		}
		th, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, te.ThreadID)
		if err != nil {
			return fmt.Errorf("resume started process: %w", err)
		}
		_, err = windows.ResumeThread(th)
		windows.CloseHandle(th)
		if err != nil {
			return fmt.Errorf("resume started process: %w", err)
		}
		resumed++
	}
	if resumed == 0 {
		return errors.New("resume started process: no thread found")
	}
	return nil
}

type jobInfo struct {
	inJob bool
	flags uint32
}

func currentJob() (jobInfo, error) {
	inJob, err := processInJob(windows.CurrentProcess())
	if err != nil {
		return jobInfo{}, err
	}
	if !inJob {
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
