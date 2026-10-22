//go:build windows

package utils

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const jobHelperEnv = "DESKTOP_SECRETS_JOB_HELPER"

func TestDaemonSysProcAttrsBreakAwayFirst(t *testing.T) {
	attrs := DaemonSysProcAttrs()
	if len(attrs) != 2 {
		t.Fatalf("expected 2 attempts, got %d", len(attrs))
	}
	if attrs[0].CreationFlags&windows.CREATE_BREAKAWAY_FROM_JOB == 0 {
		t.Fatal("first attempt must break away from the caller's job")
	}
	if attrs[1].CreationFlags&windows.CREATE_BREAKAWAY_FROM_JOB != 0 {
		t.Fatal("fallback attempt must not request breakaway")
	}
	for i, a := range attrs {
		if a.CreationFlags&windows.DETACHED_PROCESS == 0 {
			t.Fatalf("attempt %d is not detached from the console", i)
		}
		if a.CreationFlags&windows.CREATE_NEW_PROCESS_GROUP == 0 {
			t.Fatalf("attempt %d does not start a new process group", i)
		}
	}
}

func TestJobStatusReportsJob(t *testing.T) {
	if s := JobStatus(); !strings.HasPrefix(s, "job: ") {
		t.Fatalf("unexpected status %q", s)
	}
}

func TestDaemonSurvivesKillOnJobClose(t *testing.T) {
	if os.Getenv(jobHelperEnv) != "" {
		t.Skip("helper process")
	}
	out, err := helperCmd(t, "TestJobHelper").Output()
	if err != nil {
		t.Fatalf("helper failed: %v\n%s", err, out)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		t.Fatalf("helper output %q: %v", out, err)
	}
	h, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		t.Fatalf("child %d is gone after job close: %v", pid, err)
	}
	defer windows.CloseHandle(h)
	defer windows.TerminateProcess(h, 0)

	ev, err := windows.WaitForSingleObject(h, 500)
	if err != nil {
		t.Fatal(err)
	}
	if ev == windows.WAIT_OBJECT_0 {
		t.Fatalf("child %d was terminated with the job", pid)
	}
}

func TestJobHelper(t *testing.T) {
	switch os.Getenv(jobHelperEnv) {
	case "parent":
		runJobParent(t)
	case "child":
		time.Sleep(30 * time.Second)
	default:
		t.Skip("helper process")
	}
}

func runJobParent(t *testing.T) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | windows.JOB_OBJECT_LIMIT_BREAKAWAY_OK
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		t.Fatal(err)
	}
	if err := windows.AssignProcessToJobObject(job, windows.CurrentProcess()); err != nil {
		t.Fatal(err)
	}

	cmd := helperCmd(t, "TestJobHelper")
	cmd.Env = append(os.Environ(), jobHelperEnv+"=child")
	cmd.SysProcAttr = DaemonSysProcAttrs()[0]
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	fmt.Println(cmd.Process.Pid)
	windows.CloseHandle(job)
}

func helperCmd(t *testing.T, name string) *exec.Cmd {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^"+name+"$")
	cmd.Env = append(os.Environ(), jobHelperEnv+"=parent")
	return cmd
}
