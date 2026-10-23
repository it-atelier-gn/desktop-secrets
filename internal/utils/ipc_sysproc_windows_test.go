//go:build windows

package utils

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"golang.org/x/sys/windows"
)

const (
	jobHelperEnv  = "DESKTOP_SECRETS_JOB_HELPER"
	jobPidFileEnv = "DESKTOP_SECRETS_JOB_HELPER_PIDFILE"
	testTaskName  = "desktop-secrets test helper"
	helperRun     = "-test.run=^TestJobHelper$"
)

func TestDaemonLaunchersOrder(t *testing.T) {
	ls := DaemonLaunchers()
	names := make([]string, len(ls))
	for i, l := range ls {
		names[i] = l.Name
	}
	want := []string{"breakaway from job", "task scheduler", "detached inside job"}
	if !slices.Equal(names, want) {
		t.Fatalf("launchers = %v, want %v", names, want)
	}
	for i, l := range ls {
		if l.Degraded != (i == len(ls)-1) {
			t.Fatalf("launcher %q degraded=%v", l.Name, l.Degraded)
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
	pidFile := filepath.Join(t.TempDir(), "pid")
	runHelper(t, "parent", pidFile)
	pid, _ := waitForChild(t, pidFile)
	assertSurvives(t, pid)
}

func TestScheduledDaemonSurvivesJobWithoutBreakaway(t *testing.T) {
	if os.Getenv(jobHelperEnv) != "" {
		t.Skip("helper process")
	}
	if os.Getenv("CI") != "" {
		t.Skip("task scheduler needs an interactive logon session")
	}
	pidFile := filepath.Join(t.TempDir(), "pid")
	t.Cleanup(func() { _ = deleteScheduledTask(testTaskName) })
	runHelper(t, "strict-parent", pidFile)

	pid, status := waitForChild(t, pidFile)
	t.Logf("scheduled child: %s", status)
	if strings.Contains(status, "kill-on-close=true") {
		t.Fatalf("scheduled child runs in a kill-on-close job: %s", status)
	}
	assertSurvives(t, pid)
}

func TestJobHelper(t *testing.T) {
	ApplySetenvArgs(os.Args)
	switch os.Getenv(jobHelperEnv) {
	case "parent":
		runJobParent(t)
	case "strict-parent":
		runStrictJobParent(t)
	case "child":
		data := fmt.Sprintf("%d\n%s", os.Getpid(), JobStatus())
		if err := os.WriteFile(os.Getenv(jobPidFileEnv), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		time.Sleep(30 * time.Second)
	default:
		t.Skip("helper process")
	}
}

func runJobParent(t *testing.T) {
	job := enterKillOnCloseJob(t, windows.JOB_OBJECT_LIMIT_BREAKAWAY_OK)
	defer windows.CloseHandle(job)
	t.Setenv(jobHelperEnv, "child")
	if err := DaemonLaunchers()[0].Start(testExe(t), []string{helperRun}, nil); err != nil {
		t.Fatal(err)
	}
}

func runStrictJobParent(t *testing.T) {
	job := enterKillOnCloseJob(t, 0)
	defer windows.CloseHandle(job)
	exe := testExe(t)
	args := []string{helperRun, "--"}
	if err := DaemonLaunchers()[0].Start(exe, args, nil); err == nil {
		t.Fatal("breakaway must fail inside a job without JOB_OBJECT_LIMIT_BREAKAWAY_OK")
	}
	env := []string{jobHelperEnv + "=child", jobPidFileEnv + "=" + os.Getenv(jobPidFileEnv)}
	if err := startScheduledTask(testTaskName, exe, args, env); err != nil {
		t.Fatal(err)
	}
}

func enterKillOnCloseJob(t *testing.T, extra uint32) windows.Handle {
	t.Helper()
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | extra
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		t.Fatal(err)
	}
	if err := windows.AssignProcessToJobObject(job, windows.CurrentProcess()); err != nil {
		t.Fatal(err)
	}
	return job
}

func runHelper(t *testing.T, role, pidFile string) {
	t.Helper()
	cmd := exec.Command(testExe(t), helperRun)
	cmd.Env = append(os.Environ(), jobHelperEnv+"="+role, jobPidFileEnv+"="+pidFile)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("helper failed: %v\n%s", err, out)
	}
}

func waitForChild(t *testing.T, pidFile string) (int, string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		data, err := os.ReadFile(pidFile)
		if pidLine, status, ok := strings.Cut(string(data), "\n"); err == nil && ok {
			pid, err := strconv.Atoi(pidLine)
			if err != nil {
				t.Fatalf("pid file %q: %v", data, err)
			}
			return pid, status
		}
		if time.Now().After(deadline) {
			t.Fatalf("child did not report its pid: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func assertSurvives(t *testing.T, pid int) {
	t.Helper()
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

func deleteScheduledTask(name string) error {
	_, sid, err := currentUser()
	if err != nil {
		return err
	}
	return withScheduler(func(svc *ole.IDispatch) error {
		v, err := oleutil.CallMethod(svc, "GetFolder", `\`)
		if err != nil {
			return err
		}
		defer v.Clear()
		_, err = oleutil.CallMethod(v.ToIDispatch(), "DeleteTask", name+" "+sid, 0)
		return err
	})
}

func testExe(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return exe
}
