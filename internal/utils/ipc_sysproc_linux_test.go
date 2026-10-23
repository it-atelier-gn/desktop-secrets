//go:build linux

package utils

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	unitHelperEnv  = "DESKTOP_SECRETS_UNIT_HELPER"
	unitPidFileEnv = "DESKTOP_SECRETS_UNIT_HELPER_PIDFILE"
	unitHelperRun  = "-test.run=^TestUnitHelper$"
)

func TestDaemonLaunchersOrder(t *testing.T) {
	ls := DaemonLaunchers()
	var names []string
	for _, l := range ls {
		names = append(names, l.Name)
		if l.Degraded {
			t.Fatalf("launcher %q must not be degraded", l.Name)
		}
	}
	if !slices.Equal(names, []string{"systemd user unit", "new session"}) {
		t.Fatalf("launchers = %v", names)
	}
}

func TestSystemdRunArgs(t *testing.T) {
	got := systemdRunArgs("unit-x", "/opt/getsec", []string{"--daemon"},
		[]string{"HOME=/home/a", "BASH_FUNC_f%%=() { :; }", "DISPLAY=:0", "HOME=/other", "1BAD=x", "EMPTY="})

	want := []string{
		"--user", "--quiet", "--collect", "--same-dir", "--unit=unit-x",
		"--description=desktop-secrets daemon", "--property=Type=exec",
		"--setenv=HOME", "--setenv=DISPLAY", "--setenv=EMPTY",
		"--", "/opt/getsec", "--daemon",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("args =\n%q\nwant\n%q", got, want)
	}
	for _, a := range got {
		if strings.Contains(a, "/home/a") {
			t.Fatalf("environment values must not appear on the command line: %q", a)
		}
	}
}

func TestParseCgroup(t *testing.T) {
	cases := map[string]string{
		"0::/user.slice/user-1000.slice/user@1000.service/app.slice/desktop-secrets-daemon.service\n": "/user.slice/user-1000.slice/user@1000.service/app.slice/desktop-secrets-daemon.service",
		"12:pids:/x\n0::/y\n": "/y",
		"1:name=systemd:/z":   "1:name=systemd:/z",
	}
	for in, want := range cases {
		if got := parseCgroup(in); got != want {
			t.Fatalf("parseCgroup(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestJobStatusReportsCgroup(t *testing.T) {
	if s := JobStatus(); !strings.HasPrefix(s, "cgroup: ") {
		t.Fatalf("unexpected status %q", s)
	}
}

func TestDaemonUnitSurvivesCallerUnitStop(t *testing.T) {
	if os.Getenv(unitHelperEnv) != "" {
		t.Skip("helper process")
	}
	out, _ := exec.Command("systemctl", "--user", "is-system-running").Output()
	if state := strings.TrimSpace(string(out)); state == "" || state == "offline" {
		t.Skip("no systemd user manager")
	}
	suffix := strconv.Itoa(os.Getpid())
	callerUnit := "desktop-secrets-test-caller-" + suffix
	childUnit := "desktop-secrets-test-child-" + suffix
	dir := t.TempDir()
	unitPid := filepath.Join(dir, "unit")
	sessionPid := filepath.Join(dir, "session")
	t.Cleanup(func() { _ = exec.Command("systemctl", "--user", "stop", childUnit+".service").Run() })

	exe := testExe(t)
	cmd := exec.Command("systemd-run", "--user", "--quiet", "--wait", "--collect", "--unit="+callerUnit,
		"--setenv="+unitHelperEnv+"=caller",
		"--setenv="+unitPidFileEnv+"="+unitPid,
		"--setenv=DESKTOP_SECRETS_UNIT_HELPER_SESSION_PIDFILE="+sessionPid,
		"--setenv=DESKTOP_SECRETS_UNIT_HELPER_CHILD_UNIT="+childUnit,
		"--", exe, unitHelperRun)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("caller unit failed: %v\n%s", err, out)
	}

	pid, status := waitForPidFile(t, unitPid)
	t.Logf("unit child: %s", status)
	if !strings.Contains(status, childUnit) {
		t.Fatalf("child is not in its own unit: %s", status)
	}
	sessPid, _ := waitForPidFile(t, sessionPid)
	time.Sleep(300 * time.Millisecond)

	if !processAlive(pid) {
		t.Fatalf("child %d in its own unit was killed with the caller unit", pid)
	}
	if processAlive(sessPid) {
		_ = syscall.Kill(sessPid, syscall.SIGKILL)
		t.Fatalf("setsid child %d survived the caller unit, the test does not reproduce the cgroup kill", sessPid)
	}
}

func TestUnitHelper(t *testing.T) {
	switch os.Getenv(unitHelperEnv) {
	case "caller":
		exe := testExe(t)
		t.Setenv(unitHelperEnv, "child")
		if err := startSystemdUnit(os.Getenv("DESKTOP_SECRETS_UNIT_HELPER_CHILD_UNIT"), exe, []string{unitHelperRun}, nil); err != nil {
			t.Fatal(err)
		}
		t.Setenv(unitPidFileEnv, os.Getenv("DESKTOP_SECRETS_UNIT_HELPER_SESSION_PIDFILE"))
		if err := DaemonLaunchers()[1].Start(exe, []string{unitHelperRun}, nil); err != nil {
			t.Fatal(err)
		}
		waitForPidFile(t, os.Getenv(unitPidFileEnv))
	case "child":
		data := fmt.Sprintf("%d\n%s", os.Getpid(), JobStatus())
		if err := os.WriteFile(os.Getenv(unitPidFileEnv), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		time.Sleep(30 * time.Second)
	default:
		t.Skip("helper process")
	}
}

func waitForPidFile(t *testing.T, path string) (int, string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		data, err := os.ReadFile(path)
		if pidLine, status, ok := strings.Cut(string(data), "\n"); err == nil && ok {
			pid, err := strconv.Atoi(pidLine)
			if err != nil {
				t.Fatalf("pid file %q: %v", data, err)
			}
			return pid, status
		}
		if time.Now().After(deadline) {
			t.Fatalf("child did not report its pid in %s: %v", path, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func processAlive(pid int) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	fields := strings.Fields(string(data))
	return len(fields) > 2 && fields[2] != "Z"
}

func testExe(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return exe
}
