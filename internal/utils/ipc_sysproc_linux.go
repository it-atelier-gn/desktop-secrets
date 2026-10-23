//go:build linux

package utils

import (
	"os"
	"strings"
	"syscall"
)

func DaemonLaunchers() []DaemonLauncher {
	return []DaemonLauncher{
		{Name: "systemd user unit", Start: startSystemdDaemon},
		{Name: "new session", Start: spawnWith(&syscall.SysProcAttr{Setsid: true})},
	}
}

func JobStatus() string {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "cgroup: unknown: " + err.Error()
	}
	return "cgroup: " + parseCgroup(string(data))
}

func parseCgroup(data string) string {
	for _, line := range strings.Split(strings.TrimSpace(data), "\n") {
		if path, ok := strings.CutPrefix(line, "0::"); ok {
			return path
		}
	}
	return strings.TrimSpace(data)
}

func JobKillsOnClose() bool { return false }
