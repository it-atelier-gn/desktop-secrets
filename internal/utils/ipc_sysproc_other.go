//go:build !windows && !linux

package utils

import "syscall"

func DaemonLaunchers() []DaemonLauncher {
	return []DaemonLauncher{
		{Name: "new session", Start: spawnWith(&syscall.SysProcAttr{Setsid: true})},
	}
}

func JobStatus() string { return "" }

func JobKillsOnClose() bool { return false }
