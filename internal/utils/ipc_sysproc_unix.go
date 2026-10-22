//go:build !windows

package utils

import "syscall"

type sysProcAttr = syscall.SysProcAttr

func DaemonSysProcAttrs() []*sysProcAttr {
	return []*sysProcAttr{{Setsid: true}}
}

func JobStatus() string { return "" }
