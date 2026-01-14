//go:build !windows

package utils

import "syscall"

type sysProcAttr = syscall.SysProcAttr

func DetachSysProcAttr() *sysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}

func HideWindowSysProcAttr() *sysProcAttr { return nil }
