//go:build windows

package utils

import "syscall"

type sysProcAttr = syscall.SysProcAttr

func DetachSysProcAttr() *sysProcAttr { return &syscall.SysProcAttr{} }

// CREATE_NO_WINDOW flag to avoid console popping on daemon start.
func HideWindowSysProcAttr() *sysProcAttr {
	return &syscall.SysProcAttr{CreationFlags: 0x08000000}
}
