//go:build darwin

package clientinfo

import (
	ps "github.com/mitchellh/go-ps"
)

// On macOS without cgo we can only obtain the basename via go-ps. The
// non-cgo path to a full exe path requires libproc / proc_pidpath, so
// we degrade to Name-only here.
func Lookup(pid int) Info {
	info := Info{PID: pid}
	if pid <= 0 {
		return info
	}
	if p, err := ps.FindProcess(pid); err == nil && p != nil {
		info.Name = p.Executable()
	}
	fillFromGopsutil(&info)
	return info
}
