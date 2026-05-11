//go:build !windows && !linux && !darwin

package clientinfo

import ps "github.com/mitchellh/go-ps"

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
