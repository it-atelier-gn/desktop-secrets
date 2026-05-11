package clientinfo

import (
	gopsproc "github.com/shirou/gopsutil/v4/process"
)

// fillFromGopsutil populates the cross-platform Info fields (Cwd,
// Cmdline, Username, Parent*) via gopsutil. Individual platform Lookup
// implementations call this after populating Name / ExePath / StartTime
// so we can keep the per-OS files focused on the values gopsutil cannot
// supply (Windows FILETIME, /proc parsing, etc.). Errors are swallowed
// — every field is best-effort.
func fillFromGopsutil(info *Info) {
	if info.PID <= 0 {
		return
	}
	p, err := gopsproc.NewProcess(int32(info.PID))
	if err != nil {
		return
	}
	if cwd, err := p.Cwd(); err == nil {
		info.Cwd = cwd
	}
	if cl, err := p.Cmdline(); err == nil {
		info.Cmdline = cl
	}
	if u, err := p.Username(); err == nil {
		info.Username = u
	}
	if ppid, err := p.Ppid(); err == nil && ppid > 0 {
		info.ParentPID = int(ppid)
		if parent, err := gopsproc.NewProcess(ppid); err == nil {
			if name, err := parent.Name(); err == nil {
				info.ParentName = name
			}
		}
	}
}
