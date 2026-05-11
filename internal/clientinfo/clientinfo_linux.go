//go:build linux

package clientinfo

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	ps "github.com/mitchellh/go-ps"
)

func Lookup(pid int) Info {
	info := Info{PID: pid}
	if pid <= 0 {
		return info
	}
	if p, err := ps.FindProcess(pid); err == nil && p != nil {
		info.Name = p.Executable()
	}
	if path, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil {
		info.ExePath = path
		if info.Name == "" {
			info.Name = filepath.Base(path)
		}
	}
	if st, err := procStartTime(pid); err == nil {
		info.StartTime = st
	}
	fillFromGopsutil(&info)
	return info
}

// procStartTime parses /proc/<pid>/stat field 22 (starttime, in clock
// ticks). The comm field can contain spaces and ')', so we split after
// the LAST ')'; starttime is then fields[19] (zero-indexed).
func procStartTime(pid int) (uint64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	rparen := strings.LastIndexByte(string(data), ')')
	if rparen < 0 || rparen+2 >= len(data) {
		return 0, fmt.Errorf("malformed /proc/%d/stat", pid)
	}
	fields := strings.Fields(string(data[rparen+2:]))
	if len(fields) < 20 {
		return 0, fmt.Errorf("short /proc/%d/stat", pid)
	}
	return strconv.ParseUint(fields[19], 10, 64)
}
