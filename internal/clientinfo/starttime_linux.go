//go:build linux

package clientinfo

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	bootTimeOnce sync.Once
	bootTime     time.Time
	bootTimeOK   bool

	// Linux's CLK_TCK is fixed at compile time of the kernel and has
	// been 100 on every mainstream distro for decades. Reading it via
	// sysconf would need cgo (the libc value, not the kernel HZ).
	clkTck int64 = 100
)

func loadBootTime() {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "btime ") {
			continue
		}
		v, err := strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(line, "btime ")), 10, 64)
		if err != nil {
			return
		}
		bootTime = time.Unix(v, 0)
		bootTimeOK = true
		return
	}
}

// startTimeToWallClock converts /proc/<pid>/stat field 22 (starttime in
// clock ticks since boot) into a local-zone time.Time.
func startTimeToWallClock(ticks uint64) (time.Time, bool) {
	if ticks == 0 {
		return time.Time{}, false
	}
	bootTimeOnce.Do(loadBootTime)
	if !bootTimeOK {
		return time.Time{}, false
	}
	sec := int64(ticks) / clkTck
	nsec := (int64(ticks) % clkTck) * (int64(time.Second) / clkTck)
	return bootTime.Add(time.Duration(sec)*time.Second + time.Duration(nsec)).Local(), true
}
