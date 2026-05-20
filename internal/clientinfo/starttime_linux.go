//go:build linux

package clientinfo

import (
	"math"
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

	clkTck int64 = 100
)

func loadBootTime() {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return
	}
	for line := range strings.SplitSeq(string(data), "\n") {
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

func startTimeToWallClock(ticks uint64) (time.Time, bool) {
	if ticks == 0 || ticks > math.MaxInt64 {
		return time.Time{}, false
	}
	bootTimeOnce.Do(loadBootTime)
	if !bootTimeOK {
		return time.Time{}, false
	}
	t := int64(ticks)
	sec := t / clkTck
	nsec := (t % clkTck) * (int64(time.Second) / clkTck)
	return bootTime.Add(time.Duration(sec)*time.Second + time.Duration(nsec)).Local(), true
}
