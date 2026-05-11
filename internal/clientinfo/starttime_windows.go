//go:build windows

package clientinfo

import "time"

// startTimeToWallClock converts a Windows FILETIME (100-nanosecond
// intervals since 1601-01-01 UTC, packed as high<<32|low into a single
// uint64) into a local-zone time.Time.
func startTimeToWallClock(ft uint64) (time.Time, bool) {
	if ft == 0 {
		return time.Time{}, false
	}
	// FILETIME epoch (1601-01-01 UTC) → Unix epoch (1970-01-01 UTC) gap.
	const epochDiff100ns uint64 = 116444736000000000
	if ft < epochDiff100ns {
		return time.Time{}, false
	}
	unix100ns := ft - epochDiff100ns
	sec := int64(unix100ns / 10000000)
	nsec := int64((unix100ns % 10000000) * 100)
	return time.Unix(sec, nsec).Local(), true
}
