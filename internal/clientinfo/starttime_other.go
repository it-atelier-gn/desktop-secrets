//go:build !windows && !linux

package clientinfo

import "time"

// startTimeToWallClock has no meaningful interpretation for StartTime on
// platforms where we don't currently populate it.
func startTimeToWallClock(uint64) (time.Time, bool) {
	return time.Time{}, false
}
