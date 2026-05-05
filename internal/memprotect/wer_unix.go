//go:build !windows

package memprotect

import "golang.org/x/sys/unix"

// DisableErrorReporting disables core dumps for the current process so
// that a crash cannot leak secrets to disk via a core file.
func DisableErrorReporting() {
	_ = unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0})
}
