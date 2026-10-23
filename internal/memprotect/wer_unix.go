//go:build !windows

package memprotect

import "golang.org/x/sys/unix"

func DisableErrorReporting() {
	_ = unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0})
}
