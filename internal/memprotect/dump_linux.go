//go:build linux

package memprotect

import "golang.org/x/sys/unix"

func excludeFromCoreDump(b []byte) {
	_ = unix.Madvise(b, unix.MADV_DONTDUMP)
}

func HardenProcess() error {
	return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}
