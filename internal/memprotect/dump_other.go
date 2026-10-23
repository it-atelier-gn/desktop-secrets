//go:build !windows && !linux

package memprotect

func excludeFromCoreDump([]byte) {}

func HardenProcess() error { return nil }
