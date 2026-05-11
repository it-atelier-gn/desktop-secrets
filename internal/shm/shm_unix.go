//go:build !windows

package shm

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/it-atelier-gn/desktop-secrets/internal/utils"
	"golang.org/x/sys/unix"
)

const (
	shmNameUnix = "tplenv_state"
	shmSize     = 4096
)

func shmPathUnix() (string, error) {
	dir, err := utils.GetRuntimeDirectory()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, shmNameUnix), nil
}

// ShmDaemonPublish creates/initializes a RAM-backed file, mmaps it RW, and writes data.
// Returns cleanup func to unmap and file handle close (optionally remove file on exit).
func ShmDaemonPublish(b []byte) (func(), error) {
	if len(b) > shmSize {
		return nil, fmt.Errorf("state too large (%d > %d)", len(b), shmSize)
	}
	path, err := shmPathUnix()
	if err != nil {
		return nil, err
	}

	// O_NOFOLLOW: refuse to traverse a symlink at this path.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	// Ensure fixed size so mmap has a consistent length.
	if err := f.Truncate(shmSize); err != nil {
		_ = f.Close()
		return nil, err
	}

	// Map RW
	data, err := unix.Mmap(int(f.Fd()), 0, shmSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		_ = f.Close()
		return nil, err
	}

	// Write buffer + zero the remainder.
	copy(data, b)
	if len(b) < len(data) {
		for i := len(b); i < len(data); i++ {
			data[i] = 0
		}
	}

	cleanup := func() {
		_ = unix.Munmap(data)
		_ = f.Close()
		// Optional strict cleanup:
		// _ = os.Remove(path)
	}
	return cleanup, nil
}

// ShmClientRead mmaps RO and returns the non-zero prefix.
func ShmClientRead() ([]byte, error) {
	path, err := shmPathUnix()
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, err := unix.Mmap(int(f.Fd()), 0, shmSize, unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		return nil, err
	}
	defer unix.Munmap(data)

	// Trim trailing zeros
	n := len(data)
	for n > 0 && data[n-1] == 0 {
		n--
	}
	out := make([]byte, n)
	copy(out, data[:n])
	return out, nil
}

// On Unix, removing the shared memory is removing the file (optional).
func shmRemove() {
	if path, err := shmPathUnix(); err == nil {
		_ = os.Remove(path)
	}
}
