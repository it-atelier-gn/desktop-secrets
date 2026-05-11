//go:build !windows

package ipc

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"

	"github.com/it-atelier-gn/desktop-secrets/internal/utils"
)

// Listen creates a 0600 Unix-domain socket in the per-user runtime directory.
// A tight umask is set around the bind so there is no window where the socket
// inode is world-connectable.
func Listen() (net.Listener, Endpoint, error) {
	dir, err := utils.GetRuntimeDirectory()
	if err != nil {
		return nil, "", err
	}
	path := filepath.Join(dir, fmt.Sprintf("desktop-secrets-%s.sock", randomToken()))

	// Best-effort cleanup of stale socket at the chosen path. Path
	// includes a random token so collisions with an unrelated daemon
	// are vanishingly rare; remove only if it exists.
	_ = os.Remove(path)

	addr, err := net.ResolveUnixAddr("unix", path)
	if err != nil {
		return nil, "", err
	}

	prevMask := syscall.Umask(0o077)
	ln, lerr := net.ListenUnix("unix", addr)
	syscall.Umask(prevMask)
	if lerr != nil {
		return nil, "", lerr
	}
	// Defence in depth: chmod again in case a sandbox layer ignored umask.
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		_ = os.Remove(path)
		return nil, "", err
	}
	// Remove socket file when listener closes.
	ln.SetUnlinkOnClose(true)
	return ln, Endpoint(path), nil
}

// Dial connects to the Unix domain socket at addr. Network argument
// ignored.
func Dial(ctx context.Context, _ string, addr string) (net.Conn, error) {
	d := net.Dialer{}
	return d.DialContext(ctx, "unix", addr)
}
