//go:build darwin

package ipc

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// macOS LOCAL_PEERPID returns the connecting client's PID for an
// AF_UNIX socket. Available since 10.8.
func peerPID(c net.Conn) (int, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, fmt.Errorf("not a unix conn (type %T)", c)
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var pid int
	var callErr error
	ctlErr := raw.Control(func(fd uintptr) {
		pid, callErr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	})
	if ctlErr != nil {
		return 0, ctlErr
	}
	if callErr != nil {
		return 0, callErr
	}
	return pid, nil
}
