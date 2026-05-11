//go:build linux

package ipc

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

func peerPID(c net.Conn) (int, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, fmt.Errorf("not a unix conn (type %T)", c)
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var ucred *unix.Ucred
	var callErr error
	ctlErr := raw.Control(func(fd uintptr) {
		ucred, callErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if ctlErr != nil {
		return 0, ctlErr
	}
	if callErr != nil {
		return 0, callErr
	}
	if ucred == nil {
		return 0, fmt.Errorf("nil ucred")
	}
	return int(ucred.Pid), nil
}
